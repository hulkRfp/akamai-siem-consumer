"""
配置加载、验证和命令行参数解析模块

配置优先级：命令行参数 > 配置文件 > 默认配置
配置文件格式：YAML
支持环境变量引用：${ENV_VAR} 或 ${ENV_VAR:default_value}
"""

import argparse
import copy
import os
import re
from datetime import datetime
from typing import Any, Dict

import yaml

from .logging_setup import LOG_LEVELS, logger

# 环境变量引用的正则表达式（模块级预编译）
_ENV_PATTERN = re.compile(r'\$\{([^}:]+)(?::([^}]*))?\}')

# 默认配置
DEFAULT_CONFIG = {
    "site": "all",
    "mode": "offset",
    "limit": 1000,
    "log_level": "info",
    "run_mode": "once",
    "service": {
        "interval": 60,
        "max_consecutive_failures": 10
    },
    "resume": {
        "enabled": True,
        "fallback_minutes": 30,
        "redis": {
            "host": "127.0.0.1",
            "port": 6379,
            "db": 0,
            "password": None,
            "socket_timeout": 5
        },
        "key_prefix": "akamai_siem:resume",
        "ttl": None
    }
}


def validate_config(config: Dict) -> None:
    """验证配置参数的完整性"""
    # 验证基本配置项
    required_basic_fields = ["mode", "limit", "log_level"]
    for field in required_basic_fields:
        if field not in config or not config[field]:
            raise ValueError(f"缺少必要参数: {field}")

    # 验证Akamai配置
    if "akamai" not in config:
        raise ValueError("配置文件缺少 'akamai' 部分")

    akamai_config = config["akamai"]
    required_akamai_fields = ["base_url", "client_token", "client_secret", "access_token", "configId"]
    for field in required_akamai_fields:
        if field not in akamai_config or not akamai_config[field]:
            raise ValueError(f"Akamai配置缺少必要参数: {field}")

    # 验证Logstash配置（stdout 模式下不需要）
    if not config.get("output_stdout", False):
        if "logstash" not in config:
            raise ValueError("配置文件缺少 'logstash' 部分")

        logstash_config = config["logstash"]
        required_logstash_fields = ["host", "port", "protocol"]
        for field in required_logstash_fields:
            if field not in logstash_config:
                raise ValueError(f"Logstash配置缺少必要参数: {field}")

        if logstash_config["protocol"] not in ["tcp", "udp"]:
            raise ValueError(f"无效的Logstash协议: {logstash_config['protocol']}")

    # 验证拉取模式参数
    if config["mode"] == "offset":
        if "offset" in config:
            config["offset"] = str(config["offset"])
    elif config["mode"] == "time-based":
        _validate_time_param(config, "from_time")
        _validate_time_param(config, "to_time")
    else:
        raise ValueError(f"无效的拉取模式: {config['mode']}")

    # 验证 limit 为正整数
    if not isinstance(config["limit"], int) or config["limit"] <= 0:
        raise ValueError(f"limit 必须为正整数，当前值: {config['limit']}")

    logger.info("配置验证通过")


def _validate_time_param(config: Dict, param_name: str) -> None:
    """验证并转换时间参数为 Unix 时间戳"""
    if param_name not in config:
        return

    value = config[param_name]

    # 已经是数字类型
    if isinstance(value, (int, float)):
        return

    # 字符串类型，尝试解析
    if isinstance(value, str):
        try:
            config[param_name] = float(value)
            return
        except ValueError:
            pass

        try:
            config[param_name] = datetime.fromisoformat(value).timestamp()
            return
        except ValueError:
            raise ValueError(f"无效的时间格式 ({param_name}): {value}")

    raise ValueError(f"{param_name} 类型无效: {type(value)}")


def load_config(config_path: str) -> Dict:
    """加载 YAML 配置文件

    :param config_path: 配置文件路径（支持 .yaml / .yml）
    :return: 配置字典
    :raises FileNotFoundError: 配置文件不存在
    :raises yaml.YAMLError: YAML 解析失败
    """
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"配置文件不存在: {config_path}")

    with open(config_path, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)

    if config is None:
        logger.warning(f"配置文件 {config_path} 为空")
        return {}

    if not isinstance(config, dict):
        raise ValueError(f"配置文件格式错误，顶层必须是字典: {config_path}")

    return config


def resolve_env_vars(config: Any) -> Any:
    """递归解析配置中的环境变量引用

    支持两种格式：
    - "${ENV_VAR}" — 完整替换，环境变量不存在时保留原值并警告
    - "${ENV_VAR:default}" — 环境变量不存在时使用默认值
    - 字符串中嵌入: "prefix_${ENV_VAR}_suffix" — 内联替换

    :param config: 任意配置值（递归处理）
    :return: 解析后的配置值
    """
    if isinstance(config, str):
        return _resolve_string(config)
    elif isinstance(config, dict):
        return {k: resolve_env_vars(v) for k, v in config.items()}
    elif isinstance(config, list):
        return [resolve_env_vars(item) for item in config]
    return config


def _resolve_string(value: str) -> str:
    """解析字符串中的环境变量引用"""
    def _replacer(match):
        env_name = match.group(1)
        default = match.group(2)
        env_value = os.environ.get(env_name)
        if env_value is not None:
            return env_value
        elif default is not None:
            return default
        else:
            logger.warning(f"环境变量 {env_name} 未设置且无默认值")
            return match.group(0)  # 保留原始 ${...} 文本

    return _ENV_PATTERN.sub(_replacer, value)


def merge_dict(dest: Dict, src: Dict) -> None:
    """递归深度合并字典

    src 中的值覆盖 dest 中的同名键。
    当两边都是 dict 时递归合并，否则直接覆盖。
    """
    for key, value in src.items():
        if (
            key in dest
            and isinstance(dest[key], dict)
            and isinstance(value, dict)
        ):
            merge_dict(dest[key], value)
        else:
            dest[key] = value


def get_config() -> Dict:
    """获取完整配置信息

    处理配置优先级：命令行参数 > 配置文件 > 默认配置
    """
    # 解析命令行参数
    parser = argparse.ArgumentParser(
        description="Akamai SIEM日志拉取和发送到Logstash的程序"
    )
    parser.add_argument("--config", type=str, default="config.yaml",
                        help="配置文件路径 (YAML格式)")
    parser.add_argument("--mode", type=str, choices=["time-based", "offset"],
                        help="拉取模式")
    parser.add_argument("--from-time", type=str,
                        help="开始时间 (ISO格式或Unix时间戳)")
    parser.add_argument("--to-time", type=str,
                        help="结束时间 (ISO格式或Unix时间戳)")
    parser.add_argument("--offset", type=str,
                        help="偏移量 (offset模式使用)")
    parser.add_argument("--limit", type=int,
                        help="每次拉取数量")
    parser.add_argument("--log-level", type=str, choices=LOG_LEVELS.keys(),
                        help="日志级别")
    parser.add_argument("--service", action="store_true",
                        help="以服务模式运行")
    parser.add_argument("--once", action="store_true",
                        help="只运行一次")
    parser.add_argument("--stdout", action="store_true",
                        help="单次运行模式下将事件输出到标准输出，不发送到Logstash")

    args = parser.parse_args()

    # 1. 深拷贝默认配置作为基础
    config = copy.deepcopy(DEFAULT_CONFIG)

    # 2. 加载配置文件
    try:
        file_config = load_config(args.config)
        file_config = resolve_env_vars(file_config)
        merge_dict(config, file_config)
        logger.info(f"配置文件加载成功: {args.config}")
    except FileNotFoundError:
        logger.warning(f"配置文件 {args.config} 不存在，将使用默认配置")
    except Exception as e:
        logger.warning(f"加载配置文件 {args.config} 失败: {e}，将使用默认配置")

    # 3. 合并命令行参数（优先级最高）
    if args.mode is not None:
        config["mode"] = args.mode
    if args.limit is not None:
        config["limit"] = args.limit
    if args.log_level is not None:
        config["log_level"] = args.log_level
    if args.from_time is not None:
        config["from_time"] = args.from_time
    if args.to_time is not None:
        config["to_time"] = args.to_time
    if args.offset is not None:
        config["offset"] = str(args.offset)

    # 设置运行模式
    if args.service and args.once:
        raise ValueError("--service 和 --once 不能同时使用")
    elif args.service:
        config["run_mode"] = "service"
    elif args.once:
        config["run_mode"] = "once"

    # stdout 输出模式
    if args.stdout:
        config["output_stdout"] = True

    # 语义一致性检查：提示用户可能的参数矛盾
    if config["mode"] == "offset" and ("from_time" in config or "to_time" in config):
        if args.from_time is not None or args.to_time is not None:
            logger.warning("当前为offset模式，--from-time/--to-time 参数将被忽略。如需使用时间范围，请指定 --mode time-based")
    if config["mode"] == "time-based" and "offset" in config:
        if args.offset is not None:
            logger.warning("当前为time-based模式，--offset 参数将被忽略。如需使用偏移量，请指定 --mode offset")

    # 4. 验证配置
    validate_config(config)

    return config
