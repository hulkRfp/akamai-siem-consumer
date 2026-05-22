#!/usr/bin/env python3
"""
Akamai SIEM日志拉取和发送到Logstash的程序 - 入口文件

功能包括：
- 从Akamai安全API拉取SIEM日志并发送到Logstash
- 支持两种日志拉取模式：基于偏移量(offset)和基于时间范围(time-based)
- 提供断点续传功能，确保重启后能从上次中断处继续拉取
- 支持命令行传参，可单独运行一次或作为持续运行的服务模式运行
"""

# 尝试导入ujson，如果不可用则回退到标准json库
try:
    import ujson as json
except ImportError:
    import json

import sys
import time
import copy
import signal
from datetime import datetime, timedelta, timezone
from typing import Dict

from akamai_siem.logging_setup import logger, setup_logging
from akamai_siem.config import get_config
from akamai_siem.api import fetch_siem_events
from akamai_siem.processor import process_logs as process_event_data
from akamai_siem.sender import send_to_logstash
from akamai_siem.resume import load_resume_point, save_resume_point

# 优雅退出标志
_shutdown_requested = False


def _signal_handler(signum, frame):
    """信号处理器，设置退出标志"""
    global _shutdown_requested
    _shutdown_requested = True
    logger.info(f"收到信号 {signum}，准备优雅退出...")


def process_logs(config: Dict, should_save_resume: bool = True) -> bool:
    """处理日志的主函数"""
    try:
        # 加载断点续传信息
        resume_data = load_resume_point(config)

        # 如果有断点续传信息，且命令行没有显式指定参数，使用断点续传信息
        if resume_data:
            if config["mode"] == "offset":
                if "offset" in resume_data and "offset" not in config:
                    config["offset"] = resume_data["offset"]
            else:
                if "from_time" in resume_data and "from_time" not in config:
                    config["from_time"] = resume_data["from_time"]
        else:
            # 断点信息不存在，自动切换为 time-based 模式，从30分钟前开始
            if "offset" not in config and "from_time" not in config:
                fallback_minutes = config.get("resume", {}).get("fallback_minutes", 30)
                from_time = datetime.now(timezone.utc) - timedelta(minutes=fallback_minutes)
                config["mode"] = "time-based"
                config["from_time"] = from_time.timestamp()
                logger.info(
                    f"断点信息不存在，自动切换为time-based模式，"
                    f"从 {fallback_minutes} 分钟前开始拉取 (from_time={config['from_time']})"
                )

        # 拉取日志
        result = fetch_siem_events(config)
        logs = result.get("data", [])
        metadata = result.get("metadata", {})

        if not logs:
            logger.info("没有获取到日志")
            return True

        # 按配置规则处理事件字段
        processed_logs = process_event_data(logs, config)

        # 发送到Logstash
        if send_to_logstash(config, processed_logs):
            # 更新断点续传信息
            new_resume_data = {}
            if config["mode"] == "offset":
                if metadata and "offset" in metadata:
                    if metadata["offset"]:
                        new_resume_data["offset"] = metadata["offset"]
                        logger.debug(f"使用API元数据中的offset: {new_resume_data['offset']}")
                    else:
                        logger.warning("获取的下一次offset值为空，跳过断点续传信息更新")
                        should_save_resume = False
                else:
                    logger.warning("无法获取下一次offset，跳过断点续传信息更新")
                    should_save_resume = False
            else:
                # time-based模式下
                if config.get("next_time"):
                    new_resume_data["from_time"] = config["next_time"]
                else:
                    new_resume_data["from_time"] = datetime.now(timezone.utc).timestamp()

                if metadata and "offset" in metadata:
                    new_resume_data["offset"] = metadata["offset"]

            if should_save_resume:
                save_resume_point(config, new_resume_data)

            return True
        else:
            # 发送到Logstash失败，记录详细失败信息
            logstash_config = config.get("logstash", {})
            logger.error(
                f"发送 {len(processed_logs)} 条日志到Logstash失败 "
                f"(目标: {logstash_config.get('protocol', 'tcp')}:"
                f"{logstash_config.get('host', 'unknown')}:"
                f"{logstash_config.get('port', 'unknown')})"
            )
            if config["mode"] == "offset":
                logger.error(f"失败批次offset: {config.get('offset', 'N/A')}")
            else:
                logger.error(
                    f"失败批次时间范围: from={config.get('from_time', 'N/A')}, "
                    f"to={config.get('to_time', 'N/A')}"
                )
            if metadata:
                logger.error(f"失败批次元数据: {metadata}")

            # 不更新断点续传，下次重试同一批数据
            return False

    except Exception as e:
        logger.error(f"处理日志失败: {e}")
        logger.exception(e)
        return False


def ask_user_to_save_resume() -> bool:
    """询问用户是否保存断点续传信息"""
    try:
        while True:
            response = input("是否将本次运行的状态覆盖至断点续传文件中？(y/n): ").strip().lower()
            if response == 'y':
                return True
            elif response == 'n':
                return False
            else:
                print("请输入 'y' 或 'n'")
    except EOFError:
        logger.info("非交互式环境，默认不保存断点续传信息")
        return False
    except KeyboardInterrupt:
        logger.info("用户中断输入，默认不保存断点续传信息")
        return False


def service_mode(config: Dict) -> None:
    """以服务模式运行"""
    global _shutdown_requested
    logger.info("启动服务模式")
    interval = config.get("service", {}).get("interval", 60)
    max_consecutive_failures = config.get("service", {}).get("max_consecutive_failures", 10)
    consecutive_failures = 0
    is_first_execution = True

    try:
        # 保存必要的配置信息（不包含数据范围参数）
        base_config = {
            "site": config.get("site", None),
            "akamai": config.get("akamai", {}),
            "logstash": config.get("logstash", {}),
            "resume": config.get("resume", {}),
            "processing": config.get("processing", {}),
            "service": config.get("service", {}),
            "mode": config.get("mode", "offset"),
            "limit": config.get("limit", 1000),
            "log_level": config.get("log_level", "info"),
            "log_file": config.get("log_file", None),
            "run_mode": "service"
        }

        while not _shutdown_requested:
            logger.info(f"开始新一轮日志拉取 (间隔: {interval}秒)")

            if is_first_execution:
                current_config = copy.deepcopy(config)
                logger.info("首次执行，使用命令行传参的范围参数")
            else:
                current_config = copy.deepcopy(base_config)
                logger.info("非首次执行，使用断点续传的范围参数")

            if process_logs(current_config, should_save_resume=True):
                consecutive_failures = 0
            else:
                consecutive_failures += 1
                logger.warning(f"连续失败 {consecutive_failures} 次")

                if consecutive_failures >= max_consecutive_failures:
                    logger.error(f"达到最大连续失败次数 {max_consecutive_failures}，退出服务")
                    sys.exit(1)

            is_first_execution = False

            # 使用短间隔循环检查退出标志，而非一次性 sleep
            logger.info(f"等待 {interval} 秒后再次拉取")
            for _ in range(interval):
                if _shutdown_requested:
                    break
                time.sleep(1)

        logger.info("服务正常退出")

    except KeyboardInterrupt:
        logger.info("收到中断信号，停止服务")
    except Exception as e:
        logger.error(f"服务模式运行失败: {e}")
        logger.exception(e)
        sys.exit(1)


def run_once(config: Dict) -> int:
    """只运行一次"""
    logger.info("运行一次模式")

    try:
        should_save_resume = ask_user_to_save_resume()

        if process_logs(config, should_save_resume):
            logger.info("单次运行完成")
            return 0
        else:
            logger.error("单次运行失败")
            return 1
    except Exception as e:
        logger.error(f"单次运行异常: {e}")
        logger.exception(e)
        return 1


def main():
    """主函数"""
    try:
        # 注册信号处理器（优雅退出）
        signal.signal(signal.SIGTERM, _signal_handler)
        signal.signal(signal.SIGINT, _signal_handler)

        # 获取完整配置
        config = get_config()

        # 设置日志
        setup_logging(config.get("log_level", "info"), config.get("log_file", None))

        logger.info("Akamai SIEM日志拉取和发送到Logstash的程序启动")
        logger.debug(f"配置: {json.dumps(config, default=str)}")

        # 运行模式
        run_mode = config.get("run_mode", "once")

        if run_mode == "service":
            service_mode(config)
            return 0
        else:
            return run_once(config)

    except Exception as e:
        logger.error(f"程序启动失败: {e}")
        logger.exception(e)
        return 1


if __name__ == "__main__":
    exit(main())
