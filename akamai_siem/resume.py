"""
断点续传模块 - 使用 Redis 存储

当 Redis 中不存在断点信息时，返回空字典，由调用方决定回退策略。
"""

# 尝试导入ujson，如果不可用则回退到标准json库
try:
    import ujson as json
except ImportError:
    import json

import redis
import threading
from typing import Dict, Optional

from .logging_setup import logger

# 模块级 Redis 连接池（惰性初始化）
_redis_client: Optional[redis.Redis] = None
_redis_lock = threading.Lock()


def _get_redis_client(config: Dict) -> redis.Redis:
    """获取或创建 Redis 客户端连接（线程安全）"""
    global _redis_client

    if _redis_client is not None:
        return _redis_client

    with _redis_lock:
        # 双重检查
        if _redis_client is not None:
            return _redis_client

        redis_config = config.get("resume", {}).get("redis", {})
        host = redis_config.get("host", "127.0.0.1")
        port = redis_config.get("port", 6379)
        db = redis_config.get("db", 0)
        password = redis_config.get("password", None)
        socket_timeout = redis_config.get("socket_timeout", 5)

        # 空字符串视为无密码
        if not password:
            password = None

        client = redis.Redis(
            host=host,
            port=port,
            db=db,
            password=password,
            socket_timeout=socket_timeout,
            decode_responses=True
        )

        # 测试连接
        client.ping()
        logger.debug(f"Redis连接成功: {host}:{port} db={db}")

        _redis_client = client

    return _redis_client


def _get_redis_key(config: Dict) -> str:
    """生成 Redis 存储键名"""
    resume_config = config.get("resume", {})
    # 支持自定义 key 前缀，默认使用 configId 区分不同配置
    key_prefix = resume_config.get("key_prefix", "akamai_siem:resume")
    config_id = config.get("akamai", {}).get("configId", "default")
    return f"{key_prefix}:{config_id}"


def load_resume_point(config: Dict) -> Dict:
    """从 Redis 加载断点续传信息

    :return: 断点数据字典，不存在时返回空字典
    """
    if not config.get("resume", {}).get("enabled", True):
        logger.info("断点续传功能已禁用")
        return {}

    try:
        client = _get_redis_client(config)
        key = _get_redis_key(config)

        data = client.get(key)
        if data:
            resume_data = json.loads(data)
            logger.info(f"从Redis加载断点续传信息成功: key={key}, data={resume_data}")
            return resume_data
        else:
            logger.info(f"Redis中未找到断点续传信息: key={key}")
            return {}

    except redis.ConnectionError as e:
        logger.error(f"Redis连接失败，无法加载断点续传信息: {e}")
        return {}
    except Exception as e:
        logger.error(f"加载断点续传信息失败: {e}")
        return {}


def save_resume_point(config: Dict, resume_data: Dict) -> None:
    """将断点续传信息保存到 Redis"""
    if not config.get("resume", {}).get("enabled", True):
        return

    try:
        client = _get_redis_client(config)
        key = _get_redis_key(config)

        # 可选设置 TTL，防止过期数据永久残留
        ttl = config.get("resume", {}).get("ttl", None)

        data = json.dumps(resume_data)
        if ttl:
            client.setex(key, ttl, data)
        else:
            client.set(key, data)

        logger.debug(f"保存断点续传信息到Redis成功: key={key}, data={resume_data}")

    except redis.ConnectionError as e:
        logger.error(f"Redis连接失败，无法保存断点续传信息: {e}")
    except Exception as e:
        logger.error(f"保存断点续传信息失败: {e}")
