"""
日志系统配置模块

所有日志输出到标准输出（stdout），便于容器化部署和日志收集。
"""

import sys
import logging
from typing import Optional

# 日志级别映射
LOG_LEVELS = {
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "warning": logging.WARNING,
    "error": logging.ERROR,
    "critical": logging.CRITICAL
}

# 创建全局日志记录器
logger = logging.getLogger("akamai_siem")


def setup_logging(log_level: str, log_file: Optional[str] = None, stderr: bool = False) -> None:
    """设置日志系统

    :param log_level: 日志级别
    :param log_file: 保留兼容性，不再使用
    :param stderr: 是否输出到 stderr（stdout 模式下使用，避免与数据输出混淆）
    """
    # 清除可能存在的旧处理器
    if logger.handlers:
        logger.handlers.clear()

    level = LOG_LEVELS.get(log_level.lower(), logging.INFO)
    logger.setLevel(level)

    # 选择输出流
    stream = sys.stderr if stderr else sys.stdout
    handler = logging.StreamHandler(stream)
    handler.setLevel(level)

    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)

    logger.addHandler(handler)
