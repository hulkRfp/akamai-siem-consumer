"""
Logstash 日志发送模块

支持 TCP（长连接复用）和 UDP 两种协议。
大批量日志会自动分批发送，避免内存峰值过高。
"""

# 尝试导入ujson，如果不可用则回退到标准json库
try:
    import ujson as json
except ImportError:
    import json

import socket
from typing import Dict, List, Optional

from .logging_setup import logger

# TCP 长连接（模块级复用）
_tcp_socket: Optional[socket.socket] = None
_tcp_target: Optional[tuple] = None

# 每批发送的最大日志条数（控制内存使用）
BATCH_SIZE = 2000


def send_to_logstash(config: Dict, logs: List[Dict]) -> bool:
    """将日志发送到Logstash"""
    logstash_config = config.get("logstash", {})
    host = logstash_config.get("host", "localhost")
    port = logstash_config.get("port", 5045)
    protocol = logstash_config.get("protocol", "tcp")
    timeout = logstash_config.get("timeout", 10)

    if not logs:
        logger.debug("没有日志需要发送到Logstash")
        return True

    try:
        if protocol == "tcp":
            _send_tcp_batched(host, port, timeout, logs)
        else:
            _send_udp_batched(host, port, timeout, logs)

        logger.info(f"成功发送 {len(logs)} 条日志到Logstash ({protocol}:{host}:{port})")
        return True
    except Exception as e:
        logger.error(f"发送日志到Logstash失败: {e}")
        # TCP 连接可能已断开，清理以便下次重建
        _close_tcp_connection()
        return False


def _get_tcp_connection(host: str, port: int, timeout: int) -> socket.socket:
    """获取或创建 TCP 长连接"""
    global _tcp_socket, _tcp_target

    target = (host, port)

    # 如果目标地址变化或连接不存在，重新创建
    if _tcp_socket is not None and _tcp_target == target:
        # 检查连接是否仍然有效
        try:
            # 使用 getpeername 检测连接状态
            _tcp_socket.getpeername()
            return _tcp_socket
        except (socket.error, OSError):
            # 连接已断开，需要重建
            _close_tcp_connection()

    # 创建新连接
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)  # 禁用 Nagle 算法
    s.connect(target)

    _tcp_socket = s
    _tcp_target = target
    logger.debug(f"建立TCP连接到 {host}:{port}")

    return _tcp_socket


def _close_tcp_connection() -> None:
    """关闭 TCP 连接"""
    global _tcp_socket, _tcp_target

    if _tcp_socket is not None:
        try:
            _tcp_socket.close()
        except Exception:
            pass
        _tcp_socket = None
        _tcp_target = None


def _send_tcp_batched(host: str, port: int, timeout: int, logs: List[Dict]) -> None:
    """使用 TCP 长连接分批发送日志

    使用 bytearray 累积序列化结果，避免大量中间字符串分配。
    """
    conn = _get_tcp_connection(host, port, timeout)

    # 分批发送
    for i in range(0, len(logs), BATCH_SIZE):
        batch = logs[i:i + BATCH_SIZE]

        # 使用 bytearray 累积，减少中间字符串对象
        buffer = bytearray()
        for log in batch:
            buffer.extend(json.dumps(log).encode("utf-8"))
            buffer.extend(b"\n")

        data = bytes(buffer)
        total_sent = 0
        while total_sent < len(data):
            try:
                sent = conn.send(data[total_sent:])
                if sent == 0:
                    raise RuntimeError("TCP连接已关闭")
                total_sent += sent
            except (socket.error, OSError) as e:
                # 连接断开，尝试重连一次
                logger.warning(f"TCP发送失败，尝试重连: {e}")
                _close_tcp_connection()
                conn = _get_tcp_connection(host, port, timeout)
                # 重新发送当前批次剩余数据
                remaining = data[total_sent:]
                total_sent_retry = 0
                while total_sent_retry < len(remaining):
                    sent = conn.send(remaining[total_sent_retry:])
                    if sent == 0:
                        raise RuntimeError("TCP重连后发送仍然失败")
                    total_sent_retry += sent
                break  # 当前批次发送完成


def _send_udp_batched(host: str, port: int, timeout: int, logs: List[Dict]) -> None:
    """使用 UDP 分批发送日志"""
    max_udp_size = 65507  # UDP最大有效负载大小

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)

        for i in range(0, len(logs), BATCH_SIZE):
            batch = logs[i:i + BATCH_SIZE]

            buffer = bytearray()
            for log in batch:
                buffer.extend(json.dumps(log).encode("utf-8"))
                buffer.extend(b"\n")

            data = bytes(buffer)

            if len(data) <= max_udp_size:
                s.sendto(data, (host, port))
            else:
                # 数据超过 UDP 限制，逐条发送
                for log in batch:
                    single = json.dumps(log).encode("utf-8") + b"\n"
                    s.sendto(single, (host, port))
