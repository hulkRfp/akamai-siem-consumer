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

# 每批发送的最大字节数（控制单次 send 体积，避免大批次导致发送超时）
# 一条 Akamai 事件平均 5~15KB，按 5MB 切分大约对应 500~1000 条。
# 可通过 logstash.max_batch_bytes 配置覆盖。
MAX_BATCH_BYTES = 5 * 1024 * 1024

# 发送超时默认值（秒）。TCP send 偶尔慢于此值即判定整批失败，
# 由上层 resume 机制从 offset 重新拉取，宁可重复不可错位。
DEFAULT_TIMEOUT = 30


def send_to_logstash(config: Dict, logs: List[Dict]) -> bool:
    """将日志发送到Logstash"""
    logstash_config = config.get("logstash", {})
    host = logstash_config.get("host", "localhost")
    port = logstash_config.get("port", 5045)
    protocol = logstash_config.get("protocol", "tcp")
    timeout = logstash_config.get("timeout", DEFAULT_TIMEOUT)
    max_batch_bytes = int(logstash_config.get("max_batch_bytes", MAX_BATCH_BYTES))

    if not logs:
        logger.debug("没有日志需要发送到Logstash")
        return True

    try:
        if protocol == "tcp":
            _send_tcp_batched(host, port, timeout, logs, max_batch_bytes)
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


def _split_into_byte_batches(logs: List[Dict], max_batch_bytes: int) -> List[bytes]:
    """将日志列表按字节上限切分为多个批次。

    每条日志序列化为 JSON + 换行符，累积到接近 max_batch_bytes 时封批。
    单条日志超过上限也会单独成批（不会被截断，保证每条记录完整）。
    """
    batches = []
    current = bytearray()
    current_size = 0

    for log in logs:
        line = json.dumps(log).encode("utf-8") + b"\n"
        line_len = len(line)

        # 当前批次非空且加入本条会超出上限 → 先封批
        if current_size > 0 and current_size + line_len > max_batch_bytes:
            batches.append(bytes(current))
            current = bytearray()
            current_size = 0

        current.extend(line)
        current_size += line_len

    if current_size > 0:
        batches.append(bytes(current))

    return batches


def _send_tcp_batched(host: str, port: int, timeout: int, logs: List[Dict], max_batch_bytes: int = MAX_BATCH_BYTES) -> None:
    """使用 TCP 长连接分批发送日志。

    ⚠️ 关键不变量：任何发送异常（超时或断连）都整批作废，绝不补发剩余字节。

    原因：TCP 断连/超时后，发送方对“对方实际收到多少字节”处于完全无知状态，
    total_sent 之前的字节可能已送达、可能只到一半、也可能全丢。断点几乎必然
    落在某条记录中间，从 total_sent 续发会产生错位的半条 JSON —— 这是脏数据，
    会污染下游整张表。正确做法是整批丢弃，由上层 resume/offset 机制重新拉取
    并重发整批（宁可重复，不可错位）。重复记录可用 requestId 去重或容忍，
    错位的半条记录无法自愈。
    """
    batches = _split_into_byte_batches(logs, max_batch_bytes)

    conn = _get_tcp_connection(host, port, timeout)

    for batch_index, data in enumerate(batches):
        try:
            # 一次性发送整个批次。socket.send 在大数据时可能只发一部分，
            # 这里用循环把“本批次”发完整——注意：这只在连接正常时循环，
            # 一旦抛出异常（超时/断连），立刻停止，整批作废。
            total_sent = 0
            while total_sent < len(data):
                sent = conn.send(data[total_sent:])
                if sent == 0:
                    # 对端关闭连接，无数据可继续发送
                    raise BrokenPipeError("TCP连接已关闭 (send 返回 0)")
                total_sent += sent
        except (socket.error, OSError) as e:
            # 整批作废：关闭连接，交由上层重试整批（重新拉取 + 重发）。
            logger.error(
                f"TCP发送失败（批次 {batch_index + 1}/{len(batches)}，"
                f"共 {len(data)} 字节），整批作废，等待上层重传: {e}"
            )
            _close_tcp_connection()
            # 抛出异常，send_to_logstash 捕获后返回 False，
            # process_logs 不会更新 resume offset → 下一轮从同一 offset 重新拉取。
            raise


def _send_udp_batched(host: str, port: int, timeout: int, logs: List[Dict]) -> None:
    """使用 UDP 分批发送日志"""
    max_udp_size = 65507  # UDP最大有效负载大小

    # UDP 按数据报发送，单条事件可能超过单报限制，因此逐条发送最安全。
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)

        for log in logs:
            data = json.dumps(log).encode("utf-8") + b"\n"
            if len(data) <= max_udp_size:
                s.sendto(data, (host, port))
            else:
                # 单条超过 UDP 限制，截断风险由上层决定，此处仅记录并跳过该条
                logger.warning(
                    f"单条日志 {len(data)} 字节超过 UDP 上限 {max_udp_size}，"
                    f"已跳过 (requestId={log.get('httpMessage', {}).get('requestId', 'N/A')})"
                )
