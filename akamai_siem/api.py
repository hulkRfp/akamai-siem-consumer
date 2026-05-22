"""
Akamai SIEM API 调用模块
"""

# 尝试导入ujson，如果不可用则回退到标准json库
try:
    import ujson as json
except ImportError:
    import json

import time
import requests
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional

from akamai.edgegrid import EdgeGridAuth

from .logging_setup import logger

# 模块级 Session（复用 TCP 连接）
_session: Optional[requests.Session] = None
_session_config_hash: Optional[str] = None


def _get_session(akamai_config: Dict) -> requests.Session:
    """获取或创建可复用的 requests Session

    当 Akamai 凭证配置变化时重新创建 Session。
    """
    global _session, _session_config_hash

    # 用凭证信息生成简单哈希，检测配置是否变化
    config_hash = (
        f"{akamai_config.get('base_url')}:"
        f"{akamai_config.get('client_token')}:"
        f"{akamai_config.get('access_token')}"
    )

    if _session is not None and _session_config_hash == config_hash:
        return _session

    # 创建新 Session
    session = requests.Session()
    session.auth = EdgeGridAuth(
        client_token=akamai_config.get('client_token'),
        client_secret=akamai_config.get('client_secret'),
        access_token=akamai_config.get('access_token')
    )
    session.headers.update({
        'accept': 'application/json',
        'User-Agent': 'Akamai-SIEM-Logstash-Collector/1.0'
    })

    _session = session
    _session_config_hash = config_hash
    logger.debug("创建新的API Session")

    return _session


def fetch_siem_events(config: Dict) -> Dict:
    """从Akamai SIEM API拉取事件"""
    akamai_config = config.get("akamai", {})

    # 构建API端点
    base_url = akamai_config.get('base_url')
    if not base_url:
        raise ValueError("缺少必要的配置参数: base_url")

    base_url = base_url.rstrip('/')
    endpoint = f"{base_url}/siem/v1/configs/{akamai_config.get('configId')}"

    # 构建查询参数
    if config["run_mode"] == "service" and config["mode"] == "time-based":
        params = {}
    else:
        params = {"limit": config.get("limit")}

    if config["mode"] == "offset":
        params["offset"] = config.get("offset")
    else:
        # time-based模式
        if "from_time" in config:
            params["from"] = config["from_time"]
        else:
            from_time = datetime.now(timezone.utc) - timedelta(minutes=5)
            params["from"] = from_time.timestamp()

        if "to_time" in config:
            params["to"] = config["to_time"]
            config['next_time'] = config["to_time"]
        else:
            to_time = datetime.now(timezone.utc)
            params["to"] = to_time.timestamp()
            config['next_time'] = to_time.timestamp()

    # 获取可复用的 Session
    session = _get_session(akamai_config)

    logger.info(f"调用API: {endpoint}")
    logger.debug(f"参数: {params}")

    # 获取重试配置
    max_retries = akamai_config.get('max_retries', 3)
    retry_delay = akamai_config.get('retry_delay', 5)
    timeout = akamai_config.get('api_timeout', 30)

    last_exception: Optional[Exception] = None

    for attempt in range(max_retries + 1):
        try:
            response = session.get(
                endpoint,
                params=params,
                timeout=(timeout, timeout)
            )

            logger.debug(f"响应状态码: {response.status_code}")
            logger.debug(f"响应头: {dict(response.headers)}")

            if len(response.text) < 1000:
                logger.debug(f"响应内容: {response.text}")
            else:
                logger.debug(f"响应内容长度: {len(response.text)} 字符")

            response.raise_for_status()

            result = _parse_siem_response(response.text, config)
            logger.info(f"API响应成功，获取到 {len(result.get('data', []))} 条日志")
            return result

        except requests.exceptions.ConnectionError as e:
            logger.error(f"连接错误 (尝试 {attempt+1}/{max_retries+1}): {e}")
            last_exception = e
        except requests.exceptions.Timeout as e:
            logger.error(f"请求超时 (尝试 {attempt+1}/{max_retries+1}): {e}")
            last_exception = e
        except requests.exceptions.HTTPError as e:
            status_code = e.response.status_code if hasattr(e, 'response') and e.response else "未知"
            logger.error(f"HTTP错误 {status_code} (尝试 {attempt+1}/{max_retries+1}): {e}")
            last_exception = e
            # 某些HTTP错误不需要重试
            if status_code in [400, 401, 403, 404]:
                logger.error(f"错误状态码 {status_code}，无需重试")
                if hasattr(e, 'response') and e.response:
                    try:
                        error_detail = e.response.json()
                        logger.error(f"错误详情: {json.dumps(error_detail)}")
                    except Exception:
                        logger.error(f"响应内容: {e.response.text}")
                raise
        except json.JSONDecodeError as e:
            logger.error(f"JSON解析错误 (尝试 {attempt+1}/{max_retries+1}): {e}")
            last_exception = e
            if 'response' in locals() and hasattr(response, 'text'):
                response_text = response.text
                start_pos = max(0, e.pos - 50)
                end_pos = min(len(response_text), e.pos + 100)
                logger.error(f"错误位置附近的内容: {response_text[start_pos:end_pos]}")
        except requests.exceptions.RequestException as e:
            logger.error(f"API请求失败 (尝试 {attempt+1}/{max_retries+1}): {e}")
            last_exception = e
        except Exception as e:
            logger.error(f"未知错误 (尝试 {attempt+1}/{max_retries+1}): {e}")
            import traceback
            logger.error(f"错误堆栈: {traceback.format_exc()}")
            last_exception = e

        # 如果不是最后一次尝试，等待后重试
        if attempt < max_retries:
            wait_time = retry_delay * (2 ** attempt)  # 指数退避
            logger.info(f"{wait_time}秒后重试...")
            time.sleep(wait_time)

    # 所有重试均失败
    logger.error(f"已达到最大重试次数 {max_retries}")
    raise RuntimeError(
        f"API调用失败，已重试{max_retries}次: {last_exception}"
    ) from last_exception


def _parse_siem_response(response_text: str, config: Dict) -> Dict:
    """解析SIEM API的响应内容

    根据SIEM官方文档：响应包含一系列换行分隔的JSON对象，
    每个对象对应一个安全事件，最后一行是偏移量上下文对象。

    使用逐行迭代避免一次性创建完整行列表，减少内存分配。
    """
    import io

    result_data = []
    site = config["site"]

    logger.debug(f"响应内容长度: {len(response_text)} 字符")

    line_count = 0
    for line in io.StringIO(response_text):
        line = line.strip()
        if not line:
            continue

        line_count += 1
        try:
            obj = json.loads(line)
            obj["site"] = site
            result_data.append(obj)
        except json.JSONDecodeError as e:
            logger.error(f"行 {line_count} JSON解析错误: {e}")
            logger.debug(f"错误行内容: {line[:500]}...")

    # 检查最后一个元素是否为偏移量上下文对象
    metadata = {}
    if result_data and isinstance(result_data[-1], dict):
        last_obj = result_data[-1]
        if "total" in last_obj or "offset" in last_obj or "limit" in last_obj:
            metadata = result_data.pop()
            logger.debug(f"从数据末尾找到偏移量上下文对象: {metadata}")

    logger.info(f"成功解析 {len(result_data)} 条安全事件")
    if metadata:
        logger.debug(
            f"偏移量上下文: 总记录数={metadata.get('total', 'N/A')}, "
            f"下一批偏移量={metadata.get('offset', 'N/A')}, "
            f"限制={metadata.get('limit', 'N/A')}"
        )

    return {"data": result_data, "metadata": metadata}
