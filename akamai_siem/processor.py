"""
日志处理模块 - 基于配置的字段处理（性能优化版）

支持的处理操作类型：
- drop: 按字段值丢弃整条事件
- url_decode: URL解码指定字段
- replace: 字符串替换
- base64_expand: 对字段做 URL解码 + 分号分割 + Base64解码，展开为结构化数组

配置示例见 config.yaml 中的 "processing" 段。
"""

import re
import base64
from urllib.parse import unquote
from typing import Any, Dict, List, Optional, Tuple

from .logging_setup import logger

# 默认处理规则（与原始硬编码逻辑等价）
DEFAULT_PROCESSING_RULES = {
    "drop_rules": [
        {
            "field": "httpMessage.status",
            "values": [204, "204"]
        }
    ],
    "field_transforms": [
        {
            "field": "httpMessage.requestHeaders",
            "operations": [
                {"type": "url_decode"},
                {"type": "replace", "old": "\r\n", "new": " "},
                {"type": "replace", "old": "\"", "new": "'"}
            ]
        },
        {
            "field": "httpMessage.responseHeaders",
            "operations": [
                {"type": "url_decode"},
                {"type": "replace", "old": "\r\n", "new": " "},
                {"type": "replace", "old": "\"", "new": "'"}
            ]
        }
    ],
    "attack_data_decode": {
        "enabled": True,
        "source_field": "attackData",
        "target_field": "attackRules",
        "key_pattern": "^rule",
        "remove_decoded_keys": True
    }
}


# ============================================================
# 预编译的处理上下文（避免每条日志重复解析配置）
# ============================================================

class _DropRule:
    """预编译的丢弃规则"""
    __slots__ = ('path_parts', 'values_set')

    def __init__(self, field_path: str, values: list):
        self.path_parts: Tuple[str, ...] = tuple(field_path.split("."))
        self.values_set: frozenset = frozenset(values)


class _FieldTransform:
    """预编译的字段转换规则"""
    __slots__ = ('path_parts', 'operations')

    def __init__(self, field_path: str, operations: List[Dict]):
        self.path_parts: Tuple[str, ...] = tuple(field_path.split("."))
        # 预解析操作列表为元组，避免重复 dict.get
        self.operations: Tuple[tuple, ...] = tuple(
            self._parse_op(op) for op in operations
        )

    @staticmethod
    def _parse_op(op: Dict) -> tuple:
        op_type = op.get("type", "")
        if op_type == "replace":
            return ("replace", op.get("old", ""), op.get("new", ""))
        return (op_type,)


class _AttackDecodeConfig:
    """预编译的 attackData 解码配置"""
    __slots__ = ('enabled', 'source_field', 'target_field', 'pattern', 'remove_decoded')

    def __init__(self, config: Dict):
        self.enabled: bool = config.get("enabled", False)
        self.source_field: str = config.get("source_field", "attackData")
        self.target_field: str = config.get("target_field", "attackRules")
        self.remove_decoded: bool = config.get("remove_decoded_keys", True)
        key_pattern = config.get("key_pattern", "^rule")
        self.pattern: Optional[re.Pattern] = re.compile(key_pattern) if self.enabled else None


class _ProcessingContext:
    """预编译的完整处理上下文，在 process_logs 入口创建一次"""
    __slots__ = ('drop_rules', 'field_transforms', 'attack_decode')

    def __init__(self, processing_config: Dict):
        # 预编译丢弃规则
        self.drop_rules: Tuple[_DropRule, ...] = tuple(
            _DropRule(rule.get("field", ""), rule.get("values", []))
            for rule in processing_config.get("drop_rules", [])
        )

        # 预编译字段转换
        self.field_transforms: Tuple[_FieldTransform, ...] = tuple(
            _FieldTransform(t.get("field", ""), t.get("operations", []))
            for t in processing_config.get("field_transforms", [])
        )

        # 预编译 attackData 解码配置
        self.attack_decode = _AttackDecodeConfig(
            processing_config.get("attack_data_decode", {})
        )


# ============================================================
# 公开接口
# ============================================================

def process_logs(logs: List[Dict], config: Dict) -> List[Dict]:
    """处理日志列表

    :param logs: 原始日志列表
    :param config: 完整配置（从中读取 processing 段）
    :return: 处理后的日志列表（已过滤丢弃的事件）
    """
    processing_config = config.get("processing", {})

    # 如果未配置 processing，不做任何字段处理，直接返回原始日志
    if not processing_config:
        return list(logs)

    # 创建预编译上下文（一次性开销）
    ctx = _ProcessingContext(processing_config)

    # 单线程顺序处理，直接构建结果列表
    processed_logs = []
    for log in logs:
        result = _process_single_log(log, ctx)
        if result is not None:
            processed_logs.append(result)

    return processed_logs


# ============================================================
# 内部处理函数
# ============================================================

def _process_single_log(log: Dict, ctx: _ProcessingContext) -> Optional[Dict]:
    """根据预编译上下文处理单条日志"""
    try:
        # 1. 丢弃规则
        for rule in ctx.drop_rules:
            value = _get_by_parts(log, rule.path_parts)
            if value is not None and value in rule.values_set:
                return None

        # 2. 字段转换
        for transform in ctx.field_transforms:
            _apply_transform(log, transform)

        # 3. attackData 解码
        if ctx.attack_decode.enabled:
            _decode_attack_data(log, ctx.attack_decode)

        return log
    except Exception as e:
        logger.error(f"处理单条日志失败: {e}")
        return None


def _get_by_parts(obj: Dict, parts: Tuple[str, ...]) -> Any:
    """通过预分割的路径元组获取嵌套字段值"""
    current = obj
    for part in parts:
        if isinstance(current, dict):
            current = current.get(part)
            if current is None:
                return None
        else:
            return None
    return current


def _set_by_parts(obj: Dict, parts: Tuple[str, ...], value: Any) -> None:
    """通过预分割的路径元组设置嵌套字段值"""
    current = obj
    for part in parts[:-1]:
        if isinstance(current, dict):
            current = current.get(part)
            if current is None:
                return
        else:
            return
    if isinstance(current, dict):
        current[parts[-1]] = value


def _apply_transform(log: Dict, transform: _FieldTransform) -> None:
    """对指定字段依次应用预编译的转换操作"""
    value = _get_by_parts(log, transform.path_parts)
    if not isinstance(value, str):
        return

    for op in transform.operations:
        op_type = op[0]
        if op_type == "url_decode":
            value = unquote(value)
        elif op_type == "replace":
            value = value.replace(op[1], op[2])
        # 未知类型静默跳过（已在配置加载时可校验）

    _set_by_parts(log, transform.path_parts, value)


def _decode_attack_data(log: Dict, decode_cfg: _AttackDecodeConfig) -> None:
    """解码 attackData 中匹配模式的字段"""
    attack_data = log.get(decode_cfg.source_field)
    if not isinstance(attack_data, dict):
        return

    pattern = decode_cfg.pattern
    rules_array: List[Dict] = []
    del_keys: List[str] = []

    for member in list(attack_data.keys()):
        if not pattern.match(member):
            continue

        try:
            member_as_singular = member[:-1] if member.endswith('s') else member

            # URL解码，并移除末尾的分号
            url_decoded = unquote(attack_data[member]).rstrip(';')

            # 按分号分割
            member_array = url_decoded.split(";")

            # 初始化rules_array
            if not rules_array:
                rules_array = [{} for _ in range(len(member_array))]

            # Base64解码
            for i, item in enumerate(member_array):
                if not item:
                    continue

                try:
                    decoded_bytes = base64.b64decode(item)
                    try:
                        decoded_item = decoded_bytes.decode('utf-8')
                    except UnicodeDecodeError:
                        logger.warning(f"无法将{member}的第{i}项解码为UTF-8字符串")
                        decoded_item = 'Is not UTF_8 string -- fei'

                    rules_array[i][member_as_singular] = decoded_item
                except Exception:
                    logger.error(f"无法解码{member}中的Base64字符串 '{item}'")
                    if i < len(rules_array):
                        rules_array[i][member_as_singular] = None

            del_keys.append(member)
        except Exception as e:
            logger.error(f"处理{decode_cfg.source_field}中的'{member}'字段失败: {e}")
            continue

    if rules_array:
        log[decode_cfg.target_field] = rules_array
        if decode_cfg.remove_decoded:
            for key in del_keys:
                del attack_data[key]
