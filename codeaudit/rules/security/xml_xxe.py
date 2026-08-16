"""Detect XML External Entity processing (CWE-611)."""
import ast

from codeaudit.rules.base import Finding, Rule, Severity, register


def _is_unsafe_xml(func):
    """Check if a function name looks like an unsafe XML parser."""
    lower = func.lower()
    if "etree" in lower and "parse" in lower:
        return True
    if "lxml" in lower and ("parse" in lower or "fromstring" in lower):
        return True
    if "sax" in lower and "parse" in lower:
        return True
    if "minidom" in lower and "parse" in lower:
        return True
    if "xml.dom" in lower and "parse" in lower:
        return True
    if func in ("ET.parse", "etree.parse", "ET.fromstring"):
        return True
    return False


@register
class XXE(Rule):
    id = "S007"
    name = "xxe"
    severity = Severity.ERROR
    description = "Detect XXE: XML parsing without entity resolution disabled"
    description_zh = "检测XXE：未禁用实体解析的XML解析"

    def check(self, tree, context):
        findings = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = _func_name(node.func)
            if not _is_unsafe_xml(func):
                continue
            # Skip if resolve_entities=False is explicitly set
            if any(kw.arg == "resolve_entities" for kw in node.keywords):
                continue
            findings.append(self._make(node, func, context))
        return findings

    def _make(self, node, func, ctx):
        return Finding(rule_id=self.id,
                       message="XXE risk: XML parser without entity resolution disabled",
                       message_zh="XXE风险：未禁用实体解析的XML解析器",
                       file=str(ctx.file_path), line=node.lineno or 0,
                       severity=self.severity,
                       fix="Disable external entities: XMLParser(resolve_entities=False)")


def _func_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parts = []
        cur = node
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
        return ".".join(reversed(parts))
    return ""
