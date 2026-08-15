"""Detect XML External Entity processing (CWE-611)."""
import ast

from codeaudit.rules.base import Finding, Rule, Severity, register


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
            # etree.parse / SAX / minidom without secure defaults
            if "etree" in func and "parse" in func:
                findings.append(self._make(node, func, context))
            elif "lxml" in func and ("parse" in func or "fromstring" in func):
                has_resolve = any(kw.arg == "resolve_entities" for kw in node.keywords)
                if not has_resolve:
                    findings.append(self._make(node, func, context))
            elif "sax" in func.lower() and "parse" in func.lower() or "minidom" in func and "parse" in func or "xml.dom" in func and "parse" in func:
                findings.append(self._make(node, func, context))
        return findings

    def _make(self, node, func, ctx):
        return Finding(rule_id=self.id, message="XXE risk: XML parser without entity resolution disabled",
                       message_zh="XXE风险：未禁用实体解析的XML解析器", file=str(ctx.file_path),
                       line=node.lineno or 0, severity=self.severity,
                       fix="Disable external entities: etree.set_default_parser() or parser=etree.XMLParser(resolve_entities=False)")


def _func_name(node):
    if isinstance(node, ast.Name): return node.id
    if isinstance(node, ast.Attribute):
        parts = []; cur = node
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr); cur = cur.value
        if isinstance(cur, ast.Name): parts.append(cur.id)
        return ".".join(reversed(parts))
    return ""
