"""Detect path traversal vulnerabilities (CWE-22)."""
import ast

from codeaudit.rules.base import Finding, Rule, Severity, register

FILE_OPENERS = {"open", "codecs.open"}
PATH_JOIN_FUNCS = {"os.path.join", "os.path.abspath", "os.path.realpath"}


@register
class PathTraversal(Rule):
    id = "S004"
    name = "path-traversal"
    severity = Severity.ERROR
    description = "Detect path traversal: user-controlled file paths"
    description_zh = "检测路径遍历：用户控制的文件路径"

    def check(self, tree, context):
        findings = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = _func_name(node.func)
            if func in FILE_OPENERS and node.args:
                arg = node.args[0]
                if isinstance(arg, (ast.Name, ast.Attribute)):
                    findings.append(self._make(node, func, context))
        return findings

    def _make(self, node, func, ctx):
        return Finding(rule_id=self.id, message=f"Path traversal risk: user input in '{func}()'",
                       message_zh=f"路径遍历风险：用户输入传入 '{func}()'", file=str(ctx.file_path),
                       line=node.lineno or 0, severity=self.severity,
                       snippet=ctx.lines[node.lineno - 1].strip() if node.lineno else None,
                       fix="Use os.path.abspath() and validate against allowed path")


def _func_name(node):
    if isinstance(node, ast.Name): return node.id
    if isinstance(node, ast.Attribute):
        parts = []; cur = node
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr); cur = cur.value
        if isinstance(cur, ast.Name): parts.append(cur.id)
        return ".".join(reversed(parts))
    return ""
