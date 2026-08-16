"""Detect path traversal (CWE-22): user-controlled paths in file operations."""
import ast

from codeaudit.rules.base import Finding, Rule, Severity, register

FILE_OPENERS = {"open", "codecs.open"}
SUSPICIOUS_JOIN = {"os.path.join", "os.path.abspath", "os.path.realpath"}


def _is_variable(node):
    return isinstance(node, (ast.Name, ast.Attribute))


def _is_dynamic_path(node):
    """True if the path expression contains dynamic content (user input)."""
    # f-string with interpolation: f"/dir/{name}"
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(v, ast.FormattedValue) for v in node.values)
    # string concatenation: "/dir/" + name
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return True
    # function call: open(get_input()) - clearly user input
    return isinstance(node, ast.Call)


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

            # Pattern 1: open(variable_or_dynamic_path)
            if func in FILE_OPENERS and node.args:
                if _is_dynamic_path(node.args[0]):
                    findings.append(self._make(node, func, context))
                continue

            # Pattern 2: os.path.join(variable, ...) or similar
            if func in SUSPICIOUS_JOIN and node.args:
                for arg in node.args:
                    if isinstance(arg, ast.Call):
                        findings.append(self._make_join(node, func, context))
                        break

        return findings

    def _make(self, node, func, ctx):
        return Finding(rule_id=self.id, message=f"Path traversal: user input in '{func}()'",
                       message_zh=f"路径遍历：用户输入传入 '{func}()'",
                       file=str(ctx.file_path), line=node.lineno or 0, severity=self.severity,
                       snippet=ctx.lines[node.lineno - 1].strip() if node.lineno else None,
                       fix="Validate and sanitize the path: use os.path.abspath() + allowed path check")

    def _make_join(self, node, func, ctx):
        return Finding(rule_id=self.id, message="Path traversal: os.path.join() with user input",
                       message_zh="路径遍历：os.path.join() 包含用户输入",
                       file=str(ctx.file_path), line=node.lineno or 0, severity=self.severity,
                       snippet=ctx.lines[node.lineno - 1].strip() if node.lineno else None,
                       fix="Whitelist allowed paths before joining with user input")


def _func_name(node):
    if isinstance(node, ast.Name): return node.id
    if isinstance(node, ast.Attribute):
        parts = []
        cur = node
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr); cur = cur.value
        if isinstance(cur, ast.Name): parts.append(cur.id)
        return ".".join(reversed(parts))
    return ""
