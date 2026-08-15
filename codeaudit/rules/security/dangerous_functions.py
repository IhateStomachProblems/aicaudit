import ast

from codeaudit.rules.base import Finding, Rule, Severity, register

DANGEROUS = {
    "eval": Severity.CRITICAL,
    "exec": Severity.CRITICAL,
    "pickle.loads": Severity.CRITICAL,
    "os.system": Severity.ERROR,
    "yaml.load": Severity.ERROR,
    "input": Severity.WARNING,
}

# Subprocess functions: dangerous only when shell=True
SUBPROCESS_FUNCS = {"subprocess.call", "subprocess.Popen", "subprocess.run"}


@register
class DangerousFunctions(Rule):
    id = "S003"
    name = "dangerous-functions"
    severity = Severity.ERROR
    description = "Detect eval, exec, pickle, and shell invocation"
    description_zh = "检测eval、exec、pickle和shell调用等危险函数"

    def check(self, tree, context):
        findings = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = _func_name(node.func)
            if func in DANGEROUS:
                sev = DANGEROUS[func]
                findings.append(self._make(node, func, sev, context))
            elif func in SUBPROCESS_FUNCS and _has_shell_true(node):
                findings.append(self._make(node, func, Severity.WARNING, context))
        return findings

    def _make(self, node, func, sev, ctx):
        line = node.lineno or 0
        return Finding(
            rule_id=self.id,
            message=f"Use of dangerous function '{func}'",
            message_zh=f"使用了危险函数 '{func}'",
            file=str(ctx.file_path),
            line=line,
            severity=sev,
            snippet=ctx.lines[line - 1].strip() if line else None,
            fix=f"Avoid '{func}()'. Use a safe alternative or validate input strictly.",
        )


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


def _has_shell_true(call):
    """Check if call has keyword argument shell=True."""
    for kw in call.keywords:
        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
            return True
    return False
