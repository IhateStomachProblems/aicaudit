import ast

from codeaudit.rules.base import Finding, Rule, Severity, register

DANGEROUS = {
    "eval": Severity.CRITICAL,
    "exec": Severity.CRITICAL,
    "pickle.loads": Severity.CRITICAL,
    "os.system": Severity.ERROR,
    "subprocess.call": Severity.WARNING,
    "subprocess.Popen": Severity.WARNING,
    "subprocess.run": Severity.WARNING,
    "yaml.load": Severity.ERROR,
    "input": Severity.WARNING,
}

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
                line = node.lineno or 0
                findings.append(Finding(
                    rule_id=self.id,
                    message=f"Use of dangerous function '{func}'",
                    message_zh=f"使用了危险函数 '{func}'",
                    file=str(context.file_path),
                    line=line,
                    severity=sev,
                    snippet=context.lines[line - 1].strip() if line else None,
                    fix=f"Avoid '{func}()'. Use a safe alternative or validate input strictly.",
                ))
        return findings


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
