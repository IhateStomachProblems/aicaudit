"""Detect insecure use of non-cryptographic random (CWE-338)."""
import ast

from codeaudit.rules.base import Finding, Rule, Severity, register

INSECURE_RANDOM_FUNCS = {
    "random.random", "random.randint", "random.randrange",
    "random.choice", "random.choices", "random.sample",
    "random.uniform", "random.triangular",
}

INSECURE_MODULES = {"random"}


@register
class InsecureRandom(Rule):
    id = "S008"
    name = "insecure-random"
    severity = Severity.WARNING
    description = "Detect non-cryptographic random used where crypto-safe random is expected"
    description_zh = "检测在安全场景中使用非加密安全的随机数"

    def check(self, tree, context):
        findings = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = _func_name(node.func)
            if func in INSECURE_RANDOM_FUNCS:
                findings.append(self._make(node, func, context))
        return findings

    def _make(self, node, func, ctx):
        return Finding(
            rule_id=self.id,
            message=f"Insecure random: '{func}()' is not cryptographically secure",
            message_zh=f"不安全的随机数：'{func}()' 不是加密安全的",
            file=str(ctx.file_path), line=node.lineno or 0,
            severity=self.severity,
            snippet=ctx.lines[node.lineno - 1].strip() if node.lineno else None,
            fix="Use secrets module: secrets.token_hex(), secrets.randbelow()",
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
