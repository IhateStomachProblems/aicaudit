"""Detect weak cryptographic algorithms (CWE-327)."""
import ast

from codeaudit.rules.base import Finding, Rule, Severity, register

WEAK_HASHES = {"md5", "sha1"}
WEAK_CIPHERS = {"DES", "DES3", "RC4", "ARC4", "Blowfish"}
WEAK_MODES = {"ECB"}


@register
class WeakCrypto(Rule):
    id = "S006"
    name = "weak-crypto"
    severity = Severity.WARNING
    description = "Detect weak cryptographic algorithms: MD5, SHA1, DES, RC4, ECB"
    description_zh = "检测弱加密算法：MD5、SHA1、DES、RC4、ECB"

    def check(self, tree, context):
        findings = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = _func_name(node.func)
                for w in WEAK_HASHES:
                    if w in func.lower():
                        findings.append(self._make(node, func, context))
                        break
                for w in WEAK_CIPHERS:
                    if w in func:
                        findings.append(self._make(node, func, context))
                        break
            if isinstance(node, ast.Attribute):
                for w in WEAK_MODES:
                    if w in node.attr:
                        findings.append(Finding(
                            rule_id=self.id, message=f"Weak encryption mode: {node.attr}",
                            message_zh=f"弱加密模式：{node.attr}", file=str(context.file_path), line=node.lineno or 0, severity=self.severity,
                            snippet=context.lines[node.lineno - 1].strip() if node.lineno else None))
        return findings

    def _make(self, node, func, context):
        return Finding(rule_id=self.id, message=f"Weak crypto: {func}",
                       message_zh=f"弱加密算法：{func}", file=str(context.file_path),
                       line=node.lineno or 0, severity=self.severity)


def _func_name(node):
    if isinstance(node, ast.Name): return node.id
    if isinstance(node, ast.Attribute):
        parts = []; cur = node
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr); cur = cur.value
        if isinstance(cur, ast.Name): parts.append(cur.id)
        return ".".join(reversed(parts))
    return ""
