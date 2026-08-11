"""Detect hardcoded secrets: passwords, API keys, tokens."""

import ast
import re

from codeaudit.rules.base import Finding, Rule, ScanContext, Severity, register

SENSITIVE_NAMES = re.compile(
    r"(api[_-]?key|secret|token|password|passwd|pwd|auth|credential)", re.IGNORECASE
)
KEY_PATTERNS = re.compile(
    r"(sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{36,}|AKIA[0-9A-Z]{16}|"
    r"AIza[0-9A-Za-z_-]{35}|xox[baprs]-[0-9A-Za-z-]{10,}|"
    r"[a-z0-9]{32,})"
)


@register
class SecretLeak(Rule):
    id = "S002"
    name = "secret-leak"
    severity = Severity.CRITICAL
    description = "Detect hardcoded API keys, passwords, and tokens"
    description_zh = "检测硬编码的API密钥、密码和令牌"

    def check(self, tree: ast.AST, context: ScanContext) -> list[Finding]:
        findings = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            for target in node.targets:
                if not isinstance(target, ast.Name):
                    continue
                if not SENSITIVE_NAMES.search(target.id):
                    continue
                value = node.value
                if isinstance(value, ast.Constant) and isinstance(value.value, str):
                    val: str = value.value
                    if KEY_PATTERNS.search(val):
                        findings.append(self._make(target, value, context))
                    elif len(val) >= 16 and not val.isdigit():
                        # Long string assigned to a sensitive name — likely a secret
                        findings.append(self._make(target, value, context))
        return findings

    def _make(self, target: ast.Name, value: ast.Constant, ctx: ScanContext) -> Finding:
        line = target.lineno or 0
        return Finding(
            rule_id=self.id,
            message=f"Hardcoded secret in variable '{target.id}'",
            message_zh=f"变量 '{target.id}' 中硬编码了密钥",
            file=str(ctx.file_path),
            line=line,
            severity=self.severity,
            snippet=ctx.lines[line - 1].strip() if line else None,
            fix="Load from environment variable: os.environ['" + target.id.upper() + "']",
        )
