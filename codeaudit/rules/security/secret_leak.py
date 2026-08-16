"""Detect hardcoded secrets: passwords, API keys, tokens, certificates, database URLs."""

import ast
import re

from codeaudit.rules.base import Finding, Rule, Severity, register

SENSITIVE_NAMES = re.compile(
    r"(api[_-]?key|secret|token|password|passwd|pwd|auth|credential|"
    r"private[_-]?key|certificate|pem|cert|key|access[_-]?key|"
    r"secret[_-]?key|app[_-]?secret|consumer[_-]?secret|"
    r"db_url|db[_-]?url|database[_-]?url|jdbc|connection[_-]?string|redis_url|"
    r"client[_-]?secret|bearer)", re.IGNORECASE
)

KEY_PATTERNS = re.compile(
    r"(sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{36,}|gho_[a-zA-Z0-9]{36,}|"
    r"ghu_[a-zA-Z0-9]{36,}|ghs_[a-zA-Z0-9]{36,}|"
    r"AKIA[0-9A-Z]{16}|"
    r"AIza[0-9A-Za-z_-]{35}|"
    r"xox[baprs]-[0-9A-Za-z-]{10,}|"
    r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----|"
    r"pk_[a-zA-Z0-9]{20,}|"
    r"sk_live_[a-zA-Z0-9]{20,}|"
    r"rk_live_[a-zA-Z0-9]{20,}|"
    r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}|"
    r"mongodb(?::\+srv)?://[a-zA-Z0-9]+:[^@]+@|"
    r"postgresql://[a-zA-Z0-9]+:[^@]+@|"
    r"mysql://[a-zA-Z0-9]+:[^@]+@|"
    r"redis://(:[^@]*@|[a-zA-Z0-9]+:[^@]+@)|"
    r"https://[a-zA-Z0-9]+:[^@]+@)",
    re.IGNORECASE
)


@register
class SecretLeak(Rule):
    id = "S002"
    name = "secret-leak"
    severity = Severity.CRITICAL
    description = "Detect hardcoded API keys, passwords, tokens, certificates, and database URLs"
    description_zh = "检测硬编码的API密钥、密码、令牌、证书和数据库URL"

    def check(self, tree, context):
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
                    val = value.value
                    if KEY_PATTERNS.search(val) or len(val) >= 16 and not val.isdigit():
                        findings.append(self._make(target, value, context))
        return findings

    def _make(self, target, value, ctx):
        line = target.lineno or 0
        return Finding(
            rule_id=self.id,
            message=f"Hardcoded secret in variable '{target.id}'",
            message_zh=f"变量 '{target.id}' 中硬编码了密钥",
            file=str(ctx.file_path), line=line, severity=self.severity,
            snippet=ctx.lines[line - 1].strip() if line else None,
            fix="Load from environment variable: os.environ['" + target.id.upper() + "']",
        )
