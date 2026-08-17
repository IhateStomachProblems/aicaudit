"""Detect Server-Side Request Forgery (CWE-918)."""
import ast

from codeaudit.rules.base import Finding, Rule, Severity, register

HTTP_CLIENTS = {
    "requests.get", "requests.post", "requests.put", "requests.delete",
    "requests.patch", "requests.request", "urlopen", "urllib.request.urlopen",
    "urlretrieve", "urllib.request.urlretrieve",
    "httpx.get", "httpx.post", "httpx.put", "httpx.Client",
    "aiohttp.ClientSession.get", "aiohttp.ClientSession.post",
}


@register
class SSRF(Rule):
    id = "S005"
    name = "ssrf"
    severity = Severity.ERROR
    description = "Detect SSRF: HTTP requests to user-controlled URLs"
    description_zh = "检测SSRF：用户可控URL的HTTP请求"

    def check(self, tree, context):
        findings = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = _func_name(node.func)
            if func in HTTP_CLIENTS and node.args:
                arg = node.args[0]
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    continue
                if _is_user_supplied(arg):
                    findings.append(self._make(node, func, context))
        return findings

    def _make(self, node, func, ctx):
        return Finding(rule_id=self.id, message=f"SSRF risk: user-controlled URL in '{func}()'",
                       message_zh=f"SSRF风险：用户可控URL传入 '{func}()'", file=str(ctx.file_path),
                       line=node.lineno or 0, severity=self.severity,
                       snippet=ctx.lines[node.lineno - 1].strip() if node.lineno else None,
                       fix="Validate URL against a whitelist of allowed domains")


def _is_user_supplied(node):
    return isinstance(node, (ast.Call, ast.Name, ast.Attribute))


def _func_name(node):
    if isinstance(node, ast.Name): return node.id
    if isinstance(node, ast.Attribute):
        parts = []; cur = node
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr); cur = cur.value
        if isinstance(cur, ast.Name): parts.append(cur.id)
        return ".".join(reversed(parts))
    return ""
