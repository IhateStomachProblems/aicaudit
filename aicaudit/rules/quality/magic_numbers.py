import ast

from aicaudit.rules.base import Finding, Rule, Severity, register

ALLOWED = {0, 1, -1, 100}

# Common logic numbers (ranges, indexes, counters)
COMMON_NUMBERS = {
    2, 3, 4, 5, 6, 7, 8, 9, 10,
    16, 24, 30, 31, 32, 60, 64, 100, 128, 144, 256, 512, 1024,
}

# HTTP status codes (common)
HTTP_CODES = {
    200, 201, 202, 204, 301, 302, 303, 304, 307, 308,
    400, 401, 402, 403, 404, 405, 406, 408, 409, 410, 411,
    412, 413, 415, 422, 429, 451,
    500, 501, 502, 503, 504, 505,
}

# Common ports
COMMON_PORTS = {
    21, 22, 23, 25, 53, 80, 110, 123, 143, 161, 443, 445,
    465, 514, 543, 587, 631, 636, 993, 995, 1433, 1521, 2049,
    2375, 2376, 3128, 3306, 3389, 4333, 4444, 5000, 5432, 5500,
    5900, 5901, 5984, 6379, 6443, 6666, 7001, 7070, 8080, 8090,
    8443, 8888, 9000, 9090, 9200, 9300, 11211, 27017, 27018,
}

# Common time constants (seconds)
TIME_CONSTANTS = {
    3600, 7200, 86400, 172800, 2592000, 5184000, 7776000,
}


def _is_module_const(tree, node, value):
    if isinstance(node, ast.Assign) and len(node.targets) == 1:
        target = node.targets[0]
        if isinstance(target, ast.Name) and target.id.isupper():
            return True
    return False


@register
class MagicNumbers(Rule):
    id = "Q002"
    name = "magic-numbers"
    severity = Severity.INFO
    description = "Detect unexplained numeric literals (magic numbers)"
    description_zh = "检测未命名的数字字面量（魔法数字）"

    def check(self, tree, context):
        # Precompute named constants (module-level UPPER_CASE assignments)
        named_consts = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and len(node.targets) == 1:
                target = node.targets[0]
                if (isinstance(target, ast.Name) and target.id.isupper()
                        and isinstance(node.value, ast.Constant)):
                    named_consts.add(id(node.value))

        SAFE = ALLOWED | COMMON_NUMBERS | HTTP_CODES | COMMON_PORTS | TIME_CONSTANTS

        findings = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Constant):
                continue
            if not isinstance(node.value, int):
                continue
            if node.value in SAFE:
                continue
            if abs(node.value) <= 10:
                continue
            if id(node) in named_consts:
                continue
            findings.append(Finding(
                rule_id=self.id,
                message=f"Magic number {node.value}: consider naming it as a constant",
                message_zh=f"魔法数字 {node.value}：建议定义为常量",
                file=str(context.file_path),
                line=node.lineno or 0,
                severity=self.severity,
                snippet=context.lines[node.lineno - 1].strip() if node.lineno else None,
            ))
        return findings
