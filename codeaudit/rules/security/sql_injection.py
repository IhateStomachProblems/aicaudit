import ast

from codeaudit.rules.base import Finding, Rule, Severity, register

DANGEROUS_METHODS = {"execute", "executemany", "executescript"}
SQL_KEYWORDS = {"select", "insert", "update", "delete", "create", "drop", "alter"}


def _join_text(node):
    """Extract readable text from a string node, including f-strings."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        parts = []
        for value in node.values:
            if isinstance(value, ast.Constant):
                parts.append(str(value.value))
            elif isinstance(value, ast.FormattedValue):
                parts.append("{...}")
        return "".join(parts)
    return None


def _contains_sql(text):
    lower = text.lower().strip()
    return any(lower.startswith(kw) for kw in SQL_KEYWORDS)


def _is_parametrized(call):
    if len(call.args) < 2:
        return False
    second = call.args[1]
    return isinstance(second, (ast.Tuple, ast.List, ast.Dict, ast.Name))


@register
class SqlInjection(Rule):
    id = "S001"
    name = "sql-injection"
    severity = Severity.CRITICAL
    description = "Detect SQL queries built with string formatting or concatenation"
    description_zh = "检测使用字符串拼接或格式化构建的SQL查询"

    def check(self, tree, context):
        findings = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if not isinstance(node.func, ast.Attribute):
                continue
            if node.func.attr not in DANGEROUS_METHODS:
                continue
            if not node.args:
                continue

            sql_arg = node.args[0]
            text = _join_text(sql_arg)

            # A variable passed to execute - flag unless parameterized
            if text is None:
                if not _is_parametrized(node):
                    findings.append(self._make(sql_arg, context))
                continue

            if not _contains_sql(text):
                continue

            # Parameterized queries are safe
            if _is_parametrized(node):
                continue

            # Non-parameterized SQL: f-strings, concatenation, or plain literal
            # are all injection risks when built without parameters
            findings.append(self._make(sql_arg, context))

        return findings

    def _make(self, node, ctx):
        return Finding(
            rule_id=self.id,
            message="SQL injection risk: query built with string formatting",
            message_zh="SQL注入风险：使用字符串拼接构建查询",
            file=str(ctx.file_path),
            line=node.lineno or 0,
            severity=self.severity,
            snippet=ctx.lines[node.lineno - 1].strip() if node.lineno else None,
            fix="Use parameterized queries: cursor.execute('SELECT * FROM t WHERE id = ?', (id,))",
        )
