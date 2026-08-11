import ast

from codeaudit.rules.base import Finding, Rule, Severity, register

DANGEROUS_METHODS = {"execute", "executemany", "executescript"}
SQL_KEYWORDS = {"select", "insert", "update", "delete", "create", "drop", "alter"}


def _is_f_string(node):
    for n in ast.walk(node):
        if isinstance(n, ast.JoinedStr):
            return True
    return False


def _is_string_concat(node):
    return isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add)


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

            if isinstance(sql_arg, ast.Constant) and isinstance(sql_arg.value, str):
                if not _contains_sql(sql_arg.value):
                    continue
                if _is_f_string(sql_arg) or _is_string_concat(sql_arg):
                    findings.append(self._make(sql_arg, context))
                elif _is_parametrized(node):
                    continue
                else:
                    findings.append(self._make(sql_arg, context))
                continue

            if isinstance(sql_arg, (ast.Name, ast.Attribute)):
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

