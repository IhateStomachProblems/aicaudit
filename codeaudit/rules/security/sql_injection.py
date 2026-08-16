import ast

from codeaudit.rules.base import Finding, Rule, Severity, register

DANGEROUS_METHODS = {"execute", "executemany", "executescript"}
SQL_KEYWORDS = {"select", "insert", "update", "delete", "create", "drop", "alter"}


def _is_dynamic_string(node):
    if isinstance(node, ast.JoinedStr):
        for v in node.values:
            if isinstance(v, ast.FormattedValue):
                return True
        return False
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return True
    return False


def _is_percent_format(node):
    """Detect %-formatting: "SELECT ... WHERE id = %s" % user_input"""
    # BinOp(Mod): left is string with %s/%d, right is the interpolated value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
        left = node.left
        if isinstance(left, ast.Constant) and isinstance(left.value, str) and any(p in left.value for p in ("%s", "%d", "%r", "%f", "%(name)s")):
            return True
    return False


def _is_format_string(node):
    """Detect .format() method call on strings."""
    if isinstance(node, ast.Call):
        return (isinstance(node.func, ast.Attribute)
                and node.func.attr == "format"
                and isinstance(node.func.value, ast.Constant)
                and isinstance(node.func.value.value, str))
    return False

def _is_variable(node):
    """True if the node is a variable reference (not a literal)."""
    return isinstance(node, (ast.Name, ast.Attribute))


def _is_parametrized(call):
    """True if the SQL call uses parameterized args."""
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

            # Case 1: f-string / concat / %-format / .format() → dynamic → risk
            if _is_dynamic_string(sql_arg) or _is_format_string(sql_arg) or _is_percent_format(sql_arg):
                findings.append(self._make(sql_arg, context))
                continue

            # Case 2: variable passed to execute → flag unless parameterized
            if _is_variable(sql_arg):
                if not _is_parametrized(node):
                    findings.append(self._make(sql_arg, context))
                continue

            # Case 3: plain string literal → safe (no external input)
            # conn.execute("SELECT 1") or conn.execute("SELECT * FROM t", params) are fine
            if isinstance(sql_arg, ast.Constant) and isinstance(sql_arg.value, str):
                continue

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
