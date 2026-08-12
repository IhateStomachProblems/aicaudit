import ast

from codeaudit.rules.base import Finding, Rule, Severity, register


@register
class BareExcept(Rule):
    id = "Q001"
    name = "bare-except"
    severity = Severity.WARNING
    description = "Detect bare except: clauses that catch all exceptions"
    description_zh = "检测捕获所有异常的裸except语句"

    def check(self, tree, context):
        findings = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.ExceptHandler):
                continue
            if node.type is None:
                findings.append(Finding(
                    rule_id=self.id,
                    message="Bare except: catches all exceptions, consider except Exception:",
                    message_zh="裸except会捕获所有异常，建议改为 except Exception:",
                    file=str(context.file_path),
                    line=node.lineno or 0,
                    severity=self.severity,
                    snippet=context.lines[node.lineno - 1].strip() if node.lineno else None,
                    fix="except Exception: instead of bare except:",
                ))
        return findings
