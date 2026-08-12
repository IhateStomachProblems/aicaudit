import re

from codeaudit.rules.base import Finding, Rule, Severity, register

TODO_RE = re.compile(r"#\s*(TODO|FIXME|HACK|XXX)\b", re.IGNORECASE)

@register
class TodoComment(Rule):
    id = "Q004"
    name = "todo-comment"
    severity = Severity.INFO
    description = "Detect TODO, FIXME, HACK, and XXX comments"
    description_zh = "检测TODO、FIXME、HACK和XXX注释"

    def check(self, tree, context):
        findings = []
        for i, line in enumerate(context.lines, 1):
            m = TODO_RE.search(line)
            if m:
                findings.append(Finding(
                    rule_id=self.id,
                    message=f"{m.group(1)} comment left in code",
                    message_zh=f"代码中遗留了{m.group(1)}注释",
                    file=str(context.file_path),
                    line=i,
                    severity=self.severity,
                    snippet=line.strip(),
                ))
        return findings
