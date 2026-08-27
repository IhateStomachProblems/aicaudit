"""Markdown output formatter."""

from aicaudit.rules.base import Finding


def dump_markdown(findings: list[Finding], lang: str = "en") -> str:
    """Render findings as markdown."""
    lines = ["# AICAudit Report", ""]
    severity_order = ["critical", "error", "warning", "info"]

    for sev in severity_order:
        group = [f for f in findings if f.severity.value == sev]
        if not group:
            continue
        heading = f"## {sev.upper()}"
        if lang == "zh":
            labels = {"critical": "严重", "error": "错误", "warning": "警告", "info": "提示"}
            heading = f"## {labels.get(sev, sev)}"
        lines.append(heading)
        lines.append("")

        for f in group:
            desc = f.text(lang)
            lines.append(f"### {f.rule_id}: {desc}")
            lines.append("")
            lines.append(f"- **File**: `{f.file}:{f.line}`")
            if f.snippet:
                lines.append(f"- **Snippet**: `{f.snippet}`")
            if f.fix:
                lines.append(f"- **Fix**: {f.fix}")
            lines.append("")

    return "\n".join(lines)
