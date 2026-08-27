"""JSON output formatter."""

import json

from aicaudit.rules.base import Finding


def dump_json(findings: list[Finding], lang: str = "en") -> str:
    """Serialize findings to JSON string."""
    records = []
    for f in findings:
        records.append({
            "rule_id": f.rule_id,
            "message": f.text(lang),
            "file": f.file,
            "line": f.line,
            "severity": f.severity.value,
            "snippet": f.snippet,
            "fix": f.fix,
        })
    return json.dumps({"findings": records, "total": len(records)}, indent=2, ensure_ascii=False)
