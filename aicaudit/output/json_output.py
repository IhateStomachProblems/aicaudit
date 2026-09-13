"""JSON output formatter."""

import json

from aicaudit.rules.base import Finding


def dump_json(findings: list[Finding], lang: str = "en") -> str:
    """Serialize findings to JSON string."""
    records = []
    for f in findings:
        rec = {
            "rule_id": f.rule_id,
            "message": f.text(lang),
            "file": f.file,
            "line": f.line,
            "severity": f.severity.value,
            "snippet": f.snippet,
            "fix": f.fix,
            "cwe": f.cwe,
        }
        if f.taint_path:
            rec["taint_path"] = [p.to_dict() for p in f.taint_path]
        if f.ai:
            rec["ai"] = {
                "status": f.ai.get("ai_status", "unverified"),
                "confidence": f.ai.get("ai_confidence", 0.0),
                "reason": f.ai.get("ai_reason", ""),
                "severity": f.ai.get("ai_severity"),
                "cwe": f.ai.get("ai_cwe", ""),
                "suggested_fix": f.ai.get("ai_suggested_fix", ""),
            }
        records.append(rec)
    return json.dumps({"findings": records, "total": len(records)}, indent=2, ensure_ascii=False)
