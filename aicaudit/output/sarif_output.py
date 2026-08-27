"""SARIF 2.1 output formatter — GitHub Code Scanning compatible."""

import json

from aicaudit.rules.base import Finding, Severity, all_rules

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

SEVERITY_MAP = {
    Severity.CRITICAL: "error",
    Severity.ERROR: "error",
    Severity.WARNING: "warning",
    Severity.INFO: "note",
}


def _ensure_rules():
    """Make sure all rule modules are imported (registers them)."""
    from aicaudit.scan import _import_all_rules
    _import_all_rules()


def _build_tool() -> dict:
    """Build the tool component."""
    _ensure_rules()
    rule_objs = [cls() for cls in all_rules()]
    return {
        "driver": {
            "name": "AICAudit",
            "version": "0.1.0",
            "informationUri": "https://github.com/IhateStomachProblems/aicaudit",
            "rules": [
                {
                    "id": r.id,
                    "name": r.name,
                    "shortDescription": {"text": r.description},
                    "fullDescription": {"text": r.description_zh if r.description_zh else r.description},
                    "defaultConfiguration": {"level": SEVERITY_MAP.get(r.severity, "warning")},
                    "properties": {"severity": r.severity.value, "tags": ["security", "code-quality"]},
                }
                for r in rule_objs
            ],
        }
    }


def _build_results(findings: list[Finding]) -> list[dict]:
    """Build results array from findings."""
    results = []
    for f in findings:
        msg_text = f.message + (f" Suggested fix: {f.fix}" if f.fix else "")
        result = {
            "ruleId": f.rule_id,
            "ruleIndex": -1,
            "level": SEVERITY_MAP.get(f.severity, "warning"),
            "message": {"text": msg_text},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.file},
                        "region": {
                            "startLine": f.line,
                            "snippet": {"text": f.snippet or ""},
                        },
                    }
                }
            ],
            "properties": {"severity": f.severity.value},
        }
        results.append(result)
    return results


def dump_sarif(findings: list[Finding], lang: str = "en") -> str:
    """Serialize findings to SARIF 2.1 JSON string."""
    _ensure_rules()
    sarif_doc = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": _build_tool(),
                "results": _build_results(findings),
                "columnKind": "utf16CodeUnits",
                "properties": {"language": lang},
            }
        ],
    }
    return json.dumps(sarif_doc, indent=2, ensure_ascii=False)
