"""AICAudit MCP server — call the audit engine from any AI editor.

Run with `aicaudit mcp` (stdio transport). Requires the optional extra:

    pip install aicaudit[mcp]

Exposed tools are designed for agent consumption: compact JSON, explicit
taint paths, and three-state AI verdicts (confirmed / false_positive /
unverified) so an agent can reason about confidence instead of trusting
a boolean.
"""
from __future__ import annotations

import json
from pathlib import Path

from aicaudit.config import find_project_root
from aicaudit.scan import _import_all_rules
from aicaudit.scan import scan as run_scan


def _finding_dict(f, lang: str = "en") -> dict:
    d = {
        "rule_id": f.rule_id,
        "message": f.text(lang),
        "file": f.file,
        "line": f.line,
        "severity": f.severity.value,
        "cwe": f.cwe,
        "fix": f.fix,
    }
    if f.taint_path:
        d["taint_path"] = [p.render() for p in f.taint_path[:2]]
    if f.ai:
        d["ai"] = {
            "status": f.ai.get("ai_status", "unverified"),
            "confidence": f.ai.get("ai_confidence", 0.0),
            "reason": f.ai.get("ai_reason", ""),
            "suggested_fix": f.ai.get("ai_suggested_fix", ""),
        }
    return d


def _summary(findings) -> dict:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
    return {"total": len(findings), "by_severity": counts}


def scan_impl(paths: list[str], rules: str | None = None,
              min_severity: str | None = None, lang: str = "en",
              max_results: int = 50, ai_verify: bool = False) -> dict:
    """Core scan logic shared by the MCP tool (kept importable for tests)."""
    findings = run_scan(
        [Path(p) for p in paths],
        lang=lang,
        rules={r for r in (rules or "").split(",") if r} or None,
        min_severity=min_severity,
        base_root=find_project_root(Path(paths[0])),
        ai_verify=ai_verify,
    )
    serialized = [_finding_dict(f, lang) for f in findings]
    truncated = serialized[:max_results]
    return {
        "summary": _summary(findings),
        "findings": truncated,
        **({"note": f"showing first {max_results} of {len(findings)}; "
                    "narrow with rules/min_severity"} if len(findings) > max_results else {}),
    }


def rules_impl() -> list[dict]:
    """Rule catalog (kept importable for tests)."""
    _import_all_rules()
    from aicaudit.llm.prompts import INJECTION_RULES, POLICY_RULES
    from aicaudit.rules.base import all_rules
    out = []
    for cls in all_rules():
        out.append({
            "id": cls.id,
            "name": cls.name,
            "severity": cls.severity.value,
            "description": cls.description,
            "category": ("taint-aware" if cls.id in INJECTION_RULES
                         else "policy" if cls.id in POLICY_RULES else "quality"),
            "custom": not cls.id[0] in "SQP" or int(cls.id[1:] or 0) >= 100,
        })
    return sorted(out, key=lambda r: r["id"])


def verify_impl(paths: list[str], rules: str | None = None) -> dict:
    """Scan + attach AI verdicts (respects AICAUDIT_AI_* env config)."""
    result = scan_impl(paths, rules=rules, ai_verify=True)
    statuses = {"confirmed": 0, "false_positive": 0, "unverified": 0}
    for f in result["findings"]:
        if "ai" in f:
            statuses[f["ai"]["status"]] = statuses.get(f["ai"]["status"], 0) + 1
    return {
        "ai_summary": statuses,
        "note": ("verdicts are advisory marks; unverified means the AI could not "
                 "judge confidently — never treat missing verdicts as 'safe'"),
        **result,
    }


def explain_finding_impl(file: str, line: int, rule_id: str) -> dict:
    """Return the taint path + code context for one finding."""
    from aicaudit.llm.prompts import enclosing_function_source
    finding = None
    for f in run_scan([Path(file)], rules={rule_id}):
        if f.line == line:
            finding = f
            break
    if finding is None:
        return {"error": f"no {rule_id} finding at {file}:{line} — rescan to confirm"}
    try:
        source = Path(file).read_text(encoding="utf-8-sig", errors="replace")
        func = enclosing_function_source(source, line)
    except OSError:
        func = ""
    return {
        "finding": _finding_dict(finding),
        "taint_path_detail": [p.to_dict() for p in (finding.taint_path or [])[:2]],
        "enclosing_function": func or None,
        "snippet": finding.snippet,
    }


def fix_preview_impl(file: str, rule_id: str, line: int, fix: str | None = None) -> dict:
    """Dry-run the auto-fix and return the unified diff (no writes)."""
    import difflib

    from aicaudit.fix import fix_file

    for f in run_scan([Path(file)], rules={rule_id}):
        if f.line == line:
            finding = f
            break
    else:
        return {"error": f"no {rule_id} finding at {file}:{line}"}
    result = fix_file(file, [finding], dry_run=True, backup=False)
    diff = "".join(difflib.unified_diff(
        (result.before or "").splitlines(keepends=True),
        (result.after or "").splitlines(keepends=True),
        fromfile=Path(file).name, tofile=Path(file).name + " (fixed)", n=3))
    return {"changed": bool(diff), "diff": diff, "verified": result.verified,
            "note": "preview only — nothing written; apply fixes yourself or via the CLI"}


def build_server():
    """Create the FastMCP server (imported lazily so the extra stays optional)."""
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP("aicaudit")

    @mcp.tool()
    def scan(paths: list[str], rules: str | None = None,
             min_severity: str | None = None, max_results: int = 50) -> str:
        """Audit Python code for security issues with taint analysis.

        Returns findings with severity, CWE, and (when traced) the full
        user-input-to-sink taint path. Constants are proven safe and stay
        quiet, so output noise is low. Use before declaring code secure.

        Args:
            paths: files or directories to scan
            rules: optional comma-separated rule IDs (e.g. "S001,S003"); default all
            min_severity: optional floor ("info"|"warning"|"error"|"critical")
            max_results: cap on returned findings (default 50)
        """
        return json.dumps(
            scan_impl(paths, rules=rules, min_severity=min_severity,
                      max_results=max_results),
            ensure_ascii=False, indent=1)

    @mcp.tool()
    def list_rules() -> str:
        """List all audit rules: id, severity, CWE category, taint-awareness.

        Rule IDs starting S/Q/P are builtin; anything else is a project-local
        custom rule (from .aicaudit/rules/)."""
        return json.dumps(rules_impl(), ensure_ascii=False, indent=1)

    @mcp.tool()
    def verify(paths: list[str], rules: str | None = None) -> str:
        """Scan, then attach evidence-grounded AI verdicts to each finding.

        Verdicts: confirmed / false_positive / unverified (with confidence).
        Requires AICAUDIT_AI_* env vars (OpenAI-compatible relay, OpenAI,
        Claude, OpenRouter, or local ollama). Without config everything comes
        back unverified — treat that as 'no AI opinion', never as 'safe'."""
        return json.dumps(verify_impl(paths, rules=rules), ensure_ascii=False, indent=1)

    @mcp.tool()
    def explain_finding(file: str, line: int, rule_id: str) -> str:
        """Explain one finding: taint path hop-by-hop + enclosing function source.

        Use after `scan` when you need the evidence behind a finding — the
        source of the tainted data, every propagation step, and the sink."""
        return json.dumps(explain_finding_impl(file, line, rule_id),
                          ensure_ascii=False, indent=1)

    @mcp.tool()
    def fix_preview(file: str, rule_id: str, line: int) -> str:
        """Preview the auto-fix diff for a finding. Dry-run only, writes nothing.

        Supports the same rules as the CLI `--fix` flow (bare except, dangerous
        calls). For everything else the finding's `fix` field carries advice."""
        return json.dumps(fix_preview_impl(file, rule_id, line),
                          ensure_ascii=False, indent=1)

    return mcp


def main() -> None:
    """Entry point for `aicaudit mcp`."""
    build_server().run()


if __name__ == "__main__":
    main()
