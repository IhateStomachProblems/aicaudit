"""AI deep audit: static scan + taint evidence + AI verdicts.

Orchestrates:
1. Static scan (rules + taint engine) to find suspicious code
2. Evidence assembly: taint paths, enclosing functions, entry points
3. AI verdicts grounded in that evidence (three-state, fail-safe)
4. Structured audit report with evidence and confidence
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path

from aicaudit.graph import CodeGraph
from aicaudit.llm.client import load_ai_config, verify_findings
from aicaudit.llm.prompts import (
    FindingEvidence,
    enclosing_function_source,
    imports_block,
)
from aicaudit.scan import scan


@dataclass
class AuditIssue:
    rule_id: str
    message: str
    message_zh: str
    file: str
    line: int
    static_severity: str
    snippet: str = ""
    cwe: str | None = None
    # AI verdict fields (three-state status + confidence)
    ai_status: str = ""            # "" = AI not used; confirmed/false_positive/unverified
    ai_confidence: float = 0.0
    ai_reason: str = ""
    ai_severity: str = ""
    ai_cwe: str = ""
    ai_vuln_type: str = ""
    ai_suggested_fix: str = ""
    evidence_chain: list = field(default_factory=list)  # [(file,line,desc),...]
    entry_point: str = ""
    taint_paths: list = field(default_factory=list)     # rendered source->sink paths


def run_audit(paths, lang="en", use_ai=True) -> dict:
    """Run a full AI deep audit. Returns structured report dict."""
    start = time.time()
    root = Path(paths[0]) if paths else Path(".")

    # 1. Static scan (taint-aware: findings may carry taint_path + cwe)
    findings = scan([Path(p) for p in paths], lang=lang)

    # 2. Code graph for entry points / containing functions
    graph = CodeGraph(root)
    graph.build()

    # 3. Assemble issues with evidence
    sources: dict[str, str] = {}
    audit_issues: list[AuditIssue] = []
    for f in findings:
        if f.file not in sources:
            try:
                with open(f.file, encoding="utf-8-sig", errors="replace") as fh:
                    sources[f.file] = fh.read()
            except OSError:
                sources[f.file] = ""

        containing_func = _find_containing_func(graph, f.file, f.line)
        chain_path = [(f.file, containing_func.line, containing_func.name)] if containing_func else []
        ep = ""
        for entry in graph.entry_points:
            if _entry_in_file(entry, f.file):
                ep = f'{entry.kind}: {entry.pattern or entry.location}'
                break

        audit_issues.append(AuditIssue(
            rule_id=f.rule_id, message=f.message, message_zh=getattr(f, "message_zh", ""),
            file=f.file, line=f.line, static_severity=f.severity.value,
            snippet=f.snippet or "", cwe=f.cwe, entry_point=ep, evidence_chain=chain_path,
            taint_paths=[p.render() for p in (f.taint_path or [])],
        ))

    # 4. AI verdicts grounded in taint paths + enclosing functions
    ai_summary = {"provider": "disabled", "model": "",
                  "confirmed": 0, "false_positive": 0, "unverified": 0, "total": 0}
    if use_ai:
        cfg = load_ai_config()
        if cfg.provider != "mock":
            evidences = []
            for issue, f in zip(audit_issues, findings):
                src = sources.get(issue.file, "")
                evidences.append(FindingEvidence(
                    rule_id=issue.rule_id, cwe=f.cwe, severity=issue.static_severity,
                    message=issue.message, file=issue.file, line=issue.line,
                    snippet=issue.snippet, fix=f.fix,
                    function_source=enclosing_function_source(src, issue.line),
                    imports=imports_block(src),
                    taint_paths=list(f.taint_path or []),
                ))
            verdicts = verify_findings(evidences, cfg)
            for issue, v in zip(audit_issues, verdicts):
                issue.ai_status = v.get("ai_status", "unverified")
                issue.ai_confidence = v.get("ai_confidence", 0.0)
                issue.ai_reason = v.get("ai_reason", "")
                issue.ai_severity = v.get("ai_severity", "")
                issue.ai_cwe = v.get("ai_cwe", "")
                issue.ai_vuln_type = v.get("ai_vuln_type", "")
                issue.ai_suggested_fix = v.get("ai_suggested_fix", "")
            ai_summary = {
                "provider": cfg.provider, "model": cfg.model,
                "confirmed": sum(1 for i in audit_issues if i.ai_status == "confirmed"),
                "false_positive": sum(1 for i in audit_issues if i.ai_status == "false_positive"),
                "unverified": sum(1 for i in audit_issues if i.ai_status == "unverified"),
                "total": len(audit_issues),
            }

    elapsed = time.time() - start
    return {
        "tool": "aicaudit",
        "version": "0.1.0",
        "paths": [str(p) for p in paths],
        "scan": {"findings": len(audit_issues), "files": len(graph.files),
                 "duration_s": round(elapsed, 2),
                 "taint_paths_traced": sum(1 for i in audit_issues if i.taint_paths)},
        "ai": ai_summary,
        "issues": [
            {
                "rule_id": i.rule_id, "message": i.message,
                "message_zh": i.message_zh, "file": i.file, "line": i.line,
                "static_severity": i.static_severity, "snippet": i.snippet,
                "cwe": i.cwe, "entry_point": i.entry_point,
                "evidence_chain": i.evidence_chain, "taint_paths": i.taint_paths,
                "ai": {
                    "status": i.ai_status or None,
                    "confidence": i.ai_confidence,
                    "reason": i.ai_reason,
                    "severity": i.ai_severity, "cwe": i.ai_cwe,
                    "vuln_type": i.ai_vuln_type, "suggested_fix": i.ai_suggested_fix,
                },
            }
            for i in audit_issues
        ],
    }


def _find_containing_func(graph, file_path, line):
    """Find the function that contains the given line in a file."""
    target = file_path.replace('\\', '/')
    target_base = target.split('/')[-1]
    best = None
    for funcs in graph.funcs.values():
        for fd in funcs:
            fd_base = fd.file.replace('\\', '/').split('/')[-1]
            if fd_base == target_base and fd.line <= line and (best is None or fd.line > best.line):
                best = fd
    return best


def _entry_in_file(entry, file_path):
    """Check if an entry point is in the given file (basename match)."""
    entry_f = entry.location.split(':')[0].replace('\\', '/').split('/')[-1]
    target = file_path.replace('\\', '/').split('/')[-1]
    return entry_f == target
