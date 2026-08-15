"""AI deep audit: codebase understanding + evidence chains + AI verdict.

This is the flagship command. It orchestrates:
1. Scan (static) to find suspicious code
2. CodeGraph to build evidence chains (entry -> path -> sink)
3. AI to deep-audit findings with evidence-chain context
4. Structured audit report with evidence and confidence
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path

from codeaudit.graph import CodeGraph
from codeaudit.llm.client import load_ai_config, verify_findings
from codeaudit.scan import scan


@dataclass
class AuditIssue:
    rule_id: str
    message: str
    message_zh: str
    file: str
    line: int
    static_severity: str
    snippet: str = ""
    # AI verdict fields
    ai_confirmed: bool | None = None   # None = AI not used
    ai_reason: str = ""
    ai_severity: str = ""
    ai_vuln_type: str = ""
    ai_suggested_fix: str = ""
    evidence_chain: list = field(default_factory=list)  # [(file,line,func),...]
    entry_point: str = ""


def run_audit(paths, lang="en", use_ai=True) -> dict:
    """Run a full AI deep audit. Returns structured report dict."""
    start = time.time()
    root = Path(paths[0]) if paths else Path(".")

    # 1. Static scan
    from pathlib import Path as _P
    findings = scan([_P(p) for p in paths], lang=lang)

    # 2. Build code graph for evidence chains
    graph = CodeGraph(root)
    graph.build()

    # 3. Attach evidence chains per finding
    audit_issues = []
    for f in findings:
        chain_path = []
        ep = ''
        # Find the function containing this finding's line, anchor chain at it
        containing_func = _find_containing_func(graph, f.file, f.line)
        if containing_func:
            chain_path = [(f.file, containing_func.line, containing_func.name)]
            # Find the closest entry point in the same file
            for entry in graph.entry_points:
                if _entry_in_file(entry, f.file):
                    ep = f'{entry.kind}: {entry.pattern or entry.location}'
                    break
        audit_issues.append(AuditIssue(
            rule_id=f.rule_id, message=f.message, message_zh=getattr(f, "message_zh", ""),
            file=f.file, line=f.line, static_severity=f.severity.value,
            snippet=f.snippet or "", entry_point=ep, evidence_chain=chain_path,
        ))

    # 4. AI deep-audit
    ai_summary = {"provider": "disabled", "model": "", "confirmed": 0, "total": 0}
    if use_ai:
        cfg = load_ai_config()
        if cfg.provider != "mock":
            snippets = {i.line: i.snippet for i in audit_issues}
            ec_map = {}
            for i in audit_issues:
                k = i.rule_id + ":" + i.file + ":" + str(i.line)
                if i.evidence_chain:
                    ec_map[k] = [type("EC", (), {"entry": i.entry_point, "path": i.evidence_chain, "sink": i.rule_id, "risk": "medium"})]
            # Convert audit_issues back to minimal objects for verify_findings
            from codeaudit.rules.base import Finding, Severity
            finding_objs = [
                Finding(rule_id=i.rule_id, message=i.message, message_zh=i.message_zh,
                        file=i.file, line=i.line,
                        severity=Severity(i.static_severity), snippet=i.snippet)
                for i in audit_issues
            ]
            verified = verify_findings(finding_objs, snippets, ec_map, cfg)
            # Map verdicts back
            for idx, v in enumerate(verified):
                if idx < len(audit_issues):
                    audit_issues[idx].ai_confirmed = v.get("ai_verified")
                    audit_issues[idx].ai_reason = v.get("ai_reason", "")
                    audit_issues[idx].ai_severity = v.get("ai_severity", "")
                    audit_issues[idx].ai_vuln_type = v.get("ai_vuln_type", "")
                    audit_issues[idx].ai_suggested_fix = v.get("ai_suggested_fix", "")
            ai_summary = {
                "provider": cfg.provider, "model": cfg.model,
                "confirmed": sum(1 for i in audit_issues if i.ai_confirmed),
                "total": len(audit_issues),
            }

    elapsed = time.time() - start
    return {
        "tool": "codeaudit",
        "version": "0.1.0",
        "paths": [str(p) for p in paths],
        "scan": {"findings": len(audit_issues), "files": len(graph.files),
                 "duration_s": round(elapsed, 2),
                 "evidence_chains_traced": sum(1 for i in audit_issues if i.evidence_chain)},
        "ai": ai_summary,
        "issues": [
            {
                "rule_id": i.rule_id, "message": i.message,
                "message_zh": i.message_zh, "file": i.file, "line": i.line,
                "static_severity": i.static_severity, "snippet": i.snippet,
                "entry_point": i.entry_point, "evidence_chain": i.evidence_chain,
                "ai": {
                    "confirmed": i.ai_confirmed, "reason": i.ai_reason,
                    "severity": i.ai_severity, "vuln_type": i.ai_vuln_type,
                    "suggested_fix": i.ai_suggested_fix,
                },
            }
            for i in audit_issues
        ],
    }


def _build_file_function_map(graph):
    """Map file -> list of FuncDef sorted by line (for containing-func lookup)."""
    mapping = {}
    for funcs in graph.funcs.values():
        for fd in funcs:
            if fd.file not in mapping:
                mapping[fd.file] = []
            mapping[fd.file].append(fd)
    for funcs in mapping.values():
        funcs.sort(key=lambda fd: fd.line)
    return mapping


def _find_containing_func(graph, file_path, line):
    """Find the function that contains the given line in a file."""
    # Normalize file comparison (graph stores relative path, finding stores absolute)
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
