"""Scan engine: collects files, runs rules, aggregates findings."""

import ast
import re
import sys
import time

from aicaudit.rules.base import Finding, ScanContext, Severity, active_rules

# Inline suppression: # aicaudit: ignore  OR  # aicaudit: ignore=S001
_SUPPRESS_RE = re.compile(r"#\s*aicaudit:\s*ignore(?:\s*[= ]\s*(\S+))?", re.IGNORECASE)


def _collect_python_files(paths, ignore_patterns=(), base_root=None):
    files = []
    for p in paths:
        if p.is_file():
            if p.suffix == ".py" and not _is_ignored(p, ignore_patterns, base_root):
                files.append(p)
        elif p.is_dir():
            for fp in p.rglob("*.py"):
                if not _is_ignored(fp, ignore_patterns, base_root):
                    files.append(fp)
    return sorted(set(files))


def _is_ignored(path, patterns, base_root):
    if not patterns:
        return False
    from aicaudit.config import matches_ignore
    return matches_ignore(path, patterns, base_root)


def scan(paths, lang="en", rules=None, min_severity=None, ignore_patterns=None, base_root=None, ai_verify=False):
    """Scan Python files. Returns findings filtered by rules and severity."""
    _import_all_rules()

    # Determine which rules to run
    sel_rules = active_rules()
    if rules:
        sel_rules = [r for r in sel_rules if r.id in rules]

    files = _collect_python_files(paths, ignore_patterns or (), base_root)
    if not files:
        print("No Python files found in " + str([str(p) for p in paths]), file=sys.stderr)
        return []

    start = time.time()
    all_findings = []

    for file_path in files:
        all_findings.extend(
            _scan_single_file(file_path, sel_rules, min_severity, lang)
        )

    elapsed = time.time() - start
    _print_summary(all_findings, len(files), elapsed, lang)

    if ai_verify and all_findings:
        all_findings = _ai_verify_findings(all_findings, base_root)
    return all_findings


def _severity_rank(sev):
    order = {Severity.INFO: 0, Severity.WARNING: 1, Severity.ERROR: 2, Severity.CRITICAL: 3}
    return order.get(sev, 0)


_RULE_MODULES = (
    "performance.complexity",
    "performance.nesting_depth",
    "quality.bare_except",
    "quality.magic_numbers",
    "quality.todo_comment",
    "quality.undefined_name",
    "quality.unused_variable",
    "security.dangerous_functions",
    "security.insecure_random",
    "security.path_traversal",
    "security.secret_leak",
    "security.sql_injection",
    "security.ssrf",
    "security.weak_crypto",
    "security.xml_xxe",
)


def _import_all_rules():
    # Side-effect imports: loading a rule module registers its rule.
    # importlib keeps these immune to unused-import lint fixes.
    import importlib

    for name in _RULE_MODULES:
        importlib.import_module(f"aicaudit.rules.{name}")


def _parse_suppressions(lines):
    """Parse inline suppression comments. Returns dict: line_num -> set of rule IDs or None."""
    suppress = {}
    for i, line in enumerate(lines, 1):
        m = _SUPPRESS_RE.search(line)
        if m:
            rule_id = m.group(1)
            if rule_id:
                suppress[i] = {rule_id.upper()}
            else:
                suppress[i] = None  # None means ignore all
    return suppress


def _is_suppressed(finding, suppress_map):
    """Check if a finding should be suppressed by inline comments."""
    for check_line in (finding.line, finding.line - 1):
        if check_line in suppress_map:
            allowed = suppress_map[check_line]
            if allowed is None or finding.rule_id.upper() in allowed:
                return True
    return False


def _print_summary(findings, file_count, elapsed, lang):
    counts = {}
    for f in findings:
        sev = f.severity.value
        counts[sev] = counts.get(sev, 0) + 1

    if lang == "zh":
        head = f"\n扫描完成: {file_count} 个文件, {len(findings)} 个发现, {elapsed:.2f}s"
        labels = {"critical": "严重", "error": "错误", "warning": "警告", "info": "提示"}
    else:
        head = f"\nScan complete: {file_count} files, {len(findings)} findings, {elapsed:.2f}s"
        labels = {"critical": "CRITICAL", "error": "ERROR", "warning": "WARNING", "info": "INFO"}

    print(head, file=sys.stderr)
    for sev in ("critical", "error", "warning", "info"):
        if sev in counts:
            print(f"  [{labels[sev].upper()}] {counts[sev]}", file=sys.stderr)


def _scan_single_file(file_path, sel_rules, min_severity, lang):
    """Scan one file with all rules, applying severity filter and inline suppressions."""
    try:
        source = file_path.read_text(encoding="utf-8-sig", errors="replace")
    except OSError:
        return []
    try:
        tree = ast.parse(source, filename=str(file_path))
    except SyntaxError:
        return []

    lines = source.splitlines(keepends=False)
    ctx = ScanContext(file_path=file_path, source=source, lines=lines, lang=lang)
    suppress_map = _parse_suppressions(lines)
    findings = []
    for rule_cls in sel_rules:
        try:
            rule = rule_cls()
            f_results = rule.check(tree, ctx)
            for f in f_results:
                if min_severity and _severity_rank(f.severity) < _severity_rank(Severity(min_severity)):
                    continue
                if _is_suppressed(f, suppress_map):
                    continue
                findings.append(f)
        except Exception as exc:  # noqa: BLE001 - isolate rule failures
            print(f"  Rule {rule_cls.id} failed: {exc}", file=sys.stderr)
    return findings


def _ai_verify_findings(all_findings, base_root):
    """Run AI verification on findings with evidence-chain context."""
    from pathlib import Path as _P

    from aicaudit.graph import CodeGraph
    from aicaudit.llm.client import filter_verified, verify_findings
    from aicaudit.rules.base import Severity as _Sev

    snippets = {f.line: f.snippet or "" for f in all_findings}
    try:
        graph = CodeGraph(base_root or _P("."))
        graph.build()
        evidence_chains = {}
        for f in all_findings:
            key = f.rule_id + ":" + f.file + ":" + str(f.line)
            chains = graph.find_evidence_chain(f.rule_id, max_depth=3)
            if chains:
                evidence_chains[key] = chains
    except Exception:  # noqa: BLE001
        evidence_chains = {}

    verified = verify_findings(all_findings, snippets, evidence_chains)
    real = filter_verified(verified)
    print(f"  AI verdict: {len(all_findings)} static -> {len(real)} confirmed", file=sys.stderr)
    if evidence_chains:
        print(f"  Evidence chains: {sum(len(v) for v in evidence_chains.values())} paths traced", file=sys.stderr)

    converted = []
    for v in real:
        sev = v.get("ai_severity") or v.get("severity", "warning")
        converted.append(Finding(
            rule_id=v["rule_id"], message=v["message"],
            message_zh=v.get("message_zh", v["message"]),
            file=v["file"], line=v["line"],
            severity=_Sev(sev),
            snippet=v.get("snippet"), fix=v.get("ai_suggested_fix") or v.get("fix"),
        ))
    return converted
