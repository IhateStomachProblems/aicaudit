"""Scan engine: collects files, runs rules, aggregates findings."""

import ast
import time

from codeaudit.rules.base import Finding, ScanContext, Severity, active_rules


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
    from codeaudit.config import matches_ignore
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
        print("No Python files found in " + str([str(p) for p in paths]))
        return []

    start = time.time()
    all_findings = []

    for file_path in files:
        try:
            source = file_path.read_text(encoding="utf-8-sig", errors="replace")
        except OSError:
            continue

        try:
            tree = ast.parse(source, filename=str(file_path))
        except SyntaxError:
            continue

        lines = source.splitlines(keepends=False)
        ctx = ScanContext(file_path=file_path, source=source, lines=lines, lang=lang)

        for rule_cls in sel_rules:
            try:
                rule = rule_cls()
                findings = rule.check(tree, ctx)
                for f in findings:
                    if min_severity and _severity_rank(f.severity) < _severity_rank(
                        Severity(min_severity)
                    ):
                        continue
                    all_findings.append(f)
            except Exception as exc:  # noqa: BLE001 - isolate rule failures
                print(f"  Rule {rule_cls.id} failed: {exc}")

    elapsed = time.time() - start
    _print_summary(all_findings, len(files), elapsed, lang)

    if ai_verify and all_findings:
        from pathlib import Path as _P

        from codeaudit.graph import CodeGraph
        from codeaudit.llm.client import filter_verified, verify_findings
        snippets = {f.line: f.snippet or "" for f in all_findings}
        # Build code graph for evidence-chain context
        try:
            graph = CodeGraph(base_root or _P("."))
            graph.build()
            evidence_chains = {}
            for f in all_findings:
                key = f.rule_id + ":" + f.file + ":" + str(f.line)
                chains = graph.find_evidence_chain(f.rule_id, max_depth=3)
                if chains:
                    evidence_chains[key] = chains
        except Exception:  # noqa: BLE001 - graph failure is non-fatal
            evidence_chains = {}
        # AI verify with evidence chains
        verified = verify_findings(all_findings, snippets, evidence_chains)
        real = filter_verified(verified)
        print(f"  AI verdict: {len(all_findings)} static -> {len(real)} confirmed")
        if evidence_chains:
            total_chains = sum(len(v) for v in evidence_chains.values())
            print(f"  Evidence chains: {total_chains} paths traced")
        # Convert dicts back to Finding objects
        converted = []
        for v in real:
            sev = v.get("ai_severity") or v.get("severity", "warning")
            converted.append(Finding(
                rule_id=v["rule_id"], message=v["message"],
                message_zh=v.get("message_zh", v["message"]),
                file=v["file"], line=v["line"],
                severity=Severity(sev),
                snippet=v.get("snippet"), fix=v.get("ai_suggested_fix") or v.get("fix"),
            ))
        all_findings = converted

    return all_findings


def _severity_rank(sev):
    order = {Severity.INFO: 0, Severity.WARNING: 1, Severity.ERROR: 2, Severity.CRITICAL: 3}
    return order.get(sev, 0)


def _import_all_rules():
    import codeaudit.rules.performance.complexity
    import codeaudit.rules.performance.nesting_depth
    import codeaudit.rules.quality.bare_except
    import codeaudit.rules.quality.magic_numbers
    import codeaudit.rules.quality.todo_comment
    import codeaudit.rules.quality.undefined_name
    import codeaudit.rules.quality.unused_variable
    import codeaudit.rules.security.dangerous_functions
    import codeaudit.rules.security.secret_leak
    import codeaudit.rules.security.sql_injection  # noqa: F401


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

    print(head)
    for sev in ("critical", "error", "warning", "info"):
        if sev in counts:
            print(f"  [{labels[sev].upper()}] {counts[sev]}")
