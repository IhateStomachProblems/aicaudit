"""Scan engine: collects files, runs rules, aggregates findings."""

import ast
import time

from codeaudit.rules.base import ScanContext, Severity, active_rules


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


def scan(paths, lang="en", rules=None, min_severity=None, ignore_patterns=None, base_root=None):
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
