import os
proj_dir = r"C:\Users\17390\Desktop\开源git项目\codeaudit"

content = '''"""Scan engine: collects files, runs rules, aggregates findings."""

import ast
import time

from codeaudit.rules.base import ScanContext, active_rules


def _collect_python_files(paths):
    files = []
    for p in paths:
        if p.is_file():
            if p.suffix == ".py":
                files.append(p)
        elif p.is_dir():
            files.extend(p.rglob("*.py"))
    return sorted(set(files))


def scan(paths, lang="en"):
    _import_all_rules()
    files = _collect_python_files(paths)
    if not files:
        print(f"No Python files found in {[str(p) for p in paths]}")
        return []

    rules = active_rules()
    start = time.time()
    all_findings = []

    for file_path in files:
        try:
            source = file_path.read_text(encoding="utf-8-sig", errors="replace")
        except OSError as e:
            print(f"  Skipping {file_path}: {e}")
            continue

        try:
            tree = ast.parse(source, filename=str(file_path))
        except SyntaxError:
            continue

        lines = source.splitlines(keepends=False)
        ctx = ScanContext(file_path=file_path, source=source, lines=lines, lang=lang)

        for rule_cls in rules:
            try:
                rule = rule_cls()
                findings = rule.check(tree, ctx)
                all_findings.extend(findings)
            except Exception as e:  # noqa: BLE001
                print(f"  Rule {rule_cls.id} failed on {file_path}: {e}")

    elapsed = time.time() - start
    _print_summary(all_findings, len(files), elapsed, lang)
    return all_findings


def _import_all_rules():
    import codeaudit.rules.security.sql_injection  # noqa: F401
    import codeaudit.rules.security.secret_leak  # noqa: F401
    import codeaudit.rules.security.dangerous_functions  # noqa: F401
    import codeaudit.rules.quality.bare_except  # noqa: F401
    import codeaudit.rules.quality.magic_numbers  # noqa: F401
    import codeaudit.rules.quality.undefined_name  # noqa: F401
    import codeaudit.rules.quality.todo_comment  # noqa: F401
    import codeaudit.rules.quality.unused_variable  # noqa: F401


def _print_summary(findings, file_count, elapsed, lang):
    counts = {}
    for f in findings:
        sev = f.severity.value
        counts[sev] = counts.get(sev, 0) + 1

    print(f"\\nScan complete: {file_count} files, {len(findings)} findings, {elapsed:.2f}s")
    for sev in ("critical", "error", "warning", "info"):
        if sev in counts:
            print(f"  [{sev.upper()}] {counts[sev]}")
'''

with open(os.path.join(proj_dir, "codeaudit", "scan.py"), "w", encoding="utf-8") as f:
    f.write(content)
print("scan.py rewritten")
