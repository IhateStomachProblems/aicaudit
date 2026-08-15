"""Fix engine: applies automated fixes to source files.

Design:
- Each finding carries a `fix` string (text description)
- Fixes are line-based replacements (safe, no AST manipulation)
- Original files are backed up before modification
- Dry-run mode shows diff without applying
"""

import shutil
from collections import defaultdict
from pathlib import Path


def apply_fixes(findings, source_files, dry_run=True, backup=True):
    """Apply fixes to source files.

    Args:
        findings: list of Finding objects with non-None fix fields
        source_files: dict of file_path -> original source text
        dry_run: if True, only print diffs, do not modify
        backup: if True, create .bak file before modifying

    Returns:
        dict of file_path -> fixed source text (or None if dry_run)
    """
    fixes_by_file = defaultdict(list)
    for f in findings:
        if f.fix:
            fixes_by_file[f.file].append(f)

    results = {}
    for file_path_str, file_findings in sorted(fixes_by_file.items()):
        file_path = Path(file_path_str)
        if not file_path.exists():
            print(f"  Skipping {file_path}: file not found")
            continue

        original = file_path.read_text(encoding="utf-8-sig", errors="replace")
        lines = original.splitlines(keepends=True)
        modified = _apply_findings_to_lines(lines, file_findings)

        if original == modified:
            continue

        results[file_path_str] = modified

        if dry_run:
            _print_diff(file_path_str, original, modified)
        else:
            if backup:
                backup_path = file_path.with_suffix(file_path.suffix + ".bak")
                shutil.copy2(file_path, backup_path)
                print(f"  Backup: {backup_path}")
            file_path.write_text(modified, encoding="utf-8")
            print(f"  Fixed: {file_path}")

    return results


def _apply_findings_to_lines(lines, findings):
    """Apply findings to lines (reverse order to preserve line numbers)."""
    findings_sorted = sorted(findings, key=lambda f: f.line, reverse=True)
    for f in findings_sorted:
        if 0 < f.line <= len(lines):
            fixed = _apply_fix_to_line(lines[f.line - 1], f)
            if fixed is not None:
                lines[f.line - 1] = fixed
    return "".join(lines)


def _apply_fix_to_line(line, finding):
    """Apply a single fix to a line of code."""
    if finding.rule_id == "Q001":
        return _fix_bare_except(line)
    if finding.rule_id == "S003" and _is_dangerous_call(line):
        return _comment_dangerous(line)
    return None


def _fix_bare_except(line):
    """Convert bare except: to except Exception:."""
    stripped = line.strip()
    if stripped == "except:" or stripped.startswith("except :"):
        indent = line[:len(line) - len(line.lstrip())]
        return indent + "except Exception:" + "\n"
    return None


def _is_dangerous_call(line):
    stripped = line.strip()
    return any(stripped.startswith(x + "(") for x in ("eval", "exec", "os.system"))


def _comment_dangerous(line):
    """Comment out dangerous function call and add a safe alternative hint."""
    indent = line[:len(line) - len(line.lstrip())]
    return indent + "# TODO: " + line.lstrip()


def _print_diff(file_path, original, modified):
    """Print a unified diff of the changes."""
    import difflib
    orig_lines = original.splitlines(keepends=True)
    mod_lines = modified.splitlines(keepends=True)
    diff = difflib.unified_diff(
        orig_lines, mod_lines,
        fromfile=file_path, tofile=file_path + " (fixed)",
        n=2,
    )
    diff_text = "".join(diff)
    if diff_text.strip():
        print(diff_text)
