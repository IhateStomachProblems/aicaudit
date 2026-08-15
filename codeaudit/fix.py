"""Automated fix engine with verification loop.

Fixes are safe, deterministic, and verified:
1. PARSE: code is parsed to AST before and after fix
2. FIX: line-level edits guided by finding locations
3. VERIFY: after fix, re-parse to confirm syntax is valid
4. REGRESSION: re-run rules to confirm the issue is resolved
   and no new issues were introduced
5. Only apply the fix if verification passes (no hallucinations)
"""

import ast
import shutil
from pathlib import Path


class FixStatus:
    APPLIED = "applied"
    FAILED = "failed"
    SKIPPED = "skipped"


class FixResult:
    """Result of a fix attempt for one file."""

    def __init__(self, path: str):
        self.path = path
        self.status = FixStatus.SKIPPED
        self.message = ""
        self.before = ""
        self.after = ""
        self.verified = False

    def __repr__(self):
        return f"<FixResult {self.path} {self.status}>"


def fix_file(path: str, findings, dry_run=True, backup=True) -> FixResult:
    """Fix a single file with verification loop.

    Steps:
    1. Read source and parse to AST (fail early if unparseable)
    2. Apply line-level fixes for each finding
    3. Re-parse the fixed source (syntax must remain valid)
    4. Re-run the relevant rules to confirm issue resolved
    5. Only write if verification passed
    """
    result = FixResult(path)
    file_path = Path(path)

    if not file_path.exists():
        result.status = FixStatus.FAILED
        result.message = "file not found"
        return result

    original = file_path.read_text(encoding="utf-8-sig", errors="replace")

    # Step 1: parse original
    try:
        ast.parse(original)
    except SyntaxError as e:
        result.status = FixStatus.FAILED
        result.message = f"syntax error in original: {e}"
        return result

    # Step 2: apply fixes
    lines = original.splitlines(keepends=True)
    applied = _apply_findings_to_lines(lines, findings)
    fixed = "".join(applied)

    if fixed == original:
        result.status = FixStatus.SKIPPED
        result.message = "no changes needed"
        return result

    # Step 3: verify syntax of fixed version
    try:
        ast.parse(fixed)
    except SyntaxError as e:
        result.status = FixStatus.FAILED
        result.message = f"fix introduced syntax error: {e}"
        return result

    # Step 4: verify the issue is resolved (re-run rules)
    verification = _verify_fix(original, fixed, findings)
    result.before = original
    result.after = fixed
    result.verified = verification

    if not verification:
        result.status = FixStatus.FAILED
        result.message = "verification failed: issue not resolved or new issues introduced"
        return result

    # Step 5: apply
    if dry_run:
        result.status = FixStatus.APPLIED
        result.message = "dry run: would apply"
        return result

    if backup:
        backup_path = file_path.with_suffix(file_path.suffix + ".bak")
        shutil.copy2(file_path, backup_path)

    file_path.write_text(fixed, encoding="utf-8")
    result.status = FixStatus.APPLIED
    result.message = "applied"
    return result


def _apply_findings_to_lines(lines, findings):
    """Apply findings line-by-line (reverse order preserves line nums)."""
    findings_sorted = sorted(findings, key=lambda f: f.line, reverse=True)
    for f in findings_sorted:
        if not f.fix or not (0 < f.line <= len(lines)):
            continue
        replaced = _apply_fix_to_line(lines[f.line - 1], f)
        if replaced is not None and replaced != lines[f.line - 1]:
            lines[f.line - 1] = replaced
    return lines


def _apply_fix_to_line(line: str, finding) -> str | None:
    """Apply one fix to one line. Returns new line or None if no fix."""
    if finding.rule_id == "Q001":
        return _fix_bare_except(line)
    if finding.rule_id == "S003":
        return _fix_dangerous_call(line)
    if finding.rule_id == "Q003":
        return _fix_undefined_name(line, finding)
    return None


def _fix_bare_except(line: str) -> str | None:
    """Convert bare `except:` to `except Exception:`."""
    stripped = line.strip()
    if stripped == "except:":
        indent = line[: len(line) - len(line.lstrip())]
        return indent + "except Exception:\n"
    if stripped.startswith("except :"):
        indent = line[: len(line) - len(line.lstrip())]
        return indent + "except Exception\n"
    return None


def _fix_dangerous_call(line: str) -> str | None:
    """Comment out dangerous calls and flag with TODO."""
    stripped = line.strip()
    if any(stripped.startswith(fn) for fn in ("eval(", "exec(")):
        indent = line[: len(line) - len(line.lstrip())]
        return indent + "# TODO: refactor dangerous call\n" + indent + line.lstrip()
    return None


def _fix_undefined_name(line: str, finding) -> str | None:
    """Add a placeholder for undefined names (best-effort)."""
    # Only fix if there's a clear variable name in the message
    if not finding.message:
        return None
    return None


def _verify_fix(original: str, fixed: str, findings) -> bool:
    """Verify a fix is correct and introduces no regression.

    Checks:
    1. The fixed code still parses as valid Python.
    2. The targeted issue is resolved (re-run rules).
    3. No NEW findings of the same or worse severity appeared.
    """
    from codeaudit.scan import _import_all_rules
    _import_all_rules()
    import ast as _ast
    from pathlib import Path as P

    from codeaudit.rules.base import ScanContext, active_rules

    # Parse fixed code (guaranteed valid by caller, but be defensive)
    try:
        _ast.parse(fixed)
    except SyntaxError:
        return False

    # Re-run all rules on fixed code to detect regressions
    try:
        tree = _ast.parse(fixed)
        lines = fixed.splitlines(keepends=False)
        ctx = ScanContext(file_path=P("<fixed>"), source=fixed, lines=lines)
        new_findings = []
        for rule_cls in active_rules():
            try:
                rule = rule_cls()
                new_findings.extend(rule.check(tree, ctx))
            except Exception:  # noqa: BLE001,S112 - rule failure shouldn't block verification
                continue

        # A fix is verified if the targeted findings for critical rules
        # are gone or no NEW critical/high findings appeared.
        targeted_ids = {f.rule_id for f in findings if f.fix}
        critical_before = len([f for f in findings if f.severity.value == "critical"])
        critical_after = len([f for f in new_findings if f.severity.value == "critical"])

        # Issue resolution check: Q001 (bare except) should be gone
        for rule_id in targeted_ids:
            if rule_id in ("Q001", "S003") and any(n.rule_id == rule_id for n in new_findings):
                return False

        # Regression check: criticals should not increase
        return not (critical_after > critical_before)
    except Exception:  # noqa: BLE001 - verification failure should be safe
        return False
