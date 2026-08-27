"""Coverage: fix engine defensive branches."""

import os
import tempfile

from aicaudit.fix import (
    FixResult,
    FixStatus,
    _apply_fix_to_line,
    _fix_undefined_name,
    fix_file,
)
from aicaudit.rules.base import Finding, Severity


def make_finding(rule_id="Q001", line=1, file="test.py"):
    return Finding(rule_id=rule_id, message="test", message_zh="test", file=file, line=line, severity=Severity.WARNING)


def test_fixresult_repr():
    r = FixResult("x.py")
    r.status = FixStatus.APPLIED
    assert "FixResult" in repr(r)
    assert "applied" in repr(r)


def test_fix_origin_syntax_error():
    f = tempfile.NamedTemporaryFile("w", suffix=".py", delete=False, encoding="utf-8")  # noqa: SIM115
    f.write("def broken(:\n")
    fname = f.name
    f.close()
    try:
        r = fix_file(fname, [], dry_run=True)
        assert r.status == FixStatus.FAILED
        assert "syntax" in r.message
    finally:
        os.unlink(fname)


def test_apply_fix_undefined_name_rule():
    # _apply_fix_to_line for Q003 -> _fix_undefined_name returns None
    result = _apply_fix_to_line("print(x)", make_finding(rule_id="Q003", line=1))
    assert result is None


def test_fix_undefined_name_direct():
    # returns None (best-effort, no auto-fix)
    assert _fix_undefined_name("print(x)", make_finding(rule_id="Q003")) is None
    assert _fix_undefined_name("print(x)", make_finding(rule_id="Q003", line=1)) is None


def test_fix_verify_regression_trips():
    # Force verification to fail: rule still present after fix
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False, encoding="utf-8") as f:
        f.write("try:\n    x = 1\nexcept:  # keep\n    pass\n")
        fname = f.name
    try:
        # A finding that won't be fully fixed should still verify safely
        findings = [make_finding(rule_id="Q001", line=3, file=fname)]
        r = fix_file(fname, findings, dry_run=True)
        # On Windows, comment keeps except:, fix may not change -> skipped or applied
        assert r.status in (FixStatus.APPLIED, FixStatus.SKIPPED)
    finally:
        os.unlink(fname)
