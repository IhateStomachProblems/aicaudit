"""Coverage: remaining branches in config, fix, llm."""

import os
import tempfile
from pathlib import Path

from aicaudit.config import (
    find_project_root,
    load_pyproject,
    matches_ignore,
    merge_config,
)
from aicaudit.fix import FixStatus, _apply_fix_to_line, fix_file
from aicaudit.llm.client import _parse_deep_response
from aicaudit.rules.base import Finding, Severity


def make_finding(rule_id="S001", line=1, msg="test", file="test.py"):
    return Finding(rule_id=rule_id, message=msg, message_zh=msg+"zh", file=file, line=line, severity=Severity.WARNING)


# config.py: load_pyproject error handling
def test_load_pyproject_bad_toml():
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        (d / "pyproject.toml").write_text("{{bad toml", encoding="utf-8")
        result = load_pyproject(d)
        assert result == {}


def test_load_pyproject_no_file():
    with tempfile.TemporaryDirectory() as td:
        result = load_pyproject(Path(td))
        assert result == {}


def test_matches_ignore_glob():
    assert matches_ignore(Path("tests/test.py"), ["tests/*"], Path("."))
    assert not matches_ignore(Path("src/main.py"), ["tests/*"], Path("."))


def test_find_project_root_with_setup():
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        (d / "setup.py").write_text("", encoding="utf-8")
        sub = d / "src" / "pkg"
        sub.mkdir(parents=True)
        assert find_project_root(sub) == d


def test_find_project_root_none_found():
    with tempfile.TemporaryDirectory() as td:
        assert find_project_root(Path(td)) == Path(td)


def test_merge_config_empty_cli_overrides():
    cfg = merge_config("", "", Path.cwd())
    assert cfg.rules == set()


def test_merge_config_cli_rules_set():
    cfg = merge_config("S001,P001", None, Path.cwd())
    assert cfg.rules == {"S001", "P001"}


# fix.py: _apply_fix_to_line returns None for unknown rule
def test_apply_fix_unknown_rule():
    result = _apply_fix_to_line("x = 1\n", make_finding(rule_id="ZZZ"))
    assert result is None


def test_apply_fix_without_fix_field():
    f = make_finding(rule_id="Q001")
    f.fix = None
    result = _apply_fix_to_line("except:\n", f)
    assert result is not None


def test_fix_file_out_of_range_line():
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False, encoding="utf-8") as tf:
        tf.write("x = 1\n")
        fname = tf.name
    try:
        findings = [make_finding(rule_id="Q001", line=999, file=fname)]
        result = fix_file(fname, findings, dry_run=True)
        assert result.status == FixStatus.SKIPPED
    finally:
        os.unlink(fname)


def test_fix_file_no_fix_field():
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False, encoding="utf-8") as tf:
        tf.write("x = 1\n")
        fname = tf.name
    try:
        f = make_finding(rule_id="Q001", line=1, file=fname)
        f.fix = None
        result = fix_file(fname, [f], dry_run=True)
        assert result.status == FixStatus.SKIPPED
    finally:
        os.unlink(fname)


# llm/client.py: parse_response edge cases

def test_parse_deep_response_empty_list():
    result = _parse_deep_response("[]", [], {})
    assert result == []


def test_parse_deep_response_not_list():
    result = _parse_deep_response("{\"key\": \"value\"}", [make_finding()], {})
    assert result[0]["ai_verified"] == True
    assert "Fallback" in result[0]["ai_reason"]
