"""Client verdict parsing: three-state schema with fail-safe semantics."""
import json

from aicaudit.llm.client import (
    CONFIDENCE_THRESHOLD,
    _extract_json_array,
    _parse_verdicts,
    filter_confirmed,
)
from aicaudit.llm.prompts import FindingEvidence


def make_evidence(rule_id="S001", line=5):
    return FindingEvidence(rule_id=rule_id, severity="critical", file="app.py",
                           line=line, message="sql risk", snippet="conn.execute(q)")


def ok_verdict(idx=0, is_real=True, confidence=0.9, **extra):
    v = {"index": idx, "is_real": is_real, "confidence": confidence,
         "severity": "critical", "cwe": "CWE-89", "vuln_type": "sql-injection",
         "suggested_fix": "parameterize", "reason": "taint reaches sink"}
    v.update(extra)
    return v


class TestConfirmedVerdicts:

    def test_confirmed_kept_with_fields(self):
        r = _parse_verdicts(json.dumps([ok_verdict()]), [make_evidence()])
        assert r[0]["ai_status"] == "confirmed"
        assert r[0]["ai_confidence"] == 0.9
        assert r[0]["ai_cwe"] == "CWE-89"
        assert r[0]["ai_vuln_type"] == "sql-injection"
        assert r[0]["ai_suggested_fix"] == "parameterize"

    def test_false_positive_kept(self):
        r = _parse_verdicts(json.dumps([ok_verdict(is_real=False, confidence=0.95)]),
                            [make_evidence()])
        assert r[0]["ai_status"] == "false_positive"

    def test_confidence_clamped(self):
        r = _parse_verdicts(json.dumps([ok_verdict(confidence=7)]), [make_evidence()])
        assert r[0]["ai_confidence"] == 1.0

    def test_absolute_index_with_offset(self):
        # model echoed absolute indices; parser is told the batch offset
        r = _parse_verdicts(json.dumps([ok_verdict(idx=10)]), [make_evidence()], offset=10)
        assert r[0]["ai_status"] == "confirmed"

    def test_code_fenced_response(self):
        text = "```json\n" + json.dumps([ok_verdict()]) + "\n```"
        r = _parse_verdicts(text, [make_evidence()])
        assert r[0]["ai_status"] == "confirmed"

    def test_prose_wrapped_response(self):
        text = "Here is my analysis:\n" + json.dumps([ok_verdict()]) + "\nDone."
        r = _parse_verdicts(text, [make_evidence()])
        assert r[0]["ai_status"] == "confirmed"


class TestFailSafe:

    def test_unparseable_response_marks_unverified(self):
        r = _parse_verdicts("the model rambled", [make_evidence()])
        assert r[0]["ai_status"] == "unverified"
        assert "unparseable" in r[0]["ai_reason"]

    def test_error_object_response(self):
        r = _parse_verdicts(json.dumps({"error": "LLM call failed"}), [make_evidence()])
        assert r[0]["ai_status"] == "unverified"

    def test_missing_index_marks_unverified(self):
        r = _parse_verdicts(json.dumps([ok_verdict(idx=99)]), [make_evidence()])
        assert r[0]["ai_status"] == "unverified"

    def test_missing_is_real_marks_unverified(self):
        v = ok_verdict()
        del v["is_real"]
        r = _parse_verdicts(json.dumps([v]), [make_evidence()])
        assert r[0]["ai_status"] == "unverified"

    def test_low_confidence_confirmed_downgraded(self):
        r = _parse_verdicts(json.dumps([ok_verdict(confidence=0.2)]), [make_evidence()])
        assert r[0]["ai_status"] == "unverified"
        assert str(CONFIDENCE_THRESHOLD) in r[0]["ai_reason"]

    def test_not_a_list_marks_unverified(self):
        r = _parse_verdicts(json.dumps({"key": "value"}), [make_evidence()])
        assert r[0]["ai_status"] == "unverified"

    def test_empty_batch(self):
        assert _parse_verdicts("[]", []) == []


class TestExtractJsonArray:

    def test_plain(self):
        assert isinstance(_extract_json_array('[{"a":1}]'), list)

    def test_none_for_garbage(self):
        assert _extract_json_array("no brackets here") is None

    def test_none_for_empty(self):
        assert _extract_json_array("") is None

    def test_object_not_list(self):
        assert _extract_json_array('{"a":1}') is None


def test_filter_confirmed():
    items = [
        {"ai_status": "confirmed"},
        {"ai_status": "false_positive"},
        {"ai_status": "unverified"},
    ]
    kept = filter_confirmed(items)
    assert len(kept) == 1 and kept[0]["ai_status"] == "confirmed"
