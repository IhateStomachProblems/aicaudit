"""Prompt evidence content: taint paths, functions, category awareness."""
from aicaudit.llm.prompts import (
    FindingEvidence,
    build_evidence_prompt,
    enclosing_function_source,
    imports_block,
)
from aicaudit.taint.model import TaintHop, TaintOrigin, TaintPath


def make_taint_path():
    return TaintPath(
        origin=TaintOrigin(kind="source", desc="request.args (Flask user input)",
                           file="app.py", line=10),
        hops=[TaintHop(file="app.py", line=11, desc="assigned to 'uid'")],
        sink=TaintHop(file="app.py", line=13, desc=".execute()"),
    )


def make_evidence(rule_id="S001", **kw):
    defaults = {
        "rule_id": rule_id, "severity": "critical", "file": "app.py", "line": 13,
        "message": "SQL injection risk", "snippet": "conn.execute(q)",
        "function_source": "def view(conn):\n    conn.execute(q)",
        "imports": "from flask import request", "taint_paths": [make_taint_path()],
    }
    defaults.update(kw)
    return FindingEvidence(**defaults)


class TestPromptContent:

    def test_prompt_contains_taint_path(self):
        prompt = build_evidence_prompt([make_evidence()])
        assert "Taint path (1 traced" in prompt
        assert "request.args (Flask user input)" in prompt
        assert "assigned to 'uid'" in prompt
        assert ".execute()" in prompt

    def test_prompt_contains_function_and_imports(self):
        prompt = build_evidence_prompt([make_evidence()])
        assert "Enclosing function:" in prompt
        assert "def view(conn):" in prompt
        assert "from flask import request" in prompt

    def test_injection_rules_get_dataflow_instructions(self):
        prompt = build_evidence_prompt([make_evidence(rule_id="S001")])
        assert "INJECTION-class" in prompt
        assert "sanitizer" in prompt

    def test_policy_rules_get_usage_instructions(self):
        prompt = build_evidence_prompt([make_evidence(rule_id="S006")])
        assert "POLICY-class" in prompt
        assert "INJECTION-class" not in prompt

    def test_verdict_schema_fields(self):
        prompt = build_evidence_prompt([make_evidence()])
        assert "confidence" in prompt
        assert "cwe" in prompt
        assert "is_real" in prompt

    def test_cwe_anchor_from_engine(self):
        prompt = build_evidence_prompt([make_evidence(cwe="CWE-89")])
        assert "Engine CWE: CWE-89" in prompt
        assert "anchor" in prompt

    def test_no_taint_path_stated(self):
        prompt = build_evidence_prompt([make_evidence(taint_paths=[])])
        assert "none traced" in prompt

    def test_snippet_fallback_without_function(self):
        prompt = build_evidence_prompt([make_evidence(function_source="")])
        assert "Code line: conn.execute(q)" in prompt


class TestSourceExtraction:

    SRC = (
        "import os\n"
        "from flask import request\n"
        "\n"
        "def outer():\n"
        "    def inner(param):\n"
        "        value = param + 1\n"
        "        return value\n"
        "    return inner\n"
    )

    def test_innermost_function_wins(self):
        src = "def a():\n    x = 1\n\ndef b():\n    y = 2\n    return y\n"
        assert "def b()" in enclosing_function_source(src, 5)
        assert "def a()" in enclosing_function_source(src, 2)

    def test_dedented(self):
        out = enclosing_function_source(self.SRC, 6)
        assert "def inner(param):" in out
        # inner body dedented to the def's own level, not the raw 8-space depth
        assert "    value = param + 1" in out
        assert "\n        value" not in out

    def test_module_level_line_returns_empty(self):
        assert enclosing_function_source(self.SRC, 1) == ""

    def test_syntax_error_returns_empty(self):
        assert enclosing_function_source("def broken(:\n", 1) == ""

    def test_truncation_marker(self):
        body = "\n".join(f"    x{i} = {i}" for i in range(120))
        src = "def big():\n" + body + "\n"
        out = enclosing_function_source(src, 5)
        assert "more lines" in out
        assert "x119" not in out

    def test_imports_block(self):
        out = imports_block(self.SRC)
        assert "import os" in out
        assert "from flask import request" in out
