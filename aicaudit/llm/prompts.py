"""Evidence-grounded, category-aware prompt building for AI verdicts.

Design is informed by the 2026 research landscape:
- Agents beat one-shot prompting mainly through navigation + iterative
  reasoning; we pre-compute the navigation (taint paths, enclosing functions)
  with the static engine and hand the LLM the distilled evidence.
- LLM verifiers habitually (a) pattern-match API names without checking
  sanitization, (b) mislabel CWEs, and (c) dismiss policy/crypto findings
  (77-84% miss on CWE-327/328-class) while injection findings are near-perfect.
  Category-aware instruction blocks below target exactly those failure modes.
- Best-known configurations still wrongly suppress ~22% of true positives, so
  verdicts downstream are advisory marks, never silent deletions.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, field

from aicaudit.taint.model import TaintPath

# Rules whose verdict is a dataflow question (does tainted input reach the
# sink unsanitized?) versus a policy/configuration question.
INJECTION_RULES = {"S001", "S003", "S004", "S005", "S007"}
POLICY_RULES = {"S002", "S006", "S008"}

_MAX_FUNCTION_LINES = 80
_MAX_IMPORTS = 25

VERDICT_SCHEMA = (
    "- index: integer (the finding number)\n"
    "- is_real: boolean (true = genuine vulnerability, false = false positive)\n"
    "- confidence: number between 0.0 and 1.0 (your certainty in the verdict)\n"
    "- severity: string (info, warning, error, critical)\n"
    "- cwe: string (CWE identifier, e.g. CWE-89; keep the rule's CWE unless clearly wrong)\n"
    "- vuln_type: string (short name, e.g. sql-injection, weak-hash)\n"
    "- suggested_fix: string (concise fix advice, 1-3 sentences)\n"
    "- reason: string (1-3 sentences; when confirming an injection finding, "
    "reference the taint path or the missing sanitizer)\n"
)

_SYSTEM_PRINCIPLES = """You are a senior security code reviewer verifying static-analysis
findings. Principles:
1. Evidence first: judge the code and the taint path shown, not just API names.
2. If a sanitizer, validation, or safe construction actually neutralizes the
   data flow, the finding is a false positive — say which one.
3. Do NOT confirm because the pattern "looks dangerous"; do NOT dismiss
   because the code "looks fine". Check the actual flow shown to you.
4. When genuinely uncertain, still give your best verdict but lower the
   confidence — never pad confidence.
"""

_INJECTION_BLOCK = """This is an INJECTION-class finding. The engine has traced the data flow
from source to sink (shown below). Verify:
- Does user-controlled data actually reach the sink?
- Is there any sanitizer, parameterization, or validation on the path?
- Is the taint path consistent with the code shown?
If the path is provably neutralized or the source is not attacker-controlled,
is_real=false and name the neutralizer in the reason."""

_POLICY_BLOCK = """This is a POLICY-class finding (hardcoded secret / weak crypto / insecure
random). There is no data flow to trace; judge the usage context:
- What is the value used for? (password hashing vs. cache key; session token
  vs. test shuffle)
- Is a safer alternative clearly applicable here?
Do NOT dismiss it merely because the code functions correctly — policy
findings are about the choice of primitive, not correctness."""


@dataclass
class FindingEvidence:
    """Everything the LLM sees for one finding."""

    rule_id: str
    rule_name: str = ""
    cwe: str | None = None
    severity: str = "warning"
    message: str = ""
    file: str = ""
    line: int = 0
    snippet: str = ""
    fix: str | None = None
    function_source: str = ""
    imports: str = ""
    taint_paths: list[TaintPath] = field(default_factory=list)

    @classmethod
    def from_finding(cls, f, function_source: str = "", imports: str = "") -> FindingEvidence:
        return cls(
            rule_id=f.rule_id, cwe=f.cwe, severity=f.severity.value, message=f.message,
            file=f.file, line=f.line, snippet=f.snippet or "", fix=f.fix,
            function_source=function_source, imports=imports,
            taint_paths=list(f.taint_path or []),
        )

    @property
    def category_block(self) -> str:
        if self.rule_id in INJECTION_RULES:
            return _INJECTION_BLOCK
        if self.rule_id in POLICY_RULES:
            return _POLICY_BLOCK
        return ""


# ── source extraction helpers (shared by scan/audit/web callers) ─────────────

def enclosing_function_source(source: str, line: int) -> str:
    """Source of the innermost function containing `line` (dedented, capped)."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return ""
    best = None
    best_size = None
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        end = node.end_lineno or node.lineno
        if node.lineno <= line <= end:
            size = end - node.lineno
            if best is None or size < (best_size or 0):
                best, best_size = node, size
    if best is None:
        return ""
    lines = source.splitlines()
    body = lines[best.lineno - 1:(best.end_lineno or best.lineno)]
    text = "\n".join(_dedent(body))
    if len(body) > _MAX_FUNCTION_LINES:
        keep = _MAX_FUNCTION_LINES - 1
        text = "\n".join(_dedent(body[:keep])) + f"\n... ({len(body) - keep} more lines)"
    return text


def imports_block(source: str) -> str:
    """Import statements of the file (capped), one per line."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return ""
    out = []
    for node in tree.body:
        if isinstance(node, ast.Import):
            out.append(f"import {', '.join(a.name + (' as ' + a.asname if a.asname else '') for a in node.names)}")
        elif isinstance(node, ast.ImportFrom):
            names = ", ".join(a.name + (" as " + a.asname if a.asname else "") for a in node.names)
            out.append(f"from {node.module or '.'} import {names}")
        if len(out) >= _MAX_IMPORTS:
            break
    return "\n".join(out)


def _dedent(lines: list[str]) -> list[str]:
    if not lines:
        return lines
    first = lines[0]
    indent = len(first) - len(first.lstrip())
    return [ln[indent:] if ln.strip() else "" for ln in lines]


# ── prompt assembly ──────────────────────────────────────────────────────────

def build_evidence_prompt(evidences: list[FindingEvidence], offset: int = 0) -> str:
    parts = [
        _SYSTEM_PRINCIPLES,
        "\nAnalyze each finding below and respond with a JSON array — one object per",
        "finding, ONLY these fields:\n",
        VERDICT_SCHEMA,
        "\nRespond ONLY with the JSON array, no other text.\n",
    ]
    for i, ev in enumerate(evidences):
        idx = offset + i
        parts.append(f"=== Finding [{idx}] ===\n")
        rule_line = f"Rule: {ev.rule_id}" + (f" ({ev.rule_name})" if ev.rule_name else "")
        if ev.cwe:
            rule_line += f" | Engine CWE: {ev.cwe} (anchor to this unless clearly wrong)"
        parts.append(rule_line + f" | Static severity: {ev.severity}\n")
        if ev.message:
            parts.append(f"Message: {ev.message}\n")
        parts.append(f"File: {ev.file}:{ev.line}\n")
        category = ev.category_block
        if category:
            parts.append("\n" + category + "\n")
        if ev.taint_paths:
            parts.append(f"\nTaint path ({len(ev.taint_paths)} traced, engine-verified):\n")
            for p in ev.taint_paths[:2]:
                parts.append(f"  {p.render()}\n")
        else:
            parts.append("\nTaint path: none traced (source unresolved by the static engine).\n")
        if ev.imports:
            parts.append("\nFile imports:\n" + ev.imports + "\n")
        if ev.function_source:
            parts.append("\nEnclosing function:\n```python\n" + ev.function_source + "\n```\n")
        elif ev.snippet:
            parts.append("\nCode line: " + ev.snippet + "\n")
        parts.append("\n")
    return "".join(parts)
