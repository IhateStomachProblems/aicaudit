---
name: aicaudit
description: Audit Python code for security vulnerabilities with taint-path static analysis and optional AI verdicts. Use when the user asks to check code security, find vulnerabilities, audit Python files/projects, review for injection risks (SQL, command, path traversal, SSRF, XXE), locate hardcoded secrets, or verify whether a flagged issue is a real risk. Runs locally via pip install aicaudit; every finding can carry a machine-checkable source-to-sink dataflow path, and false positives from constant arguments are filtered by a taint engine.
---

# AICAudit — evidence-driven Python security audit

AICAudit is a local CLI (`pip install aicaudit`) that finds security issues in Python code with a **taint engine**: it traces user input (Flask/Django/FastAPI request objects, `input()`, `os.environ`, `sys.argv`) through assignments, f-strings, and function calls to dangerous sinks. Two consequences matter to you as an agent:

1. **Low noise.** Provably-constant arguments don't fire. `eval("1+1")`, `os.path.join(BASE_DIR, "x")` with a constant `BASE_DIR`, and parameterized queries stay quiet. What remains is usually real.
2. **Evidence attached.** Injection findings carry the full path: `source (file:line, what kind of user input) -> propagation hops -> sink (file:line)`. Read it before contradicting the finding.

## When to use

- User asks "is this code secure / does this have vulnerabilities / audit this project" (Python targets)
- You're about to claim generated or reviewed code is safe — run it first as a cheap check
- User pastes a SAST report and asks which findings matter — aicaudit's taint paths tell you which ones have real dataflow

## Commands

```bash
pip install aicaudit              # install (PyPI)
aicaudit scan <path>              # scan; JSON/markdown/sarif via --output
aicaudit scan <path> --rules S001,S005      # subset of rules
aicaudit scan <path> --min-severity error   # floor the noise
aicaudit scan <path> --fail-on error        # CI gate: exit 1 if hit
```

Read `aicaudit scan --output json` output when you need to machine-parse: each finding has `rule_id`, `severity` (info/warning/error/critical), `cwe`, `fix` advice, and — when the engine traced it — `taint_path` (a list of `file:line desc` steps from source to sink).

## MCP mode (preferred inside AI editors)

If the aicaudit MCP server is configured (`pip install aicaudit[mcp]`), prefer its tools over shelling out:

- `scan` — findings as compact JSON (severity, CWE, taint path per finding)
- `list_rules` — rule catalog with categories
- `verify` — attach three-state AI verdicts: `confirmed` / `false_positive` / `unverified` + confidence
- `explain_finding` — full taint path hop-by-hop + enclosing function source for one finding
- `fix_preview` — dry-run unified diff of the auto-fix (writes nothing)

## Interpreting results

- **Rule families**: S001 SQL injection, S002 hardcoded secrets, S003 dangerous functions (eval/exec/pickle/os.system), S004 path traversal, S005 SSRF, S006 weak crypto, S007 XXE, S008 insecure random. Q*/P* are quality/performance rules — usually ignore them during security reviews.
- **`taint_path` present** → the engine proved user input reaches this sink. High confidence; treat as real unless a sanitizer visibly intervenes (the path shows you every hop — check them).
- **No `taint_path`** → dynamic input the engine couldn't resolve to a source. Plausible but unproven; use judgment or `verify`/`explain_finding`.
- **AI verdicts** are advisory marks, never gates: `unverified` means the model couldn't judge confidently — do NOT interpret it as "safe". `confirmed`/`false_positive` come with a `reason` you can inspect.

## Limits to respect

- Python only. No dataflow through closures, metaprogramming, or C extensions — absence of findings is not proof of safety; say so when it matters.
- Findings in `tests/`, fixture dirs, or deliberately-vulnerable samples are expected — don't report them as product bugs.
- Inline suppression exists (`# aicaudit: ignore S001`); if the user suppressed a rule, respect it.
