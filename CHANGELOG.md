# Changelog

## v0.2.0 — Evidence-Driven AI Audit (2026-09-13)

The "show your work" release: every security verdict now ships with a
machine-checkable taint path, an evidence-grounded AI verdict, and a UI that
visualizes both.

### Taint engine (new)

- Pure-Python source-to-sink analysis (`aicaudit/taint/`): tracks user input
  from Flask/Django/FastAPI requests, `input()`, `os.environ`, `sys.argv`
  through assignments, f-strings, concatenation, and across function
  boundaries to the sink
- Proves constants safe — kills the classic false-positive classes
  (`os.path.join(BASE_DIR, "x")`, constant SQL variables, `eval("1+1")`)
- Sanitizer catalog (parameterized SQL, `os.path.basename`, `int()`, …) and
  pure-function folding for constness
- Scope-aware import-alias resolution (function-local `defusedxml` imports no
  longer whitelist the whole file)

### Rules

- S001/S003/S004/S005 are taint-aware; recall preserved for unresolved sources
- Structured CWE field on all security rules; SARIF codeFlows render taint
  paths natively in the GitHub Security tab
- External rule dirs: `.aicaudit/rules/` auto-discovery + `rule-dirs` config;
  same-id registration overrides builtins (Python API now, YAML DSL planned)

### AI verdicts 2.0

- Three-state verdicts (`confirmed` / `false_positive` / `unverified`) with
  confidence; fail-safe parsing — never auto-confirmed
- Evidence-grounded prompts: full enclosing function + imports + taint path;
  category-aware instructions (injection vs policy) targeting documented LLM
  verifier failure modes
- `--ai` marks findings instead of silently deleting them; `--ai-strict`
  opt-in filtering

### Web UI 2.0

- Zero-build frontend (vendored CSS/JS, no CDN — works offline)
- Results browser: pygments-highlighted code context, taint-path stepper,
  AI verdict cards with confidence, fix diff-preview/apply/rollback
- SSE live scan progress; session persistence with dashboard history

### DX

- `aicaudit init` config wizard
- CI gate: `--fail-on <severity>` exit codes (0/1/2)
- Composite GitHub Action at the repo root (`uses: …/aicaudit@ref`)
- pre-commit hook definition

### Benchmarks & tests

- Labeled corpus + honest runner (`benchmarks/run.py`): 8 security rules at
  100% precision/recall on 104 labeled cases, with Bandit comparison and
  documented design tiers
- 305 tests, 92% coverage

### Earlier

- v0.1.0 (unreleased internal): initial scanner, 15 rules, SARIF/JSON output,
  bilingual reports, AI relay support
