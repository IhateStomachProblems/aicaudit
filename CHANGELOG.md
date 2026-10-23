# Changelog

## Unreleased

### Security hardening (dependency + attack surface)

- Dependency floors raised to patched versions: `jinja2>=3.1.5`
  (CVE-2024-56201/56326 sandbox breakout), `fastapi>=0.161.0` and explicit
  `starlette>=1.9.0` (CVE-2026-48710 "BadHost" host-header auth bypass,
  CVE-2026-54283 DoS). Fresh-install tree audited clean via pip-audit.
- Web UI: all file-touching endpoints (`/api/file-content`, fix
  preview/apply/rollback) are now session-scoped — paths outside the scanned
  project roots are rejected with 403. Previously, binding the server to a
  non-loopback host would have exposed arbitrary file read/restore.
- CI: new `supply-chain` job audits the resolved dependency tree with
  pip-audit on every push; Dependabot enabled (pip + github-actions, weekly).

### Performance

- Taint engine: refinement rounds now early-exit on convergence (a round that
  changes no summary and no override proves the fixed point; the analysis is
  deterministic). End-to-end scan of this repo's own codebase: 0.97s → 0.74s;
  single file 0.31s → 0.25s (Python 3.14, best of 3, same method before/after).
- Source text parsed by the engine is reused by the scan pass instead of
  re-reading every file from disk.
- Benchmark accuracy unchanged: 8 security rules still 100% P/R.

### Fixes

- Test hygiene: the external-rule-override test no longer leaves a custom rule
  registered as builtin S008 for the rest of the test session.

## v0.3.0 — Harness Integration (2026-10-04)

The harness-era release: aicaudit stops being just a CLI you run and becomes
a tool your AI editor calls for you.

### MCP server + agent skill

- `pip install aicaudit[mcp]` adds an official MCP server (`aicaudit mcp`, stdio):
  `scan`, `list_rules`, `verify`, `explain_finding`, `fix_preview` — taint paths
  and three-state AI verdicts are consumable directly by AI editors and agents
  (Claude Code, Cursor, Codex-style clients, anything speaking MCP)
- Agent skill at `skill/SKILL.md` (standard SKILL.md format) teaching skill-aware
  harnesses when/how to use the tools and how to interpret a taint path
- Dual-generation MCP SDK compatibility (v1 FastMCP / v2 MCPServer)

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
