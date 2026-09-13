# AICAudit 🛡️

> Evidence-driven AI code audit for Python — every verdict ships with a machine-checkable taint path.
>
> 证据链驱动的 Python 代码审计：每个判定都附带可复核的污点传播路径（source → … → sink）

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=flat&logo=python&logoColor=white" alt="Python"/>
  <img src="https://img.shields.io/badge/tests-305%20passed-brightgreen" alt="Tests"/>
  <img src="https://img.shields.io/badge/coverage-92%25-brightgreen" alt="Coverage"/>
  <img src="https://img.shields.io/badge/license-MIT-blue" alt="License"/>
  <img src="https://img.shields.io/badge/rules-15-brightgreen" alt="Rules"/>
  <img src="https://img.shields.io/badge/SARIF-2.1-blue" alt="SARIF"/>
  <img src="https://img.shields.io/github/stars/IhateStomachProblems/aicaudit?style=social" alt="Stars"/>
</p>

---

## Why AICAudit

Other tools give you a verdict. AICAudit gives you the **evidence**:

```text
S001  app.py:16  SQL injection risk
  taint path: app.py:14 request.args (Flask user input)
            -> app.py:14 assigned to 'uid'
            -> app.py:15 assigned to 'query'
            -> app.py:16 conn.execute()
```

- **Taint engine** (pure Python, zero plugins): tracks user input from source
  (Flask/Django/FastAPI request, `input()`, `os.environ`, `sys.argv`) through
  assignments, f-strings, concatenation, and **across function boundaries** to
  the sink — and proves constants safe, killing the classic false-positive
  classes (`open(BASE_DIR/"x")`, constant SQL variables, `eval("1+1")`)
- **AI verdicts with receipts**: the LLM sees the full function and the taint
  path, not a one-line snippet — hallucination-resistant by construction
- **SARIF codeFlows**: taint paths render natively in the GitHub Security tab
- **Zero config**: `pip install` and scan; works offline, local LLMs supported

---

## Quick Start

```bash
# From source (PyPI package arrives with v0.2.0)
pip install git+https://github.com/IhateStomachProblems/aicaudit.git
```

```bash
# Scan a file or directory
aicaudit scan ./src

# Markdown report (default)
aicaudit scan ./src --output markdown

# JSON output (for CI / scripts / AI agent integration)
aicaudit scan ./src --output json

# SARIF 2.1 output (GitHub Code Scanning compatible)
aicaudit scan ./src --output sarif

# Chinese language
aicaudit scan ./src --lang zh

# CI gate: exit 1 when any finding is error or worse (0 clean / 2 usage error)
aicaudit scan ./src --fail-on error
```

---

## CI & Git Integration

**One-line GitHub Action** (this repo ships a composite action at its root):

```yaml
- uses: IhateStomachProblems/aicaudit@main
  with:
    path: .
    fail-on: error      # optional: fail the job at this severity
    sarif: "true"       # optional: upload SARIF to Code Scanning
```

**pre-commit** (local hook until the PyPI release):

```yaml
repos:
  - repo: local
    hooks:
      - id: aicaudit
        name: aicaudit
        entry: aicaudit scan --fail-on error
        language: system
        types: [python]
```

**Project config** — generate it interactively:

```bash
aicaudit init            # writes [tool.aicaudit] into pyproject.toml
```

---

## Custom Rules (Python files, no DSL)

Drop rule files into `.aicaudit/rules/` (auto-discovered) or list extra dirs
under `[tool.aicaudit] rule-dirs`. Rules are ordinary Python using the public
API — a later registration with the same id overrides the builtin:

```python
# .aicaudit/rules/no_print.py
import ast
from aicaudit.rules.base import Finding, Rule, Severity, register

@register
class NoPrint(Rule):
    id = "Q100"
    name = "no-print"
    severity = Severity.INFO
    description = "Detect print() calls"

    def check(self, tree, context):
        return [Finding(rule_id=self.id, message="print() — prefer logging",
                        message_zh="print()——建议改用 logging",
                        file=str(context.file_path), line=n.lineno,
                        severity=self.severity)
                for n in ast.walk(tree)
                if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
                and n.func.id == "print"]
```

A ready-to-copy example lives at
[examples/custom_rule_example.py](examples/custom_rule_example.py).
(A declarative YAML rule format is planned for v0.3 — the loader is ready.)

---

## Rules

### Security

| ID | Rule | Severity |
|----|------|----------|
| S001 | SQL injection detection | CRITICAL |
| S002 | Hardcoded secret detection | CRITICAL |
| S003 | Dangerous functions (eval, exec, pickle, os.system) | ERROR |
| S004 | Path traversal detection | ERROR |
| S005 | SSRF detection | ERROR |
| S006 | Weak cryptography detection | WARNING |
| S007 | XML External Entity (XXE) detection | ERROR |
| S008 | Insecure random (non-crypto PRNG) | WARNING |

### Quality

| ID | Rule | Severity |
|----|------|----------|
| Q001 | Bare except detection | WARNING |
| Q002 | Magic number detection | INFO |
| Q003 | Undefined name detection | ERROR |
| Q004 | TODO/FIXME comment detection | INFO |
| Q005 | Unused variable detection | WARNING |

### Performance

| ID | Rule | Severity |
|----|------|----------|
| P001 | Cyclomatic complexity | WARNING |
| P002 | Nesting depth | WARNING |

---

## Inline Suppression

Suppress specific findings with inline comments:

```python
# Ignore a specific rule on this line
query = f"SELECT * FROM users WHERE id={user_id}"  # aicaudit: ignore S001

# Ignore all rules on this line
eval(user_input)  # aicaudit: ignore
```

---

## Web UI

Prefer a browser over the terminal? Start the built-in web interface:

```bash
aicaudit web          # http://127.0.0.1:8080
```

The UI is vendored and offline-first — no CDN, no build step, works air-gapped:

- **Results browser**: code context with syntax highlighting (server-side
  pygments), the **taint path as a visual stepper** (source → hops → sink),
  AI verdict card with confidence, and diff-preview/apply/rollback for fixes
- **Live scan progress**: per-file streaming (SSE), no fake progress bars
- **Scan history**: sessions persist under `.aicaudit/web/`, dashboard shows
  trends across runs
- Rules browser and AI provider config (relay / OpenAI / Claude / OpenRouter /
  local ollama)

API docs at `/docs` (Swagger UI). Found something rough? [Open an issue](https://github.com/IhateStomachProblems/aicaudit/issues).

---

## GitHub Code Scanning Integration

AICAudit produces [SARIF 2.1](https://sarifweb.azurewebsites.net/) output compatible with GitHub Code Scanning:

```bash
aicaudit scan ./src --output sarif > aicaudit.sarif
```

Upload the result in a GitHub Actions workflow:

```yaml
- name: Run AICAudit
  run: aicaudit scan . --output sarif > aicaudit.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: aicaudit.sarif
```

---

## Caveats

AICAudit is a young project. Here are some honest limitations:

- **Python only** for now — other languages are planned
- **Static analysis** — not a runtime security tool
- **Best-effort** — no tool catches every bug ; please review findings critically
- The rules reflect common patterns but may not fit every codebase

---

## Performance

| Scenario | Time |
|----------|------|
| 35 files directory | ~0.13s |
| Single file | ~0.01s |

---

## Benchmarks

Labeled corpus (104 cases: function-level samples + a realistic Flask app with
planted vulnerabilities), scored against ground truth with an honest
methodology — including the categories where aicaudit is deliberately
conservative or deliberately silent. Bandit runs on the same corpus for
reference; buckets Bandit does not cover are marked.

| Rule | aicaudit P/R | Bandit P/R (comparable bucket) |
|------|-------------|-------------------------------|
| S001 SQL injection | 100% / 100% | 100% / 86% |
| S003 dangerous functions | 100% / 100% | 92% / 75% |
| S004 path traversal | 100% / 100% | no coverage |
| S005 SSRF | 100% / 100% | no coverage |
| S007 XXE | 100% / 100% | 100% / 50% |

Full table with F1, timing, and the honest-notes section (design tiers,
conservative flags): [benchmarks/RESULTS.md](benchmarks/RESULTS.md).
Reproduce and challenge it yourself:

```bash
python benchmarks/run.py
```

---

## Testing

- 305 unit tests (pytest)
- 92% code coverage (pytest-cov)
- Taint engine: 17 dedicated tests (sources, constness, sanitizers, interprocedural)
- AI pipeline: fail-safe parsing, transport retry, category-aware prompts all tested
- Integration tests for CLI, JSON, Markdown, SARIF, Web UI, Chinese output
- Self-scan validation: we audit our own codebase
- CI: GitHub Actions on Python 3.10–3.13 (ruff + mypy + coverage + self-scan)

---

## AI Verdicts (evidence-grounded, fail-safe)

`aicaudit scan ./src --ai` attaches a verdict to every finding. The LLM sees
the full enclosing function, the file's imports, and the engine-traced taint
path — not a one-line snippet — and answers with a structured verdict
(`is_real`, `confidence`, `cwe`, `reason`, `suggested_fix`).

Three verdict states, by design:

| status | meaning |
|--------|---------|
| `confirmed` | AI agrees it is real, confidence ≥ 0.5 |
| `false_positive` | AI judged it noise (reason always included) |
| `unverified` | missing/failed/low-confidence response — **never** auto-confirmed |

Why not auto-filter? The best published LLM-verifier configurations still
wrongly suppress ~22% of true vulnerabilities ([arXiv 2601.22952](https://arxiv.org/abs/2601.22952)),
so verdicts mark findings instead of deleting them. If you want aggressive
filtering anyway, it is an explicit opt-in:

```bash
aicaudit scan ./src --ai --ai-strict    # keep only AI-confirmed findings
```

Prompts are category-aware: injection-class findings (S001/S003/S004/S005/S007)
get dataflow verification instructions anchored on the taint path;
policy-class findings (S002/S006/S008) get usage-context instructions —
targeting the documented failure modes of LLM verifiers (surface pattern
matching, CWE mislabeling, crypto/policy dismissals).

---

## AI Configuration

AICAudit supports multiple LLM providers for AI-powered verification.

### Direct API

```bash
# OpenAI
export AICAUDIT_AI_PROVIDER=openai
export AICAUDIT_AI_KEY=sk-xxx
aicaudit scan ./src --ai

# Claude
export AICAUDIT_AI_PROVIDER=claude
export ANTHROPIC_API_KEY=sk-ant-xxx
aicaudit scan ./src --ai
```

### Relay / Proxy Service (中转接口)

Any OpenAI-compatible relay service works. Set the provider to `relay` and point to your relay endpoint:

```bash
# Example: API2D, OhMyGPT, NewAPI, OneAPI, etc.
export AICAUDIT_AI_PROVIDER=relay
export AICAUDIT_AI_BASE=https://your-relay.com/v1
export AICAUDIT_AI_KEY=sk-your-key
export AICAUDIT_AI_MODEL=gpt-4o-mini
aicaudit scan ./src --ai
```

Also accepts `custom` or `proxy` as provider names for the same behavior.

### Local Models

```bash
export AICAUDIT_AI_PROVIDER=ollama
aicaudit scan ./src --ai
```

---

## License

MIT © IhateStomachProblems

---

<div align="center">

---

# AICAudit 中文版

## 快速开始

```bash
# 源码安装（v0.2.0 将上架 PyPI）
pip install git+https://github.com/IhateStomachProblems/aicaudit.git
aicaudit scan ./项目目录    # 扫描项目
aicaudit scan ./src --lang zh  # 使用中文输出
aicaudit scan ./src --output json  # JSON 输出
aicaudit scan ./src --output sarif  # SARIF 输出（GitHub Code Scanning 兼容）
```

## 规则列表

**安全**：SQL注入检测、硬编码密钥检测、危险函数检测、路径遍历、SSRF、弱加密、XXE、不安全随机数
**质量**：裸except、魔法数字、未定义变量、TODO注释、未使用变量
**性能**：圈复杂度、嵌套深度

## 行内抑制

```python
# 忽略特定规则
query = f"SELECT * FROM users WHERE id={user_id}"  # aicaudit: ignore S001

# 忽略该行所有规则
eval(user_input)  # aicaudit: ignore
```

## GitHub Code Scanning 集成

```bash
aicaudit scan ./src --output sarif > aicaudit.sarif
```

在 GitHub Actions 中上传结果：

```yaml
- name: Run AICAudit
  run: aicaudit scan . --output sarif > aicaudit.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: aicaudit.sarif
```

## 注意事项

- 目前仅支持 Python — 更多语言正在规划中
- 纯静态分析，不是运行时安全工具
- 没有工具能发现所有问题，请结合人工审查
- 规则反映常见模式，可能不适用于所有代码库

## 测试

305 个单元测试，92% 代码覆盖率：污点引擎专项、AI 判定管线（fail-safe/重试/类别感知 prompt）、Web UI（SSE/pygments/修复回滚/会话持久化）、CI 退出码/init 向导/外部规则目录、CLI/JSON/Markdown/SARIF/中文输出全覆盖。
