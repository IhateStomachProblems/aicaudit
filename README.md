# AICAudit 🛡️

> AI-powered code audit CLI for Python — security, quality, and performance analysis.
>
> AI 驱动的 Python 代码审计 CLI：安全、质量、性能一站式分析

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=flat&logo=python&logoColor=white" alt="Python"/>
  <img src="https://img.shields.io/badge/tests-230%20passed-brightgreen" alt="Tests"/>
  <img src="https://img.shields.io/badge/coverage-91%25-brightgreen" alt="Coverage"/>
  <img src="https://img.shields.io/badge/license-MIT-blue" alt="License"/>
  <img src="https://img.shields.io/badge/rules-15-brightgreen" alt="Rules"/>
  <img src="https://img.shields.io/badge/SARIF-2.1-blue" alt="SARIF"/>
  <img src="https://img.shields.io/github/stars/IhateStomachProblems/aicaudit?style=social" alt="Stars"/>
</p>

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
```

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

Pages: Dashboard, Scan, Rules, AI Config. API docs at `/docs` (Swagger UI).
The web UI is young — report anything that feels off.

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

## Testing

- 230 unit tests (pytest)
- 91% code coverage (pytest-cov)
- Integration tests for CLI, JSON, Markdown, SARIF, Web UI, Chinese output
- Self-scan validation: we audit our own codebase
- CI: GitHub Actions on Python 3.10–3.13 (ruff + mypy + coverage + self-scan)

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

230 个单元测试，91% 代码覆盖率，CLI/JSON/Markdown/SARIF/Web UI/中文输出集成测试。
