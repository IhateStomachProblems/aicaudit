# CodeAudit 🛡️

> AI-powered code audit CLI for Python — security, quality, and performance analysis.
>
> AI 驱动的 Python 代码审计 CLI：安全、质量、性能一站式分析

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=flat&logo=python&logoColor=white" alt="Python"/>
  <img src="https://img.shields.io/badge/tests-204%20passed-brightgreen" alt="Tests"/>
  <img src="https://img.shields.io/badge/coverage-91%25-brightgreen" alt="Coverage"/>
  <img src="https://img.shields.io/badge/license-MIT-blue" alt="License"/>
  <img src="https://img.shields.io/badge/rules-15-brightgreen" alt="Rules"/>
  <img src="https://img.shields.io/badge/SARIF-2.1-blue" alt="SARIF"/>
  <img src="https://img.shields.io/github/stars/IhateStomachProblems/codeaudit?style=social" alt="Stars"/>
</p>

---

## Quick Start

```bash
pip install codeaudit
```

```bash
# Scan a file or directory
codeaudit scan ./src

# Markdown report (default)
codeaudit scan ./src --output markdown

# JSON output (for CI / scripts / AI agent integration)
codeaudit scan ./src --output json

# SARIF 2.1 output (GitHub Code Scanning compatible)
codeaudit scan ./src --output sarif

# Chinese language
codeaudit scan ./src --lang zh
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
query = f"SELECT * FROM users WHERE id={user_id}"  # codeaudit: ignore S001

# Ignore all rules on this line
eval(user_input)  # codeaudit: ignore
```

---

## GitHub Code Scanning Integration

CodeAudit produces [SARIF 2.1](https://sarifweb.azurewebsites.net/) output compatible with GitHub Code Scanning:

```bash
codeaudit scan ./src --output sarif > codeaudit.sarif
```

Upload the result in a GitHub Actions workflow:

```yaml
- name: Run CodeAudit
  run: codeaudit scan . --output sarif > codeaudit.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: codeaudit.sarif
```

---

## Caveats

CodeAudit is a young project. Here are some honest limitations:

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

- 204 unit tests (pytest)
- 91% code coverage (pytest-cov)
- Integration tests for CLI, JSON, Markdown, SARIF, Chinese output
- Self-scan validation: we audit our own codebase
- CI: GitHub Actions on Python 3.10–3.13 (ruff + mypy + coverage + self-scan)

---

## AI Configuration

CodeAudit supports multiple LLM providers for AI-powered verification.

### Direct API

```bash
# OpenAI
export CODEAUDIT_AI_PROVIDER=openai
export CODEAUDIT_AI_KEY=sk-xxx
codeaudit scan ./src --ai

# Claude
export CODEAUDIT_AI_PROVIDER=claude
export ANTHROPIC_API_KEY=sk-ant-xxx
codeaudit scan ./src --ai
```

### Relay / Proxy Service (中转接口)

Any OpenAI-compatible relay service works. Set the provider to `relay` and point to your relay endpoint:

```bash
# Example: API2D, OhMyGPT, NewAPI, OneAPI, etc.
export CODEAUDIT_AI_PROVIDER=relay
export CODEAUDIT_AI_BASE=https://your-relay.com/v1
export CODEAUDIT_AI_KEY=sk-your-key
export CODEAUDIT_AI_MODEL=gpt-4o-mini
codeaudit scan ./src --ai
```

Also accepts `custom` or `proxy` as provider names for the same behavior.

### Local Models

```bash
export CODEAUDIT_AI_PROVIDER=ollama
codeaudit scan ./src --ai
```

---

## License

MIT © IhateStomachProblems

---

<div align="center">

---

# CodeAudit 中文版

## 快速开始

```bash
pip install codeaudit
codeaudit scan ./项目目录    # 扫描项目
codeaudit scan ./src --lang zh  # 使用中文输出
codeaudit scan ./src --output json  # JSON 输出
codeaudit scan ./src --output sarif  # SARIF 输出（GitHub Code Scanning 兼容）
```

## 规则列表

**安全**：SQL注入检测、硬编码密钥检测、危险函数检测、路径遍历、SSRF、弱加密、XXE、不安全随机数
**质量**：裸except、魔法数字、未定义变量、TODO注释、未使用变量
**性能**：圈复杂度、嵌套深度

## 行内抑制

```python
# 忽略特定规则
query = f"SELECT * FROM users WHERE id={user_id}"  # codeaudit: ignore S001

# 忽略该行所有规则
eval(user_input)  # codeaudit: ignore
```

## GitHub Code Scanning 集成

```bash
codeaudit scan ./src --output sarif > codeaudit.sarif
```

在 GitHub Actions 中上传结果：

```yaml
- name: Run CodeAudit
  run: codeaudit scan . --output sarif > codeaudit.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: codeaudit.sarif
```

## 注意事项

- 目前仅支持 Python — 更多语言正在规划中
- 纯静态分析，不是运行时安全工具
- 没有工具能发现所有问题，请结合人工审查
- 规则反映常见模式，可能不适用于所有代码库

## 测试

204 个单元测试，91% 代码覆盖率，CLI/JSON/Markdown/SARIF/中文输出集成测试。
