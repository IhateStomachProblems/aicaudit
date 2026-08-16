# CodeAudit 🛡️

> AI-powered code audit CLI for Python — security, quality, and performance analysis.
>
> AI 驱动的 Python 代码审计 CLI：安全、质量、性能一站式分析

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=flat&logo=python&logoColor=white" alt="Python"/>
  <img src="https://img.shields.io/badge/tests-182%20passed-brightgreen" alt="Tests"/>
  <img src="https://img.shields.io/badge/coverage-91%25-brightgreen" alt="Coverage"/>
  <img src="https://img.shields.io/badge/license-MIT-blue" alt="License"/>
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

# JSON output (for CI / AI agent integration)
codeaudit scan ./src --output json

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
| 100 files directory | ~0.8s |
| Single file | ~0.01s |
| Empty file | ~0.01s |

---

## Testing

- 182 unit tests (pytest)
- 91% code coverage (pytest-cov)
- Integration tests for CLI, JSON output, Chinese output
- Self-scan validation: we audit our own codebase

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
```

## 规则列表

**安全**：SQL注入检测、硬编码密钥检测、危险函数检测、路径遍历、SSRF、弱加密、XXE
**质量**：裸except、魔法数字、未定义变量、TODO注释、未使用变量
**性能**：圈复杂度、嵌套深度

## 注意事项

- 目前仅支持 Python — 更多语言正在规划中
- 纯静态分析，不是运行时安全工具
- 没有工具能发现所有问题，请结合人工审查
- 规则反映常见模式，可能不适用于所有代码库

## 测试

182 个单元测试，91% 代码覆盖率，CLI/JSON/中文输出集成测试。


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

<div align="center"></div>
