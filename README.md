# CodeAudit 🛡️

> AI-powered code audit CLI for Python — security, quality, and performance analysis.
>
> AI 驱动的 Python 代码审计 CLI：安全、质量、性能一站式分析

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=flat&logo=python&logoColor=white" alt="Python"/>
  <img src="https://img.shields.io/badge/tests-60%20passed-brightgreen" alt="Tests"/>
  <img src="https://img.shields.io/badge/coverage-99%25-brightgreen" alt="Coverage"/>
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
| 2000-line file | ~0.4s |
| 100 files directory | ~0.4s |
| Empty file | ~0.01s |

---

## Testing

- 60 unit tests (pytest)
- 99% code coverage (pytest-cov)
- 13 mutation tests (behavioral validation)
- Integration tests for CLI, JSON output, Chinese output
- Dogfooding: we scan our own codebase

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

**安全**：SQL注入检测、硬编码密钥检测、危险函数检测（eval/exec/pickle/os.system）
**质量**：裸except、魔法数字、未定义变量、TODO注释、未使用变量
**性能**：圈复杂度、嵌套深度

## 注意事项

- 目前仅支持 Python — 更多语言正在规划中
- 纯静态分析，不是运行时安全工具
- 没有工具能发现所有问题，请结合人工审查
- 规则反映常见模式，可能不适用于所有代码库

## 测试

60 个单元测试，99% 代码覆盖率，13 个变异测试验证，CLI/JSON/中文输出集成测试。

</div>
