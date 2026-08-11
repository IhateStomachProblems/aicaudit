# CodeAudit

AI-powered code audit CLI for Python projects.

## Install

```bash
pip install codeaudit
```

## Usage

```bash
codeaudit scan ./src
codeaudit scan ./src --output json
codeaudit scan ./src --lang zh
```

## Rules

- **S001** SQL injection detection
- **S002** Hardcoded secret detection
- **S003** Dangerous function detection

## License

MIT
