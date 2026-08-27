# Contributing to AICAudit

Thanks for considering contributing! Here's what you need to know.

## Development Setup

```bash
git clone https://github.com/IhateStomachProblems/aicaudit.git
cd aicaudit
pip install -e .
pip install pytest pytest-cov ruff mypy
```

## Running Tests

```bash
pytest tests/ -v
```

## Code Quality Gates

Before submitting a PR, ensure:

```bash
ruff check aicaudit tests
mypy aicaudit --ignore-missing-imports
pytest tests/ --cov=aicaudit --cov-fail-under=95
```

## Adding a New Rule

1. Create `aicaudit/rules/<category>/<name>.py`
2. Subclass `Rule`, set `id`, `name`, `severity`, and implement `check()`
3. Decorate with `@register`
4. Add it to `_import_all_rules()` in `scan.py`
5. Write tests in `tests/`
6. Update the README rules table

## Style Guide

- Follow the project's existing style (PEP8 + ruff defaults)
- Keep functions small and focused
- No excessive comments — let the code speak
- Add both English and Chinese messages to every Finding
