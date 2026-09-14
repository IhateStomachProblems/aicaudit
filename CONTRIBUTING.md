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

Before submitting a PR, ensure (CI enforces the same):

```bash
ruff check aicaudit tests
mypy aicaudit --ignore-missing-imports
pytest tests/ --cov=aicaudit --cov-fail-under=90
```

## Adding a New Rule

**External rule (easiest — no core changes):**

1. Write a Python file using the public API — see
   [examples/custom_rule_example.py](examples/custom_rule_example.py)
2. Drop it into `.aicaudit/rules/` (auto-discovered) or a dir listed under
   `[tool.aicaudit] rule-dirs`
3. Test it against real code: `aicaudit scan <target>`

**Builtin rule:**

1. Create `aicaudit/rules/<category>/<name>.py`
2. Subclass `Rule`, set `id`, `name`, `severity`, and implement `check()`
3. Decorate with `@register`; add the module name to `_RULE_MODULES` in `scan.py`
4. Write tests in `tests/` (positive AND negative cases — false positives are
   treated as bugs here)
5. Update the README rules table

## Honesty Policy

- Every number in the README (tests, coverage, benchmark results) must be
  reproducible from the repo. Regenerate with `pytest` and
  `python benchmarks/run.py` before submitting changes that affect them.
- Security findings in `tests/`, `benchmarks/corpus/`, and `examples/` are
  labeled fixtures, not vulnerabilities.

## Style Guide

- Follow the project's existing style (PEP8 + ruff defaults)
- Keep functions small and focused
- No excessive comments — let the code speak
- Add both English and Chinese messages to every Finding
