"""Configuration loading for CodeAudit.

Reads settings from:
1. pyproject.toml [tool.codeaudit] section (project level)
2. .codeauditignore file (path exclusions)
3. CLI arguments (highest priority, overrides config)

Design notes:
- Never crash on bad config — fall back to sane defaults
- Rule filters use closed sets, validated against the registry
- Path ignores support glob patterns
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class AuditConfig:
    rules: set[str] = field(default_factory=set)      # empty = run all
    min_severity: str | None = None                    # None = no filter
    ignore_patterns: list[str] = field(default_factory=list)


def find_project_root(start: Path) -> Path:
    """Walk up to find the directory containing pyproject.toml or setup.py."""
    for current in [start, *start.parents]:
        if (current / "pyproject.toml").exists() or (current / "setup.py").exists():
            return current
    return start


def load_pyproject(root: Path) -> dict:
    """Load [tool.codeaudit] from pyproject.toml. Never raises."""
    # Python 3.10 uses tomli; 3.11+ has tomllib built in
    try:
        import tomllib
    except ImportError:  # pragma: no cover - py3.10 compat
        import tomli as tomllib  # type: ignore

    pyproject = root / "pyproject.toml"
    if not pyproject.exists():
        return {}
    try:
        with open(pyproject, "rb") as f:
            data = tomllib.load(f)
        return data.get("tool", {}).get("codeaudit", {})
    except Exception:  # noqa: BLE001 - broken config should not crash the tool
        return {}


def load_ignore_file(root: Path) -> list[str]:
    """Read .codeauditignore (one glob per line, empty/comment lines skipped)."""
    path = root / ".codeauditignore"
    if not path.exists():
        return []
    patterns = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            patterns.append(line)
    return patterns


def merge_config(cli_rules, cli_min_severity, start: Path | None = None) -> AuditConfig:
    """Merge config file + .codeauditignore + CLI overrides."""
    root = find_project_root(start or Path.cwd())
    file_cfg = load_pyproject(root)
    ignore_patterns = load_ignore_file(root)

    # rules: CLI wins, else config
    rules: set[str] = set()
    if cli_rules:
        rules = {r.strip().upper() for r in cli_rules.split(",") if r.strip()}
    elif file_cfg.get("rules"):
        rules = {str(r).strip().upper() for r in file_cfg["rules"] if str(r).strip()}

    # min-severity: CLI wins, else config
    min_sev = cli_min_severity or file_cfg.get("min-severity") or file_cfg.get("min_severity")

    # ignore: config file patterns + .codeauditignore patterns
    ignore = list(file_cfg.get("ignore", []))
    ignore.extend(ignore_patterns)

    return AuditConfig(
        rules=rules,
        min_severity=str(min_sev) if min_sev else None,
        ignore_patterns=[str(p) for p in ignore],
    )


def matches_ignore(path: Path, patterns: list[str], root: Path | None = None) -> bool:
    """Check if path matches any ignore pattern (glob)."""
    if not patterns:
        return False
    base = root or Path.cwd()
    try:
        rel = path.relative_to(base)
    except ValueError:
        rel = path
    rel_str = str(rel).replace(os.sep, "/")
    for pat in patterns:
        p = pat.replace(os.sep, "/").strip("/")
        if p and (rel_str == p or rel_str.startswith(p + "/") or _fnmatch(rel_str, p)):
            return True
    return False


def _fnmatch(name: str, pattern: str) -> bool:
    """Minimal glob matcher: * matches any chars, ** matches across /"""
    import fnmatch
    if "**" in pattern:
        parts = pattern.split("**")
        if len(parts) == 2:
            prefix, suffix = parts
            return name.startswith(prefix) and name.endswith(suffix)
    return fnmatch.fnmatch(name, pattern)
