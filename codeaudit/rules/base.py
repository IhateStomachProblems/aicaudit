"""Rules: the atomic unit of code audit."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from enum import Enum
from pathlib import Path


class Severity(Enum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass
class Finding:
    rule_id: str
    message: str           # English by default, .zh for Chinese
    message_zh: str
    file: str
    line: int
    severity: Severity
    snippet: str | None = None
    fix: str | None = None

    def text(self, lang: str = "en") -> str:
        return self.message if lang == "en" else self.message_zh


@dataclass
class ScanContext:
    """What the scanner knows about the current file."""
    file_path: Path
    source: str
    lines: list[str]
    lang: str = "en"


class Rule:
    """Base class for all audit rules.

    Subclasses set `id`, `name`, `severity`, and implement `check()`.
    """

    id: str = ""
    name: str = ""
    severity: Severity = Severity.WARNING
    description: str = ""
    description_zh: str = ""

    def check(self, tree: ast.AST, context: ScanContext) -> list[Finding]:
        raise NotImplementedError


_registry: dict[str, type[Rule]] = {}


def register(cls: type[Rule]) -> type[Rule]:
    """Decorator: register a rule class so the scanner can find it."""
    _registry[cls.id] = cls
    return cls


def get_rule(rule_id: str) -> type[Rule] | None:
    return _registry.get(rule_id)


def all_rules() -> list[type[Rule]]:
    return list(_registry.values())


def active_rules(include: set[str] | None = None) -> list[type[Rule]]:
    """Return rules that should run. Empty include means all."""
    if include is None or not include:
        return all_rules()
    return [cls for cls in _registry.values() if cls.id in include]

