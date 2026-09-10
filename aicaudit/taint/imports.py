"""Import-alias resolution: map local names to canonical dotted names."""
from __future__ import annotations

import ast


class ImportTable:
    """Resolves names introduced by import statements in one file."""

    def __init__(self) -> None:
        # local alias -> canonical module or object, e.g. "sp" -> "subprocess"
        self.aliases: dict[str, str] = {}
        self.modules: set[str] = set()   # canonical module names imported

    @classmethod
    def from_tree(cls, tree: ast.AST) -> ImportTable:
        """File-wide alias table (all imports, any nesting)."""
        table = cls()
        for node in ast.walk(tree):
            table._add_import(node)
        return table

    @classmethod
    def from_module(cls, tree: ast.Module) -> ImportTable:
        """Alias table from module-level imports only (no nested scopes)."""
        table = cls()
        for node in tree.body:
            table._add_import(node)
        return table

    @classmethod
    def from_scope(cls, node: ast.FunctionDef | ast.AsyncFunctionDef,
                   base: ImportTable | None = None) -> ImportTable:
        """Alias table for one function scope: module imports + local ones.

        Nested function/class bodies are skipped (they build their own scope).
        """
        table = cls()
        if base is not None:
            table.aliases.update(base.aliases)
            table.modules.update(base.modules)
        stack: list[ast.AST] = list(ast.iter_child_nodes(node))
        while stack:
            sub = stack.pop()
            if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            table._add_import(sub)
            stack.extend(ast.iter_child_nodes(sub))
        return table

    def _add_import(self, node: ast.AST) -> None:
        if isinstance(node, ast.Import):
            for alias in node.names:
                self.modules.add(alias.name)
                local = alias.asname or alias.name.split(".")[0]
                self.aliases[local] = alias.name if alias.asname else alias.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            self.modules.add(node.module)
            for alias in node.names:
                local = alias.asname or alias.name
                self.aliases[local] = f"{node.module}.{alias.name}"

    def resolve_name(self, name: str) -> str:
        """Resolve a bare name to its canonical dotted name (or itself)."""
        if name in self.aliases:
            return self.aliases[name]
        if name in _BUILTIN_NAMES:
            return f"builtins.{name}"
        return name

    def has_any_module(self, modules: set[str]) -> bool:
        return bool(self.modules & modules)


_BUILTIN_NAMES = {
    "abs", "all", "any", "ascii", "bin", "bool", "bytes", "callable", "chr",
    "compile", "dict", "dir", "divmod", "enumerate", "eval", "exec", "filter",
    "float", "format", "frozenset", "getattr", "hash", "hex", "id", "input",
    "int", "isinstance", "len", "list", "map", "max", "min", "next", "object",
    "oct", "open", "ord", "pow", "range", "repr", "reversed", "round", "set",
    "slice", "sorted", "str", "sum", "tuple", "type", "zip",
}


def dotted_name(node: ast.AST, table: ImportTable) -> str | None:
    """Build the canonical dotted name of an expression node, or None."""
    parts: list[str] = []
    cur = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(table.resolve_name(cur.id))
        return ".".join(reversed(parts))
    if isinstance(cur, ast.Call):
        name = dotted_name(cur.func, table)
        return f"{name}()" if name else None
    return None
