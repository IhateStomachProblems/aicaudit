"""Code knowledge graph: call graph, entry points, import index, evidence chains.

This is the core of CodeAudit's AI audit competitive advantage:
- Tool builds structured understanding of the codebase
- AI audit consumes evidence chains, not raw files
- Each finding is backed by a traceable call path
"""

import ast
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class FuncDef:
    name: str
    file: str
    line: int
    docstring: str = ""
    calls: set = field(default_factory=set)


@dataclass
class EntryPoint:
    kind: str
    location: str
    pattern: str = ""
    method: str = "GET"


@dataclass
class Sink:
    func: str
    file: str
    line: int
    code: str = ""


@dataclass
class EvidenceChain:
    entry: str
    path: list
    sink: str
    risk: str = "medium"


class CodeGraph:
    def __init__(self, root: Path):
        self.root = root
        self.funcs: dict[str, list[FuncDef]] = defaultdict(list)
        self.entry_points: list[EntryPoint] = []
        self.sinks: list[Sink] = []
        self.files: list[Path] = []
        self._built = False

    def build(self):
        self.files = list(self.root.rglob("*.py"))
        for fp in self.files:
            try:
                source = fp.read_text(encoding="utf-8-sig", errors="replace")
                tree = ast.parse(source)
                self._scan_file(fp, tree, source)
            except (SyntaxError, OSError):
                continue
        self._built = True

    def _scan_file(self, file_path: Path, tree: ast.AST, source: str):
        rel = str(file_path.relative_to(self.root))
        lines = source.splitlines(keepends=False)
        for node in ast.walk(tree):
            self._scan_funcdef(node, rel)
            self._scan_entrypoint(node, rel)
            self._scan_sink(node, rel, lines)

    def _scan_funcdef(self, node, rel):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return
        calls = {self._call_name(sub) for sub in ast.walk(node)
                 if isinstance(sub, ast.Call) and self._call_name(sub)}
        self.funcs[node.name].append(FuncDef(
            name=node.name, file=rel, line=node.lineno or 0,
            docstring=ast.get_docstring(node) or "", calls=calls))

    def _scan_entrypoint(self, node, rel):
        if isinstance(node, ast.Call):
            name = self._call_name(node)
            if name and "route" in name:
                for kw in node.keywords:
                    if kw.arg == "rule" and isinstance(kw.value, ast.Constant):
                        self.entry_points.append(EntryPoint(
                            kind="route", location=f"{rel}:{node.lineno}",
                            pattern=str(kw.value.value)))
        if isinstance(node, ast.If) and self._is_main_check(node):
            self.entry_points.append(EntryPoint(
                kind="main", location=f"{rel}:{node.lineno}"))

    def _scan_sink(self, node, rel, lines):
        if not isinstance(node, ast.Call):
            return
        name = self._call_name(node)
        if name and name in ("eval", "exec", "os.system", "subprocess.run",
                            "subprocess.Popen", "pickle.loads", "yaml.load",
                            "conn.execute", "cursor.execute"):
            self.sinks.append(Sink(
                func=name, file=rel, line=node.lineno or 0,
                code=lines[node.lineno - 1].strip() if node.lineno else ""))

    @staticmethod
    def _call_name(node: ast.Call) -> str:
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            parts = []
            cur = node.func  # type: ignore[assignment]
            while isinstance(cur, ast.Attribute):
                parts.append(cur.attr)
                cur = cur.value  # type: ignore[assignment]
            if isinstance(cur, ast.Name):
                parts.append(cur.id)
            return ".".join(reversed(parts))
        return ""

    @staticmethod
    def _is_main_check(node: ast.If) -> bool:
        return (isinstance(node.test, ast.Compare)
                and isinstance(node.test.left, ast.Name)
                and node.test.left.id == "__name__"
                and any(isinstance(c, ast.Constant) and c.value == "__main__"
                        for c in ast.walk(node.test)))

    def callers_of(self, func_name: str) -> list[FuncDef]:
        return [fd for fds in self.funcs.values() for fd in fds if func_name in fd.calls]

    def callees_of(self, func_name: str) -> list[FuncDef]:
        result = []
        for fd in self.funcs.get(func_name, []):
            for name in fd.calls:
                result.extend(self.funcs.get(name, []))
        return result

    def find_evidence_chain(self, func_name: str, max_depth=3) -> list[EvidenceChain]:
        chains = []
        for ep in self.entry_points:
            path = self._trace_path(ep.location, func_name, max_depth, set())
            if path:
                chains.append(EvidenceChain(
                    entry=f"{ep.kind}: {ep.pattern or ep.location}",
                    path=path, sink=func_name,
                    risk="high" if any(s.func == func_name for s in self.sinks) else "medium"))
        return chains

    def _trace_path(self, start_loc, target, depth, visited):
        if depth <= 0:
            return None
        key = f"{start_loc}->{target}"
        if key in visited:
            return None
        visited.add(key)
        for fd_list in self.funcs.values():
            for fd in fd_list:
                if target in fd.calls:
                    if fd.name == target or fd.name == start_loc.split(":")[0]:
                        return [(fd.file, fd.line, fd.name)]
                    deeper = self._trace_path(start_loc, fd.name, depth - 1, visited)
                    if deeper is not None:
                        return deeper + [(fd.file, fd.line, fd.name)]
        return None
