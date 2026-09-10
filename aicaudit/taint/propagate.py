"""Intra-procedural taint + constness analysis.

Walks one scope (module or function) tracking an environment of variable
abstract values. Every expression gets a state in {CONST, CLEAN, UNKNOWN,
TAINTED}; dangerous calls record SinkEvents with full source-to-sink paths.

Design notes:
- Sequential statement visit (branches both visited; merges are unions) —
  sound for taint, may under-kill constness, never produces false "safe".
- Params are seeded UNKNOWN with param_deps so the inter-procedural pass can
  upgrade (tainted caller) or refine (all-constant callers) them later.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, field

from aicaudit.taint.catalog import (
    FRAMEWORK_REQUEST_NAMES,
    PROPAGATOR_CALLS,
    PURE_FUNCS,
    PURE_METHODS,
    SANITIZER_CALLS,
    SANITIZER_METHODS,
    SOURCE_CALLS,
    SOURCE_OBJECTS,
    WEB_FRAMEWORK_MODULES,
    sink_for_attr,
    sink_for_call,
)
from aicaudit.taint.imports import ImportTable, dotted_name
from aicaudit.taint.model import (
    CLEAN,
    CONST,
    TAINTED,
    UNKNOWN,
    FuncSummary,
    SinkEvent,
    TaintHop,
    TaintOrigin,
    TaintPath,
    VarInfo,
)


def _merge(infos: list[VarInfo]) -> VarInfo:
    out = VarInfo(state=CONST)
    for info in infos:
        out = out.merged(info)
    return out


def _copy_paths(info: VarInfo) -> list[TaintPath]:
    return [TaintPath(origin=p.origin, hops=list(p.hops)) for p in info.paths]


_MAX_RETURN_PATHS = 4


@dataclass
class CallEdge:
    """A call to a locally-defined function, kept for the inter-procedural pass."""

    callee: str                 # bare function name as written
    file: str
    line: int
    args: list[VarInfo] = field(default_factory=list)


@dataclass
class FuncAnalysis:
    """Everything learned about one function (or module scope)."""

    name: str
    file: str
    node: ast.FunctionDef | ast.AsyncFunctionDef | ast.Module
    summary: FuncSummary
    events: list[SinkEvent] = field(default_factory=list)
    edges: list[CallEdge] = field(default_factory=list)


class ScopeAnalyzer:
    """Analyzes one scope; usable for module level and for functions.

    ``summarize`` (optional) resolves a bare callee name to a FuncSummary for
    return-taint propagation through locally-defined functions.
    """

    def __init__(self, file: str, table: ImportTable, base_env: dict[str, VarInfo] | None = None,
                 param_names: list[str] | None = None,
                 param_overrides: dict[str, VarInfo] | None = None,
                 summarize=None) -> None:
        self.file = file
        self.table = table
        self.env: dict[str, VarInfo] = dict(base_env or {})
        self.events: list[SinkEvent] = []
        self.edges: list[CallEdge] = []
        self.arg_states: dict[int, str] = {}
        self.call_events: dict[int, SinkEvent] = {}
        self.return_infos: list[VarInfo] = []
        self.param_names = param_names or []
        self.summarize = summarize
        for p in self.param_names:
            if param_overrides and p in param_overrides:
                self.env[p] = param_overrides[p]
            else:
                self.env[p] = VarInfo(state=UNKNOWN, param_deps={p})

    # ── statements ────────────────────────────────────────────────────────

    def visit_body(self, body: list[ast.stmt]) -> None:
        for stmt in body:
            self.visit_stmt(stmt)

    def visit_stmt(self, node: ast.stmt) -> None:
        if isinstance(node, ast.Assign):
            value = self.eval_expr(node.value)
            for target in node.targets:
                self.assign(target, value, node.lineno)
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign)):
            value = self.eval_expr(node.value) if node.value else VarInfo(state=UNKNOWN)
            if isinstance(node, ast.AugAssign):
                current = self.eval_expr(node.target)
                value = current.merged(value)
            self.assign(node.target, value, node.lineno)
        elif isinstance(node, ast.Return):
            if node.value:
                self.return_infos.append(self.eval_expr(node.value))
        elif isinstance(node, ast.For):
            iter_info = self.eval_expr(node.iter)
            self.assign(node.target, iter_info, node.lineno)
            self.visit_body(node.body)
            self.visit_body(node.orelse)
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                if item.optional_vars is not None:
                    self.eval_expr(item.context_expr)   # record any sink on the context expr
                    self.assign(item.optional_vars, VarInfo(state=UNKNOWN), item.context_expr.lineno)
            self.visit_body(node.body)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            pass    # analyzed separately
        elif isinstance(node, ast.Try):
            self.visit_body(node.body)
            for handler in node.handlers:
                self.visit_body(handler.body)
            self.visit_body(node.orelse)
            self.visit_body(node.finalbody)
        else:
            for child in ast.iter_child_nodes(node):
                if isinstance(child, ast.stmt):
                    self.visit_stmt(child)
                elif isinstance(child, ast.expr):
                    self.eval_expr(child)
                else:
                    for sub in ast.walk(child):
                        if isinstance(sub, ast.expr):
                            self.eval_expr(sub)

    def assign(self, target: ast.AST, value: VarInfo, line: int) -> None:
        if isinstance(target, ast.Name):
            stored = VarInfo(
                state=value.state,
                paths=self._extended(value, f"assigned to '{target.id}'", line),
                param_deps=set(value.param_deps),
                canonical=value.canonical,
            )
            self.env[target.id] = stored
        elif isinstance(target, ast.Attribute):
            key = self._attr_key(target)
            if key:
                self.env[key] = VarInfo(
                    state=value.state,
                    paths=self._extended(value, f"assigned to '{key}'", line),
                    param_deps=set(value.param_deps),
                )
        elif isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                self.assign(elt, value, line)
        elif isinstance(target, ast.Subscript):
            base = self._subscript_base_name(target)
            if base and base in self.env:
                cur = self.env[base]
                if value.state in (TAINTED, UNKNOWN):
                    self.env[base] = cur.merged(value)
        elif isinstance(target, ast.Starred):
            self.assign(target.value, value, line)

    def _extended(self, value: VarInfo, desc: str, line: int) -> list[TaintPath]:
        paths = _copy_paths(value)
        for p in paths:
            p.hops.append(TaintHop(file=self.file, line=line, desc=desc))
        return paths

    def _attr_key(self, node: ast.Attribute) -> str | None:
        parts: list[str] = []
        cur: ast.AST = node
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
            return ".".join(reversed(parts))
        return None

    def _subscript_base_name(self, node: ast.Subscript) -> str | None:
        cur: ast.AST = node
        while isinstance(cur, ast.Subscript):
            cur = cur.value
        if isinstance(cur, ast.Name):
            return cur.id
        return None

    # ── expressions ───────────────────────────────────────────────────────

    def eval_expr(self, node: ast.AST) -> VarInfo:
        if isinstance(node, ast.Constant):
            return VarInfo(state=CONST)
        if isinstance(node, ast.Name):
            if node.id in ("__file__", "__name__", "__doc__", "__package__", "__spec__"):
                return VarInfo(state=CONST)
            info = self.env.get(node.id)
            if info:
                return info
            resolved = self.table.resolve_name(node.id)
            if resolved in SOURCE_OBJECTS:
                return self._source_info(resolved, SOURCE_OBJECTS[resolved], node.lineno)
            return VarInfo(state=UNKNOWN, canonical=resolved if resolved != node.id else None)
        if isinstance(node, ast.Attribute):
            return self.eval_attribute(node)
        if isinstance(node, ast.Subscript):
            return self.eval_subscript(node)
        if isinstance(node, ast.Call):
            return self.eval_call(node)
        if isinstance(node, ast.BinOp):
            return _merge([self.eval_expr(node.left), self.eval_expr(node.right)])
        if isinstance(node, ast.JoinedStr):
            return _merge([self.eval_expr(v) for v in node.values])
        if isinstance(node, ast.FormattedValue):
            return self.eval_expr(node.value)
        if isinstance(node, ast.BoolOp):
            return _merge([self.eval_expr(v) for v in node.values])
        if isinstance(node, ast.IfExp):
            return _merge([self.eval_expr(node.body), self.eval_expr(node.orelse)])
        if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
            return _merge([self.eval_expr(e) for e in node.elts])
        if isinstance(node, ast.Dict):
            return _merge([self.eval_expr(v) for v in node.values] +
                          [self.eval_expr(k) for k in node.keys if k is not None])
        if isinstance(node, ast.Starred):
            return self.eval_expr(node.value)
        if isinstance(node, ast.NamedExpr):
            value = self.eval_expr(node.value)
            self.assign(node.target, value, node.lineno)
            return value
        if isinstance(node, (ast.Await, ast.Starred)):
            return self.eval_expr(node.value)
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
            iter_infos = [self.eval_expr(g.iter) for g in node.generators]
            return _merge([self.eval_expr(node.elt)] + iter_infos)
        if isinstance(node, ast.DictComp):
            iter_infos = [self.eval_expr(g.iter) for g in node.generators]
            return _merge([self.eval_expr(node.key), self.eval_expr(node.value)] + iter_infos)
        if isinstance(node, ast.Slice):
            parts = [n for n in (node.lower, node.upper, node.step) if n]
            return _merge([self.eval_expr(n) for n in parts])
        return VarInfo(state=UNKNOWN)

    def eval_attribute(self, node: ast.Attribute) -> VarInfo:
        canonical = dotted_name(node, self.table)
        if canonical:
            for obj, desc in SOURCE_OBJECTS.items():
                if canonical == obj or canonical.startswith(obj + "."):
                    return self._source_info(canonical, desc, node.lineno)
        # request-like parameter attribute: param named 'request' + web framework
        if (isinstance(node.value, ast.Name) and node.value.id in FRAMEWORK_REQUEST_NAMES
                and self.table.has_any_module(WEB_FRAMEWORK_MODULES)):
            return self._source_info(
                f"{node.value.id}.{node.attr}", f"{node.value.id}.{node.attr} (web request input)",
                node.lineno)
        base = self.eval_expr(node.value)
        key = self._attr_key(node)
        if key and key in self.env:
            return self.env[key]
        return base

    def eval_subscript(self, node: ast.Subscript) -> VarInfo:
        canonical = dotted_name(node.value, self.table)
        if canonical:
            for obj, desc in SOURCE_OBJECTS.items():
                if canonical == obj or canonical.startswith(obj + "."):
                    return self._source_info(canonical, desc, node.lineno)
        base = self.eval_expr(node.value)
        self.eval_expr(node.slice)
        return base

    def _source_info(self, canonical: str, desc: str, line: int) -> VarInfo:
        origin = TaintOrigin(kind="source", desc=desc, file=self.file, line=line)
        path = TaintPath(origin=origin)
        return VarInfo(state=TAINTED, paths=[path], canonical=canonical)

    def eval_call(self, node: ast.Call) -> VarInfo:
        canonical = dotted_name(node.func, self.table) or ""
        arg_infos = [self.eval_expr(a) for a in node.args]
        for a in node.args:
            self.arg_states[id(a)] = self.arg_states.get(id(a)) or UNKNOWN
        for kw in node.keywords:
            info = self.eval_expr(kw.value)
            self.arg_states.setdefault(id(kw.value), info.state)
            arg_infos.append(info)
        for info in arg_infos:
            self.arg_states.setdefault(id(node), info.state)

        # 1. framework request attribute calls: request.args.get(...)
        for obj, desc in SOURCE_OBJECTS.items():
            if canonical.startswith(obj + "."):
                return self._source_info(canonical, desc, node.lineno)
        if canonical in SOURCE_CALLS:
            return self._source_info(canonical, SOURCE_CALLS[canonical], node.lineno)

        # 2. sanitizers neutralize
        if canonical in SANITIZER_CALLS:
            return VarInfo(state=CLEAN)

        # 3. sinks: record events for dangerous arguments
        self._record_sink(node, canonical, arg_infos)

        # 4. pure functions are transparent (const in -> const out, taint passes)
        if canonical in PURE_FUNCS or canonical in PROPAGATOR_CALLS:
            return _merge(arg_infos)

        # 5. method-call behaviors by attribute name
        if isinstance(node.func, ast.Attribute):
            receiver = self.eval_expr(node.func.value)
            if node.func.attr in PURE_METHODS:
                return receiver.merged(_merge(arg_infos))
            if node.func.attr in SANITIZER_METHODS:
                return VarInfo(state=CLEAN)
            return receiver.merged(_merge(arg_infos)) if arg_infos else receiver

        # 6. call to a locally-defined function
        if isinstance(node.func, ast.Name):
            self.edges.append(CallEdge(callee=node.func.id, file=self.file,
                                       line=node.lineno, args=arg_infos))
            if self.summarize is not None:
                summary = self.summarize(node.func.id, self.file)
                if summary is not None:
                    if summary.returns_tainted:
                        paths: list[TaintPath] = []
                        # taint born inside the callee flows out via its return
                        for p in summary.return_paths[:_MAX_RETURN_PATHS]:
                            paths.append(TaintPath(
                                origin=p.origin, hops=list(p.hops) + [TaintHop(
                                    file=self.file, line=node.lineno,
                                    desc=f"returned from {node.func.id}()")]))
                        # taint passed in through arguments and returned
                        for arg in arg_infos:
                            if arg.state == TAINTED:
                                for p in arg.paths:
                                    paths.append(TaintPath(
                                        origin=p.origin, hops=list(p.hops) + [TaintHop(
                                            file=self.file, line=node.lineno,
                                            desc=f"returned from {node.func.id}()")]))
                        if paths:
                            return VarInfo(state=TAINTED, paths=paths)
                    if summary.return_can_be_const and \
                            all(a.state in (CONST, CLEAN) for a in arg_infos):
                        return VarInfo(state=CONST)
            return VarInfo(state=UNKNOWN)

        return VarInfo(state=UNKNOWN)

    def _record_sink(self, node: ast.Call, canonical: str, arg_infos: list[VarInfo]) -> None:
        hit = sink_for_call(canonical)
        if hit is None and isinstance(node.func, ast.Attribute):
            hit = sink_for_attr(node.func.attr)
        if hit is None:
            return
        kind, desc = hit
        for info in arg_infos:
            if info.state in (TAINTED, UNKNOWN):
                event = SinkEvent(kind=kind, file=self.file, line=node.lineno, desc=desc,
                                  state=info.state,
                                  paths=self._sink_paths(info, node.lineno, desc),
                                  param_deps=set(info.param_deps))
                self.events.append(event)
                self.call_events[id(node)] = event
                break    # one event per call site

    def _sink_paths(self, info: VarInfo, line: int, desc: str) -> list[TaintPath]:
        paths = _copy_paths(info)
        for p in paths:
            p.sink = TaintHop(file=self.file, line=line, desc=desc)
        return paths


def analyze_module(file: str, tree: ast.Module, table: ImportTable) -> FuncAnalysis:
    """Analyze module-level statements; returns module scope analysis."""
    analyzer = ScopeAnalyzer(file, table)
    analyzer.visit_body(tree.body)
    summary = FuncSummary(name="<module>", file=file, line=1)
    return FuncAnalysis(name="<module>", file=file, node=tree, summary=summary,
                        events=analyzer.events, edges=analyzer.edges)


def analyze_function(file: str, node: ast.FunctionDef | ast.AsyncFunctionDef, table: ImportTable,
                     module_env: dict[str, VarInfo],
                     param_overrides: dict[str, VarInfo] | None = None,
                     summarize=None) -> tuple[FuncAnalysis, ScopeAnalyzer]:
    """Analyze one function; returns the analysis and its analyzer (for query maps)."""
    params = [a.arg for a in node.args.args if a.arg != "self"] + \
             [a.arg for a in node.args.kwonlyargs] + \
             ([node.args.vararg.arg] if node.args.vararg else []) + \
             ([node.args.kwarg.arg] if node.args.kwarg else [])
    analyzer = ScopeAnalyzer(file, table, base_env=module_env, param_names=params,
                             param_overrides=param_overrides, summarize=summarize)
    analyzer.visit_body(node.body)

    ret = _merge(analyzer.return_infos) if analyzer.return_infos else VarInfo(state=CONST)
    returns_const = any(r.state in (CONST, CLEAN) for r in analyzer.return_infos)
    internal_paths: list[TaintPath] = []
    for r in analyzer.return_infos:
        for p in r.paths:
            if p not in internal_paths:
                internal_paths.append(p)
    summary = FuncSummary(
        name=node.name, file=file, line=node.lineno, params=params,
        returns_tainted=ret.state == TAINTED or bool(ret.param_deps & set(params)),
        return_param_deps=ret.param_deps & set(params),
        return_can_be_const=returns_const,
        return_paths=internal_paths[:_MAX_RETURN_PATHS],
    )
    analysis = FuncAnalysis(name=node.name, file=file, node=node, summary=summary,
                            events=analyzer.events, edges=analyzer.edges)
    return analysis, analyzer
