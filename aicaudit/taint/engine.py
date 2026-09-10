"""TaintEngine: orchestrates parsing, analysis rounds, and the query index."""
from __future__ import annotations

import ast
from pathlib import Path

from aicaudit.taint.imports import ImportTable
from aicaudit.taint.interproc import (
    gather_param_facts,
    merge_facts,
    overrides_from,
    resolve_callee,
)
from aicaudit.taint.model import FuncSummary, SinkEvent, VarInfo
from aicaudit.taint.propagate import (
    FuncAnalysis,
    ScopeAnalyzer,
    analyze_function,
)

_ROUNDS = 3


class TaintIndex:
    """Query interface handed to rules via ScanContext.

    Node identity (id()) is stable because rules scan the SAME trees the
    engine analyzed — scan() must reuse tree_for().
    """

    def __init__(self) -> None:
        self._arg_states: dict[int, str] = {}
        self._call_events: dict[int, SinkEvent] = {}
        self._trees: dict[str, ast.Module] = {}
        self.events: list[SinkEvent] = []

    def add(self, analyzer: ScopeAnalyzer, tree: ast.Module, file: str) -> None:
        self._arg_states.update(analyzer.arg_states)
        self._call_events.update(analyzer.call_events)
        self._trees[file] = tree
        self.events.extend(analyzer.events)

    def tree_for(self, file: str) -> ast.Module | None:
        return self._trees.get(file)

    def state_of(self, expr_node: ast.AST) -> str | None:
        """Abstract state of an expression node, or None if not recorded."""
        return self._arg_states.get(id(expr_node))

    def event_for(self, call_node: ast.AST) -> SinkEvent | None:
        """Sink event recorded at this call node, if the call is dangerous."""
        return self._call_events.get(id(call_node))


class TaintEngine:
    """Runs the multi-round taint analysis over a set of Python files."""

    def __init__(self) -> None:
        self.index = TaintIndex()
        self.summaries: dict[tuple[str, str], FuncSummary] = {}

    def analyze(self, files: list[Path]) -> TaintIndex:
        # 1. parse all files once; keep trees + import tables
        parsed: dict[str, tuple[ast.Module, ImportTable]] = {}
        for fp in files:
            try:
                source = fp.read_text(encoding="utf-8-sig", errors="replace")
                tree = ast.parse(source, filename=str(fp))
            except (OSError, SyntaxError):
                continue
            parsed[str(fp)] = (tree, ImportTable.from_tree(tree))
        if not parsed:
            return self.index

        # 2. module scopes (seed envs) + function inventory
        module_envs: dict[str, dict[str, VarInfo]] = {}
        func_specs: list[tuple[str, ast.FunctionDef | ast.AsyncFunctionDef, ImportTable]] = []
        for file, (tree, table) in parsed.items():
            module_analyzer = ScopeAnalyzer(file, table)
            module_analyzer.visit_body(
                [n for n in tree.body if not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))])
            module_envs[file] = dict(module_analyzer.env)
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    func_specs.append((file, node, table))

        # 3. refinement rounds
        analyses: dict[tuple[str, str], FuncAnalysis] = {}
        analyzers: list[tuple[ScopeAnalyzer, ast.Module, str]] = []
        module_analyzers: list[ScopeAnalyzer] = []
        overrides: dict[tuple[str, str], dict[str, VarInfo]] = {}

        for round_no in range(_ROUNDS):
            by_key = dict(analyses)
            overrides = self._gather_overrides(func_specs, by_key, module_analyzers)

            def summarize(callee: str, caller_file: str,
                          _by_key: dict = by_key) -> FuncSummary | None:
                fa = resolve_callee(callee, caller_file, _by_key)
                return fa.summary if fa else None

            analyses = {}
            analyzers = []
            module_analyzers = []
            for file, (tree, table) in parsed.items():
                module_analyzer = ScopeAnalyzer(file, table, summarize=summarize)
                module_analyzer.visit_body(
                    [n for n in tree.body if not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))])
                module_analyzers.append(module_analyzer)
                analyzers.append((module_analyzer, tree, file))
            for file, node, table in func_specs:
                ovr = overrides.get((file, node.name))
                fa, analyzer = analyze_function(file, node, table,
                                                module_envs.get(file) or {},
                                                param_overrides=ovr, summarize=summarize)
                analyses[(file, node.name)] = fa
                analyzers.append((analyzer, parsed[file][0], file))

        # 4. publish index from the final round
        for analyzer, tree, file in analyzers:
            self.index.add(analyzer, tree, file)
        self.summaries = {k: fa.summary for k, fa in analyses.items()}
        return self.index

    def _gather_overrides(self, func_specs, by_key,
                          module_analyzers=None) -> dict[tuple[str, str], dict[str, VarInfo]]:
        """Collect call-edge evidence (functions + module scopes) into overrides."""
        from collections import defaultdict

        from aicaudit.taint.interproc import ParamFacts

        facts: dict[tuple[str, str, str], ParamFacts] = defaultdict(ParamFacts)
        for file, node, _table in func_specs:
            fa = by_key.get((file, node.name))
            if fa is None:
                continue
            merge_facts(facts, gather_param_facts(fa.edges, file, by_key))
        for analyzer in module_analyzers or []:
            merge_facts(facts, gather_param_facts(analyzer.edges, analyzer.file, by_key))
        return overrides_from(facts)
