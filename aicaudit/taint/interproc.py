"""Inter-procedural facts: call-edge collection and per-parameter verdicts."""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from aicaudit.taint.model import CLEAN, CONST, TAINTED, TaintHop, TaintPath, VarInfo
from aicaudit.taint.propagate import CallEdge, FuncAnalysis

_MAX_PATHS_PER_PARAM = 4


@dataclass
class ParamFacts:
    """Call-site evidence about one (file, function, param) triple."""

    tainted_paths: list[TaintPath] = field(default_factory=list)
    const_callers: int = 0
    unknown_callers: int = 0
    resolved_callers: int = 0

    def verdict(self) -> VarInfo | None:
        """Param seed override; None keeps the default UNKNOWN seed."""
        if self.tainted_paths:
            return VarInfo(state=TAINTED, paths=self.tainted_paths[:_MAX_PATHS_PER_PARAM])
        if self.const_callers and not self.unknown_callers and self.resolved_callers:
            return VarInfo(state=CONST)
        return None


def resolve_callee(callee: str, edge_file: str,
                   by_key: dict[tuple[str, str], FuncAnalysis]) -> FuncAnalysis | None:
    """Resolve a bare callee name: same file first, then unambiguous cross-file."""
    same_file = by_key.get((edge_file, callee))
    if same_file:
        return same_file
    cross = [fa for (f, n), fa in by_key.items() if n == callee and f != edge_file]
    if len(cross) == 1:
        return cross[0]
    return None


def gather_param_facts(edges: list[CallEdge], edge_file: str,
                       by_key: dict[tuple[str, str], FuncAnalysis],
                       ) -> dict[tuple[str, str, str], ParamFacts]:
    """Accumulate per-parameter evidence from one scope's call edges."""
    facts: dict[tuple[str, str, str], ParamFacts] = defaultdict(ParamFacts)
    for edge in edges:
        callee = resolve_callee(edge.callee, edge_file, by_key)
        if callee is None:
            continue
        for i, arg in enumerate(edge.args):
            if i >= len(callee.summary.params):
                break
            param = callee.summary.params[i]
            key = (callee.file, callee.name, param)
            fact = facts[key]
            fact.resolved_callers += 1
            if arg.state == TAINTED and arg.paths:
                for p in arg.paths:
                    extended = TaintPath(origin=p.origin, hops=list(p.hops))
                    extended.hops.append(TaintHop(
                        file=edge_file, line=edge.line,
                        desc=f"passed as '{param}' to {callee.name}()"))
                    fact.tainted_paths.append(extended)
            elif arg.state in (CONST, CLEAN):
                fact.const_callers += 1
            else:
                fact.unknown_callers += 1
    return facts


def merge_facts(target: dict[tuple[str, str, str], ParamFacts],
                more: dict[tuple[str, str, str], ParamFacts]) -> None:
    for key, fact in more.items():
        t = target.setdefault(key, ParamFacts())
        t.tainted_paths.extend(fact.tainted_paths)
        t.const_callers += fact.const_callers
        t.unknown_callers += fact.unknown_callers
        t.resolved_callers += fact.resolved_callers


def overrides_from(facts: dict[tuple[str, str, str], ParamFacts]) -> dict[tuple[str, str], dict[str, VarInfo]]:
    """Convert facts into per-function param override maps."""
    out: dict[tuple[str, str], dict[str, VarInfo]] = defaultdict(dict)
    for (file, name, param), fact in facts.items():
        verdict = fact.verdict()
        if verdict is not None:
            out[(file, name)][param] = verdict
    return dict(out)
