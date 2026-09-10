"""Taint engine data model: origins, paths, variable states, sink events."""
from __future__ import annotations

from dataclasses import dataclass, field

# Variable expression states, ordered by merge precedence (higher wins).
CONST = "const"      # provably constant (literal / pure folds of constants)
CLEAN = "clean"      # sanitized (passed through a known sanitizer)
UNKNOWN = "unknown"  # dynamic, origin unresolved (external call, param, ...)
TAINTED = "tainted"  # provably tainted (traced to a source)

_PRECEDENCE = {CONST: 0, CLEAN: 1, UNKNOWN: 2, TAINTED: 3}


def merge_state(a: str, b: str) -> str:
    """Merge two expression states conservatively (the weaker claim loses)."""
    if a not in _PRECEDENCE or b not in _PRECEDENCE:
        return UNKNOWN
    return a if _PRECEDENCE[a] >= _PRECEDENCE[b] else b


@dataclass
class TaintOrigin:
    """Where a taint was born (a user-input source)."""

    kind: str      # "source" for catalog hits, "param" for inter-procedural
    desc: str      # human-readable, e.g. "request.args (Flask user input)"
    file: str
    line: int

    def to_dict(self) -> dict:
        return {"kind": self.kind, "desc": self.desc, "file": self.file, "line": self.line}


@dataclass
class TaintHop:
    """One propagation step on a taint path."""

    file: str
    line: int
    desc: str      # e.g. "assigned to 'query'", "returned from build_query()"

    def to_dict(self) -> dict:
        return {"file": self.file, "line": self.line, "desc": self.desc}


@dataclass
class TaintPath:
    """A complete source-to-sink path. Serializable for reports/UI."""

    origin: TaintOrigin
    hops: list[TaintHop] = field(default_factory=list)
    sink: TaintHop | None = None       # the sink call location

    def to_dict(self) -> dict:
        return {
            "source": self.origin.to_dict(),
            "hops": [h.to_dict() for h in self.hops],
            "sink": self.sink.to_dict() if self.sink else None,
        }

    def render(self) -> str:
        """One-line human rendering: src.py:3 request.args -> ... -> sink.py:9 execute()."""
        parts = [f"{_short(self.origin.file)}:{self.origin.line} {self.origin.desc}"]
        for h in self.hops:
            parts.append(f"{_short(h.file)}:{h.line} {h.desc}")
        if self.sink:
            parts.append(f"{_short(self.sink.file)}:{self.sink.line} {self.sink.desc}")
        return " -> ".join(parts)


def _short(path: str) -> str:
    return path.replace("\\", "/").rsplit("/", 1)[-1]


@dataclass
class VarInfo:
    """Abstract value of one variable in the environment."""

    state: str = UNKNOWN
    paths: list[TaintPath] = field(default_factory=list)        # for TAINTED
    param_deps: set[str] = field(default_factory=set)           # params influencing this value
    canonical: str | None = None    # resolved dotted name, e.g. "flask.request"

    def merged(self, other: VarInfo) -> VarInfo:
        seen = {(p.origin.file, p.origin.line, p.origin.desc): p for p in self.paths}
        for p in other.paths:
            key = (p.origin.file, p.origin.line, p.origin.desc)
            if key not in seen:
                seen[key] = p
        return VarInfo(
            state=merge_state(self.state, other.state),
            paths=list(seen.values()),
            param_deps=self.param_deps | other.param_deps,
            canonical=self.canonical or other.canonical,
        )


@dataclass
class SinkEvent:
    """A sink call whose argument is potentially dangerous.

    state reflects the merged argument state:
      TAINTED  -> provably user-controlled, path is complete
      UNKNOWN  -> dynamic but source unresolved (fire without path)
      (CONST/CLEAN sinks are never recorded)
    """

    kind: str                 # "sql" | "eval" | "http" | "path" | "cmd" | "archive" | "deserialize"
    file: str
    line: int
    desc: str                 # sink description, e.g. "cursor.execute()"
    state: str = UNKNOWN
    paths: list[TaintPath] = field(default_factory=list)
    param_deps: set[str] = field(default_factory=set)   # params that reach this sink

    def to_dict(self) -> dict:
        return {
            "kind": self.kind, "file": self.file, "line": self.line,
            "desc": self.desc, "state": self.state,
            "paths": [p.to_dict() for p in self.paths],
        }


@dataclass
class FuncSummary:
    """Inter-procedural summary of one analyzed function."""

    name: str
    file: str
    line: int
    params: list[str] = field(default_factory=list)
    returns_tainted: bool = False
    return_param_deps: set[str] = field(default_factory=set)   # params flowing to return
    return_can_be_const: bool = False    # some return path is constant/pure
    return_paths: list[TaintPath] = field(default_factory=list)  # taint born inside the function

    def to_public(self) -> dict:
        return {"name": self.name, "file": self.file, "line": self.line,
                "params": self.params, "returns_tainted": self.returns_tainted}
