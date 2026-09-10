"""Taint engine: lightweight source-to-sink dataflow analysis (pure Python)."""
from aicaudit.taint.engine import TaintEngine, TaintIndex
from aicaudit.taint.model import SinkEvent, TaintOrigin, TaintPath

__all__ = [
    "SinkEvent",
    "TaintEngine",
    "TaintIndex",
    "TaintOrigin",
    "TaintPath",
]
