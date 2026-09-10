"""Taint engine unit tests: sources, constness, sanitizers, paths, interproc."""
from pathlib import Path

from aicaudit.taint.engine import TaintEngine, TaintIndex


def analyze(tmp_path: Path, code: str, name: str = "m.py") -> TaintIndex:
    p = tmp_path / name
    p.write_text(code, encoding="utf-8")
    engine = TaintEngine()
    return engine.analyze([p])


def events_for(index: TaintIndex, kind: str):
    return [e for e in index.events if e.kind == kind]


class TestSourcesAndConstness:

    def test_literal_is_const_no_events(self, tmp_path):
        index = analyze(tmp_path, 'q = "SELECT 1"\nconn.execute(q)\n')
        assert index.events == []

    def test_pure_fold_is_const(self, tmp_path):
        index = analyze(tmp_path,
                        'import os\n'
                        'BASE = os.path.dirname(os.path.abspath(__file__))\n'
                        'p = os.path.join(BASE, "x.txt")\n'
                        'f = open(p)\n')
        assert index.events == []

    def test_flask_request_is_tainted(self, tmp_path):
        index = analyze(tmp_path,
                        'from flask import request\n'
                        'uid = request.args.get("id")\n'
                        'conn.execute(f"SELECT * FROM t WHERE id={uid}")\n')
        events = events_for(index, "sql")
        assert len(events) == 1
        assert events[0].state == "tainted"
        assert "request" in events[0].paths[0].origin.desc

    def test_input_source(self, tmp_path):
        index = analyze(tmp_path, 'name = input()\nopen(name)\n')
        events = events_for(index, "path")
        assert len(events) == 1 and events[0].state == "tainted"
        assert "input()" in events[0].paths[0].origin.desc

    def test_environ_source(self, tmp_path):
        index = analyze(tmp_path,
                        'import os\nimport requests\n'
                        'url = os.environ["TARGET"]\n'
                        'requests.get(url)\n')
        events = events_for(index, "http")
        assert len(events) == 1 and events[0].state == "tainted"

    def test_django_style_request_param(self, tmp_path):
        index = analyze(tmp_path,
                        'import django\n'
                        'def view(request):\n'
                        '    q = request.GET.get("q")\n'
                        '    conn.execute(q)\n')
        events = events_for(index, "sql")
        assert len(events) == 1 and events[0].state == "tainted"

    def test_sanitizer_basename_neutralizes(self, tmp_path):
        index = analyze(tmp_path,
                        'import os\n'
                        'name = input()\n'
                        'safe = os.path.basename(name)\n'
                        'open(safe)\n')
        assert events_for(index, "path") == []

    def test_int_cast_neutralizes(self, tmp_path):
        index = analyze(tmp_path,
                        'uid = input()\n'
                        'n = int(uid)\n'
                        'q = f"SELECT * FROM t WHERE id={n}"\n'
                        'conn.execute(q)\n')
        assert events_for(index, "sql") == []

    def test_unknown_keeps_recall(self, tmp_path):
        # param with no visible caller: UNKNOWN, event still recorded
        index = analyze(tmp_path,
                        'def load(filename):\n'
                        '    open(filename)\n')
        events = events_for(index, "path")
        assert len(events) == 1
        assert events[0].state == "unknown"
        assert "filename" in events[0].param_deps


class TestPaths:

    def test_full_path_rendering(self, tmp_path):
        index = analyze(tmp_path,
                        'from flask import request\n'
                        'uid = request.args.get("id")\n'
                        'q = f"SELECT {uid}"\n'
                        'conn.execute(q)\n')
        ev = events_for(index, "sql")[0]
        rendered = ev.paths[0].render()
        assert "m.py:2" in rendered
        assert "assigned to 'uid'" in rendered
        assert "assigned to 'q'" in rendered
        assert ".execute()" in rendered

    def test_serialization_roundtrip(self, tmp_path):
        import json
        index = analyze(tmp_path, 'name = input()\nopen(name)\n')
        ev = events_for(index, "path")[0]
        d = ev.to_dict()
        assert d["kind"] == "path"
        assert json.dumps(d)          # serializable
        assert d["paths"][0]["source"]["desc"].startswith("input()")


class TestInterprocedural:

    def test_return_taint_flows_to_caller(self, tmp_path):
        index = analyze(tmp_path,
                        'from flask import request\n'
                        'def read():\n'
                        '    return request.args.get("n")\n'
                        'def run(conn):\n'
                        '    v = read()\n'
                        '    q = "SELECT " + v\n'
                        '    conn.execute(q)\n')
        ev = events_for(index, "sql")[0]
        assert ev.state == "tainted"
        assert any("returned from read()" in h.desc for p in ev.paths for h in p.hops)

    def test_const_caller_refines_param(self, tmp_path):
        index = analyze(tmp_path,
                        'def handle(name):\n'
                        '    open(name)\n'
                        'handle("data/x.txt")\n')
        assert events_for(index, "path") == []

    def test_tainted_caller_upgrades_param(self, tmp_path):
        index = analyze(tmp_path,
                        'name = input()\n'
                        'def handle(n):\n'
                        '    open(n)\n'
                        'handle(name)\n')
        ev = events_for(index, "path")
        assert len(ev) == 1 and ev[0].state == "tainted"

    def test_cross_file_unique_name(self, tmp_path):
        (tmp_path / "a.py").write_text(
            'from flask import request\n'
            'def get_target():\n'
            '    return request.args.get("url")\n', encoding="utf-8")
        (tmp_path / "b.py").write_text(
            'import requests\n'
            'from a import get_target\n'
            'u = get_target()\n'
            'requests.get(u)\n', encoding="utf-8")
        engine = TaintEngine()
        index = engine.analyze(list(tmp_path.glob("*.py")))
        ev = events_for(index, "http")
        assert len(ev) == 1 and ev[0].state == "tainted"
        assert any(h.file.endswith("b.py") for p in ev[0].paths for h in p.hops)


class TestImportTable:

    def test_alias_resolution(self, tmp_path):
        index = analyze(tmp_path,
                        'import subprocess as sp\n'
                        'cmd = input()\n'
                        'sp.run(cmd)\n')
        assert len(events_for(index, "cmd")) == 1

    def test_from_import_resolution(self, tmp_path):
        index = analyze(tmp_path,
                        'from os import path as p\n'
                        'base = p.dirname("/x")\n'
                        'f = open(p.join(base, "y"))\n')
        assert index.events == []
