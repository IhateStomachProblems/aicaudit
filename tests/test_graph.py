from pathlib import Path

from aicaudit.graph import CodeGraph, EvidenceChain, FuncDef


def test_codegraph_build():
    g = CodeGraph(Path("."))
    g.build()
    assert len(g.files) > 0
    assert len(g.funcs) > 0  # any function found


def test_codegraph_entry_points():
    g = CodeGraph(Path("."))
    g.build()
    assert len(g.entry_points) >= 0


def test_codegraph_sinks():
    g = CodeGraph(Path("."))
    g.build()
    assert len(g.sinks) >= 0


def test_codegraph_callers_of():
    g = CodeGraph(Path("."))
    g.build()
    callers = g.callers_of("_call_name")
    assert isinstance(callers, list)


def test_funcdef_basic():
    fd = FuncDef(name="test", file="x.py", line=1, calls={"foo", "bar"})
    assert fd.name == "test"
    assert "foo" in fd.calls


def test_evidence_chain_basic():
    ec = EvidenceChain(entry="test", path=[("a.py", 1, "f")], sink="eval")
    assert ec.risk == "medium"
    ec2 = EvidenceChain(entry="test", path=[("a.py", 1, "f")], sink="eval", risk="high")
    assert ec2.risk == "high"


def test_call_name():
    import ast
    tree = ast.parse("os.system('ls')")
    call = tree.body[0].value
    name = CodeGraph._call_name(call)
    assert name == "os.system"


def test_call_name_simple():
    import ast
    tree = ast.parse("eval('1+1')")
    call = tree.body[0].value
    name = CodeGraph._call_name(call)
    assert name == "eval"


def test_is_main_check():
    import ast
    tree = ast.parse("if __name__ == '__main__':\n    pass")
    test_node = tree.body[0]
    assert CodeGraph._is_main_check(test_node)


def test_graph_on_small_project():
    import tempfile
    from pathlib import Path
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        (d / "app.py").write_text("from flask import Flask\napp = Flask(__name__)\n@app.route('/api')\ndef hello():\n    return 'ok'\nif __name__ == '__main__':\n    app.run()", encoding="utf-8")
        (d / "danger.py").write_text("import os\ndef run_cmd(cmd):\n    os.system(cmd)\n", encoding="utf-8")
        g = CodeGraph(d)
        g.build()
        assert len(g.files) == 2
        assert "hello" in g.funcs
        assert "run_cmd" in g.funcs
        assert len(g.entry_points) >= 1
        sinks = [s.func for s in g.sinks]
        assert "os.system" in sinks
