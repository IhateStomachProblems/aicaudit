"""Catalogs for the taint engine: sources, sanitizers, pure functions, sinks.

All names are canonical dotted names after import-alias resolution
(e.g. "flask.request", "os.path.join"). Attribute sinks like SQL ``execute``
match on the attribute name regardless of receiver.
"""
from __future__ import annotations

# ─── Sources: user-input entry points ────────────────────────────────────────

# Full dotted name -> description. Attribute access below these roots is a
# source (request.args, request.form["x"], request.json, ...).
SOURCE_OBJECTS: dict[str, str] = {
    "flask.request": "Flask request (user input)",
    "django.request": "Django request (user input)",
    "fastapi.Request": "FastAPI Request (user input)",
    "starlette.request.Request": "FastAPI/Starlette Request (user input)",
    "os.environ": "environment variable",
    "sys.argv": "command-line argument",
}

# Bare-name objects that behave as request-like sources when the module
# imports a web framework (from flask import request).
FRAMEWORK_REQUEST_NAMES = {"request", "req"}

# Call sources: canonical name -> description.
SOURCE_CALLS: dict[str, str] = {
    "builtins.input": "input() (user input)",
    "os.getenv": "os.getenv (environment variable)",
    "socket.socket.recv": "socket.recv (network data)",
    "socket.socket.recvfrom": "socket.recvfrom (network data)",
    "socket.recv": "socket.recv (network data)",
    "socket.recvfrom": "socket.recvfrom (network data)",
}

WEB_FRAMEWORK_MODULES = {"flask", "django", "fastapi", "starlette", "bottle", "tornado"}


# ─── Sanitizers: calls that neutralize taint ─────────────────────────────────

SANITIZER_CALLS: dict[str, str] = {
    "os.path.basename": "os.path.basename (path sanitization)",
    "werkzeug.utils.secure_filename": "secure_filename (path sanitization)",
    "markupsafe.escape": "markupsafe.escape (XSS sanitization)",
    "html.escape": "html.escape (XSS sanitization)",
    "bleach.clean": "bleach.clean (XSS sanitization)",
    "builtins.int": "int() cast (type coercion)",
    "builtins.float": "float() cast (type coercion)",
    "builtins.len": "len() (returns a number)",
    "builtins.hash": "hash() (returns a number)",
    "shutil.copyfileobj": "streamed copy",
}

# Method names that sanitize when called on any receiver.
SANITIZER_METHODS: dict[str, str] = {
    "replace": "str.replace (context-dependent; treated as neutral)",
}


# ─── Pure functions: constant-preserving calls ───────────────────────────────
# A call to one of these is CONST whenever receiver + all args are CONST/CLEAN.
PURE_FUNCS: set[str] = {
    "os.path.join", "os.path.dirname", "os.path.basename", "os.path.abspath",
    "os.path.realpath", "os.path.normpath", "os.path.relpath", "os.path.split",
    "os.path.splitext", "os.getcwd", "os.path.getsize",
    "pathlib.Path", "pathlib.PosixPath", "pathlib.WindowsPath",
    "builtins.str", "builtins.repr", "builtins.ascii", "builtins.round",
    "builtins.abs", "builtins.min", "builtins.max", "builtins.enumerate",
    "builtins.range", "builtins.sorted", "builtins.reversed", "builtins.zip",
    "builtins.format", "builtins.chr", "builtins.ord",
}

# Methods that are pure when receiver + args are constant.
PURE_METHODS: set[str] = {
    "strip", "lstrip", "rstrip", "lower", "upper", "title", "capitalize",
    "casefold", "split", "rsplit", "splitlines", "startswith", "endswith",
    "join", "format", "format_map", "encode", "decode", "replace", "keys",
    "values", "items", "get", "copy", "name", "stem", "suffix", "parent",
}


# ─── Propagators: calls that pass taint through unchanged ────────────────────

PROPAGATOR_CALLS: set[str] = {
    "builtins.list", "builtins.dict", "builtins.tuple", "builtins.set",
    "builtins.frozenset", "builtins.str", "builtins.bytes",
    "typing.cast", "functools.partial",
}


# ─── Sinks: dangerous call targets ───────────────────────────────────────────
# kind -> {canonical names}, plus attribute-name sinks.

SINK_CALLS: dict[str, dict[str, str]] = {
    "eval": {
        "builtins.eval": "eval()",
        "builtins.exec": "exec()",
        "builtins.compile": "compile()",
        "builtins.__import__": "__import__()",
    },
    "cmd": {
        "os.system": "os.system()",
        "os.popen": "os.popen()",
        "subprocess.run": "subprocess.run()",
        "subprocess.call": "subprocess.call()",
        "subprocess.Popen": "subprocess.Popen()",
        "subprocess.check_output": "subprocess.check_output()",
        "subprocess.check_call": "subprocess.check_call()",
        "subprocess.getoutput": "subprocess.getoutput()",
        "subprocess.getstatusoutput": "subprocess.getstatusoutput()",
    },
    "http": {
        "requests.get": "requests.get()",
        "requests.post": "requests.post()",
        "requests.put": "requests.put()",
        "requests.delete": "requests.delete()",
        "requests.patch": "requests.patch()",
        "requests.head": "requests.head()",
        "requests.request": "requests.request()",
        "urllib.request.urlopen": "urlopen()",
        "urllib.request.urlretrieve": "urlretrieve()",
        "httpx.get": "httpx.get()",
        "httpx.post": "httpx.post()",
        "httpx.request": "httpx.request()",
    },
    "path": {
        "builtins.open": "open()",
        "codecs.open": "codecs.open()",
        "os.path.join": "os.path.join()",
        "os.path.abspath": "os.path.abspath()",
        "os.path.realpath": "os.path.realpath()",
        "os.path.normpath": "os.path.normpath()",
    },
    "deserialize": {
        "pickle.load": "pickle.load()",
        "pickle.loads": "pickle.loads()",
        "marshal.load": "marshal.load()",
        "marshal.loads": "marshal.loads()",
        "shelve.open": "shelve.open()",
        "yaml.load": "yaml.load()",
        "yaml.unsafe_load": "yaml.unsafe_load()",
    },
}

# Attribute-name sinks: match on attr regardless of receiver object.
SINK_ATTRS: dict[str, dict[str, str]] = {
    "sql": {
        "execute": ".execute()",
        "executemany": ".executemany()",
        "executescript": ".executescript()",
    },
    "archive": {
        "extract": ".extract()",
        "extractall": ".extractall()",
    },
}

# Reverse lookup helpers -------------------------------------------------------

_SANITIZER_NAMES = set(SANITIZER_CALLS)
_SINK_NAME_TO_KIND: dict[str, tuple[str, str]] = {}
for _kind, _m in SINK_CALLS.items():
    for _name, _desc in _m.items():
        _SINK_NAME_TO_KIND[_name] = (_kind, _desc)
_SINK_ATTR_TO_KIND: dict[str, tuple[str, str]] = {}
for _kind, _m in SINK_ATTRS.items():
    for _name, _desc in _m.items():
        _SINK_ATTR_TO_KIND[_name] = (_kind, _desc)


def sink_for_call(canonical: str) -> tuple[str, str] | None:
    """Return (kind, description) if canonical name is a sink call."""
    return _SINK_NAME_TO_KIND.get(canonical)


def sink_for_attr(attr: str) -> tuple[str, str] | None:
    """Return (kind, description) if attribute name is a sink."""
    return _SINK_ATTR_TO_KIND.get(attr)
