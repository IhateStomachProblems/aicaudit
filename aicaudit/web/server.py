"""AICAudit Web Server — FastAPI application (v2, zero-build frontend).

Frontend assets are vendored (static/app.css, static/app.js) — no CDN,
works offline. Syntax highlighting is server-side via pygments.
Sessions persist to .aicaudit/web/sessions/*.json so history survives restarts.
"""
import difflib
import json
import os
import queue
import threading
import time
import uuid
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pygments import highlight
from pygments.formatters import HtmlFormatter
from pygments.lexers import PythonLexer

from aicaudit.config import find_project_root
from aicaudit.fix import fix_file
from aicaudit.llm.client import load_ai_config, verify_findings
from aicaudit.output.json_output import dump_json
from aicaudit.output.sarif_output import dump_sarif
from aicaudit.rules.base import all_rules
from aicaudit.scan import _import_all_rules
from aicaudit.scan import scan as run_scan

HERE = Path(__file__).parent

app = FastAPI(title="AICAudit", version="0.2.0", description="AI code audit web UI")

# Static files (vendored, no CDN)
static_dir = HERE / "static"
static_dir.mkdir(parents=True, exist_ok=True)
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

# Templates
templates = Jinja2Templates(directory=str(HERE / "templates"))

# Session store: in-memory mirror + JSON persistence under .aicaudit/web/
SESSIONS_DIR = Path.cwd() / ".aicaudit" / "web" / "sessions"
sessions: dict[str, dict] = {}


def _serialize_finding(f, lang="en"):
    d = {
        "rule_id": f.rule_id, "message": f.text(lang),
        "file": f.file, "line": f.line,
        "severity": f.severity.value, "snippet": f.snippet,
        "fix": f.fix, "cwe": f.cwe,
    }
    if f.taint_path:
        d["taint_path"] = [p.to_dict() for p in f.taint_path]
    if f.ai:
        d["ai"] = {
            "status": f.ai.get("ai_status", "unverified"),
            "confidence": f.ai.get("ai_confidence", 0.0),
            "reason": f.ai.get("ai_reason", ""),
            "severity": f.ai.get("ai_severity"),
            "cwe": f.ai.get("ai_cwe", ""),
            "suggested_fix": f.ai.get("ai_suggested_fix", ""),
        }
    return d


def _save_session(session_id: str) -> None:
    try:
        SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
        (SESSIONS_DIR / f"{session_id}.json").write_text(
            json.dumps(sessions[session_id], ensure_ascii=False), encoding="utf-8")
    except OSError:
        pass


def _load_sessions() -> None:
    if not SESSIONS_DIR.is_dir():
        return
    for p in SESSIONS_DIR.glob("*.json"):
        try:
            doc = json.loads(p.read_text(encoding="utf-8"))
            sessions[doc.get("session_id", p.stem)] = doc
        except (OSError, json.JSONDecodeError):
            continue


_load_sessions()


def _summary(s: dict) -> dict:
    counts = {"critical": 0, "error": 0, "warning": 0, "info": 0}
    for f in s.get("findings", []):
        sev = f.get("severity", "info")
        counts[sev] = counts.get(sev, 0) + 1
    return {
        "session_id": s.get("session_id"), "timestamp": s.get("timestamp"),
        "total": s.get("total", 0), "duration": s.get("duration"),
        "files_scanned": s.get("files_scanned"), "paths": s.get("paths", []),
        "counts": counts,
    }


# ─── Pages ───────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse(request, "index.html", {"request": request})


@app.get("/scan", response_class=HTMLResponse)
async def scan_page(request: Request):
    _import_all_rules()
    rules_list = [{"id": cls.id, "name": cls.name, "severity": cls.severity.value}
                  for cls in all_rules()]
    return templates.TemplateResponse(request, "scan.html", {
        "request": request, "rules": rules_list,
    })


@app.get("/results/{session_id}", response_class=HTMLResponse)
async def results_page(request: Request, session_id: str):
    session = sessions.get(session_id)
    return templates.TemplateResponse(request, "results.html", {
        "request": request, "session": session, "session_id": session_id,
    })


@app.get("/rules", response_class=HTMLResponse)
async def rules_page(request: Request):
    _import_all_rules()
    rules_list = [{"id": cls.id, "name": cls.name, "severity": cls.severity.value,
                   "description": cls.description}
                  for cls in all_rules()]
    return templates.TemplateResponse(request, "rules.html", {
        "request": request, "rules": rules_list,
    })


@app.get("/config", response_class=HTMLResponse)
async def config_page(request: Request):
    ai_cfg = load_ai_config()
    return templates.TemplateResponse(request, "config.html", {
        "request": request, "ai_cfg": ai_cfg,
    })


# ─── Scan API (simple POST) ──────────────────────────────────────

@app.post("/api/scan")
async def api_scan(request: Request):
    """Run a scan and return results."""
    body = await request.json()
    paths = body.get("paths", ["."])
    rules = body.get("rules")
    lang = body.get("lang", "en")
    min_severity = body.get("min_severity")

    session_id = uuid.uuid4().hex[:12]
    start = time.time()

    findings = run_scan(
        [Path(p) for p in paths],
        lang=lang,
        rules=set(rules.split(",")) if rules else None,
        min_severity=min_severity,
        base_root=find_project_root(Path(paths[0])),
    )

    duration = time.time() - start
    sessions[session_id] = {
        "session_id": session_id,
        "paths": list(paths),
        "findings": [_serialize_finding(f, lang) for f in findings],
        "total": len(findings),
        "duration": round(duration, 2),
        "files_scanned": len({f.file for f in findings}) or "?",
        "lang": lang,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    _save_session(session_id)

    return {"session_id": session_id, "total": len(findings), "duration": round(duration, 2)}


# ─── Scan API (SSE stream with real progress) ────────────────────

@app.get("/api/scan/stream")
async def api_scan_stream(request: Request):
    """Server-sent events: phase progress while scanning, then the session id."""
    params = request.query_params
    raw_paths = params.get("paths", ".").split("|")
    paths = [p for p in raw_paths if p]
    lang = params.get("lang", "en")
    rules = params.get("rules", "")
    min_severity = params.get("min_severity", "")

    def event_gen():
        q: queue.Queue = queue.Queue()
        session_id = uuid.uuid4().hex[:12]

        def cb(phase, cur, total, detail):
            q.put({"type": "progress", "phase": phase, "current": cur,
                   "total": total, "detail": detail})

        def worker():
            start = time.time()
            try:
                findings = run_scan(
                    [Path(p) for p in paths], lang=lang,
                    rules={r for r in rules.split(",") if r} or None,
                    min_severity=min_severity or None,
                    base_root=find_project_root(Path(paths[0])),
                    progress=cb)
                sessions[session_id] = {
                    "session_id": session_id,
                    "paths": list(paths),
                    "findings": [_serialize_finding(f, lang) for f in findings],
                    "total": len(findings),
                    "duration": round(time.time() - start, 2),
                    "files_scanned": len({f.file for f in findings}) or "?",
                    "lang": lang,
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                }
                _save_session(session_id)
                q.put({"type": "done", "session_id": session_id,
                       "total": len(findings)})
            except Exception as exc:  # noqa: BLE001 — report to the client
                q.put({"type": "error", "message": str(exc)})

        threading.Thread(target=worker, daemon=True).start()
        while True:
            item = q.get()
            yield f"data: {json.dumps(item, ensure_ascii=False)}\n\n"
            if item.get("type") in ("done", "error"):
                break

    return StreamingResponse(event_gen(), media_type="text/event-stream")


# ─── Sessions ────────────────────────────────────────────────────

@app.get("/api/sessions")
async def api_sessions():
    items = sorted((s for s in sessions.values() if s.get("total") is not None),
                   key=lambda s: s.get("timestamp", ""), reverse=True)
    return {"sessions": [_summary(s) for s in items[:30]]}


@app.get("/api/results/{session_id}")
async def api_results(session_id: str):
    session = sessions.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return session


# ─── Code viewer (server-side pygments) ──────────────────────────

@app.get("/api/file-content")
async def api_file_content(request: Request):
    """Return a pygments-highlighted code window around a target line."""
    path = request.query_params.get("path", "")
    try:
        line = int(request.query_params.get("line", "1"))
    except ValueError:
        line = 1
    context = 6
    try:
        context = max(1, min(20, int(request.query_params.get("context", "6"))))
    except ValueError:
        pass

    p = Path(path)
    if not p.is_file():
        raise HTTPException(status_code=404, detail="File not found")
    try:
        source = p.read_text(encoding="utf-8-sig", errors="replace")
    except OSError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    lines = source.splitlines()
    start = max(1, line - context)
    end = min(len(lines), line + context)
    window = "\n".join(lines[start - 1:end])

    formatter = HtmlFormatter(
        linenos="inline", linenostart=start, style="monokai",
        hl_lines=[max(1, line - start + 1)], noclasses=False,
        prestyles="margin:0")
    html = highlight(window, PythonLexer(), formatter)
    return {"start_line": start, "end_line": end, "target_line": line,
            "html": html, "line_count": len(lines)}


# ─── AI verification ─────────────────────────────────────────────

@app.post("/api/verify")
async def api_verify(request: Request):
    """Attach AI verdicts to session findings (evidence-grounded)."""
    body = await request.json()
    session_id = body.get("session_id")
    session = sessions.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    findings_data = session["findings"]
    from aicaudit.llm.prompts import (
        FindingEvidence,
        enclosing_function_source,
        imports_block,
    )

    sources: dict[str, str] = {}
    evidences = []
    for f in findings_data:
        if f["file"] not in sources:
            try:
                # local single-user tool: blocking read of a source file is fine
                with open(f["file"], encoding="utf-8-sig", errors="replace") as fh:  # noqa: ASYNC230
                    sources[f["file"]] = fh.read()
            except OSError:
                sources[f["file"]] = ""
        src = sources.get(f["file"], "")
        evidences.append(FindingEvidence(
            rule_id=f["rule_id"], severity=f["severity"], message=f["message"],
            file=f["file"], line=f["line"], snippet=f.get("snippet") or "",
            fix=f.get("fix"), cwe=f.get("cwe"),
            function_source=enclosing_function_source(src, f["line"]),
            imports=imports_block(src),
        ))

    cfg = load_ai_config()
    if cfg.provider == "mock":
        return {"error": "No AI provider configured", "ai_verified": False}

    results = verify_findings(evidences, config=cfg)
    confirmed = sum(1 for r in results if r.get("ai_status") == "confirmed")

    for f, v in zip(findings_data, results):
        f["ai"] = {
            "status": v.get("ai_status", "unverified"),
            "confidence": v.get("ai_confidence", 0.0),
            "reason": v.get("ai_reason", ""),
            "severity": v.get("ai_severity"),
            "cwe": v.get("ai_cwe", ""),
            "suggested_fix": v.get("ai_suggested_fix", ""),
        }
        # legacy field kept for older clients
        f["ai_verified"] = v.get("ai_status") == "confirmed"
        f["ai_reason"] = v.get("ai_reason", "")
        f["ai_severity"] = v.get("ai_severity", f["severity"])
        f["ai_suggested_fix"] = v.get("ai_suggested_fix", "")

    session["findings"] = findings_data
    _save_session(session_id)
    return {
        "total": len(findings_data),
        "confirmed": confirmed,
        "false_positive": sum(1 for r in results if r.get("ai_status") == "false_positive"),
        "unverified": sum(1 for r in results if r.get("ai_status") == "unverified"),
        "ai_verified": True,
    }


# ─── Config ──────────────────────────────────────────────────────

@app.post("/api/config")
async def api_config(request: Request):
    """Update AI configuration."""
    body = await request.json()
    for key, value in body.items():
        env_key = f"AICAUDIT_{key.upper()}"
        if value:
            os.environ[env_key] = str(value)
        else:
            os.environ.pop(env_key, None)
    return {"ok": True}


@app.get("/api/config/status")
async def api_config_status():
    cfg = load_ai_config()
    return {"provider": cfg.provider, "model": cfg.model,
            "configured": bool(cfg.api_key) or cfg.provider == "ollama"}


# ─── Export ──────────────────────────────────────────────────────

@app.post("/api/export")
async def api_export(request: Request):
    """Export findings as JSON or SARIF."""
    body = await request.json()
    session_id = body.get("session_id")
    fmt = body.get("format", "json")
    session = sessions.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    from aicaudit.rules.base import Finding
    from aicaudit.rules.base import Severity as Sev
    findings = []
    for f in session["findings"]:
        findings.append(Finding(
            rule_id=f["rule_id"], message=f["message"], message_zh=f["message"],
            file=f["file"], line=f["line"],
            severity=Sev(f["severity"]),
            snippet=f.get("snippet"), fix=f.get("fix"),
        ))

    if fmt == "sarif":
        return JSONResponse(json.loads(dump_sarif(findings)))
    return JSONResponse(json.loads(dump_json(findings)))


# ─── Fixes: preview / apply / rollback ───────────────────────────

def _finding_from_payload(body: dict):
    from aicaudit.rules.base import Finding
    from aicaudit.rules.base import Severity as Sev
    file_path = body.get("file")
    fix_text = body.get("fix")
    if not file_path or not fix_text:
        raise HTTPException(status_code=400, detail="Missing file or fix")
    finding = Finding(
        rule_id=body.get("rule_id") or "UNKNOWN",
        message=body.get("message") or fix_text,
        message_zh=body.get("message") or fix_text,
        file=file_path, line=body.get("line") or 1,
        severity=Sev(body.get("severity") or "warning"),
        fix=fix_text,
    )
    return file_path, finding


@app.post("/api/fix-preview")
async def api_fix_preview(request: Request):
    """Dry-run the fix and return a unified diff."""
    body = await request.json()
    file_path, finding = _finding_from_payload(body)
    result = fix_file(file_path, [finding], dry_run=True, backup=False)
    diff = difflib.unified_diff(
        (result.before or "").splitlines(keepends=True),
        (result.after or "").splitlines(keepends=True),
        fromfile=Path(file_path).name, tofile=Path(file_path).name + " (fixed)", n=3)
    diff_text = "".join(diff)
    return {
        "status": str(result.status), "message": result.message,
        "verified": result.verified, "diff": diff_text,
        "changed": bool(diff_text),
    }


@app.post("/api/apply-fix")
async def api_apply_fix(request: Request):
    """Apply a fix for a specific finding (with .bak backup)."""
    body = await request.json()
    file_path, finding = _finding_from_payload(body)

    result = fix_file(file_path, [finding], dry_run=False, backup=True)
    return {"ok": True, "backup": result.backup_path, "path": result.path,
            "status": str(result.status), "message": result.message,
            "verified": result.verified}


@app.post("/api/fix-rollback")
async def api_fix_rollback(request: Request):
    """Restore a file from its .bak backup."""
    import shutil
    body = await request.json()
    backup = body.get("backup", "")
    if not backup.endswith(".bak"):
        raise HTTPException(status_code=400, detail="backup must be a .bak file")
    backup_path = Path(backup)
    if not backup_path.is_file():
        raise HTTPException(status_code=404, detail="Backup not found")
    target = Path(str(backup_path)[:-4])
    shutil.copy2(backup_path, target)
    try:
        backup_path.unlink()
    except OSError:
        pass
    return {"ok": True, "restored": str(target)}


# ─── Server ──────────────────────────────────────────────────────

def run_server(host: str = "127.0.0.1", port: int = 8080, reload: bool = False):
    """Start the AICAudit web UI server."""
    import uvicorn
    print(f"  AICAudit Web UI: http://{host}:{port}")
    print(f"  API docs: http://{host}:{port}/docs")
    uvicorn.run(app, host=host, port=port, reload=reload)
