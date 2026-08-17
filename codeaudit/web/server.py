"""CodeAudit Web Server — FastAPI application."""

import json
import os
import time
import uuid
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from codeaudit.scan import scan as run_scan
from codeaudit.scan import _import_all_rules
from codeaudit.rules.base import all_rules, Severity
from codeaudit.config import find_project_root, merge_config
from codeaudit.output.json_output import dump_json
from codeaudit.output.sarif_output import dump_sarif
from codeaudit.llm.client import load_ai_config, verify_findings, AiConfig
from codeaudit.fix import fix_file, FixResult

HERE = Path(__file__).parent

app = FastAPI(title="CodeAudit", version="0.1.0", description="AI-powered code audit web UI")

# Static files
static_dir = HERE / "static"
static_dir.mkdir(parents=True, exist_ok=True)
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

# Templates
templates = Jinja2Templates(directory=str(HERE / "templates"))

# Session store (in-memory for v1)
sessions: dict[str, dict] = {}


# ─── Pages ───────────────────────────────────────────────

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


# ─── API ─────────────────────────────────────────────────

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
        "findings": [{
            "rule_id": f.rule_id, "message": f.text(lang),
            "file": f.file, "line": f.line,
            "severity": f.severity.value, "snippet": f.snippet,
            "fix": f.fix,
        } for f in findings],
        "total": len(findings),
        "duration": round(duration, 2),
        "files_scanned": len(set(f.file for f in findings)) or "?",
        "lang": lang,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
    }

    return {"session_id": session_id, "total": len(findings), "duration": round(duration, 2)}


@app.get("/api/results/{session_id}")
async def api_results(session_id: str):
    session = sessions.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return session


@app.post("/api/verify")
async def api_verify(request: Request):
    """Run AI verification on findings."""
    body = await request.json()
    session_id = body.get("session_id")
    session = sessions.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    findings_data = session["findings"]
    from codeaudit.rules.base import Finding, Severity as Sev

    findings = []
    for f in findings_data:
        findings.append(Finding(
            rule_id=f["rule_id"], message=f["message"], message_zh=f["message"],
            file=f["file"], line=f["line"],
            severity=Sev(f["severity"]),
            snippet=f.get("snippet"), fix=f.get("fix"),
        ))

    snippets = {}
    for f in findings:
        snippets[f.line] = f.snippet or ""

    cfg = load_ai_config()
    if cfg.provider == "mock":
        return {"error": "No AI provider configured", "ai_verified": False}

    results = verify_findings(findings, snippets, config=cfg)
    from codeaudit.llm.client import filter_verified
    confirmed = filter_verified(results)

    for i, f in enumerate(findings_data):
        if i < len(results):
            f["ai_verified"] = results[i].get("ai_verified", True)
            f["ai_reason"] = results[i].get("ai_reason", "")
            f["ai_severity"] = results[i].get("ai_severity", f["severity"])
            f["ai_suggested_fix"] = results[i].get("ai_suggested_fix", "")

    session["findings"] = findings_data
    return {
        "total": len(findings_data),
        "confirmed": len(confirmed),
        "ai_verified": True,
    }


@app.post("/api/config")
async def api_config(request: Request):
    """Update AI configuration."""
    body = await request.json()
    for key, value in body.items():
        env_key = f"CODEAUDIT_{key.upper()}"
        if value:
            os.environ[env_key] = str(value)
        else:
            os.environ.pop(env_key, None)
    return {"ok": True}


@app.post("/api/export")
async def api_export(request: Request):
    """Export findings as JSON or SARIF."""
    body = await request.json()
    session_id = body.get("session_id")
    fmt = body.get("format", "json")
    session = sessions.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    from codeaudit.rules.base import Finding, Severity as Sev
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


@app.post("/api/apply-fix")
async def api_apply_fix(request: Request):
    """Apply a fix for a specific finding."""
    body = await request.json()
    file_path = body.get("file")
    rule_id = body.get("rule_id")
    line = body.get("line")
    fix_text = body.get("fix")

    if not file_path or not fix_text:
        raise HTTPException(status_code=400, detail="Missing file or fix")

    from codeaudit.rules.base import Finding, Severity as Sev
    finding = Finding(
        rule_id=rule_id or "UNKNOWN", message=fix_text, message_zh=fix_text,
        file=file_path, line=line or 1, severity=Sev.WARNING,
        fix=fix_text,
    )

    result = fix_file(file_path, [finding], dry_run=False, backup=True)
    return {"ok": True, "backup": result.backup, "path": result.path}


# ─── Server ──────────────────────────────────────────────

def run_server(host: str = "127.0.0.1", port: int = 8080, reload: bool = False):
    """Start the CodeAudit web UI server."""
    import uvicorn
    print(f"  CodeAudit Web UI: http://{host}:{port}")
    print(f"  API docs: http://{host}:{port}/docs")
    uvicorn.run(app, host=host, port=port, reload=reload)
