"""LLM client: multi-provider AI verification with evidence-chain context."""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass


@dataclass
class AiConfig:
    provider: str = "mock"
    model: str = ""
    api_key: str = ""
    api_base: str = ""
    temperature: float = 0.1
    max_tokens: int = 4096


def load_ai_config() -> AiConfig:
    cfg = AiConfig()
    cfg.provider = os.environ.get("CODEAUDIT_AI_PROVIDER", "mock").lower()
    cfg.api_key = os.environ.get("CODEAUDIT_AI_KEY", "")
    cfg.api_base = os.environ.get("CODEAUDIT_AI_BASE", "")
    if cfg.provider in ("relay", "custom", "proxy"):
        cfg.model = os.environ.get("CODEAUDIT_AI_MODEL", "gpt-4o-mini")
        return cfg
    if cfg.provider == "openai":
        cfg.model = os.environ.get("CODEAUDIT_AI_MODEL", "gpt-4o-mini")
        cfg.api_base = cfg.api_base or "https://api.openai.com/v1"
    elif cfg.provider == "claude":
        cfg.model = os.environ.get("CODEAUDIT_AI_MODEL", "claude-sonnet-4-20250514")
    elif cfg.provider == "openrouter":
        cfg.model = os.environ.get("CODEAUDIT_AI_MODEL", "openai/gpt-4o-mini")
        cfg.api_base = cfg.api_base or "https://openrouter.ai/api/v1"
    elif cfg.provider == "ollama":
        cfg.model = os.environ.get("CODEAUDIT_AI_MODEL", "llama3.2")
        cfg.api_base = cfg.api_base or "http://localhost:11434/v1"
    else:
        cfg.provider = "mock"
    return cfg


def verify_findings(findings, code_snippets, evidence_chains=None, config=None):
    cfg = config or load_ai_config()
    if cfg.provider == "mock":
        return _mock_verify(findings)
    return _llm_verify(findings, code_snippets, evidence_chains, cfg)


def _mock_verify(findings):
    return [_mark_verified(f) for f in findings]


def _mark_verified(f, reason="Mock AI: pass-through (no LLM configured)"):
    d = _finding_to_dict(f)
    d["ai_verified"] = True
    d["ai_reason"] = reason
    d["ai_severity"] = d["severity"]
    d["ai_vuln_type"] = ""
    d["ai_suggested_fix"] = d.get("fix", "")
    d["evidence_used"] = []
    return d


def _finding_to_dict(f):
    return {"rule_id": f.rule_id, "message": f.message, "file": f.file,
            "line": f.line, "severity": f.severity.value,
            "snippet": f.snippet, "fix": f.fix}


def _llm_verify(findings, code_snippets, evidence_chains, cfg):
    if not cfg.api_key and cfg.provider not in ("ollama",):
        return _mock_verify(findings)
    batch_size = 10
    all_results = []
    for start in range(0, len(findings), batch_size):
        batch = findings[start:start + batch_size]
        prompt = _build_deep_prompt(batch, code_snippets, evidence_chains, start)
        response = _call_llm_with_retry(prompt, cfg, retries=2)
        batch_results = _parse_deep_response(response, batch, evidence_chains)
        all_results.extend(batch_results)
    return all_results


def _call_llm_with_retry(prompt, cfg, retries=2):
    last_error = None
    for attempt in range(retries + 1):
        try:
            return _call_llm(prompt, cfg)
        except Exception as e:
            last_error = str(e)
            if attempt < retries:
                time.sleep(1 * (attempt + 1))
    return json.dumps({"error": "LLM call failed after " + str(retries + 1) + " attempts: " + str(last_error)})


def _build_deep_prompt(findings, code_snippets, evidence_chains, offset=0):
    parts = [
        "You are a senior security code reviewer. Analyze each finding and respond",
        "with a JSON array of objects. Each object MUST have these fields:\n",
        "- index: integer (the finding number, starting from " + str(offset) + ")\n",
        "- is_real: boolean (true = genuine vulnerability, false = false positive)\n",
        "- severity: string (info, warning, error, critical)\n",
        "- vuln_type: string (e.g. SQL-injection, secret-leak, command-injection)\n",
        "- suggested_fix: string (concise fix advice, 2-3 sentences)\n",
        "- reason: string (why you decided this, 1-2 sentences)\n",
        "\nRespond ONLY with the JSON array, no other text.\n\n",
    ]
    for i, f in enumerate(findings):
        idx = offset + i
        parts.append("=== Finding [" + str(idx) + "] ===\n")
        parts.append("Rule: " + f.rule_id + " | Static severity: " + f.severity.value + "\n")
        parts.append("Message: " + f.message + "\n")
        parts.append("File: " + f.file + ":" + str(f.line) + "\n")
        parts.append("Code: " + str(code_snippets.get(f.line, "")) + "\n")
        key = f.rule_id + ":" + f.file + ":" + str(f.line)
        chains = (evidence_chains or {}).get(key, [])
        if chains:
            parts.append("Evidence chain (" + str(len(chains)) + " paths):\n")
            for c in chains[:2]:
                entries = " -> ".join(
                    str(fp) + ":" + str(ln) + "(" + str(fn) + ")"
                    for fp, ln, fn in c.path
                )
                parts.append(
                    "  Entry: " + c.entry + " | Path: " + entries
                    + " | Sink: " + c.sink + " | Risk: " + c.risk + "\n"
                )
        parts.append("\n")
    return "".join(parts)


def _call_llm(prompt, cfg):
    if cfg.provider == "claude":
        return _call_claude(prompt, cfg)
    return _call_openai_compat(prompt, cfg)


def _call_openai_compat(prompt, cfg):
    import urllib.request
    body = json.dumps({
        "model": cfg.model,
        "messages": [
            {"role": "system", "content": "Respond with valid JSON only."},
            {"role": "user", "content": prompt},
        ],
        "temperature": cfg.temperature,
        "max_tokens": cfg.max_tokens,
    }).encode("utf-8")
    headers = {"Content-Type": "application/json", "User-Agent": "codeaudit-ai"}
    if cfg.api_key:
        headers["Authorization"] = "Bearer " + cfg.api_key
    endpoint = cfg.api_base.rstrip("/") + "/chat/completions"
    req = urllib.request.Request(endpoint, data=body, headers=headers, method="POST")
    resp = urllib.request.urlopen(req, timeout=60)
    result = json.load(resp)
    return result["choices"][0]["message"]["content"]


def _call_claude(prompt, cfg):
    import anthropic
    client = anthropic.Anthropic(
        api_key=cfg.api_key or os.environ.get("ANTHROPIC_API_KEY", "")
    )
    msg = client.messages.create(
        model=cfg.model,
        max_tokens=cfg.max_tokens,
        temperature=cfg.temperature,
        system="Respond with valid JSON only. No other text.",
        messages=[{"role": "user", "content": prompt}],
    )
    return msg.content[0].text


def _parse_deep_response(response_text, findings, evidence_chains):
    results = []
    try:
        verdicts = json.loads(response_text)
        if isinstance(verdicts, list):
            vmap = {}
            for v in verdicts:
                if isinstance(v, dict) and "index" in v:
                    vmap[v["index"]] = v
            for i, f in enumerate(findings):
                if i in vmap:
                    v = vmap[i]
                    d = _finding_to_dict(f)
                    d["ai_verified"] = v.get("is_real", True)
                    d["ai_reason"] = v.get("reason", "")
                    d["ai_severity"] = v.get("severity", d["severity"])
                    d["ai_vuln_type"] = v.get("vuln_type", "")
                    d["ai_suggested_fix"] = v.get("suggested_fix", "")
                    key = f.rule_id + ":" + f.file + ":" + str(f.line)
                    d["evidence_used"] = (evidence_chains or {}).get(key, [])
                    results.append(d)
                else:
                    results.append(
                        _mark_verified(f, "No verdict from AI for index " + str(i))
                    )
            return results
    except (json.JSONDecodeError, TypeError, ValueError):
        pass
    return [_mark_verified(f, "Fallback: AI response parsing failed") for f in findings]


def filter_verified(items):
    return [f for f in items if f.get("ai_verified", True)]
