"""LLM client for AI verification."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass


@dataclass
class AiConfig:
    provider: str = "mock"
    model: str = ""
    api_key: str = ""
    api_base: str = ""
    temperature: float = 0.1
    max_tokens: int = 1024


def load_ai_config() -> AiConfig:
    cfg = AiConfig()
    cfg.provider = os.environ.get("CODEAUDIT_AI_PROVIDER", "mock").lower()
    cfg.api_key = os.environ.get("CODEAUDIT_AI_KEY", "")
    cfg.api_base = os.environ.get("CODEAUDIT_AI_BASE", "")
    if cfg.provider == "openai":
        cfg.model = os.environ.get("CODEAUDIT_AI_MODEL", "gpt-4o-mini")
        cfg.api_base = cfg.api_base or "https://api.openai.com/v1"
    elif cfg.provider == "openrouter":
        cfg.model = os.environ.get("CODEAUDIT_AI_MODEL", "openai/gpt-4o-mini")
        cfg.api_base = cfg.api_base or "https://openrouter.ai/api/v1"
    elif cfg.provider == "ollama":
        cfg.model = os.environ.get("CODEAUDIT_AI_MODEL", "llama3.2")
        cfg.api_base = cfg.api_base or "http://localhost:11434/v1"
    else:
        cfg.provider = "mock"
    return cfg


def verify_findings(findings, code_snippets, config=None):
    cfg = config or load_ai_config()
    if cfg.provider == "mock":
        return _mock_verify(findings)
    return _llm_verify(findings, code_snippets, cfg)


def _mock_verify(findings):
    results = []
    for f in findings:
        d = _finding_to_dict(f)
        d["ai_verified"] = True
        d["ai_reason"] = "Mock AI: pass-through (no LLM configured)"
        results.append(d)
    return results


def _finding_to_dict(f):
    return {
        "rule_id": f.rule_id,
        "message": f.message,
        "file": f.file,
        "line": f.line,
        "severity": f.severity.value,
        "snippet": f.snippet,
        "fix": f.fix,
    }


def _llm_verify(findings, code_snippets, cfg):
    if not cfg.api_key and cfg.provider not in ("ollama",):
        return _mock_verify(findings)
    prompt = _build_prompt(findings, code_snippets)
    response = _call_llm(prompt, cfg)
    return _parse_response(response, findings)


def _build_prompt(findings, code_snippets):
    intro = (
        "You are a code review expert. Verify each potential issue.\n"
        "Respond with JSON array: [{\"index\": 0, \"is_real\": true, \"reason\": \"...\"}]\n"
        "ONLY return valid JSON, no other text.\n\n"
    )
    parts = [intro]
    for i, f in enumerate(findings):
        snippet = code_snippets.get(f.line, "")
        parts.append("[" + str(i) + "] " + f.rule_id + " " + f.severity.value + "\n")
        parts.append("    " + f.message + "\n")
        parts.append("    Code: " + snippet + "\n\n")
    return "".join(parts)


def _call_llm(prompt, cfg):
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
    req = urllib.request.Request(
        cfg.api_base.rstrip("/") + "/chat/completions",
        data=body, headers=headers, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            result = json.load(resp)
            return result["choices"][0]["message"]["content"]
    except Exception as e:  # noqa: BLE001 - network failure should fall back gracefully
        return json.dumps({"error": str(e)})


def _parse_response(response_text, findings):
    results = []
    try:
        verdicts = json.loads(response_text)
        if isinstance(verdicts, list):
            verdict_map = {v.get("index"): v for v in verdicts if "index" in v}
            for i, f in enumerate(findings):
                d = _finding_to_dict(f)
                if i in verdict_map:
                    v = verdict_map[i]
                    d["ai_verified"] = v.get("is_real", True)
                    d["ai_reason"] = v.get("reason", "")
                else:
                    d["ai_verified"] = True
                    d["ai_reason"] = "No verdict from AI"
                results.append(d)
            return results
    except (json.JSONDecodeError, TypeError):
        pass
    for f in findings:
        d = _finding_to_dict(f)
        d["ai_verified"] = True
        d["ai_reason"] = "Fallback: AI response parsing failed"
        results.append(d)
    return results


def filter_verified(findings_with_ai):
    return [f for f in findings_with_ai if f.get("ai_verified", True)]
