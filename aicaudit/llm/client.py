"""LLM client: evidence-grounded AI verdicts with fail-safe semantics.

Verdict lifecycle: every finding gets a three-state verdict —
  confirmed       AI judged it a genuine vulnerability (confidence >= threshold)
  false_positive  AI judged it noise
  unverified      AI missing/error/parse-failure/low-confidence — NEVER auto-
                  confirmed (the old fail-open behavior silently suppressed
                  nothing but also rubber-stamped everything; both directions
                  were wrong).
Suppressing findings is an explicit opt-in (`--ai-strict`), because the best
reported LLM-verifier configurations still wrongly suppress ~22% of true
positives (arXiv 2601.22952).
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass

from aicaudit.llm.prompts import FindingEvidence, build_evidence_prompt

CONFIDENCE_THRESHOLD = 0.5
BATCH_SIZE = 10


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
    cfg.provider = os.environ.get("AICAUDIT_AI_PROVIDER", "mock").lower()
    cfg.api_key = os.environ.get("AICAUDIT_AI_KEY", "")
    cfg.api_base = os.environ.get("AICAUDIT_AI_BASE", "")
    if cfg.provider in ("relay", "custom", "proxy"):
        cfg.model = os.environ.get("AICAUDIT_AI_MODEL", "gpt-4o-mini")
        return cfg
    if cfg.provider == "openai":
        cfg.model = os.environ.get("AICAUDIT_AI_MODEL", "gpt-4o-mini")
        cfg.api_base = cfg.api_base or "https://api.openai.com/v1"
    elif cfg.provider == "claude":
        cfg.model = os.environ.get("AICAUDIT_AI_MODEL", "claude-sonnet-4-20250514")
    elif cfg.provider == "openrouter":
        cfg.model = os.environ.get("AICAUDIT_AI_MODEL", "openai/gpt-4o-mini")
        cfg.api_base = cfg.api_base or "https://openrouter.ai/api/v1"
    elif cfg.provider == "ollama":
        cfg.model = os.environ.get("AICAUDIT_AI_MODEL", "llama3.2")
        cfg.api_base = cfg.api_base or "http://localhost:11434/v1"
    else:
        cfg.provider = "mock"
    return cfg


# ── public API ───────────────────────────────────────────────────────────────

def verify_findings(evidences: list[FindingEvidence], config: AiConfig | None = None) -> list[dict]:
    """Verify findings against their evidence. Returns one verdict dict each."""
    cfg = config or load_ai_config()
    if cfg.provider == "mock":
        return [_unverified(f, "no AI provider configured") for f in evidences]
    if not cfg.api_key and cfg.provider != "ollama":
        return [_unverified(f, "no API key configured") for f in evidences]
    return _llm_verify(evidences, cfg)


def filter_confirmed(verdicts: list[dict]) -> list[dict]:
    """Strict mode: keep only AI-confirmed findings."""
    return [v for v in verdicts if v.get("ai_status") == "confirmed"]


def verdict_status(v: dict) -> str:
    return v.get("ai_status", "unverified")


# ── internals ────────────────────────────────────────────────────────────────

def _base_dict(ev: FindingEvidence) -> dict:
    return {"rule_id": ev.rule_id, "message": ev.message, "file": ev.file,
            "line": ev.line, "severity": ev.severity, "snippet": ev.snippet,
            "fix": ev.fix, "cwe": ev.cwe}


def _unverified(ev: FindingEvidence, reason: str) -> dict:
    d = _base_dict(ev)
    d.update({"ai_status": "unverified", "ai_confidence": 0.0, "ai_reason": reason,
              "ai_severity": ev.severity, "ai_cwe": ev.cwe or "",
              "ai_vuln_type": "", "ai_suggested_fix": "",
              "evidence_used": [p.render() for p in ev.taint_paths]})
    return d


def _llm_verify(evidences: list[FindingEvidence], cfg: AiConfig) -> list[dict]:
    all_results: list[dict] = []
    for start in range(0, len(evidences), BATCH_SIZE):
        batch = evidences[start:start + BATCH_SIZE]
        prompt = build_evidence_prompt(batch, offset=start)
        response = _call_llm_with_retry(prompt, cfg, retries=2)
        all_results.extend(_parse_verdicts(response, batch, offset=start))
    return all_results


def _parse_verdicts(response_text: str, batch: list[FindingEvidence],
                    offset: int = 0) -> list[dict]:
    """Fail-safe: anything the LLM did not clearly judge becomes unverified."""
    verdicts = _extract_json_array(response_text)
    if verdicts is None:
        return [_unverified(f, "AI response unparseable — marked unverified") for f in batch]

    vmap: dict[int, dict] = {}
    for v in verdicts:
        if isinstance(v, dict) and isinstance(v.get("index"), int):
            vmap[v["index"]] = v

    results: list[dict] = []
    for i, f in enumerate(batch):
        # candidates: batch-relative index, then the absolute index (some
        # models echo the prompt's global numbering)
        v = vmap.get(i) or vmap.get(i + offset)
        if v is None:
            results.append(_unverified(f, f"no verdict returned for index {i}"))
            continue
        d = _base_dict(f)
        d["evidence_used"] = [p.render() for p in f.taint_paths]

        if "is_real" not in v:
            results.append(_unverified(f, "verdict missing is_real — marked unverified"))
            continue
        try:
            confidence = float(v.get("confidence", 0.0))
        except (TypeError, ValueError):
            confidence = 0.0
        confidence = max(0.0, min(1.0, confidence))

        is_real = bool(v["is_real"])
        status = "confirmed" if is_real else "false_positive"
        reason = str(v.get("reason", "")).strip()
        if status == "confirmed" and confidence < CONFIDENCE_THRESHOLD:
            status = "unverified"
            reason = (reason + " — ").lstrip() + f"confidence {confidence:.2f} below threshold {CONFIDENCE_THRESHOLD}"
        d.update({
            "ai_status": status,
            "ai_confidence": round(confidence, 2),
            "ai_reason": reason or "(no reason given)",
            "ai_severity": v.get("severity", f.severity),
            "ai_cwe": v.get("cwe", f.cwe or ""),
            "ai_vuln_type": v.get("vuln_type", ""),
            "ai_suggested_fix": v.get("suggested_fix", ""),
        })
        results.append(d)
    return results


def _extract_json_array(text: str) -> list | None:
    """Parse the LLM response as a JSON array, tolerating code fences."""
    if not text:
        return None
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.strip("`")
        cleaned = cleaned.removeprefix("json")
        cleaned = cleaned.strip()
    try:
        parsed = json.loads(cleaned)
    except json.JSONDecodeError:
        start = cleaned.find("[")
        end = cleaned.rfind("]")
        if start == -1 or end <= start:
            return None
        try:
            parsed = json.loads(cleaned[start:end + 1])
        except json.JSONDecodeError:
            return None
    return parsed if isinstance(parsed, list) else None


def _call_llm_with_retry(prompt, cfg, retries=2):
    last_error = None
    for attempt in range(retries + 1):
        try:
            return _call_llm(prompt, cfg)
        except Exception as e:  # noqa: BLE001 — retry on any transport/parse failure, fall back below
            last_error = str(e)
            if attempt < retries:
                time.sleep(1 * (attempt + 1))
    return json.dumps({"error": "LLM call failed after " + str(retries + 1) + " attempts: " + str(last_error)})


def _call_llm(prompt, cfg):
    if cfg.provider == "claude":
        return _call_claude(prompt, cfg)
    return _call_openai_compat(prompt, cfg)


def _extract_response_text(message):
    """Extract text from LLM response message.

    Some models (e.g. GLM-5.2) put the actual response in 'reasoning_content'
    when content is empty. This function handles both cases.
    """
    content = message.get("content", "") or ""
    if not content.strip():
        reasoning = message.get("reasoning_content", "") or ""
        if reasoning.strip():
            return reasoning
    return content


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
    headers = {"Content-Type": "application/json", "User-Agent": "aicaudit-ai"}
    if cfg.api_key:
        headers["Authorization"] = "Bearer " + cfg.api_key
    endpoint = cfg.api_base.rstrip("/") + "/chat/completions"
    req = urllib.request.Request(endpoint, data=body, headers=headers, method="POST")
    resp = urllib.request.urlopen(req, timeout=60)
    result = json.load(resp)
    message = result["choices"][0]["message"]
    return _extract_response_text(message)


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
