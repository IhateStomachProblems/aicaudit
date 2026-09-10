#!/usr/bin/env python3
"""Benchmark runner: aicaudit vs Bandit on the labeled corpus.

Method (fully reproducible — just run `python benchmarks/run.py`):
  1. Scan benchmarks/corpus/** with aicaudit (--output json) and Bandit (-f json).
  2. Map findings to ground-truth cases by rule and line range (function bodies
     resolved via AST; module-level cases list explicit lines).
  3. Per rule: TP = positives matched, FP = findings outside positives
     (conservative/design_skip cases are reported separately, not counted as
     FP), FN = positives missed. Precision/recall/F1 follow.
  4. Bandit findings map into comparable rule buckets via test-id prefixes;
     buckets Bandit does not cover are marked "no bandit coverage".

The comparison is intentionally honest: Bandit's usage-tier alerts on constant
arguments are reported as the documented design difference, not hidden.
"""
from __future__ import annotations

import ast
import json
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).parent
REPO = HERE.parent

# Bandit test-id prefixes -> aicaudit rule buckets (comparable categories)
BANDIT_MAP = {
    "B608": "S001",                       # hardcoded_sql_expressions
    "B105": "S002", "B106": "S002", "B107": "S002",   # hardcoded password variants
    "B301": "S003", "B302": "S003", "B304": "S003", "B305": "S003",  # deserialization
    "B307": "S003", "B102": "S003",       # eval / exec
    "B605": "S003",                       # os.system with shell
    "B607": "S003",                       # getoutput
    "B324": "S006",                       # hashlib weak hash
    "B313": "S007", "B314": "S007", "B315": "S007", "B316": "S007",  # xml
}


def run_json(cmd: list[str], timeout: int = 300) -> tuple[dict | None, float]:
    start = time.perf_counter()
    proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                          errors="replace", cwd=str(REPO), timeout=timeout, check=False)
    elapsed = time.perf_counter() - start
    if proc.returncode not in (0, 1):     # bandit exits 1 on findings
        print(f"  command failed ({proc.returncode}): {' '.join(cmd)}", file=sys.stderr)
        print(proc.stderr[:500], file=sys.stderr)
        return None, elapsed
    raw = proc.stdout
    try:
        start_i = raw.index("{")
        end_i = raw.rindex("}") + 1
        return json.loads(raw[start_i:end_i]), elapsed
    except ValueError:
        return None, elapsed


def scan_aicaudit(root: Path) -> tuple[list[dict], float]:
    doc, elapsed = run_json([sys.executable, "-m", "aicaudit", "scan", str(root),
                             "--output", "json"])
    if doc is None:
        return [], elapsed
    return doc.get("findings", []), elapsed


def scan_bandit(root: Path) -> tuple[list[dict], float]:
    proc_start = time.perf_counter()
    proc = subprocess.run([sys.executable, "-m", "bandit", "-r", str(root), "-f", "json", "-q"],
                          capture_output=True, text=True, encoding="utf-8",
                          errors="replace", cwd=str(REPO), timeout=300, check=False)
    elapsed = time.perf_counter() - proc_start
    try:
        doc = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return [], elapsed
    out = []
    for res in doc.get("results", []):
        for prefix, rule in BANDIT_MAP.items():
            if res["test_id"].startswith(prefix):
                out.append({"rule_id": rule,
                            "file": Path(res["filename"]).name,
                            "line": res["line_number"]})
                break
    return out, elapsed


def func_ranges(path: Path) -> dict[str, tuple[int, int]]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    out = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            end = max(getattr(n, "end_lineno", node.lineno) for n in ast.walk(node)
                      if hasattr(n, "lineno"))
            out[node.name] = (node.lineno, end)
    return out


def case_lines(case: dict, ranges: dict[str, tuple[int, int]]) -> set[int]:
    if case.get("func") == "<module>":
        return set(case.get("lines", []))
    span = ranges.get(case["func"])
    if span is None:
        return set()
    return set(range(span[0], span[1] + 1))


def evaluate(findings: list[dict], cases: list[dict], files: dict[str, dict]) -> dict:
    """Returns per-rule metrics plus details for the report."""
    by_rule: dict[str, dict] = defaultdict(lambda: {
        "tp": 0, "fn": 0, "fp": 0, "missed": [], "extra": [],
        "conservative": 0, "design_skip": 0, "design_total": 0,
        "conservative_total": 0, "with_path": 0})

    case_by_rule: dict[str, list[dict]] = defaultdict(list)
    for case in cases:
        case_by_rule[case["rule"]].append(case)

    for rule, rule_cases in case_by_rule.items():
        m = by_rule[rule]
        m["design_total"] = sum(1 for c in rule_cases if c["kind"] == "design_skip")
        m["conservative_total"] = sum(1 for c in rule_cases if c["kind"] == "conservative")
        lines_index: dict[tuple[str, int], str] = {}   # (file basename, line) -> case kind
        for case in rule_cases:
            fname = case["file"]
            ranges = files.get(fname, {})
            for ln in case_lines(case, ranges):
                lines_index[(fname, ln)] = case["kind"]
        rule_findings = [f for f in findings if f["rule_id"] == rule]
        hit_cases: set[tuple[str, str]] = set()
        for f in rule_findings:
            fbase = Path(f["file"]).name
            kind = lines_index.get((fbase, f["line"]))
            if kind == "positive":
                m["tp"] += 1
                hit_cases.add((fbase, f["line"]))
                if f.get("taint_path"):
                    m["with_path"] += 1
            elif kind in ("conservative", "design_skip"):
                m[kind] += 1
            else:
                # negative or line not covered by any case of this rule
                m["fp"] += 1
                m["extra"].append(f"{fbase}:{f['line']}")
        for case in rule_cases:
            if case["kind"] != "positive":
                continue
            lines = case_lines(case, files.get(case["file"], {}))
            if not any((case["file"], ln) in hit_cases for ln in lines):
                m["fn"] += 1
                m["missed"].append(f"{case['file']}:{case['func']}")
    return dict(by_rule)


def prf(tp: int, fp: int, fn: int) -> tuple[float, float, float]:
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return precision, recall, f1


def main() -> int:
    gt = json.loads((HERE / "ground_truth.json").read_text(encoding="utf-8"))
    all_aicaudit: list[dict] = []
    all_bandit: list[dict] = []
    total_aicaudit_time = 0.0
    total_bandit_time = 0.0
    all_cases: list[dict] = []
    files_meta: dict[str, dict] = {}

    for corpus in gt["corpora"]:
        root = HERE / corpus["root"]
        print(f"== corpus: {corpus['name']} ({root})")
        for py in sorted(root.rglob("*.py")):
            files_meta[py.name] = func_ranges(py)
        findings, t1 = scan_aicaudit(root)
        all_aicaudit.extend(findings)
        total_aicaudit_time += t1
        print(f"   aicaudit: {len(findings)} findings in {t1:.2f}s")
        bandit_findings, t2 = scan_bandit(root)
        all_bandit.extend(bandit_findings)
        total_bandit_time += t2
        print(f"   bandit  : {len(bandit_findings)} mapped findings in {t2:.2f}s")
        all_cases.extend(corpus["cases"])

    ai = evaluate(all_aicaudit, all_cases, files_meta)
    bd = evaluate(all_bandit, all_cases, files_meta)

    lines: list[str] = []
    lines.append("# Benchmark Results")
    lines.append("")
    lines.append("Generated by `python benchmarks/run.py` — rerun to reproduce. "
                 "See the methodology docstring in `run.py`.")
    lines.append("")
    lines.append(f"- aicaudit scan time: **{total_aicaudit_time:.2f}s**"
                 f" | Bandit scan time: **{total_bandit_time:.2f}s**")
    lines.append("")
    lines.append("| Rule | aicaudit P | aicaudit R | aicaudit F1 | Bandit P | Bandit R | Bandit F1 | taint paths |")
    lines.append("|------|-----------|-----------|------------|---------|---------|----------|--------------|")
    for rule in ("S001", "S002", "S003", "S004", "S005", "S006", "S007", "S008"):
        a, b = ai.get(rule), bd.get(rule)
        if a is None and b is None:
            continue
        ap, ar, af = prf(a["tp"], a["fp"], a["fn"]) if a else (0, 0, 0)
        if b and (b["tp"] + b["fp"]) > 0:
            bp, br, bf = prf(b["tp"], b["fp"], b["fn"])
            bandit_cell = f"{bp:.0%} | {br:.0%} | {bf:.0%}"
        else:
            bandit_cell = "no coverage | — | —"
        paths = a["with_path"] if a else 0
        lines.append(f"| {rule} | {ap:.0%} | {ar:.0%} | {af:.0%} | {bandit_cell} | {paths} |")
    lines.append("")
    lines.append("### Honest notes")
    total_cases = len(all_cases)
    total_pos = sum(1 for c in all_cases if c["kind"] == "positive")
    total_neg = sum(1 for c in all_cases if c["kind"] == "negative")
    lines.append(f"- Corpus: **{total_cases} labeled cases** "
                 f"({total_pos} positives / {total_neg} negatives + conservative/design tiers). "
                 f"It is our own labeled corpus — challenge it: `python benchmarks/run.py`.")
    for rule in ("S001", "S002", "S003", "S004", "S005", "S006", "S007", "S008"):
        a = ai.get(rule)
        if not a:
            continue
        notes = []
        if a["missed"]:
            notes.append(f"missed: {', '.join(a['missed'][:6])}")
        if a["extra"]:
            notes.append(f"false positives: {', '.join(a['extra'][:6])}")
        if a["conservative_total"]:
            notes.append(f"{a['conservative_total']} conservative case(s) — tool flags them by "
                         f"documented conservative design (not counted as FP)")
        if a["design_total"]:
            notes.append(f"{a['design_total']} constant-usage case(s) intentionally silent in "
                         f"taint mode (usage tier; Bandit fires there by design)")
        if notes:
            lines.append(f"- **{rule}**: " + "; ".join(notes))
    lines.append("")

    out = HERE / "RESULTS.md"
    out.write_text("\n".join(lines), encoding="utf-8")
    print(f"\nwrote {out}")
    # console summary
    for rule in sorted(ai):
        a = ai[rule]
        p, r, f1 = prf(a["tp"], a["fp"], a["fn"])
        print(f"{rule}: TP={a['tp']} FP={a['fp']} FN={a['fn']} P={p:.0%} R={r:.0%} F1={f1:.0%} paths={a['with_path']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
