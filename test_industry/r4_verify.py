"""Round 4 验证：全 A 冲刺核查"""
import json, subprocess, sys, os
sys.stdout.reconfigure(encoding="utf-8")
PYTHON = r"D:\Users\17390\AppData\Local\Programs\Python\Python313\python.exe"
PROJ_DIR = r"D:\Desktop\开源git项目\codeaudit"

def scan(fp):
    r = subprocess.run([PYTHON, "-m", "codeaudit", "scan", fp, "--output", "json"],
                       capture_output=True, text=True, cwd=PROJ_DIR, encoding="utf-8", errors="replace")
    return json.loads(r.stdout[r.stdout.index("{"):])

def build_ranges(fp):
    source = open(os.path.join(PROJ_DIR, fp), encoding="utf-8").readlines()
    fns = []
    for i, line in enumerate(source, 1):
        s = line.strip()
        if s.startswith("def "):
            fns.append((s.split("(")[0].replace("def ", ""), i))
    ranges = {}
    for idx, (fn, start) in enumerate(fns):
        end = fns[idx+1][1]-1 if idx+1 < len(fns) else len(source)
        ranges[fn] = (start, end)
    return ranges

def hit(rid, fn, ranges, findings):
    if fn not in ranges: return False
    s, e = ranges[fn]
    return any(f["rule_id"]==rid and s <= f["line"] <= e for f in findings)

d = scan("test_industry/security/s004_s007_new_rules.py")
r = build_ranges("test_industry/security/s004_s007_new_rules.py")
source = open(os.path.join(PROJ_DIR, "test_industry/security/s004_s007_new_rules.py"), encoding="utf-8").readlines()

groups = {
    "S004": (["path_traversal_join","path_traversal_concat","path_traversal_fstring",
              "path_traversal_abspath","path_traversal_normpath","path_traversal_realpath"],
             ["safe_path_basename","safe_path_constant"]),
    "S005": (["ssrf_requests","ssrf_requests_post","ssrf_requests_put","ssrf_requests_delete",
              "ssrf_urlopen_simple","ssrf_urlopen_request","ssrf_urllib_urlretrieve"],
             ["safe_requests_constant"]),
    "S006": (["weak_md5","weak_sha1"], ["safe_sha256"]),
    "S007": (["xxe_lxml_str","xxe_minidom","xxe_etree_parse","xxe_minidom_parse","xxe_elementtree_parse"],
             ["safe_etree_fromstring","safe_defusedxml"]),
}

print("="*66)
print("  ROUND 4 验证 — 全 A 冲刺核查")
print("="*66)
all_pass = True
for rid, (pos, neg) in groups.items():
    ph = sum(1 for fn in pos if hit(rid, fn, r, d["findings"]))
    fp = sum(1 for fn in neg if hit(rid, fn, r, d["findings"]))
    status = "PASS" if (ph == len(pos) and fp == 0) else "FAIL"
    if status == "FAIL": all_pass = False
    print(f"\n[{rid}] {status}")
    print(f"  正例: {ph}/{len(pos)}")
    for fn in pos:
        if not hit(rid, fn, r, d["findings"]): print(f"    MISS: {fn}")
    print(f"  误报: {fp}")
    if fp:
        for fn in neg:
            if hit(rid, fn, r, d["findings"]): print(f"    FP: {fn}")

# S001/S002/S003 回归
print("\n" + "="*66)
print("  回归: S001/S002/S003/S004 额外变体")
print("="*66)

# 自扫描
print("\n[自扫描] ERROR/CRITICAL:")
ds = scan("codeaudit/")
errs = [f for f in ds["findings"] if f["severity"] in ("error","critical")]
print(f"  ERROR+CRITICAL: {len(errs)}")
for f in errs:
    print(f'    {f["rule_id"]} line {f["line"]}: {f.get("snippet","")[:60]}')

print(f"\n总结: {'全部 PASS ✅' if all_pass else '存在 FAIL ❌'}")
