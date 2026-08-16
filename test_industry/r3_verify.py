"""Round 3 验证：本轮声称的全部修复"""
import json, subprocess, sys, os, re
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

print("="*66)
print("  ROUND 3 验证 — 声称修复点逐条核对")
print("="*66)

d = scan("test_industry/security/s004_s007_new_rules.py")
r = build_ranges("test_industry/security/s004_s007_new_rules.py")

# 1. S004 路径遍历
print("\n[1] S004 路径遍历 (声称 Name/Attribute 检测)")
pos4 = ["path_traversal_join","path_traversal_concat","path_traversal_fstring",
        "path_traversal_abspath","path_traversal_normpath","path_traversal_realpath",
        "path_traversal_zip","path_traversal_tar"]
neg4 = ["safe_path_basename","safe_path_constant","safe_path_no_user_input"]
hit4 = sum(1 for fn in pos4 if hit("S004",fn,r,d["findings"]))
fp4 = sum(1 for fn in neg4 if hit("S004",fn,r,d["findings"]))
print(f"  正例: {hit4}/{len(pos4)}")
for fn in pos4:
    if not hit("S004",fn,r,d["findings"]): print(f"    MISS: {fn}")
print(f"  误报: {fp4}")
if fp4:
    for fn in neg4:
        if hit("S004",fn,r,d["findings"]): print(f"    FP: {fn}")

# 2. S005 SSRF (声称 0/7->6/7)
print("\n[2] S005 SSRF (声称变量检测恢复)")
pos5 = ["ssrf_requests","ssrf_requests_post","ssrf_requests_put","ssrf_requests_delete",
        "ssrf_urlopen_simple","ssrf_urlopen_request","ssrf_urllib_urlretrieve"]
neg5 = ["safe_requests_constant","safe_urlopen_constant"]
hit5 = sum(1 for fn in pos5 if hit("S005",fn,r,d["findings"]))
fp5 = sum(1 for fn in neg5 if hit("S005",fn,r,d["findings"]))
print(f"  正例: {hit5}/{len(pos5)}")
for fn in pos5:
    if not hit("S005",fn,r,d["findings"]): print(f"    MISS: {fn}")
print(f"  误报: {fp5}")
if fp5:
    for fn in neg5:
        if hit("S005",fn,r,d["findings"]): print(f"    FP: {fn}")

# 3. S006 / S007（上轮已通过，回归确认）
print("\n[3] S006/S007 回归")
pos6 = ["weak_md5","weak_sha1","weak_md5_bytes","weak_sha1_bytes"]
neg6 = ["safe_sha256","safe_sha256_bytes","safe_sha3_256"]
print(f"  S006: 正例 {sum(1 for fn in pos6 if hit('S006',fn,r,d['findings']))}/{len(pos6)}, 误报 {sum(1 for fn in neg6 if hit('S006',fn,r,d['findings']))}")
pos7 = ["xxe_lxml","xxe_minidom","xxe_etree_parse","xxe_minidom_parse"]
neg7 = ["safe_etree_fromstring"]
print(f"  S007: 正例 {sum(1 for fn in pos7 if hit('S007',fn,r,d['findings']))}/{len(pos7)}, 误报 {sum(1 for fn in neg7 if hit('S007',fn,r,d['findings']))}")

# 4. S001 %s/.format (声称修复)
print("\n[4] S001 %s/.format (声称 7/7)")
d1 = scan("test_industry/security/sql_injection_variants.py")
r1 = build_ranges("test_industry/security/sql_injection_variants.py")
pos1 = ["sqlite3_fstring","sqlite3_concat","sqlite3_percent_format","sqlite3_dot_format",
        "sqlite3_joined_with_variable","sqlite3_executemany","sqlite3_executescript_ignore",
        "sqlite3_multiline_fstring","sqlite3_nested_var","sqlite3_join_list"]
neg1 = ["sqlite3_param_q","sqlite3_param_named","sqlite3_param_list","sqlite3_literal_no_input","sqlite3_literal_param_combo"]
hit1 = sum(1 for fn in pos1 if hit("S001",fn,r1,d1["findings"]))
fp1 = sum(1 for fn in neg1 if hit("S001",fn,r1,d1["findings"]))
print(f"  正例: {hit1}/{len(pos1)}")
for fn in pos1:
    if not hit("S001",fn,r1,d1["findings"]): print(f"    MISS: {fn}")
print(f"  误报: {fp1}")

# 5. S002 redis 无用户名 (声称修复)
print("\n[5] S002 redis 无用户名 (声称修复)")
d2 = scan("test_industry/security/secret_leak_variants.py")
redis_hit = any(f["rule_id"]=="S002" and "redis" in str(f.get("snippet","")) for f in d2["findings"])
print(f"  redis_url_nouser: {'检出' if redis_hit else '仍漏报'}")
# 模块级密钥汇总
mod_keys = {"AWS_ACCESS_KEY":3,"aws_secret":4,"GH_TOKEN":5,"gh_oauth":6,"secret_key":7,
            "api_token":8,"jwt_token":9,"DB_URL":10,"ssh_key":11,"redis_url_nouser":12}
missing = [k for k,ln in mod_keys.items() if not any(f["rule_id"]=="S002" and f["line"]==ln for f in d2["findings"])]
print(f"  模块级密钥: {len(mod_keys)-len(missing)}/{len(mod_keys)} 检出")
if missing: print(f"    漏报: {missing}")

# 6. S003 回归
print("\n[6] S003 回归")
d3 = scan("test_industry/security/dangerous_func_variants.py")
r3 = build_ranges("test_industry/security/dangerous_func_variants.py")
s3_pos = ["pos_eval","pos_exec","pos_pickle_loads","pos_pickle_load","pos_marshal_loads",
          "pos_marshal_load","pos_shelve_open","pos_yaml_load","pos_os_system","pos_os_popen",
          "pos_subprocess_run_shell","pos_subprocess_getoutput","pos_ctypes_cdll",
          "pos_shutil_rmtree","pos_input"]
s3_neg = ["neg_subprocess_no_shell","neg_safe_loads","neg_pickle_dump","neg_normal_functions"]
hit3 = sum(1 for fn in s3_pos if hit("S003",fn,r3,d3["findings"]))
fp3 = sum(1 for fn in s3_neg if hit("S003",fn,r3,d3["findings"]))
print(f"  正例: {hit3}/{len(s3_pos)}")
for fn in s3_pos:
    if not hit("S003",fn,r3,d3["findings"]): print(f"    MISS: {fn}")
print(f"  误报: {fp3}")

# 7. 自扫描
print("\n[7] 自扫描 ERROR/CRITICAL")
ds = scan("codeaudit/")
errs = [f for f in ds["findings"] if f["severity"] in ("error","critical")]
print(f"  自扫描 ERROR+CRITICAL: {len(errs)} 个")
for f in errs:
    print(f"    {f['rule_id']} line {f['line']}: {f.get('snippet','')[:60]}")
