"""FP 分析"""
import json, subprocess, sys
sys.stdout.reconfigure(encoding="utf-8")
PYTHON = r"D:\Users\17390\AppData\Local\Programs\Python\Python313\python.exe"
PROJ_DIR = r"D:\Desktop\开源git项目\aicaudit"

r = subprocess.run([PYTHON, "-m", "aicaudit", "scan", "test_industry/security/s004_s007_new_rules.py", "--output", "json"], capture_output=True, text=True, cwd=PROJ_DIR)
d = json.loads(r.stdout[r.stdout.index("{"):])
for f in d["findings"]:
    if f["rule_id"] in ("S004","S007"):
        print(f'{f["rule_id"]} line {f["line"]}: {f.get("snippet","")[:80]}')
        print(f'  msg: {f.get("message","")[:100]}')
        print(f'  fix: {f.get("fix","")[:80]}')
        print()
