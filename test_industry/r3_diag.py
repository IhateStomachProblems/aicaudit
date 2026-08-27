"""S002/S003 诊断"""
import json, subprocess, sys
sys.stdout.reconfigure(encoding="utf-8")
PYTHON = r"D:\Users\17390\AppData\Local\Programs\Python\Python313\python.exe"
PROJ_DIR = r"D:\Desktop\开源git项目\aicaudit"

def scan(fp):
    r = subprocess.run([PYTHON, "-m", "aicaudit", "scan", fp, "--output", "json"],
                       capture_output=True, text=True, cwd=PROJ_DIR, encoding="utf-8", errors="replace")
    return json.loads(r.stdout[r.stdout.index("{"):])

print("S002 所有发现:")
d = scan("test_industry/security/secret_leak_variants.py")
for f in d["findings"]:
    if f["rule_id"]=="S002":
        print(f'  line {f["line"]}: {f.get("snippet","")[:70]}')

print("\nS003 所有发现:")
d3 = scan("test_industry/security/dangerous_func_variants.py")
print(f"Total findings: {d3['total']}")
for f in d3["findings"]:
    if f["rule_id"]=="S003":
        print(f'  line {f["line"]}: {f.get("snippet","")[:70]}')
