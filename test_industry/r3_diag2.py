"""S002/S003 精确行号分析"""
import json, subprocess, sys
sys.stdout.reconfigure(encoding="utf-8")
PYTHON = r"D:\Users\17390\AppData\Local\Programs\Python\Python313\python.exe"
PROJ_DIR = r"D:\Desktop\开源git项目\codeaudit"

def scan(fp):
    r = subprocess.run([PYTHON, "-m", "codeaudit", "scan", fp, "--output", "json"],
                       capture_output=True, text=True, cwd=PROJ_DIR, encoding="utf-8", errors="replace")
    return json.loads(r.stdout[r.stdout.index("{"):])

# S002 精确行号
print("S002 精确行号:")
d = scan("test_industry/security/secret_leak_variants.py")
found_lines = set()
for f in d["findings"]:
    if f["rule_id"]=="S002":
        found_lines.add(f["line"])
        print(f"  检出 line {f['line']}")

print("\n文件中的密钥行:")
with open(PROJ_DIR + "/test_industry/security/secret_leak_variants.py", encoding="utf-8") as fh:
    for i, line in enumerate(fh, 1):
        if "=" in line and any(k in line.lower() for k in ["key","secret","token","password","url","ssh","jwt"]):
            status = "检出" if i in found_lines else "漏报"
            if "def " not in line:
                print(f"  [{status}] line {i}: {line.strip()[:60]}")

# S003
print("\nS003 精确行号:")
d3 = scan("test_industry/security/dangerous_func_variants.py")
found3 = set()
for f in d3["findings"]:
    if f["rule_id"]=="S003":
        found3.add(f["line"])
print(f"  总检出: {len(found3)}")
print(f"  行号: {sorted(found3)}")
