"""S007 FP 详细分析"""
import json, subprocess, sys, ast
sys.stdout.reconfigure(encoding="utf-8")
PYTHON = r"D:\Users\17390\AppData\Local\Programs\Python\Python313\python.exe"
PROJ_DIR = r"D:\Desktop\开源git项目\aicaudit"

r = subprocess.run([PYTHON, "-m", "aicaudit", "scan", "test_industry/security/s004_s007_new_rules.py", "--output", "json"], capture_output=True, text=True, cwd=PROJ_DIR)
d = json.loads(r.stdout[r.stdout.index("{"):])
print("S007 所有发现:")
for f in d["findings"]:
    if f["rule_id"] == "S007":
        s = f.get("snippet") or "(None)"
        print(f"  line {f['line']:3d}: {s[:80]}")

print("\ndefusedxml 检测分析:")
src = open(PROJ_DIR + "/test_industry/security/s004_s007_new_rules.py", encoding="utf-8").read()
tree = ast.parse(src)
for node in ast.walk(tree):
    if isinstance(node, ast.Call):
        func = ""
        if isinstance(node.func, ast.Attribute):
            parts = []
            cur = node.func
            while isinstance(cur, ast.Attribute):
                parts.append(cur.attr)
                cur = cur.value
            if isinstance(cur, ast.Name):
                parts.append(cur.id)
            func = ".".join(reversed(parts))
        elif isinstance(node.func, ast.Name):
            func = node.func.id
        if "parse" in func.lower() or "fromstring" in func.lower():
            has_defused = any(
                "defusedxml" in str(n.id).lower()
                for n in ast.walk(node) if isinstance(n, ast.Name)
            )
            print(f"  {func} (line {node.lineno}): defusedxml={has_defused}")
