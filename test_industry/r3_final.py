"""Round 3 最终验证：自扫描 + 复杂度"""
import json, subprocess, sys, ast
sys.stdout.reconfigure(encoding="utf-8")
PYTHON = r"D:\Users\17390\AppData\Local\Programs\Python\Python313\python.exe"
PROJ_DIR = r"D:\Desktop\开源git项目\codeaudit"

r = subprocess.run([PYTHON, "-m", "codeaudit", "scan", "codeaudit/", "--output", "json"],
                   capture_output=True, text=True, cwd=PROJ_DIR)
d = json.loads(r.stdout[r.stdout.index("{"):])
errs = [f for f in d["findings"] if f["severity"] in ("error", "critical")]
print(f"自扫描 ERROR+CRITICAL: {len(errs)} 个 (声称0)")
for f in errs:
    print(f'  {f["rule_id"]} line {f["line"]}: {f.get("snippet","")[:60]}')

print("\nscan.py 复杂度检查:")
src = open(PROJ_DIR + "/codeaudit/scan.py", encoding="utf-8").read()
tree = ast.parse(src)
from codeaudit.rules.performance.complexity import _complexity
for n in ast.walk(tree):
    if isinstance(n, ast.FunctionDef):
        c = _complexity(n)
        if c >= 10:
            print(f"  WARNING: {n.name} complexity={c}")
print("  (无输出 = 全部 <10)")
