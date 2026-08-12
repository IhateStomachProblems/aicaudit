import os
proj_dir = r"C:\Users\17390\Desktop\开源git项目\codeaudit"
path = os.path.join(proj_dir, "codeaudit", "scan.py")

with open(path, "r", encoding="utf-8") as f:
    content = f.read()

old = "def _import_all_rules():\n    import codeaudit.rules.security.sql_injection  # noqa: F401\n    import codeaudit.rules.security.secret_leak  # noqa: F401\n    import codeaudit.rules.security.dangerous_functions  # noqa: F401"

new = """def _import_all_rules():
    import codeaudit.rules.security.sql_injection  # noqa: F401
    import codeaudit.rules.security.secret_leak  # noqa: F401
    import codeaudit.rules.security.dangerous_functions  # noqa: F401
    import codeaudit.rules.quality.bare_except  # noqa: F401
    import codeaudit.rules.quality.magic_numbers  # noqa: F401
    import codeaudit.rules.quality.undefined_name  # noqa: F401
    import codeaudit.rules.quality.todo_comment  # noqa: F401
    import codeaudit.rules.quality.unused_variable  # noqa: F401"""

content = content.replace(old, new)

with open(path, "w", encoding="utf-8") as f:
    f.write(content)

print("scan.py updated OK")
