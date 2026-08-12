from click.testing import CliRunner
from codeaudit.cli import main
r = CliRunner().invoke(main, ["scan", r"C:\Users\17390\Desktop\开源git项目\codeaudit\codeaudit"])
print(r.output)
