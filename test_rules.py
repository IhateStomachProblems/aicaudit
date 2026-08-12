from click.testing import CliRunner
from codeaudit.cli import main
r = CliRunner().invoke(main, ["rules"])
print(r.output)
