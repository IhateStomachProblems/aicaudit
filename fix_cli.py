import os
proj_dir = r"C:\Users\17390\Desktop\开源git项目\codeaudit"

content = (
    '"""Command-line interface for CodeAudit."""\n\n'
    'from pathlib import Path\n'
    'import click\n'
    'from codeaudit.scan import scan, _import_all_rules\n'
    'from codeaudit.output.json_output import dump_json\n'
    'from codeaudit.output.markdown_output import dump_markdown\n\n\n'
    '@click.group()\n'
    '@click.version_option("0.1.0")\n'
    'def main():\n'
    '    """CodeAudit — AI-powered code audit for Python projects."""\n\n\n'
    '@main.command()\n'
    '@click.argument("paths", nargs=-1, type=click.Path(exists=True))\n'
    '@click.option("--output", "-o", type=click.Choice(["json", "markdown"]), default="markdown")\n'
    '@click.option("--lang", type=click.Choice(["en", "zh"]), default="en")\n'
    '@click.option("--ai", is_flag=True, help="Use AI to verify findings (experimental)")\n'
    "def scan_cmd(paths, output, lang, ai):\n"
    '    """Scan Python files for code issues."""\n'
    "    if not paths:\n"
    '        paths = ["."]\n'
    "    click.echo(f\"Scanning {len(paths)} path(s)...\")\n"
    "    findings = scan([Path(p) for p in paths], lang=lang)\n"
    "    if not findings:\n"
    '        click.echo("No issues found. Good job!")\n'
    "        return\n"
    "    if output == \"json\":\n"
    "        click.echo(dump_json(findings, lang=lang))\n"
    "    else:\n"
    "        click.echo(dump_markdown(findings, lang=lang))\n\n\n"
    "@main.command()\n"
    "def rules():\n"
    '    """List all registered audit rules."""\n'
    "    _import_all_rules()\n"
    "    from codeaudit.rules.base import all_rules\n"
    "    for cls in all_rules():\n"
    "        r = cls()\n"
    '        click.echo(f"  {r.id:6s}  {r.severity.value:8s}  {r.name}")\n\n\n'
    'if __name__ == "__main__":\n'
    "    main()\n"
)

path = os.path.join(proj_dir, "codeaudit", "cli.py")
with open(path, "w", encoding="utf-8") as f:
    f.write(content)
print("cli.py written OK")
