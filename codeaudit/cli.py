"""Command-line interface for CodeAudit."""

from pathlib import Path

import click

from codeaudit.output.json_output import dump_json
from codeaudit.output.markdown_output import dump_markdown
from codeaudit.scan import scan


@click.group()
@click.version_option("0.1.0")
def main():
    """CodeAudit — AI-powered code audit for Python projects."""


@main.command()
@click.argument("paths", nargs=-1, type=click.Path(exists=True))
@click.option("--output", "-o", type=click.Choice(["json", "markdown"]), default="markdown")
@click.option("--lang", type=click.Choice(["en", "zh"]), default="en")
@click.option("--ai", is_flag=True, help="Use AI to verify findings (experimental)")
def scan_cmd(paths, output, lang, ai):
    """Scan Python files for code issues."""
    if not paths:
        paths = ["."]
    click.echo(f"Scanning {len(paths)} path(s)...")
    findings = scan([Path(p) for p in paths], lang=lang)

    if not findings:
        click.echo("No issues found. Good job!")
        return

    if output == "json":
        click.echo(dump_json(findings, lang=lang))
    else:
        click.echo(dump_markdown(findings, lang=lang))


@main.command()
def rules():
    """List all registered audit rules."""
    from codeaudit.rules.base import all_rules

    for cls in all_rules():
        r = cls()
        click.echo(f"  {r.id:6s}  {r.severity.value:8s}  {r.name}")


if __name__ == "__main__":
    main()
