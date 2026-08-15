"""Command-line interface for CodeAudit."""

from pathlib import Path

import click

from codeaudit.config import find_project_root, merge_config
from codeaudit.output.json_output import dump_json
from codeaudit.output.markdown_output import dump_markdown
from codeaudit.scan import _import_all_rules, scan


@click.group()
@click.version_option("0.1.0")
def main():
    """CodeAudit — AI-powered code audit for Python projects."""


@main.command()
@click.argument("paths", nargs=-1, type=click.Path(exists=True))
@click.option("--output", "-o", type=click.Choice(["json", "markdown"]), default="markdown",
              help="Output format: json or markdown")
@click.option("--lang", type=click.Choice(["en", "zh"]), default="en",
              help="Output language: en or zh")
@click.option("--ai", is_flag=True, help="Use AI to verify findings (experimental)")
@click.option("--rules", default=None,
              help="Comma-separated rule IDs to run, e.g. --rules S001,Q001")
@click.option("--min-severity", type=click.Choice(["info", "warning", "error", "critical"]),
              default=None, help="Minimum severity to report")
def scan_cmd(paths, output, lang, ai, rules, min_severity):
    """Scan Python files for code issues."""
    if not paths:
        paths = ["."]

    start = Path(paths[0])
    # Load config (file + CLI overrides)
    cfg = merge_config(rules, min_severity, start)

    click.echo(f"Scanning {len(paths)} path(s)...")
    findings = scan(
        [Path(p) for p in paths],
        lang=lang,
        rules=cfg.rules or None,
        min_severity=cfg.min_severity,
        ignore_patterns=cfg.ignore_patterns,
        base_root=find_project_root(start),
        ai_verify=ai,
    )

    if not findings:
        click.echo("No issues found.")
        return

    if output == "json":
        click.echo(dump_json(findings, lang=lang))
    else:
        click.echo(dump_markdown(findings, lang=lang))

    # Apply fixes if --fix is set
    if ai:  # reuse --ai as --fix for now (simplify CLI)
        from codeaudit.fix import apply_fixes
        source_files = {}
        for f in findings:
            if f.file not in source_files:
                p = Path(f.file)
                if p.exists():
                    source_files[f.file] = p.read_text(encoding="utf-8-sig", errors="replace")
        apply_fixes(findings, source_files, dry_run=True, backup=False)


@main.command()
def rules():
    """List all registered audit rules."""
    _import_all_rules()
    from codeaudit.rules.base import all_rules
    for cls in all_rules():
        r = cls()
        click.echo(f"  {r.id:6s}  {r.severity.value:8s}  {r.name}")


if __name__ == "__main__":
    main()
