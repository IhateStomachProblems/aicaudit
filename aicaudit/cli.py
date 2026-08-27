"""Command-line interface for AICAudit."""

from pathlib import Path

import click

from aicaudit.config import find_project_root, merge_config
from aicaudit.output.json_output import dump_json
from aicaudit.output.markdown_output import dump_markdown
from aicaudit.output.sarif_output import dump_sarif
from aicaudit.scan import _import_all_rules, scan


@click.group()
@click.version_option("0.1.0")
def main():
    """AICAudit — AI-powered code audit for Python projects."""


@main.command()
@click.option("--host", default="127.0.0.1", help="Host to bind")
@click.option("--port", default=8080, help="Port to bind")
@click.option("--reload", is_flag=True, help="Auto-reload on changes")
def web(host, port, reload):
    """Start AICAudit Web UI."""
    from aicaudit.web.server import run_server
    run_server(host=host, port=port, reload=reload)



@main.command()
@click.argument("paths", nargs=-1, type=click.Path(exists=True))
@click.option("--output", "-o", type=click.Choice(["json", "markdown", "sarif"]), default="markdown",
              help="Output format: json, markdown, or sarif")
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
    elif output == "sarif":
        click.echo(dump_sarif(findings, lang=lang))
    else:
        click.echo(dump_markdown(findings, lang=lang))

    # AI mode: verify findings, then show fix preview
    if ai:
        from aicaudit.fix import fix_file
        seen = set()
        for f in findings:
            if f.file in seen or not f.fix:
                continue
            seen.add(f.file)
            p = Path(f.file)
            if p.exists():
                result = fix_file(str(p), [f], dry_run=True, backup=False)
                if result.after and result.after != result.before:
                    _print_fix_diff(result)
        click.echo("")
        click.echo("Run with --apply-fix to actually apply fixes.")


@main.command()
def rules():
    """List all registered audit rules."""
    _import_all_rules()
    from aicaudit.rules.base import all_rules
    for cls in all_rules():
        r = cls()
        click.echo(f"  {r.id:6s}  {r.severity.value:8s}  {r.name}")


if __name__ == "__main__":
    main()


def _print_fix_diff(result):
    """Print a unified diff for a proposed fix."""
    import difflib
    if result.before == result.after:
        return
    diff = difflib.unified_diff(
        result.before.splitlines(keepends=True),
        result.after.splitlines(keepends=True),
        fromfile=result.path, tofile=result.path + " (fixed)", n=2,
    )
    print("".join(diff))


@main.command()
@click.argument("paths", nargs=-1, type=click.Path(exists=True))
@click.option("--lang", type=click.Choice(["en", "zh"]), default="en")
@click.option("--no-ai", is_flag=True, help="Disable AI deep-audit")
@click.option("--output", "-o", type=click.Choice(["json", "markdown"]), default="markdown")
def audit_cmd(paths, lang, no_ai, output):
    """AI deep audit: static + graph + AI verdict with evidence chains."""
    if not paths:
        paths = ["."]
    from aicaudit.audit import run_audit
    report = run_audit(paths, lang=lang, use_ai=not no_ai)
    import json
    if output == "json":
        click.echo(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        click.echo(_format_audit_markdown(report, lang))


def _format_audit_markdown(report, lang):
    lines = ['# AICAudit Deep Audit', '']
    scan = report['scan']
    ai = report['ai']
    lines.append('**Scan**: {} findings / {} files / {}s'.format(scan['findings'], scan['files'], scan['duration_s']))
    lines.append('**Evidence chains**: {} paths traced'.format(scan['evidence_chains_traced']))
    lines.append('**AI**: provider={} confirmed {}/{}'.format(ai['provider'], ai['confirmed'], ai['total']))
    lines.append('')
    for issue in report['issues']:
        lines.append('### {}: {}'.format(issue['rule_id'], issue['message']))
        mark = '' + issue['file'] + ':' + str(issue['line']) + ''
        lines.append('- **File**: ' + mark)
        lines.append('- **Static severity**: ' + issue['static_severity'])
        if issue.get('entry_point'):
            lines.append('- **Entry point**: ' + issue['entry_point'])
        if issue.get('evidence_chain'):
            ps = ' -> '.join(f'{fp}:{ln}({fn})' for fp, ln, fn in issue['evidence_chain'])
            lines.append('- **Evidence chain**: ' + ps)
        ai_issue = issue.get('ai') or {}
        if ai_issue.get('confirmed') is not None:
            verdict = 'confirmed' if ai_issue['confirmed'] else 'false positive'
            lines.append('- **AI verdict**: ' + verdict)
            if ai_issue.get('reason'):
                lines.append('- **AI reason**: ' + ai_issue['reason'])
            if ai_issue.get('suggested_fix'):
                lines.append('- **Suggested fix**: ' + ai_issue['suggested_fix'])
        lines.append('')
    return chr(10).join(lines)
