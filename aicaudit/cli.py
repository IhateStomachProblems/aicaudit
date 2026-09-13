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
@click.option("--ai", is_flag=True, help="Attach AI verdicts to findings (marks, never hides)")
@click.option("--ai-strict", is_flag=True,
              help="With --ai: keep only AI-confirmed findings (can suppress true positives)")
@click.option("--rules", default=None,
              help="Comma-separated rule IDs to run, e.g. --rules S001,Q001")
@click.option("--min-severity", type=click.Choice(["info", "warning", "error", "critical"]),
              default=None, help="Minimum severity to report")
@click.option("--fail-on", "fail_on", type=click.Choice(["info", "warning", "error", "critical"]),
              default=None,
              help="CI gate: exit 1 when any finding is at or above this severity "
                   "(exit 0 = clean, 1 = threshold exceeded, 2 = usage error)")
def scan_cmd(paths, output, lang, ai, ai_strict, rules, min_severity, fail_on):
    """Scan Python files for code issues."""
    if not paths:
        paths = ["."]

    start = Path(paths[0])
    # Load config (file + CLI overrides)
    cfg = merge_config(rules, min_severity, start)

    click.echo(f"Scanning {len(paths)} path(s)...", err=True)
    findings = scan(
        [Path(p) for p in paths],
        lang=lang,
        rules=cfg.rules or None,
        min_severity=cfg.min_severity,
        ignore_patterns=cfg.ignore_patterns,
        base_root=find_project_root(start),
        ai_verify=ai,
    )

    if ai and ai_strict:
        before = len(findings)
        findings = [f for f in findings if (f.ai or {}).get("ai_status") == "confirmed"]
        click.echo(f"--ai-strict: {before} findings -> {len(findings)} AI-confirmed", err=True)

    if not findings:
        click.echo("No issues found.", err=True)
        _exit_code(findings, fail_on)
        return

    if output == "json":
        click.echo(dump_json(findings, lang=lang))
    elif output == "sarif":
        click.echo(dump_sarif(findings, lang=lang))
    else:
        click.echo(dump_markdown(findings, lang=lang))

    # AI mode: show fix previews (dry-run only)
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
        click.echo("", err=True)
        click.echo("Fix previews above are dry-run only; nothing was written.", err=True)

    _exit_code(findings, fail_on)


def _exit_code(findings, fail_on):
    """CI gate: exit 1 when findings reach the threshold (click ctx.exit)."""
    if not fail_on:
        return
    rank = {"info": 0, "warning": 1, "error": 2, "critical": 3}
    threshold = rank[fail_on]
    exceeded = [f for f in findings if rank.get(f.severity.value, 0) >= threshold]
    if exceeded:
        click.echo(f"fail-on {fail_on}: {len(exceeded)} finding(s) at or above threshold", err=True)
        click.get_current_context().exit(1)


@main.command()
def rules():
    """List all registered audit rules."""
    _import_all_rules()
    from aicaudit.rules.base import all_rules
    for cls in all_rules():
        r = cls()
        click.echo(f"  {r.id:6s}  {r.severity.value:8s}  {r.name}")


@main.command()
@click.option("--min-severity", type=click.Choice(["info", "warning", "error", "critical"]),
              default=None, help="Minimum severity to report (skip the prompt)")
@click.option("--ignore", default=None,
              help="Comma-separated glob patterns to ignore (skip the prompt)")
@click.option("--yes", "-y", is_flag=True, help="Accept defaults without prompting")
def init_cmd(min_severity, ignore, yes):
    """Create or update the [tool.aicaudit] section in pyproject.toml."""
    root = find_project_root(Path.cwd())
    pyproject = root / "pyproject.toml"

    default_sev = "warning"
    if min_severity:
        sev = min_severity
    elif yes:
        sev = default_sev
    else:
        sev = click.prompt("Minimum severity to report", default=default_sev,
                           type=click.Choice(["info", "warning", "error", "critical"]))

    if ignore is not None:
        ignores = [p.strip() for p in ignore.split(",") if p.strip()]
    elif yes:
        ignores = []
    else:
        raw = click.prompt("Ignore patterns (comma-separated globs, empty for none)", default="")
        ignores = [p.strip() for p in raw.split(",") if p.strip()]

    section = _render_aicaudit_section(sev, ignores)

    if pyproject.exists():
        text = pyproject.read_text(encoding="utf-8")
        if "[tool.aicaudit]" in text:
            text = _replace_section(text, section)
            action = "updated"
        else:
            text = text.rstrip("\n") + "\n\n" + section
            action = "updated"
    else:
        text = section
        action = "created"
    pyproject.write_text(text, encoding="utf-8")

    click.echo(f"{action}: {pyproject}")
    click.echo(section.rstrip())
    click.echo("Custom rules: drop .py rule files into .aicaudit/rules/ "
               "or set rule-dirs in the section above.", err=True)


def _render_aicaudit_section(min_severity, ignores):
    lines = ["[tool.aicaudit]", f'min-severity = "{min_severity}"']
    if ignores:
        joined = ", ".join(f'"{g}"' for g in ignores)
        lines.append(f"ignore = [{joined}]")
    lines.append('# rule-dirs = ["custom_rules"]   # extra dirs with Python rule files')
    return "\n".join(lines) + "\n"


def _replace_section(text, new_section):
    """Replace an existing [tool.aicaudit] section (until the next [section])."""
    import re
    pattern = re.compile(r"\[tool\.aicaudit\][^\[]*", re.DOTALL)
    if pattern.search(text):
        return pattern.sub(new_section, text, count=1)
    return text.rstrip("\n") + "\n\n" + new_section


if __name__ == "__main__":
    main()


def _print_fix_diff(result):
    """Print a unified diff for a proposed fix."""
    import difflib
    import sys
    if result.before == result.after:
        return
    diff = difflib.unified_diff(
        result.before.splitlines(keepends=True),
        result.after.splitlines(keepends=True),
        fromfile=result.path, tofile=result.path + " (fixed)", n=2,
    )
    print("".join(diff), file=sys.stderr)


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
