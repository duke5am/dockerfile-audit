"""Command-line interface for dockerfile-audit.

Exit codes (documented in the README as well)::

    0   no findings at or above the requested severity threshold
    1   at least one finding at or above the threshold
    2   usage error, unreadable path, or a file that is not a Dockerfile
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Dict, List, Optional, Sequence, Tuple

from . import __version__
from .parser import Dockerfile, ParseError, parse_file
from .rules import RULE_SUMMARY, SEVERITY_ORDER, Finding, audit, dedupe, severity_at_least

__all__ = ["main", "build_parser", "discover", "is_dockerfile_name", "format_report"]

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2

_COLORS = {
    "high": "\033[1;31m",
    "medium": "\033[1;33m",
    "low": "\033[1;36m",
    "reset": "\033[0m",
    "dim": "\033[2m",
}


def is_dockerfile_name(name: str) -> bool:
    """True when *name* looks like a Dockerfile.

    Matches ``Dockerfile``, ``Dockerfile.prod``, ``api.Dockerfile`` (and the
    lower-case variants), but not ``Dockerfile.md`` notes or ``foo.Dockerfile.bak``
    style backups?  Backups are matched on purpose: a stale Dockerfile in the
    tree is worth auditing.  Notes are not.
    """
    lower = name.lower()
    if lower in ("dockerfile", "containerfile"):
        return True
    if lower.startswith("dockerfile.") and not lower.endswith((".md", ".txt", ".rst")):
        return True
    if lower.endswith(".dockerfile"):
        return True
    return False


def discover(paths: Sequence[str]) -> Tuple[List[str], List[str]]:
    """Expand *paths* into a sorted list of Dockerfiles plus unreadable paths.

    Directories are walked recursively; files are taken as given even when their
    name does not look like a Dockerfile, because an explicit path is a
    deliberate request.
    """
    found: List[str] = []
    errors: List[str] = []
    seen = set()

    def add(p: str) -> None:
        real = os.path.abspath(p)
        if real not in seen:
            seen.add(real)
            found.append(p)

    for raw in paths:
        if not os.path.exists(raw):
            errors.append(f"{raw}: no such file or directory")
            continue
        if os.path.isdir(raw):
            hits: List[str] = []
            for dirpath, dirnames, filenames in os.walk(raw):
                dirnames[:] = sorted(
                    d for d in dirnames if d not in (".git", "node_modules", ".venv", "__pycache__")
                )
                for name in sorted(filenames):
                    if is_dockerfile_name(name):
                        hits.append(os.path.join(dirpath, name))
            if not hits:
                errors.append(f"{raw}: no Dockerfile found (looked for Dockerfile, *.Dockerfile, Dockerfile.*)")
            for hit in sorted(hits):
                add(hit)
        else:
            add(raw)
    return found, errors


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="dockerfile-audit",
        description=(
            "Static Dockerfile auditor: finds root users, baked-in secrets, floating base "
            "tags, apt/toolchain bloat, cache-busting layer order and fatal RUNs in "
            "scratch stages. No Docker daemon required."
        ),
        epilog=(
            "exit codes: 0 = clean, 1 = findings at or above --severity, 2 = usage/parse error.\n"
            "example: dockerfile-audit . --severity high --json"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("paths", nargs="*", metavar="PATH", help="Dockerfile(s) or directories to scan")
    p.add_argument(
        "--severity",
        choices=("high", "medium", "low"),
        default="low",
        help="minimum severity to report (default: low)",
    )
    p.add_argument("--json", action="store_true", help="emit machine-readable JSON instead of text")
    p.add_argument("--quiet", action="store_true", help="suppress output; use the exit code only")
    p.add_argument("--list-rules", action="store_true", help="print the rule catalogue and exit")
    p.add_argument("--version", action="version", version=f"dockerfile-audit {__version__}")
    return p


def _relative(path: str) -> str:
    try:
        rel = os.path.relpath(path, os.getcwd())
    except ValueError:  # different drive on exotic platforms
        return path
    return path if rel.startswith("..") else rel


def format_report(
    results: Sequence[Tuple[Dockerfile, List[Finding]]],
    errors: Sequence[str],
    threshold: str,
    color: bool = True,
) -> str:
    """Render the human-readable report."""
    def c(kind: str, text: str) -> str:
        return f"{_COLORS[kind]}{text}{_COLORS['reset']}" if color else text

    lines: List[str] = []
    counts = {"high": 0, "medium": 0, "low": 0}
    total = 0

    for df, findings in results:
        path = df.path
        shown = _relative(path)
        if not findings:
            lines.append(f"{c('dim', 'ok')}   {shown} - no findings at or above '{threshold}'")
            continue
        lines.append(shown)
        for f in findings:
            counts[f.severity] += 1
            total += 1
            tag = c(f.severity, f.severity.upper().ljust(6))
            loc = f"{f.path or path}:{f.line}" if f.rule_id == "DF010" else f"line {f.line}"
            lines.append(f"  {tag} {f.rule_id}  {loc}  {f.message}")
            if f.detail:
                for chunk in _wrap(f.detail, 96):
                    lines.append(f"           {c('dim', chunk)}")
            if f.fix:
                lines.append("           fix:")
                for chunk in f.fix.splitlines():
                    lines.append(f"             {chunk}")
            lines.append("")
        if lines and lines[-1] == "":
            lines.pop()
        lines.append("")

    summary = (
        f"{total} finding{'s' if total != 1 else ''} "
        f"({counts['high']} high, {counts['medium']} medium, {counts['low']} low) "
        f"across {len(results)} Dockerfile{'s' if len(results) != 1 else ''}; "
        f"threshold '{threshold}'"
    )
    lines.append(summary)
    return "\n".join(lines)


def _wrap(text: str, width: int) -> List[str]:
    words = text.split()
    out: List[str] = []
    cur = ""
    for w in words:
        if cur and len(cur) + 1 + len(w) > width:
            out.append(cur)
            cur = w
        else:
            cur = f"{cur} {w}".strip()
    if cur:
        out.append(cur)
    return out or [""]


#: Options that consume a value; used by :func:`_split_double_dash`.
_VALUE_OPTIONS = ("--severity",)
_FLAG_OPTIONS = ("-h", "--help", "--json", "--quiet", "--list-rules", "--version")


def _split_double_dash(argv: Sequence[str]) -> Tuple[List[str], List[str], bool]:
    """Handle a POSIX ``--`` separator before argparse gets a chance to.

    argparse treats ``--`` specially with ``nargs='*'`` positionals: it will not
    consume it, and then reports everything after it as unrecognised arguments.
    So the separator is split out here.  The same pass keeps a path that does
    not exist on disk (a typo, or a path that starts with ``-``) out of the
    option list, where argparse would otherwise call it an unknown flag.

    Returns ``(option_tokens, path_tokens, had_separator)``.
    """
    tokens = list(argv)
    options: List[str] = []
    paths: List[str] = []
    pos = 0
    while pos < len(tokens):
        tok = tokens[pos]
        if tok == "--":
            paths.extend(tokens[pos + 1 :])
            return options, paths, True
        if tok in _VALUE_OPTIONS:
            options.append(tok)
            if pos + 1 < len(tokens):
                options.append(tokens[pos + 1])
                pos += 2
                continue
            pos += 1
            continue
        if tok in _FLAG_OPTIONS or (tok.startswith("--") and "=" in tok):
            options.append(tok)
            pos += 1
            continue
        if tok.startswith("-") and not os.path.exists(tok):
            options.append(tok)  # an option, or a typo argparse should report
            pos += 1
            continue
        paths.append(tok)
        pos += 1
    return options, paths, False


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    raw = list(sys.argv[1:] if argv is None else argv)
    option_tokens, path_tokens, had_separator = _split_double_dash(raw)
    args = parser.parse_args(option_tokens)
    if had_separator or path_tokens:
        args.paths = list(args.paths) + path_tokens

    if args.list_rules:
        width = max(len(r) for r, _, _ in RULE_SUMMARY)
        for rule_id, severity, desc in RULE_SUMMARY:
            print(f"{rule_id:<{width}}  {severity:<6}  {desc}")
        return EXIT_CLEAN

    if not args.paths:
        parser.print_usage(sys.stderr)
        print("dockerfile-audit: error: give me at least one Dockerfile or directory", file=sys.stderr)
        return EXIT_USAGE

    color = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None

    files, errors = discover(args.paths)
    parsed: List[Tuple[Dockerfile, List[Finding]]] = []
    for path in files:
        try:
            df = parse_file(path)
        except ParseError as exc:
            errors.append(str(exc))
            continue
        parsed.append((df, []))

    results: List[Tuple[Dockerfile, List[Finding]]] = []
    corpus = [d for d, _ in parsed]
    for df, _ in parsed:
        # dedupe() stops a shared build context (.dockerignore rule) from being
        # reported inside more than one Dockerfile's section.
        findings = dedupe(
            [f for f in audit(df, corpus) if severity_at_least(f.severity, args.severity)]
        )
        results.append((df, findings))

    total = sum(len(f) for _, f in results)

    # Errors always go to stderr, in every output mode, so that a JSON consumer
    # still gets a parseable document on stdout and a human still sees why.
    for err in errors:
        print(f"dockerfile-audit: error: {err}", file=sys.stderr)

    if args.json:
        payload: Dict[str, object] = {
            "tool": "dockerfile-audit",
            "version": __version__,
            "threshold": args.severity,
            "summary": {
                "files": len(results),
                "findings": total,
                "errors": len(errors),
                "by_severity": {
                    sev: sum(1 for _, fs in results for f in fs if f.severity == sev)
                    for sev in ("high", "medium", "low")
                },
            },
            "results": [
                {
                    "path": os.path.abspath(df.path),
                    "context": os.path.abspath(df.context_dir),
                    "findings": [f.as_dict() for f in findings],
                }
                for df, findings in results
            ],
            "errors": errors,
        }
        if not args.quiet:
            print(json.dumps(payload, indent=2, sort_keys=False))
    elif not args.quiet:
        print(format_report(results, errors, args.severity, color=color))

    if errors:
        return EXIT_USAGE
    if total > 0:
        return EXIT_FINDINGS
    return EXIT_CLEAN


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
