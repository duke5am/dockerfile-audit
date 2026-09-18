"""dockerfile-audit - a static Dockerfile auditor that needs no Docker daemon.

The public surface is intentionally tiny::

    from dockerfile_audit import parse_text, audit, Finding

    findings = audit(parse_text("FROM ubuntu:latest\\nRUN echo hi\\n"))

Everything the CLI reports is reachable from these three names, which makes the
tool usable as a pre-commit hook or a library in a CI script.
"""

from __future__ import annotations

from typing import List, Optional, Sequence

from .parser import (
    Dockerfile,
    Instruction,
    ParseError,
    Stage,
    image_repo_tag,
    is_builder_image,
    is_shell_less_image,
    parse,
    parse_file,
)
from .rules import RULE_SUMMARY, SEVERITY_ORDER, Finding, audit, severity_at_least

__version__ = "1.0.0"
__author__ = "duke5am"
__license__ = "MIT"

__all__ = [
    "__version__",
    "Dockerfile",
    "Finding",
    "Instruction",
    "ParseError",
    "RULE_SUMMARY",
    "SEVERITY_ORDER",
    "Stage",
    "audit",
    "audit_text",
    "image_repo_tag",
    "is_builder_image",
    "is_shell_less_image",
    "parse",
    "parse_file",
    "parse_text",
    "severity_at_least",
]


def parse_text(text: str, path: str = "<memory>", context_dir: str = ".") -> Dockerfile:
    """Parse Dockerfile *text* (thin alias for :func:`dockerfile_audit.parser.parse`)."""
    return parse(text, path=path, context_dir=context_dir)


def audit_text(
    text: str,
    path: str = "<memory>",
    context_dir: str = ".",
    minimum_severity: Optional[str] = None,
) -> List[Finding]:
    """Parse and audit Dockerfile *text* in one call.

    *minimum_severity* filters the result the same way ``--severity`` does.
    """
    df = parse(text, path=path, context_dir=context_dir)
    findings = audit(df)
    if minimum_severity:
        findings = [f for f in findings if severity_at_least(f.severity, minimum_severity)]
    return findings
