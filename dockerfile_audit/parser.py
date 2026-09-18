"""Static Dockerfile parser.

This module turns Dockerfile *text* into a small, queryable structure.  It never
contacts a Docker daemon, never pulls an image and never executes anything: the
whole audit is a text analysis, which is exactly what makes it usable on a
machine with no container runtime at all.

The parser understands the parts of the Dockerfile grammar that the audit rules
need:

* comments (whole-line and trailing) and blank lines
* line continuations using the default ``\\`` escape character, or a custom
  escape character declared with ``# escape=``
* the ``# syntax=`` directive
* JSON / exec-form arguments (``RUN ["a", "b"]``) which are flattened to a
  shell-like string for command analysis
* heredocs (``RUN <<EOF ... EOF``) whose bodies are attached to the instruction
  that opened them and removed from the instruction stream
* stage splitting on ``FROM``, including ``AS <name>``, ``FROM <stage>`` reuse,
  the reserved ``scratch`` base and digest-pinned references

Nothing here is Docker-version specific beyond that: unknown instructions are
kept verbatim so rules can still scan them.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Iterable, List, Optional, Sequence, Tuple

__all__ = [
    "Instruction",
    "Stage",
    "Dockerfile",
    "ParseError",
    "parse",
    "parse_file",
    "split_env",
    "split_arg",
    "shell_tokens",
    "image_repo_tag",
    "is_shell_less_image",
    "is_builder_image",
    "BUILD_TOOL_PACKAGES",
]

#: Severity ranking, lowest first.  Shared by the rules and the CLI.
SEVERITIES: Tuple[str, ...] = ("low", "medium", "high")


class ParseError(Exception):
    """Raised when a file cannot be read or is not a Dockerfile at all."""


# ---------------------------------------------------------------------------
# data model
# ---------------------------------------------------------------------------


@dataclass
class Instruction:
    """One logical Dockerfile instruction (continuations already folded)."""

    cmd: str
    """Upper-cased instruction keyword, e.g. ``RUN`` or ``FROM``."""

    arg: str
    """Raw argument text with line continuations folded into single lines."""

    line: int
    """1-based line number of the first physical line of the instruction."""

    raw: str = ""
    """The logical line exactly as written (continuations still expanded)."""

    heredocs: List[str] = field(default_factory=list)
    """Heredoc bodies opened by this instruction, in order of appearance."""

    index: int = -1
    """Position of the instruction in :attr:`Dockerfile.instructions`."""

    @property
    def tokens(self) -> List[str]:
        """Shell-ish tokens of the argument text (see :func:`shell_tokens`)."""
        return shell_tokens(self.arg)

    @property
    def first_token(self) -> str:
        """First token of the argument text, or ``""`` when there is none."""
        toks = self.tokens
        return toks[0] if toks else ""

    def mentions(self, needle: str) -> bool:
        """True when *needle* occurs anywhere in the raw argument text."""
        return needle in self.arg


@dataclass
class Stage:
    """A build stage: one ``FROM`` plus every instruction that follows it."""

    index: int
    """0-based position of the stage in the Dockerfile."""

    base: str
    """Raw base image reference as written (may be a previous stage name)."""

    name: Optional[str]
    """Stage name from ``AS <name>``, or ``None``."""

    line: int
    """Line number of the ``FROM`` instruction."""

    from_instruction: Instruction
    instructions: List[Instruction] = field(default_factory=list)

    @property
    def repo(self) -> str:
        """Image repository without tag or digest (``""`` for a stage ref)."""
        return image_repo_tag(self.base)[0]

    @property
    def tag(self) -> Optional[str]:
        """Explicit tag, ``None`` when the reference carries no tag."""
        return image_repo_tag(self.base)[1]

    @property
    def digest(self) -> Optional[str]:
        """Digest when the reference is pinned as ``repo@sha256:...``."""
        return image_repo_tag(self.base)[2]

    @property
    def is_scratch(self) -> bool:
        return self.base.strip().lower() in ("scratch", "scratch:")

    @property
    def is_shell_less(self) -> bool:
        """True for ``scratch`` and for distroless-style images (no shell)."""
        return is_shell_less_image(self.base)

    def runs(self) -> List[Instruction]:
        """Every ``RUN`` instruction in this stage, in order."""
        return [i for i in self.instructions if i.cmd == "RUN"]

    def of(self, cmd: str) -> List[Instruction]:
        """Every instruction whose keyword equals *cmd* (upper-case)."""
        cmd = cmd.upper()
        return [i for i in self.instructions if i.cmd == cmd]

    def users(self) -> List[Instruction]:
        return self.of("USER")

    def effective_user(self) -> Optional[str]:
        """Last ``USER`` in the stage, or ``None`` when the stage never sets one."""
        users = self.users()
        return users[-1].arg.strip() if users else None

    def joined_run_text(self) -> str:
        """All ``RUN`` text of the stage joined with ``&&``.

        Rules that reason about *build state* (did we clean the apt lists
        somewhere in this stage?) use this rather than a single instruction.
        """
        return " && ".join(r.arg for r in self.runs())


@dataclass
class Dockerfile:
    """A parsed Dockerfile."""

    path: str
    instructions: List[Instruction]
    stages: List[Stage]
    syntax: Optional[str] = None
    escape: str = "\\"
    context_dir: str = "."
    """Directory used to resolve build-context files such as ``.dockerignore``."""

    def instructions_of(self, cmd: str) -> List[Instruction]:
        cmd = cmd.upper()
        return [i for i in self.instructions if i.cmd == cmd]

    @property
    def final_stage(self) -> Optional[Stage]:
        """The stage that produces the image (the last ``FROM`` wins)."""
        return self.stages[-1] if self.stages else None

    def has(self, cmd: str) -> bool:
        return bool(self.instructions_of(cmd))

    @property
    def stage_names(self) -> set:
        """Names declared with ``FROM ... AS <name>``."""
        return {s.name for s in self.stages if s.name}

    def is_stage_reference(self, ref: str) -> bool:
        """True when *ref* names an earlier stage rather than an image.

        ``FROM builder`` and ``FROM build AS test`` reuse a previous stage; such
        a reference carries no tag and must never be reported as a floating tag.
        """
        text = (ref or "").strip()
        if not text or text.lower() == "scratch":
            return False
        if text in self.stage_names:
            return True
        # A bare identifier that matches no declared stage is ambiguous: Docker
        # would treat it as an image name and fail to find it, so it is left to
        # the tag rule rather than guessed at here.
        return False

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<Dockerfile {self.path!r} stages={len(self.stages)}>"


# ---------------------------------------------------------------------------
# tokenising helpers
# ---------------------------------------------------------------------------

#: mawk/sh-style separators: anything in here ends a shell command.
_SEPARATORS = set(";&|(){}<>`\n\r\t")


def _first_shell_position(text: str, needle: str) -> int:
    """Index of *needle* standing on a command boundary, or ``-1``.

    ``apt-get install`` must not match ``myapt-get install``; a boundary means
    the character before *needle* is a separator, a quote or nothing at all.
    """
    start = 0
    while True:
        pos = text.find(needle, start)
        if pos < 0:
            return -1
        if pos == 0 or text[pos - 1] in _SEPARATORS or text[pos - 1] in "\"'":
            return pos
        start = pos + 1


def shell_tokens(text: str) -> List[str]:
    """Split *text* into shell-ish tokens.

    Quotes are honoured, ``&&``/``||``/``;``/``|`` become their own tokens, and
    every other punctuation glues to its neighbours (so ``curl|sh`` still
    yields a ``|`` token while ``--flag=value`` stays intact).
    """
    tokens: List[str] = []
    cur: List[str] = []
    quote: Optional[str] = None

    def flush() -> None:
        if cur:
            tokens.append("".join(cur))
            cur.clear()

    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if quote:
            if ch == quote:
                quote = None
            elif ch == "\\" and quote == '"' and i + 1 < n:
                i += 1
                cur.append(text[i])
            else:
                cur.append(ch)
            i += 1
            continue
        if ch in "\"'":
            quote = ch
            i += 1
            continue
        if ch in " \t\n\r":
            flush()
            i += 1
            continue
        if ch == "\\" and i + 1 < n:
            cur.append(text[i + 1])
            i += 2
            continue
        if ch == "&" and i + 1 < n and text[i + 1] == "&":
            flush()
            tokens.append("&&")
            i += 2
            continue
        if ch == "|" and i + 1 < n and text[i + 1] == "|":
            flush()
            tokens.append("||")
            i += 2
            continue
        if ch in "|;":
            flush()
            tokens.append(ch)
            i += 1
            continue
        cur.append(ch)
        i += 1
    flush()
    return tokens


def _split_words(text: str) -> List[str]:
    return shell_tokens(text)


def split_env(arg: str) -> List[Tuple[str, str]]:
    """Parse the argument of ``ENV`` into ``(key, value)`` pairs.

    Supports both syntaxes::

        ENV KEY=value OTHER=value      # multi-pair, needs '='
        ENV KEY value with spaces      # legacy single pair

    Returns an empty list for an empty argument.
    """
    text = arg.strip()
    if not text:
        return []
    toks = _split_words(text)
    if not toks:
        return []
    if "=" in toks[0]:
        pairs: List[Tuple[str, str]] = []
        for tok in toks:
            if "=" in tok:
                key, _, value = tok.partition("=")
                pairs.append((key, value))
            elif pairs:
                # A bare token following KEY=value is a continuation of the last
                # value, e.g. ENV A=1 B=2 becomes A=1, B=2 but ENV A=1 2 keeps 2
                # attached to nothing meaningful; Docker rejects it, so keep the
                # pair list as parsed and let it be a non-issue for the rules.
                continue
        return pairs
    key = toks[0]
    value = text[len(key):].strip()
    return [(key, value)]


def split_arg(arg: str) -> List[Tuple[str, Optional[str]]]:
    """Parse the argument of ``ARG`` into ``(name, default_or_None)`` pairs."""
    text = arg.strip()
    if not text:
        return []
    name, sep, default = text.partition("=")
    name = name.strip()
    if not name:
        return []
    if sep:
        return [(name, default.strip().strip('"\''))]
    return [(name, None)]


_REF_RE = re.compile(
    r"""^
    (?P<repo>[^@:]+)              # registry/repo, may contain a registry port...
    (?::(?P<tag>[^@]*))?          # ...but a ':' tag is optional
    (?:@(?P<digest>[^\s]+))?      # optional digest pin
    $""",
    re.VERBOSE,
)


def image_repo_tag(ref: str) -> Tuple[str, Optional[str], Optional[str]]:
    """Split an image reference into ``(repo, tag, digest)``.

    ``repo`` keeps any registry host and namespace; ``tag`` is ``None`` when the
    reference carries no tag (including the digest-pinned case).  A registry
    host with a port (``registry:5000/app``) is handled by treating the segment
    after the *last* colon as a tag only when it is not a namespace separator.
    """
    text = (ref or "").strip()
    if not text:
        return "", None, None
    if text.lower() == "scratch":
        return "scratch", None, None
    digest: Optional[str] = None
    if "@" in text:
        text, _, digest = text.partition("@")
    if not text:
        return "", None, digest
    # Only the part after the last '/' can carry the tag, so a registry port
    # (registry.example.com:5000/app) is never mistaken for a tag.
    head, slash, tail = text.rpartition("/")
    tag: Optional[str] = None
    if ":" in tail:
        repo_tail, _, candidate = tail.partition(":")
        tag = candidate
        text = (head + slash if slash else "") + repo_tail
    return text, tag, digest


#: Images that are *only* sensible as a build stage: they exist to compile.
_BUILDER_IMAGE_EXACT = {
    "buildpack-deps",
    "golang",
    "rust",
    "maven",
    "gradle",
    "ant",
    "sbt",
    "cargo",
    "gcc",
    "clang",
    "llvm",
    "cmake",
    "ninja",
    "meson",
    "bazel",
    "golang-alpine",
}

#: Compiler toolchain packages that have no business in a runtime image.
BUILD_TOOL_PACKAGES: Tuple[str, ...] = (
    "build-essential",
    "gcc",
    "g++",
    "make",
    "cmake",
    "ninja-build",
    "clang",
    "llvm",
    "musl-dev",
    "libc6-dev",
    "linux-headers-generic",
    "python3-dev",
    "default-libmysqlclient-dev",
    "pkg-config",
    "autoconf",
    "automake",
    "libtool",
)


def _repo_basename(repo: str) -> str:
    return repo.rpartition("/")[2].lower()


def is_builder_image(ref: str) -> bool:
    """True when *ref* is a build-only image (golang, rust, buildpack-deps...).

    Deliberately conservative: ``node``, ``python``, ``openjdk`` and friends are
    *not* builder images, because shipping their interpreter/runtime is a normal
    way to run an application.
    """
    repo, _tag, _digest = image_repo_tag(ref)
    base = _repo_basename(repo)
    if not base:
        return False
    if base in _BUILDER_IMAGE_EXACT:
        return True
    return base.startswith(("golang", "buildpack-deps", "rust"))


def is_shell_less_image(ref: str) -> bool:
    """True for ``scratch`` and for distroless images, which ship no shell.

    A ``RUN`` in a stage based on one of these is fatal at build time: Docker
    starts the instruction with ``/bin/sh -c`` and there is no ``/bin/sh``.
    """
    repo, tag, _digest = image_repo_tag(ref)
    base = _repo_basename(repo)
    if not base:
        return False
    if base == "scratch":
        return True
    if "distroless" in repo.lower():
        return True
    return base.startswith("distroless")


# ---------------------------------------------------------------------------
# the parser
# ---------------------------------------------------------------------------

_SYNTAX_RE = re.compile(r"^#\s*syntax\s*=\s*(\S+)\s*$", re.IGNORECASE)
_ESCAPE_RE = re.compile(r"^#\s*escape\s*=\s*(\S+)\s*$", re.IGNORECASE)
_HEREDOC_RE = re.compile(r"<<(?P<dash>-?)\s*(?P<q>[\"']?)(?P<mark>[A-Za-z_][A-Za-z0-9_]*)(?P=q)")


def _blank(inst: Instruction) -> bool:
    return inst.cmd == "" and not inst.arg.strip()


def _uncontinue(line: str, escape: str) -> Tuple[str, bool]:
    """Split *line* into ``(text_without_escape, continues)``.

    An odd-length run of escape characters at the end of the line continues the
    instruction; an even-length run (including none) ends it.
    """
    if not escape:
        return line, False
    char = escape[-1]
    stripped = line.rstrip()
    run = 0
    while run < len(stripped) and stripped[len(stripped) - 1 - run] == char:
        run += 1
    if run % 2 == 1:
        return stripped[: len(stripped) - 1], True
    return stripped, False


def parse(text: str, path: str = "<memory>", context_dir: str = ".") -> Dockerfile:
    """Parse Dockerfile *text* into a :class:`Dockerfile`.

    Raises :class:`ParseError` when the text contains no ``FROM`` instruction,
    because there is no build to audit in that case.
    """
    lines = (text or "").splitlines(keepends=True)
    escape = "\\"
    syntax: Optional[str] = None

    # The first two non-blank lines may hold parser directives.
    directive_slots = 0
    for raw in lines:
        stripped = raw.strip()
        if not stripped:
            if directive_slots:
                break
            continue
        if not stripped.startswith("#"):
            break
        m = _SYNTAX_RE.match(stripped)
        if m:
            syntax = m.group(1)
            directive_slots += 1
            continue
        m = _ESCAPE_RE.match(stripped)
        if m:
            escape = m.group(1)
            directive_slots += 1
            continue
        break

    instructions: List[Instruction] = []
    heredoc_queue: List[Tuple[str, bool]] = []
    pending: Optional[Instruction] = None
    i = 0
    total = len(lines)
    while i < total:
        raw = lines[i]
        lineno = i + 1
        i += 1
        line = raw.rstrip("\n").rstrip("\r")

        if heredoc_queue:
            marker, strip_tabs = heredoc_queue[0]
            probe = line.lstrip("\t") if strip_tabs else line
            if probe.strip() == marker:
                heredoc_queue.pop(0)
            else:
                if pending is not None and pending.heredocs:
                    pending.heredocs[-1].append(line)
            continue

        stripped = line.lstrip()
        if not stripped or stripped.startswith("#"):
            continue

        # Fold continuations for this instruction.
        body = line.rstrip()
        buf: List[str] = []
        start_line = lineno
        while True:
            segment, continued = _uncontinue(body, escape)
            buf.append(segment)
            if not continued or i >= total:
                break
            nxt = lines[i].rstrip("\n").rstrip("\r")
            i += 1
            if nxt.lstrip().startswith("#"):
                # Docker allows comments between continuation lines; they are
                # stripped before the instruction is handed to the builder.
                body = "\\" if escape == "\\" else escape
                continue
            body = nxt.rstrip()

        logical = " ".join(seg.strip() for seg in buf)
        word, _, arg = logical.partition(" ")
        if not arg:
            word, _, arg = logical.partition("\t")
        cmd = word.strip().upper()
        arg = arg.strip()

        if "[" in arg[:1]:
            try:
                items = json.loads(arg)
            except ValueError:
                items = None
            if isinstance(items, list):
                arg = " ".join(str(x) for x in items)

        inst = Instruction(cmd=cmd, arg=arg, line=start_line, raw=logical)
        # Heredocs opened on this logical line: their bodies follow, in the
        # order the heredoc operators appear, and must be removed from the
        # instruction stream before the next instruction is parsed.
        matches = list(_HEREDOC_RE.finditer(logical))
        if matches:
            inst.heredocs = [[] for _ in matches]
            pending = inst
            heredoc_queue = [(m.group("mark"), m.group("dash") == "-") for m in matches]
        instructions.append(inst)

    stages = _build_stages(instructions)
    if not stages:
        raise ParseError(
            f"{path}: no FROM instruction found - this does not look like a Dockerfile"
        )

    for idx, inst in enumerate(instructions):
        inst.index = idx

    return Dockerfile(
        path=path,
        instructions=instructions,
        stages=stages,
        syntax=syntax,
        escape=escape,
        context_dir=context_dir,
    )


def _build_stages(instructions: Iterable[Instruction]) -> List[Stage]:
    stages: List[Stage] = []
    current: Optional[Stage] = None
    for inst in instructions:
        if inst.cmd == "FROM":
            toks = inst.tokens
            base = toks[0] if toks else ""
            name: Optional[str] = None
            for pos, tok in enumerate(toks):
                if tok.upper() == "AS" and pos + 1 < len(toks):
                    name = toks[pos + 1]
                    break
            current = Stage(
                index=len(stages),
                base=base,
                name=name,
                line=inst.line,
                from_instruction=inst,
            )
            stages.append(current)
            continue
        if current is not None:
            current.instructions.append(inst)
    return stages


def parse_file(path: str, context_dir: Optional[str] = None) -> Dockerfile:
    """Read and parse the file at *path*.

    *context_dir* defaults to the directory holding the Dockerfile, which is
    the build context used to look for ``.dockerignore``.
    """
    import os

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError as exc:
        raise ParseError(f"{path}: cannot read file ({exc.strerror or exc})") from exc
    if context_dir is None:
        context_dir = os.path.dirname(os.path.abspath(path)) or "."
    return parse(text, path=path, context_dir=context_dir)
