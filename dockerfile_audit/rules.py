"""The audit rules.

Each rule is a small function that receives one :class:`~dockerfile_audit.parser.Dockerfile`
and returns a list of :class:`Finding` objects.  Rules are pure: they only read
the parsed text, never the filesystem (the one exception is :data:`RULES`'s
``DF010``, which stats ``.dockerignore`` next to the Dockerfile and is documented
as such) and never a Docker daemon.

Severity policy -- the levels are meant to be defensible:

``high``
    Objectively broken or a direct privilege/credential exposure.  ``RUN`` in a
    ``scratch`` stage cannot build.  An image with no ``USER`` runs as uid 0.
    A credential baked into an ``ENV`` of the shipped stage is readable by
    anyone who can pull the image.

``medium``
    A real security or reproducibility defect with a context-dependent impact,
    or a definite build-hygiene problem: floating base tags, build args holding
    secrets, a compiler toolchain shipped to runtime, apt cache left in a layer,
    a cache-busting ``COPY . .``, a build context that ships ``.git``.

``low``
    Advice that reduces attack surface or improves practice but is not wrong in
    every context: no ``HEALTHCHECK``, ``ADD`` where ``COPY`` would do,
    ``curl | sh`` (common in official docs), unpinned package versions.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from .parser import (
    BUILD_TOOL_PACKAGES,
    Dockerfile,
    Instruction,
    image_repo_tag,
    is_builder_image,
    shell_tokens,
    split_arg,
    split_env,
)

__all__ = ["Finding", "RULES", "SEVERITY_ORDER", "audit", "dedupe", "severity_at_least"]

SEVERITY_ORDER: Dict[str, int] = {"low": 0, "medium": 1, "high": 2}


@dataclass
class Finding:
    """One concrete problem found in one Dockerfile."""

    rule_id: str
    severity: str
    message: str
    line: int = 1
    fix: Optional[str] = None
    detail: Optional[str] = None
    path: Optional[str] = None

    def as_dict(self) -> Dict[str, object]:
        data: Dict[str, object] = {
            "rule": self.rule_id,
            "severity": self.severity,
            "line": self.line,
            "message": self.message,
        }
        if self.fix:
            data["fix"] = self.fix
        if self.detail:
            data["detail"] = self.detail
        return data


def severity_at_least(severity: str, minimum: str) -> bool:
    """True when *severity* is at or above the *minimum* threshold."""
    return SEVERITY_ORDER[severity] >= SEVERITY_ORDER[minimum]


# ---------------------------------------------------------------------------
# shared helpers
# ---------------------------------------------------------------------------

#: Names that look like credentials.  Matched case-insensitively as a whole word
#: with an optional separator plus a short suffix, so ``MONKEY`` does not match
#: but ``API_KEY``, ``api-key``, ``DB_PASSWORD``, ``SECRET_KEY_FILE`` do.
_SECRET_KEY_RE = re.compile(
    r"(?<![A-Za-z0-9])"
    r"(?:password|passwd|passphrase|pwd|secret|token|apikey|api_key|"
    r"auth_token|access_key|private_key|priv_key|credential|credentials|"
    r"key)"
    r"(?:[._-]?(?:key|id|ids|file|path|name|token|secret|value|pw))?"
    r"(?![A-Za-z0-9])",
    re.IGNORECASE,
)

_APT_INSTALL_RE = re.compile(r"\bapt(?:-get)?\s+(?:-\S+\s+)*install\b")
_APT_UPGRADE_RE = re.compile(r"\bapt(?:-get)?\s+(?:-\S+\s+)*(?:dist-)?upgrade\b")
_APT_LISTS_CLEANUP_RE = re.compile(r"/var/lib/apt/lists")
_ARCHIVE_RE = re.compile(r"\.(?:tar|tar\.gz|tgz|tar\.bz2|tbz2?|tar\.xz|txz|zip|gz|bz2|xz)(?:$|[?#])", re.IGNORECASE)
_SHELL_WORDS = {"sh", "bash", "dash", "zsh", "ksh", "ash", "python", "python3", "perl", "ruby", "node"}

def _secret_names(arg: str, kind: str) -> List[str]:
    """Credential-looking variable names in an ``ARG``/``ENV`` instruction."""
    if kind == "ENV":
        pairs: List[Tuple[str, str]] = list(split_env(arg))
    else:
        pairs = list(split_arg(arg))
    return [k for k, _v in pairs if k and _SECRET_KEY_RE.search(k)]


def _is_broad_context_copy(inst: Instruction) -> bool:
    """True for ``COPY . .`` / ``COPY . /app`` style instructions."""
    toks = [t for t in inst.tokens if not t.startswith("--") or "=" in t]
    toks = [t for t in toks if not (t.startswith("--") and "=" in t)]
    if len(toks) < 2:
        return False
    src, dst = toks[0], toks[1]
    if src.rstrip("/") not in (".", "./"):
        return False
    dest = dst.rstrip("/")
    return dest in (".", "") or dest.startswith("/")


def _runs_after_install(text: str) -> bool:
    """True when *text* contains a dependency-install command."""
    for cmd_re in (
        r"\b(?:npm|pnpm|yarn)\s+(?:ci|install|i)\b",
        r"\bpip3?\s+install\b",
        r"\bpipenv\s+install\b",
        r"\bpoetry\s+install\b",
        r"\bgo\s+mod\s+download\b",
        r"\bgo\s+build\b",
        r"\bgo\s+install\b",
        r"\bbundle\s+install\b",
        r"\bcomposer\s+install\b",
        r"\bcargo\s+build\b",
        r"\bmvn\b",
        r"\bgradle\b",
    ):
        if re.search(cmd_re, text):
            return True
    return False


def _context_dirs(dfs: Sequence[Dockerfile]) -> List[str]:
    seen: List[str] = []
    for df in dfs:
        ctx = os.path.abspath(df.context_dir)
        if ctx not in seen:
            seen.append(ctx)
    return seen


# ---------------------------------------------------------------------------
# DF001 - runs as root
# ---------------------------------------------------------------------------


def rule_df001_runs_as_root(df: Dockerfile) -> List[Finding]:
    stage = df.final_stage
    if stage is None:
        return []
    users = stage.users()
    if not users:
        return [
            Finding(
                rule_id="DF001",
                severity="high",
                line=stage.line,
                message=(
                    f"final stage '{stage.base}' has no USER instruction, so the container "
                    "runs as root (uid 0) by default"
                ),
                detail="A root container that escapes its application gains root on the host namespace and can write to any mounted volume.",
                fix=(
                    "create an unprivileged user in the image and switch to it, e.g.\n"
                    "      RUN addgroup -S app && adduser -S -G app app\n"
                    "      USER app"
                ),
            )
        ]
    last = users[-1]
    if last.arg.strip().lower() in ("root", "0", "0:0", "root:root"):
        return [
            Finding(
                rule_id="DF001",
                severity="high",
                line=last.line,
                message=f"the container deliberately switches back to root: USER {last.arg.strip()}",
                fix="drop the USER root instruction, or set USER to a dedicated unprivileged account",
            )
        ]
    return []


# ---------------------------------------------------------------------------
# DF002 / DF003 - secrets in ARG / ENV
# ---------------------------------------------------------------------------


def rule_df002_env_secret(df: Dockerfile) -> List[Finding]:
    findings: List[Finding] = []
    final = df.final_stage
    for inst in df.instructions_of("ENV"):
        names = _secret_names(inst.arg, "ENV")
        if not names:
            continue
        in_final = final is not None and any(inst is i for i in final.instructions)
        findings.append(
            Finding(
                rule_id="DF002",
                severity="high" if in_final else "medium",
                line=inst.line,
                message=(
                    "ENV holds what looks like a credential: "
                    + ", ".join(sorted(names))
                    + ("" if in_final else " (build stage)")
                ),
                detail=(
                    "ENV values are stored verbatim in the image config, appear in `docker history`/`docker inspect`, "
                    "and are visible to every process in the container - including one that is only supposed to build it."
                ),
                fix=(
                    "inject the value at run time from a secret store instead, e.g.\n"
                    "      # docker run --env-file ./runtime.env myimage\n"
                    "      # or use the orchestrator's secret object (Kubernetes Secret, Compose secrets)"
                ),
            )
        )
    return findings


def rule_df003_arg_secret(df: Dockerfile) -> List[Finding]:
    uses_build_secrets = any(
        "--mount=type=secret" in i.arg or "type=secret" in i.arg or "--secret" in i.arg
        for i in df.instructions_of("RUN")
    )
    findings: List[Finding] = []
    for inst in df.instructions_of("ARG"):
        names = _secret_names(inst.arg, "ARG")
        if not names:
            continue
        fix = (
            "use a build secret and keep the value out of the image, e.g.\n"
            "      RUN --mount=type=secret,id=npmrc,target=/root/.npmrc npm ci\n"
            "      docker build --secret id=npmrc,src=$HOME/.npmrc ."
        )
        if uses_build_secrets:
            fix = (
                "this Dockerfile already uses --mount=type=secret; make sure every secret "
                "ARG is passed that way rather than as --build-arg"
            )
        findings.append(
            Finding(
                rule_id="DF003",
                severity="medium",
                line=inst.line,
                message=(
                    "build ARG with a credential-looking name: "
                    + ", ".join(sorted(names))
                ),
                detail=(
                    "Build args are recorded in the image history (`docker history --no-trunc`) "
                    "and are visible to every stage, even if the value is never copied into the final image."
                ),
                fix=fix,
            )
        )
    return findings


# ---------------------------------------------------------------------------
# DF004 - floating base image tag
# ---------------------------------------------------------------------------


def rule_df004_latest_or_missing_tag(df: Dockerfile) -> List[Finding]:
    findings: List[Finding] = []
    for stage in df.stages:
        if stage.is_scratch:
            continue
        tag = stage.tag
        repo = image_repo_tag(stage.base)[0]
        if not repo or repo.lower() in (".", "scratch"):
            continue  # a reference to an earlier stage, not an external image
        if df.is_stage_reference(stage.base):
            continue  # FROM <stage-name>: not an image reference at all
        if tag is None:
            findings.append(
                Finding(
                    rule_id="DF004",
                    severity="medium",
                    line=stage.from_instruction.line,
                    message=f"FROM {stage.base} has no tag, which implicitly means ':latest'",
                    detail="An untagged base can change under you between two builds of the same commit, and a breaking update lands silently in production.",
                    fix=(
                        "pin an explicit version, and pin the digest when the rebuild must be byte-identical, e.g.\n"
                        f"      FROM {repo}:1.2.3\n"
                        f"      FROM {repo}:1.2.3@sha256:<digest>"
                    ),
                )
            )
        elif tag == "latest":
            findings.append(
                Finding(
                    rule_id="DF004",
                    severity="medium",
                    line=stage.from_instruction.line,
                    message=f"FROM {stage.base} tracks the floating ':latest' tag",
                    detail="':latest' is re-published by upstream on every release, so two builds of the same source can produce different images.",
                    fix=f"pin a version tag instead, e.g. FROM {repo}:1.2.3",
                )
            )
    return findings


# ---------------------------------------------------------------------------
# DF005 - compiler toolchain ships to runtime
# ---------------------------------------------------------------------------


def rule_df005_toolchain_in_runtime(df: Dockerfile) -> List[Finding]:
    findings: List[Finding] = []
    if len(df.stages) == 1:
        stage = df.stages[0]
        if is_builder_image(stage.base) and not stage.base.startswith("."):
            findings.append(
                Finding(
                    rule_id="DF005",
                    severity="medium",
                    line=stage.from_instruction.line,
                    message=(
                        f"single-stage build on the build-only image '{stage.base}': the whole "
                        "compiler toolchain ships to production"
                    ),
                    detail="That is typically several hundred megabytes of compilers, headers, package caches and shell that the running container never uses - and every one of them is extra attack surface.",
                    fix=(
                        "split the build into two stages and copy only the artifact:\n"
                        "      FROM golang:1.22 AS build\n"
                        "      # ... compile here ...\n"
                        "      FROM gcr.io/distroless/static-debian12\n"
                        "      COPY --from=build /out/app /app\n"
                        "      USER nonroot:nonroot\n"
                        "      ENTRYPOINT [\"/app\"]"
                    ),
                )
            )
        return findings

    final = df.final_stage
    if final is None:
        return findings
    if is_builder_image(final.base) and not any(
        s.name and s.name == final.base for s in df.stages[:-1]
    ):
        findings.append(
            Finding(
                rule_id="DF005",
                severity="medium",
                line=final.from_instruction.line,
                message=(
                    f"multi-stage build, but the final stage still uses the build-only image "
                    f"'{final.base}'"
                ),
                detail="Multi-stage builds only pay off when the last stage is a runtime base; here the toolchain still ships.",
                fix="finish on a slim runtime base and COPY --from=<builder> only the build output",
            )
        )
    return findings


def rule_df005b_toolchain_packages_in_runtime(df: Dockerfile) -> List[Finding]:
    findings: List[Finding] = []
    if len(df.stages) != 1:
        return findings  # dev packages in a *builder* stage are normal
    stage = df.stages[0]
    for run in stage.runs():
        text = run.arg
        if not _APT_INSTALL_RE.search(text):
            continue
        for pkg in BUILD_TOOL_PACKAGES:
            if re.search(r"(?<![\w.+-])" + re.escape(pkg) + r"(?![\w.+-])", text):
                findings.append(
                    Finding(
                        rule_id="DF005",
                        severity="medium",
                        line=run.line,
                        message=f"the runtime stage installs the compiler toolchain package '{pkg}'",
                        detail="Compilers and -dev headers in the shipped image are pure attack surface: no process in the container should be able to build code.",
                        fix=(
                            f"move '{pkg}' (and any other build-only package) into a separate builder "
                            "stage and copy the built artifact forward"
                        ),
                    )
                )
                break
    return findings


# ---------------------------------------------------------------------------
# DF006 / DF007 / DF008 - apt hygiene
# ---------------------------------------------------------------------------


def rule_df006_apt_no_install_recommends(df: Dockerfile) -> List[Finding]:
    findings: List[Finding] = []
    for inst in df.instructions_of("RUN"):
        m = _APT_INSTALL_RE.search(inst.arg)
        if not m:
            continue
        if "--no-install-recommends" in inst.arg:
            continue
        findings.append(
            Finding(
                rule_id="DF006",
                severity="medium",
                line=inst.line,
                message="apt-get install without --no-install-recommends pulls in the full recommends closure",
                detail="Recommended packages are not required for the software to work, commonly pull in daemons and X libraries, and inflate both the image and its CVE count.",
                fix="add the flag to every apt-get install, e.g. apt-get install -y --no-install-recommends <packages>",
            )
        )
    return findings


def rule_df007_apt_lists_not_cleaned(df: Dockerfile) -> List[Finding]:
    findings: List[Finding] = []
    for inst in df.instructions_of("RUN"):
        if not _APT_INSTALL_RE.search(inst.arg):
            continue
        if _APT_LISTS_CLEANUP_RE.search(inst.arg):
            continue
        findings.append(
            Finding(
                rule_id="DF007",
                severity="medium",
                line=inst.line,
                message="apt package lists are never removed in this RUN, so they stay in the image layer",
                detail=(
                    "The lists are only needed to resolve the install. Leaving them behind costs tens of "
                    "megabytes and, because the layer is immutable, deleting them in a later RUN does not shrink the image."
                ),
                fix=(
                    "clean up in the same RUN as the install:\n"
                    "      RUN apt-get update && apt-get install -y --no-install-recommends <pkgs> \\\n"
                    "          && rm -rf /var/lib/apt/lists/*"
                ),
            )
        )
    return findings


def rule_df008_apt_upgrade(df: Dockerfile) -> List[Finding]:
    findings: List[Finding] = []
    for inst in df.instructions_of("RUN"):
        if not _APT_UPGRADE_RE.search(inst.arg):
            continue
        findings.append(
            Finding(
                rule_id="DF008",
                severity="low",
                line=inst.line,
                message="apt-get upgrade in a build makes the image non-reproducible",
                detail="The set of packages that gets upgraded depends on whatever the mirrors hold at build time, so the same Dockerfile yields different images on different days - and upgrades can break a working base image.",
                fix="remove the upgrade and get fixes by rebuilding on a newer, pinned base image tag instead",
            )
        )
    return findings


def rule_df009_unpinned_packages(df: Dockerfile) -> List[Finding]:
    findings: List[Finding] = []
    for inst in df.instructions_of("RUN"):
        if not _APT_INSTALL_RE.search(inst.arg):
            continue
        if re.search(r"[\w.+-]+=[\w.:~+-]+", inst.arg):
            continue  # at least one pinned package: assume that is deliberate
        findings.append(
            Finding(
                rule_id="DF009",
                severity="low",
                line=inst.line,
                message="apt packages are installed without version pins",
                detail="The installed version depends on the state of the APT mirror at build time, so the same Dockerfile can produce different images on different days.",
                fix="pin the versions you depend on, e.g. apt-get install -y --no-install-recommends curl=8.5.0-2",
            )
        )
    return findings


# ---------------------------------------------------------------------------
# DF010 - missing / weak .dockerignore
# ---------------------------------------------------------------------------

DOCKERIGNORE_REQUIRED = (".git", "node_modules", ".env")


def rule_df010_dockerignore(_, dfs: Sequence[Dockerfile]) -> List[Finding]:
    """Checks every build context touched by this run (uses the filesystem)."""
    findings: List[Finding] = []
    for ctx in _context_dirs(dfs):
        ignore_path = os.path.join(ctx, ".dockerignore")
        if not os.path.isfile(ignore_path):
            findings.append(
                Finding(
                    rule_id="DF010",
                    severity="medium",
                    line=1,
                    path=ignore_path,
                    message=f"no .dockerignore in the build context {ctx}",
                    detail="Without one, the client sends the entire context to the daemon, and any COPY that reaches it can bake .git history, node_modules and .env files into the image.",
                    fix=(
                        "add a .dockerignore next to the Dockerfile:\n"
                        "      .git\n"
                        "      node_modules\n"
                        "      .env\n"
                        "      .venv\n"
                        "      __pycache__\n"
                        "      *.log"
                    ),
                )
            )
            continue
        try:
            with open(ignore_path, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()
        except OSError:
            continue
        missing = [p for p in DOCKERIGNORE_REQUIRED if p not in content]
        if missing:
            findings.append(
                Finding(
                    rule_id="DF010",
                    severity="medium",
                    line=1,
                    path=ignore_path,
                    message="the .dockerignore does not exclude: " + ", ".join(missing),
                    detail="These are the entries that most often leak source history, vendored dependencies and local credentials into an image.",
                    fix="add the missing patterns to " + ignore_path,
                )
            )
    return findings


# ---------------------------------------------------------------------------
# DF011 - RUN after switching to a scratch / distroless base
# ---------------------------------------------------------------------------


def rule_df011_run_in_shell_less_stage(df: Dockerfile) -> List[Finding]:
    findings: List[Finding] = []
    for stage in df.stages:
        if not stage.is_shell_less:
            continue
        for run in stage.runs():
            findings.append(
                Finding(
                    rule_id="DF011",
                    severity="high",
                    line=run.line,
                    message=(
                        f"RUN in stage based on '{stage.base}', which contains no shell - "
                        "this build cannot succeed"
                    ),
                    detail=(
                        "Docker runs every RUN with `/bin/sh -c`, and 'scratch' (and distroless images) "
                        "ship no /bin/sh, no coreutils and no package manager. The build fails with "
                        "\"exec: \\\"/bin/sh\\\": stat /bin/sh: no such file or directory\". A RUN is only "
                        "valid here if a shell was COPYed in earlier in the same stage."
                    ),
                    fix=(
                        "do the work before the switch to a shell-less base and only copy results in:\n"
                        "      FROM alpine:3.20 AS build\n"
                        "      RUN apk add --no-cache curl && curl -fsSLo /out/app https://internal.example/app\n"
                        "      FROM scratch\n"
                        "      COPY --from=build /out/app /app\n"
                        "      USER 65532:65532\n"
                        "      ENTRYPOINT [\"/app\"]"
                    ),
                )
            )
    return findings


# ---------------------------------------------------------------------------
# DF012 - HEALTHCHECK
# ---------------------------------------------------------------------------


def rule_df012_missing_healthcheck(df: Dockerfile) -> List[Finding]:
    for inst in df.instructions_of("HEALTHCHECK"):
        if inst.arg.strip().upper().startswith("NONE"):
            continue
        return []
    line = df.final_stage.line if df.final_stage else 1
    return [
        Finding(
            rule_id="DF012",
            severity="low",
            line=line,
            message="no HEALTHCHECK instruction, so the runtime has no way to tell a live container from a wedged one",
            detail="Skipping this is defensible on Kubernetes, which probes over the network instead - in that case add a comment saying so. Anywhere else (Compose, plain docker run, ECS) nothing restarts a hung process.",
            fix=(
                "add a check that exercises the real dependency path, e.g.\n"
                "      HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \\\n"
                "        CMD [\"/app\", \"healthcheck\"]"
            ),
        )
    ]


# ---------------------------------------------------------------------------
# DF013 - ADD where COPY suffices
# ---------------------------------------------------------------------------


def rule_df013_add_where_copy_suffices(df: Dockerfile) -> List[Finding]:
    findings: List[Finding] = []
    for inst in df.instructions_of("ADD"):
        src = inst.first_token
        if src.startswith(("http://", "https://", "git@", "git://")):
            continue  # ADD is the documented way to fetch a URL (though curl is clearer)
        if _ARCHIVE_RE.search(src):
            continue  # local archive: ADD's auto-extract may well be the intent
        findings.append(
            Finding(
                rule_id="DF013",
                severity="low",
                line=inst.line,
                message=f"ADD copies a plain local path ('{src}') where COPY is the honest instruction",
                detail="ADD silently does more than copy: it fetches URLs, and it auto-extracts local tar archives into the destination. That implicit behaviour surprises readers and hides an extraction step.",
                fix=f"replace with: COPY {inst.arg}",
            )
        )
    return findings


# ---------------------------------------------------------------------------
# DF014 - COPY . . before dependency install
# ---------------------------------------------------------------------------


def rule_df014_copy_before_install(df: Dockerfile) -> List[Finding]:
    findings: List[Finding] = []
    for stage in df.stages:
        earliest_copy: Optional[Instruction] = None
        for inst in stage.instructions:
            if inst.cmd in ("COPY", "ADD") and _is_broad_context_copy(inst):
                earliest_copy = inst
                break
        if earliest_copy is None:
            continue
        for run in stage.runs():
            if run.line <= earliest_copy.line:
                continue
            if _runs_after_install(run.arg):
                findings.append(
                    Finding(
                        rule_id="DF014",
                        severity="medium",
                        line=earliest_copy.line,
                        message=(
                            "the whole build context is copied in before dependencies are installed, "
                            "so every source edit invalidates the dependency layer"
                        ),
                        detail=(
                            "Docker rebuilds a layer when its inputs change. Copying the entire context first "
                            "means a one-character code change re-runs the whole dependency install on every "
                            "build - and the dependency download is usually the slowest step."
                        ),
                        fix=(
                            "copy the manifests first, install, then copy the source:\n"
                            "      COPY package.json package-lock.json ./\n"
                            "      RUN npm ci --omit=dev\n"
                            "      COPY src/ ./src/"
                        ),
                    )
                )
                break
    return findings


# ---------------------------------------------------------------------------
# DF015 - curl | sh
# ---------------------------------------------------------------------------


def rule_df015_pipe_to_shell(df: Dockerfile) -> List[Finding]:
    findings: List[Finding] = []
    for inst in df.instructions_of("RUN"):
        toks = shell_tokens(inst.arg)
        for pos, tok in enumerate(toks):
            if tok != "|" or pos + 1 >= len(toks):
                continue
            nxt = toks[pos + 1]
            if nxt not in _SHELL_WORDS:
                continue
            prev = toks[:pos]
            if any(t in ("curl", "wget") for t in prev) or _ARCHIVE_RE.search(" ".join(prev[-3:])):
                findings.append(
                    Finding(
                        rule_id="DF015",
                        severity="low",
                        line=inst.line,
                        message=f"downloaded content is piped straight into {nxt}",
                        detail=(
                            "There is no integrity check anywhere on the path: whatever the remote host "
                            "returns today is executed. A truncated download can also be partly executed, "
                            "and the executed script is invisible in the image history."
                        ),
                        fix=(
                            "download to a file, verify it, then run it:\n"
                            "      RUN curl -fsSLo /tmp/install.sh https://example.com/install.sh \\\n"
                            "          && echo \"<sha256>  /tmp/install.sh\" | sha256sum -c - \\\n"
                            "          && sh /tmp/install.sh && rm /tmp/install.sh"
                        ),
                    )
                )
        # base64-encoded payloads hide the same problem.
        if re.search(r"\bbase64\s+-d\b", inst.arg) and "|" in inst.arg:
            findings.append(
                Finding(
                    rule_id="DF015",
                    severity="low",
                    line=inst.line,
                    message="a base64 payload is decoded and piped into a shell",
                    detail="Obfuscated install steps cannot be reviewed, pinned or audited after the fact.",
                    fix="replace the encoded payload with an explicit, readable command",
                )
            )
    return findings


# ---------------------------------------------------------------------------
# registry
# ---------------------------------------------------------------------------

#: Rules that take only the parsed Dockerfile.
SIMPLE_RULES: Tuple[Callable[[Dockerfile], List[Finding]], ...] = (
    rule_df001_runs_as_root,
    rule_df002_env_secret,
    rule_df003_arg_secret,
    rule_df004_latest_or_missing_tag,
    rule_df005_toolchain_in_runtime,
    rule_df005b_toolchain_packages_in_runtime,
    rule_df006_apt_no_install_recommends,
    rule_df007_apt_lists_not_cleaned,
    rule_df008_apt_upgrade,
    rule_df009_unpinned_packages,
    rule_df011_run_in_shell_less_stage,
    rule_df012_missing_healthcheck,
    rule_df013_add_where_copy_suffices,
    rule_df014_copy_before_install,
    rule_df015_pipe_to_shell,
)

#: Rules that need to see every Dockerfile of the run (corpus-aware rules).
CORPUS_RULES: Tuple[Callable[[Dockerfile, Sequence[Dockerfile]], List[Finding]], ...] = (
    rule_df010_dockerignore,
)

#: Human-readable rule catalogue, used by the README and by ``--list-rules``.
RULE_SUMMARY: Tuple[Tuple[str, str, str], ...] = (
    ("DF001", "high", "container runs as root"),
    ("DF002", "high", "credential in ENV"),
    ("DF003", "medium", "credential in a build ARG"),
    ("DF004", "medium", "floating or missing base image tag"),
    ("DF005", "medium", "compiler toolchain ships to runtime"),
    ("DF006", "medium", "apt-get install without --no-install-recommends"),
    ("DF007", "medium", "apt lists not removed in the same RUN"),
    ("DF008", "low", "apt-get upgrade in a build"),
    ("DF009", "low", "apt packages not version-pinned"),
    ("DF010", "medium", "missing or incomplete .dockerignore"),
    ("DF011", "high", "RUN in a scratch/distroless stage (no shell)"),
    ("DF012", "low", "no HEALTHCHECK"),
    ("DF013", "low", "ADD where COPY suffices"),
    ("DF014", "medium", "COPY . . before dependency install"),
    ("DF015", "low", "curl | sh style install"),
)

RULES = SIMPLE_RULES  # backwards-friendly alias


def dedupe(findings: Sequence[Finding]) -> List[Finding]:
    """Drop repeated findings, keeping the first occurrence of each.

    ``DF010`` describes a build context, and several Dockerfiles can share one,
    so the same missing ``.dockerignore`` would otherwise be printed once per
    Dockerfile in that directory.  Deduplication is keyed on the rule, the file
    the finding is *about*, its line and its message, so two genuinely different
    findings that happen to share a line are both kept.
    """
    seen: set = set()
    kept: List[Finding] = []
    for finding in findings:
        key = (finding.rule_id, finding.path, finding.line, finding.message)
        if key in seen:
            continue
        seen.add(key)
        kept.append(finding)
    return kept


def audit(df: Dockerfile, corpus: Optional[Sequence[Dockerfile]] = None) -> List[Finding]:
    """Run every rule from :data:`SIMPLE_RULES` plus :data:`CORPUS_RULES`.

    Findings from corpus rules are de-duplicated; per-file rules are always
    reported in full.  A caller auditing several Dockerfiles should also call
    :func:`dedupe` on the combined findings, because a corpus rule can describe
    a shared build context once per file.
    """
    corpus = list(corpus) if corpus is not None else [df]
    findings: List[Finding] = []
    for rule in SIMPLE_RULES:
        findings.extend(rule(df))

    # Corpus rules may comment on a *shared* build context.  Attribute each
    # finding to the Dockerfile that owns it (same path, or same context), so
    # reporting several Dockerfiles does not repeat a neighbour's finding.
    own_path = os.path.abspath(df.path)
    own_context = os.path.abspath(df.context_dir)

    for rule in CORPUS_RULES:
        for finding in rule(df, corpus):
            if finding.path is None:
                finding.path = df.path
            else:
                finding_path = os.path.abspath(finding.path)
                finding_context = os.path.dirname(finding_path)
                if finding_path != own_path and finding_context != own_context:
                    continue
            findings.append(finding)

    findings.sort(key=lambda f: (-SEVERITY_ORDER[f.severity], f.line, f.rule_id))
    return dedupe(findings)
