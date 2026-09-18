# dockerfile-audit

A small, dependency-free Dockerfile linter. It reads Dockerfiles as **text** and
reports concrete problems: a container that will run as root, credentials baked
into `ENV`/`ARG`, floating base images, apt cache left in a layer, a `RUN` in a
`scratch` stage (which cannot build at all), and more — each with an explanation
and a suggested fix.

**No Docker daemon, no build, no network, no dependencies.** Python 3.8+ and the
standard library are the whole requirement, which is the point: you can run it in
a CI job, a pre-commit hook, or on a machine that has never had a container
runtime installed.

```
$ python3 -m dockerfile_audit examples/Dockerfile.insecure
examples/Dockerfile.insecure
  HIGH   DF001  line 5  final stage 'node:latest' has no USER instruction, so the container runs as root (uid 0) by default
           ...
11 findings (2 high, 5 medium, 4 low) across 1 Dockerfile; threshold 'low'
```

---

## Install-free usage

There is nothing to install. Clone or copy the directory and run it:

```bash
# as a module
python3 -m dockerfile_audit path/to/Dockerfile

# or as a single-file script (same code, resolves the package next to itself)
python3 dockerfile_audit.py path/to/Dockerfile

# several files
python3 -m dockerfile_audit Dockerfile api.Dockerfile

# a whole tree: finds Dockerfile, *.Dockerfile and Dockerfile.*
python3 -m dockerfile_audit .
```

`dockerfile-audit` (the console script in `pyproject.toml`) is only needed if you
choose to `pip install .`; the two commands above never touch pip.

### Flags

| Flag | Meaning |
| --- | --- |
| `--severity high\|medium\|low` | Minimum severity to report. Default `low` (everything). |
| `--json` | Machine-readable findings on stdout instead of the text report. |
| `--quiet` | Print nothing at all; use the exit code only. |
| `--list-rules` | Print the rule catalogue (`DF001`…) and exit. |
| `--version` | Print the version and exit. |

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | No findings at or above the requested threshold. |
| `1` | At least one finding at or above the threshold. |
| `2` | Usage error: no path given, a path that does not exist, a directory with no Dockerfile in it, or a file with no `FROM` instruction (so it is not a Dockerfile). |

`2` wins over `1`: if any input could not be audited, the run is a failure even
when other files did produce findings. Errors always go to **stderr**, so
`--json` output on stdout stays parseable.

```bash
# fail a CI job only on the serious stuff
python3 -m dockerfile_audit . --severity high --quiet
echo "exit: $?"          # 1 if a high finding exists, 0 otherwise
```

### JSON shape

```json
{
  "tool": "dockerfile-audit",
  "version": "1.0.0",
  "threshold": "high",
  "summary": { "files": 1, "findings": 2, "errors": 0,
               "by_severity": { "high": 2, "medium": 0, "low": 0 } },
  "results": [
    { "path": "/abs/path/Dockerfile",
      "context": "/abs/path",
      "findings": [
        { "rule": "DF001", "severity": "high", "line": 5,
          "message": "final stage 'node:latest' has no USER instruction, ...",
          "detail": "A root container that escapes its application ...",
          "fix": "create an unprivileged user in the image and switch to it, ..." }
      ] }
  ],
  "errors": []
}
```

### As a library

```python
from dockerfile_audit import audit_text

for finding in audit_text(open("Dockerfile").read(), minimum_severity="medium"):
    print(finding.severity, finding.rule_id, finding.line, finding.message)
```

---

## A real example

`examples/Dockerfile.insecure` is a deliberately awful Dockerfile (every
credential in it is obviously fake). Running the tool on it, verbatim:

```
$ python3 -m dockerfile_audit examples/Dockerfile.insecure
examples/Dockerfile.insecure
  HIGH   DF001  line 5  final stage 'node:latest' has no USER instruction, so the container runs as root (uid 0) by default
           A root container that escapes its application gains root on the host namespace and can write to
           any mounted volume.
           fix:
             create an unprivileged user in the image and switch to it, e.g.
                   RUN addgroup -S app && adduser -S -G app app
                   USER app

  HIGH   DF002  line 6  ENV holds what looks like a credential: NPM_TOKEN
           ENV values are stored verbatim in the image config, appear in `docker history`/`docker inspect`,
           and are visible to every process in the container - including one that is only supposed to build
           it.
           fix:
             inject the value at run time from a secret store instead, e.g.
                   # docker run --env-file ./runtime.env myimage
                   # or use the orchestrator's secret object (Kubernetes Secret, Compose secrets)

  MEDIUM DF004  line 5  FROM node:latest tracks the floating ':latest' tag
           ':latest' is re-published by upstream on every release, so two builds of the same source can
           produce different images.
           fix:
             pin a version tag instead, e.g. FROM node:1.2.3

  MEDIUM DF003  line 7  build ARG with a credential-looking name: DB_PASSWORD
           Build args are recorded in the image history (`docker history --no-trunc`) and are visible to
           every stage, even if the value is never copied into the final image.
           fix:
             use a build secret and keep the value out of the image, e.g.
                   RUN --mount=type=secret,id=npmrc,target=/root/.npmrc npm ci
                   docker build --secret id=npmrc,src=$HOME/.npmrc .

  MEDIUM DF014  line 11  the whole build context is copied in before dependencies are installed, so every source edit invalidates the dependency layer
           Docker rebuilds a layer when its inputs change. Copying the entire context first means a
           one-character code change re-runs the whole dependency install on every build - and the
           dependency download is usually the slowest step.
           fix:
             copy the manifests first, install, then copy the source:
                   COPY package.json package-lock.json ./
                   RUN npm ci --omit=dev
                   COPY src/ ./src/

  MEDIUM DF006  line 13  apt-get install without --no-install-recommends pulls in the full recommends closure
           Recommended packages are not required for the software to work, commonly pull in daemons and X
           libraries, and inflate both the image and its CVE count.
           fix:
             add the flag to every apt-get install, e.g. apt-get install -y --no-install-recommends <packages>

  MEDIUM DF007  line 13  apt package lists are never removed in this RUN, so they stay in the image layer
           The lists are only needed to resolve the install. Leaving them behind costs tens of megabytes
           and, because the layer is immutable, deleting them in a later RUN does not shrink the image.
           fix:
             clean up in the same RUN as the install:
                   RUN apt-get update && apt-get install -y --no-install-recommends <pkgs> \
                       && rm -rf /var/lib/apt/lists/*

  LOW    DF012  line 5  no HEALTHCHECK instruction, so the runtime has no way to tell a live container from a wedged one
           Skipping this is defensible on Kubernetes, which probes over the network instead - in that case
           add a comment saying so. Anywhere else (Compose, plain docker run, ECS) nothing restarts a hung
           process.
           fix:
             add a check that exercises the real dependency path, e.g.
                   HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
                     CMD ["/app", "healthcheck"]

  LOW    DF009  line 13  apt packages are installed without version pins
           The installed version depends on the state of the APT mirror at build time, so the same
           Dockerfile can produce different images on different days.
           fix:
             pin the versions you depend on, e.g. apt-get install -y --no-install-recommends curl=8.5.0-2

  LOW    DF013  line 14  ADD copies a plain local path ('app.py') where COPY is the honest instruction
           ADD silently does more than copy: it fetches URLs, and it auto-extracts local tar archives into
           the destination. That implicit behaviour surprises readers and hides an extraction step.
           fix:
             replace with: COPY app.py /app/

  LOW    DF015  line 15  downloaded content is piped straight into bash
           There is no integrity check anywhere on the path: whatever the remote host returns today is
           executed. A truncated download can also be partly executed, and the executed script is invisible
           in the image history.
           fix:
             download to a file, verify it, then run it:
                   RUN curl -fsSLo /tmp/install.sh https://example.com/install.sh \
                       && echo "<sha256>  /tmp/install.sh" | sha256sum -c - \
                       && sh /tmp/install.sh && rm /tmp/install.sh

11 findings (2 high, 5 medium, 4 low) across 1 Dockerfile; threshold 'low'
```

(Exit code: `1`.)

The hardened counterpart, `examples/Dockerfile.hardened` — multi-stage, pinned
base, unprivileged user, healthcheck, manifests copied before dependencies:

```
$ python3 -m dockerfile_audit examples/Dockerfile.hardened
ok   examples/Dockerfile.hardened - no findings at or above 'low'
0 findings (0 high, 0 medium, 0 low) across 1 Dockerfile; threshold 'low'
```

(Exit code: `0`.) Both files are used as negative controls in the test suite: the
bad one must produce findings and the good one must produce **zero**.

---

## Rules

| Rule | Severity | What it flags |
| --- | --- | --- |
| **DF001** | high | Container runs as root: no `USER` in the final stage, or `USER root`/`USER 0`. |
| **DF002** | high (final stage) / medium (build stage) | Credential-looking name in `ENV` (`*_TOKEN`, `*_PASSWORD`, `*_SECRET`, `*_KEY`, `*_CREDENTIAL`…). `ENV` is stored in the image config and shows up in `docker history`/`inspect`. |
| **DF003** | medium | Credential-looking name in a build `ARG`. Build args are recorded in the image history, so `--build-arg DB_PASSWORD=…` leaks even if the value is never copied forward. Fix: `RUN --mount=type=secret`. |
| **DF004** | medium | `FROM` with no tag (implicitly `:latest`) or an explicit `:latest`. Only the *final* stage's toolchain matters, but every stage is checked for reproducibility. Stage references (`FROM build`) and `scratch` are exempt. |
| **DF005** | medium | Compiler toolchain ships to runtime: a single-stage build on a build-only image (`golang`, `rust`, `buildpack-deps`, …), a multi-stage build whose final stage is still one of those, or a single-stage `apt-get install` of `build-essential`/`gcc`/`make`/`-dev` headers. |
| **DF006** | medium | `apt-get install` without `--no-install-recommends`. |
| **DF007** | medium | No `rm -rf /var/lib/apt/lists/*` in the same `RUN` as the install. Removing it in a *later* layer does not shrink the image, because layers are immutable. |
| **DF008** | low | `apt-get upgrade`/`dist-upgrade` in a build: the result depends on mirror state at build time. |
| **DF009** | low | `apt-get install` with no version pin anywhere in the command (reproducibility). |
| **DF010** | medium | No `.dockerignore` in the build context, or one that does not exclude `.git`, `node_modules` and `.env`. Reported once per build context, not once per Dockerfile. |
| **DF011** | high | `RUN` after switching to a `scratch`/`distroless` stage. Docker runs `RUN` with `/bin/sh -c` and those images have no shell, so the build fails: `exec: "/bin/sh": stat /bin/sh: no such file or directory`. |
| **DF012** | low | No `HEALTHCHECK`, or `HEALTHCHECK NONE`. Defensible on Kubernetes (which probes over the network) and called out as such in the message. |
| **DF013** | low | `ADD` of a plain local path where `COPY` would do. `ADD` silently untars local archives and fetches URLs. URL and archive sources are exempt. |
| **DF014** | medium | `COPY . .` (or `COPY . /app`) *before* `npm install`/`pip install`/`go mod download`/… in the same stage, so every source edit invalidates the dependency layer. |
| **DF015** | low | `curl … \| sh` / `wget … \| bash`, and base64 payloads piped into a shell: nothing is verified before execution. |

### How severity is decided

* **high** — objectively broken, or a direct privilege/credential exposure. A
  `RUN` in a `scratch` stage cannot build; an image with no `USER` runs as uid 0;
  a credential in the shipped `ENV` is readable by anyone who can pull the image.
* **medium** — a real security or reproducibility defect whose impact depends on
  context, or a definite build-hygiene problem: floating base tags, secrets in
  build args, a compiler shipped to runtime, apt cache in a layer, a
  cache-busting `COPY . .`, a context that ships `.git`.
* **low** — advice that reduces attack surface or improves practice but is not
  wrong in every context: no `HEALTHCHECK`, `ADD` instead of `COPY`,
  `curl | sh` (which the official install docs still recommend), unpinned
  package versions.

Not everything is critical on purpose: a report where every line is red is a
report nobody reads.

---

## Tests

```bash
python3 -m unittest discover -s tests -v
# or
python3 run_tests.py
```

167 tests, 263 assertions, no dependencies. The suite covers the parser
(continuations, custom escape character, comments, heredocs, JSON forms, stage
splitting, image reference parsing), every rule in both directions (a positive
and a negative case each), severity filtering, discovery, and the exit codes of
both entry points. The two negative controls are the fixtures above: a bad
Dockerfile must produce findings, and a hardened one must produce **zero** — if a
rule starts matching something it should not, that test fails.

---

## What this does not do

Honesty section. This is a **static text analyser**, and that has hard limits:

* **It does not build anything, and it never talks to a Docker daemon.** It does
  not pull images, run containers, execute `RUN` commands, or read `/var/lib/docker`.
  A clean report means "no rule matched this text", not "this image is safe".
* **It cannot see inside your base image.** If `alpine:3.19` already sets a
  `USER`, ships vulnerable packages or contains a shell you did not expect, this
  tool has no way to know. It also cannot follow an inherited `ENV`,
  `ENTRYPOINT` or `ONBUILD` from a parent image — no parent is inspected at all.
* **It does not resolve variables.** `USER ${APP_USER}`, `FROM ${BASE_IMAGE}` and
  `COPY $SRC /app` are treated literally; whether `${APP_USER}` ends up as root
  is beyond a text pass.
* **The checks are heuristics, so both false positives and false negatives are
  possible.** Examples: a placeholder `ENV API_KEY=CHANGEME` is reported even
  though it is not a secret; a toolchain installed with `curl` instead of `apt`
  is not detected; a rule that only ever fires on apt-based images says nothing
  about `apk`, `dnf` or `zypper` images beyond the generic checks.
* **`DF010` is the one filesystem-aware rule.** It stats `.dockerignore` in the
  directory holding the Dockerfile, which is the usual build context. If you
  build with `docker build -f elsewhere/Dockerfile .`, the context it checks is
  the wrong one, and it cannot see remote or Git contexts at all.
* **It does not replace a scanner.** There is no CVE database, no SBOM, no
  signature verification, no runtime policy. Use it alongside
  [hadolint](https://github.com/hadolint/hadolint) (Dockerfile best practice),
  [Trivy](https://github.com/aquasecurity/trivy) or
  [Grype](https://github.com/anchore/grype) (vulnerabilities in the built image)
  and whatever signs your images. It complements them by needing no daemon and
  running in a fraction of a second.
* **There is no auto-fix.** Fixes are printed as suggestions; nothing is
  rewritten, and no file is modified by this tool.

If any of that matters for your threat model, do not treat a green run as
approval to deploy.

---

## Companion guide

This repository is the free companion tool to the **Docker & Image Hardening
Pack**, which covers the reasoning the rules only point at: choosing a base
image, structuring multi-stage builds, handling secrets at build and run time,
running as non-root, and verifying what actually ended up in the image. The link
is at the bottom of this file.

---

## Licence

MIT. See [`LICENSE`](LICENSE).

Copyright (c) 2026 duke5am.

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions: the above copyright notice and this
permission notice shall be included in all copies or substantial portions of the
Software. THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT
OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

---

→ **[Docker & Image Hardening Pack](https://duke5am.gumroad.com/l/15-docker-hardening)** — $24 on Gumroad <!-- GUMROAD-LINK -->
