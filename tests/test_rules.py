"""Tests for the audit rules.

Each rule gets at least a positive and a negative test, so a rule that silently
stops matching (a broken regex, a typo in an instruction name) fails loudly.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dockerfile_audit.parser import parse  # noqa: E402
from dockerfile_audit.rules import SEVERITY_ORDER, audit, severity_at_least  # noqa: E402
from tests import fixtures  # noqa: E402


class AuditTestCase(unittest.TestCase):
    """Helpers shared by the rule tests."""

    def setUp(self) -> None:
        # Isolated build contexts so the .dockerignore rule cannot see the
        # repository's own context; every directory created here is removed
        # again by tearDown.
        self._ctx: list[str] = []

    def tearDown(self) -> None:
        for d in self._ctx:
            if os.path.isdir(d):
                for name in os.listdir(d):
                    os.remove(os.path.join(d, name))
                os.rmdir(d)

    def context(self) -> str:
        """A fresh, empty build-context directory."""
        path = tempfile.mkdtemp(prefix="dfa-ctx-", dir=self._scratch())
        self._ctx.append(path)
        return path

    def _scratch(self) -> str:
        if not hasattr(self, "_scratch_dir"):
            self._scratch_dir = tempfile.mkdtemp(prefix="dfa-tests-")
            self.addCleanup(self._remove_tree, self._scratch_dir)
        return self._scratch_dir

    @staticmethod
    def _remove_tree(path: str) -> None:
        if not os.path.isdir(path):
            return
        for dirpath, dirnames, filenames in os.walk(path, topdown=False):
            for name in filenames:
                os.remove(os.path.join(dirpath, name))
            for name in dirnames:
                os.rmdir(os.path.join(dirpath, name))
        os.rmdir(path)

    def findings(self, text: str, context: str | None = None):
        """Audit *text* against an isolated (empty) build context."""
        df = parse(text, path="<test>", context_dir=context or self.context())
        return audit(df)

    def rules(self, text: str, context: str | None = None):
        return sorted(f.rule_id for f in self.findings(text, context))

    def only(self, rule_id: str, text: str):
        return [f for f in self.findings(text) if f.rule_id == rule_id]


class TestNegativeControls(AuditTestCase):
    """The single most important test: good in, nothing out."""

    def test_bad_dockerfile_produces_findings(self) -> None:
        found = self.findings(fixtures.BAD)
        self.assertGreater(len(found), 5)
        self.assertIn("DF001", [f.rule_id for f in found])

    def test_bad_dockerfile_has_a_high_finding(self) -> None:
        self.assertTrue(any(f.severity == "high" for f in self.findings(fixtures.BAD)))

    def test_hardened_dockerfile_produces_zero_findings(self) -> None:
        ctx = self.context()
        with open(os.path.join(ctx, ".dockerignore"), "w", encoding="utf-8") as fh:
            fh.write(fixtures.DOCKERIGNORE_GOOD)
        found = self.findings(fixtures.GOOD, context=ctx)
        self.assertEqual(
            found,
            [],
            "hardened fixture must be clean, got: "
            + "; ".join(f"{f.rule_id}@{f.line} {f.message}" for f in found),
        )

    def test_every_finding_carries_a_message_and_a_fix(self) -> None:
        for f in self.findings(fixtures.BAD):
            self.assertTrue(f.message, f.rule_id)
            self.assertTrue(f.fix, f.rule_id)
            self.assertIn(f.severity, SEVERITY_ORDER, f.rule_id)

    def test_findings_are_sorted_high_to_low(self) -> None:
        ranks = [SEVERITY_ORDER[f.severity] for f in self.findings(fixtures.BAD)]
        self.assertEqual(ranks, sorted(ranks, reverse=True))


class TestDF001RootUser(AuditTestCase):
    def test_missing_user_is_high(self) -> None:
        found = self.only("DF001", "FROM alpine:3.19\nRUN echo hi\n")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].severity, "high")

    def test_explicit_root_user_is_high(self) -> None:
        found = self.only("DF001", "FROM alpine:3.19\nUSER root\n")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].severity, "high")

    def test_user_zero_is_root(self) -> None:
        self.assertEqual(len(self.only("DF001", "FROM alpine:3.19\nUSER 0\n")), 1)

    def test_non_root_user_is_clean(self) -> None:
        self.assertEqual(self.only("DF001", "FROM alpine:3.19\nUSER app\n"), [])

    def test_numeric_non_root_uid_is_clean(self) -> None:
        self.assertEqual(self.only("DF001", "FROM alpine:3.19\nUSER 65532:65532\n"), [])

    def test_only_the_final_stage_counts(self) -> None:
        text = "FROM alpine:3.19 AS build\nUSER root\nFROM alpine:3.19\nUSER app\n"
        self.assertEqual(self.only("DF001", text), [])

    def test_root_in_the_final_stage_is_found(self) -> None:
        text = "FROM alpine:3.19 AS build\nUSER app\nFROM alpine:3.19\nUSER root\n"
        self.assertEqual(len(self.only("DF001", text)), 1)


class TestDF002EnvSecret(AuditTestCase):
    def test_env_token_is_high(self) -> None:
        found = self.only("DF002", "FROM alpine:3.19\nENV API_TOKEN=example-token-1234\n")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].severity, "high")

    def test_env_password_in_a_build_stage_is_medium(self) -> None:
        text = "FROM alpine:3.19 AS build\nENV DB_PASSWORD=hunter2-not-a-real-password\nFROM alpine:3.19\n"
        found = self.only("DF002", text)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].severity, "medium")

    def test_secret_in_the_middle_of_a_multi_pair_env(self) -> None:
        text = "FROM alpine:3.19\nENV NODE_ENV=production GITHUB_TOKEN=example-token-1234 PORT=3000\n"
        found = self.only("DF002", text)
        self.assertEqual(len(found), 1)
        self.assertIn("GITHUB_TOKEN", found[0].message)

    def test_harmless_env_is_clean(self) -> None:
        self.assertEqual(self.only("DF002", "FROM alpine:3.19\nENV NODE_ENV=production PORT=3000\n"), [])

    def test_monkey_is_not_a_key(self) -> None:
        self.assertEqual(self.only("DF002", "FROM alpine:3.19\nENV MONKEY=banana\n"), [])

    def test_path_like_name_is_clean(self) -> None:
        self.assertEqual(self.only("DF002", "FROM alpine:3.19\nENV PATH=/usr/local/bin:$PATH\n"), [])


class TestDF003ArgSecret(AuditTestCase):
    def test_arg_token_is_medium(self) -> None:
        found = self.only("DF003", "FROM alpine:3.19\nARG NPM_TOKEN\nRUN echo build\n")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].severity, "medium")

    def test_arg_with_default_value_is_found(self) -> None:
        self.assertEqual(len(self.only("DF003", "FROM alpine:3.19\nARG DB_PASSWORD=CHANGEME\n")), 1)

    def test_harmless_arg_is_clean(self) -> None:
        self.assertEqual(self.only("DF003", "FROM alpine:3.19\nARG VERSION=1.2.3\n"), [])

    def test_fix_mentions_image_history(self) -> None:
        found = self.only("DF003", "FROM alpine:3.19\nARG API_KEY=CHANGEME\n")
        self.assertIn("history", found[0].detail.lower())


class TestDF004BaseTag(AuditTestCase):
    def test_latest_tag_is_medium(self) -> None:
        found = self.only("DF004", "FROM ubuntu:latest\nUSER app\n")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].severity, "medium")

    def test_missing_tag_is_medium(self) -> None:
        found = self.only("DF004", "FROM ubuntu\nUSER app\n")
        self.assertEqual(len(found), 1)
        self.assertIn("no tag", found[0].message)

    def test_pinned_tag_is_clean(self) -> None:
        self.assertEqual(self.only("DF004", "FROM ubuntu:24.04\nUSER app\n"), [])

    def test_registry_port_is_not_a_tag(self) -> None:
        self.assertEqual(len(self.only("DF004", "FROM registry.local:5000/team/app\nUSER app\n")), 1)

    def test_registry_port_with_tag_is_clean(self) -> None:
        self.assertEqual(self.only("DF004", "FROM registry.local:5000/team/app:1.4\nUSER app\n"), [])

    def test_scratch_is_exempt(self) -> None:
        self.assertEqual(self.only("DF004", "FROM scratch\nCOPY --from=0 /a /a\nUSER 1000\n"), [])

    def test_earlier_stage_reference_is_exempt(self) -> None:
        text = "FROM alpine:3.19 AS build\nFROM build\nUSER app\n"
        self.assertEqual(self.only("DF004", text), [])

    def test_every_stage_is_checked(self) -> None:
        text = "FROM golang:latest AS build\nFROM alpine:3.19\nUSER app\n"
        self.assertEqual(len(self.only("DF004", text)), 1)


class TestDF005Toolchain(AuditTestCase):
    def test_single_stage_golang_is_medium(self) -> None:
        found = self.only("DF005", "FROM golang:1.22\nWORKDIR /src\nUSER app\n")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].severity, "medium")
        self.assertIn("golang:1.22", found[0].message)

    def test_single_stage_node_is_not_a_toolchain_finding(self) -> None:
        self.assertEqual(self.only("DF005", "FROM node:20-alpine\nUSER app\n"), [])

    def test_multistage_with_runtime_final_stage_is_clean(self) -> None:
        text = "FROM golang:1.22 AS build\nFROM alpine:3.19\nCOPY --from=build /a /a\nUSER app\n"
        self.assertEqual(self.only("DF005", text), [])

    def test_multistage_with_build_final_stage_is_flagged(self) -> None:
        text = "FROM alpine:3.19 AS deps\nFROM rust:1.77\nUSER app\n"
        found = self.only("DF005", text)
        self.assertEqual(len(found), 1)
        self.assertIn("final stage", found[0].message)

    def test_compiler_package_in_single_stage_is_flagged(self) -> None:
        text = "FROM debian:12\nRUN apt-get update && apt-get install -y build-essential\nUSER app\n"
        found = self.only("DF005", text)
        self.assertEqual(len(found), 1)
        self.assertIn("build-essential", found[0].message)

    def test_compiler_package_in_builder_stage_is_allowed(self) -> None:
        text = (
            "FROM debian:12 AS build\n"
            "RUN apt-get update && apt-get install -y build-essential\n"
            "FROM debian:12\nUSER app\n"
        )
        self.assertEqual(self.only("DF005", text), [])

    def test_dev_package_name_is_not_confused_with_gcc(self) -> None:
        text = "FROM debian:12\nRUN apt-get install -y gcc-doc\nUSER app\n"
        self.assertEqual(self.only("DF005", text), [])


class TestAptRules(AuditTestCase):
    def test_missing_no_install_recommends_is_medium(self) -> None:
        text = "FROM debian:12\nRUN apt-get update && apt-get install -y curl\nUSER app\n"
        self.assertEqual(len(self.only("DF006", text)), 1)

    def test_flag_present_is_clean(self) -> None:
        text = "FROM debian:12\nRUN apt-get install -y --no-install-recommends curl\nUSER app\n"
        self.assertEqual(self.only("DF006", text), [])

    def test_plain_apt_is_checked_too(self) -> None:
        text = "FROM debian:12\nRUN apt install -y curl\nUSER app\n"
        self.assertEqual(len(self.only("DF006", text)), 1)

    def test_apt_get_update_alone_is_not_an_install(self) -> None:
        self.assertEqual(self.only("DF006", "FROM debian:12\nRUN apt-get update\nUSER app\n"), [])

    def test_lists_not_removed_is_medium(self) -> None:
        text = "FROM debian:12\nRUN apt-get install -y --no-install-recommends curl\nUSER app\n"
        self.assertEqual(len(self.only("DF007", text)), 1)

    def test_lists_removed_in_the_same_run_is_clean(self) -> None:
        text = (
            "FROM debian:12\n"
            "RUN apt-get update && apt-get install -y --no-install-recommends curl \\\n"
            "    && rm -rf /var/lib/apt/lists/*\n"
            "USER app\n"
        )
        self.assertEqual(self.only("DF007", text), [])

    def test_cleanup_in_a_later_run_still_counts_as_missing(self) -> None:
        text = (
            "FROM debian:12\n"
            "RUN apt-get install -y curl\n"
            "RUN rm -rf /var/lib/apt/lists/*\n"
            "USER app\n"
        )
        self.assertEqual(len(self.only("DF007", text)), 1)

    def test_apt_upgrade_is_low(self) -> None:
        found = self.only("DF008", "FROM debian:12\nRUN apt-get upgrade -y\nUSER app\n")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].severity, "low")

    def test_dist_upgrade_is_detected(self) -> None:
        self.assertEqual(len(self.only("DF008", "FROM debian:12\nRUN apt-get dist-upgrade -y\nUSER app\n")), 1)

    def test_apt_install_is_not_an_upgrade(self) -> None:
        self.assertEqual(self.only("DF008", "FROM debian:12\nRUN apt-get install -y curl\nUSER app\n"), [])

    def test_unpinned_packages_is_low(self) -> None:
        found = self.only("DF009", "FROM debian:12\nRUN apt-get install -y --no-install-recommends curl\nUSER app\n")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].severity, "low")

    def test_pinned_package_is_clean(self) -> None:
        text = "FROM debian:12\nRUN apt-get install -y --no-install-recommends curl=8.5.0-2\nUSER app\n"
        self.assertEqual(self.only("DF009", text), [])


class TestDockerignore(AuditTestCase):
    def test_missing_dockerignore_is_medium(self) -> None:
        found = self.only("DF010", "FROM alpine:3.19\nUSER app\n")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].severity, "medium")
        self.assertIn(".dockerignore", found[0].message)

    def test_complete_dockerignore_is_clean(self) -> None:
        ctx = self.context()
        with open(os.path.join(ctx, ".dockerignore"), "w", encoding="utf-8") as fh:
            fh.write(fixtures.DOCKERIGNORE_GOOD)
        text = "FROM alpine:3.19\nUSER app\nHEALTHCHECK CMD [\"/app\"]\n"
        self.assertEqual(self.rules(text, context=ctx), [])

    def test_weak_dockerignore_names_the_missing_entries(self) -> None:
        ctx = self.context()
        with open(os.path.join(ctx, ".dockerignore"), "w", encoding="utf-8") as fh:
            fh.write(fixtures.DOCKERIGNORE_WEAK)
        found = [f for f in self.findings("FROM alpine:3.19\nUSER app\n", context=ctx) if f.rule_id == "DF010"]
        self.assertEqual(len(found), 1)
        for entry in ("node_modules", ".env", ".git"):
            self.assertIn(entry, found[0].message)

    def test_one_finding_per_build_context_not_per_file(self) -> None:
        ctx = self.context()
        df_a = parse("FROM alpine:3.19\nUSER app\n", path="a", context_dir=ctx)
        df_b = parse("FROM alpine:3.19\nUSER app\n", path="b", context_dir=ctx)
        found = [f for f in audit(df_a, [df_a, df_b]) if f.rule_id == "DF010"]
        self.assertEqual(len(found), 1)

    def test_a_neighbours_context_is_not_reported_against_this_file(self) -> None:
        ctx_a = self.context()
        ctx_b = self.context()
        df_a = parse("FROM alpine:3.19\nUSER app\n", path=os.path.join(ctx_a, "Dockerfile"), context_dir=ctx_a)
        df_b = parse("FROM alpine:3.19\nUSER app\n", path=os.path.join(ctx_b, "Dockerfile"), context_dir=ctx_b)
        report_a = [f for f in audit(df_a, [df_a, df_b]) if f.rule_id == "DF010"]
        self.assertEqual(len(report_a), 1)
        self.assertEqual(os.path.dirname(os.path.abspath(report_a[0].path)), os.path.abspath(ctx_a))

    def test_dedupe_keeps_one_copy_of_a_repeated_finding(self) -> None:
        from dockerfile_audit.rules import Finding, dedupe

        one = Finding(rule_id="DF010", severity="medium", message="same", line=1, path="/c/.dockerignore")
        two = Finding(rule_id="DF010", severity="medium", message="same", line=1, path="/c/.dockerignore")
        other = Finding(rule_id="DF010", severity="medium", message="other", line=1, path="/c/.dockerignore")
        self.assertEqual(len(dedupe([one, two, other])), 2)


class TestDF011ShellLessStage(AuditTestCase):
    def test_run_in_scratch_stage_is_high(self) -> None:
        found = self.only("DF011", fixtures.SCRATCH_WITH_RUN)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].severity, "high")

    def test_run_in_distroless_stage_is_high(self) -> None:
        found = self.only("DF011", fixtures.DISTROLESS_WITH_RUN)
        self.assertEqual(len(found), 1)
        self.assertIn("distroless", found[0].message)

    def test_fix_explains_the_missing_shell(self) -> None:
        found = self.only("DF011", fixtures.SCRATCH_WITH_RUN)
        self.assertIn("/bin/sh", found[0].detail)

    def test_scratch_without_run_is_clean(self) -> None:
        text = "FROM alpine:3.19 AS build\nRUN echo hi\nFROM scratch\nCOPY --from=build /a /a\nUSER 1000\n"
        self.assertEqual(self.only("DF011", text), [])

    def test_run_before_the_scratch_switch_is_fine(self) -> None:
        text = "FROM alpine:3.19\nRUN apk add --no-cache curl\nUSER app\n"
        self.assertEqual(self.only("DF011", text), [])


class TestDF012Healthcheck(AuditTestCase):
    def test_missing_healthcheck_is_low(self) -> None:
        found = self.only("DF012", "FROM alpine:3.19\nUSER app\n")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].severity, "low")

    def test_shell_form_healthcheck_is_accepted(self) -> None:
        text = "FROM alpine:3.19\nUSER app\nHEALTHCHECK CMD curl -f http://localhost/ || exit 1\n"
        self.assertEqual(self.only("DF012", text), [])

    def test_exec_form_healthcheck_is_accepted(self) -> None:
        text = 'FROM alpine:3.19\nUSER app\nHEALTHCHECK CMD ["/app", "ping"]\n'
        self.assertEqual(self.only("DF012", text), [])

    def test_disabled_healthcheck_is_still_a_finding(self) -> None:
        text = "FROM alpine:3.19\nUSER app\nHEALTHCHECK NONE\n"
        self.assertEqual(len(self.only("DF012", text)), 1)


class TestDF013AddVersusCopy(AuditTestCase):
    def test_add_of_a_plain_file_is_low(self) -> None:
        found = self.only("DF013", "FROM alpine:3.19\nADD app.py /app/\nUSER app\n")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].severity, "low")
        self.assertIn("COPY app.py /app/", found[0].fix)

    def test_add_of_a_url_is_exempt(self) -> None:
        text = "FROM alpine:3.19\nADD https://example.com/app /app\nUSER app\n"
        self.assertEqual(self.only("DF013", text), [])

    def test_add_of_an_archive_is_exempt(self) -> None:
        text = "FROM alpine:3.19\nADD rootfs.tar.gz /\nUSER app\n"
        self.assertEqual(self.only("DF013", text), [])

    def test_copy_is_never_flagged(self) -> None:
        self.assertEqual(self.only("DF013", "FROM alpine:3.19\nCOPY app.py /app/\nUSER app\n"), [])


class TestDF014LayerOrder(AuditTestCase):
    def test_copy_dot_before_npm_install_is_medium(self) -> None:
        text = "FROM node:20-alpine\nCOPY . .\nRUN npm install\nUSER app\n"
        found = self.only("DF014", text)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].severity, "medium")

    def test_manifests_first_is_clean(self) -> None:
        text = (
            "FROM node:20-alpine\n"
            "COPY package.json package-lock.json ./\n"
            "RUN npm ci\n"
            "COPY src/ ./src/\n"
            "USER app\n"
        )
        self.assertEqual(self.only("DF014", text), [])

    def test_copy_dot_after_install_is_clean(self) -> None:
        text = "FROM node:20-alpine\nRUN npm ci\nCOPY . .\nUSER app\n"
        self.assertEqual(self.only("DF014", text), [])

    def test_python_requirements_pattern(self) -> None:
        text = "FROM python:3.13-slim\nCOPY . /app\nRUN pip install -r requirements.txt\nUSER app\n"
        self.assertEqual(len(self.only("DF014", text)), 1)

    def test_copy_dot_with_no_install_is_clean(self) -> None:
        self.assertEqual(self.only("DF014", "FROM alpine:3.19\nCOPY . /app\nUSER app\n"), [])

    def test_fix_shows_the_manifest_first_pattern(self) -> None:
        found = self.only("DF014", "FROM node:20-alpine\nCOPY . .\nRUN npm install\nUSER app\n")
        self.assertIn("package.json", found[0].fix)


class TestDF015PipeToShell(AuditTestCase):
    def test_curl_pipe_sh_is_low(self) -> None:
        text = "FROM alpine:3.19\nRUN curl -fsSL https://example.com/i.sh | sh\nUSER app\n"
        found = self.only("DF015", text)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].severity, "low")

    def test_wget_pipe_bash_is_detected(self) -> None:
        text = "FROM alpine:3.19\nRUN wget -qO- https://example.com/i.sh | bash\nUSER app\n"
        self.assertEqual(len(self.only("DF015", text)), 1)

    def test_pipe_without_spaces_is_detected(self) -> None:
        text = "FROM alpine:3.19\nRUN curl -fsSL https://example.com/i.sh|sh\nUSER app\n"
        self.assertEqual(len(self.only("DF015", text)), 1)

    def test_download_then_verify_is_clean(self) -> None:
        text = (
            "FROM alpine:3.19\n"
            "RUN curl -fsSLo /tmp/i.sh https://example.com/i.sh && sh /tmp/i.sh\n"
            "USER app\n"
        )
        self.assertEqual(self.only("DF015", text), [])

    def test_ordinary_pipe_is_clean(self) -> None:
        text = "FROM alpine:3.19\nRUN cat /etc/os-release | grep NAME\nUSER app\n"
        self.assertEqual(self.only("DF015", text), [])

    def test_base64_payload_is_detected(self) -> None:
        text = "FROM alpine:3.19\nRUN echo aGVsbG8= | base64 -d | sh\nUSER app\n"
        self.assertEqual(len(self.only("DF015", text)), 1)


class TestSeverityFiltering(AuditTestCase):
    def test_high_threshold_hides_low_findings(self) -> None:
        # A context with a complete .dockerignore, a USER and a HEALTHCHECK, so
        # the only finding left is the low-severity apt-get upgrade (DF008).
        ctx = self.context()
        with open(os.path.join(ctx, ".dockerignore"), "w", encoding="utf-8") as fh:
            fh.write(fixtures.DOCKERIGNORE_GOOD)
        text = (
            "FROM debian:12\n"
            "USER app\n"
            "RUN apt-get upgrade -y\n"
            "HEALTHCHECK CMD [\"/app\"]\n"
        )
        findings = self.findings(text, context=ctx)
        self.assertEqual([f.rule_id for f in findings], ["DF008"])
        high = [f for f in findings if severity_at_least(f.severity, "high")]
        self.assertEqual(high, [])

    def test_high_threshold_keeps_high_findings(self) -> None:
        findings = self.findings("FROM alpine:3.19\nRUN echo hi\n")
        high = [f for f in findings if severity_at_least(f.severity, "high")]
        self.assertEqual([f.rule_id for f in high], ["DF001"])

    def test_threshold_ordering(self) -> None:
        self.assertTrue(severity_at_least("high", "medium"))
        self.assertTrue(severity_at_least("medium", "low"))
        self.assertFalse(severity_at_least("low", "medium"))
        self.assertFalse(severity_at_least("medium", "high"))

    def test_every_documented_rule_can_fire(self) -> None:
        from dockerfile_audit.rules import RULE_SUMMARY

        fired = {f.rule_id for f in self.findings(fixtures.BAD)}
        fired |= {f.rule_id for f in self.findings(fixtures.SCRATCH_WITH_RUN)}
        fired |= {f.rule_id for f in self.findings("FROM debian:12\nRUN apt-get upgrade -y\nUSER app\n")}
        fired |= {f.rule_id for f in self.findings("FROM golang:1.22\nUSER app\nHEALTHCHECK CMD [\"/a\"]\n")}
        expected = {rule_id for rule_id, _sev, _desc in RULE_SUMMARY}
        self.assertEqual(expected - fired, set(), "rules that never fired in any fixture")


if __name__ == "__main__":
    unittest.main()
