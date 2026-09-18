"""Tests for the command-line interface: discovery, flags, output and exit codes."""

from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from dockerfile_audit import cli  # noqa: E402
from tests import fixtures  # noqa: E402


def run_cli(args, cwd=None):
    """Run the CLI in-process and capture ``(exit_code, stdout, stderr)``."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(args)
    return code, out.getvalue(), err.getvalue()


class CliTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="dfa-cli-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self._cwd = os.getcwd()

    def tearDown(self) -> None:
        os.chdir(self._cwd)

    def write(self, relpath: str, text: str, context_ignore: str | None = None,
              write_ignore: bool = False) -> str:
        """Create *relpath* under the temp dir, optionally with a .dockerignore."""
        path = os.path.join(self.tmp, relpath)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        if write_ignore or context_ignore is not None:
            ctx = os.path.dirname(path)
            with open(os.path.join(ctx, ".dockerignore"), "w", encoding="utf-8") as fh:
                fh.write(context_ignore if context_ignore is not None else fixtures.DOCKERIGNORE_GOOD)
        return path

    def bad(self, relpath: str = "Dockerfile") -> str:
        return self.write(relpath, fixtures.BAD)

    def good(self, relpath: str = "Dockerfile") -> str:
        return self.write(relpath, fixtures.GOOD, write_ignore=True)


class TestDiscovery(CliTestCase):
    def test_is_dockerfile_name_accepts(self) -> None:
        for name in ("Dockerfile", "dockerfile", "Dockerfile.prod", "api.Dockerfile", "api.dockerfile"):
            self.assertTrue(cli.is_dockerfile_name(name), name)

    def test_is_dockerfile_name_rejects(self) -> None:
        for name in ("README.md", "Makefile", "docker-compose.yml", "notes.txt", "Dockerfile.md"):
            self.assertFalse(cli.is_dockerfile_name(name), name)

    def test_directory_walk_finds_suffixed_variants(self) -> None:
        self.bad("Dockerfile")
        self.bad("api.Dockerfile")
        self.bad("svc/Dockerfile.prod")
        found, errors = cli.discover([self.tmp])
        self.assertEqual(errors, [])
        self.assertEqual(
            sorted(os.path.relpath(p, self.tmp) for p in found),
            ["Dockerfile", "api.Dockerfile", os.path.join("svc", "Dockerfile.prod")],
        )

    def test_walk_skips_dependency_directories(self) -> None:
        self.bad("Dockerfile")
        self.bad("node_modules/pkg/Dockerfile")
        self.bad(".git/Dockerfile")
        found, _ = cli.discover([self.tmp])
        self.assertEqual(len(found), 1)

    def test_directory_without_dockerfile_is_an_error(self) -> None:
        os.makedirs(os.path.join(self.tmp, "empty"))
        found, errors = cli.discover([os.path.join(self.tmp, "empty")])
        self.assertEqual(found, [])
        self.assertEqual(len(errors), 1)
        self.assertIn("no Dockerfile found", errors[0])

    def test_missing_path_is_an_error(self) -> None:
        _, errors = cli.discover([os.path.join(self.tmp, "nope")])
        self.assertEqual(len(errors), 1)
        self.assertIn("no such file or directory", errors[0])

    def test_explicit_file_with_odd_name_is_scanned(self) -> None:
        path = self.write("weird-name.txt", fixtures.BAD)
        found, errors = cli.discover([path])
        self.assertEqual(errors, [])
        self.assertEqual(found, [path])

    def test_duplicate_paths_are_removed(self) -> None:
        path = self.bad()
        found, _ = cli.discover([path, path, self.tmp])
        self.assertEqual(len(found), 1)


class TestExitCodes(CliTestCase):
    def test_clean_dockerfile_exits_zero(self) -> None:
        code, out, _ = run_cli([self.good()])
        self.assertEqual(code, 0)
        self.assertIn("no findings", out)

    def test_bad_dockerfile_exits_one(self) -> None:
        code, out, _ = run_cli([self.bad()])
        self.assertEqual(code, 1)
        self.assertIn("DF001", out)

    def test_findings_below_threshold_exit_zero(self) -> None:
        code, _, _ = run_cli([self.bad(), "--severity", "high"])
        self.assertEqual(code, 1, "this fixture has high findings")
        path = self.write("lowonly/Dockerfile", "FROM debian:12\nUSER app\nRUN apt-get upgrade -y\n",
                          write_ignore=True)
        code, out, _ = run_cli([path, "--severity", "high"])
        self.assertEqual(code, 0)
        self.assertIn("no findings", out)

    def test_no_arguments_is_a_usage_error(self) -> None:
        code, _, err = run_cli([])
        self.assertEqual(code, 2)
        self.assertIn("error", err.lower())

    def test_missing_path_exits_two(self) -> None:
        code, _, err = run_cli([os.path.join(self.tmp, "nope")])
        self.assertEqual(code, 2)
        self.assertIn("no such file", err)

    def test_non_dockerfile_content_exits_two(self) -> None:
        path = self.write("NotADockerfile", "hello\nworld\n")
        code, _, err = run_cli([path])
        self.assertEqual(code, 2)
        self.assertIn("no FROM instruction", err)

    def test_empty_directory_exits_two(self) -> None:
        os.makedirs(os.path.join(self.tmp, "empty"))
        code, _, _ = run_cli([os.path.join(self.tmp, "empty")])
        self.assertEqual(code, 2)

    def test_error_dominates_findings(self) -> None:
        self.bad("deep/Dockerfile")
        code, _, _ = run_cli([self.tmp, os.path.join(self.tmp, "nope")])
        self.assertEqual(code, 2)


class TestSeverityFlag(CliTestCase):
    def test_high_threshold_reports_only_high(self) -> None:
        code, out, _ = run_cli([self.bad(), "--severity", "high"])
        self.assertEqual(code, 1)
        self.assertIn("DF001", out)
        self.assertNotIn("DF012", out)
        self.assertIn("0 medium, 0 low", out)

    def test_medium_threshold_excludes_low(self) -> None:
        _, out, _ = run_cli([self.bad(), "--severity", "medium"])
        self.assertIn("DF004", out)
        self.assertNotIn("DF012", out)

    def test_default_threshold_includes_low(self) -> None:
        _, out, _ = run_cli([self.bad()])
        self.assertIn("DF012", out)


class TestJsonOutput(CliTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.bad_path = self.bad()

    def test_json_is_valid_and_well_formed(self) -> None:
        code, out, _ = run_cli([self.bad_path, "--json"])
        self.assertEqual(code, 1)
        payload = json.loads(out)
        self.assertEqual(payload["tool"], "dockerfile-audit")
        self.assertEqual(payload["threshold"], "low")
        self.assertEqual(len(payload["results"]), 1)
        result = payload["results"][0]
        self.assertEqual(result["path"], os.path.abspath(self.bad_path))
        self.assertTrue(result["findings"])
        for finding in result["findings"]:
            self.assertIn(finding["severity"], ("low", "medium", "high"))
            self.assertIn("rule", finding)
            self.assertIn("message", finding)
            self.assertIn("fix", finding)
            self.assertIsInstance(finding["line"], int)

    def test_json_severity_filter_is_applied(self) -> None:
        _, out, _ = run_cli([self.bad_path, "--json", "--severity", "high"])
        payload = json.loads(out)
        severities = {f["severity"] for f in payload["results"][0]["findings"]}
        self.assertEqual(severities, {"high"})
        self.assertEqual(payload["summary"]["by_severity"]["low"], 0)

    def test_json_summary_counts_match_findings(self) -> None:
        _, out, _ = run_cli([self.bad_path, "--json"])
        payload = json.loads(out)
        counted = sum(len(r["findings"]) for r in payload["results"])
        self.assertEqual(payload["summary"]["findings"], counted)
        self.assertEqual(payload["summary"]["files"], 1)

    def test_json_reports_errors(self) -> None:
        code, out, err = run_cli([self.bad_path, "--json", "--", os.path.join(self.tmp, "nope")])
        self.assertEqual(code, 2)
        payload = json.loads(out)
        self.assertEqual(len(payload["errors"]), 1)
        self.assertIn("no such file", err)

    def test_clean_run_produces_an_empty_findings_list(self) -> None:
        code, out, _ = run_cli([self.good(), "--json"])
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertEqual(payload["results"][0]["findings"], [])
        self.assertEqual(payload["summary"]["findings"], 0)


class TestQuietAndMisc(CliTestCase):
    def test_quiet_prints_nothing_but_keeps_the_exit_code(self) -> None:
        code, out, err = run_cli([self.bad(), "--quiet"])
        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertEqual(err, "")

    def test_quiet_json_prints_nothing(self) -> None:
        code, out, _ = run_cli([self.bad(), "--json", "--quiet"])
        self.assertEqual(code, 1)
        self.assertEqual(out, "")

    def test_list_rules_prints_the_catalogue(self) -> None:
        code, out, _ = run_cli(["--list-rules"])
        self.assertEqual(code, 0)
        self.assertIn("DF001", out)
        self.assertIn("DF015", out)

    def test_relative_paths_are_used_for_local_files(self) -> None:
        path = self.bad("rel/Dockerfile")
        os.chdir(self.tmp)
        _, out, _ = run_cli([path])
        self.assertIn(os.path.join("rel", "Dockerfile"), out)

    def test_multiple_files_are_all_reported(self) -> None:
        a = self.bad("a/Dockerfile")
        b = self.bad("b/Dockerfile")
        _, out, _ = run_cli([a, b])
        self.assertIn("across 2 Dockerfiles", out)

    def test_directory_scan_end_to_end(self) -> None:
        self.bad("svc/Dockerfile")
        code, out, _ = run_cli([self.tmp])
        self.assertEqual(code, 1)
        self.assertIn("DF001", out)
        self.assertIn("DF010", out)

    def test_shared_context_is_reported_once_per_section(self) -> None:
        # Two Dockerfiles in one directory share a build context, so the same
        # missing .dockerignore is reported in each section - but never twice
        # within one section.
        self.bad("Dockerfile")
        self.bad("api.Dockerfile")
        _, out, _ = run_cli([self.tmp])
        self.assertEqual(out.count(".dockerignore:1"), 2)
        self.assertEqual(out.count("no .dockerignore in the build context"), 2)
        self.assertIn("across 2 Dockerfiles", out)

    def test_errors_are_written_to_stderr(self) -> None:
        code, out, err = run_cli([self.bad(), "--", os.path.join(self.tmp, "nope")])
        self.assertEqual(code, 2)
        self.assertIn("no such file", err)
        self.assertNotIn("no such file", out)


class TestSubprocessEntryPoints(CliTestCase):
    """The two documented ways to invoke the tool must really work."""

    def test_module_invocation(self) -> None:
        path = self.bad()
        proc = subprocess.run(
            [sys.executable, "-m", "dockerfile_audit", path],
            cwd=ROOT, capture_output=True, text=True, timeout=120,
        )
        self.assertEqual(proc.returncode, 1)
        self.assertIn("DF001", proc.stdout)

    def test_script_invocation(self) -> None:
        path = self.good()
        proc = subprocess.run(
            [sys.executable, os.path.join(ROOT, "dockerfile_audit.py"), path],
            cwd=ROOT, capture_output=True, text=True, timeout=120,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("no findings", proc.stdout)

    def test_script_invocation_json_flag(self) -> None:
        path = self.bad()
        proc = subprocess.run(
            [sys.executable, os.path.join(ROOT, "dockerfile_audit.py"), path, "--json", "--severity", "high"],
            cwd=ROOT, capture_output=True, text=True, timeout=120,
        )
        self.assertEqual(proc.returncode, 1)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["threshold"], "high")

    def test_version_flag(self) -> None:
        proc = subprocess.run(
            [sys.executable, "-m", "dockerfile_audit", "--version"],
            cwd=ROOT, capture_output=True, text=True, timeout=120,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertIn("dockerfile-audit", proc.stdout)


if __name__ == "__main__":
    unittest.main()
