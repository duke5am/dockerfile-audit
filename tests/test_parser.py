"""Tests for the static Dockerfile parser."""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dockerfile_audit.parser import (  # noqa: E402
    ParseError,
    image_repo_tag,
    is_builder_image,
    is_shell_less_image,
    parse,
    shell_tokens,
    split_arg,
    split_env,
)


class TestInstructions(unittest.TestCase):
    def setUp(self) -> None:
        self.df = parse(
            "FROM alpine:3.19 AS base\n"
            "RUN echo one\n"
            "RUN echo two\n"
            "COPY app.py /app/\n"
            "USER app\n"
        )

    def test_instruction_count(self) -> None:
        self.assertEqual(len(self.df.instructions), 5)

    def test_commands_are_upper_cased(self) -> None:
        self.assertEqual([i.cmd for i in self.df.instructions], ["FROM", "RUN", "RUN", "COPY", "USER"])

    def test_line_numbers(self) -> None:
        self.assertEqual([i.line for i in self.df.instructions], [1, 2, 3, 4, 5])

    def test_args_are_trimmed(self) -> None:
        self.assertEqual(self.df.instructions[1].arg, "echo one")

    def test_stage_name_and_base(self) -> None:
        stage = self.df.stages[0]
        self.assertEqual(stage.base, "alpine:3.19")
        self.assertEqual(stage.name, "base")

    def test_stage_instructions_exclude_the_from(self) -> None:
        self.assertEqual(len(self.df.stages[0].instructions), 4)

    def test_effective_user(self) -> None:
        self.assertEqual(self.df.final_stage.effective_user(), "app")

    def test_tokens_split_on_whitespace(self) -> None:
        self.assertEqual(self.df.instructions[3].tokens, ["app.py", "/app/"])

    def test_first_token(self) -> None:
        self.assertEqual(self.df.instructions[3].first_token, "app.py")


class TestCommentsAndContinuations(unittest.TestCase):
    def test_full_line_comments_are_ignored(self) -> None:
        df = parse("# a comment\nFROM alpine:3.19\n# another\nRUN echo hi\n")
        self.assertEqual([i.cmd for i in df.instructions], ["FROM", "RUN"])

    def test_trailing_comment_is_kept_in_the_argument(self) -> None:
        # Docker only strips '#' comments at the start of a line; inside a RUN
        # the shell sees the rest of the line, so the parser must not eat it.
        df = parse("FROM alpine:3.19\nRUN echo hi # not a comment\n")
        self.assertEqual(df.instructions[1].arg, "echo hi # not a comment")

    def test_blank_lines_are_ignored(self) -> None:
        df = parse("\n\nFROM alpine:3.19\n\n\nRUN echo hi\n\n")
        self.assertEqual(len(df.instructions), 2)

    def test_backslash_continuation_joins_lines(self) -> None:
        df = parse("FROM alpine:3.19\nRUN echo one \\\n    && echo two\n")
        self.assertEqual(df.instructions[1].arg, "echo one && echo two")

    def test_continuation_reports_the_first_line(self) -> None:
        df = parse("FROM alpine:3.19\nRUN echo one \\\n    && echo two\nUSER app\n")
        self.assertEqual(df.instructions[1].line, 2)
        self.assertEqual(df.instructions[2].line, 4)

    def test_continuation_skips_interleaved_comment_lines(self) -> None:
        df = parse("FROM alpine:3.19\nRUN echo one \\\n# comment\n    && echo two\n")
        self.assertEqual(len(df.instructions), 2)
        self.assertIn("echo two", df.instructions[1].arg)

    def test_custom_escape_directive(self) -> None:
        df = parse("# escape=`\nFROM alpine:3.19\nRUN echo one `\n    && echo two\n")
        self.assertEqual(df.escape, "`")
        self.assertEqual(len(df.instructions), 2)

    def test_syntax_directive_is_captured(self) -> None:
        df = parse("# syntax=docker/dockerfile:1.7\nFROM alpine:3.19\n")
        self.assertEqual(df.syntax, "docker/dockerfile:1.7")

    def test_exec_form_is_flattened(self) -> None:
        df = parse('FROM alpine:3.19\nRUN ["/bin/sh", "-c", "echo hi"]\n')
        self.assertEqual(df.instructions[1].arg, "/bin/sh -c echo hi")

    def test_json_array_in_cmd_stays_intact(self) -> None:
        df = parse('FROM alpine:3.19\nCMD ["node", "server.js"]\n')
        self.assertEqual(df.instructions[1].arg, "node server.js")


class TestHeredocs(unittest.TestCase):
    def test_heredoc_body_is_not_an_instruction(self) -> None:
        df = parse(
            "FROM alpine:3.19\n"
            "RUN <<EOF\n"
            "echo hello\n"
            "echo world\n"
            "EOF\n"
            "USER app\n"
        )
        self.assertEqual([i.cmd for i in df.instructions], ["FROM", "RUN", "USER"])

    def test_heredoc_body_is_attached_to_the_run(self) -> None:
        df = parse("FROM alpine:3.19\nRUN <<EOF\necho hello\necho world\nEOF\n")
        run = df.instructions[1]
        self.assertEqual(len(run.heredocs), 1)
        self.assertEqual(run.heredocs[0], ["echo hello", "echo world"])

    def test_instruction_after_heredoc_keeps_its_line_number(self) -> None:
        df = parse("FROM alpine:3.19\nRUN <<EOF\necho hello\nEOF\nUSER app\n")
        self.assertEqual(df.instructions[2].line, 5)


class TestStages(unittest.TestCase):
    def test_multiple_stages(self) -> None:
        df = parse("FROM golang:1.22 AS build\nRUN go build\nFROM alpine:3.19\nUSER app\n")
        self.assertEqual(len(df.stages), 2)
        self.assertEqual(df.stages[0].name, "build")
        self.assertEqual(df.stages[1].base, "alpine:3.19")

    def test_final_stage_is_the_last_from(self) -> None:
        df = parse("FROM golang:1.22 AS build\nFROM alpine:3.19\nRUN apk add curl\n")
        self.assertEqual(df.final_stage.base, "alpine:3.19")
        self.assertEqual(len(df.final_stage.runs()), 1)

    def test_stage_reference_is_kept_as_the_base(self) -> None:
        df = parse("FROM golang:1.22 AS build\nFROM build AS test\nRUN go test ./...\n")
        self.assertEqual(df.stages[1].base, "build")

    def test_scratch_is_recognised(self) -> None:
        df = parse("FROM scratch\nCOPY --from=0 /app /app\n")
        self.assertTrue(df.stages[0].is_scratch)
        self.assertTrue(df.stages[0].is_shell_less)

    def test_digest_pin_is_parsed(self) -> None:
        digest = "sha256:" + "a" * 64
        df = parse("FROM alpine@" + digest + "\n")
        self.assertEqual(df.stages[0].repo, "alpine")
        self.assertIsNone(df.stages[0].tag)
        self.assertEqual(df.stages[0].digest, digest)

    def test_joined_run_text_concatenates_stage_runs(self) -> None:
        df = parse("FROM alpine:3.19\nRUN echo one\nRUN echo two\n")
        self.assertEqual(df.final_stage.joined_run_text(), "echo one && echo two")


class TestParseErrors(unittest.TestCase):
    def test_missing_from_raises(self) -> None:
        with self.assertRaises(ParseError):
            parse("RUN echo hi\n")

    def test_empty_text_raises(self) -> None:
        with self.assertRaises(ParseError):
            parse("")

    def test_comment_only_text_raises(self) -> None:
        with self.assertRaises(ParseError):
            parse("# just a comment\n")


class TestHelpers(unittest.TestCase):
    def test_shell_tokens_splits_operators(self) -> None:
        self.assertEqual(shell_tokens("a && b || c"), ["a", "&&", "b", "||", "c"])

    def test_shell_tokens_keeps_quoted_text_together(self) -> None:
        self.assertEqual(shell_tokens('echo "hello world"'), ["echo", "hello world"])

    def test_shell_tokens_does_not_need_spaces_around_pipe(self) -> None:
        self.assertEqual(shell_tokens("curl -fsSL https://x|sh"), ["curl", "-fsSL", "https://x", "|", "sh"])

    def test_shell_tokens_keeps_flags_intact(self) -> None:
        tokens = shell_tokens("apt-get install -y --no-install-recommends curl")
        self.assertIn("--no-install-recommends", tokens)
        self.assertEqual(tokens[-1], "curl")

    def test_split_env_multiple_pairs(self) -> None:
        self.assertEqual(split_env("A=1 B=2"), [("A", "1"), ("B", "2")])

    def test_split_env_legacy_single_pair(self) -> None:
        self.assertEqual(split_env("PATH /usr/local/bin"), [("PATH", "/usr/local/bin")])

    def test_split_arg_with_default(self) -> None:
        self.assertEqual(split_arg("VERSION=1.2.3"), [("VERSION", "1.2.3")])

    def test_split_arg_without_default(self) -> None:
        self.assertEqual(split_arg("TOKEN"), [("TOKEN", None)])

    def test_image_repo_tag_plain(self) -> None:
        self.assertEqual(image_repo_tag("alpine:3.19"), ("alpine", "3.19", None))

    def test_image_repo_tag_missing(self) -> None:
        self.assertEqual(image_repo_tag("alpine"), ("alpine", None, None))

    def test_image_repo_tag_with_namespace(self) -> None:
        self.assertEqual(image_repo_tag("library/node:20"), ("library/node", "20", None))

    def test_image_repo_tag_with_registry_port(self) -> None:
        self.assertEqual(image_repo_tag("registry.local:5000/team/app:1.0"), ("registry.local:5000/team/app", "1.0", None))

    def test_image_repo_tag_scratch(self) -> None:
        self.assertEqual(image_repo_tag("scratch"), ("scratch", None, None))

    def test_is_builder_image_positive(self) -> None:
        self.assertTrue(is_builder_image("golang:1.22"))
        self.assertTrue(is_builder_image("docker.io/library/buildpack-deps:bookworm"))

    def test_is_builder_image_negative_for_runtimes(self) -> None:
        self.assertFalse(is_builder_image("node:20-alpine"))
        self.assertFalse(is_builder_image("python:3.13-slim"))

    def test_is_shell_less_image(self) -> None:
        self.assertTrue(is_shell_less_image("scratch"))
        self.assertTrue(is_shell_less_image("gcr.io/distroless/static-debian12:nonroot"))
        self.assertFalse(is_shell_less_image("alpine:3.19"))
        self.assertFalse(is_shell_less_image("debian:bookworm-slim"))


if __name__ == "__main__":
    unittest.main()
