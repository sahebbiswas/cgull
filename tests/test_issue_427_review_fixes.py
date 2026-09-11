"""Regression coverage for PR #440 review fixes."""

from cgull.cli import _is_preprocessor_command


def test_preprocessor_routing_accepts_global_verbosity_forms():
    assert _is_preprocessor_command(["-v", "preprocessor", "sample.c"])
    assert _is_preprocessor_command(["-vv", "preprocessor", "sample.c"])
    assert _is_preprocessor_command(["-vvv", "preprocessor", "sample.c"])
    assert _is_preprocessor_command(["--verbose", "preprocessor", "sample.c"])


def test_preprocessor_routing_accepts_global_logging_options():
    assert _is_preprocessor_command(["--log-level", "debug", "preprocessor", "sample.c"])
    assert _is_preprocessor_command(["--log-level=debug", "preprocessor", "sample.c"])
    assert _is_preprocessor_command(["--log-file", "cgull.log", "preprocessor", "sample.c"])
    assert _is_preprocessor_command(["--log-file=cgull.log", "preprocessor", "sample.c"])
    assert _is_preprocessor_command(
        ["-vv", "--log-level", "trace", "--log-file", "cgull.log", "preprocessor", "sample.c"]
    )


def test_preprocessor_routing_preserves_legacy_path_shorthand():
    assert not _is_preprocessor_command(["source.c"])
    assert not _is_preprocessor_command(["-v", "source.c"])
    assert not _is_preprocessor_command(["--", "preprocessor"])
