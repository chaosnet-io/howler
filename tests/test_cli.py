"""
Tests for howler.parse_args — the external-mode CLI surface.

argparse wiring is easy to break silently (a renamed dest, a dropped flag),
and the whole external profile hangs off these three flags. Pin them.
"""
from __future__ import annotations

from pathlib import Path

import pytest

# parse_args lives in howler.py, which defers its heavy imports (rich/pyyaml).
# Skip if those aren't installed rather than reporting a false failure.
pytest.importorskip("rich")
pytest.importorskip("yaml")

from howler import parse_args


def test_external_flags_default_off():
    a = parse_args(["10.0.0.1"])
    assert a.external is False
    assert a.assume_up is False
    assert a.exclude_file is None


def test_external_short_and_long_flag():
    assert parse_args(["-x", "10.0.0.1"]).external is True
    assert parse_args(["--external", "10.0.0.1"]).external is True


def test_assume_up_flag():
    assert parse_args(["--assume-up", "10.0.0.1"]).assume_up is True


def test_exclude_file_is_a_path():
    a = parse_args(["--exclude-file", "/tmp/scope.txt", "10.0.0.1"])
    assert a.exclude_file == Path("/tmp/scope.txt")


def test_external_flags_compose():
    a = parse_args(["-x", "--assume-up", "--exclude-file", "scope.txt", "-f", "targets.txt"])
    assert a.external and a.assume_up
    assert a.exclude_file == Path("scope.txt")
    assert a.target_file == Path("targets.txt")
