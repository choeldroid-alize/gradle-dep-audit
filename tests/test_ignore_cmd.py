"""Tests for gradle_dep_audit.ignore_cmd."""
from __future__ import annotations

import argparse
import json
import pytest
from pathlib import Path

from gradle_dep_audit.ignore_cmd import build_ignore_parser, run_ignore, DEFAULT_IGNORE_FILE


@pytest.fixture()
def ignore_file(tmp_path) -> str:
    return str(tmp_path / ".ignore.json")


def _make_args(action: str, coordinate: str = "", reason: str = "", file: str = "") -> argparse.Namespace:
    ns = argparse.Namespace(
        ignore_action=action,
        coordinate=coordinate,
        reason=reason,
        file=file or DEFAULT_IGNORE_FILE,
    )
    return ns


def test_add_creates_entry(ignore_file):
    args = _make_args("add", "org.example:lib", reason="CVE-2024-0001 not applicable", file=ignore_file)
    rc = run_ignore(args)
    assert rc == 0
    data = json.loads(Path(ignore_file).read_text())
    assert len(data) == 1
    assert data[0]["coordinate"] == "org.example:lib"
    assert "CVE-2024-0001" in data[0]["reason"]


def test_add_duplicate_returns_error(ignore_file):
    args = _make_args("add", "org.example:lib", file=ignore_file)
    run_ignore(args)
    rc = run_ignore(args)
    assert rc == 1


def test_add_multiple_entries(ignore_file):
    run_ignore(_make_args("add", "com.google:guava", file=ignore_file))
    run_ignore(_make_args("add", "org.apache:commons-lang", file=ignore_file))
    data = json.loads(Path(ignore_file).read_text())
    assert len(data) == 2


def test_remove_existing_entry(ignore_file):
    run_ignore(_make_args("add", "org.example:lib", file=ignore_file))
    rc = run_ignore(_make_args("remove", "org.example:lib", file=ignore_file))
    assert rc == 0
    data = json.loads(Path(ignore_file).read_text())
    assert data == []


def test_remove_nonexistent_returns_error(ignore_file):
    rc = run_ignore(_make_args("remove", "does.not:exist", file=ignore_file))
    assert rc == 1


def test_list_empty(ignore_file, capsys):
    rc = run_ignore(_make_args("list", file=ignore_file))
    assert rc == 0
    out = capsys.readouterr().out
    assert "No ignore rules" in out


def test_list_shows_entries(ignore_file, capsys):
    run_ignore(_make_args("add", "com.example:foo", reason="safe", file=ignore_file))
    run_ignore(_make_args("add", "com.example:bar", file=ignore_file))
    rc = run_ignore(_make_args("list", file=ignore_file))
    assert rc == 0
    out = capsys.readouterr().out
    assert "com.example:foo" in out
    assert "safe" in out
    assert "com.example:bar" in out


def test_build_ignore_parser_registers_subcommand():
    root = argparse.ArgumentParser()
    sub = root.add_subparsers(dest="command")
    build_ignore_parser(sub)
    args = root.parse_args(["ignore", "list"])
    assert args.command == "ignore"
    assert args.ignore_action == "list"
