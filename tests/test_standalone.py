"""The unit works from a checkout of its own directory alone, as Copybara exports it."""

from __future__ import annotations

import ast
import os
import shutil
import subprocess
import sys
from pathlib import Path

UNIT = Path(__file__).resolve().parents[1]


def _escapes(path: Path) -> set[tuple[str, str]]:
    """`(file, function)` for every `.parents[n >= 2]` or `../..` in *path*."""
    found = set()

    def visit(node: ast.AST, function: str) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            function = node.name
        escapes = (
            isinstance(node, ast.Subscript)
            and isinstance(node.value, ast.Attribute)
            and node.value.attr == "parents"
            and not (isinstance(node.slice, ast.Constant) and node.slice.value in (0, 1))
        ) or (
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and "../.." in node.value
        )
        if escapes:
            found.add((path.relative_to(UNIT).as_posix(), function))
        for child in ast.iter_child_nodes(node):
            visit(child, function)

    visit(ast.parse(path.read_text(encoding="utf-8")), "<module>")
    return found


def test_nothing_reads_outside_the_unit() -> None:
    escapes = set().union(
        *(
            _escapes(path)
            for path in UNIT.rglob("*.py")
            if ".local" not in path.parts and path != Path(__file__).resolve()
        )
    )
    assert escapes == set()


def test_the_test_suite_passes_in_a_copy_of_the_unit_alone(tmp_path: Path) -> None:
    copy = tmp_path / "cage-init"
    shutil.copytree(
        UNIT,
        copy,
        ignore=shutil.ignore_patterns(".local", "__pycache__", ".pytest_cache", "dist"),
    )
    # A standalone checkout is a Git clone: releases are packaged from what it tracks.
    for argv in (
        ["init", "-q"],
        ["add", "-A"],
        ["-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "copy"],
    ):
        subprocess.run(["git", *argv], cwd=copy, check=True, capture_output=True)
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "-p",
            "no:cacheprovider",
            f"--basetemp={tmp_path / 'basetemp'}",
            # Never this module: the copy must not copy itself again.
            f"--ignore={copy / 'tests' / 'test_standalone.py'}",
            str(copy / "tests"),
        ],
        cwd=copy,
        # A standalone checkout has no harness: drop the harness's
        # PYTEST_ADDOPTS, whose `--basetemp` is a parent of this copy and
        # which pytest refuses even when overridden on the command line.
        env={
            **{key: value for key, value in os.environ.items() if key != "PYTEST_ADDOPTS"},
            "PYTHONDONTWRITEBYTECODE": "1",
        },
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout[-4000:] + result.stderr[-2000:]
