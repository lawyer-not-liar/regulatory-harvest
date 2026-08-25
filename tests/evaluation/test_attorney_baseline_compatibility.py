"""Retained-byte and Protocol 2.1 default compatibility gates."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
TAG = "v0.1.0-beta.8"
FULL_RUNNER = ROOT / "scripts" / "harvest_skill.py"
PORTABLE_RUNNER = ROOT / "scripts" / "harvest_portable.py"
V21_CASE = ROOT / "tests" / "fixtures" / "attorney-eval-v21" / "stable" / "case.json"
RETAINED_FIXTURE_ROOTS = (
    "tests/fixtures/attorney-eval",
    "tests/fixtures/attorney-eval-v2",
    "tests/fixtures/attorney-eval-v21",
    "tests/fixtures/attorney-eval-v22",
)
TEMPLATE_HASHES = {
    "assets/attorney-evaluation-response.template.json": (
        "774af5d3f5a2126c04190c3559e2cad9ba61ee677b0f85b67e0825ce97ed38d7"
    ),
    "assets/attorney-evaluation-v2-response.template.json": (
        "6196f39634dc550fb03804ca3a550746f255981ff2103c11247f7fbb92cea00f"
    ),
    "assets/attorney-evaluation-v21-response.template.json": (
        "f02dc3c539816af51f6ab0fa709844a22af1041528a43018488b631aacd44955"
    ),
    "assets/attorney-evaluation-v22-response.template.json": (
        "f62f2215d79cb417234939ab33f3b9ab13efc39d211daade273f9e3e8ca1a949"
    ),
}


def _git(*args: str) -> bytes:
    return subprocess.run(
        ["git", *args],
        cwd=ROOT,
        check=True,
        capture_output=True,
    ).stdout


def _tree(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def _run(
    runner: Path,
    *args: str,
) -> tuple[int, str, str]:
    command = [sys.executable]
    if runner == PORTABLE_RUNNER:
        command.extend(("-I", "-S"))
    completed = subprocess.run(
        [*command, str(runner), *args],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
    )
    return completed.returncode, completed.stdout, completed.stderr


@pytest.mark.parametrize("path", sorted(TEMPLATE_HASHES))
def test_retained_response_template_bytes_match_beta8_exactly(path: str) -> None:
    current = (ROOT / path).read_bytes()
    assert hashlib.sha256(current).hexdigest() == TEMPLATE_HASHES[path]
    assert current == _git("show", f"{TAG}:{path}")


def test_every_retained_fixture_byte_and_path_matches_beta8() -> None:
    current = set(
        _git("ls-files", "--", *RETAINED_FIXTURE_ROOTS).decode().splitlines()
    )
    retained = set(
        _git("ls-tree", "-r", "--name-only", TAG, "--", *RETAINED_FIXTURE_ROOTS)
        .decode()
        .splitlines()
    )
    assert current == retained
    assert current
    for path in sorted(current):
        assert (ROOT / path).read_bytes() == _git("show", f"{TAG}:{path}")


def test_eval_init_default_remains_protocol_21_with_exact_full_portable_behavior(
    tmp_path: Path,
) -> None:
    invalid = tmp_path / "invalid.json"
    invalid.write_bytes(b"[]")
    runs = {
        "full-default": (FULL_RUNNER, ()),
        "full-explicit": (FULL_RUNNER, ("--protocol", "2.1")),
        "portable-default": (PORTABLE_RUNNER, ()),
        "portable-explicit": (PORTABLE_RUNNER, ("--protocol", "2.1")),
    }
    transcripts: dict[str, list[tuple[int, str, str]]] = {}
    pending_trees: dict[str, dict[str, bytes]] = {}
    for name, (runner, protocol_args) in runs.items():
        run = tmp_path / name
        transcript = [
            _run(
                runner,
                "eval-init",
                *protocol_args,
                "--case",
                str(V21_CASE),
                "--run",
                str(run),
                "--seed-hex",
                "0" * 64,
            )
        ]
        assert transcript[0][0] == 0, transcript[0]
        state = json.loads(transcript[0][1])
        assert state["schema_version"] == "2.1"
        before = _tree(run)
        transcript.extend(
            (
                _run(runner, "eval-status", "--run", str(run)),
                _run(runner, "eval-verify", "--run", str(run)),
                _run(
                    runner,
                    "eval-submit-safe",
                    "--run",
                    str(run),
                    "--response",
                    str(invalid),
                ),
            )
        )
        assert _tree(run) == before
        transcripts[name] = transcript
        pending_trees[name] = before

    assert len({tuple(value) for value in transcripts.values()}) == 1
    first_tree = next(iter(pending_trees.values()))
    assert all(tree == first_tree for tree in pending_trees.values())
