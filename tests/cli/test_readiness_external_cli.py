"""External admission works through both full and isolated portable CLI routes."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest
from test_readiness_cli import ROOT, _support_modules, _tree_bytes


@pytest.mark.parametrize("extra", [(), ("--validation-receipt", "receipt.json")])
def test_external_cli_full_isolated_portable_parity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, extra: tuple[str, ...]
) -> None:
    inputs, _ = _support_modules(monkeypatch)
    source = inputs._make_verified_inputs(tmp_path, limitations=None)
    report = tmp_path / "external.md"
    report.write_text(source.report_text, encoding="utf-8")
    full_run = tmp_path / "full"
    portable_run = tmp_path / "portable"
    common = [
        "eval-readiness-init",
        "--baseline-run",
        str(source.baseline_run_dir),
        "--qualification-run",
        str(source.qualification_run_dir),
        "--external-report",
        str(report),
        *extra,
    ]
    results = []
    for script, flags, run in (
        ("attorney_eval_full.py", [], full_run),
        ("harvest_portable.py", ["-I", "-S"], portable_run),
    ):
        results.append(
            subprocess.run(
                [
                    sys.executable,
                    *flags,
                    str(ROOT / "scripts" / script),
                    *common,
                    "--run",
                    str(run),
                ],
                check=False,
                capture_output=True,
                cwd=ROOT,
            )
        )
    full, portable = results
    assert (full.returncode, full.stdout, full.stderr) == (
        portable.returncode,
        portable.stdout,
        portable.stderr,
    )
    assert full.returncode == (2 if extra else 0)
    assert _tree_bytes(full_run) == _tree_bytes(portable_run)
    if extra:
        assert not full_run.exists() and not portable_run.exists()
