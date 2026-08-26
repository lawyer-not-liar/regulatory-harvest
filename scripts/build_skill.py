#!/usr/bin/env python3
"""Build one reproducible Agent Skill archive for Codex and Claude."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import zipfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
ARCHIVE_ROOT = "regulatory-harvest"
FIXED_TIME = (1980, 1, 1, 0, 0, 0)
PACKAGE_MANIFEST = ROOT / "scripts" / "skill-package-files.txt"
GUARDED_TREES = ("agents", "assets", "references", "src/regulatory_harvest")
V21_ARCHIVE_REQUIREMENTS = frozenset(
    {
        "assets/attorney-evaluation-v21-response.template.json",
        "src/regulatory_harvest/evaluation/attorney_protocol.py",
        "src/regulatory_harvest/evaluation/attorney_v21_artifacts.py",
        "src/regulatory_harvest/evaluation/attorney_v21_compiler.py",
        "src/regulatory_harvest/evaluation/attorney_v21_models.py",
        "src/regulatory_harvest/evaluation/attorney_v21_requests.py",
        "src/regulatory_harvest/evaluation/attorney_v21_rubric.py",
        "src/regulatory_harvest/evaluation/attorney_v21_workflow.py",
    }
)
V22_ARCHIVE_REQUIREMENTS = frozenset(
    {
        "assets/attorney-evaluation-v22-response.template.json",
        "src/regulatory_harvest/evaluation/attorney_v22_artifacts.py",
        "src/regulatory_harvest/evaluation/attorney_v22_compiler.py",
        "src/regulatory_harvest/evaluation/attorney_v22_drafts.py",
        "src/regulatory_harvest/evaluation/attorney_v22_models.py",
        "src/regulatory_harvest/evaluation/attorney_v22_requests.py",
        "src/regulatory_harvest/evaluation/attorney_v22_workflow.py",
    }
)
BASELINE_ARCHIVE_REQUIREMENTS = frozenset(
    {
        "assets/attorney-evaluation-baseline-correction.template.json",
        "assets/attorney-evaluation-baseline-input.template.json",
        "assets/attorney-evaluation-baseline-response.template.json",
        "assets/evaluation-baseline-policy-v1.json",
        "src/regulatory_harvest/evaluation/attorney_baseline_artifacts.py",
        "src/regulatory_harvest/evaluation/attorney_baseline_compiler.py",
        "src/regulatory_harvest/evaluation/attorney_baseline_input.py",
        "src/regulatory_harvest/evaluation/attorney_baseline_models.py",
        "src/regulatory_harvest/evaluation/attorney_baseline_projection.py",
        "src/regulatory_harvest/evaluation/attorney_baseline_requests.py",
        "src/regulatory_harvest/evaluation/attorney_baseline_workflow.py",
    }
)
BASELINE_CANONICAL_JSON_INPUTS = frozenset(
    path for path in BASELINE_ARCHIVE_REQUIREMENTS if path.startswith("assets/")
)
READINESS_ARCHIVE_REQUIREMENTS = frozenset(
    {
        "README.md",
        "SKILL.md",
        "assets/attorney-delivery-readiness-input.template.json",
        "assets/attorney-delivery-readiness-response.template.json",
        "docs/evaluation.md",
        "references/attorney-evaluation.md",
        "references/security-and-privacy.md",
        "scripts/attorney_eval_full.py",
        "scripts/attorney_eval_portable.py",
        "scripts/harvest_portable.py",
        "scripts/harvest_skill.py",
        "src/regulatory_harvest/evaluation/attorney_readiness_artifacts.py",
        "src/regulatory_harvest/evaluation/attorney_readiness_compiler.py",
        "src/regulatory_harvest/evaluation/attorney_readiness_drafts.py",
        "src/regulatory_harvest/evaluation/attorney_readiness_handoff.py",
        "src/regulatory_harvest/evaluation/attorney_readiness_inputs.py",
        "src/regulatory_harvest/evaluation/attorney_readiness_models.py",
        "src/regulatory_harvest/evaluation/attorney_readiness_requests.py",
        "src/regulatory_harvest/evaluation/attorney_readiness_workflow.py",
        "src/regulatory_harvest/evaluation/readiness-rubric-v1.json",
    }
)
READINESS_CANONICAL_JSON_INPUTS = frozenset(
    {
        "assets/attorney-delivery-readiness-input.template.json",
        "assets/attorney-delivery-readiness-response.template.json",
        "src/regulatory_harvest/evaluation/readiness-rubric-v1.json",
    }
)


class SkillBuildError(RuntimeError):
    """The universal skill archive could not be built safely."""


def _assert_baseline_canonical_inputs() -> None:
    for relative in sorted(BASELINE_CANONICAL_JSON_INPUTS):
        data = (ROOT / relative).read_bytes()
        try:
            value = json.loads(data)
            canonical = json.dumps(
                value,
                allow_nan=False,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
            raise SkillBuildError(
                f"evaluation-baseline-v1 input is not canonical JSON: {relative}"
            ) from error
        if data != canonical:
            raise SkillBuildError(f"evaluation-baseline-v1 input is not canonical JSON: {relative}")


def _assert_readiness_canonical_inputs() -> None:
    for relative in sorted(READINESS_CANONICAL_JSON_INPUTS):
        data = (ROOT / relative).read_bytes()
        try:
            value = json.loads(data)
            canonical = json.dumps(
                value,
                allow_nan=False,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
            raise SkillBuildError(
                f"delivery-readiness-v1 input is not canonical JSON: {relative}"
            ) from error
        if data != canonical:
            raise SkillBuildError(f"delivery-readiness-v1 input is not canonical JSON: {relative}")


def _runtime_files() -> list[Path]:
    try:
        manifest_entries = PACKAGE_MANIFEST.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise SkillBuildError("skill package manifest is unavailable") from error
    if (
        not manifest_entries
        or manifest_entries != sorted(manifest_entries)
        or len(manifest_entries) != len(set(manifest_entries))
    ):
        raise SkillBuildError("skill package manifest must be nonempty, sorted, and unique")
    for entry in manifest_entries:
        path = PurePosixPath(entry)
        if path.is_absolute() or ".." in path.parts or path.as_posix() != entry:
            raise SkillBuildError("skill package manifest contains an unsafe path")

    paths = [ROOT / entry for entry in manifest_entries]
    expected = set(manifest_entries)
    missing_v21 = sorted(V21_ARCHIVE_REQUIREMENTS - expected)
    if missing_v21:
        raise SkillBuildError(
            f"skill package manifest is missing Protocol 2.1 input: {missing_v21[0]}"
        )
    missing_v22 = sorted(V22_ARCHIVE_REQUIREMENTS - expected)
    if missing_v22:
        raise SkillBuildError(
            f"skill package manifest is missing Protocol 2.2 input: {missing_v22[0]}"
        )
    missing_baseline = sorted(BASELINE_ARCHIVE_REQUIREMENTS - expected)
    if missing_baseline:
        raise SkillBuildError(
            f"skill package manifest is missing evaluation-baseline-v1 input: {missing_baseline[0]}"
        )
    missing_readiness = sorted(READINESS_ARCHIVE_REQUIREMENTS - expected)
    if missing_readiness:
        raise SkillBuildError(
            f"skill package manifest is missing delivery-readiness-v1 input: {missing_readiness[0]}"
        )
    discovered: set[str] = set()
    for relative in GUARDED_TREES:
        tree = ROOT / relative
        if not tree.is_dir() or tree.is_symlink():
            raise SkillBuildError(f"required runtime tree is unavailable: {relative}")
        for path in tree.rglob("*"):
            if "__pycache__" in path.parts or path.suffix in {".pyc", ".pyo"}:
                continue
            if path.is_symlink():
                raise SkillBuildError("runtime archive inputs must not be symbolic links")
            if path.is_file():
                discovered.add(path.relative_to(ROOT).as_posix())
    unexpected = sorted(discovered - expected)
    if unexpected:
        raise SkillBuildError(f"unexpected runtime file is not allowlisted: {unexpected[0]}")
    missing = [path.relative_to(ROOT).as_posix() for path in paths if not path.is_file()]
    if missing:
        raise SkillBuildError(f"required runtime file is unavailable: {missing[0]}")
    if any(path.is_symlink() for path in paths):
        raise SkillBuildError("runtime archive inputs must not be symbolic links")
    _assert_baseline_canonical_inputs()
    _assert_readiness_canonical_inputs()
    return sorted(set(paths), key=lambda path: path.relative_to(ROOT).as_posix())


def build_skill(output: Path) -> dict[str, object]:
    output = output.expanduser().resolve(strict=False)
    if output.exists() and not output.is_file():
        raise SkillBuildError("output path must be a ZIP file")
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(f".{output.name}.tmp")
    files = _runtime_files()
    try:
        with zipfile.ZipFile(
            temporary,
            mode="w",
            compression=zipfile.ZIP_DEFLATED,
            compresslevel=9,
        ) as archive:
            for path in files:
                relative = path.relative_to(ROOT).as_posix()
                info = zipfile.ZipInfo(f"{ARCHIVE_ROOT}/{relative}", FIXED_TIME)
                info.compress_type = zipfile.ZIP_DEFLATED
                info.create_system = 3
                mode = 0o755 if relative == "scripts/harvest_skill.py" else 0o644
                info.external_attr = mode << 16
                archive.writestr(info, path.read_bytes(), compresslevel=9)
        os.replace(temporary, output)
    finally:
        temporary.unlink(missing_ok=True)
    data = output.read_bytes()
    return {
        "archive": str(output),
        "file_count": len(files),
        "root": ARCHIVE_ROOT,
        "sha256": hashlib.sha256(data).hexdigest(),
        "size_bytes": len(data),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        receipt = build_skill(args.output)
    except (OSError, SkillBuildError) as error:
        sys.stderr.write(json.dumps({"code": "SKILL_BUILD_FAILED", "message": str(error)}) + "\n")
        return 1
    print(json.dumps(receipt, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
