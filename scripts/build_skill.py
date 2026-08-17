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


class SkillBuildError(RuntimeError):
    """The universal skill archive could not be built safely."""


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
