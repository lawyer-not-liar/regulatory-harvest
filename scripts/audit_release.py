#!/usr/bin/env python3
"""Audit release candidates and built archives for clean-room hazards."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import stat
import subprocess
import sys
import unicodedata
import zipfile
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from typing import Final
from urllib.parse import urlsplit


@dataclass(frozen=True, order=True)
class Finding:
    code: str
    path: str
    line: int
    message: str


MANUAL_REQUIREMENTS: Final = [
    {
        "code": "MANUAL_CONFIRMATION_REQUIRED",
        "message": (
            "The repository owner must independently confirm ownership and publication "
            "authorization before creating a public remote."
        ),
    }
]

SECRET_PATTERNS: Final = (
    re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(
        r"(?im)^\s*[A-Z0-9_]*(?:API_KEY|PASSWORD|SECRET|TOKEN)\s*[:=]\s*"
        r"[\"']?[A-Za-z0-9_./+\-=]{16,}[\"']?\s*$"
    ),
)
URL_PATTERN: Final = re.compile(r"https?://[^\s<>'\"]+", re.IGNORECASE)
ABSOLUTE_HOME_PATTERNS: Final = (
    re.compile("/" + r"Users/[^/\s\"']+/"),
    re.compile("/" + r"home/[^/\s\"']+/"),
    re.compile(r"(?i)\b[A-Z]:\\Users\\[^\\\s\"']+\\"),
)
LEGACY_TOKEN_PATTERN: Final = re.compile(
    r"(?<![A-Za-z0-9-])[A-Za-z][A-Za-z0-9-]{3,63}(?![A-Za-z0-9-])"
)
LEGACY_IDENTIFIER_HASHES: Final = frozenset(
    {
        "a7b1d852e2921abf74839749b0dd226c7ee4354230b98a4e3c24a4cdd64a1719",
        "f402f4fb1fe3dd587c89c434c0a19bc5d23732148a9a30a26e2d4563a70cf197",
    }
)
FIXTURE_LICENSE_NAMES: Final = ("FIXTURE_LICENSE.md", "FIXTURE_LICENSES.md")
GENERATED_DIRECTORIES: Final = frozenset({"run", "runs", "output", "outputs"})
GENERATED_FILENAMES: Final = frozenset(
    {
        "bundle.json",
        "coverage-review.json",
        "audit.md",
        "evaluation.json",
        "manifest.json",
        "receipt.json",
        "report.md",
        "result.json",
    }
)
PRIVATE_EVALUATION_FIELDS: Final = frozenset(
    {
        "harvest_label",
        "legacy_label",
        "private_record_hash",
        "private_record_id",
        "private_round",
        "report_system_mapping",
        "sealed_answer",
        "source_case_id",
    }
)
JSON_CREDENTIAL_FIELDS: Final = frozenset(
    {
        "access_token",
        "api_key",
        "client_secret",
        "password",
        "secret",
        "token",
    }
)
JSON_CREDENTIAL_COMPACT_FIELDS: Final = frozenset(
    field.replace("_", "") for field in JSON_CREDENTIAL_FIELDS
)
WINDOWS_RESERVED_NAMES: Final = frozenset(
    {
        "aux",
        "con",
        "nul",
        "prn",
        *(f"com{number}" for number in range(1, 10)),
        *(f"lpt{number}" for number in range(1, 10)),
    }
)
MAX_PRIVATE_MARKER_FILE_BYTES: Final = 1024 * 1024
MAX_ARCHIVE_ENTRY_BYTES: Final = 32 * 1024 * 1024
MAX_ARCHIVE_TOTAL_BYTES: Final = 256 * 1024 * 1024

# These files deliberately exercise or document one exact blocked sentinel. Each
# exception includes the precise matched value; another match in the same file fails.
ALLOWLIST: Final = frozenset(
    {
        (
            "docs/superpowers/plans/2026-08-05-core-local-cli.md",
            "PRIVATE_NETWORK_URL",
            "http://" + "127.0.0.1/admin",
        ),
        (
            "docs/superpowers/plans/2026-08-05-core-local-cli.md",
            "PRIVATE_NETWORK_URL",
            "http://" + "169.254.169.254/latest/meta-data",
        ),
        (
            "tests/adapters/cite/test_client.py",
            "SECRET_PATTERN",
            'secret = "top-secret-token"',
        ),
        (
            "tests/analysis/test_report.py",
            "ABSOLUTE_HOME_PATH",
            "/" + "Users/private/",
        ),
        (
            "tests/analysis/test_report.py",
            "ABSOLUTE_HOME_PATH",
            "C:\\" + "Users\\private\\",
        ),
        (
            "tests/cli/test_cite_cli.py",
            "SECRET_PATTERN",
            'secret = "private-bearer-token"',
        ),
        (
            "tests/scripts/test_audit_release.py",
            "SECRET_PATTERN",
            "sk-" + "a" * 48,
        ),
        (
            "tests/sources/test_fetch.py",
            "PRIVATE_NETWORK_URL",
            "http://" + "127.0.0.1/private",
        ),
        (
            "tests/sources/test_security.py",
            "PRIVATE_NETWORK_URL",
            "http://" + "127.0.0.1/admin",
        ),
        (
            "tests/sources/test_security.py",
            "PRIVATE_NETWORK_URL",
            "http://" + "[::1]/admin",
        ),
        (
            "tests/sources/test_security.py",
            "PRIVATE_NETWORK_URL",
            "http://" + "169.254.169.254/latest/meta-data",
        ),
        (
            "tests/sources/test_security.py",
            "PRIVATE_NETWORK_URL",
            "https://" + "user:pass@198.51.100.10/rule",
        ),
    }
)


class AuditError(RuntimeError):
    """The repository could not be audited reliably."""


class DuplicateJSONKeyError(ValueError):
    """A JSON object repeated a member name."""


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise DuplicateJSONKeyError
        value[key] = item
    return value


def _load_unique_json(text: str) -> object:
    return json.loads(text, object_pairs_hook=_unique_json_object)


def _tracked_paths(repo: Path) -> list[str]:
    result = subprocess.run(
        [
            "git",
            "-C",
            str(repo),
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
        ],
        check=False,
        capture_output=True,
    )
    if result.returncode != 0:
        raise AuditError("git could not enumerate candidate files")
    return sorted(path.decode("utf-8") for path in result.stdout.split(b"\0") if path)


def _read_text(repo: Path, relative_path: str) -> str | None:
    target = repo / relative_path
    try:
        data = os.readlink(target).encode("utf-8") if target.is_symlink() else target.read_bytes()
    except (OSError, UnicodeEncodeError) as error:
        raise AuditError(f"release candidate file could not be read: {relative_path}") from error
    if b"\0" in data:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _finding(
    code: str,
    path: str,
    line: int,
    message: str,
    matched_value: str = "",
) -> Finding | None:
    if (path, code, matched_value) in ALLOWLIST:
        return None
    return Finding(code=code, path=path, line=line, message=message)


def _scan_secrets(path: str, text: str) -> list[Finding]:
    findings: list[Finding] = []
    for pattern in SECRET_PATTERNS:
        for match in pattern.finditer(text):
            finding = _finding(
                "SECRET_PATTERN",
                path,
                _line_number(text, match.start()),
                "Release content matches a credential or private-key pattern.",
                match.group(0).strip(),
            )
            if finding is not None:
                findings.append(finding)
    return findings


def _is_private_host(host: str) -> bool:
    normalized = host.rstrip(".").lower()
    if normalized == "localhost" or normalized.endswith((".local", ".internal")):
        return True
    try:
        return not ipaddress.ip_address(normalized).is_global
    except ValueError:
        return False


def _scan_private_urls(path: str, text: str) -> list[Finding]:
    findings: list[Finding] = []
    for match in URL_PATTERN.finditer(text):
        matched_url = match.group(0).rstrip(".,);]")
        host = urlsplit(matched_url).hostname
        if host is None or not _is_private_host(host):
            continue
        finding = _finding(
            "PRIVATE_NETWORK_URL",
            path,
            _line_number(text, match.start()),
            "Release content contains a URL for a private or non-global host.",
            matched_url,
        )
        if finding is not None:
            findings.append(finding)
    return findings


def _scan_home_paths(path: str, text: str) -> list[Finding]:
    findings: list[Finding] = []
    for pattern in ABSOLUTE_HOME_PATTERNS:
        for match in pattern.finditer(text):
            finding = _finding(
                "ABSOLUTE_HOME_PATH",
                path,
                _line_number(text, match.start()),
                "Release content contains an absolute user-home path.",
                match.group(0),
            )
            if finding is not None:
                findings.append(finding)
    return findings


def _scan_legacy_identifiers(path: str, text: str) -> list[Finding]:
    findings: list[Finding] = []
    for match in LEGACY_TOKEN_PATTERN.finditer(text):
        identifier = match.group(0)
        digest = hashlib.sha256(identifier.encode("utf-8")).hexdigest()
        if digest not in LEGACY_IDENTIFIER_HASHES:
            continue
        finding = _finding(
            "LEGACY_INTERNAL_IDENTIFIER",
            path,
            _line_number(text, match.start()),
            "Release content contains a prohibited legacy or internal project identifier.",
            identifier,
        )
        if finding is not None:
            findings.append(finding)
    return findings


def _scan_workflow_export(path: str, text: str) -> list[Finding]:
    if not path.lower().endswith(".json"):
        return []
    try:
        payload = _load_unique_json(text)
    except (json.JSONDecodeError, DuplicateJSONKeyError, RecursionError):
        return []
    is_export = (
        isinstance(payload, dict)
        and isinstance(payload.get("nodes"), list)
        and isinstance(payload.get("connections"), dict)
        and ("active" in payload or "settings" in payload)
    )
    if not is_export:
        return []
    finding = _finding(
        "N8N_WORKFLOW_EXPORT",
        path,
        1,
        "Release JSON has the structural fingerprint of an n8n workflow export.",
    )
    return [] if finding is None else [finding]


def _private_json_fields(value: object) -> set[str]:
    fields: set[str] = set()
    pending = [value]
    while pending:
        current = pending.pop()
        if isinstance(current, dict):
            fields.update(str(key) for key in current if key in PRIVATE_EVALUATION_FIELDS)
            pending.extend(current.values())
        elif isinstance(current, list):
            pending.extend(current)
    return fields


def _scan_private_evaluation_fields(path: str, text: str) -> list[Finding]:
    if not path.lower().endswith(".json"):
        return []
    try:
        payload = _load_unique_json(text)
    except (json.JSONDecodeError, DuplicateJSONKeyError, RecursionError):
        return []
    findings: list[Finding] = []
    for field in sorted(_private_json_fields(payload)):
        offset = text.find(json.dumps(field))
        findings.append(
            Finding(
                code="PRIVATE_EVALUATION_MARKER",
                path=path,
                line=_line_number(text, max(offset, 0)),
                message=(
                    "Release content contains a structural field reserved for private "
                    "evaluation records or report-to-system mappings."
                ),
            )
        )
    return findings


def _normalized_json_key(key: object) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(key).casefold()).strip("_")


def _json_value_is_present(value: object) -> bool:
    return value is not None and value != "" and value != [] and value != {}


def _scan_decoded_json(
    path: str,
    text: str,
    markers: tuple[str, ...],
) -> list[Finding]:
    if not path.lower().endswith(".json"):
        return []
    try:
        payload = _load_unique_json(text)
    except (json.JSONDecodeError, DuplicateJSONKeyError, RecursionError):
        return []

    findings: list[Finding] = []
    pending = [payload]
    while pending:
        current = pending.pop()
        if isinstance(current, dict):
            for key, value in current.items():
                normalized_key = _normalized_json_key(key)
                if (
                    (
                        normalized_key in JSON_CREDENTIAL_FIELDS
                        or normalized_key.replace("_", "")
                        in JSON_CREDENTIAL_COMPACT_FIELDS
                    )
                    and _json_value_is_present(value)
                ):
                    encoded_key = json.dumps(str(key), ensure_ascii=False)
                    offset = text.find(encoded_key)
                    finding = _finding(
                        "SECRET_PATTERN",
                        path,
                        _line_number(text, max(offset, 0)),
                        "Release JSON contains a populated credential field.",
                    )
                    if finding is not None:
                        findings.append(finding)
                encoded_key = json.dumps(str(key), ensure_ascii=False)
                key_line = _line_number(text, max(text.find(encoded_key), 0))
                for finding in _scan_external_private_markers(path, str(key), markers):
                    findings.append(
                        Finding(
                            code=finding.code,
                            path=finding.path,
                            line=key_line,
                            message=finding.message,
                        )
                    )
                pending.append(value)
        elif isinstance(current, list):
            pending.extend(current)
        elif isinstance(current, str):
            encoded_value = json.dumps(current, ensure_ascii=False)
            offset = text.find(encoded_value)
            source_line = _line_number(text, max(offset, 0))
            for scanner in (
                _scan_secrets,
                _scan_private_urls,
                _scan_home_paths,
                _scan_legacy_identifiers,
            ):
                for finding in scanner(path, current):
                    findings.append(
                        Finding(
                            code=finding.code,
                            path=finding.path,
                            line=source_line,
                            message=finding.message,
                        )
                    )
            for finding in _scan_external_private_markers(path, current, markers):
                findings.append(
                    Finding(
                        code=finding.code,
                        path=finding.path,
                        line=source_line,
                        message=finding.message,
                    )
                )
    return findings


def _scan_external_private_markers(
    path: str,
    text: str,
    markers: tuple[str, ...],
) -> list[Finding]:
    findings: list[Finding] = []
    for marker in markers:
        offset = text.find(marker)
        if offset < 0:
            continue
        findings.append(
            Finding(
                code="PRIVATE_EVALUATION_MARKER",
                path=path,
                line=_line_number(text, offset),
                message="Release content matches a locally supplied private-evaluation marker.",
            )
        )
    return findings


def _scan_duplicate_json_keys(path: str, text: str) -> list[Finding]:
    if not path.lower().endswith(".json"):
        return []
    try:
        _load_unique_json(text)
    except DuplicateJSONKeyError:
        return [
            Finding(
                code="DUPLICATE_JSON_KEY",
                path=path,
                line=1,
                message="Release JSON repeats an object member name.",
            )
        ]
    except (json.JSONDecodeError, RecursionError):
        return []
    return []


def _load_private_markers(path: Path | None, *, repo: Path) -> tuple[str, ...]:
    if path is None:
        return ()
    expanded = path.expanduser()
    if expanded.is_symlink():
        raise AuditError("private marker file must be a regular file outside the repository")
    try:
        resolved = expanded.resolve(strict=True)
        if resolved.is_relative_to(repo) or not resolved.is_file():
            raise AuditError("private marker file must be a regular file outside the repository")
        data = resolved.read_bytes()
    except OSError as error:
        raise AuditError("private marker file is unavailable") from error
    if len(data) > MAX_PRIVATE_MARKER_FILE_BYTES or b"\0" in data:
        raise AuditError("private marker file is invalid")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise AuditError("private marker file is invalid") from error
    markers = tuple(sorted({line for line in text.splitlines() if line}))
    if not markers or any(len(marker) < 4 or marker != marker.strip() for marker in markers):
        raise AuditError("private marker file is invalid")
    return markers


def _scan_text(path: str, text: str, markers: tuple[str, ...]) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(_scan_secrets(path, text))
    findings.extend(_scan_private_urls(path, text))
    findings.extend(_scan_home_paths(path, text))
    findings.extend(_scan_legacy_identifiers(path, text))
    findings.extend(_scan_duplicate_json_keys(path, text))
    findings.extend(_scan_workflow_export(path, text))
    findings.extend(_scan_private_evaluation_fields(path, text))
    findings.extend(_scan_decoded_json(path, text, markers))
    findings.extend(_scan_external_private_markers(path, text, markers))
    return findings


def _fixture_is_licensed(path: PurePosixPath, tracked: set[str]) -> bool:
    try:
        fixture_index = path.parts.index("fixtures")
    except ValueError:
        return True
    fixture_root = PurePosixPath(*path.parts[: fixture_index + 1])
    directory = path.parent
    while True:
        if any(str(directory / name) in tracked for name in FIXTURE_LICENSE_NAMES):
            return True
        if directory == fixture_root:
            return False
        directory = directory.parent


def _scan_path(path: str, tracked: set[str]) -> list[Finding]:
    pure_path = PurePosixPath(path)
    findings: list[Finding] = []
    if (
        "fixtures" in pure_path.parts
        and pure_path.name not in FIXTURE_LICENSE_NAMES
        and not _fixture_is_licensed(pure_path, tracked)
    ):
        finding = _finding(
            "UNLICENSED_FIXTURE",
            path,
            1,
            "Release fixture has no license manifest in its fixture tree.",
        )
        if finding is not None:
            findings.append(finding)
    if (
        GENERATED_DIRECTORIES.intersection(pure_path.parts[:-1])
        and pure_path.name in GENERATED_FILENAMES
    ):
        finding = _finding(
            "GENERATED_EXPORT",
            path,
            1,
            "Release run output appears to be a prohibited generated export.",
        )
        if finding is not None:
            findings.append(finding)
    return findings


def audit_repository(repo: Path, *, markers: tuple[str, ...] = ()) -> list[Finding]:
    repo = repo.resolve()
    paths = _tracked_paths(repo)
    tracked = set(paths)
    findings: list[Finding] = []
    for path in paths:
        findings.extend(_scan_path(path, tracked))
        text = _read_text(repo, path)
        if text is None:
            continue
        findings.extend(_scan_text(path, text, markers))
    return sorted(set(findings))


def audit_archive(path: Path, *, markers: tuple[str, ...] = ()) -> list[Finding]:
    expanded = path.expanduser()
    if expanded.is_symlink():
        raise AuditError("release archive must be a regular ZIP file")
    try:
        resolved = expanded.resolve(strict=True)
    except OSError as error:
        raise AuditError("release archive is unavailable") from error
    if not resolved.is_file():
        raise AuditError("release archive must be a regular ZIP file")
    findings: list[Finding] = []
    try:
        with zipfile.ZipFile(resolved) as archive:
            infos = archive.infolist()
            names = [info.filename for info in infos]
            if len(names) != len(set(names)):
                raise AuditError("release archive contains duplicate paths")
            normalized_names: set[str] = set()
            total_size = 0
            for info in infos:
                name = info.filename
                path_text = name[:-1] if name.endswith("/") else name
                segments = path_text.split("/")
                unsafe_segment = any(
                    not segment
                    or segment in {".", ".."}
                    or segment.endswith((".", " "))
                    or any(
                        unicodedata.category(character) in {"Cc", "Cf"}
                        for character in segment
                    )
                    or ":" in segment
                    or segment.split(".", 1)[0]
                    .translate(str.maketrans("¹²³", "123"))
                    .casefold()
                    in WINDOWS_RESERVED_NAMES
                    for segment in segments
                )
                drive_qualified = bool(re.match(r"(?i)^[a-z]:", path_text))
                if (
                    not path_text
                    or name.startswith("/")
                    or "\\" in name
                    or drive_qualified
                    or unsafe_segment
                    or PurePosixPath(name).as_posix() != name
                    or ((info.external_attr >> 16) & 0o170000) == stat.S_IFLNK
                ):
                    raise AuditError("release archive contains an unsafe path")
                normalized_name = "/".join(
                    unicodedata.normalize("NFC", segment).casefold() for segment in segments
                )
                if normalized_name in normalized_names:
                    raise AuditError("release archive contains an unsafe path")
                normalized_names.add(normalized_name)
                if info.file_size > MAX_ARCHIVE_ENTRY_BYTES:
                    raise AuditError("release archive contains an oversized entry")
                total_size += info.file_size
                if total_size > MAX_ARCHIVE_TOTAL_BYTES:
                    raise AuditError("release archive exceeds the expanded-size limit")
                data = archive.read(info)
                if b"\0" in data:
                    continue
                try:
                    text = data.decode("utf-8")
                except UnicodeDecodeError:
                    continue
                display_path = f"archive:{resolved.name}!/{info.filename}"
                findings.extend(_scan_text(display_path, text, markers))
    except AuditError:
        raise
    except (OSError, zipfile.BadZipFile, RuntimeError) as error:
        raise AuditError("release archive could not be inspected") from error
    return sorted(set(findings))


def _payload(findings: list[Finding]) -> dict[str, object]:
    return {
        "automated_findings": [asdict(finding) for finding in findings],
        "manual_requirements": MANUAL_REQUIREMENTS,
        "ok": not findings,
    }


def _print_human(findings: list[Finding]) -> None:
    if findings:
        print(f"Release audit found {len(findings)} automated issue(s):")
        for finding in findings:
            print(f"- {finding.code} {finding.path}:{finding.line} — {finding.message}")
    else:
        print("Release audit found no automated issues.")
    print(f"- MANUAL_CONFIRMATION_REQUIRED — {MANUAL_REQUIREMENTS[0]['message']}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--archive", action="append", default=[], type=Path)
    parser.add_argument("--private-markers", type=Path)
    parser.add_argument("--json", action="store_true", help="emit one JSON object")
    args = parser.parse_args(argv)
    try:
        try:
            repo = args.repo.expanduser().resolve(strict=True)
        except OSError as error:
            raise AuditError("repository root is unavailable") from error
        markers = _load_private_markers(args.private_markers, repo=repo)
        findings = audit_repository(repo, markers=markers)
        for archive in args.archive:
            findings.extend(audit_archive(archive, markers=markers))
        findings = sorted(set(findings))
    except AuditError as error:
        if args.json:
            print(json.dumps({"error": str(error)}, sort_keys=True))
        else:
            print(f"Release audit could not run: {error}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(_payload(findings), indent=2, sort_keys=True))
    else:
        _print_human(findings)
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
