#!/usr/bin/env python3
"""Audit tracked release files for clean-room and provenance hazards."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import subprocess
import sys
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
        "evaluation.json",
        "manifest.json",
        "receipt.json",
        "report.md",
        "result.json",
    }
)

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


def _tracked_paths(repo: Path) -> list[str]:
    result = subprocess.run(
        ["git", "-C", str(repo), "ls-files", "-z"],
        check=False,
        capture_output=True,
    )
    if result.returncode != 0:
        raise AuditError("git could not enumerate tracked files")
    return sorted(
        path.decode("utf-8") for path in result.stdout.split(b"\0") if path
    )


def _read_text(repo: Path, relative_path: str) -> str | None:
    target = repo / relative_path
    try:
        data = (
            os.readlink(target).encode("utf-8")
            if target.is_symlink()
            else target.read_bytes()
        )
    except (OSError, UnicodeEncodeError) as error:
        raise AuditError(f"tracked file could not be read: {relative_path}") from error
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
                "Tracked text matches a credential or private-key pattern.",
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
            "Tracked text contains a URL for a private or non-global host.",
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
                "Tracked text contains an absolute user-home path.",
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
            "Tracked text contains a prohibited legacy or internal project identifier.",
            identifier,
        )
        if finding is not None:
            findings.append(finding)
    return findings


def _scan_workflow_export(path: str, text: str) -> list[Finding]:
    if not path.lower().endswith(".json"):
        return []
    try:
        payload = json.loads(text)
    except (json.JSONDecodeError, RecursionError):
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
        "Tracked JSON has the structural fingerprint of an n8n workflow export.",
    )
    return [] if finding is None else [finding]


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
            "Tracked fixture has no license manifest in its fixture tree.",
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
            "Tracked run output appears to be a prohibited generated export.",
        )
        if finding is not None:
            findings.append(finding)
    return findings


def audit_repository(repo: Path) -> list[Finding]:
    repo = repo.resolve()
    paths = _tracked_paths(repo)
    tracked = set(paths)
    findings: list[Finding] = []
    for path in paths:
        findings.extend(_scan_path(path, tracked))
        text = _read_text(repo, path)
        if text is None:
            continue
        findings.extend(_scan_secrets(path, text))
        findings.extend(_scan_private_urls(path, text))
        findings.extend(_scan_home_paths(path, text))
        findings.extend(_scan_legacy_identifiers(path, text))
        findings.extend(_scan_workflow_export(path, text))
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
    print(
        "- MANUAL_CONFIRMATION_REQUIRED — "
        f"{MANUAL_REQUIREMENTS[0]['message']}"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--json", action="store_true", help="emit one JSON object")
    args = parser.parse_args(argv)
    try:
        findings = audit_repository(args.repo)
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
