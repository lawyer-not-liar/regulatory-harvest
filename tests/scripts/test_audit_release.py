import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[2]
AUDIT_SCRIPT = ROOT / "scripts" / "audit_release.py"


def _init_repo(path: Path, files: dict[str, str]) -> None:
    subprocess.run(["git", "init", "-q", str(path)], check=True)
    for relative_path, content in files.items():
        target = path / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    subprocess.run(["git", "-C", str(path), "add", "."], check=True)


def _run_audit(path: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(AUDIT_SCRIPT), "--repo", str(path), "--json"],
        check=False,
        capture_output=True,
        text=True,
    )


@pytest.mark.parametrize(
    ("relative_path", "content", "expected_code"),
    [
        (
            "settings.txt",
            "OPENAI_API_KEY=sk-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
            "SECRET_PATTERN",
        ),
        (
            "settings.txt",
            "callback=http://" + "127.0.0.1/admin\n",
            "PRIVATE_NETWORK_URL",
        ),
        (
            "notes.txt",
            "source=/" + "Users/example/private.txt\n",
            "ABSOLUTE_HOME_PATH",
        ),
        (
            "notes.txt",
            "legacy project: " + "OLAA" + "LA\n",
            "LEGACY_INTERNAL_IDENTIFIER",
        ),
        (
            "workflow.json",
            '{"nodes": [], "connections": {}, "active": false}\n',
            "N8N_WORKFLOW_EXPORT",
        ),
        ("tests/fixtures/unlicensed.txt", "synthetic fixture\n", "UNLICENSED_FIXTURE"),
        ("runs/demo/bundle.json", "{}\n", "GENERATED_EXPORT"),
    ],
)
def test_audit_reports_stable_codes_without_echoing_sensitive_content(
    tmp_path: Path,
    relative_path: str,
    content: str,
    expected_code: str,
) -> None:
    """Removing a release check must expose the corresponding unsafe tracked input."""
    _init_repo(tmp_path, {relative_path: content})

    result = _run_audit(tmp_path)

    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert expected_code in {
        finding["code"] for finding in payload["automated_findings"]
    }
    assert content.strip() not in result.stdout
    assert content.strip() not in result.stderr


def test_audit_accepts_licensed_synthetic_fixtures_and_keeps_manual_gate(
    tmp_path: Path,
) -> None:
    """Treating the publication gate as automated would falsely authorize a release."""
    _init_repo(
        tmp_path,
        {
            "README.md": "# Clean test repository\n",
            "tests/fixtures/FIXTURE_LICENSE.md": "Synthetic fixture; CC0-1.0.\n",
            "tests/fixtures/example.txt": "Synthetic public rule.\n",
        },
    )

    result = _run_audit(tmp_path)

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["ok"] is True
    assert payload["automated_findings"] == []
    assert [item["code"] for item in payload["manual_requirements"]] == [
        "MANUAL_CONFIRMATION_REQUIRED"
    ]


def test_audit_exception_allows_only_the_exact_synthetic_sentinel(
    tmp_path: Path,
) -> None:
    """A file-level exception must not hide a different credential in the same file."""
    allowed = "sk-" + "a" * 48
    unexpected = "sk-" + "b" * 48
    _init_repo(
        tmp_path,
        {
            "tests/scripts/test_audit_release.py": (
                f'allowed = "{allowed}"\nunexpected = "{unexpected}"\n'
            )
        },
    )

    result = _run_audit(tmp_path)
    payload = json.loads(result.stdout)

    assert result.returncode == 1
    assert [item["code"] for item in payload["automated_findings"]] == [
        "SECRET_PATTERN"
    ]


def test_current_repository_has_no_automated_release_audit_findings() -> None:
    """Adding private or unlicensed material to the release must fail the repository audit."""
    result = _run_audit(ROOT)

    assert result.returncode == 0, result.stdout
    payload = json.loads(result.stdout)
    assert payload["automated_findings"] == []
    assert [item["code"] for item in payload["manual_requirements"]] == [
        "MANUAL_CONFIRMATION_REQUIRED"
    ]
