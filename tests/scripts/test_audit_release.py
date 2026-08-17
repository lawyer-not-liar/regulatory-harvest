import json
import subprocess
import sys
import zipfile
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


def _run_audit(path: Path, *extra: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(AUDIT_SCRIPT),
            "--repo",
            str(path),
            *extra,
            "--json",
        ],
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
        ("runs/demo/audit.md", "# Generated audit\n", "GENERATED_EXPORT"),
        ("runs/demo/coverage-review.json", "{}\n", "GENERATED_EXPORT"),
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
    assert expected_code in {finding["code"] for finding in payload["automated_findings"]}
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
    assert [item["code"] for item in payload["automated_findings"]] == ["SECRET_PATTERN"]


def test_audit_scans_untracked_nonignored_candidate_files(tmp_path: Path) -> None:
    """A pre-commit audit must not miss a newly created private file."""
    _init_repo(tmp_path, {"README.md": "# Clean test repository\n"})
    candidate = tmp_path / "private-notes.md"
    candidate.write_text("source=/" + "Users/example/private.txt\n", encoding="utf-8")

    result = _run_audit(tmp_path)
    payload = json.loads(result.stdout)

    assert result.returncode == 1
    assert [item["code"] for item in payload["automated_findings"]] == ["ABSOLUTE_HOME_PATH"]
    assert payload["automated_findings"][0]["path"] == "private-notes.md"


@pytest.mark.parametrize(
    "field",
    [
        "api_key",
        "apiKey",
        "ApiKey",
        "accessToken",
        "AccessToken",
        "clientSecret",
        "ClientSecret",
        "password",
    ],
)
def test_audit_rejects_credentials_stored_as_json_values(
    tmp_path: Path,
    field: str,
) -> None:
    """Removing decoded JSON inspection would let common credential files ship."""
    secret = "synthetic" + "credential0123456789"
    _init_repo(tmp_path, {"settings.json": json.dumps({field: secret})})

    result = _run_audit(tmp_path)
    payload = json.loads(result.stdout)

    assert result.returncode == 1
    assert {item["code"] for item in payload["automated_findings"]} == {"SECRET_PATTERN"}
    assert secret not in result.stdout
    assert secret not in result.stderr


@pytest.mark.parametrize("replacement", ["null", '""'])
def test_audit_rejects_duplicate_repository_json_keys_without_echo(
    tmp_path: Path,
    replacement: str,
) -> None:
    """A later empty duplicate must not erase a populated credential during audit."""
    secret = "synthetic" + "credential0123456789"
    content = f'{{"api_key":"{secret}","api_key":{replacement}}}'
    _init_repo(tmp_path, {"settings.json": content})

    result = _run_audit(tmp_path)
    payload = json.loads(result.stdout)

    assert result.returncode == 1
    assert "DUPLICATE_JSON_KEY" in {
        item["code"] for item in payload["automated_findings"]
    }
    assert secret not in result.stdout
    assert secret not in result.stderr


def test_audit_rejects_a_json_escaped_windows_home_path(tmp_path: Path) -> None:
    """Scanning only serialized JSON would miss decoded Windows private paths."""
    private_path = "C:\\Users\\example\\private.txt"
    _init_repo(tmp_path, {"settings.json": json.dumps({"path": private_path})})

    result = _run_audit(tmp_path)
    payload = json.loads(result.stdout)

    assert result.returncode == 1
    assert {item["code"] for item in payload["automated_findings"]} == {
        "ABSOLUTE_HOME_PATH"
    }
    assert private_path not in result.stdout
    assert private_path not in result.stderr


@pytest.mark.parametrize(
    "field",
    [
        "api_key",
        "apiKey",
        "ApiKey",
        "accessToken",
        "AccessToken",
        "clientSecret",
        "ClientSecret",
        "password",
    ],
)
def test_audit_rejects_credentials_in_json_inside_the_exact_archive(
    tmp_path: Path,
    field: str,
) -> None:
    """Scanning only repository JSON would let credentials ship in the exact ZIP."""
    secret = "synthetic" + "credential0123456789"
    _init_repo(tmp_path, {"README.md": "# Clean test repository\n"})
    archive = tmp_path / "candidate.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("regulatory-harvest/settings.json", json.dumps({field: secret}))

    result = _run_audit(tmp_path, "--archive", str(archive))
    payload = json.loads(result.stdout)

    assert result.returncode == 1
    assert {item["code"] for item in payload["automated_findings"]} == {"SECRET_PATTERN"}
    assert secret not in result.stdout
    assert secret not in result.stderr


@pytest.mark.parametrize("replacement", ["null", '""'])
def test_audit_rejects_duplicate_json_keys_inside_the_exact_archive_without_echo(
    tmp_path: Path,
    replacement: str,
) -> None:
    """The exact ZIP must reject duplicate object keys before last-value decoding."""
    secret = "synthetic" + "credential0123456789"
    _init_repo(tmp_path, {"README.md": "# Clean test repository\n"})
    archive = tmp_path / "candidate.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr(
            "regulatory-harvest/settings.json",
            f'{{"api_key":"{secret}","api_key":{replacement}}}',
        )

    result = _run_audit(tmp_path, "--archive", str(archive))
    payload = json.loads(result.stdout)

    assert result.returncode == 1
    assert "DUPLICATE_JSON_KEY" in {
        item["code"] for item in payload["automated_findings"]
    }
    assert secret not in result.stdout
    assert secret not in result.stderr


def test_audit_rejects_a_json_escaped_windows_home_path_inside_the_exact_archive(
    tmp_path: Path,
) -> None:
    """Archive scanning must inspect decoded JSON strings just like repository scanning."""
    private_path = "C:\\Users\\example\\private.txt"
    _init_repo(tmp_path, {"README.md": "# Clean test repository\n"})
    archive = tmp_path / "candidate.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr(
            "regulatory-harvest/settings.json",
            json.dumps({"path": private_path}),
        )

    result = _run_audit(tmp_path, "--archive", str(archive))
    payload = json.loads(result.stdout)

    assert result.returncode == 1
    assert {item["code"] for item in payload["automated_findings"]} == {
        "ABSOLUTE_HOME_PATH"
    }
    assert private_path not in result.stdout
    assert private_path not in result.stderr


@pytest.mark.parametrize(
    "private_field",
    [
        "private_round",
        "source_case_id",
        "legacy_label",
        "harvest_label",
        "report_system_mapping",
        "sealed_answer",
        "private_record_id",
        "private_record_hash",
    ],
)
def test_audit_rejects_structural_private_evaluation_fields(
    tmp_path: Path,
    private_field: str,
) -> None:
    """Private mappings must fail structurally without publishing their actual values."""
    _init_repo(
        tmp_path,
        {"assets/case.json": json.dumps({private_field: "synthetic-private-value"})},
    )

    result = _run_audit(tmp_path)
    payload = json.loads(result.stdout)

    assert result.returncode == 1
    assert [item["code"] for item in payload["automated_findings"]] == ["PRIVATE_EVALUATION_MARKER"]
    assert "synthetic-private-value" not in result.stdout


def test_audit_uses_an_external_private_marker_file_without_echoing_values(
    tmp_path: Path,
) -> None:
    """Real private phrases and round IDs belong in local config, never public source."""
    _init_repo(tmp_path, {"README.md": "contains synthetic-private-phrase\n"})
    marker_file = tmp_path.parent / f"{tmp_path.name}-private-markers.txt"
    marker_file.write_text("synthetic-private-phrase\n", encoding="utf-8")

    result = _run_audit(tmp_path, "--private-markers", str(marker_file))
    payload = json.loads(result.stdout)

    assert result.returncode == 1
    assert [item["code"] for item in payload["automated_findings"]] == ["PRIVATE_EVALUATION_MARKER"]
    assert "synthetic-private-phrase" not in result.stdout


@pytest.mark.parametrize(
    "marker",
    ["synthetic\\private-marker", "synthetic-private-\N{SNOWMAN}"],
)
def test_audit_matches_external_private_markers_in_decoded_repository_json(
    tmp_path: Path,
    marker: str,
) -> None:
    """Scanning only serialized JSON would miss escaped caller-supplied markers."""
    _init_repo(tmp_path, {"settings.json": json.dumps({"value": marker})})
    marker_file = tmp_path.parent / f"{tmp_path.name}-private-markers.txt"
    marker_file.write_text(f"{marker}\n", encoding="utf-8")

    result = _run_audit(tmp_path, "--private-markers", str(marker_file))
    payload = json.loads(result.stdout)

    assert result.returncode == 1
    assert {item["code"] for item in payload["automated_findings"]} == {
        "PRIVATE_EVALUATION_MARKER"
    }
    assert marker not in result.stdout
    assert marker not in result.stderr


@pytest.mark.parametrize(
    "marker",
    ["synthetic\\private-marker", "synthetic-private-\N{SNOWMAN}"],
)
def test_audit_matches_external_private_markers_in_decoded_archive_json(
    tmp_path: Path,
    marker: str,
) -> None:
    """Exact-ZIP auditing must apply private markers after JSON decoding."""
    _init_repo(tmp_path, {"README.md": "# Clean test repository\n"})
    marker_file = tmp_path.parent / f"{tmp_path.name}-private-markers.txt"
    marker_file.write_text(f"{marker}\n", encoding="utf-8")
    archive = tmp_path / "candidate.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr(
            "regulatory-harvest/settings.json",
            json.dumps({"value": marker}),
        )

    result = _run_audit(
        tmp_path,
        "--archive",
        str(archive),
        "--private-markers",
        str(marker_file),
    )
    payload = json.loads(result.stdout)

    assert result.returncode == 1
    assert {item["code"] for item in payload["automated_findings"]} == {
        "PRIVATE_EVALUATION_MARKER"
    }
    assert marker not in result.stdout
    assert marker not in result.stderr


def test_audit_rejects_a_symlinked_private_marker_file(tmp_path: Path) -> None:
    """A marker-file path must not follow a link into an unintended record."""
    _init_repo(tmp_path, {"README.md": "# Clean test repository\n"})
    actual = tmp_path.parent / f"{tmp_path.name}-actual-markers.txt"
    actual.write_text("synthetic-private-phrase\n", encoding="utf-8")
    linked = tmp_path.parent / f"{tmp_path.name}-linked-markers.txt"
    linked.symlink_to(actual)

    result = _run_audit(tmp_path, "--private-markers", str(linked))
    payload = json.loads(result.stdout)

    assert result.returncode == 2
    assert payload == {"error": "private marker file must be a regular file outside the repository"}


def test_audit_scans_the_exact_built_zip_for_private_markers(tmp_path: Path) -> None:
    """A clean source tree must not hide a private record inside the release artifact."""
    _init_repo(tmp_path, {"README.md": "# Clean test repository\n"})
    archive = tmp_path / "candidate.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr(
            "regulatory-harvest/assets/case.json",
            json.dumps({"sealed_answer": "synthetic-private-value"}),
        )

    result = _run_audit(tmp_path, "--archive", str(archive))
    payload = json.loads(result.stdout)

    assert result.returncode == 1
    assert any(
        item["code"] == "PRIVATE_EVALUATION_MARKER" and item["path"].startswith("archive:")
        for item in payload["automated_findings"]
    )
    assert "synthetic-private-value" not in result.stdout


@pytest.mark.parametrize(
    "member_name",
    [
        "../outside.txt",
        "..\\outside.txt",
        "/absolute.txt",
        "C:/outside.txt",
        "C:\\outside.txt",
        "folder\\file.txt",
        "folder/control\x01.txt",
        "folder/c1-control\N{NEXT LINE}.txt",
        "folder/format\N{ZERO WIDTH NON-JOINER}.txt",
        "folder/CON",
        "folder/aux.txt",
        "folder/LPT9.log",
        "folder/stream:name.txt",
        "folder/file.txt:stream",
        "folder/COM\N{SUPERSCRIPT ONE}.txt",
        "folder/COM\N{SUPERSCRIPT TWO}.txt",
        "folder/COM\N{SUPERSCRIPT THREE}.txt",
        "folder/LPT\N{SUPERSCRIPT ONE}.txt",
        "folder/LPT\N{SUPERSCRIPT TWO}.txt",
        "folder/LPT\N{SUPERSCRIPT THREE}.txt",
        "folder/trailing-dot./file.txt",
        "folder/trailing-space /file.txt",
    ],
)
def test_audit_rejects_cross_platform_unsafe_archive_names(
    tmp_path: Path,
    member_name: str,
) -> None:
    """Removing Windows path checks would permit traversal or drive-qualified members."""
    _init_repo(tmp_path, {"README.md": "# Clean test repository\n"})
    archive = tmp_path / "candidate.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr(member_name, "synthetic public content\n")

    result = _run_audit(tmp_path, "--archive", str(archive))
    payload = json.loads(result.stdout)

    assert result.returncode == 2
    assert payload == {"error": "release archive contains an unsafe path"}


@pytest.mark.parametrize(
    "member_names",
    [
        ("regulatory-harvest/Report.md", "regulatory-harvest/report.md"),
        (
            "regulatory-harvest/caf\N{LATIN SMALL LETTER E WITH ACUTE}.txt",
            "regulatory-harvest/cafe\N{COMBINING ACUTE ACCENT}.txt",
        ),
    ],
)
def test_audit_rejects_cross_platform_archive_name_collisions(
    tmp_path: Path,
    member_names: tuple[str, str],
) -> None:
    """Case or Unicode normalization must not overwrite a member on extraction."""
    _init_repo(tmp_path, {"README.md": "# Clean test repository\n"})
    archive = tmp_path / "candidate.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        for member_name in member_names:
            bundle.writestr(member_name, "synthetic public content\n")

    result = _run_audit(tmp_path, "--archive", str(archive))
    payload = json.loads(result.stdout)

    assert result.returncode == 2
    assert payload == {"error": "release archive contains an unsafe path"}


def test_audit_messages_are_neutral_across_repository_and_archive_inputs(
    tmp_path: Path,
) -> None:
    """Finding text must describe release content without claiming Git tracking state."""
    private_path = "/" + "Users/example/private.txt"
    _init_repo(tmp_path, {"tracked.txt": private_path})
    (tmp_path / "untracked.txt").write_text(private_path, encoding="utf-8")
    archive = tmp_path / "candidate.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("regulatory-harvest/archive.txt", private_path)

    result = _run_audit(tmp_path, "--archive", str(archive))
    payload = json.loads(result.stdout)

    assert result.returncode == 1
    assert len(payload["automated_findings"]) == 3
    for finding in payload["automated_findings"]:
        assert "tracked" not in finding["message"].lower()
        assert "untracked" not in finding["message"].lower()


def test_current_repository_has_no_automated_release_audit_findings() -> None:
    """Adding private or unlicensed material to the release must fail the repository audit."""
    result = _run_audit(ROOT)

    assert result.returncode == 0, result.stdout
    payload = json.loads(result.stdout)
    assert payload["automated_findings"] == []
    assert [item["code"] for item in payload["manual_requirements"]] == [
        "MANUAL_CONFIRMATION_REQUIRED"
    ]
