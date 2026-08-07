import json
from pathlib import Path

from regulatory_harvest.adapters.cite import CiteImportResult
from regulatory_harvest.cli import main


def test_cite_import_writes_receipt_and_never_reports_token(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    """The CLI must persist exchange results without exposing bearer credentials."""
    secret = "private-bearer-token"
    monkeypatch.setenv("CITE_TOKEN", secret)

    async def fake_import(_client, corpus_id: str):
        return CiteImportResult(
            cite_base_url="https://cite.example",
            corpus_id=corpus_id,
        )

    monkeypatch.setattr(
        "regulatory_harvest.adapters.cite.cli.import_cite_corpus",
        fake_import,
    )
    output = tmp_path / "exchange"

    exit_code = main(
        [
            "cite",
            "import",
            "--url",
            "https://cite.example",
            "--corpus",
            "public-corpus",
            "--output",
            str(output),
            "--json",
        ]
    )

    status = json.loads(capsys.readouterr().out)
    receipt = output / "cite-import.json"
    assert exit_code == 0
    assert status == {
        "corpus": "public-corpus",
        "gaps": 0,
        "ok": True,
        "receipt": str(receipt),
        "target": "https://cite.example",
    }
    assert receipt.exists()
    assert secret not in receipt.read_text(encoding="utf-8")
    assert secret not in json.dumps(status)


def test_cite_export_requires_token_from_environment_before_reading_bundle(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    """An export without authentication must fail locally before opening user artifacts."""
    monkeypatch.delenv("CITE_TOKEN", raising=False)
    output = tmp_path / "exchange"

    exit_code = main(
        [
            "cite",
            "export",
            "--url",
            "https://cite.example",
            "--corpus",
            "corpus-node-1",
            "--bundle",
            str(tmp_path / "missing-bundle.json"),
            "--document-targets",
            str(tmp_path / "missing-targets.json"),
            "--annotation-label-id",
            "label-1",
            "--output",
            str(output),
            "--json",
        ]
    )

    status = json.loads(capsys.readouterr().out)
    assert exit_code == 2
    assert status == {"error": "cite_token_missing", "ok": False}
    assert not output.exists()


def test_cite_private_import_requires_token_when_requested(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    """A private import must not degrade silently to public-only results."""
    monkeypatch.delenv("PRIVATE_CITE_TOKEN", raising=False)

    exit_code = main(
        [
            "cite",
            "import",
            "--url",
            "https://cite.example",
            "--corpus",
            "private-corpus",
            "--output",
            str(tmp_path / "exchange"),
            "--token-env",
            "PRIVATE_CITE_TOKEN",
            "--require-auth",
            "--json",
        ]
    )

    assert exit_code == 2
    assert json.loads(capsys.readouterr().out) == {
        "error": "cite_token_missing",
        "ok": False,
    }


def test_cite_error_output_is_sanitized(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    """Remote failure details must not reach JSON automation logs."""

    async def failing_import(_client, _corpus_id: str):
        from regulatory_harvest.adapters.cite import CiteRequestError

        raise CiteRequestError("remote included private matter text")

    monkeypatch.setattr(
        "regulatory_harvest.adapters.cite.cli.import_cite_corpus",
        failing_import,
    )

    exit_code = main(
        [
            "cite",
            "import",
            "--url",
            "https://cite.example",
            "--corpus",
            "public-corpus",
            "--output",
            str(tmp_path / "exchange"),
            "--json",
        ]
    )

    output = capsys.readouterr().out
    assert exit_code == 3
    assert json.loads(output) == {"error": "cite_request_failed", "ok": False}
    assert "private matter" not in output
