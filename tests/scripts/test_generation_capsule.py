from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).parents[2]
FULL_RUNNER = ROOT / "scripts" / "harvest_skill.py"
PORTABLE_RUNNER = ROOT / "scripts" / "harvest_portable.py"
GENERATION_MODULE = ROOT / "src" / "regulatory_harvest" / "evaluation" / "attorney_generation.py"
RUNNERS = (FULL_RUNNER, PORTABLE_RUNNER)


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _run(runner: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(runner), *args],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )


def _run_bounded(
    runner: Path, *args: str, timeout: float = 2.0
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(runner), *args],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _snapshot(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def _write_fixture(
    root: Path,
    *,
    source_bytes: bytes = b"\xef\xbb\xbfSynthetic rule.\r\nA filer must give notice.\r\n",
    client_facts_bytes: bytes | None = b"  The filer is covered.\n",
    generator_bytes: bytes = b"generator-build\x00\xff\n",
) -> Path:
    (root / "sources").mkdir(parents=True)
    (root / "generator").mkdir()
    (root / "sources" / "rule.txt").write_bytes(source_bytes)
    (root / "generator" / "descriptor.bin").write_bytes(generator_bytes)
    if client_facts_bytes is not None:
        (root / "client-facts.txt").write_bytes(client_facts_bytes)
    value = {
        "candidate_id": "synthetic-candidate",
        "client_facts_path": ("client-facts.txt" if client_facts_bytes is not None else None),
        "generation_instructions": ("Produce an attorney briefing using only the supplied record."),
        "generator_artifacts": [{"artifact_id": "generator", "path": "generator/descriptor.bin"}],
        "question": "What does the supplied synthetic rule require?",
        "schema_version": "1.0",
        "sources": [{"path": "sources/rule.txt", "source_id": "rule"}],
    }
    path = root / "generation-input.json"
    path.write_bytes(_canonical(value))
    return path


def _response(
    request: dict[str, object],
    *,
    report_text: str = "# Synthetic Rule\r\n\r\nA filer must give notice.\r\n",
) -> dict[str, object]:
    return {
        "generation_isolation": "fresh_context",
        "model_name": "host-configured-model",
        "operation": "generate_report",
        "payload": {"report_text": report_text},
        "provider_name": "host-agent",
        "request_fingerprint": request["request_fingerprint"],
        "response_id": None,
        "schema_version": "1.0",
        "usage": {},
    }


def _init(
    runner: Path,
    input_path: Path,
    run: Path,
    nonce: str = "a" * 64,
) -> subprocess.CompletedProcess[str]:
    return _run(
        runner,
        "eval-gen-init",
        "--input",
        str(input_path),
        "--run",
        str(run),
        "--nonce-hex",
        nonce,
    )


def _complete(runner: Path, run: Path, response_path: Path) -> None:
    next_result = _run(runner, "eval-gen-next", "--run", str(run))
    assert next_result.returncode == 0, next_result.stderr
    response_path.write_bytes(_canonical(_response(json.loads(next_result.stdout))))
    submitted = _run(
        runner,
        "eval-gen-submit",
        "--run",
        str(run),
        "--response",
        str(response_path),
    )
    assert submitted.returncode == 0, submitted.stderr


def _load_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("attorney_generation_test", GENERATION_MODULE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_generation_capsule_full_and_portable_complete_with_exact_byte_parity(
    tmp_path: Path,
) -> None:
    """A duplicate runner implementation could drift in artifacts, hashing, or output."""
    source = b"\xef\xbb\xbf  Exact source\r\n"
    facts = b"Exact facts without final newline"
    generator = b"\x00\xffgenerator\r\n"
    input_path = _write_fixture(
        tmp_path / "input",
        source_bytes=source,
        client_facts_bytes=facts,
        generator_bytes=generator,
    )
    runs = [tmp_path / "full", tmp_path / "portable"]

    init_outputs = []
    for runner, run in zip(RUNNERS, runs, strict=True):
        initialized = _init(runner, input_path, run)
        assert initialized.returncode == 0, initialized.stderr
        init_outputs.append(initialized.stdout)

        request_result = _run(runner, "eval-gen-next", "--run", str(run))
        assert request_result.returncode == 0, request_result.stderr
        request = json.loads(request_result.stdout)
        assert request["operation"] == "generate_report"
        serialized = json.dumps(request, sort_keys=True)
        assert "_path" not in serialized
        assert "sources/rule.txt" not in serialized
        assert request["sources"][0]["text"] == source.decode("utf-8")
        assert request["client_facts"] == facts.decode("utf-8")
        assert request["generator_artifacts"] == [
            {"artifact_id": "generator", "content_hash": _hash(generator)}
        ]

        status = _run(runner, "eval-gen-status", "--run", str(run))
        assert status.returncode == 0, status.stderr
        assert json.loads(status.stdout)["state"] == "awaiting-report"

        report = "\ufeff# Exact Report\r\n\r\nFinal line\r\n"
        response_bytes = _canonical(_response(request, report_text=report))
        response_path = tmp_path / f"{runner.stem}-response.json"
        response_path.write_bytes(response_bytes)
        submitted = _run(
            runner,
            "eval-gen-submit",
            "--run",
            str(run),
            "--response",
            str(response_path),
        )
        assert submitted.returncode == 0, submitted.stderr
        assert json.loads(submitted.stdout)["state"] == "completed"
        assert (run / "captured" / "sources" / "rule.txt").read_bytes() == source
        assert (run / "captured" / "client-facts.txt").read_bytes() == facts
        assert (run / "captured" / "generator" / "generator.bin").read_bytes() == generator
        assert (run / "generation-response.json").read_bytes() == response_bytes
        assert (run / "report.md").read_bytes() == report.encode("utf-8")

        exhausted = _run(runner, "eval-gen-next", "--run", str(run))
        assert exhausted.returncode == 0, exhausted.stderr
        assert exhausted.stdout == "null\n"
        verified = _run(runner, "eval-gen-verify", "--run", str(run))
        assert verified.returncode == 0, verified.stderr
        assert json.loads(verified.stdout)["ok"] is True

    assert init_outputs[0] == init_outputs[1]
    assert _snapshot(runs[0]) == _snapshot(runs[1])


def test_distinguishable_runnable_builds_generate_and_bind_distinct_reports(
    tmp_path: Path,
) -> None:
    """A captured label is not a build test; the digest-matched executable must run."""
    build_sources = {
        "a": (
            b"import json, sys\n"
            b"request = json.load(sys.stdin)\n"
            b"sys.stdout.write('# Synthetic Rule\\n\\nBuild A report for: ' "
            b"+ request['question'])\n"
        ),
        "b": (
            b"import json, sys\n"
            b"request = json.load(sys.stdin)\n"
            b"sys.stdout.write('# Synthetic Rule\\n\\nBuild B distinct report for: ' "
            b"+ request['question'])\n"
        ),
    }
    reports: dict[str, bytes] = {}
    records: dict[str, dict[str, object]] = {}
    runs: dict[str, Path] = {}

    for label, build_bytes in build_sources.items():
        input_root = tmp_path / f"input-{label}"
        input_path = _write_fixture(input_root, generator_bytes=build_bytes)
        build_path = input_root / "generator" / "descriptor.bin"
        run = tmp_path / f"run-{label}"
        runs[label] = run
        initialized = _init(FULL_RUNNER, input_path, run, nonce="c" * 64)
        assert initialized.returncode == 0, initialized.stderr
        request_result = _run(FULL_RUNNER, "eval-gen-next", "--run", str(run))
        assert request_result.returncode == 0, request_result.stderr
        request = json.loads(request_result.stdout)
        expected_build_hash = request["generator_artifacts"][0]["content_hash"]

        # This is the launch gate required of a real host: hash the exact runnable
        # artifact immediately before executing that same path.
        assert _hash(build_path.read_bytes()) == expected_build_hash
        generated = subprocess.run(
            [sys.executable, str(build_path)],
            input=_canonical(request),
            check=False,
            capture_output=True,
        )
        assert generated.returncode == 0, generated.stderr
        reports[label] = generated.stdout
        response = _response(request, report_text=generated.stdout.decode("utf-8"))
        response["generation_isolation"] = "scripted_fixture"
        response["provider_name"] = "local-runnable-fixture"
        response["model_name"] = f"fixture-build-{label}"
        response_path = tmp_path / f"response-{label}.json"
        response_path.write_bytes(_canonical(response))
        submitted = _run(
            FULL_RUNNER,
            "eval-gen-submit",
            "--run",
            str(run),
            "--response",
            str(response_path),
        )
        assert submitted.returncode == 0, submitted.stderr
        verified = _run(FULL_RUNNER, "eval-gen-verify", "--run", str(run))
        assert verified.returncode == 0, verified.stderr
        records[label] = json.loads((run / "generation-record.json").read_bytes())

    assert reports["a"] != reports["b"]
    assert records["a"]["generator_artifact_hashes"] != records["b"][
        "generator_artifact_hashes"
    ]
    assert records["a"]["report_hash"] != records["b"]["report_hash"]

    # Changing a sealed build cannot be hidden behind its former descriptor.
    captured_build = runs["a"] / "captured" / "generator" / "generator.bin"
    captured_build.write_bytes(build_sources["b"])
    tampered = _run(FULL_RUNNER, "eval-gen-verify", "--run", str(runs["a"]))
    assert tampered.returncode == 5


def test_generation_fingerprints_match_independent_golden_vectors(tmp_path: Path) -> None:
    """Fingerprint drift must fail against values computed outside the substrate."""
    module = _load_module()
    input_path = _write_fixture(tmp_path / "input")
    run = tmp_path / "run"

    state = module.initialize_generation(input_path, run, nonce_hex="a" * 64)
    request = module.next_generation_request(run)
    assert request is not None

    source = b"\xef\xbb\xbfSynthetic rule.\r\nA filer must give notice.\r\n"
    facts = b"  The filer is covered.\n"
    generator = b"generator-build\x00\xff\n"
    capture = {
        "candidate_id": "synthetic-candidate",
        "client_facts_hash": _hash(facts),
        "generation_instructions": "Produce an attorney briefing using only the supplied record.",
        "generator_artifacts": [{"artifact_id": "generator", "content_hash": _hash(generator)}],
        "question": "What does the supplied synthetic rule require?",
        "schema_version": "1.0",
        "sources": [{"content_hash": _hash(source), "source_id": "rule"}],
    }
    capture_fingerprint = _hash(_canonical(capture))
    assert capture_fingerprint == "69fea4f202ab363e35198b46b9b8437d0802759cedbfd7b496913e6822be65db"
    capture["capture_fingerprint"] = capture_fingerprint
    assert json.loads((run / "generation-input.json").read_bytes()) == capture

    nonce_fingerprint = _hash(("a" * 64).encode("ascii"))
    assert nonce_fingerprint == "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb"
    expected_request = {
        "candidate_id": "synthetic-candidate",
        "capture_fingerprint": capture_fingerprint,
        "client_facts": facts.decode("utf-8"),
        "client_facts_hash": _hash(facts),
        "generation_instructions": "Produce an attorney briefing using only the supplied record.",
        "generator_artifacts": [{"artifact_id": "generator", "content_hash": _hash(generator)}],
        "nonce_fingerprint": nonce_fingerprint,
        "operation": "generate_report",
        "question": "What does the supplied synthetic rule require?",
        "schema_version": "1.0",
        "sources": [
            {
                "content_hash": _hash(source),
                "source_id": "rule",
                "text": source.decode("utf-8"),
            }
        ],
    }
    request_fingerprint = _hash(_canonical(expected_request))
    assert request_fingerprint == "53569ba6d7a9f70bf9f1d2618d407b6b41669dd9af92f99176dc38751d8bc56c"
    expected_request["request_fingerprint"] = request_fingerprint
    assert request == expected_request
    assert state["manifest_root"] == (
        "9a2f1a886478cf8369c14ec88cb6681608a125bb13744a564635c1106fd6b54b"
    )


@pytest.mark.parametrize("client_facts_bytes", [None, b"Client facts\n"])
def test_generation_capsule_valid_nullable_facts_resume_with_parity(
    client_facts_bytes: bytes | None,
    tmp_path: Path,
) -> None:
    """Resume must preserve both valid nullable-path branches without changing state."""
    input_path = _write_fixture(tmp_path / "input", client_facts_bytes=client_facts_bytes)
    snapshots: list[dict[str, bytes]] = []
    for runner_name, runner in (("full", FULL_RUNNER), ("portable", PORTABLE_RUNNER)):
        run = tmp_path / runner_name
        initialized = _init(runner, input_path, run)
        assert initialized.returncode == 0, initialized.stderr
        before = _snapshot(run)
        status = _run(runner, "eval-gen-status", "--run", str(run))
        assert status.returncode == 0, status.stderr
        assert _snapshot(run) == before
        snapshots.append(before)
    assert snapshots[0] == snapshots[1]


def test_generation_next_is_repeatable_read_only_and_awaiting_capsule_verifies(
    tmp_path: Path,
) -> None:
    """Treating next as issuance would silently mutate an otherwise resumable capsule."""
    input_path = _write_fixture(tmp_path / "input")
    for index, runner in enumerate(RUNNERS):
        run = tmp_path / f"run-{index}"
        assert _init(runner, input_path, run).returncode == 0
        before = _snapshot(run)
        first = _run(runner, "eval-gen-next", "--run", str(run))
        second = _run(runner, "eval-gen-next", "--run", str(run))
        verified = _run(runner, "eval-gen-verify", "--run", str(run))
        assert first.returncode == second.returncode == verified.returncode == 0
        assert first.stdout == second.stdout
        assert json.loads(verified.stdout)["state"]["state"] == "awaiting-report"
        assert _snapshot(run) == before


@pytest.mark.parametrize(
    "identifier",
    ["../escape", "a/b", "a\\b", ".", "..", "/absolute", "NUL", "bad:id"],
)
@pytest.mark.parametrize("family", ["source", "artifact"])
def test_generation_init_rejects_hostile_identifiers_without_outside_writes(
    identifier: str,
    family: str,
    tmp_path: Path,
) -> None:
    """An identifier must never become a traversal or platform-ambiguous output name."""
    input_path = _write_fixture(tmp_path / "input")
    value = json.loads(input_path.read_bytes())
    collection = "sources" if family == "source" else "generator_artifacts"
    field = "source_id" if family == "source" else "artifact_id"
    value[collection][0][field] = identifier
    input_path.write_bytes(_canonical(value))
    sentinel = tmp_path / "escape.txt"

    for index, runner in enumerate(RUNNERS):
        result = _init(runner, input_path, tmp_path / f"run-{index}")
        assert result.returncode == 2
        assert not sentinel.exists()


@pytest.mark.parametrize("family", ["candidate", "source", "artifact"])
def test_generation_identifier_length_boundary_is_enforced_before_run_creation(
    family: str,
    tmp_path: Path,
) -> None:
    """Unbounded identifiers can exceed filesystem component limits during capture."""
    input_path = _write_fixture(tmp_path / "input")
    original = json.loads(input_path.read_bytes())
    field_path = {
        "candidate": ("candidate_id",),
        "source": ("sources", 0, "source_id"),
        "artifact": ("generator_artifacts", 0, "artifact_id"),
    }[family]

    for runner_index, runner in enumerate(RUNNERS):
        for length, expected_code in ((100, 0), (101, 2), (300, 2)):
            value = json.loads(_canonical(original))
            target = value
            for segment in field_path[:-1]:
                target = target[segment]
            target[field_path[-1]] = "a" * length
            input_path.write_bytes(_canonical(value))
            run = tmp_path / f"run-{runner_index}-{length}"

            result = _init(runner, input_path, run)

            assert result.returncode == expected_code, result.stderr
            assert run.exists() is (expected_code == 0)


@pytest.mark.parametrize("runner", RUNNERS)
@pytest.mark.parametrize("run_location", ["equal", "nested"])
def test_generation_init_rejects_capsule_inside_input_root_before_writing(
    runner: Path,
    run_location: str,
    tmp_path: Path,
) -> None:
    """Output beneath the capture root can contaminate or alias the exact input view."""
    root = tmp_path / "input"
    input_path = _write_fixture(root)
    run = root if run_location == "equal" else root / "capsules" / "candidate"
    before = _snapshot(root)

    result = _init(runner, input_path, run)

    assert result.returncode == 2
    assert result.stderr == (
        '{"code": "GENERATION_INPUT_INVALID", '
        '"message": "generation capsule must be outside the input root"}\n'
    )
    assert _snapshot(root) == before
    if run_location == "nested":
        assert not run.exists()


@pytest.mark.parametrize("mutation", ["source-casefold", "artifact-casefold", "duplicate-path"])
def test_generation_init_rejects_casefold_collisions_and_duplicate_input_paths(
    mutation: str,
    tmp_path: Path,
) -> None:
    """Case-insensitive filesystems and reused paths must not collapse distinct commitments."""
    root = tmp_path / "input"
    input_path = _write_fixture(root)
    value = json.loads(input_path.read_bytes())
    if mutation == "source-casefold":
        value["sources"].append({"path": "sources/rule-2.txt", "source_id": "RULE"})
        (root / "sources" / "rule-2.txt").write_bytes(b"Second rule")
    elif mutation == "artifact-casefold":
        value["generator_artifacts"].append(
            {"artifact_id": "GENERATOR", "path": "generator/descriptor-2.bin"}
        )
        (root / "generator" / "descriptor-2.bin").write_bytes(b"second")
    else:
        value["generator_artifacts"][0]["path"] = "sources/rule.txt"
    input_path.write_bytes(_canonical(value))

    for index, runner in enumerate(RUNNERS):
        assert _init(runner, input_path, tmp_path / f"run-{index}").returncode == 2


def test_generation_capsule_multiple_items_have_stable_order_and_no_secret_or_path_leakage(
    tmp_path: Path,
) -> None:
    """A multi-item packet must preserve declared order but expose no raw nonce or local path."""
    root = tmp_path / "private-input-root"
    input_path = _write_fixture(root)
    value = json.loads(input_path.read_bytes())
    value["sources"].insert(0, {"path": "sources/first.txt", "source_id": "first"})
    value["generator_artifacts"].insert(
        0, {"artifact_id": "first-build", "path": "generator/first.bin"}
    )
    (root / "sources" / "first.txt").write_bytes(b"First source")
    (root / "generator" / "first.bin").write_bytes(b"first build")
    input_path.write_bytes(_canonical(value))
    nonce = "d" * 64
    run = tmp_path / "disjoint-output-root" / "capsule"

    assert _init(FULL_RUNNER, input_path, run, nonce).returncode == 0
    request = json.loads(_run(FULL_RUNNER, "eval-gen-next", "--run", str(run)).stdout)
    assert [item["source_id"] for item in request["sources"]] == ["first", "rule"]
    assert [item["artifact_id"] for item in request["generator_artifacts"]] == [
        "first-build",
        "generator",
    ]
    all_bytes = b"\n".join(_snapshot(run).values())
    assert str(root).encode() not in all_bytes
    assert nonce.encode() not in all_bytes
    for path in _snapshot(run):
        mode = (run / path).stat().st_mode & 0o777
        assert mode == 0o600
    assert run.stat().st_mode & 0o777 == 0o700


@pytest.mark.parametrize(
    ("path", "replacement"),
    [
        pytest.param(("schema_version",), 1, id="schema-int"),
        pytest.param(("candidate_id",), True, id="candidate-bool"),
        pytest.param(("question",), None, id="question-null"),
        pytest.param(("generation_instructions",), [], id="instructions-array"),
        pytest.param(("sources",), {}, id="sources-object"),
        pytest.param(("sources", 0, "source_id"), False, id="source-id-bool"),
        pytest.param(("sources", 0, "path"), None, id="source-path-null"),
        pytest.param(("client_facts_path",), False, id="facts-path-bool"),
        pytest.param(("generator_artifacts",), None, id="artifacts-null"),
        pytest.param(("generator_artifacts", 0, "artifact_id"), 1, id="artifact-id-int"),
        pytest.param(("generator_artifacts", 0, "path"), True, id="artifact-path-bool"),
    ],
)
def test_generation_init_rejects_every_non_string_field_family_with_parity(
    path: tuple[str | int, ...],
    replacement: object,
    tmp_path: Path,
) -> None:
    """JSON bool, null, array, and number values must never coerce into legal strings."""
    input_path = _write_fixture(tmp_path / "input")
    value: object = json.loads(input_path.read_bytes())
    target = value
    for segment in path[:-1]:
        target = target[segment]  # type: ignore[index]
    target[path[-1]] = replacement  # type: ignore[index]
    input_path.write_bytes(_canonical(value))

    codes = [
        _init(runner, input_path, tmp_path / f"run-{index}").returncode
        for index, runner in enumerate(RUNNERS)
    ]
    assert codes == [2, 2]


@pytest.mark.parametrize(
    "mutation",
    [
        "extra-input-field",
        "duplicate-source-id",
        "duplicate-artifact-id",
        "empty-sources",
        "empty-generator-artifacts",
        "unsafe-source-path",
        "unsafe-facts-path",
        "unsafe-generator-path",
        "invalid-nonce",
        "noncanonical-input",
        "invalid-source-utf8",
        "blank-source",
        "blank-facts",
    ],
)
def test_generation_init_rejects_invalid_schema_path_nonce_and_text(
    mutation: str,
    tmp_path: Path,
) -> None:
    """Weak initialization would create a capsule from ambiguous or unsafe evidence."""
    root = tmp_path / "input"
    input_path = _write_fixture(root)
    value = json.loads(input_path.read_bytes())
    nonce = "a" * 64
    if mutation == "extra-input-field":
        value["unexpected"] = True
    elif mutation == "duplicate-source-id":
        value["sources"].append(dict(value["sources"][0]))
    elif mutation == "duplicate-artifact-id":
        value["generator_artifacts"].append(dict(value["generator_artifacts"][0]))
    elif mutation == "empty-sources":
        value["sources"] = []
    elif mutation == "empty-generator-artifacts":
        value["generator_artifacts"] = []
    elif mutation == "unsafe-source-path":
        value["sources"][0]["path"] = "../rule.txt"
    elif mutation == "unsafe-facts-path":
        value["client_facts_path"] = "/tmp/facts.txt"
    elif mutation == "unsafe-generator-path":
        value["generator_artifacts"][0]["path"] = "generator\\descriptor.bin"
    elif mutation == "invalid-nonce":
        nonce = "A" * 64
    elif mutation == "noncanonical-input":
        input_path.write_text(json.dumps(value, indent=2), encoding="utf-8")
    elif mutation == "invalid-source-utf8":
        (root / "sources" / "rule.txt").write_bytes(b"\xff")
    elif mutation == "blank-source":
        (root / "sources" / "rule.txt").write_bytes(b" \r\n")
    else:
        (root / "client-facts.txt").write_bytes(b"\xef\xbb\xbf \n")
    if mutation not in {
        "noncanonical-input",
        "invalid-source-utf8",
        "blank-source",
        "blank-facts",
    }:
        input_path.write_bytes(_canonical(value))

    for index, runner in enumerate(RUNNERS):
        result = _init(runner, input_path, tmp_path / f"run-{index}", nonce)
        assert result.returncode == 2


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        pytest.param("schema_version", 1, id="schema-int"),
        pytest.param("operation", None, id="operation-null"),
        pytest.param("request_fingerprint", False, id="fingerprint-bool"),
        pytest.param("provider_name", 1, id="provider-int"),
        pytest.param("model_name", None, id="model-null"),
        pytest.param("generation_isolation", True, id="isolation-bool"),
        pytest.param("response_id", False, id="response-id-bool"),
        pytest.param("usage", [], id="usage-array"),
        pytest.param("payload", None, id="payload-null"),
    ],
)
def test_generation_submit_rejects_non_string_response_field_families_without_advancing(
    field: str,
    replacement: object,
    tmp_path: Path,
) -> None:
    """Malformed generation metadata must not be sealed or consume the one response."""
    input_path = _write_fixture(tmp_path / "input")
    for index, runner in enumerate(RUNNERS):
        run = tmp_path / f"run-{index}"
        initialized = _init(runner, input_path, run)
        assert initialized.returncode == 0, initialized.stderr
        request = json.loads(_run(runner, "eval-gen-next", "--run", str(run)).stdout)
        response = _response(request)
        response[field] = replacement
        response_path = tmp_path / f"response-{index}.json"
        response_path.write_bytes(_canonical(response))
        before = _snapshot(run)

        result = _run(
            runner,
            "eval-gen-submit",
            "--run",
            str(run),
            "--response",
            str(response_path),
        )
        assert result.returncode == 2
        assert _snapshot(run) == before


@pytest.mark.parametrize(
    "mutation",
    [
        "extra-response-field",
        "extra-payload-field",
        "wrong-operation",
        "wrong-request",
        "unsupported-isolation",
        "blank-provider",
        "negative-usage",
        "bool-usage",
        "blank-report",
        "noncanonical-response",
        "cross-capsule-response",
    ],
)
def test_generation_submit_rejects_unbound_or_malformed_response_without_advancing(
    mutation: str,
    tmp_path: Path,
) -> None:
    """Only one exact canonical response bound to the current capsule may advance it."""
    input_path = _write_fixture(tmp_path / "input")
    for index, runner in enumerate(RUNNERS):
        run = tmp_path / f"run-{index}"
        initialized = _init(runner, input_path, run, nonce=f"{index + 1:x}" * 64)
        assert initialized.returncode == 0, initialized.stderr
        request = json.loads(_run(runner, "eval-gen-next", "--run", str(run)).stdout)
        response = _response(request)
        if mutation == "extra-response-field":
            response["unexpected"] = True
        elif mutation == "extra-payload-field":
            response["payload"]["unexpected"] = True
        elif mutation == "wrong-operation":
            response["operation"] = "grade_report"
        elif mutation in {"wrong-request", "cross-capsule-response"}:
            response["request_fingerprint"] = "0" * 64
        elif mutation == "unsupported-isolation":
            response["generation_isolation"] = "unknown"
        elif mutation == "blank-provider":
            response["provider_name"] = " "
        elif mutation == "negative-usage":
            response["usage"] = {"input_tokens": -1}
        elif mutation == "bool-usage":
            response["usage"] = {"input_tokens": True}
        elif mutation == "blank-report":
            response["payload"] = {"report_text": "\ufeff \r\n"}
        response_path = tmp_path / f"response-{mutation}-{index}.json"
        if mutation == "noncanonical-response":
            response_path.write_text(json.dumps(response, indent=2), encoding="utf-8")
        else:
            response_path.write_bytes(_canonical(response))
        before = _snapshot(run)

        result = _run(
            runner,
            "eval-gen-submit",
            "--run",
            str(run),
            "--response",
            str(response_path),
        )
        assert result.returncode == 2
        assert _snapshot(run) == before


@pytest.mark.parametrize("runner", RUNNERS)
def test_generation_submit_is_one_use_and_out_of_order_fails_closed(
    runner: Path,
    tmp_path: Path,
) -> None:
    """A second or pre-initialization response must never create or replace artifacts."""
    missing_run = tmp_path / "missing"
    placeholder = tmp_path / "placeholder.json"
    placeholder.write_bytes(b"{}")
    before = _snapshot(tmp_path)
    early = _run(
        runner,
        "eval-gen-submit",
        "--run",
        str(missing_run),
        "--response",
        str(placeholder),
    )
    assert early.returncode == 5
    assert not missing_run.exists()
    assert _snapshot(tmp_path) == before

    input_path = _write_fixture(tmp_path / "input")
    run = tmp_path / "run"
    assert _init(runner, input_path, run).returncode == 0
    _complete(runner, run, tmp_path / "response.json")
    completed = _snapshot(run)
    duplicate = _run(
        runner,
        "eval-gen-submit",
        "--run",
        str(run),
        "--response",
        str(tmp_path / "response.json"),
    )
    assert duplicate.returncode == 2
    assert _snapshot(run) == completed


@pytest.mark.parametrize("runner", RUNNERS)
@pytest.mark.parametrize("response_location", ["equal", "child"])
def test_generation_submit_rejects_capsule_response_path_without_locking_or_mutation(
    runner: Path,
    response_location: str,
    tmp_path: Path,
) -> None:
    """Re-locking the capsule while holding its exclusive lock self-deadlocks."""
    input_path = _write_fixture(tmp_path / "input")
    run = tmp_path / f"run-{runner.stem}-{response_location}"
    initialized = _init(runner, input_path, run)
    assert initialized.returncode == 0, initialized.stderr
    response_path = run if response_location == "equal" else run / "generation-request.json"
    before = _snapshot(run)

    result = _run_bounded(
        runner,
        "eval-gen-submit",
        "--run",
        str(run),
        "--response",
        str(response_path),
    )

    assert result.returncode == 2
    assert result.stdout == ""
    assert result.stderr == (
        '{"code": "GENERATION_INPUT_INVALID", '
        '"message": "generation response path must be outside the capsule"}\n'
    )
    assert _snapshot(run) == before


@pytest.mark.parametrize("operation", ["init", "submit"])
def test_generation_capsule_concurrent_transition_allows_exactly_one_winner(
    operation: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Without an exclusive transition, identical concurrent callers can both report success."""
    module = _load_module()
    input_path = _write_fixture(tmp_path / "input")
    run = tmp_path / "run"
    barrier = threading.Barrier(2)
    original_write = module._PosixStorage.atomic_write

    def synchronized_write(
        storage: object,
        artifact_path: str,
        data: bytes,
        *,
        mutable: bool,
    ) -> None:
        synchronize = (
            artifact_path == "captured/client-facts.txt"
            if operation == "init"
            else artifact_path == "generation-response.json"
        )
        if synchronize:
            with suppress(threading.BrokenBarrierError):
                barrier.wait(timeout=0.5)
        original_write(storage, artifact_path, data, mutable=mutable)

    monkeypatch.setattr(module._PosixStorage, "atomic_write", synchronized_write)
    if operation == "submit":
        module.initialize_generation(input_path, run, nonce_hex="a" * 64)
        request = module.next_generation_request(run)
        assert request is not None
        response_path = tmp_path / "response.json"
        response_path.write_bytes(_canonical(_response(request)))

        def transition() -> object:
            return module.submit_generation_response(run, response_path)

    else:

        def transition() -> object:
            return module.initialize_generation(input_path, run, nonce_hex="a" * 64)

    outcomes: list[object] = []
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(transition) for _ in range(2)]
        for future in futures:
            try:
                outcomes.append(future.result())
            except (module.GenerationInputError, module.GenerationIntegrityError) as error:
                outcomes.append(error)

    assert sum(isinstance(outcome, dict) for outcome in outcomes) == 1
    assert module.verify_generation_capsule(run)["ok"] is True
    expected_state = "completed" if operation == "submit" else "awaiting-report"
    assert module.generation_status(run)["state"] == expected_state


def test_generation_response_from_a_real_distinct_capsule_cannot_be_swapped(
    tmp_path: Path,
) -> None:
    """A synthetic zero hash does not exercise actual nonce-bound cross-capsule replay."""
    input_path = _write_fixture(tmp_path / "input")
    first = tmp_path / "first"
    second = tmp_path / "second"
    assert _init(FULL_RUNNER, input_path, first, "1" * 64).returncode == 0
    assert _init(FULL_RUNNER, input_path, second, "2" * 64).returncode == 0
    first_request = json.loads(_run(FULL_RUNNER, "eval-gen-next", "--run", str(first)).stdout)
    second_request = json.loads(_run(FULL_RUNNER, "eval-gen-next", "--run", str(second)).stdout)
    assert first_request["request_fingerprint"] != second_request["request_fingerprint"]
    response_path = tmp_path / "swapped.json"
    response_path.write_bytes(_canonical(_response(first_request)))
    before = _snapshot(second)

    submitted = _run(
        FULL_RUNNER,
        "eval-gen-submit",
        "--run",
        str(second),
        "--response",
        str(response_path),
    )
    assert submitted.returncode == 2
    assert _snapshot(second) == before


@pytest.mark.parametrize(
    "exact_source",
    [b"Rule", b"Rule\n", b"Rule\r\n", b"\xef\xbb\xbfRule"],
)
def test_generation_fingerprints_are_sensitive_to_every_exact_byte_variant(
    exact_source: bytes,
    tmp_path: Path,
) -> None:
    """Whitespace normalization would collapse materially distinct captured byte streams."""
    fingerprints: list[tuple[str, str]] = []
    for index, runner in enumerate(RUNNERS):
        input_path = _write_fixture(tmp_path / f"input-{index}", source_bytes=exact_source)
        run = tmp_path / f"run-{index}"
        initialized = _init(runner, input_path, run)
        assert initialized.returncode == 0, initialized.stderr
        state = json.loads(initialized.stdout)
        fingerprints.append((state["capture_fingerprint"], state["request_fingerprint"]))
    assert fingerprints[0] == fingerprints[1]


def test_generation_fingerprints_distinguish_lf_crlf_bom_and_final_newline(
    tmp_path: Path,
) -> None:
    """All byte-only variants must alter both capture and nonce-bound request identity."""
    identities: set[tuple[str, str]] = set()
    for index, source in enumerate((b"Rule", b"Rule\n", b"Rule\r\n", b"\xef\xbb\xbfRule")):
        input_path = _write_fixture(tmp_path / f"input-{index}", source_bytes=source)
        result = _init(FULL_RUNNER, input_path, tmp_path / f"run-{index}")
        assert result.returncode == 0, result.stderr
        state = json.loads(result.stdout)
        identities.add((state["capture_fingerprint"], state["request_fingerprint"]))
    assert len(identities) == 4


def test_generation_invalid_diagnostics_are_byte_identical_between_runners(
    tmp_path: Path,
) -> None:
    """Thin CLI adapters must not drift in stable exit or diagnostic contracts."""
    input_path = _write_fixture(tmp_path / "input")
    value = json.loads(input_path.read_bytes())
    value["candidate_id"] = True
    input_path.write_bytes(_canonical(value))
    results = [
        _init(runner, input_path, tmp_path / f"run-{index}") for index, runner in enumerate(RUNNERS)
    ]
    assert [result.returncode for result in results] == [2, 2]
    assert results[0].stdout == results[1].stdout == ""
    assert results[0].stderr == results[1].stderr


def test_generation_submit_size_limit_rejects_without_advancing(
    tmp_path: Path,
) -> None:
    """An unbounded response read could exhaust the local host before schema validation."""
    input_path = _write_fixture(tmp_path / "input")
    run = tmp_path / "run"
    assert _init(FULL_RUNNER, input_path, run).returncode == 0
    response_path = tmp_path / "oversized.json"
    response_path.write_bytes(b"{" + b"x" * (16 * 1024 * 1024) + b"}")
    before = _snapshot(run)
    result = _run(
        FULL_RUNNER,
        "eval-gen-submit",
        "--run",
        str(run),
        "--response",
        str(response_path),
    )
    assert result.returncode == 2
    assert _snapshot(run) == before


def test_generation_submit_fault_leaves_deterministically_rejected_capsule(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A mid-commit fault must never look awaiting, resumable, or completed."""
    module = _load_module()
    input_path = _write_fixture(tmp_path / "input")
    run = tmp_path / "run"
    module.initialize_generation(input_path, run, nonce_hex="a" * 64)
    request = module.next_generation_request(run)
    assert request is not None
    response_path = tmp_path / "response.json"
    response_path.write_bytes(_canonical(_response(request)))
    original_write = module._PosixStorage.atomic_write
    response_written = False

    def fail_after_response(
        storage: object,
        artifact_path: str,
        data: bytes,
        *,
        mutable: bool,
    ) -> None:
        nonlocal response_written
        if response_written and artifact_path != "generation-response.json":
            raise OSError("injected write failure")
        original_write(storage, artifact_path, data, mutable=mutable)
        if artifact_path == "generation-response.json":
            response_written = True

    monkeypatch.setattr(module._PosixStorage, "atomic_write", fail_after_response)
    with pytest.raises((module.GenerationInputError, module.GenerationIntegrityError)):
        module.submit_generation_response(run, response_path)
    with pytest.raises(module.GenerationIntegrityError):
        module.generation_status(run)
    with pytest.raises(module.GenerationIntegrityError):
        module.verify_generation_capsule(run)


@pytest.mark.parametrize("runner", RUNNERS)
@pytest.mark.parametrize(
    "mutation",
    [
        "captured-source",
        "request",
        "response",
        "report",
        "record",
        "manifest",
        "injected-file",
        "removed-file",
    ],
)
def test_generation_status_and_verify_fail_closed_on_every_artifact_attack(
    runner: Path,
    mutation: str,
    tmp_path: Path,
) -> None:
    """Verification must cover content, inventory, and manifest semantics, not hashes alone."""
    input_path = _write_fixture(tmp_path / "input")
    run = tmp_path / "run"
    assert _init(runner, input_path, run).returncode == 0
    _complete(runner, run, tmp_path / "response.json")
    targets = {
        "captured-source": run / "captured" / "sources" / "rule.txt",
        "request": run / "generation-request.json",
        "response": run / "generation-response.json",
        "report": run / "report.md",
        "record": run / "generation-record.json",
        "manifest": run / "generation-manifest.json",
        "removed-file": run / "captured" / "generator" / "generator.bin",
    }
    if mutation == "injected-file":
        (run / "injected.txt").write_bytes(b"injected")
    elif mutation == "removed-file":
        targets[mutation].unlink()
    else:
        targets[mutation].write_bytes(targets[mutation].read_bytes() + b"x")

    status = _run(runner, "eval-gen-status", "--run", str(run))
    verified = _run(runner, "eval-gen-verify", "--run", str(run))
    assert status.returncode == 5
    assert verified.returncode == 5


@pytest.mark.parametrize("runner", RUNNERS)
@pytest.mark.parametrize(
    "mutation",
    [
        "source-leaf-symlink",
        "source-parent-symlink",
        "facts-leaf-symlink",
        "generator-leaf-symlink",
        "input-leaf-symlink",
        "run-parent-symlink",
        "response-leaf-symlink",
    ],
)
def test_generation_capsule_rejects_symlink_boundaries(
    runner: Path,
    mutation: str,
    tmp_path: Path,
) -> None:
    """Following any input, response, or run symlink would defeat local sequencing."""
    root = tmp_path / "input"
    input_path = _write_fixture(root)
    run = tmp_path / "run"
    try:
        if mutation == "source-leaf-symlink":
            leaf = root / "sources" / "rule.txt"
            target = root / "source-target.txt"
            leaf.replace(target)
            leaf.symlink_to(target)
        elif mutation == "source-parent-symlink":
            parent = root / "sources"
            target = root / "source-target"
            parent.replace(target)
            parent.symlink_to(target, target_is_directory=True)
        elif mutation == "facts-leaf-symlink":
            leaf = root / "client-facts.txt"
            target = root / "facts-target.txt"
            leaf.replace(target)
            leaf.symlink_to(target)
        elif mutation == "generator-leaf-symlink":
            leaf = root / "generator" / "descriptor.bin"
            target = root / "generator-target.bin"
            leaf.replace(target)
            leaf.symlink_to(target)
        elif mutation == "input-leaf-symlink":
            target = root / "retained-input.json"
            input_path.replace(target)
            input_path.symlink_to(target)
        elif mutation == "run-parent-symlink":
            target = tmp_path / "actual-runs"
            target.mkdir()
            alias = tmp_path / "alias"
            alias.symlink_to(target, target_is_directory=True)
            run = alias / "run"
    except OSError as error:
        pytest.skip(f"fixture symlinks are unavailable: {error}")

    initialized = _init(runner, input_path, run)
    if mutation != "response-leaf-symlink":
        assert initialized.returncode in {2, 5}
        return
    assert initialized.returncode == 0, initialized.stderr
    request = json.loads(_run(runner, "eval-gen-next", "--run", str(run)).stdout)
    target = tmp_path / "retained-response.json"
    target.write_bytes(_canonical(_response(request)))
    response_path = tmp_path / "response.json"
    response_path.symlink_to(target)
    submitted = _run(
        runner,
        "eval-gen-submit",
        "--run",
        str(run),
        "--response",
        str(response_path),
    )
    assert submitted.returncode in {2, 5}


@pytest.mark.parametrize(
    "mutation", ["preexisting-empty-run", "source-directory", "source-hardlink"]
)
def test_generation_capsule_rejects_preexisting_or_nonregular_boundaries(
    mutation: str,
    tmp_path: Path,
) -> None:
    """A preclaimed capsule or nonregular input could bypass exclusive exact capture."""
    root = tmp_path / "input"
    input_path = _write_fixture(root)
    run = tmp_path / "run"
    if mutation == "preexisting-empty-run":
        run.mkdir()
    elif mutation == "source-directory":
        source = root / "sources" / "rule.txt"
        source.unlink()
        source.mkdir()
    else:
        try:
            os.link(root / "sources" / "rule.txt", root / "source-hardlink.txt")
        except OSError as error:
            pytest.skip(f"hard links are unavailable: {error}")

    for runner in RUNNERS:
        result = _init(runner, input_path, run)
        assert result.returncode == 5


@pytest.mark.parametrize("target", ["source", "generator", "response"])
def test_generation_capsule_detects_same_name_replacement_during_exact_read(
    target: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A retained descriptor must not validate bytes under a replaced pathname."""
    module = _load_module()
    root = tmp_path / "input"
    input_path = _write_fixture(root)
    run = tmp_path / "run"
    response_path = tmp_path / "response.json"
    if target == "response":
        module.initialize_generation(input_path, run, nonce_hex="a" * 64)
        request = module.next_generation_request(run)
        assert request is not None
        response_path.write_bytes(_canonical(_response(request)))
    targets = {
        "source": root / "sources" / "rule.txt",
        "generator": root / "generator" / "descriptor.bin",
        "response": response_path,
    }
    attacked = targets[target]
    original = module._read_all
    replaced = False
    attacked_stat = os.stat(attacked, follow_symlinks=False)
    attacked_identity = (attacked_stat.st_dev, attacked_stat.st_ino)

    def replace_then_read(descriptor: int) -> bytes:
        nonlocal replaced
        opened_stat = os.fstat(descriptor)
        opened_identity = (opened_stat.st_dev, opened_stat.st_ino)
        if not replaced and opened_identity == attacked_identity:
            replaced = True
            attacked.replace(attacked.with_name(f"retained-{attacked.name}"))
            attacked.write_bytes(b"replacement")
        return original(descriptor)

    monkeypatch.setattr(module, "_read_all", replace_then_read)
    with pytest.raises(module.GenerationIntegrityError):
        if target == "response":
            module.submit_generation_response(run, response_path)
        else:
            module.initialize_generation(input_path, run, nonce_hex="a" * 64)
    assert replaced is True
    if target != "response":
        assert not run.exists()


def test_generation_capsule_detects_run_root_replacement_before_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A replaced output pathname must never receive response artifacts through stale trust."""
    module = _load_module()
    input_path = _write_fixture(tmp_path / "input")
    run = tmp_path / "run"
    module.initialize_generation(input_path, run, nonce_hex="a" * 64)
    request = module.next_generation_request(run)
    assert request is not None
    response_path = tmp_path / "response.json"
    response_path.write_bytes(_canonical(_response(request)))
    retained = tmp_path / "retained-run"
    original_write = module._PosixStorage.atomic_write
    replaced = False

    def replace_root_then_write(
        storage: object,
        artifact_path: str,
        data: bytes,
        *,
        mutable: bool,
    ) -> None:
        nonlocal replaced
        if not replaced and artifact_path == "generation-record.json":
            replaced = True
            run.replace(retained)
            run.mkdir()
        original_write(storage, artifact_path, data, mutable=mutable)

    monkeypatch.setattr(module._PosixStorage, "atomic_write", replace_root_then_write)
    with pytest.raises(module.GenerationIntegrityError):
        module.submit_generation_response(run, response_path)
    assert replaced is True
    assert list(run.iterdir()) == []


def test_generation_capsule_platform_boundary_is_stable_and_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unsupported non-POSIX hosts must refuse capture before creating a run."""
    module = _load_module()
    input_path = _write_fixture(tmp_path / "input")
    run = tmp_path / "run"
    monkeypatch.setattr(module, "_storage_platform", lambda: "nt")

    with pytest.raises(
        module.GenerationIntegrityError,
        match="GENERATION_STORAGE_PLATFORM_UNSUPPORTED",
    ):
        module.initialize_generation(input_path, run, nonce_hex="a" * 64)
    assert not run.exists()


def test_generation_module_imports_under_isolated_python_without_third_party(
    tmp_path: Path,
) -> None:
    """The portable capsule must not depend on the installed project or site packages."""
    script = (
        "import importlib.util,sys;"
        f"p={str(GENERATION_MODULE)!r};"
        "s=importlib.util.spec_from_file_location('generation_isolated',p);"
        "m=importlib.util.module_from_spec(s);s.loader.exec_module(m);"
        "print(m.GENERATION_SCHEMA_VERSION)"
    )
    result = subprocess.run(
        [sys.executable, "-I", "-S", "-c", script],
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == "1.0\n"


def test_generation_input_leaf_replacement_during_retained_read_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A same-name replacement during descriptor reading must not produce a capsule."""
    module = _load_module()
    input_path = _write_fixture(tmp_path / "input")
    run = tmp_path / "run"
    original = module._read_all
    replaced = False

    def replace_then_read(descriptor: int) -> bytes:
        nonlocal replaced
        if not replaced:
            replaced = True
            input_path.replace(input_path.with_suffix(".retained.json"))
            input_path.write_bytes(b"{}")
        return original(descriptor)

    monkeypatch.setattr(module, "_read_all", replace_then_read)
    with pytest.raises(module.GenerationIntegrityError):
        module.initialize_generation(input_path, run, nonce_hex="a" * 64)
    assert replaced is True
    assert not run.exists()
