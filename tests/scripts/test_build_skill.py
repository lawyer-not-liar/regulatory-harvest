import copy
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from regulatory_harvest.api import validate_research_bundle

ROOT = Path(__file__).parents[2]
BUILDER = ROOT / "scripts" / "build_skill.py"
EVALUATION_FIXTURE = ROOT / "tests" / "fixtures" / "attorney-eval"
EVALUATOR_RELIABILITY_PACKAGE_PATHS = (
    "assets/attorney-evaluation-v2-response.template.json",
    "assets/attorney-evaluation-qualification.template.json",
    "scripts/attorney_eval_full.py",
    "scripts/attorney_eval_portable.py",
    "scripts/harvest_portable.py",
    "scripts/harvest_skill.py",
    "src/regulatory_harvest/evaluation/attorney_admission.py",
    "src/regulatory_harvest/evaluation/attorney_artifacts.py",
    "src/regulatory_harvest/evaluation/attorney_cli.py",
    "src/regulatory_harvest/evaluation/attorney_contract.py",
    "src/regulatory_harvest/evaluation/attorney_ledger.py",
    "src/regulatory_harvest/evaluation/attorney_qualification.py",
    "src/regulatory_harvest/evaluation/attorney_v2_artifacts.py",
    "src/regulatory_harvest/evaluation/attorney_v2_compiler.py",
    "src/regulatory_harvest/evaluation/attorney_v2_models.py",
    "src/regulatory_harvest/evaluation/attorney_v2_requests.py",
    "src/regulatory_harvest/evaluation/attorney_v2_rubric.py",
    "src/regulatory_harvest/evaluation/attorney_v2_workflow.py",
    "src/regulatory_harvest/evaluation/attorney_workflow.py",
)

EVALUATOR_V2_PACKAGE_PATHS = (
    "assets/attorney-evaluation-v2-response.template.json",
    "src/regulatory_harvest/evaluation/attorney_v2_artifacts.py",
    "src/regulatory_harvest/evaluation/attorney_v2_compiler.py",
    "src/regulatory_harvest/evaluation/attorney_v2_models.py",
    "src/regulatory_harvest/evaluation/attorney_v2_requests.py",
    "src/regulatory_harvest/evaluation/attorney_v2_rubric.py",
    "src/regulatory_harvest/evaluation/attorney_v2_workflow.py",
)

EVALUATOR_V21_PACKAGE_PATHS = (
    "assets/attorney-evaluation-v21-response.template.json",
    "src/regulatory_harvest/evaluation/attorney_protocol.py",
    "src/regulatory_harvest/evaluation/attorney_v21_artifacts.py",
    "src/regulatory_harvest/evaluation/attorney_v21_compiler.py",
    "src/regulatory_harvest/evaluation/attorney_v21_models.py",
    "src/regulatory_harvest/evaluation/attorney_v21_requests.py",
    "src/regulatory_harvest/evaluation/attorney_v21_rubric.py",
    "src/regulatory_harvest/evaluation/attorney_v21_workflow.py",
)

EVALUATOR_V22_PACKAGE_PATHS = (
    "assets/attorney-evaluation-v22-response.template.json",
    "src/regulatory_harvest/evaluation/attorney_v22_artifacts.py",
    "src/regulatory_harvest/evaluation/attorney_v22_compiler.py",
    "src/regulatory_harvest/evaluation/attorney_v22_drafts.py",
    "src/regulatory_harvest/evaluation/attorney_v22_models.py",
    "src/regulatory_harvest/evaluation/attorney_v22_requests.py",
    "src/regulatory_harvest/evaluation/attorney_v22_workflow.py",
)
BASELINE_PACKAGE_PATHS = (
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
)
BASELINE_ASSET_PATHS = BASELINE_PACKAGE_PATHS[:4]
READINESS_PACKAGE_PATHS = (
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
)
READINESS_CANONICAL_JSON_PATHS = (
    "assets/attorney-delivery-readiness-input.template.json",
    "assets/attorney-delivery-readiness-response.template.json",
    "src/regulatory_harvest/evaluation/readiness-rubric-v1.json",
)
SPEC = importlib.util.spec_from_file_location("regulatory_harvest_skill_builder", BUILDER)
assert SPEC is not None and SPEC.loader is not None
skill_builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(skill_builder)


def _build(output: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(BUILDER), "--output", str(output)],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def test_ci_public_audit_targets_the_exact_built_archive() -> None:
    """CI must scan the universal ZIP it just built without assuming owner markers."""
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

    assert (
        "python scripts/audit_release.py --archive dist/regulatory-harvest-skill.zip --json"
    ) in workflow
    assert "--private-markers" not in workflow


def _run_isolated(
    runner: Path,
    cwd: Path,
    *args: str,
    without_site_packages: bool = True,
) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment.update(
        {
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "PIP_NO_INDEX": "1",
            "PYTHONNOUSERSITE": "1",
        }
    )
    python_args = [sys.executable, "-I"]
    if without_site_packages:
        python_args.append("-S")
    return subprocess.run(
        [*python_args, str(runner), *args],
        cwd=cwd,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )


def _build_and_extract(tmp_path: Path) -> Path:
    built = tmp_path / "skill.zip"
    result = _build(built)
    assert result.returncode == 0, result.stderr
    extracted = tmp_path / "extracted"
    with zipfile.ZipFile(built) as archive:
        archive.extractall(extracted)
    return extracted / "regulatory-harvest"


def _run_snapshot(run: Path) -> dict[str, bytes]:
    return {
        path.relative_to(run).as_posix(): path.read_bytes()
        for path in sorted(run.rglob("*"))
        if path.is_file()
    }


def test_extracted_qualification_template_completes_full_and_portable_lifecycle(
    tmp_path: Path,
) -> None:
    """Both clean archive runtimes must seal identical schema-1.1 qualification bytes."""
    skill = _build_and_extract(tmp_path)
    runner = skill / "scripts" / "harvest_skill.py"
    fixture = tmp_path / "qualification-fixture"
    (fixture / "sources").mkdir(parents=True)
    template = json.loads(
        (skill / "assets" / "attorney-evaluation-qualification.template.json").read_bytes()
    )
    materialized = json.loads(json.dumps(template).replace("__REPLACE__", "archive-test"))
    for filename, content in (
        (
            "fictional-public-workshop-rule-operative-archive-test.txt",
            b"Fictional rule text only. A public workshop keeps a record.\n",
        ),
        (
            "fictional-public-workshop-rule-status-archive-test.txt",
            b"Fictional status only. The fictional rule remains effective.\n",
        ),
    ):
        (fixture / "sources" / filename).write_bytes(content)
    case_path = fixture / "qualification.json"
    case_path.write_bytes(_canonical_bytes(materialized))
    runs = (
        (tmp_path / "qualification-full", False),
        (tmp_path / "qualification-portable", True),
    )

    initialized = [
        _run_isolated(
            runner,
            tmp_path,
            "eval-qualify-init",
            "--case",
            str(case_path),
            "--run",
            str(run),
            "--nonce-hex",
            "6" * 64,
            without_site_packages=portable,
        )
        for run, portable in runs
    ]
    assert [result.returncode for result in initialized] == [0, 0]
    assert initialized[0].stdout == initialized[1].stdout
    assert initialized[0].stderr == initialized[1].stderr == ""
    assert _run_snapshot(runs[0][0]) == _run_snapshot(runs[1][0])

    next_results = [
        _run_isolated(
            runner,
            tmp_path,
            "eval-qualify-next",
            "--run",
            str(run),
            without_site_packages=portable,
        )
        for run, portable in runs
    ]
    assert [result.returncode for result in next_results] == [0, 0]
    assert next_results[0].stdout == next_results[1].stdout
    assert next_results[0].stderr == next_results[1].stderr == ""
    request = json.loads(next_results[0].stdout)
    source_ids = [source["source_id"] for source in request["payload"]["sources"]]
    response = {
        "judge_isolation": "scripted_fixture",
        "model_name": "fictional-qualification-model",
        "operation": "admit_case",
        "payload": {
            "checks": [
                {
                    "code": code,
                    "material": True,
                    "rationale": "The fictional source record satisfies this check.",
                    "satisfied": True,
                    "source_ids": source_ids,
                }
                for code in (
                    "AUTHORITY_ALIGNMENT",
                    "OPERATIVE_TEXT",
                    "CURRENTNESS_EVIDENCE",
                    "LANGUAGE_RESOLUTION",
                    "SOURCE_PARITY",
                )
            ],
            "issues": [],
            "request_fingerprint": request["request_fingerprint"],
        },
        "provider_name": "fictional-qualification-provider",
        "request_fingerprint": request["request_fingerprint"],
        "schema_version": "1.0",
    }
    response_path = tmp_path / "qualification-response.json"
    response_path.write_bytes(_canonical_bytes(response))

    submitted = [
        _run_isolated(
            runner,
            tmp_path,
            "eval-qualify-submit",
            "--run",
            str(run),
            "--response",
            str(response_path),
            without_site_packages=portable,
        )
        for run, portable in runs
    ]
    assert [result.returncode for result in submitted] == [0, 0]
    assert submitted[0].stdout == submitted[1].stdout
    assert submitted[0].stderr == submitted[1].stderr == ""
    assert json.loads(submitted[0].stdout)["receipt"]["readiness"]["status"] == "ADMITTED"
    assert _run_snapshot(runs[0][0]) == _run_snapshot(runs[1][0])

    statuses = [
        _run_isolated(
            runner,
            tmp_path,
            "eval-qualify-status",
            "--run",
            str(run),
            without_site_packages=portable,
        )
        for run, portable in runs
    ]
    verifications = [
        _run_isolated(
            runner,
            tmp_path,
            "eval-qualify-verify",
            "--run",
            str(run),
            without_site_packages=portable,
        )
        for run, portable in runs
    ]
    assert [result.returncode for result in statuses] == [0, 0]
    assert [result.returncode for result in verifications] == [0, 0]
    assert statuses[0].stdout == statuses[1].stdout
    assert verifications[0].stdout == verifications[1].stdout
    assert json.loads(statuses[0].stdout)["status"] == "qualified"
    assert json.loads(verifications[0].stdout)["valid"] is True
    assert _run_snapshot(runs[0][0]) == _run_snapshot(runs[1][0])


def test_built_skill_preserves_qualification_and_ledger_repair_contract(
    tmp_path: Path,
) -> None:
    """The portable archive must carry the same hidden controller safeguards."""
    skill = _build_and_extract(tmp_path)
    for relative_path in ("SKILL.md", "references/attorney-evaluation.md"):
        instructions = (skill / relative_path).read_text(encoding="utf-8").casefold()
        for required_contract in (
            "qualify every locked case before generating a candidate",
            "use eval-submit-safe for every evaluator response",
            "one initial response and at most one fresh mechanical repair per fragment",
            "stop as `inconclusive_mechanical` after a second mechanical refusal",
            "never retry an unfavorable substantive judgment",
            "accept an unfavorable substantive result without retry",
            "verify terminal evaluation artifacts",
            "start every mechanical repair in a genuinely fresh role context",
            "stop rather than repair in the same role context",
        ):
            assert required_contract in instructions

    response_template = json.loads(
        (skill / "assets" / "attorney-evaluation-response.template.json").read_bytes()
    )
    assert set(response_template) == {
        "judge_isolation",
        "model_name",
        "operation",
        "payload",
        "provider_name",
        "request_fingerprint",
        "schema_version",
    }
    assert response_template["judge_isolation"] == "fresh_context"
    reference = " ".join(
        (skill / "references" / "attorney-evaluation.md").read_text(encoding="utf-8").split()
    ).casefold()
    assert "public `fresh_context` value is illustrative, not an observed default" in (reference)
    assert "explicitly replace `judge_isolation`" in reference
    assert "only for an initial role response" in reference
    assert "this fallback never applies to a mechanical repair" in reference
    assert (
        "every build, audit, and repair request carries the same versioned "
        "ledger_invariant_contract. it is explanatory input; deterministic "
        "validation remains authoritative. repairs must globally recheck ids, "
        "walk order, relationships, citations, category fields, materiality, and "
        "audit binding."
    ) in reference


def _profiled_brief(
    finding_id: str,
    claim_text: str,
    *,
    list_kind: str,
) -> dict[str, object]:
    return {
        "structure_profile": "regulatory-walk-v1",
        "executive_summary": [
            {
                "kind": "paragraph",
                "purpose": "legal_analysis",
                "text": claim_text,
                "finding_ids": [finding_id],
                "claim_ids": ["claim-1"],
                "atom_ids": ["atom-1"],
            }
        ],
        "sections": [
            {
                "section_id": "key-requirements",
                "title": "Key Requirements",
                "role": "key_requirements",
                "blocks": [
                    {
                        "kind": list_kind,
                        "purpose": "legal_analysis",
                        "items": [
                            {
                                "text": claim_text,
                                "finding_ids": [finding_id],
                                "claim_ids": ["claim-1"],
                                "atom_ids": ["atom-1"],
                            }
                        ],
                    }
                ],
            },
            {
                "section_id": "penalties-and-enforcement",
                "title": "Penalties and Enforcement",
                "role": "penalties_enforcement",
                "blocks": [
                    {
                        "kind": "paragraph",
                        "purpose": "limitation",
                        "text": (
                            "Not established: The retained authority does not establish "
                            "penalties or enforcement mechanisms."
                        ),
                    }
                ],
            },
            {
                "section_id": "implementation-workplan",
                "title": "Implementation Workplan",
                "role": "implementation",
                "blocks": [
                    {
                        "kind": "paragraph",
                        "purpose": "application",
                        "text": "Assign ownership and timing for the documentation duty.",
                        "finding_ids": [finding_id],
                    }
                ],
            },
        ],
    }


def _strict_coverage(dossier: dict[str, object]) -> dict[str, object]:
    source_units = dossier["source_unit_inventory"]
    evidence_inventory = dossier["evidence_inventory"]
    assert isinstance(source_units, dict)
    assert isinstance(evidence_inventory, dict)
    units = source_units["units"]
    leads = evidence_inventory["leads"]
    assert isinstance(units, list)
    assert isinstance(leads, list)
    atom_ids = ["atom-1"]
    dimensions = {
        "authority_status_timing": {"disposition": "not_present"},
        "actors_scope_activities": {
            "disposition": "mapped",
            "atom_ids": atom_ids,
        },
        "definitions_categories": {"disposition": "not_present"},
        "duties_rights_prohibitions": {
            "disposition": "mapped",
            "atom_ids": atom_ids,
        },
        "triggers_thresholds": {"disposition": "not_present"},
        "conditions_exceptions_defenses": {"disposition": "not_present"},
        "deadlines_transitions": {"disposition": "not_present"},
        "enforcement_remedies_consequences": {"disposition": "not_present"},
        "cross_references_dependencies": {"disposition": "not_present"},
    }
    elements = {
        field: {"status": "not_applicable"}
        for field in (
            "actor",
            "modality",
            "operative_action",
            "object",
            "trigger",
            "threshold",
            "condition",
            "exception",
            "timing",
            "authority",
            "route",
            "consequence",
            "defined_term",
            "defined_meaning",
        )
    }
    for field, text in (
        ("actor", "controller"),
        ("modality", "must"),
        ("operative_action", "document"),
        ("object", "risks"),
    ):
        elements[field] = {
            "status": "stated",
            "text": text,
            "claim_ids": ["claim-1"],
        }
    unit_ids = [str(unit["unit_id"]) for unit in units]
    lead_ids = [str(lead["lead_id"]) for lead in leads]
    return {
        "coverage_contract_version": "proposition-coverage-v2",
        "lead_reviews": [],
        "proposition_coverage": [],
        "unit_reviews": [{"unit_id": unit_id, "dimensions": dimensions} for unit_id in unit_ids],
        "lead_dispositions_v2": [
            {
                "lead_id": lead_id,
                "disposition": "mapped",
                "atom_ids": atom_ids,
            }
            for lead_id in lead_ids
        ],
        "rule_atoms": [
            {
                "atom_id": "atom-1",
                "unit_ids": unit_ids,
                "lead_ids": lead_ids,
                "category": "requirements",
                "proposition_type": "duty",
                "materiality": "critical",
                "elements": elements,
                "omission_rationale": "Omission would hide the documentation duty.",
            }
        ],
        "rule_relationships": [],
    }


def test_skill_archive_is_one_reproducible_cross_platform_package(tmp_path: Path) -> None:
    """Platform-specific or nondeterministic archives would defeat the one-package contract."""
    first = tmp_path / "first.zip"
    second = tmp_path / "second.zip"

    first_result = _build(first)
    second_result = _build(second)

    assert first_result.returncode == 0, first_result.stderr
    assert second_result.returncode == 0, second_result.stderr
    assert (
        hashlib.sha256(first.read_bytes()).digest() == hashlib.sha256(second.read_bytes()).digest()
    )
    receipt = json.loads(first_result.stdout)
    assert receipt["archive"] == str(first)
    assert receipt["root"] == "regulatory-harvest"

    for index, built in enumerate((first, second), start=1):
        extracted = tmp_path / f"extracted-{index}"
        with zipfile.ZipFile(built) as archive:
            archive.extractall(extracted)
            for relative_path in EVALUATOR_RELIABILITY_PACKAGE_PATHS:
                archive_path = f"regulatory-harvest/{relative_path}"
                assert archive.read(archive_path) == (ROOT / relative_path).read_bytes()
                assert (extracted / archive_path).read_bytes() == (
                    ROOT / relative_path
                ).read_bytes()

    with zipfile.ZipFile(first) as archive:
        names = archive.namelist()
        assert names == sorted(names)
        assert len(names) == len(set(names))
        assert all(name.startswith("regulatory-harvest/") for name in names)
        assert {
            "regulatory-harvest/SKILL.md",
            "regulatory-harvest/pyproject.toml",
            "regulatory-harvest/README.md",
            "regulatory-harvest/SECURITY.md",
            "regulatory-harvest/agents/openai.yaml",
            "regulatory-harvest/scripts/harvest_skill.py",
            "regulatory-harvest/scripts/attorney_eval_full.py",
            "regulatory-harvest/scripts/attorney_eval_portable.py",
            "regulatory-harvest/src/regulatory_harvest/api.py",
            "regulatory-harvest/src/regulatory_harvest/evaluation/attorney_generation.py",
            "regulatory-harvest/src/regulatory_harvest/evaluation/attorney_workflow.py",
            "regulatory-harvest/src/regulatory_harvest/models/brief.py",
            "regulatory-harvest/assets/attorney-evaluation-case.template.json",
            "regulatory-harvest/assets/attorney-generation-input.template.json",
            "regulatory-harvest/assets/research-charter.template.json",
            "regulatory-harvest/docs/providers.md",
            "regulatory-harvest/references/attorney-evaluation.md",
            "regulatory-harvest/references/research-protocol.md",
        } <= set(names)
        assert not any(
            part in {".git", ".worktrees", "tests", "dist", "__pycache__"}
            for name in names
            for part in Path(name).parts
        )
        assert not any(
            "/docs/superpowers/" in name or "/docs/verification/" in name for name in names
        )
        assert {info.date_time for info in archive.infolist()} == {(1980, 1, 1, 0, 0, 0)}
        assert archive.read("regulatory-harvest/agents/openai.yaml").decode("utf-8") == (
            "interface:\n"
            '  display_name: "Regulatory Harvest"\n'
            '  short_description: "Cited regulatory research and report evaluation"\n'
            '  default_prompt: "Use $regulatory-harvest to research the governing '
            'regulation and produce a cited attorney briefing."\n'
        )


def test_protocol_2_runtime_and_template_are_exactly_packaged(tmp_path: Path) -> None:
    """A clean archive must carry each v2 runtime byte once and reproducibly."""
    manifest_entries = (
        (ROOT / "scripts" / "skill-package-files.txt").read_text(encoding="utf-8").splitlines()
    )
    assert manifest_entries == sorted(set(manifest_entries))
    assert all(manifest_entries.count(path) == 1 for path in EVALUATOR_V2_PACKAGE_PATHS)

    first, second = tmp_path / "v2-a.zip", tmp_path / "v2-b.zip"
    assert _build(first).returncode == 0
    assert _build(second).returncode == 0
    assert first.read_bytes() == second.read_bytes()
    with zipfile.ZipFile(first) as archive:
        for path in EVALUATOR_V2_PACKAGE_PATHS:
            assert archive.read(f"regulatory-harvest/{path}") == (ROOT / path).read_bytes()


def test_protocol_21_runtime_and_template_are_exactly_packaged(tmp_path: Path) -> None:
    """A clean archive must contain every Protocol 2.1 runtime byte exactly once."""
    manifest_entries = (
        (ROOT / "scripts" / "skill-package-files.txt").read_text(encoding="utf-8").splitlines()
    )
    assert manifest_entries == sorted(set(manifest_entries))
    assert all(manifest_entries.count(path) == 1 for path in EVALUATOR_V21_PACKAGE_PATHS)

    built = tmp_path / "v21.zip"
    assert _build(built).returncode == 0
    with zipfile.ZipFile(built) as archive:
        for path in EVALUATOR_V21_PACKAGE_PATHS:
            assert archive.read(f"regulatory-harvest/{path}") == (ROOT / path).read_bytes()


def test_protocol_22_runtime_and_template_are_exactly_packaged(tmp_path: Path) -> None:
    """A clean archive contains every Protocol 2.2 runtime byte exactly once."""
    manifest_entries = (
        (ROOT / "scripts" / "skill-package-files.txt").read_text(encoding="utf-8").splitlines()
    )
    assert manifest_entries == sorted(set(manifest_entries))
    assert all(manifest_entries.count(path) == 1 for path in EVALUATOR_V22_PACKAGE_PATHS)

    built = tmp_path / "v22.zip"
    assert _build(built).returncode == 0
    with zipfile.ZipFile(built) as archive:
        names = archive.namelist()
        for path in EVALUATOR_V22_PACKAGE_PATHS:
            member = f"regulatory-harvest/{path}"
            assert names.count(member) == 1
            assert archive.read(member) == (ROOT / path).read_bytes()


def test_baseline_runtime_and_assets_are_exactly_packaged_once(tmp_path: Path) -> None:
    """An installable skill must carry the complete stable-baseline runtime byte-for-byte."""
    entries = (
        (ROOT / "scripts" / "skill-package-files.txt").read_text(encoding="utf-8").splitlines()
    )
    assert entries == sorted(set(entries))
    assert all(entries.count(path) == 1 for path in BASELINE_PACKAGE_PATHS)

    built = tmp_path / "baseline-skill.zip"
    result = _build(built)
    assert result.returncode == 0, result.stderr
    with zipfile.ZipFile(built) as archive:
        names = archive.namelist()
        for path in BASELINE_PACKAGE_PATHS:
            member = f"regulatory-harvest/{path}"
            assert names.count(member) == 1
            assert archive.read(member) == (ROOT / path).read_bytes()
        assert not any("/tests/" in name for name in names)
        assert not any("attorney-eval-baseline" in name for name in names)


def test_readiness_runtime_assets_docs_and_runners_are_exactly_packaged_once(
    tmp_path: Path,
) -> None:
    """Removing any readiness dependency must make the distributable incomplete."""
    entries = (
        (ROOT / "scripts" / "skill-package-files.txt").read_text(encoding="utf-8").splitlines()
    )
    assert entries == sorted(set(entries))
    assert all(entries.count(path) == 1 for path in READINESS_PACKAGE_PATHS)

    built = tmp_path / "readiness-skill.zip"
    result = _build(built)
    assert result.returncode == 0, result.stderr
    with zipfile.ZipFile(built) as archive:
        names = archive.namelist()
        for path in READINESS_PACKAGE_PATHS:
            member = f"regulatory-harvest/{path}"
            assert names.count(member) == 1
            assert archive.read(member) == (ROOT / path).read_bytes()


@pytest.mark.parametrize("required", READINESS_PACKAGE_PATHS)
def test_skill_build_refuses_each_missing_readiness_runtime_input(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    required: str,
) -> None:
    """The build guard must name every omitted readiness input before writing a ZIP."""
    entries = (
        (ROOT / "scripts" / "skill-package-files.txt").read_text(encoding="utf-8").splitlines()
    )
    manifest = tmp_path / "skill-package-files.txt"
    manifest.write_text(
        "\n".join(entry for entry in entries if entry != required) + "\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(skill_builder, "PACKAGE_MANIFEST", manifest)

    with pytest.raises(
        skill_builder.SkillBuildError,
        match="skill package manifest is missing delivery-readiness-v1 input: " + required,
    ):
        skill_builder._runtime_files()


def test_installed_wheel_exposes_exact_readiness_rubric_resource(tmp_path: Path) -> None:
    """Dropping package JSON data would make installed readiness policy unavailable."""
    wheel_dir = tmp_path / "wheel"
    built = subprocess.run(
        ["uv", "build", "--wheel", "--out-dir", str(wheel_dir)],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert built.returncode == 0, built.stderr
    wheel = next(wheel_dir.glob("*.whl"))
    installed_root = tmp_path / "installed"
    installed = subprocess.run(
        [
            "uv",
            "pip",
            "install",
            "--no-deps",
            "--target",
            str(installed_root),
            str(wheel),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert installed.returncode == 0, installed.stderr
    probe = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "from importlib.resources import files;"
                "print((files('regulatory_harvest')/'evaluation'/"
                "'readiness-rubric-v1.json').read_bytes().hex())"
            ),
        ],
        cwd=tmp_path,
        env={**os.environ, "PYTHONPATH": str(installed_root)},
        check=False,
        capture_output=True,
        text=True,
    )
    assert probe.returncode == 0, probe.stderr
    assert (
        bytes.fromhex(probe.stdout.strip())
        == (ROOT / "src/regulatory_harvest/evaluation/readiness-rubric-v1.json").read_bytes()
    )


def test_extracted_skill_runs_all_readiness_help_and_public_terminal_journeys(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The built ZIP must execute every public tier without the checkout as runtime."""
    skill = _build_and_extract(tmp_path)
    full_runner = skill / "scripts" / "harvest_skill.py"
    portable_runner = skill / "scripts" / "harvest_portable.py"
    commands = (
        "eval-readiness-init",
        "eval-readiness-next",
        "eval-readiness-submit-safe",
        "eval-readiness-status",
        "eval-readiness-verify",
    )
    for command in commands:
        full_help = _run_isolated(
            full_runner,
            tmp_path,
            command,
            "--help",
            without_site_packages=False,
        )
        portable_help = _run_isolated(
            portable_runner,
            tmp_path,
            command,
            "--help",
            without_site_packages=True,
        )
        assert full_help.returncode == portable_help.returncode == 0
        assert full_help.stderr == portable_help.stderr == ""

    rubric = skill / "src/regulatory_harvest/evaluation/readiness-rubric-v1.json"
    assert (
        rubric.read_bytes()
        == (ROOT / "src/regulatory_harvest/evaluation/readiness-rubric-v1.json").read_bytes()
    )

    monkeypatch.syspath_prepend(str(ROOT / "tests" / "skill"))
    monkeypatch.syspath_prepend(str(ROOT / "tests" / "evaluation"))
    fixture_support = __import__("test_skill_package")
    stress = __import__("test_attorney_readiness_stress")
    baseline_artifacts = __import__("test_attorney_baseline_artifacts")
    input_helpers = __import__("test_attorney_readiness_inputs")
    workflow_tests = __import__("test_attorney_readiness_workflow")
    draft_tests = __import__("test_attorney_readiness_drafts")
    from regulatory_harvest.evaluation.attorney_readiness_drafts import (
        ReadinessEvaluatorProvenanceV1,
        compile_readiness_draft_v1,
    )
    from regulatory_harvest.evaluation.attorney_readiness_models import (
        ReadinessEvaluatorRequestV1,
        ReadinessOperationV1,
    )

    _, rubric_policy, _ = stress._portable()._readiness_rubric_v1()
    script = json.loads(
        (ROOT / "tests/fixtures/attorney-readiness-v1/stable/scripted-drafts.json").read_bytes()
    )
    ordinary_journeys = [
        journey for journey in script["journeys"] if not journey["historical_fail_cross_check"]
    ]
    assert [journey["expected_delivery_readiness"] for journey in ordinary_journeys] == [
        "HIGH_ASSURANCE",
        "REVIEW_READY_WITH_GAPS",
        "NOT_DELIVERABLE",
    ]
    provenance = ReadinessEvaluatorProvenanceV1(
        provider_name="public-package-provider",
        model_name="public-package-model",
        judge_isolation="scripted_fixture",
    )

    for journey in ordinary_journeys:
        journey_id = str(journey["journey_id"])
        inputs_root = tmp_path / f"package-inputs-{journey_id}"
        inputs_root.mkdir()
        qualification_run, baseline_run, baseline_context = fixture_support._write_fixture_baseline(
            inputs_root,
            input_helpers,
            baseline_artifacts,
        )
        generation_run, receipt_path, report_text = (
            fixture_support._write_fixture_validation_matter(
                inputs_root,
                baseline_context,
                journey,
                input_helpers,
            )
        )
        full_run = tmp_path / f"package-full-{journey_id}"
        portable_run = tmp_path / f"package-portable-{journey_id}"
        common = (
            "eval-readiness-init",
            "--baseline-run",
            str(baseline_run),
            "--qualification-run",
            str(qualification_run),
            "--generation-run",
            str(generation_run),
            "--validation-receipt",
            str(receipt_path),
        )
        full_init = _run_isolated(
            full_runner,
            tmp_path,
            *common,
            "--run",
            str(full_run),
            without_site_packages=False,
        )
        portable_init = _run_isolated(
            portable_runner,
            tmp_path,
            *common,
            "--run",
            str(portable_run),
            without_site_packages=True,
        )
        assert (full_init.returncode, full_init.stdout, full_init.stderr) == (
            portable_init.returncode,
            portable_init.stdout,
            portable_init.stderr,
        )
        assert full_init.returncode == 0
        assert _run_snapshot(full_run) == _run_snapshot(portable_run)

        vector = stress._vector(journey["seed"], rubric_policy)
        vector.update(journey["vector_overrides"])
        while True:
            full_next = _run_isolated(
                full_runner,
                tmp_path,
                "eval-readiness-next",
                "--run",
                str(full_run),
                without_site_packages=False,
            )
            portable_next = _run_isolated(
                portable_runner,
                tmp_path,
                "eval-readiness-next",
                "--run",
                str(portable_run),
                without_site_packages=True,
            )
            assert (full_next.returncode, full_next.stdout, full_next.stderr) == (
                portable_next.returncode,
                portable_next.stdout,
                portable_next.stderr,
            )
            request_wire = json.loads(full_next.stdout)
            if request_wire is None:
                break
            request = ReadinessEvaluatorRequestV1.model_validate(request_wire)
            if request.operation in {
                ReadinessOperationV1.BASELINE_LOCKED_GRADE,
                ReadinessOperationV1.BASELINE_LOCKED_CONTESTED_GRADE,
            }:
                draft = stress._grade_draft(
                    request,
                    workflow_tests,
                    vector["coverage_mode"],
                    vector["requirement_count"],
                )
            elif request.operation is ReadinessOperationV1.SAFETY_REVIEW:
                draft = stress._safety_draft(
                    request,
                    workflow_tests,
                    draft_tests,
                    vector,
                )
            else:
                draft = workflow_tests._draft(request, grade_mode="met")
            compiled = compile_readiness_draft_v1(
                request,
                copy.deepcopy(draft),
                provenance,
            )
            response_path = tmp_path / f"{journey_id}-response.json"
            response_path.write_bytes(_canonical_bytes(compiled.response.model_dump(mode="json")))
            full_submit = _run_isolated(
                full_runner,
                tmp_path,
                "eval-readiness-submit-safe",
                "--run",
                str(full_run),
                "--response",
                str(response_path),
                without_site_packages=False,
            )
            portable_submit = _run_isolated(
                portable_runner,
                tmp_path,
                "eval-readiness-submit-safe",
                "--run",
                str(portable_run),
                "--response",
                str(response_path),
                without_site_packages=True,
            )
            assert (
                full_submit.returncode,
                full_submit.stdout,
                full_submit.stderr,
            ) == (
                portable_submit.returncode,
                portable_submit.stdout,
                portable_submit.stderr,
            )
            assert json.loads(full_submit.stdout)["accepted"] is True
            assert _run_snapshot(full_run) == _run_snapshot(portable_run)

        expected_exit = (
            4 if journey["expected_delivery_readiness"] == "NOT_DELIVERABLE" else 0
        )
        for command in ("eval-readiness-status", "eval-readiness-verify"):
            full_terminal = _run_isolated(
                full_runner,
                tmp_path,
                command,
                "--run",
                str(full_run),
                without_site_packages=False,
            )
            portable_terminal = _run_isolated(
                portable_runner,
                tmp_path,
                command,
                "--run",
                str(portable_run),
                without_site_packages=True,
            )
            assert (
                full_terminal.returncode,
                full_terminal.stdout,
                full_terminal.stderr,
            ) == (
                portable_terminal.returncode,
                portable_terminal.stdout,
                portable_terminal.stderr,
            )
            assert full_terminal.returncode == expected_exit
            payload = json.loads(full_terminal.stdout)
            assert payload["protocol_version"] == "delivery-readiness-v1"
            assert payload["delivery_readiness"] == journey["expected_delivery_readiness"]
            if command == "eval-readiness-status":
                assert payload["engine_paused"] is False
                assert payload["pending_operation"] is None
            else:
                assert payload["ok"] is True
                assert payload["issue_codes"] == []
            assert _run_snapshot(full_run) == _run_snapshot(portable_run)
        result = json.loads((full_run / "delivery-readiness.json").read_bytes())
        assert result["delivery_readiness"] == journey["expected_delivery_readiness"]
        handoff = (full_run / "attorney-review-handoff.md").read_text(encoding="utf-8")
        assert (report_text in handoff) is (
            journey["expected_delivery_readiness"] != "NOT_DELIVERABLE"
        )


@pytest.mark.parametrize("protocol", ["1.3", "2.0", "2.1", "2.2"])
def test_readiness_packaging_preserves_retained_protocol_trees_and_transcripts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    protocol: str,
) -> None:
    """Opt-in readiness commands must never infer or mutate a retained companion."""
    skill = _build_and_extract(tmp_path)
    full_runner = skill / "scripts" / "harvest_skill.py"
    portable_runner = skill / "scripts" / "harvest_portable.py"
    monkeypatch.syspath_prepend(str(ROOT / "tests" / "scripts"))
    monkeypatch.syspath_prepend(str(ROOT / "tests" / "evaluation"))
    retained = __import__("test_harvest_skill")
    v22 = __import__("test_attorney_v22_workflow")
    run = tmp_path / f"retained-{protocol.replace('.', '')}"
    if protocol == "1.3":
        retained._initialize_eval_run(full_runner, run)
    elif protocol == "2.0":
        retained._initialize_v2_eval_run(run)
    elif protocol == "2.1":
        retained._initialize_v21_eval_run(run)
    else:
        v22.initialize_evaluation_v22(v22._case(), run, seed_hex="4" * 64)

    frozen_tree = _run_snapshot(run)

    def retained_transcripts() -> tuple[tuple[int, str, str], ...]:
        outputs: list[tuple[int, str, str]] = []
        for command in ("eval-status", "eval-verify"):
            full = _run_isolated(
                full_runner,
                tmp_path,
                command,
                "--run",
                str(run),
                without_site_packages=False,
            )
            portable = _run_isolated(
                portable_runner,
                tmp_path,
                command,
                "--run",
                str(run),
                without_site_packages=True,
            )
            full_transcript = (full.returncode, full.stdout, full.stderr)
            portable_transcript = (portable.returncode, portable.stdout, portable.stderr)
            assert full_transcript == portable_transcript
            assert full.returncode == 0
            outputs.append(full_transcript)
        return tuple(outputs)

    before = retained_transcripts()
    assert _run_snapshot(run) == frozen_tree
    frozen_siblings = tuple(sorted(path.name for path in tmp_path.iterdir()))
    for runner, isolated in ((full_runner, False), (portable_runner, True)):
        for command in (
            "eval-readiness-init",
            "eval-readiness-next",
            "eval-readiness-submit-safe",
            "eval-readiness-status",
            "eval-readiness-verify",
        ):
            help_result = _run_isolated(
                runner,
                tmp_path,
                command,
                "--help",
                without_site_packages=isolated,
            )
            assert help_result.returncode == 0
            assert tuple(sorted(path.name for path in tmp_path.iterdir())) == frozen_siblings
        refused = _run_isolated(
            runner,
            tmp_path,
            "eval-readiness-status",
            "--run",
            str(run),
            without_site_packages=isolated,
        )
        assert refused.returncode != 0
        assert _run_snapshot(run) == frozen_tree
        assert tuple(sorted(path.name for path in tmp_path.iterdir())) == frozen_siblings

    assert retained_transcripts() == before
    assert _run_snapshot(run) == frozen_tree
    assert not any("readiness" in path for path in frozen_tree)


@pytest.mark.parametrize("required", READINESS_CANONICAL_JSON_PATHS)
def test_skill_build_refuses_each_noncanonical_readiness_json_input(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    required: str,
) -> None:
    """Reformatting policy or public wire assets must not alter packaged bytes."""
    for relative in READINESS_CANONICAL_JSON_PATHS:
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, target)
    target = tmp_path / required
    target.write_text(
        json.dumps(json.loads(target.read_bytes()), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(skill_builder, "ROOT", tmp_path)

    with pytest.raises(
        skill_builder.SkillBuildError,
        match="delivery-readiness-v1 input is not canonical JSON: " + required,
    ):
        skill_builder._assert_readiness_canonical_inputs()


def test_atomic_v2_template_and_runtime_dependencies_are_byte_complete_in_archive(
    tmp_path: Path,
) -> None:
    """Omitting an atomic dependency or shipping the V1 template breaks clean installs."""
    built = tmp_path / "atomic-v2-skill.zip"
    result = _build(built)
    assert result.returncode == 0, result.stderr
    required = (
        "assets/analysis-draft.template.json",
        "src/regulatory_harvest/analysis/atomic_coverage.py",
        "src/regulatory_harvest/analysis/coverage_common.py",
    )
    manifest_entries = (
        (ROOT / "scripts" / "skill-package-files.txt").read_text(encoding="utf-8").splitlines()
    )
    assert manifest_entries == sorted(set(manifest_entries))
    assert set(required) <= set(manifest_entries)

    with zipfile.ZipFile(built) as archive:
        for relative_path in required:
            assert (
                archive.read(f"regulatory-harvest/{relative_path}")
                == (ROOT / relative_path).read_bytes()
            )
        template = json.loads(
            archive.read("regulatory-harvest/assets/analysis-draft.template.json").decode("utf-8")
        )
    assert template["coverage_contract_version"] == "proposition-coverage-v2"
    assert template["proposition_coverage"] == []
    assert template["lead_reviews"] == []
    assert template["unit_reviews"]
    assert template["rule_atoms"]
    assert template["rule_relationships"]


def test_extracted_skill_runs_complete_flow_without_an_installed_project_copy(
    tmp_path: Path,
) -> None:
    """Importing the development checkout would hide a broken self-contained skill."""
    built = tmp_path / "skill.zip"
    result = _build(built)
    assert result.returncode == 0, result.stderr
    extracted = tmp_path / "extracted"
    with zipfile.ZipFile(built) as archive:
        archive.extractall(extracted)
    skill = extracted / "regulatory-harvest"
    source = tmp_path / "rule.txt"
    source.write_text("A controller must document risks.\n", encoding="utf-8")
    charter = tmp_path / "charter.json"
    charter.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "matter_id": "archive-smoke",
                "matter_title": "Synthetic documentation duty",
                "question": "What must be documented?",
                "jurisdictions": ["US"],
                "as_of": "2026-08-06",
                "source_mode": "provided-only",
                "sources": [
                    {
                        "location": str(source),
                        "source_role": "official_primary",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    matter = tmp_path / "matter"

    prepared = subprocess.run(
        [
            sys.executable,
            "-I",
            str(skill / "scripts" / "harvest_skill.py"),
            "prepare",
            "--charter",
            str(charter),
            "--matter",
            str(matter),
        ],
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
    )

    assert prepared.returncode == 0, prepared.stderr
    assert json.loads(prepared.stdout)["status"] == "prepared"
    assert (matter / "agent-dossier.json").is_file()
    dossier = json.loads((matter / "agent-dossier.json").read_text(encoding="utf-8"))
    source_id = dossier["sources"][0]["source_id"]
    quote = "A controller must document risks."
    draft = tmp_path / "draft.json"
    draft.write_text(
        json.dumps(
            {
                **_strict_coverage(dossier),
                "issues": [
                    {
                        "issue_id": "issue-1",
                        "title": "Documentation",
                        "category": "requirements",
                        "presentation_role": "requirement",
                        "jurisdictions": ["US"],
                    }
                ],
                "findings": [
                    {
                        "finding_id": "finding-1",
                        "issue_id": "issue-1",
                        "title": "Documentation",
                        "jurisdiction": "US",
                        "authority": "Synthetic Rule",
                        "severity": "info",
                        "practical_implication": "Document the risks.",
                        "claims": [
                            {
                                "claim_id": "claim-1",
                                "text": quote,
                                "kind": "source_supported",
                                "proposed_citations": [{"source_id": source_id, "quote": quote}],
                            }
                        ],
                    }
                ],
                "gaps": [],
                "brief": _profiled_brief("finding-1", quote, list_kind="bullet_list"),
            }
        ),
        encoding="utf-8",
    )

    finalized = subprocess.run(
        [
            sys.executable,
            "-I",
            str(skill / "scripts" / "harvest_skill.py"),
            "finalize",
            "--matter",
            str(matter),
            "--draft",
            str(draft),
        ],
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
    )

    assert finalized.returncode == 0, finalized.stderr
    receipt = json.loads(finalized.stdout)
    assert receipt["status"] == "completed"
    assert receipt["valid"] is True
    bundle = json.loads(Path(receipt["bundle"]).read_text(encoding="utf-8"))
    assert len(bundle["findings"]) == 1
    assert len(bundle["citations"]) == 1
    assert not any(gap["code"] == "MODEL_PROVIDER_NOT_CONFIGURED" for gap in bundle["gaps"])
    report = Path(receipt["report"]).read_text(encoding="utf-8")
    audit = Path(receipt["audit"]).read_text(encoding="utf-8")
    assert report.startswith("# Synthetic documentation duty\n")
    for heading in (
        "## Executive Summary",
        "## Key Requirements",
        "## Penalties and Enforcement",
        "## Implementation Workplan",
        "## Limitations and Open Questions",
        "## Sources Consulted",
    ):
        assert heading in report
    assert "## Priority and Posture" not in report
    assert "## Evidence and Validation Appendix" not in report
    assert quote in report
    assert quote in audit


@pytest.mark.parametrize("without_site_packages", [False, True])
def test_extracted_template_reaches_review_required_when_coverage_is_incomplete(
    tmp_path: Path,
    without_site_packages: bool,
) -> None:
    """The strict template must parse in both clean runtimes before coverage repair."""
    skill = _build_and_extract(tmp_path)
    source = tmp_path / "synthetic-rule.txt"
    source.write_text(
        "A controller must document risks. The source does not state a deadline.\n",
        encoding="utf-8",
    )
    charter = tmp_path / "charter.json"
    charter.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "matter_id": "template-coverage-smoke",
                "matter_title": "Synthetic coverage rule",
                "question": "What does the synthetic rule require?",
                "jurisdictions": ["US"],
                "as_of": "2026-08-14",
                "source_mode": "provided-only",
                "sources": [
                    {
                        "location": str(source),
                        "source_role": "official_primary",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    matter = tmp_path / ("matter-portable" if without_site_packages else "matter-full")
    runner = skill / "scripts" / "harvest_skill.py"

    prepared = _run_isolated(
        runner,
        tmp_path,
        "prepare",
        "--charter",
        str(charter),
        "--matter",
        str(matter),
        without_site_packages=without_site_packages,
    )
    assert prepared.returncode == 0, prepared.stderr

    finalized = _run_isolated(
        runner,
        tmp_path,
        "finalize",
        "--matter",
        str(matter),
        "--draft",
        str(skill / "assets" / "analysis-draft.template.json"),
        without_site_packages=without_site_packages,
    )

    assert finalized.returncode == 4, finalized.stderr
    receipt = json.loads(finalized.stdout)
    assert receipt["status"] == "review-required"
    assert receipt["proposition_coverage_valid"] is False
    assert receipt["provision_recall_valid"] is False
    assert Path(receipt["coverage_review"]).is_file()


def test_extracted_skill_runs_all_generation_capsule_commands_in_isolated_mode(
    tmp_path: Path,
) -> None:
    """A release missing either runtime must not advertise capsule-backed evaluation."""
    skill = _build_and_extract(tmp_path)
    runner = skill / "scripts" / "harvest_skill.py"
    capture = tmp_path / "generation-capture"
    (capture / "sources").mkdir(parents=True)
    (capture / "generator").mkdir()
    (capture / "sources" / "rule.txt").write_text(
        "Synthetic Rule. A covered operator must file notice.\n",
        encoding="utf-8",
    )
    (capture / "generator" / "build.bin").write_bytes(
        b"import json, sys\n"
        b"request = json.load(sys.stdin)\n"
        b"sys.stdout.write('# Synthetic Rule\\n\\nGenerated by captured build for: ' "
        b"+ request['question'])\n"
    )
    generation_input = capture / "generation-input.json"
    generation_input.write_bytes(
        _canonical_bytes(
            {
                "candidate_id": "candidate-one",
                "client_facts_path": None,
                "generation_instructions": "Analyze only the supplied synthetic rule.",
                "generator_artifacts": [{"artifact_id": "build", "path": "generator/build.bin"}],
                "question": "What notice is required?",
                "schema_version": "1.0",
                "sources": [{"path": "sources/rule.txt", "source_id": "source-1"}],
            }
        )
    )
    capsule = tmp_path / "capsule"

    initialized = _run_isolated(
        runner,
        tmp_path,
        "eval-gen-init",
        "--input",
        str(generation_input),
        "--run",
        str(capsule),
        "--nonce-hex",
        "1" * 64,
    )
    assert initialized.returncode == 0, initialized.stderr
    next_result = _run_isolated(runner, tmp_path, "eval-gen-next", "--run", str(capsule))
    assert next_result.returncode == 0, next_result.stderr
    request = json.loads(next_result.stdout)
    captured_build = capsule / "captured" / "generator" / "build.bin"
    expected_build_digest = request["generator_artifacts"][0]["content_hash"]
    assert hashlib.sha256(captured_build.read_bytes()).hexdigest() == expected_build_digest
    generated = subprocess.run(
        [sys.executable, "-I", "-S", str(captured_build)],
        cwd=tmp_path,
        env={**os.environ, "PYTHONNOUSERSITE": "1"},
        input=_canonical_bytes(request),
        check=False,
        capture_output=True,
    )
    assert generated.returncode == 0, generated.stderr
    response_path = tmp_path / "generation-response.json"
    response_path.write_bytes(
        _canonical_bytes(
            {
                "generation_isolation": "scripted_fixture",
                "model_name": "captured-synthetic-build",
                "operation": "generate_report",
                "payload": {"report_text": generated.stdout.decode("utf-8")},
                "provider_name": "local-runnable-fixture",
                "request_fingerprint": request["request_fingerprint"],
                "response_id": None,
                "schema_version": "1.0",
                "usage": {},
            }
        )
    )
    submitted = _run_isolated(
        runner,
        tmp_path,
        "eval-gen-submit",
        "--run",
        str(capsule),
        "--response",
        str(response_path),
    )
    assert submitted.returncode == 0, submitted.stderr
    status = _run_isolated(runner, tmp_path, "eval-gen-status", "--run", str(capsule))
    verified = _run_isolated(runner, tmp_path, "eval-gen-verify", "--run", str(capsule))
    assert status.returncode == verified.returncode == 0
    assert json.loads(status.stdout)["state"] == "completed"
    assert json.loads(verified.stdout)["ok"] is True
    assert (capsule / "report.md").read_bytes() == generated.stdout
    record = json.loads((capsule / "generation-record.json").read_text(encoding="utf-8"))
    assert record["report_hash"] == hashlib.sha256(generated.stdout).hexdigest()


def test_extracted_skill_initializes_protocol_2_evaluation_with_runtime_parity(
    tmp_path: Path,
) -> None:
    """The universal ZIP initializes the default evaluator identically without site packages."""
    skill = _build_and_extract(tmp_path)
    runner = skill / "scripts" / "harvest_skill.py"
    fixture = tmp_path / "evaluation-fixture"
    shutil.copytree(EVALUATION_FIXTURE, fixture)
    runs = {
        "full": (tmp_path / "evaluation-run-full", False),
        "portable": (tmp_path / "evaluation-run-portable", True),
    }
    for run, portable in runs.values():
        initialized = _run_isolated(
            runner,
            tmp_path,
            "eval-init",
            "--case",
            str(fixture / "case.json"),
            "--run",
            str(run),
            "--seed-hex",
            "0" * 64,
            without_site_packages=portable,
        )
        assert initialized.returncode == 0, initialized.stderr
    packets: dict[str, dict[str, object]] = {}
    for label, (run, portable) in runs.items():
        next_result = _run_isolated(
            runner,
            tmp_path,
            "eval-next",
            "--run",
            str(run),
            without_site_packages=portable,
        )
        assert next_result.returncode == 0, next_result.stderr
        packets[label] = json.loads(next_result.stdout)

    assert packets["full"] == packets["portable"]
    assert packets["full"]["operation"] == "source_review"


@pytest.mark.parametrize("source_mode", ["provided-only", "web"])
def test_extracted_skill_runs_offline_without_site_packages(
    tmp_path: Path,
    source_mode: str,
) -> None:
    """Claude must not need PyPI access when the host supplies retrieved source text."""
    built = tmp_path / "skill.zip"
    result = _build(built)
    assert result.returncode == 0, result.stderr
    extracted = tmp_path / "extracted"
    with zipfile.ZipFile(built) as archive:
        archive.extractall(extracted)
    skill = extracted / "regulatory-harvest"
    source = tmp_path / "rule.txt"
    quote = "A controller must document material risks before deployment."
    source.write_text(f"{quote}\n", encoding="utf-8")
    charter = tmp_path / "charter.json"
    charter.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "matter_id": f"offline-{source_mode}-archive-smoke",
                "matter_title": "Synthetic documentation duty",
                "question": "What must be documented?",
                "jurisdictions": ["US"],
                "as_of": "2026-08-06",
                "source_mode": source_mode,
                "sources": [
                    {
                        "location": str(source),
                        "canonical_url": "https://example.org/synthetic-rule"
                        if source_mode == "web"
                        else None,
                        "title": "Synthetic Rule",
                        "publisher": "Example Legislature" if source_mode == "web" else None,
                        "jurisdiction": "US",
                        "authority_type": "synthetic example",
                        "citation": "Synthetic Rule 1",
                        "language": "en",
                        "source_quality": "primary" if source_mode == "web" else "unknown",
                        "source_role": "official_primary",
                        "license_assertion": "CC0-1.0",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    matter = tmp_path / "matter"
    environment = os.environ.copy()
    environment.update(
        {
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "PIP_NO_INDEX": "1",
            "PYTHONNOUSERSITE": "1",
        }
    )

    prepared = subprocess.run(
        [
            sys.executable,
            "-I",
            "-S",
            str(skill / "scripts" / "harvest_skill.py"),
            "prepare",
            "--charter",
            str(charter),
            "--matter",
            str(matter),
        ],
        cwd=tmp_path,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    assert prepared.returncode == 0, prepared.stderr
    assert json.loads(prepared.stdout)["status"] == "prepared"
    assert not (matter / ".regulatory-harvest" / "runtime").exists()
    dossier = json.loads((matter / "agent-dossier.json").read_text(encoding="utf-8"))
    source_id = dossier["sources"][0]["source_id"]
    draft = tmp_path / "draft.json"
    draft.write_text(
        json.dumps(
            {
                **_strict_coverage(dossier),
                "issues": [
                    {
                        "issue_id": "issue-1",
                        "title": "Documentation",
                        "category": "requirements",
                        "presentation_role": "requirement",
                        "jurisdictions": ["US"],
                    }
                ],
                "findings": [
                    {
                        "finding_id": "finding-1",
                        "issue_id": "issue-1",
                        "title": "Documentation",
                        "jurisdiction": "US",
                        "authority": "Synthetic Rule 1",
                        "severity": "info",
                        "practical_implication": "Document the risks.",
                        "claims": [
                            {
                                "claim_id": "claim-1",
                                "text": quote,
                                "kind": "source_supported",
                                "proposed_citations": [{"source_id": source_id, "quote": quote}],
                            }
                        ],
                    }
                ],
                "gaps": (
                    [
                        {
                            "code": "CLOSED_UNIVERSE_CURRENTNESS_UNVERIFIED",
                            "message": (
                                "Currentness cannot be established from supplied material."
                            ),
                            "jurisdiction": "US",
                        }
                    ]
                    if source_mode == "provided-only"
                    else []
                ),
                "brief": _profiled_brief("finding-1", quote, list_kind="numbered_list"),
            }
        ),
        encoding="utf-8",
    )

    finalized = subprocess.run(
        [
            sys.executable,
            "-I",
            "-S",
            str(skill / "scripts" / "harvest_skill.py"),
            "finalize",
            "--matter",
            str(matter),
            "--draft",
            str(draft),
            "--host",
            "claude-desktop",
            "--model",
            "sandbox-model",
        ],
        cwd=tmp_path,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    assert finalized.returncode == 0, finalized.stderr
    receipt = json.loads(finalized.stdout)
    assert receipt["status"] == "completed"
    assert receipt["valid"] is True
    assert validate_research_bundle(Path(receipt["bundle"])).valid is True
    bundle = json.loads(Path(receipt["bundle"]).read_text(encoding="utf-8"))
    assert bundle["request"]["source_mode"] == source_mode
    assert Path(receipt["report"]).is_file()
    assert Path(receipt["audit"]).is_file()
    assert Path(receipt["bundle"]).is_file()
    assert (matter / "validation-receipt.json").is_file()


def test_skill_build_fails_when_a_runtime_tree_contains_an_unlisted_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An untracked private note beneath an included tree must never enter the archive."""
    package_root = tmp_path / "package"
    manifest = ROOT / "scripts" / "skill-package-files.txt"
    copied_manifest = package_root / "scripts" / manifest.name
    copied_manifest.parent.mkdir(parents=True)
    shutil.copyfile(manifest, copied_manifest)
    for relative in manifest.read_text(encoding="utf-8").splitlines():
        target = package_root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, target)
    unexpected = package_root / "references" / "private-note.txt"
    unexpected.write_text("private test sentinel\n", encoding="utf-8")
    monkeypatch.setattr(skill_builder, "ROOT", package_root)
    monkeypatch.setattr(skill_builder, "PACKAGE_MANIFEST", copied_manifest)

    with pytest.raises(skill_builder.SkillBuildError, match="unexpected runtime file"):
        skill_builder.build_skill(tmp_path / "skill.zip")


def test_skill_build_refuses_manifest_missing_protocol_21_runtime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The archive guard names a missing 2.1 runtime instead of silently building."""
    required = "src/regulatory_harvest/evaluation/attorney_v21_workflow.py"
    entries = (
        (ROOT / "scripts" / "skill-package-files.txt").read_text(encoding="utf-8").splitlines()
    )
    assert required in entries
    manifest = tmp_path / "skill-package-files.txt"
    manifest.write_text(
        "\n".join(entry for entry in entries if entry != required) + "\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(skill_builder, "PACKAGE_MANIFEST", manifest)

    with pytest.raises(
        skill_builder.SkillBuildError,
        match="skill package manifest is missing Protocol 2.1 input: " + required,
    ):
        skill_builder._runtime_files()


def test_skill_build_refuses_manifest_missing_protocol_22_runtime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The builder rejects an incomplete Protocol 2.2 runtime as one unit."""
    required = "src/regulatory_harvest/evaluation/attorney_v22_workflow.py"
    entries = (
        (ROOT / "scripts" / "skill-package-files.txt").read_text(encoding="utf-8").splitlines()
    )
    assert required in entries
    manifest = tmp_path / "skill-package-files.txt"
    manifest.write_text(
        "\n".join(entry for entry in entries if entry != required) + "\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(skill_builder, "PACKAGE_MANIFEST", manifest)

    with pytest.raises(
        skill_builder.SkillBuildError,
        match="skill package manifest is missing Protocol 2.2 input: " + required,
    ):
        skill_builder._runtime_files()


@pytest.mark.parametrize("required", BASELINE_PACKAGE_PATHS)
def test_skill_build_refuses_each_missing_baseline_runtime_input(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    required: str,
) -> None:
    """Every stable-baseline runtime or asset omission must name the missing input."""
    entries = (
        (ROOT / "scripts" / "skill-package-files.txt").read_text(encoding="utf-8").splitlines()
    )
    assert required in entries
    manifest = tmp_path / "skill-package-files.txt"
    manifest.write_text(
        "\n".join(entry for entry in entries if entry != required) + "\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(skill_builder, "PACKAGE_MANIFEST", manifest)

    with pytest.raises(
        skill_builder.SkillBuildError,
        match="skill package manifest is missing evaluation-baseline-v1 input: " + required,
    ):
        skill_builder._runtime_files()


@pytest.mark.parametrize("required", BASELINE_ASSET_PATHS)
def test_skill_build_refuses_each_noncanonical_baseline_json_input(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    required: str,
) -> None:
    """Every stable-baseline JSON input is guarded as canonical, newline-free bytes."""
    for relative in BASELINE_ASSET_PATHS:
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, target)
    target = tmp_path / required
    target.write_text(
        json.dumps(json.loads(target.read_bytes()), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(skill_builder, "ROOT", tmp_path)

    with pytest.raises(
        skill_builder.SkillBuildError,
        match="evaluation-baseline-v1 input is not canonical JSON: " + required,
    ):
        skill_builder._assert_baseline_canonical_inputs()
