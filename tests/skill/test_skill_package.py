import json
import re
import subprocess
import sys
from pathlib import Path

from regulatory_harvest.analysis import AnalysisDraft
from regulatory_harvest.evaluation.attorney_v21_models import EvaluatorResponseV21
from regulatory_harvest.evaluation.attorney_v22_models import EvaluatorResponseV22

ROOT = Path(__file__).parents[2]
RUNNERS = (
    ROOT / "scripts" / "harvest_skill.py",
    ROOT / "scripts" / "harvest_portable.py",
)


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _normalized_markdown_slice(
    relative_path: str,
    start_heading: str,
    end_heading: str | None,
) -> str:
    text = (ROOT / relative_path).read_text(encoding="utf-8")
    assert text.count(start_heading) == 1
    section = text.split(start_heading, 1)[1]
    if end_heading is not None:
        assert section.count(end_heading) == 1
        section = section.split(end_heading, 1)[0]
    return " ".join(section.casefold().split())


def _run_runner(runner: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(runner), *args],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )


def _complete_template_capsule(
    tmp_path: Path,
    fixture: Path,
    *,
    runner: Path,
    candidate_id: str,
    nonce: str,
    report_text: str,
) -> None:
    input_root = tmp_path / f"input-{fixture.name}-{candidate_id}"
    (input_root / "sources").mkdir(parents=True)
    (input_root / "generator").mkdir()
    for name in (
        "synthetic-registry-rule-consolidated.txt",
        "synthetic-registry-rule-status.txt",
    ):
        (input_root / "sources" / name).write_bytes(
            (fixture / "sources" / name).read_bytes()
        )
    (input_root / "client-facts.txt").write_bytes(
        (fixture / "client-facts.txt").read_bytes()
    )
    (input_root / "generator" / "regulatory-harvest-build.zip").write_bytes(
        b"fictional runnable build archive for template-shape testing"
    )
    generation_input = json.loads(
        (ROOT / "assets" / "attorney-generation-input.template.json").read_bytes()
    )
    generation_input["candidate_id"] = candidate_id
    input_path = input_root / "generation-input.json"
    input_path.write_bytes(_canonical_bytes(generation_input))
    capsule = fixture / "capsules" / candidate_id
    initialized = _run_runner(
        runner,
        "eval-gen-init",
        "--input",
        str(input_path),
        "--run",
        str(capsule),
        "--nonce-hex",
        nonce,
    )
    assert initialized.returncode == 0, initialized.stderr
    requested = _run_runner(runner, "eval-gen-next", "--run", str(capsule))
    assert requested.returncode == 0, requested.stderr
    request = json.loads(requested.stdout)
    generation_response = json.loads(
        (ROOT / "assets" / "attorney-generation-response.template.json").read_bytes()
    )
    generation_response["request_fingerprint"] = request["request_fingerprint"]
    generation_response["payload"]["report_text"] = report_text
    response_path = tmp_path / f"response-{fixture.name}-{candidate_id}.json"
    response_path.write_bytes(_canonical_bytes(generation_response))
    submitted = _run_runner(
        runner,
        "eval-gen-submit",
        "--run",
        str(capsule),
        "--response",
        str(response_path),
    )
    assert submitted.returncode == 0, submitted.stderr
    verified = _run_runner(runner, "eval-gen-verify", "--run", str(capsule))
    assert verified.returncode == 0, verified.stderr
    assert json.loads(verified.stdout)["ok"] is True


def _frontmatter(path: Path) -> tuple[dict[str, str], list[str]]:
    lines = path.read_text(encoding="utf-8").splitlines()
    assert lines[0] == "---"
    end = lines.index("---", 1)
    metadata = {}
    for line in lines[1:end]:
        key, value = line.split(":", 1)
        metadata[key.strip()] = value.strip()
    return metadata, lines[end + 1 :]


def test_skill_uses_the_cross_platform_agent_skills_subset() -> None:
    """Metadata outside Claude's stricter limits would split the universal package."""
    metadata, body = _frontmatter(ROOT / "SKILL.md")

    assert metadata.keys() == {"name", "description"}
    assert metadata["name"] == "regulatory-harvest"
    assert metadata["description"].startswith("Use when ")
    assert len(metadata["description"]) <= 200
    assert len(body) < 500


def test_skill_runtime_resources_are_complete_and_templates_are_valid_json() -> None:
    """A missing referenced runtime file would turn one-step installation into manual repair."""
    required = {
        "scripts/harvest_portable.py",
        "scripts/harvest_skill.py",
        "assets/research-charter.template.json",
        "assets/analysis-draft.template.json",
        "assets/attorney-generation-input.template.json",
        "assets/attorney-generation-response.template.json",
        "assets/attorney-evaluation-case.template.json",
        "assets/attorney-evaluation-response.template.json",
        "references/attorney-evaluation.md",
        "references/research-protocol.md",
        "references/authority-and-currentness.md",
        "references/draft-schema.md",
        "references/security-and-privacy.md",
    }

    assert {path for path in required if not (ROOT / path).is_file()} == set()
    charter = json.loads(
        (ROOT / "assets/research-charter.template.json").read_text(encoding="utf-8")
    )
    draft = json.loads((ROOT / "assets/analysis-draft.template.json").read_text(encoding="utf-8"))
    assert charter["schema_version"] == "1.0"
    assert charter["matter_title"]
    assert charter["source_mode"] in {"provided-only", "web"}
    assert charter["sources"]
    assert {"canonical_url", "language", "source_role"} <= set(charter["sources"][0])
    assert set(draft) == {
        "issues",
        "findings",
        "gaps",
        "lead_reviews",
        "coverage_contract_version",
        "proposition_coverage",
        "unit_reviews",
        "lead_dispositions_v2",
        "rule_atoms",
        "rule_relationships",
        "brief",
    }
    assert draft["coverage_contract_version"] == "proposition-coverage-v2"
    assert draft["lead_reviews"] == []
    assert draft["proposition_coverage"] == []
    assert len(draft["unit_reviews"]) == 2
    dimension_names = {
        "authority_status_timing",
        "actors_scope_activities",
        "definitions_categories",
        "duties_rights_prohibitions",
        "triggers_thresholds",
        "conditions_exceptions_defenses",
        "deadlines_transitions",
        "enforcement_remedies_consequences",
        "cross_references_dependencies",
    }
    assert all(
        set(review["dimensions"]) == dimension_names
        for review in draft["unit_reviews"]
    )
    duty_lead = next(
        row
        for row in draft["lead_dispositions_v2"]
        if row["lead_id"] == "lead-duty-__REPLACE__"
    )
    navigation_lead = next(
        row
        for row in draft["lead_dispositions_v2"]
        if row["lead_id"] == "lead-navigation-__REPLACE__"
    )
    assert duty_lead == {
        "lead_id": "lead-duty-__REPLACE__",
        "disposition": "mapped",
        "atom_ids": ["atom-duty-__REPLACE__"],
    }
    assert navigation_lead["disposition"] == "not_material"
    assert navigation_lead["rationale"]
    atoms = {row["atom_id"]: row for row in draft["rule_atoms"]}
    duty_row = atoms["atom-duty-__REPLACE__"]
    exception_row = atoms["atom-exception-__REPLACE__"]
    submission_row = atoms["atom-submission-duty-__REPLACE__"]
    deadline_row = atoms["atom-deadline-__REPLACE__"]
    assert [
        duty_row["proposition_type"],
        exception_row["proposition_type"],
        submission_row["proposition_type"],
        deadline_row["proposition_type"],
    ] == ["duty", "exception", "duty", "deadline"]
    assert set(duty_row["lead_ids"]).isdisjoint(deadline_row["lead_ids"])
    assert deadline_row["unit_ids"] == ["unit-rule-__REPLACE__"]
    assert deadline_row["lead_ids"] == ["lead-deadline-__REPLACE__"]
    assert deadline_row["category"] == "deadlines"
    assert deadline_row["elements"]["operative_action"]["text"] == "submit"
    assert deadline_row["elements"]["object"]["text"] == "incident register"
    assert deadline_row["elements"]["trigger"]["text"] == "reporting trigger"
    assert deadline_row["elements"]["timing"] == {
        "status": "stated",
        "text": "after the reporting trigger",
        "claim_ids": ["claim-deadline-__REPLACE__"],
    }
    deadline_gap = next(
        gap
        for gap in draft["gaps"]
        if gap["code"]
        == "REGISTER_SUBMISSION_INTERVAL_NOT_ESTABLISHED___REPLACE__"
    )
    assert {
        "category": deadline_gap["category"],
        "source_ids": deadline_gap["source_ids"],
    } == {
        "category": "deadlines",
        "source_ids": ["src___REPLACE__"],
    }
    navigation_unit = next(
        row
        for row in draft["unit_reviews"]
        if row["unit_id"] == "unit-navigation-__REPLACE__"
    )
    assert {
        dimension["disposition"]
        for dimension in navigation_unit["dimensions"].values()
    } == {"not_material"}
    claims = {
        claim["claim_id"]: claim
        for finding in draft["findings"]
        for claim in finding["claims"]
    }
    assert claims["claim-duty-__REPLACE__"]["text"] == (
        "A covered operator must maintain a public incident register."
    )
    assert claims["claim-deadline-__REPLACE__"]["text"] == (
        "A covered operator must submit the incident register after the reporting trigger."
    )
    duty_claim = claims["claim-duty-__REPLACE__"]
    deadline_claim = claims["claim-deadline-__REPLACE__"]
    assert duty_claim["proposed_citations"][0]["quote"] == duty_claim["text"]
    assert deadline_claim["proposed_citations"][0]["quote"] == deadline_claim["text"]
    visible_items = [
        item
        for section in draft["brief"]["sections"]
        for block in section.get("blocks", [])
        if block.get("purpose") == "legal_analysis"
        for item in block.get("items", [block])
    ]
    bound = next(
        item
        for item in visible_items
        if "relationship-exception-__REPLACE__"
        in item.get("relationship_ids", [])
    )
    assert {
        "claim-duty-__REPLACE__",
        "claim-exception-__REPLACE__",
        "claim-deadline-__REPLACE__",
    } <= set(bound["claim_ids"])
    assert {
        "atom-duty-__REPLACE__",
        "atom-exception-__REPLACE__",
        "atom-submission-duty-__REPLACE__",
        "atom-deadline-__REPLACE__",
    } <= set(bound["atom_ids"])
    relationships = {
        row["relationship_id"]: row for row in draft["rule_relationships"]
    }
    assert relationships["relationship-exception-__REPLACE__"] == {
        "relationship_id": "relationship-exception-__REPLACE__",
        "relation_type": "exception_to",
        "source_atom_id": "atom-exception-__REPLACE__",
        "target_atom_id": "atom-duty-__REPLACE__",
        "claim_ids": [
            "claim-duty-__REPLACE__",
            "claim-exception-__REPLACE__",
        ],
    }
    assert relationships["relationship-deadline-__REPLACE__"] == {
        "relationship_id": "relationship-deadline-__REPLACE__",
        "relation_type": "deadline_for",
        "source_atom_id": "atom-deadline-__REPLACE__",
        "target_atom_id": "atom-submission-duty-__REPLACE__",
        "claim_ids": ["claim-deadline-__REPLACE__"],
    }
    assert draft["issues"][0]["category"] in {
        "status",
        "scope",
        "requirements",
        "enforcement",
        "deadlines",
        "implementation",
        "other",
    }
    assert draft["gaps"][0]["category"] in {
        "status",
        "scope",
        "requirements",
        "enforcement",
        "deadlines",
        "implementation",
        "other",
    }
    assert draft["issues"][0]["presentation_role"] == "requirement"
    factual_gap = next(
        gap
        for gap in draft["gaps"]
        if gap["code"] == "FACTUAL_CONTEXT_REQUIRED___REPLACE__"
    )
    assert factual_gap["presentation_role"] == "client_facts"
    assert draft["brief"]["executive_summary"]
    assert draft["brief"]["sections"]
    assert draft["brief"]["sections"][0]["section_id"]
    assert draft["brief"]["structure_profile"] == "regulatory-walk-v1"
    assert [section["role"] for section in draft["brief"]["sections"]] == [
        "key_requirements",
        "penalties_enforcement",
        "implementation",
    ]
    assert [section["title"] for section in draft["brief"]["sections"]] == [
        "Key Requirements",
        "Penalties and Enforcement",
        "Implementation Workplan",
    ]
    assert any(
        block.get("purpose") == "limitation"
        and block.get("text", "").startswith("Not established:")
        for section in draft["brief"]["sections"]
        if section["role"] == "penalties_enforcement"
        for block in section["blocks"]
    )
    assert any(gap["category"] == "enforcement" for gap in draft["gaps"])

    purposes_by_role: dict[str, list[str]] = {}
    for section in draft["brief"]["sections"]:
        purposes = [block["purpose"] for block in section.get("blocks", [])]
        purposes.extend(
            block["purpose"]
            for subsection in section.get("subsections", [])
            for block in subsection.get("blocks", [])
        )
        purposes_by_role[section["role"]] = purposes
    assert set(purposes_by_role["key_requirements"]) <= {
        "legal_analysis",
        "limitation",
    }
    assert set(purposes_by_role["implementation"]) <= {
        "application",
        "client_fact",
        "limitation",
    }
    assert AnalysisDraft.model_validate(draft).brief is not None


def test_skill_instruction_surfaces_use_one_pass_order_and_claim_bindings() -> None:
    skill = (ROOT / "SKILL.md").read_text(encoding="utf-8")
    schema = (ROOT / "references" / "draft-schema.md").read_text(encoding="utf-8")
    protocol = (ROOT / "references" / "research-protocol.md").read_text(
        encoding="utf-8"
    )
    prompt = (
        ROOT / "src" / "regulatory_harvest" / "analysis" / "prompts" / "build-v1.md"
    ).read_text(encoding="utf-8")

    assert "Attach the supporting `finding_ids`, then group" not in skill
    assert "Attach the supporting `finding_ids`, then group" not in schema
    assert "Attach the supporting `claim_ids`" in skill
    assert "using `claim_ids`, `atom_ids`, and `relationship_ids`" in schema
    assert (
        "Attach the supporting `claim_ids` and include owning `finding_ids` when useful"
        in prompt
    )
    assert "and their owning `finding_ids`" not in prompt
    assert (
        "Use a completeness challenge and synthesis pass before the evidence-hardening pass"
        not in protocol
    )
    v2_labels = (
        "Provision sweep",
        "Target review",
        "Atomic rule graph",
        "Completeness challenge",
        "Evidence-hardening pass",
        "Synthesis pass",
        "Coverage reconciliation",
        "Adversarial omission review",
        "Finalize and repair",
    )
    positions = [skill.index(label) for label in v2_labels]
    assert positions == sorted(positions)
    protocol_labels = (
        "Provision sweep",
        "Target review",
        "Atomic rule graph",
        "Completeness challenge",
        "Evidence hardening",
        "Synthesis and visible binding",
        "Adversarial omission review",
        "Finalize and repair",
    )
    positions = [protocol.index(label) for label in protocol_labels]
    assert positions == sorted(positions)
    prompt_labels = (
        "Provision sweep",
        "Target review",
        "Proposition coverage table and atomic rule graph",
        "Completeness challenge",
        "Synthesis pass",
        "Evidence-hardening pass",
        "Coverage reconciliation",
        "Adversarial omission review",
        "Finalize and repair",
    )
    positions = [prompt.index(label) for label in prompt_labels]
    assert positions == sorted(positions)


def test_skill_routes_evaluation_without_displacing_substantive_research() -> None:
    """An evaluation request must not become research or expose a rating workflow."""
    metadata, _ = _frontmatter(ROOT / "SKILL.md")
    skill = (ROOT / "SKILL.md").read_text(encoding="utf-8")
    folded = skill.casefold()

    assert "evaluate a report" in metadata["description"].casefold()
    assert "compare reports" in metadata["description"].casefold()
    assert "references/attorney-evaluation.md" in skill
    assert "references/security-and-privacy.md" in skill
    assert "Do not ask the user to rate either report" in skill
    assert "newly generated report" in folded
    assert "generation capsule" in folded
    assert "historical or external report" in folded
    assert "absolute evaluation" in folded
    assert "winner or tie" in folded
    assert "normal regulatory research remains the default" in folded
    assert folded.index("references/attorney-evaluation.md") < folded.index(
        "## choose the source mode"
    )


def test_evaluation_reference_defines_one_request_blind_protocol_in_order() -> None:
    """Reordering the host loop would expose reports before the legal ledger is sealed."""
    skill = (ROOT / "SKILL.md").read_text(encoding="utf-8")
    reference = (ROOT / "references" / "attorney-evaluation.md").read_text(
        encoding="utf-8"
    )
    folded = reference.casefold()
    normalized = " ".join(folded.split())

    public_guidance = "\n".join(
        [
            skill,
            reference,
            *(
                (ROOT / "assets" / name).read_text(encoding="utf-8")
                for name in (
                    "attorney-generation-input.template.json",
                    "attorney-generation-response.template.json",
                    "attorney-evaluation-case.template.json",
                    "attorney-evaluation-response.template.json",
                )
            ),
        ]
    ).casefold()
    for obsolete in ("access_receipt", "self-attest", "self attestation"):
        assert obsolete not in public_guidance

    generation_markers = (
        "copy `assets/attorney-generation-input.template.json`",
        "run `eval-gen-init`",
        "run `eval-gen-next`",
        "execute only the current generation packet",
        "write only the strict generation response envelope",
        "run `eval-gen-submit`",
        "run `eval-gen-verify`",
        "schema `1.1` evaluation case",
        "run `eval-init`",
    )
    generation_offsets = [
        normalized.index(marker.casefold()) for marker in generation_markers
    ]
    assert generation_offsets == sorted(generation_offsets)
    assert "one absolute evaluation per report" in normalized
    assert "no winner or tie" in normalized
    assert "generate new comparison reports" in normalized
    assert "actual generator build used" in normalized
    assert "must produce the report" in normalized
    assert "verify its digest immediately before launch" in normalized
    assert "launch that exact verified build" in normalized
    assert "report evaluation only" in normalized
    assert "release zip" in normalized
    assert "source-tree digest manifest" in normalized
    assert "a name or version label alone is not sufficient" in normalized
    assert "malicious or compromised host" in normalized
    assert "proves only this local sequence" in normalized
    for limitation in (
        "used no other context",
        "provider and model labels are truthful",
        "obeyed the generation instructions",
        "recreated the capsule after the fact",
    ):
        assert limitation in normalized

    role_loop_start = folded.index("## run the blind role loop")
    role_loop_end = folded.index("to resume an existing run", role_loop_start)
    role_loop = folded[role_loop_start:role_loop_end]
    normalized_role_loop = " ".join(role_loop.split())
    ordered_role_markers = (
        "run `eval-init`",
        "write `next-request.json`",
        "read only `next-request.json`",
        "execute only the named role",
        "write only the judge response envelope",
        "run `eval-preflight`",
        "run `eval-submit`",
        "run `eval-verify`",
    )
    role_offsets = [
        normalized_role_loop.index(marker.casefold()) for marker in ordered_role_markers
    ]
    assert role_offsets == sorted(role_offsets)
    step_titles = [
        line.split("**", 2)[1].removesuffix(".").casefold()
        for line in role_loop.splitlines()
        if line[:1].isdigit() and ". **" in line
    ]
    assert step_titles == [
        "initialize",
        "request the next role",
        "execute one role",
        "respond",
        "preflight",
        "submit",
        "advance",
        "verify",
    ]
    assert folded.index("run `eval-verify`", role_loop_start) < folded.index(
        "`evaluation-report.md`", role_loop_end
    )
    assert reference.index("Seal the legal ledger") < reference.index("Grade Report A")
    for forbidden_read in (
        "sealed mapping",
        "other report",
        "prior grader response",
        "later-phase artifacts",
    ):
        assert forbidden_read in folded
    for terminal in ("completed", "CASE_INVALID", "INCONCLUSIVE"):
        assert terminal.casefold() in folded
    for admission_code in (
        "AUTHORITY_ALIGNMENT",
        "OPERATIVE_TEXT",
        "CURRENTNESS_EVIDENCE",
        "LANGUAGE_RESOLUTION",
        "SOURCE_PARITY",
    ):
        assert admission_code in reference
    assert "source_record.source_record_fingerprint" in reference
    assert "relationship_ids" in reference
    assert "requirement or prohibition" in folded
    assert "exception entry" in folded
    for ledger_invariant in (
        "unique ledger and gap identifiers",
        "known, non-self relationships",
        "exact, nonduplicate half-open citations",
        "exact non-commentary source support",
        "trigger or timing alone does not satisfy this",
        "preflight the complete draft",
    ):
        assert ledger_invariant in folded
    assert "one entry grade for every sealed ledger entry" in folded
    assert "all eight narrative dimensions" in folded
    assert "fresh_context" in reference
    assert "sequential_same_context" in reference
    assert "generation_capsule_path" in reference
    assert "external_report_path" in reference
    assert (
        '{"candidate_id":"historical-report","external_report_path":'
        '"reports/historical-report.md","generation_capsule_path":null,'
        '"role":"candidate"}'
    ) in reference
    assert "client_facts_path" in reference
    assert "source_parity_unproven" in folded
    assert "leading and trailing whitespace" in folded
    assert "crlf versus" in folded
    assert "physical absolute paths" in folded
    assert "symlink aliases" in folded
    assert folded.index("physical absolute paths") < folded.index(
        "## generate capsule-backed reports"
    )
    for privacy_boundary in (
        "access-controlled",
        "non-synced",
        "non-public",
        "host ai service",
        "processing and retention",
        "explicit authorization before uploading or sharing",
    ):
        assert privacy_boundary in folded
    for immutable_input in (
        "sources",
        "client facts",
        "reports",
        "role responses",
        "generator artifact",
    ):
        assert immutable_input in normalized
    for excluded_capture in (
        "credentials",
        "environment files",
        "configuration files",
        "`.git`",
        "unrelated tree files",
    ):
        assert excluded_capture in normalized
    assert "Do not ask the user for ratings" in reference
    assert "requirement-by-requirement matrix" in folded
    assert "aggregate score table" in folded
    for command in (
        "eval-gen-init",
        "eval-gen-next",
        "eval-gen-submit",
        "eval-gen-status",
        "eval-gen-verify",
        "eval-init",
        "eval-next",
        "eval-preflight",
        "eval-submit",
        "eval-status",
        "eval-verify",
    ):
        assert f"`{command}" in reference


def test_evaluation_guidance_preflights_every_role_before_submission() -> None:
    """Invalid role responses must be repaired without consuming a judge attempt."""
    reference = (ROOT / "references" / "attorney-evaluation.md").read_text(
        encoding="utf-8"
    ).casefold()
    role_loop_start = reference.index("## run the blind role loop")
    role_loop_end = reference.index("to resume an existing run", role_loop_start)
    normalized = " ".join(reference[role_loop_start:role_loop_end].split())

    assert "before every `eval-submit`" in normalized
    assert "same semantic validation" in normalized
    assert "writes nothing" in normalized
    assert "never submit an invalid response" in normalized
    assert "fresh isolated host context" in normalized
    assert "preflight again" in normalized
    assert normalized.index("run `eval-preflight`") < normalized.index(
        "run `eval-submit`"
    )


def test_fresh_role_executor_receives_outer_envelope_transport_preamble() -> None:
    """A fresh judge must not mistake the inner judgment for the submitted response."""
    reference = (ROOT / "references" / "attorney-evaluation.md").read_text(
        encoding="utf-8"
    ).casefold()
    start = reference.index("### isolation and blindness")
    end = reference.index("### judge response envelope", start)
    executor_guidance = " ".join(reference[start:end].split())

    for transport_rule in (
        "host-neutral role-executor preamble",
        "only evidence",
        "transport instructions are not evidence",
        "must not read any other file",
        "system_instructions govern the judgment",
        "json_schema governs the inner payload",
        "exact outer judge response envelope",
        '"schema_version":"1.0"',
        '"operation":"<copy operation>"',
        '"request_fingerprint":"<copy request_fingerprint>"',
        '"provider_name":"<actual provider>"',
        '"model_name":"<actual model>"',
        '"judge_isolation":"<truthful isolation mode>"',
        '"payload":<schema-valid inner judgment>',
        "canonical utf-8 json",
        "sorted object keys",
        "separators `,` and `:`",
        "no trailing newline",
    ):
        assert transport_rule in executor_guidance
    assert '"return only" the judgment' in executor_guidance
    assert "does not remove the outer envelope" in executor_guidance


def test_evaluation_guidance_separates_initial_findings_from_remaining_disputes() -> None:
    """The audit role may find defects; only unresolved repair output must be executable."""
    reference = (ROOT / "references" / "attorney-evaluation.md").read_text(
        encoding="utf-8"
    ).casefold()

    audit_start = reference.index("for `audit_ledger`")
    audit_end = reference.index("for `grade_report`", audit_start)
    audit_guidance = " ".join(reference[audit_start:audit_end].split())

    for required_initial_finding_rule in (
        "initial audit findings",
        "qualitative",
        "use only the current source record",
        "source-grounded rationale",
        "permitted action",
        "materiality",
        "every initial finding",
    ):
        assert required_initial_finding_rule in audit_guidance
    assert "remaining_audit" in audit_guidance
    assert "transaction-ready" in audit_guidance
    assert "before sealing or refereeing" in audit_guidance


def test_attorney_evaluation_stays_one_plain_language_request() -> None:
    """Maintainer safeguards must not become attorney-operated protocol mechanics."""
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    start = readme.index("### Evaluate reports automatically")
    end = readme.index("## What you receive", start)
    attorney_journey = readme[start:end].casefold()

    assert "attach the authority packet and the report or reports, then say:" in attorney_journey
    assert (
        "> evaluate these two anonymous regulatory reports against the supplied authority "
        "and give me the automatic result."
    ) in attorney_journey
    assert "one plain-language request" in attorney_journey
    assert "without opening a browser reviewer or asking you to score either report" in (
        attorney_journey
    )
    for internal_mechanic in (
        "eval-next",
        "eval-preflight",
        "eval-submit",
        "fingerprint",
        "response envelope",
        "control director",
        "command",
        "pending request",
        "json",
        "role packet",
        "role queue",
    ):
        assert internal_mechanic not in attorney_journey


def test_public_evaluation_guidance_preserves_exact_legal_disclaimer() -> None:
    """All public evaluation entry points must retain the approved legal-use text."""
    disclaimer = (
        "Results are AI Generated and may contain errors. Output must be validated "
        "by an attorney before the attorney delivers legal advice."
    )

    for path in (
        ROOT / "SKILL.md",
        ROOT / "references" / "attorney-evaluation.md",
        ROOT / "README.md",
        ROOT / "docs" / "evaluation.md",
    ):
        assert disclaimer in path.read_text(encoding="utf-8"), path


def test_qualification_template_and_guidance_publish_the_schema_1_1_contract() -> None:
    """The copyable source gate must seal build, language, and response provenance."""
    template_path = ROOT / "assets" / "attorney-evaluation-qualification.template.json"
    template = json.loads(template_path.read_bytes())

    assert template["schema_version"] == "1.1"
    assert re.fullmatch(r"[0-9a-f]{40}", template["build_binding"]["commit"])
    assert re.fullmatch(
        r"[0-9a-f]{64}", template["build_binding"]["archive_sha256"]
    )
    source_ids = [source["source_id"] for source in template["sources"]]
    treated_source_ids = [
        source_id
        for treatment in template["language_treatments"]
        for source_id in treatment["source_ids"]
    ]
    assert sorted(treated_source_ids) == sorted(source_ids)
    assert len(treated_source_ids) == len(set(treated_source_ids))
    assert all(
        treatment["method"].strip() and treatment["rationale"].strip()
        for treatment in template["language_treatments"]
    )
    assert "not law" in json.dumps(template).casefold()

    reference = (ROOT / "references" / "attorney-evaluation.md").read_text(
        encoding="utf-8"
    )
    evaluator_docs = (ROOT / "docs" / "evaluation.md").read_text(encoding="utf-8")
    combined = " ".join(f"{reference}\n{evaluator_docs}".split()).casefold()
    for field in (
        "`commit`",
        "`archive_sha256`",
        "`language_treatments`",
        "provider",
        "model",
        "judge_isolation",
    ):
        assert field in combined
    assert "replay-sealed attestations" in combined
    assert "not independent proof" in combined
    assert "schema 1.0" in combined
    assert "raw inner judgment" in combined


def test_generation_templates_match_the_strict_public_wire_contracts() -> None:
    """Template drift must fail before a host creates an unusable capsule."""
    question = (
        "For this synthetic evaluation example only (not law), what is the operative "
        "status, scope, requirements, exceptions, deadlines, enforcement routes, and "
        "penalties under the Synthetic Registry Rule as of 2026-01-15?"
    )
    input_path = ROOT / "assets" / "attorney-generation-input.template.json"
    input_raw = input_path.read_bytes()
    generation_input = json.loads(input_raw)
    assert generation_input == {
        "candidate_id": "synthetic-candidate",
        "client_facts_path": "client-facts.txt",
        "generation_instructions": (
            "Produce a regulation-centered attorney briefing using only this request "
            "packet. State the operative status, scope, requirements, exceptions, "
            "deadlines, enforcement routes, and penalties; cite the supplied source "
            "identifiers; distinguish legal requirements from implementation advice; "
            "and state material gaps."
        ),
        "generator_artifacts": [
            {
                "artifact_id": "regulatory-harvest-build",
                "path": "generator/regulatory-harvest-build.zip",
            }
        ],
        "question": question,
        "schema_version": "1.0",
        "sources": [
            {
                "path": "sources/synthetic-registry-rule-consolidated.txt",
                "source_id": "synthetic-rule-consolidated",
            },
            {
                "path": "sources/synthetic-registry-rule-status.txt",
                "source_id": "synthetic-rule-status",
            },
        ],
    }
    assert input_raw == _canonical_bytes(generation_input)

    response_path = ROOT / "assets" / "attorney-generation-response.template.json"
    response_raw = response_path.read_bytes()
    generation_response = json.loads(response_raw)
    assert generation_response == {
        "generation_isolation": "fresh_context",
        "model_name": "host-configured-model",
        "operation": "generate_report",
        "payload": {
            "report_text": (
                "# Synthetic Registry Rule\n\n"
                "Replace this fictional text with the report produced from the current "
                "generation packet."
            )
        },
        "provider_name": "host-agent",
        "request_fingerprint": "a" * 64,
        "response_id": None,
        "schema_version": "1.0",
        "usage": {},
    }
    assert response_raw == _canonical_bytes(generation_response)


def test_generation_templates_complete_with_both_packaged_runners(
    tmp_path: Path,
) -> None:
    """Both host paths must consume the public templates without shape repair."""
    for index, runner in enumerate(RUNNERS, start=1):
        fixture = tmp_path / runner.stem
        (fixture / "sources").mkdir(parents=True)
        (fixture / "sources" / "synthetic-registry-rule-consolidated.txt").write_text(
            "Synthetic Registry Rule. A covered operator must file within 10 days.\n",
            encoding="utf-8",
        )
        (fixture / "sources" / "synthetic-registry-rule-status.txt").write_text(
            "The fictional rule became operative on 2026-01-15.\n",
            encoding="utf-8",
        )
        (fixture / "client-facts.txt").write_text(
            "The fictional operator is covered.\n", encoding="utf-8"
        )
        _complete_template_capsule(
            tmp_path,
            fixture,
            runner=runner,
            candidate_id="synthetic-candidate",
            nonce=str(index) * 64,
            report_text="# Synthetic report\n\nThe operator must file within 10 days.\n",
        )
        capsule = fixture / "capsules" / "synthetic-candidate"
        assert (capsule / "report.md").is_file()
        assert (capsule / "generation-record.json").is_file()


def test_evaluation_case_template_matches_the_filesystem_case_contract() -> None:
    """The copyable case must use the strict capsule-backed schema 1.1 shape."""
    case_path = ROOT / "assets" / "attorney-evaluation-case.template.json"
    raw = case_path.read_bytes()
    case = json.loads(raw)

    canonical = json.dumps(
        case,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    assert raw == canonical
    assert set(case) == {
        "as_of",
        "candidates",
        "case_id",
        "client_facts_path",
        "jurisdiction",
        "mode",
        "question",
        "requested_authorities",
        "schema_version",
        "sources",
    }
    assert case["schema_version"] == "1.1"
    generation_input = json.loads(
        (ROOT / "assets" / "attorney-generation-input.template.json").read_bytes()
    )
    assert case["question"] == generation_input["question"]
    assert {source["source_id"] for source in case["sources"]} == {
        source["source_id"] for source in generation_input["sources"]
    }
    assert case["mode"] == "current-law"
    assert "synthetic" in case["case_id"]
    assert "not law" in json.dumps(case).casefold()
    assert case["requested_authorities"]
    requested = case["requested_authorities"][0]
    requested_sources = {
        source["source_id"]: source for source in case["sources"]
    }
    assert all(
        requested_sources[source_id]["jurisdiction"] == requested["jurisdiction"]
        and requested_sources[source_id]["authority_type"] == requested["authority_type"]
        for source_id in requested["source_ids"]
    )
    assert {source["completeness"] for source in case["sources"]} >= {
        "complete",
        "consolidated",
    }
    assert {source["language"] for source in case["sources"]} == {"en"}
    assert all(
        set(source)
        == {
            "authority_type",
            "completeness",
            "jurisdiction",
            "language",
            "path",
            "source_id",
            "source_quality",
            "source_role",
            "title",
        }
        for source in case["sources"]
    )
    assert [candidate["role"] for candidate in case["candidates"]] == [
        "candidate",
        "comparator",
    ]
    assert all(
        set(candidate)
        == {
            "candidate_id",
            "external_report_path",
            "generation_capsule_path",
            "role",
        }
        for candidate in case["candidates"]
    )
    assert case["client_facts_path"] == "client-facts.txt"
    assert all(
        candidate["generation_capsule_path"]
        and candidate["external_report_path"] is None
        for candidate in case["candidates"]
    )
    assert "content_hash" not in json.dumps(case)
    assert "sha256" not in json.dumps(case).casefold()


def test_evaluation_case_template_initializes_with_both_packaged_runners(
    tmp_path: Path,
) -> None:
    """A copyable template must pass the real strict loader after its files exist."""
    fixture = tmp_path / "case"
    (fixture / "sources").mkdir(parents=True)
    case_path = fixture / "case.json"
    case_path.write_bytes(
        (ROOT / "assets" / "attorney-evaluation-case.template.json").read_bytes()
    )
    consolidated_bytes = (
        b"Synthetic Registry Rule. A covered operator must file a notice within 10 days.\r\n"
    )
    status_bytes = (
        b"Synthetic Registry Rule became operative on 2026-01-15 and remains operative.\n"
    )
    client_facts_bytes = b"  The synthetic operator is covered.  \n"
    (fixture / "sources" / "synthetic-registry-rule-consolidated.txt").write_bytes(
        consolidated_bytes
    )
    (fixture / "sources" / "synthetic-registry-rule-status.txt").write_bytes(
        status_bytes
    )
    (fixture / "client-facts.txt").write_bytes(client_facts_bytes)
    _complete_template_capsule(
        tmp_path,
        fixture,
        runner=RUNNERS[0],
        candidate_id="synthetic-candidate",
        nonce="1" * 64,
        report_text=(
            "# Synthetic Candidate Report\n\n"
            "A covered operator must file a notice within 10 days.\n"
        ),
    )
    _complete_template_capsule(
        tmp_path,
        fixture,
        runner=RUNNERS[0],
        candidate_id="synthetic-comparator",
        nonce="2" * 64,
        report_text=(
            "# Synthetic Comparator Report\n\n"
            "The fictional rule requires a notice within 10 days.\n"
        ),
    )

    outputs = []
    for runner in RUNNERS:
        result = _run_runner(
            runner,
            "eval-init",
            "--case",
            str(case_path),
            "--run",
            str(tmp_path / f"{runner.name}-run"),
            "--seed-hex",
            "1" * 64,
        )
        assert result.returncode == 0, result.stderr
        outputs.append(result.stdout)

    assert outputs[0] == outputs[1]
    state = json.loads(outputs[0])
    assert state["phase"] == "source_review"
    assert state["current_call_id"] is not None
    assert state["terminal_status"] is None


def test_evaluation_response_template_is_only_the_public_wire_envelope() -> None:
    """Embedding role payload examples would encourage stale or cross-role responses."""
    response_path = ROOT / "assets" / "attorney-evaluation-response.template.json"
    raw = response_path.read_bytes()
    response = json.loads(raw)

    assert response == {
        "schema_version": "1.0",
        "operation": "grade_report",
        "request_fingerprint": "a" * 64,
        "provider_name": "host-agent",
        "model_name": "host-configured-model",
        "judge_isolation": "fresh_context",
        "payload": {},
    }
    canonical = json.dumps(
        response,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    assert raw == canonical


def test_retained_protocol_2_response_template_and_docs_publish_only_bounded_contract() -> None:
    """The v2 wire template remains byte-stable while the docs mark it replay-only."""
    template_path = ROOT / "assets" / "attorney-evaluation-v2-response.template.json"
    assert template_path.is_file()
    raw = template_path.read_bytes()
    response = json.loads(raw)
    assert set(response) == {
        "schema_version",
        "operation",
        "request_fingerprint",
        "provider_name",
        "model_name",
        "judge_isolation",
        "payload",
    }
    assert response["schema_version"] == "2.0"
    assert response["payload"] == {}
    assert raw == _canonical_bytes(response)

    public_docs = "\n".join(
        (ROOT / path).read_text(encoding="utf-8")
        for path in ("docs/evaluation.md", "references/attorney-evaluation.md")
    )
    for phrase in (
        "PASS means the report satisfied this versioned evaluation rubric",
        "It does not",
        "establish legal correctness",
        "at most one",
        "fresh mechanical repair",
        "Protocol 2.1 is the default for new evaluation runs",
        "Protocol 1.3 is retained for replay and read-only verification",
        "Protocol 2.0 is retained for replay and read-only verification",
        "Requirement-level findings are the primary product",
        "attorney review remains required",
    ):
        assert phrase in public_docs


def test_protocol_21_response_template_and_docs_publish_fragmented_contract() -> None:
    """New runs must expose only the gated Protocol 2.1 operator contract."""
    template_path = ROOT / "assets" / "attorney-evaluation-v21-response.template.json"
    raw = template_path.read_bytes()
    response = json.loads(raw)
    assert response == {
        "judge_isolation": "fresh_context",
        "model_name": "example-model",
        "operation": "source_referee_fragment",
        "payload": {},
        "provider_name": "example-provider",
        "request_fingerprint": "0" * 64,
        "schema_version": "2.1",
    }
    assert raw == _canonical_bytes(response)
    assert (
        EvaluatorResponseV21.model_validate_json(raw).operation.value
        == "source_referee_fragment"
    )

    public_doc_paths = (
        "README.md",
        "SKILL.md",
        "docs/evaluation.md",
        "references/attorney-evaluation.md",
    )
    public_docs = "\n".join(
        (ROOT / path).read_text(encoding="utf-8") for path in public_doc_paths
    )
    for phrase in (
        "Protocol 2.1 is the default for new evaluation runs",
        "experimental",
        "public verification gate",
        "one initial response and at most one fresh mechanical repair per fragment",
        "source-only referee packets",
        "at most five",
        "contested requirements",
        "outcome sensitivity",
        "substantive unresolved",
        "INCONCLUSIVE_MECHANICAL",
        "Protocol 1.3 is retained for replay and read-only verification",
        "Protocol 2.0 is retained for replay and read-only verification",
        "attorney review remains required",
    ):
        assert phrase in public_docs
    current_sections = {
        "README.md": (
            "### Automated evaluation operator contract",
            "## Development and contribution status",
        ),
        "SKILL.md": ("## Choose the journey", "## Non-negotiable result"),
        "docs/evaluation.md": (
            "## Protocol 2.1 current evaluator contract",
            "## Retained Protocol 1.3 reference",
        ),
        "references/attorney-evaluation.md": (
            "## Protocol 2.1 new-run contract",
            "## Retained Protocol 1.3 operator reference",
        ),
    }
    for path, (start_heading, end_heading) in current_sections.items():
        current_contract = _normalized_markdown_slice(
            path, start_heading, end_heading
        )
        assert "one initial response" in current_contract
        assert "at most one fresh mechanical repair" in current_contract
        assert any(
            fragment_scope in current_contract
            for fragment_scope in (
                "for every fragment",
                "for each protocol 2.1 fragment",
                "per fragment",
            )
        )
        assert "second mechanical refusal" in current_contract
        assert "inconclusive_mechanical" in current_contract
        assert "one initial response and at most two mechanical repairs" not in current_contract
        assert "never make a fourth attempt" not in current_contract

    retained_sections = {
        "docs/evaluation.md": ("## Retained Protocol 1.3 reference", None),
        "references/attorney-evaluation.md": (
            "## Retained Protocol 1.3 operator reference",
            None,
        ),
    }
    for path, (start_heading, end_heading) in retained_sections.items():
        retained_contract = _normalized_markdown_slice(
            path, start_heading, end_heading
        )
        assert "one initial response and at most two mechanical repairs" in retained_contract
        assert "same diagnostic code occurs twice" in retained_contract
        assert any(
            repair_bound in retained_contract
            for repair_bound in (
                "stop after the second repair even if the diagnostic codes differ",
                "never make a fourth attempt",
            )
        )
        assert (
            "one initial response and at most one fresh mechanical repair per fragment"
            not in retained_contract
        )


def test_protocol_22_evaluator_response_template_is_strict_canonical_json() -> None:
    """The v2.2 compatibility template is a strict seven-key envelope."""
    raw = (ROOT / "assets" / "attorney-evaluation-v22-response.template.json").read_bytes()
    response = json.loads(raw)
    assert response == {
        "judge_isolation": "fresh_context",
        "model_name": "example-model",
        "operation": "source_review_fragment",
        "payload": {},
        "provider_name": "example-provider",
        "request_fingerprint": "0" * 64,
        "schema_version": "2.2",
    }
    assert raw == _canonical_bytes(response)
    assert not raw.endswith(b"\n")
    assert (
        EvaluatorResponseV22.model_validate_json(raw).operation.value
        == "source_review_fragment"
    )


def test_protocol_22_current_contract_is_section_scoped_in_every_public_document() -> None:
    """Current v2.2 wording stays separate from retained protocol instructions."""
    current_sections = {
        "README.md": (
            "#### Protocol 2.2 current evaluator contract",
            "#### Retained Protocol 2.1 operator reference",
        ),
        "SKILL.md": (
            "### Protocol 2.2 current evaluator contract",
            "### Retained Protocol 2.1 operator reference",
        ),
        "docs/evaluation.md": (
            "## Protocol 2.2 current evaluator contract",
            "## Retained Protocol 2.1 reference",
        ),
        "references/attorney-evaluation.md": (
            "## Protocol 2.2 new-run contract",
            "## Retained Protocol 2.1 operator reference",
        ),
    }
    required = (
        "protocol 2.2",
        "explicit experimental",
        "protocol 2.1 remains the new-run default",
        "semantic draft",
        "strict compiled response",
        "safe normalization",
        "content quality",
        "five",
        "exit 6",
        "pending",
        "resume",
        "completed",
        "substantive inconclusive",
        "qualified-attorney",
        "no benchmark claim",
    )
    for path, (start_heading, end_heading) in current_sections.items():
        current = _normalized_markdown_slice(path, start_heading, end_heading)
        for phrase in required:
            assert phrase in current, (path, phrase)
        assert "inconclusive_mechanical" not in current

    for path, (_, retained_heading) in current_sections.items():
        retained = _normalized_markdown_slice(path, retained_heading, None)
        assert "protocol 2.1" in retained
        assert "inconclusive_mechanical" in retained
        assert "one initial response" in retained
        assert "at most one fresh mechanical repair" in retained
        assert "protocol 2.2 remains the new-run default" not in retained


def test_protocol_21_public_flow_and_surface_measurement_are_explicit() -> None:
    """Public guidance names the fragmented 2.1 lifecycle without a benchmark claim."""
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    normalized_readme = " ".join(readme.split())
    for phrase in (
        "source review",
        "source audit",
        "source-only referee packet",
        "contested requirement",
        "two independent grader lanes",
        "outcome sensitivity",
    ):
        assert phrase in normalized_readme
    assert "source-readiness" not in readme
    assert "legal-ledger" not in readme
    automatic_flow = " ".join(
        readme.split("### Evaluate reports automatically", maxsplit=1)[1]
        .split("## What you receive", maxsplit=1)[0]
        .split()
    )
    for phrase in (
        "source review",
        "source audit",
        "source-only referee",
        "contested requirement",
        "two independent grader lanes",
        "outcome sensitivity",
    ):
        assert phrase in automatic_flow

    full_modules = (
        "src/regulatory_harvest/evaluation/attorney_v2_artifacts.py",
        "src/regulatory_harvest/evaluation/attorney_v2_compiler.py",
        "src/regulatory_harvest/evaluation/attorney_v2_models.py",
        "src/regulatory_harvest/evaluation/attorney_v2_requests.py",
        "src/regulatory_harvest/evaluation/attorney_v2_rubric.py",
        "src/regulatory_harvest/evaluation/attorney_v2_workflow.py",
    )
    manifest_entries = (ROOT / "scripts" / "skill-package-files.txt").read_text(
        encoding="utf-8"
    ).splitlines()
    assert set(full_modules) <= set(manifest_entries)
    assert all((ROOT / module).is_file() for module in full_modules)

    portable_lines = (ROOT / "scripts" / "attorney_eval_portable.py").read_text(
        encoding="utf-8"
    ).splitlines()
    portable_marker = (
        "# Protocol 2.0 portable mirror "
        "-------------------------------------------------"
    )
    assert portable_lines.count(portable_marker) == 1
    section_start = portable_lines.index(portable_marker) + 1
    v21_marker = "# Protocol 2.1 portable mirror"
    assert portable_lines.count(v21_marker) == 1
    v2_section = portable_lines[section_start : portable_lines.index(v21_marker)]
    assert "def _v2_initialize_evaluation(" in v2_section
    assert any(
        line.startswith("def stop_evaluation_v2_inconclusive(") for line in v2_section
    )


def test_skill_requires_expansive_analysis_before_evidence_hardening() -> None:
    """The authoring workflow must optimize for issue recall before quote precision."""
    documents = [
        (ROOT / "SKILL.md").read_text(encoding="utf-8"),
        (ROOT / "references" / "research-protocol.md").read_text(encoding="utf-8"),
        (ROOT / "references" / "draft-schema.md").read_text(encoding="utf-8"),
    ]
    combined = "\n".join(documents).casefold()

    for term in (
        "full normalized text",
        "provision sweep",
        "evidence inventory",
        "completeness challenge",
        "synthesis pass",
        "evidence-hardening pass",
        "adversarial omission review",
        "coverage-review.json",
        "all nine dimensions",
        "typed relationships",
    ):
        assert term in combined
    assert "index, not a substitute" in combined
    assert "before attaching exact quotations" in combined
    assert "generate expansively" in combined
    assert "verify conservatively" in combined


def test_skill_requires_an_atomic_rule_graph_before_prose_drafting() -> None:
    """Narrative compression must not drop independently operative legal elements."""
    documents = [
        (ROOT / "SKILL.md").read_text(encoding="utf-8"),
        (ROOT / "references" / "research-protocol.md").read_text(encoding="utf-8"),
        (ROOT / "references" / "draft-schema.md").read_text(encoding="utf-8"),
        (
            ROOT
            / "src"
            / "regulatory_harvest"
            / "analysis"
            / "prompts"
            / "build-v1.md"
        ).read_text(encoding="utf-8"),
    ]
    combined = "\n".join(documents).casefold()

    for term in (
        "atomic rule graph",
        "independently operative proposition",
        "actor",
        "trigger",
        "condition",
        "exception",
        "timing",
        "consequence",
        "claim_ids",
        "visible `legal_analysis`",
        "mapped",
        "gap",
        "coverage reconciliation",
    ):
        assert term in combined
    for challenged_category in (
        "exceptions",
        "thresholds",
        "triggers",
        "consequences",
        "cross-references",
    ):
        assert challenged_category in combined
    assert "provision-lead inventory is not the coverage table" in combined
    assert "defined-category fidelity check" in combined
    assert "narrower or broader colloquial label" in combined


def test_skill_requires_strict_atomic_coverage_and_finite_repair() -> None:
    """The host must close every prepared target before delivery."""
    instruction_paths = (
        "SKILL.md",
        "references/draft-schema.md",
        "references/research-protocol.md",
        "src/regulatory_harvest/analysis/prompts/build-v1.md",
    )
    documents = [
        (ROOT / path).read_text(encoding="utf-8") for path in instruction_paths
    ]
    combined = "\n".join(documents)
    folded = combined.casefold()

    for phrase in (
        "proposition-coverage-v2",
        "source_unit_inventory",
        "unit_reviews",
        "lead_dispositions_v2",
        "rule_atoms",
        "rule_relationships",
        "every source unit",
        "every finite diagnostic",
        "proposition_coverage_valid",
    ):
        assert phrase.casefold() in folded
    for phrase in (
        "read every successful source in full",
        "before report prose",
        "all nine dimensions",
        "coverage-review.json",
        "evidence_precision_valid",
        "provision_recall_valid",
    ):
        assert phrase.casefold() in folded
    assert "attorney never edits the atom graph" in folded
    assert "not rendered as a database view" in folded


def test_skill_package_manifest_includes_strict_coverage_runtime_in_lexical_order() -> None:
    """Both strict-coverage modules must survive clean skill installation."""
    manifest_entries = (ROOT / "scripts/skill-package-files.txt").read_text(
        encoding="utf-8"
    ).splitlines()

    assert "src/regulatory_harvest/analysis/proposition_coverage.py" in manifest_entries
    assert "src/regulatory_harvest/analysis/source_units.py" in manifest_entries
    analysis_entries = [
        entry
        for entry in manifest_entries
        if entry.startswith("src/regulatory_harvest/analysis/")
        and "/prompts/" not in entry
    ]
    assert analysis_entries == sorted(analysis_entries)


def test_skill_requires_two_pass_status_first_attorney_research() -> None:
    """The skill must encode the research behaviors missing from the blind-review output."""
    skill = (ROOT / "SKILL.md").read_text(encoding="utf-8")
    protocol = (ROOT / "references" / "research-protocol.md").read_text(
        encoding="utf-8"
    )
    authority = (ROOT / "references" / "authority-and-currentness.md").read_text(
        encoding="utf-8"
    )
    combined = "\n".join((skill, protocol, authority)).casefold()

    assert "discovery pass" in combined
    assert "verification pass" in combined
    assert "source matrix" in combined
    assert "status-first" in combined
    assert "nonoperative" in combined
    assert "assumption matrix" in combined
    assert "source language" in combined
    assert "english" in combined
    assert "canonical_url" in combined


def test_skill_requires_adaptive_legacy_native_attorney_briefing() -> None:
    """Host-authored drafts must control a matter-specific attorney report structure."""
    draft_reference = (ROOT / "references" / "draft-schema.md").read_text(
        encoding="utf-8"
    ).casefold()
    skill = (ROOT / "SKILL.md").read_text(encoding="utf-8").casefold()

    for category in (
        "status",
        "scope",
        "requirements",
        "enforcement",
        "deadlines",
        "implementation",
    ):
        assert category in draft_reference
    combined = f"{draft_reference}\n{skill}"
    for schema_term in (
        "executive_summary",
        "sections",
        "paragraph",
        "bullet_list",
        "numbered_list",
        "table",
    ):
        assert schema_term in draft_reference
    assert "matter-specific" in combined
    assert "summary-first" in combined
    assert "`report.md`" in skill
    assert "`audit.md`" in skill
    assert "fixed report hierarchy" not in combined
    assert "report hierarchy is fixed" not in combined
    assert "presentation_role" in skill
    assert "source_role" in skill
    assert "coverage contract" in skill
    assert "do not create a separate bottom line" in skill
    assert "finished attorney memo" in combined
    assert "coherent prose" in combined
    assert "findings are evidence units, not document units" in combined
    assert "do not automatically turn each finding into a heading" in combined
    assert "compositional patterns, not required headings" in combined
    assert "## bottom line" not in skill


def test_skill_requires_regulation_centered_direct_legal_voice() -> None:
    """The host must explain the law instead of summarizing its source packet."""
    skill = (ROOT / "SKILL.md").read_text(encoding="utf-8").casefold()
    draft_reference = (ROOT / "references" / "draft-schema.md").read_text(
        encoding="utf-8"
    ).casefold()

    for document in (skill, draft_reference):
        assert "regulation-centered" in document
        assert "direct legal voice" in document
        assert "regulatory walk" in document
        assert "source sufficiency" in document
        assert "implementation workplan" in document
    assert "make the law, regulator, regulated actor, right, duty, or prohibition" in skill
    assert "scope and applicability" in skill
    assert "definitions, thresholds, exclusions, and exemptions" in skill
    assert "key substantive and procedural requirements" in skill
    assert "enforcement authorities, remedies, penalties, and private rights" in skill
    assert "deadlines, transitions, and recurring timing" in skill


def test_skill_requires_profiled_key_requirements_and_penalties_sections() -> None:
    """The universal package must positively specify the visible regulatory walk."""
    documents = [
        (ROOT / "SKILL.md").read_text(encoding="utf-8"),
        (ROOT / "references" / "draft-schema.md").read_text(encoding="utf-8"),
        (ROOT / "src" / "regulatory_harvest" / "analysis" / "prompts" / "build-v1.md").read_text(
            encoding="utf-8"
        ),
    ]
    combined = "\n".join(documents).casefold()

    for term in (
        "regulatory-walk-v1",
        "key requirements",
        "penalties and enforcement",
        "implementation workplan",
        "key_requirements",
        "penalties_enforcement",
        "not established:",
        "matching categorized gap",
    ):
        assert term in combined
    assert "every supported requirements finding" in combined
    assert "every supported enforcement finding" in combined
    assert "other headings" in combined
    assert "matter-specific" in combined
    for document in documents:
        for term in (
            "source_supported",
            "practical_implication",
            "provision-centered",
            "regulated actor or rights holder",
            "exact quotations",
            "audit.md",
        ):
            assert term in document.casefold()


def test_skill_separates_official_provenance_from_currentness() -> None:
    """Official publication may support authority quality without proving current law."""
    authority = (ROOT / "references" / "authority-and-currentness.md").read_text(
        encoding="utf-8"
    ).casefold()

    assert "legislation.gov.uk" in authority
    assert "eur-lex.europa.eu" in authority
    assert "fedlex.admin.ch" in authority
    assert "does not establish currentness" in authority


def test_attorney_first_readme_explains_precision_recall_and_currentness() -> None:
    """Users need plain-language meaning for the new gates and report label."""
    readme = (ROOT / "README.md").read_text(encoding="utf-8").casefold()
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8").casefold()
    checklist = (ROOT / "docs" / "release-checklist.md").read_text(
        encoding="utf-8"
    ).casefold()

    for term in (
        "coverage-review.json",
        "evidence_precision_valid",
        "provision_recall_valid",
        "generate expansively",
        "verify conservatively",
        "not independently verified through",
    ):
        assert term in readme
    assert "provision-lead inventory" in changelog
    assert "coverage-review.json" in checklist
    assert "private evaluation" in checklist


def test_skill_stops_before_hypothetical_analysis_without_permission() -> None:
    """A no-law result must not silently become uncited legal advice."""
    protocol = (ROOT / "references" / "research-protocol.md").read_text(
        encoding="utf-8"
    ).casefold()

    assert "hypothetical" in protocol
    assert "explicit permission" in protocol
    assert "do not finalize" in protocol
