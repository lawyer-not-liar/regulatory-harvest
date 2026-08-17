import json
import subprocess
import sys
from pathlib import Path

from regulatory_harvest.api import validate_research_bundle
from regulatory_harvest.models import ResearchBundle

ROOT = Path(__file__).parents[2]
SKILL_RUNNER = ROOT / "scripts" / "harvest_skill.py"
RULE_TEXT = (
    "A controller must document material risks before deployment unless the deployment "
    "is solely for a documented emergency test."
)

ATOMIC_ELEMENT_FIELDS = (
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


def _elements(**stated: str) -> dict[str, object]:
    elements: dict[str, object] = {
        field: {"status": "not_applicable"} for field in ATOMIC_ELEMENT_FIELDS
    }
    for field, text in stated.items():
        elements[field] = {
            "status": "stated",
            "text": text,
            "claim_ids": ["claim-rule"],
        }
    return elements


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SKILL_RUNNER), *args],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )


def test_host_agent_draft_becomes_a_valid_cited_attorney_report(tmp_path: Path) -> None:
    """A merely valid source inventory must not be mistaken for a completed attorney answer."""
    source = tmp_path / "rule.txt"
    source.write_text(f"{RULE_TEXT}\n", encoding="utf-8")
    charter = tmp_path / "charter.json"
    charter.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "matter_id": "skill-e2e",
                "matter_title": "Synthetic Documentation Rule",
                "question": "What documentation is required before deployment?",
                "jurisdictions": ["US"],
                "as_of": "2026-08-06",
                "source_mode": "provided-only",
                "sources": [
                    {
                        "location": source.name,
                        "title": "Synthetic Rule",
                        "jurisdiction": "US",
                        "authority_type": "synthetic example",
                        "citation": "Synthetic Rule 1",
                        "source_quality": "unknown",
                        "license_assertion": "CC0-1.0",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    matter = tmp_path / "matter"
    prepared = _run("prepare", "--charter", str(charter), "--matter", str(matter))
    assert prepared.returncode == 0, prepared.stderr
    dossier = json.loads((matter / "agent-dossier.json").read_text(encoding="utf-8"))
    source_id = dossier["sources"][0]["source_id"]
    unit_ids = [
        str(unit["unit_id"])
        for unit in dossier["source_unit_inventory"]["units"]
        if RULE_TEXT in str(unit["excerpt"])
    ]
    leads = [
        lead
        for lead in dossier["evidence_inventory"]["leads"]
        if RULE_TEXT in str(lead["excerpt"])
    ]
    lead_ids = [
        str(lead["lead_id"])
        for lead in leads
        if lead["issue_category"] == "requirements"
    ]
    draft = tmp_path / "analysis-draft.json"
    draft.write_text(
        json.dumps(
            {
                "coverage_contract_version": "proposition-coverage-v2",
                "unit_reviews": [
                    {
                        "unit_id": unit_id,
                        "dimensions": {
                            "authority_status_timing": {"disposition": "not_present"},
                            "actors_scope_activities": {
                                "disposition": "mapped",
                                "atom_ids": ["atom-documentation-duty"],
                            },
                            "definitions_categories": {"disposition": "not_present"},
                            "duties_rights_prohibitions": {
                                "disposition": "mapped",
                                "atom_ids": ["atom-documentation-duty"],
                            },
                            "triggers_thresholds": {"disposition": "not_present"},
                            "conditions_exceptions_defenses": {
                                "disposition": "mapped",
                                "atom_ids": ["atom-emergency-exception"],
                            },
                            "deadlines_transitions": {"disposition": "not_present"},
                            "enforcement_remedies_consequences": {
                                "disposition": "not_present"
                            },
                            "cross_references_dependencies": {
                                "disposition": "not_present"
                            },
                        },
                    }
                    for unit_id in unit_ids
                ],
                "lead_dispositions_v2": [
                    (
                        {
                            "lead_id": str(lead["lead_id"]),
                            "disposition": "mapped",
                            "atom_ids": ["atom-documentation-duty"],
                        }
                        if lead["issue_category"] == "requirements"
                        else {
                            "lead_id": str(lead["lead_id"]),
                            "disposition": "not_material",
                            "rationale": (
                                "This synthetic scope lead is navigational context."
                            ),
                        }
                    )
                    for lead in leads
                ],
                "rule_atoms": [
                    {
                        "atom_id": "atom-documentation-duty",
                        "unit_ids": unit_ids,
                        "lead_ids": lead_ids,
                        "category": "requirements",
                        "proposition_type": "duty",
                        "materiality": "critical",
                        "elements": _elements(
                            actor="a controller",
                            modality="must",
                            operative_action="document",
                            object="material risks",
                            timing="before deployment",
                        ),
                        "omission_rationale": "Omission would hide the documentation duty.",
                    },
                    {
                        "atom_id": "atom-emergency-exception",
                        "unit_ids": unit_ids,
                        "lead_ids": [],
                        "category": "requirements",
                        "proposition_type": "exception",
                        "materiality": "material",
                        "elements": _elements(
                            exception=(
                                "unless the deployment is solely for a documented "
                                "emergency test"
                            )
                        ),
                        "omission_rationale": "Omission would overstate the duty's scope.",
                    },
                ],
                "rule_relationships": [
                    {
                        "relationship_id": "relationship-emergency-exception",
                        "relation_type": "exception_to",
                        "source_atom_id": "atom-emergency-exception",
                        "target_atom_id": "atom-documentation-duty",
                        "claim_ids": ["claim-rule"],
                    }
                ],
                "issues": [
                    {
                        "issue_id": "issue-documentation",
                        "title": "Pre-deployment documentation",
                        "category": "requirements",
                        "jurisdictions": ["US"],
                    }
                ],
                "findings": [
                    {
                        "finding_id": "finding-documentation",
                        "issue_id": "issue-documentation",
                        "title": "Document material risks before deployment",
                        "jurisdiction": "US",
                        "authority": "Synthetic Rule 1",
                        "severity": "medium",
                        "practical_implication": "Create the risk record before deployment.",
                        "claims": [
                            {
                                "claim_id": "claim-rule",
                                "text": RULE_TEXT,
                                "kind": "source_supported",
                                "proposed_citations": [
                                    {"source_id": source_id, "quote": RULE_TEXT}
                                ],
                            }
                        ],
                    }
                ],
                "brief": {
                    "structure_profile": "regulatory-walk-v1",
                    "executive_summary": [
                        {
                            "kind": "paragraph",
                            "purpose": "legal_analysis",
                            "text": RULE_TEXT,
                            "finding_ids": ["finding-documentation"],
                            "claim_ids": ["claim-rule"],
                        }
                    ],
                    "sections": [
                        {
                            "section_id": "key-requirements",
                            "title": "Key Requirements",
                            "role": "key_requirements",
                            "blocks": [
                                {
                                    "kind": "bullet_list",
                                    "purpose": "legal_analysis",
                                    "items": [
                                        {
                                            "text": RULE_TEXT,
                                            "finding_ids": ["finding-documentation"],
                                            "claim_ids": ["claim-rule"],
                                            "atom_ids": [
                                                "atom-documentation-duty",
                                                "atom-emergency-exception",
                                            ],
                                            "relationship_ids": [
                                                "relationship-emergency-exception"
                                            ],
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
                                        "Not established: The supplied rule does not "
                                        "establish penalties or enforcement mechanisms."
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
                                    "kind": "numbered_list",
                                    "purpose": "application",
                                    "items": [
                                        {
                                            "text": (
                                                "Create the risk record before deployment."
                                            ),
                                            "finding_ids": ["finding-documentation"],
                                        }
                                    ],
                                }
                            ],
                        },
                    ],
                },
            }
        ),
        encoding="utf-8",
    )

    finalized = _run(
        "finalize",
        "--matter",
        str(matter),
        "--draft",
        str(draft),
        "--host",
        "test-host",
        "--model",
        "test-model",
    )

    assert finalized.returncode == 0, finalized.stderr
    receipt = json.loads(finalized.stdout)
    assert receipt["status"] == "completed"
    assert receipt["valid"] is True
    assert receipt["evidence_precision_valid"] is True
    assert receipt["proposition_coverage_valid"] is True
    assert receipt["provision_recall_valid"] is True
    assert Path(receipt["coverage_review"]).is_file()
    bundle_path = matter / "runs" / "skill-e2e" / "bundle.json"
    report_path = matter / "runs" / "skill-e2e" / "report.md"
    audit_path = matter / "runs" / "skill-e2e" / "audit.md"
    assert receipt["audit"] == str(audit_path)
    bundle = ResearchBundle.model_validate_json(bundle_path.read_bytes())
    assert validate_research_bundle(bundle).valid is True
    assert bundle.findings[0].claims[0].citation_ids
    assert not any(gap.code == "MODEL_PROVIDER_NOT_CONFIGURED" for gap in bundle.gaps)
    assert bundle.manifest.provider_metadata == {
        "model": "test-model",
        "model_provider": "test-host",
    }
    report = report_path.read_text(encoding="utf-8")
    audit = audit_path.read_text(encoding="utf-8")
    assert report.startswith("# Synthetic Documentation Rule\n")
    assert "## Key Requirements" in report
    assert "## Penalties and Enforcement" in report
    assert "## Implementation Workplan" in report
    assert report.index("## Key Requirements") < report.index(
        "## Penalties and Enforcement"
    )
    assert report.index("## Penalties and Enforcement") < report.index(
        "## Implementation Workplan"
    )
    assert "Not established:" in report
    assert RULE_TEXT in report
    assert "atom-documentation-duty" not in report
    assert "atom-emergency-exception" not in report
    assert "relationship-emergency-exception" not in report
    assert report.count("Create the risk record before deployment.") == 1
    assert audit.startswith(
        "# Synthetic Documentation Rule: Evidence and Validation Audit\n"
    )
    assert RULE_TEXT in audit
