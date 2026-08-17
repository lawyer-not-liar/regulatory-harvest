import importlib.util
import json
import os
from copy import deepcopy
from pathlib import Path
from urllib.parse import urlunsplit

import pytest
from pydantic import ValidationError

from regulatory_harvest.analysis import (
    AnalysisDraft,
    DraftLeadReview,
    DraftPropositionCoverage,
    build_evidence_inventory,
    build_source_unit_inventory,
    evaluate_atomic_coverage,
    evaluate_coverage_closure,
)
from regulatory_harvest.evaluation.attorney_cli import _qualification_case_from_fixture
from regulatory_harvest.models import SourceRecord
from regulatory_harvest.storage import canonical_json_bytes

ROOT = Path(__file__).parents[2]
PORTABLE_RUNNER = ROOT / "scripts" / "harvest_portable.py"
SPEC = importlib.util.spec_from_file_location("regulatory_harvest_portable_runner", PORTABLE_RUNNER)
assert SPEC is not None and SPEC.loader is not None
portable = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(portable)


@pytest.mark.parametrize(
    ("command", "extra", "expected"),
    [
        ("eval-submit-safe", ["--response", "response.json"], {"response": "response.json"}),
        (
            "eval-qualify-init",
            ["--case", "case.json", "--nonce-hex", "7" * 64],
            {"case": "case.json", "nonce_hex": "7" * 64},
        ),
        ("eval-qualify-next", [], {}),
        ("eval-qualify-submit", ["--response", "response.json"], {"response": "response.json"}),
        ("eval-qualify-status", [], {}),
        ("eval-qualify-verify", [], {}),
    ],
)
def test_portable_parser_routes_guarded_and_qualification_commands(
    command: str,
    extra: list[str],
    expected: dict[str, str],
) -> None:
    """Dropping a route would make the installed portable command unreachable."""
    args = portable._parser().parse_args([command, "--run", "run", *extra])

    assert vars(args) == {"command": command, "run": "run", **expected}


def _write_schema_1_1_qualification_fixture(root: Path) -> Path:
    (root / "sources").mkdir(parents=True)
    (root / "sources" / "rule.txt").write_bytes(
        "Artículo 1. El operador presentará aviso.\r\nEstado: vigente.\r\n".encode()
    )
    case = {
        "schema_version": "1.1",
        "case_id": "portable-schema-1-1",
        "mode": "closed-universe",
        "question": "¿Qué aviso debe presentar el operador?",
        "jurisdiction": "Estado de Ejemplo",
        "as_of": "2026-08-16",
        "requested_authorities": [
            {
                "authority_id": "regla-ejemplo",
                "title": "Regla de Ejemplo",
                "jurisdiction": "Estado de Ejemplo",
                "authority_type": "regulation",
                "source_ids": ["fuente-1"],
            }
        ],
        "sources": [
            {
                "source_id": "fuente-1",
                "title": "Regla de Ejemplo",
                "path": "sources/rule.txt",
                "jurisdiction": "Estado de Ejemplo",
                "authority_type": "regulation",
                "source_role": "official_primary",
                "source_quality": "primary",
                "completeness": "complete",
                "language": "es",
            }
        ],
        "build_binding": {
            "commit": "a" * 40,
            "archive_sha256": "b" * 64,
        },
        "language_treatments": [
            {
                "source_ids": ["fuente-1"],
                "method": "Revisión bilingüe del texto oficial.",
                "rationale": "La traducción conserva la obligación jurídica.",
                "limitations": "La terminología técnica sigue en español.",
            }
        ],
    }
    path = root / "qualification.json"
    path.write_bytes(canonical_json_bytes(case))
    return path


def test_portable_qualification_schema_1_1_fixture_parser_matches_full_bytes(
    tmp_path: Path,
) -> None:
    fixture_root = tmp_path / "fixture"
    case_path = _write_schema_1_1_qualification_fixture(fixture_root)

    full_case = _qualification_case_from_fixture(case_path, root=fixture_root)
    portable_case = portable._portable_qualification_case(case_path)

    assert portable_case == full_case.model_dump(mode="json")
    assert portable_case["schema_version"] == "1.1"
    assert portable_case["build_binding"] == {
        "commit": "a" * 40,
        "archive_sha256": "b" * 64,
    }
    assert portable_case["language_treatments"][0]["method"] == (
        "Revisión bilingüe del texto oficial."
    )
    assert "\r\n" in portable_case["sources"][0]["normalized_text"]


@pytest.mark.parametrize(
    "mutation",
    [
        "missing-treatment",
        "duplicate-treatment",
        "malformed-commit",
        "malformed-archive",
        "blank-method",
    ],
)
def test_portable_qualification_schema_1_1_fixture_refusals_match_full(
    mutation: str,
    tmp_path: Path,
) -> None:
    fixture_root = tmp_path / "fixture"
    case_path = _write_schema_1_1_qualification_fixture(fixture_root)
    case = json.loads(case_path.read_bytes())
    if mutation == "missing-treatment":
        case.pop("language_treatments")
    elif mutation == "duplicate-treatment":
        case["language_treatments"].append(deepcopy(case["language_treatments"][0]))
    elif mutation == "malformed-commit":
        case["build_binding"]["commit"] = "A" * 40
    elif mutation == "malformed-archive":
        case["build_binding"]["archive_sha256"] = "b" * 63
    else:
        case["language_treatments"][0]["method"] = "   "
    case_path.write_bytes(canonical_json_bytes(case))

    with pytest.raises((TypeError, ValueError, ValidationError)):
        _qualification_case_from_fixture(case_path, root=fixture_root)
    with pytest.raises(portable.PortableInputError):
        portable._portable_qualification_case(case_path)


def _charter(source: Path) -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "matter_id": "portable-adversarial",
        "matter_title": "Synthetic Rule",
        "question": "What does the synthetic source say?",
        "jurisdictions": ["US"],
        "as_of": "2026-08-06",
        "source_mode": "provided-only",
        "sources": [{"location": str(source), "title": "Synthetic Rule"}],
    }


def _brief(
    finding_id: str,
    claim_id: str,
    claim_text: str,
    *,
    finding_category: str = "requirements",
) -> dict[str, object]:
    requirements_block: dict[str, object]
    if finding_category == "requirements":
        requirements_block = {
            "kind": "bullet_list",
            "purpose": "legal_analysis",
            "items": [
                {
                    "text": claim_text,
                    "finding_ids": [finding_id],
                    "claim_ids": [claim_id],
                }
            ],
        }
    else:
        requirements_block = {
            "kind": "paragraph",
            "purpose": "limitation",
            "text": "Not established: The evidence does not establish key requirements.",
        }
    return {
        "structure_profile": "regulatory-walk-v1",
        "executive_summary": [
            {
                "kind": "paragraph",
                "purpose": "legal_analysis",
                "text": claim_text,
                "finding_ids": [finding_id],
                "claim_ids": [claim_id],
            }
        ],
        "sections": [
            {
                "section_id": "key-requirements",
                "title": "Key Requirements",
                "role": "key_requirements",
                "blocks": [requirements_block],
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
                            "Not established: The evidence does not establish penalties "
                            "or enforcement mechanisms."
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
                        "text": "Confirm implementation facts and assign next steps.",
                    }
                ],
            }
        ],
    }


def _coverage_elements_payload(*, timing: str = "not_applicable") -> dict[str, object]:
    return {
        "subject": {"status": "stated", "text": "covered operator"},
        "operative_rule": {"status": "stated", "text": "must keep a register"},
        "object": {"status": "stated", "text": "processing activities"},
        "trigger_or_threshold": {"status": "not_applicable"},
        "conditions_or_exceptions": {"status": "not_applicable"},
        "timing": {"status": timing},
        "consequence_or_remedy": {"status": "not_applicable"},
        "authority_or_route": {"status": "not_applicable"},
    }


def _attach_prepared_coverage(
    payload: dict[str, object],
    dossier: dict[str, object],
    quote: str,
    claim_id: str,
    *,
    category: str = "requirements",
    proposition_type: str = "duty",
) -> None:
    units = dossier["source_unit_inventory"]
    leads = dossier["evidence_inventory"]
    assert isinstance(units, dict)
    assert isinstance(leads, dict)
    payload["coverage_contract_version"] = "proposition-coverage-v1"
    payload["proposition_coverage"] = [
        {
            "coverage_id": "coverage-prepared-target",
            "unit_ids": [
                str(unit["unit_id"])
                for unit in units["units"]
                if quote in str(unit["excerpt"])
            ],
            "lead_ids": [
                str(lead["lead_id"])
                for lead in leads["leads"]
                if quote in str(lead["excerpt"])
            ],
            "category": category,
            "proposition_type": proposition_type,
            "disposition": "covered",
            "elements": _coverage_elements_payload(),
            "claim_ids": [claim_id],
            "gap_codes": [],
            "rationale": None,
        }
    ]


def _attach_prepared_atomic_coverage(
    payload: dict[str, object],
    dossier: dict[str, object],
    quote: str,
    claim_id: str,
) -> None:
    units = dossier["source_unit_inventory"]
    leads = dossier["evidence_inventory"]
    assert isinstance(units, dict)
    assert isinstance(leads, dict)
    unit_ids = [
        str(unit["unit_id"])
        for unit in units["units"]
        if quote in str(unit["excerpt"])
    ]
    lead_ids = [
        str(lead["lead_id"])
        for lead in leads["leads"]
        if quote in str(lead["excerpt"])
    ]
    dimensions = {
        name: (
            {"disposition": "mapped", "atom_ids": ["atom-prepared-duty"]}
            if name == "duties_rights_prohibitions"
            else {"disposition": "not_present"}
        )
        for name in _ATOMIC_DIMENSIONS
    }
    elements: dict[str, object] = {
        name: {"status": "not_applicable"} for name in _ATOMIC_ELEMENTS
    }
    for name in _ATOMIC_REQUIRED_ELEMENTS["duty"]:
        elements[name] = {
            "status": "stated",
            "text": f"Prepared {name.replace('_', ' ')}",
            "claim_ids": [claim_id],
        }
    payload.update(
        {
            "coverage_contract_version": "proposition-coverage-v2",
            "unit_reviews": [
                {"unit_id": unit_id, "dimensions": deepcopy(dimensions)}
                for unit_id in unit_ids
            ],
            "lead_dispositions_v2": [
                {
                    "lead_id": lead_id,
                    "disposition": "mapped",
                    "atom_ids": ["atom-prepared-duty"],
                }
                for lead_id in lead_ids
            ],
            "rule_atoms": [
                {
                    "atom_id": "atom-prepared-duty",
                    "unit_ids": unit_ids,
                    "lead_ids": lead_ids,
                    "category": "requirements",
                    "proposition_type": "duty",
                    "materiality": "material",
                    "elements": elements,
                    "omission_rationale": "Omission would hide the prepared duty.",
                }
            ],
            "rule_relationships": [],
        }
    )
    brief = payload["brief"]
    assert isinstance(brief, dict)

    def bind(block: object) -> None:
        if not isinstance(block, dict) or block.get("purpose") != "legal_analysis":
            return
        if block.get("kind") == "paragraph":
            block["atom_ids"] = ["atom-prepared-duty"]
        elif block.get("kind") in {"bullet_list", "numbered_list"}:
            for item in block.get("items", []):
                if isinstance(item, dict):
                    item["atom_ids"] = ["atom-prepared-duty"]
        elif block.get("kind") == "table":
            for row in block.get("rows", []):
                if isinstance(row, dict):
                    row["atom_ids"] = ["atom-prepared-duty"]

    for block in brief.get("executive_summary", []):
        bind(block)
    for section in brief.get("sections", []):
        if not isinstance(section, dict):
            continue
        for block in section.get("blocks", []):
            bind(block)
        for subsection in section.get("subsections", []):
            if isinstance(subsection, dict):
                for block in subsection.get("blocks", []):
                    bind(block)


def _use_explicit_v1_dossier(
    matter: Path, dossier: dict[str, object]
) -> None:
    dossier["coverage_contract_version"] = "proposition-coverage-v1"
    (matter / "agent-dossier.json").write_text(
        json.dumps(dossier), encoding="utf-8"
    )


def _covered_coverage_row() -> dict[str, object]:
    return {
        "coverage_id": "coverage-register",
        "unit_ids": ["unit-one"],
        "category": "requirements",
        "proposition_type": "duty",
        "disposition": "covered",
        "elements": _coverage_elements_payload(),
        "claim_ids": ["claim-register"],
    }


_ATOMIC_DIMENSIONS = (
    "authority_status_timing",
    "actors_scope_activities",
    "definitions_categories",
    "duties_rights_prohibitions",
    "triggers_thresholds",
    "conditions_exceptions_defenses",
    "deadlines_transitions",
    "enforcement_remedies_consequences",
    "cross_references_dependencies",
)
_ATOMIC_ELEMENTS = (
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
_ATOMIC_REQUIRED_ELEMENTS = {
    "status": ("object",),
    "definition": ("defined_term", "defined_meaning"),
    "scope": ("actor", "object"),
    "right": ("actor", "modality", "operative_action", "object"),
    "duty": ("actor", "modality", "operative_action", "object"),
    "prohibition": ("actor", "modality", "operative_action", "object"),
    "exception": ("exception",),
    "deadline": ("timing",),
    "enforcement_trigger": ("trigger",),
    "enforcement_route": ("authority", "route"),
    "remedy": ("consequence",),
    "penalty": ("consequence",),
    "appeal": ("route",),
    "implementation": ("operative_action", "object"),
    "other": ("object",),
}
_ATOMIC_CATEGORY = {
    "status": "status",
    "scope": "scope",
    "right": "requirements",
    "duty": "requirements",
    "prohibition": "requirements",
    "exception": "requirements",
    "deadline": "deadlines",
    "enforcement_trigger": "enforcement",
    "enforcement_route": "enforcement",
    "remedy": "enforcement",
    "penalty": "enforcement",
    "appeal": "enforcement",
    "implementation": "implementation",
}
_ATOMIC_DIMENSION = {
    "status": "authority_status_timing",
    "definition": "definitions_categories",
    "scope": "actors_scope_activities",
    "right": "duties_rights_prohibitions",
    "duty": "duties_rights_prohibitions",
    "prohibition": "duties_rights_prohibitions",
    "exception": "conditions_exceptions_defenses",
    "deadline": "deadlines_transitions",
    "enforcement_trigger": "enforcement_remedies_consequences",
    "enforcement_route": "enforcement_remedies_consequences",
    "remedy": "enforcement_remedies_consequences",
    "penalty": "enforcement_remedies_consequences",
    "appeal": "enforcement_remedies_consequences",
    "implementation": "cross_references_dependencies",
    "other": "cross_references_dependencies",
}


def _atomic_source(text: str) -> SourceRecord:
    return SourceRecord.model_validate(
        {
            "source_id": "src-atomic",
            "origin": "synthetic-rule.txt",
            "display_name": "Synthetic Rule",
            "retrieved_at": "2026-08-15T00:00:00Z",
            "content_hash": portable._sha256(text.encode()),
            "media_type": "text/plain",
            "normalized_text": text,
            "jurisdiction": "US",
        }
    )


def _atomic_inventories(
    text: str,
) -> tuple[dict[str, object], dict[str, object]]:
    unit = {
        "unit_id": "unit-atomic",
        "source_id": "src-atomic",
        "start_char": 0,
        "end_char": len(text),
        "heading": None,
        "locator": f"chars:0-{len(text)}",
        "excerpt": text,
        "coverage_required": True,
    }
    return (
        {
            "inventory_version": "source-units-v1",
            "eligible_source_count": 1,
            "unit_count": 1,
            "required_unit_count": 1,
            "units": [unit],
        },
        {
            "inventory_version": "provision-leads-v2",
            "notice": "Heuristic research leads, not legal conclusions.",
            "source_count": 1,
            "lead_count": 0,
            "priority_lead_count": 0,
            "priority_topic_counts": {},
            "priority_cap_per_topic": 3,
            "topic_counts": {},
            "leads": [],
        },
    )


def _atomic_atom(atom_id: str, proposition_type: str) -> dict[str, object]:
    elements: dict[str, object] = {
        name: {"status": "not_applicable"} for name in _ATOMIC_ELEMENTS
    }
    for name in _ATOMIC_REQUIRED_ELEMENTS[proposition_type]:
        elements[name] = {
            "status": "stated",
            "text": f"Synthetic {name.replace('_', ' ')}",
            "claim_ids": ["claim-atomic"],
        }
    return {
        "atom_id": atom_id,
        "unit_ids": ["unit-atomic"],
        "category": _ATOMIC_CATEGORY.get(proposition_type, "other"),
        "proposition_type": proposition_type,
        "materiality": "material",
        "elements": elements,
        "omission_rationale": f"Omission would hide the {proposition_type} rule.",
    }


def _atomic_payload(
    text: str,
    atom_types: list[tuple[str, str]],
    relationships: list[tuple[str, str, str, str]],
    *,
    brief_shape: str = "paragraph",
) -> dict[str, object]:
    atoms = [_atomic_atom(atom_id, proposition_type) for atom_id, proposition_type in atom_types]
    mapped_by_dimension: dict[str, list[str]] = {name: [] for name in _ATOMIC_DIMENSIONS}
    for atom_id, proposition_type in atom_types:
        mapped_by_dimension[_ATOMIC_DIMENSION[proposition_type]].append(atom_id)
    dimensions = {
        name: (
            {"disposition": "mapped", "atom_ids": sorted(atom_ids)}
            if atom_ids
            else {"disposition": "not_present"}
        )
        for name, atom_ids in mapped_by_dimension.items()
    }
    atom_ids = sorted(atom_id for atom_id, _ in atom_types)
    relationship_ids = sorted(item[0] for item in relationships)
    binding: dict[str, object] = {
        "text": text,
        "claim_ids": ["claim-atomic"],
        "atom_ids": atom_ids,
        "relationship_ids": relationship_ids,
    }
    if brief_shape == "paragraph":
        block: dict[str, object] = {
            "kind": "paragraph",
            "purpose": "legal_analysis",
            **binding,
        }
    elif brief_shape == "list":
        block = {
            "kind": "bullet_list",
            "purpose": "legal_analysis",
            "items": [binding],
        }
    else:
        block = {
            "kind": "table",
            "purpose": "legal_analysis",
            "columns": ["Rule", "Effect"],
            "rows": [
                {
                    "cells": ["Synthetic rule", "Synthetic effect"],
                    "claim_ids": ["claim-atomic"],
                    "atom_ids": atom_ids,
                    "relationship_ids": relationship_ids,
                }
            ],
        }
    return {
        "issues": [
            {
                "issue_id": "issue-atomic",
                "title": "Atomic rule",
                "category": "requirements",
                "jurisdictions": ["US"],
            }
        ],
        "findings": [
            {
                "finding_id": "finding-atomic",
                "issue_id": "issue-atomic",
                "title": "Atomic rule",
                "jurisdiction": "US",
                "authority": "Synthetic Rule",
                "severity": "info",
                "practical_implication": "Apply the synthetic rule.",
                "claims": [
                    {
                        "claim_id": "claim-atomic",
                        "text": text,
                        "kind": "source_supported",
                        "proposed_citations": [
                            {"source_id": "src-atomic", "quote": text}
                        ],
                    }
                ],
            }
        ],
        "gaps": [],
        "coverage_contract_version": "proposition-coverage-v2",
        "unit_reviews": [
            {"unit_id": "unit-atomic", "dimensions": dimensions}
        ],
        "lead_dispositions_v2": [],
        "rule_atoms": atoms,
        "rule_relationships": [
            {
                "relationship_id": relationship_id,
                "relation_type": relation_type,
                "source_atom_id": source_atom_id,
                "target_atom_id": target_atom_id,
                "claim_ids": ["claim-atomic"],
            }
            for relationship_id, relation_type, source_atom_id, target_atom_id in relationships
        ],
        "brief": {
            "structure_profile": "regulatory-walk-v1",
            "executive_summary": [deepcopy(block)],
            "sections": [
                {
                    "section_id": "atomic-rules",
                    "title": "Atomic Rules",
                    "blocks": [deepcopy(block)],
                }
            ],
        },
    }


def _atomic_gap_payload(text: str, *, not_material: bool) -> dict[str, object]:
    payload = _atomic_payload(text, [], [])
    dimensions: dict[str, object]
    if not_material:
        dimensions = {
            name: {
                "disposition": "not_material",
                "rationale": "This unit is non-substantive navigation.",
            }
            for name in _ATOMIC_DIMENSIONS
        }
    else:
        dimensions = {
            name: {"disposition": "not_present"} for name in _ATOMIC_DIMENSIONS
        }
        dimensions["authority_status_timing"] = {
            "disposition": "gap",
            "gap_codes": ["STATUS_NOT_ESTABLISHED"],
        }
        payload["gaps"] = [
            {
                "code": "STATUS_NOT_ESTABLISHED",
                "message": "The source does not establish status timing.",
                "category": "status",
                "source_ids": ["src-atomic"],
            }
        ]
    payload["unit_reviews"] = [
        {"unit_id": "unit-atomic", "dimensions": dimensions}
    ]
    return payload


def _atomic_case(
    name: str,
) -> tuple[dict[str, object], dict[str, object], dict[str, object], list[SourceRecord]]:
    text = (
        "事業者は記録を保存しなければならない。"
        if name == "non-english"
        else "A controller must maintain a synthetic register."
    )
    if name in {"gap", "not-material-navigation"}:
        payload = _atomic_gap_payload(
            text,
            not_material=name == "not-material-navigation",
        )
    elif name == "duty-exception":
        payload = _atomic_payload(
            text,
            [("atom-duty", "duty"), ("atom-exception", "exception")],
            [("relationship-exception", "exception_to", "atom-exception", "atom-duty")],
            brief_shape="list",
        )
    elif name == "deadline":
        payload = _atomic_payload(
            text,
            [("atom-duty", "duty"), ("atom-deadline", "deadline")],
            [("relationship-deadline", "deadline_for", "atom-deadline", "atom-duty")],
        )
    elif name == "enforcement-penalty":
        payload = _atomic_payload(
            text,
            [
                ("atom-duty", "duty"),
                ("atom-trigger", "enforcement_trigger"),
                ("atom-penalty", "penalty"),
            ],
            [
                ("relationship-trigger", "triggered_by", "atom-trigger", "atom-duty"),
                ("relationship-penalty", "triggered_by", "atom-penalty", "atom-trigger"),
            ],
        )
    elif name == "cross-reference":
        payload = _atomic_payload(
            text,
            [("atom-duty", "duty"), ("atom-definition", "definition")],
            [("relationship-definition", "defines", "atom-definition", "atom-duty")],
        )
    elif name == "consolidated-prose":
        payload = _atomic_payload(
            text,
            [("atom-duty", "duty"), ("atom-scope", "scope")],
            [("relationship-scope", "qualifies", "atom-scope", "atom-duty")],
            brief_shape="table",
        )
    else:
        payload = _atomic_payload(text, [("atom-duty", "duty")], [])
    units, leads = _atomic_inventories(text)
    return units, leads, payload, [_atomic_source(text)]


def _invalid_coverage_drafts() -> list[tuple[str, dict[str, object], str]]:
    vectors: list[tuple[str, dict[str, object], str]] = []

    def add_row_case(name: str, updates: dict[str, object], message: str) -> None:
        row = _covered_coverage_row()
        row.update(updates)
        vectors.append(
            (
                name,
                {"issues": [], "findings": [], "proposition_coverage": [row]},
                message,
            )
        )

    add_row_case("missing targets", {"unit_ids": [], "lead_ids": []}, "unit_id or lead_id")
    add_row_case("duplicate unit ids", {"unit_ids": ["unit-one", "unit-one"]}, "unique")
    add_row_case("blank claim id", {"claim_ids": ["   "]}, "blank")
    add_row_case("boolean proposition type", {"proposition_type": True}, "proposition_type")
    add_row_case(
        "structured element status",
        {
            "elements": {
                **_coverage_elements_payload(),
                "timing": {"status": ["not_applicable"]},
            }
        },
        "status",
    )
    add_row_case("missing covered elements", {"elements": None}, "requires elements")
    add_row_case("missing covered claims", {"claim_ids": []}, "requires claim_ids")
    add_row_case("unbound covered gap", {"gap_codes": ["UNBOUND"]}, "not_established")

    not_established = _coverage_elements_payload(timing="not_established")
    add_row_case(
        "covered element without gap",
        {"elements": not_established},
        "not_established elements require gap_codes",
    )
    add_row_case(
        "stated element without text",
        {
            "elements": {
                **_coverage_elements_payload(),
                "object": {"status": "stated", "text": None},
            }
        },
        "stated status requires nonblank text",
    )
    add_row_case(
        "not applicable element with text",
        {
            "elements": {
                **_coverage_elements_payload(),
                "timing": {"status": "not_applicable", "text": "invented"},
            }
        },
        "not_applicable status requires text to be null",
    )
    add_row_case(
        "missing eighth element",
        {
            "elements": {
                key: value
                for key, value in _coverage_elements_payload().items()
                if key != "authority_or_route"
            }
        },
        "authority_or_route",
    )
    add_row_case(
        "gap with claim",
        {
            "disposition": "gap",
            "elements": None,
            "claim_ids": ["claim-register"],
            "gap_codes": ["RULE_NOT_ESTABLISHED"],
            "rationale": "The rule is not established.",
        },
        "cannot include claim_ids",
    )
    add_row_case(
        "gap with stated element",
        {
            "disposition": "gap",
            "claim_ids": [],
            "gap_codes": ["RULE_NOT_ESTABLISHED"],
            "rationale": "The rule is not established.",
        },
        "cannot include stated elements",
    )
    add_row_case(
        "not material with gap",
        {
            "disposition": "not_material",
            "elements": None,
            "claim_ids": [],
            "gap_codes": ["NOT_A_GAP"],
            "rationale": "Navigation only.",
        },
        "cannot include gap_codes",
    )
    add_row_case(
        "not material without rationale",
        {
            "disposition": "not_material",
            "elements": None,
            "claim_ids": [],
            "rationale": None,
        },
        "requires a rationale",
    )

    duplicate_row = _covered_coverage_row()
    vectors.append(
        (
            "duplicate coverage ids",
            {
                "issues": [],
                "findings": [],
                "proposition_coverage": [duplicate_row, dict(duplicate_row)],
            },
            "coverage identifiers must be unique",
        )
    )
    vectors.append(
        (
            "unknown coverage version",
            {
                "issues": [],
                "findings": [],
                "coverage_contract_version": "proposition-coverage-v3",
            },
            "proposition-coverage-v1",
        )
    )
    vectors.append(
        (
            "structured coverage version",
            {
                "issues": [],
                "findings": [],
                "coverage_contract_version": ["proposition-coverage-v1"],
            },
            "proposition-coverage-v1",
        )
    )
    return vectors


def test_portable_draft_normalizes_coverage_contract_exactly_like_full_runtime() -> None:
    gap_elements = _coverage_elements_payload(timing="not_established")
    for field in ("subject", "object"):
        gap_elements[field] = {"status": "not_applicable"}
    gap_elements["operative_rule"] = {"status": "not_established"}
    payload = {
        "issues": [],
        "findings": [],
        "coverage_contract_version": "proposition-coverage-v1",
        "proposition_coverage": [
            _covered_coverage_row(),
            {
                "coverage_id": "coverage-gap",
                "lead_ids": ["lead-gap"],
                "category": "scope",
                "proposition_type": "scope",
                "disposition": "gap",
                "elements": gap_elements,
                "gap_codes": ["SCOPE_NOT_ESTABLISHED"],
                "rationale": "The retained source does not establish scope.",
            },
            {
                "coverage_id": "coverage-navigation",
                "unit_ids": ["unit-navigation"],
                "category": "other",
                "proposition_type": "other",
                "disposition": "not_material",
                "rationale": "Navigation text is unrelated to the question.",
            },
        ],
    }

    full = AnalysisDraft.model_validate(payload).model_dump(mode="json")
    parsed = portable._draft(payload)

    assert parsed == full
    assert set(parsed["proposition_coverage"][0]) == {
        "coverage_id",
        "unit_ids",
        "lead_ids",
        "category",
        "proposition_type",
        "disposition",
        "elements",
        "claim_ids",
        "gap_codes",
        "rationale",
    }


def test_portable_old_draft_normalizes_coverage_defaults_like_full_runtime() -> None:
    payload = {"issues": [], "findings": []}

    assert portable._draft(payload) == AnalysisDraft.model_validate(payload).model_dump(mode="json")


@pytest.mark.parametrize(
    ("name", "payload", "message"),
    _invalid_coverage_drafts(),
    ids=lambda value: value if isinstance(value, str) else None,
)
def test_portable_and_full_drafts_reject_the_same_invalid_coverage_vectors(
    name: str, payload: dict[str, object], message: str
) -> None:
    del name
    with pytest.raises(ValidationError, match=message):
        AnalysisDraft.model_validate(payload)
    with pytest.raises(portable.PortableInputError, match=message):
        portable._draft(payload)


@pytest.mark.parametrize(
    "mutation",
    [
        "mismatched_contract",
        "unit_ids_none",
        "missing_coverage_id",
        "malformed_nested_elements",
        "missing_inventory_version",
        "malformed_unit_target",
    ],
)
def test_portable_raw_coverage_reconciliation_matches_full_fail_closed_semantics(
    tmp_path: Path,
    mutation: str,
) -> None:
    """Validation-bypassing dictionaries must yield canonical diagnostics, not exceptions."""
    quote = "A controller must maintain a written register."
    source = tmp_path / "rule.txt"
    source.write_text(quote + "\n", encoding="utf-8")
    charter = tmp_path / "charter.json"
    charter.write_text(json.dumps(_charter(source)), encoding="utf-8")
    matter = tmp_path / "matter"
    portable.prepare(charter, matter)
    dossier = json.loads((matter / "agent-dossier.json").read_text(encoding="utf-8"))
    source_id = dossier["sources"][0]["source_id"]
    payload: dict[str, object] = {
        "issues": [
            {
                "issue_id": "issue-requirements",
                "title": "Requirements",
                "category": "requirements",
                "jurisdictions": ["US"],
            }
        ],
        "findings": [
            {
                "finding_id": "finding-requirements",
                "issue_id": "issue-requirements",
                "title": "Register duty",
                "jurisdiction": "US",
                "authority": "Synthetic Rule",
                "severity": "info",
                "practical_implication": "Maintain the register.",
                "claims": [
                    {
                        "claim_id": "claim-register",
                        "text": quote,
                        "kind": "source_supported",
                        "proposed_citations": [
                            {"source_id": source_id, "quote": quote}
                        ],
                    }
                ],
            }
        ],
        "gaps": [],
        "brief": _brief(
            "finding-requirements",
            "claim-register",
            quote,
            finding_category="requirements",
        ),
    }
    _attach_prepared_coverage(payload, dossier, quote, "claim-register")
    typed_draft = AnalysisDraft.model_validate(payload)
    raw_draft = portable._draft(payload)
    raw_inventory = deepcopy(dossier["evidence_inventory"])
    raw_units = deepcopy(dossier["source_unit_inventory"])
    raw_sources = deepcopy(dossier["sources"])
    valid_row = typed_draft.proposition_coverage[0]
    if mutation == "mismatched_contract":
        typed_draft = typed_draft.model_copy(
            update={"coverage_contract_version": "proposition-coverage-v2"}
        )
        raw_draft["coverage_contract_version"] = "proposition-coverage-v2"
    elif mutation == "unit_ids_none":
        typed_draft = typed_draft.model_copy(
            update={
                "proposition_coverage": [
                    valid_row.model_copy(update={"unit_ids": None})
                ]
            }
        )
        raw_draft["proposition_coverage"][0]["unit_ids"] = None
    elif mutation == "missing_coverage_id":
        typed_draft = typed_draft.model_copy(
            update={
                "proposition_coverage": [DraftPropositionCoverage.model_construct()]
            }
        )
        raw_draft["proposition_coverage"] = [{}]
    elif mutation == "malformed_nested_elements":
        typed_draft = typed_draft.model_copy(
            update={
                "proposition_coverage": [
                    valid_row.model_copy(update={"elements": {"timing": []}})
                ]
            }
        )
        raw_draft["proposition_coverage"][0]["elements"] = {"timing": []}
    elif mutation == "missing_inventory_version":
        raw_units.pop("inventory_version")
    else:
        raw_units["units"] = [None]
        raw_units["unit_count"] = 1
        raw_units["required_unit_count"] = 1
    before = deepcopy((raw_inventory, raw_units, raw_draft, raw_sources))

    full_review = evaluate_coverage_closure(
        raw_inventory,
        raw_units,
        typed_draft,
        [SourceRecord.model_validate(item) for item in raw_sources],
    )
    portable_review = portable._evaluate_coverage_closure(
        raw_inventory,
        raw_units,
        raw_draft,
        raw_sources,
    )

    assert canonical_json_bytes(full_review) == portable._canonical_bytes(portable_review)
    assert portable_review["valid"] is False
    if mutation == "mismatched_contract":
        assert portable_review["coverage_contract_version"] == "proposition-coverage-v2"
        assert {
            "ATOMIC_LEAD_REVIEW_UNRESOLVED",
            "ATOMIC_UNIT_REVIEW_UNRESOLVED",
        } <= {issue["code"] for issue in portable_review["issues"]}
    else:
        assert "COVERAGE_ROW_INVALID" in {
            issue["code"]
            for issue in portable_review["proposition_coverage"]["issues"]
        }
    assert (raw_inventory, raw_units, raw_draft, raw_sources) == before


@pytest.mark.parametrize("disposition", ["gap", "not_material"])
def test_portable_composite_projects_strict_lead_dispositions_with_byte_parity(
    disposition: str,
) -> None:
    source = SourceRecord.model_validate(
        {
            "source_id": "src_rule",
            "origin": "rule.txt",
            "display_name": "Synthetic Rule",
            "retrieved_at": "2026-08-14T00:00:00Z",
            "content_hash": portable._sha256(
                b"A violation is subject to a civil penalty of $10,000."
            ),
            "media_type": "text/plain",
            "normalized_text": (
                "A violation is subject to a civil penalty of $10,000."
            ),
            "jurisdiction": "US",
        }
    )
    source_payload = source.model_dump(mode="json")
    units = build_source_unit_inventory([source_payload])
    leads = build_evidence_inventory([source_payload])
    lead_items = leads["leads"]
    assert isinstance(lead_items, list)
    assert any(item["review_required"] is True for item in lead_items)
    gap_code = "PENALTY_SCOPE_NOT_ESTABLISHED"
    payload: dict[str, object] = {
        "issues": [],
        "findings": [],
        "gaps": (
            [
                {
                    "code": gap_code,
                    "message": "The complete penalty scope is not established.",
                    "category": "enforcement",
                    "source_ids": [source.source_id],
                }
            ]
            if disposition == "gap"
            else []
        ),
        "lead_reviews": [],
        "coverage_contract_version": "proposition-coverage-v1",
        "proposition_coverage": [
            {
                "coverage_id": f"coverage-{disposition}",
                "unit_ids": [item["unit_id"] for item in units["units"]],
                "lead_ids": [item["lead_id"] for item in leads["leads"]],
                "category": "enforcement",
                "proposition_type": "penalty",
                "disposition": disposition,
                "elements": None,
                "claim_ids": [],
                "gap_codes": [gap_code] if disposition == "gap" else [],
                "rationale": (
                    "The retained source does not establish the complete penalty scope."
                    if disposition == "gap"
                    else "The penalty sentence is outside the synthetic question."
                ),
            }
        ],
    }
    draft = AnalysisDraft.model_validate(payload)
    raw_draft = portable._draft(payload)
    before = deepcopy((leads, units, raw_draft, [source_payload]))

    full_review = evaluate_coverage_closure(leads, units, draft, [source])
    portable_review = portable._evaluate_coverage_closure(
        leads, units, raw_draft, [source_payload]
    )

    assert full_review["valid"] is True
    assert full_review["proposition_coverage"]["valid"] is True
    assert full_review["lead_recall"]["valid"] is True
    assert full_review["lead_recall"]["resolved_counts"] == {disposition: 1}
    assert canonical_json_bytes(full_review) == portable._canonical_bytes(portable_review)
    assert (leads, units, raw_draft, [source_payload]) == before


def test_portable_multiple_row_projection_matches_full_precedence_and_sorting() -> None:
    text = "A violation is subject to a civil penalty of $10,000."
    source = SourceRecord.model_validate(
        {
            "source_id": "src_rule",
            "origin": "rule.txt",
            "display_name": "Synthetic Rule",
            "retrieved_at": "2026-08-14T00:00:00Z",
            "content_hash": portable._sha256(text.encode()),
            "media_type": "text/plain",
            "normalized_text": text,
            "jurisdiction": "US",
        }
    )
    source_payload = source.model_dump(mode="json")
    units = build_source_unit_inventory([source_payload])
    leads = build_evidence_inventory([source_payload])
    lead_ids = [item["lead_id"] for item in leads["leads"]]
    assert len(lead_ids) == 1
    gap_codes = ["PENALTY_DETAIL_Z_NOT_ESTABLISHED", "PENALTY_DETAIL_A_NOT_ESTABLISHED"]
    payload: dict[str, object] = {
        "issues": [],
        "findings": [],
        "gaps": [
            {
                "code": code,
                "message": f"The retained source omits {code}.",
                "category": "enforcement",
                "source_ids": [source.source_id],
            }
            for code in gap_codes
        ],
        "lead_reviews": [
            {
                "lead_id": lead_ids[0],
                "disposition": "not_material",
                "gap_codes": [],
                "rationale": "This contradictory host review must be ignored.",
            }
        ],
        "coverage_contract_version": "proposition-coverage-v1",
        "proposition_coverage": [
            {
                "coverage_id": "coverage-gap-z",
                "unit_ids": [item["unit_id"] for item in units["units"]],
                "lead_ids": lead_ids,
                "category": "enforcement",
                "proposition_type": "penalty",
                "disposition": "gap",
                "gap_codes": [gap_codes[0]],
                "rationale": "The retained source omits penalty detail Z.",
            },
            {
                "coverage_id": "coverage-not-material",
                "lead_ids": lead_ids,
                "category": "enforcement",
                "proposition_type": "penalty",
                "disposition": "not_material",
                "rationale": "The sentence is outside the narrowed synthetic question.",
            },
            {
                "coverage_id": "coverage-gap-a",
                "lead_ids": lead_ids,
                "category": "enforcement",
                "proposition_type": "penalty",
                "disposition": "gap",
                "gap_codes": [gap_codes[1]],
                "rationale": "The retained source omits penalty detail A.",
            },
        ],
    }
    draft = AnalysisDraft.model_validate(payload)
    raw_draft = portable._draft(payload)
    before = deepcopy((leads, units, raw_draft, [source_payload]))

    full_review = evaluate_coverage_closure(leads, units, draft, [source])
    portable_review = portable._evaluate_coverage_closure(
        leads, units, raw_draft, [source_payload]
    )

    assert full_review["valid"] is True
    assert full_review["lead_recall"]["resolved_counts"] == {"gap": 1}
    assert full_review["lead_recall"]["leads"] == [
        {
            "lead_id": lead_ids[0],
            "status": "gap",
            "related_ids": sorted(gap_codes),
            "rationale": (
                "Projected from strict proposition coverage rows: "
                "coverage-gap-a, coverage-gap-z."
            ),
        }
    ]
    assert canonical_json_bytes(full_review) == portable._canonical_bytes(portable_review)
    assert (leads, units, raw_draft, [source_payload]) == before


@pytest.mark.parametrize(
    "case_name",
    [
        "duty-exception",
        "deadline",
        "enforcement-penalty",
        "cross-reference",
        "non-english",
        "gap",
        "not-material-navigation",
        "consolidated-prose",
    ],
)
def test_portable_atomic_v2_valid_review_has_full_byte_parity(
    case_name: str,
) -> None:
    """Any semantic shortcut in the portable V2 evaluator changes canonical bytes."""
    units, leads, payload, sources = _atomic_case(case_name)
    typed = AnalysisDraft.model_validate(payload)
    parsed = portable._draft(payload)
    source_payloads = [source.model_dump(mode="json") for source in sources]
    before = deepcopy((units, leads, payload, source_payloads))

    full_review = evaluate_atomic_coverage(units, leads, typed, sources)
    portable_review = portable._evaluate_coverage_closure(
        leads,
        units,
        parsed,
        source_payloads,
    )

    assert full_review["valid"] is True
    assert canonical_json_bytes(typed.model_dump(mode="json")) == portable._canonical_bytes(
        parsed
    )
    assert canonical_json_bytes(full_review) == portable._canonical_bytes(portable_review)
    assert (units, leads, payload, source_payloads) == before


_MISSING_RELATIONSHIP_CASES = (
    ("exception", [("atom-duty", "duty"), ("atom-subject", "exception")]),
    ("deadline", [("atom-duty", "duty"), ("atom-subject", "deadline")]),
    (
        "enforcement-trigger",
        [("atom-duty", "duty"), ("atom-subject", "enforcement_trigger")],
    ),
    (
        "enforcement-route",
        [("atom-duty", "duty"), ("atom-subject", "enforcement_route")],
    ),
    ("remedy", [("atom-duty", "duty"), ("atom-subject", "remedy")]),
    ("penalty", [("atom-duty", "duty"), ("atom-subject", "penalty")]),
    (
        "appeal",
        [
            ("atom-duty", "duty"),
            ("atom-penalty", "penalty"),
            ("atom-subject", "appeal"),
        ],
    ),
)


@pytest.mark.parametrize(
    ("case_name", "atom_types"),
    _MISSING_RELATIONSHIP_CASES,
    ids=[case[0] for case in _MISSING_RELATIONSHIP_CASES],
)
def test_portable_atomic_missing_relationship_diagnostics_have_full_byte_parity(
    case_name: str,
    atom_types: list[tuple[str, str]],
) -> None:
    del case_name
    text = "A controller must maintain a synthetic register."
    units, leads = _atomic_inventories(text)
    payload = _atomic_payload(text, atom_types, [])
    typed = AnalysisDraft.model_validate(payload)
    parsed = portable._draft(payload)
    sources = [_atomic_source(text)]
    source_payloads = [source.model_dump(mode="json") for source in sources]
    before = deepcopy((units, leads, parsed, source_payloads))

    full_review = evaluate_atomic_coverage(units, leads, typed, sources)
    portable_review = portable._evaluate_coverage_closure(
        leads, units, parsed, source_payloads
    )

    assert full_review["valid"] is False
    assert "ATOMIC_RELATIONSHIP_REQUIRED" in {
        issue["code"] for issue in full_review["issues"]
    }
    assert canonical_json_bytes(full_review) == portable._canonical_bytes(portable_review)
    assert (units, leads, parsed, source_payloads) == before


def test_portable_atomic_finalization_bounds_unhashable_contract_with_full_parity() -> None:
    units, leads, payload, sources = _atomic_case("duty-exception")
    reparsed_payload = deepcopy(payload)
    reparsed_payload["coverage_contract_version"] = None
    typed = AnalysisDraft.model_validate(reparsed_payload).model_copy(
        update={"coverage_contract_version": ["proposition-coverage-v2"]}
    )
    payload["coverage_contract_version"] = ["proposition-coverage-v2"]

    parsed = portable._finalization_draft(payload)
    source_payloads = [source.model_dump(mode="json") for source in sources]
    full_review = evaluate_atomic_coverage(units, leads, typed, sources)
    portable_review = portable._evaluate_portable_atomic_coverage(
        units, leads, parsed, source_payloads
    )

    assert full_review["valid"] is False
    assert canonical_json_bytes(full_review) == portable._canonical_bytes(portable_review)
    assert {issue["code"] for issue in portable_review["issues"]} >= {
        "ATOMIC_REVIEW_INVALID",
        "ATOMIC_RULE_INVALID",
    }


@pytest.mark.parametrize(
    ("mutation", "value", "expected_valid"),
    [
        pytest.param("private-canonical-url", None, False, id="private-canonical-url"),
        pytest.param("malformed-source-failure", None, False, id="malformed-failure"),
        pytest.param("valid-source-failure", None, True, id="valid-failure"),
        pytest.param("retrieved-at", 0, True, id="retrieved-at-integer"),
        pytest.param("retrieved-at", 0.5, True, id="retrieved-at-float"),
        pytest.param("retrieved-at", "0", True, id="retrieved-at-numeric-string"),
        pytest.param("retrieved-at", True, False, id="retrieved-at-boolean"),
        pytest.param("retrieved-at", " 0 ", False, id="retrieved-at-spaced-number"),
        pytest.param(
            "retrieved-at",
            "2026-08-15t00:00:00z",
            True,
            id="retrieved-at-lowercase-separator",
        ),
        pytest.param(
            "retrieved-at",
            "2026-08-15_00:00:00Z",
            True,
            id="retrieved-at-underscore-separator",
        ),
        pytest.param(
            "retrieved-at",
            "2026-08-15T00:00:00,5Z",
            True,
            id="retrieved-at-comma-fraction",
        ),
        pytest.param(
            "retrieved-at",
            "2026-08-15T00:00:00+05",
            False,
            id="retrieved-at-hour-only-offset",
        ),
        pytest.param(
            "retrieved-at",
            "2026-W33-6T00:00:00Z",
            False,
            id="retrieved-at-week-date",
        ),
        pytest.param("provider-status", True, True, id="provider-status-boolean"),
        pytest.param("provider-status", 503, True, id="provider-status-integer"),
        pytest.param("provider-status", 503.0, True, id="provider-status-float-integer"),
        pytest.param("provider-status", "503", True, id="provider-status-string"),
        pytest.param("provider-status", 503.5, False, id="provider-status-fractional"),
        pytest.param("provider-status", "invalid", False, id="provider-status-invalid"),
    ],
)
def test_portable_atomic_source_snapshot_validation_matches_full_model(
    mutation: str,
    value: object,
    expected_valid: bool,
) -> None:
    payload = _atomic_source("Synthetic source text.").model_dump(mode="json")
    if mutation == "private-canonical-url":
        payload["canonical_url"] = "http://" + "127.0.0.1/rule"
    elif mutation == "malformed-source-failure":
        payload.update(
            {
                "fetch_status": "failed",
                "error": {"category": [], "message": "Failed."},
            }
        )
    elif mutation == "valid-source-failure":
        payload.update(
            {
                "fetch_status": "failed",
                "error": {
                    "category": "retrieval",
                    "retryable": False,
                    "message": "Failed.",
                    "provider_status_code": 503,
                },
            }
        )
    elif mutation == "retrieved-at":
        payload["retrieved_at"] = value
    elif mutation in {"provider-status", "retryable"}:
        error = {
            "category": "retrieval",
            "retryable": False,
            "message": "Failed.",
            "provider_status_code": 503,
        }
        error[
            "provider_status_code" if mutation == "provider-status" else "retryable"
        ] = value
        payload.update({"fetch_status": "failed", "error": error})
    try:
        full_source = SourceRecord.model_validate(payload)
    except ValueError:
        full_valid = False
        full_snapshot = None
    else:
        full_valid = True
        full_snapshot = full_source.model_dump(mode="json")

    assert full_valid is expected_valid
    assert portable._portable_source_record_valid(payload) is expected_valid
    portable_snapshot = portable._portable_source_record(payload)
    if expected_valid:
        assert canonical_json_bytes(full_snapshot) == portable._canonical_bytes(
            portable_snapshot
        )
    else:
        assert portable_snapshot is None


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        pytest.param(True, True, id="boolean-true"),
        pytest.param(False, False, id="boolean-false"),
        pytest.param(1, True, id="integer-one"),
        pytest.param(0, False, id="integer-zero"),
        pytest.param(1.0, True, id="float-one"),
        pytest.param(0.0, False, id="float-zero"),
        pytest.param("t", True, id="t-lower"),
        pytest.param("T", True, id="t-upper"),
        pytest.param("true", True, id="true-lower"),
        pytest.param("TRUE", True, id="true-upper"),
        pytest.param("y", True, id="y-lower"),
        pytest.param("Y", True, id="y-upper"),
        pytest.param("yes", True, id="yes-lower"),
        pytest.param("YES", True, id="yes-upper"),
        pytest.param("on", True, id="on-lower"),
        pytest.param("ON", True, id="on-upper"),
        pytest.param("1", True, id="string-one"),
        pytest.param("f", False, id="f-lower"),
        pytest.param("F", False, id="f-upper"),
        pytest.param("false", False, id="false-lower"),
        pytest.param("FALSE", False, id="false-upper"),
        pytest.param("n", False, id="n-lower"),
        pytest.param("N", False, id="n-upper"),
        pytest.param("no", False, id="no-lower"),
        pytest.param("NO", False, id="no-upper"),
        pytest.param("off", False, id="off-lower"),
        pytest.param("OFF", False, id="off-upper"),
        pytest.param("0", False, id="string-zero"),
        pytest.param(2, None, id="integer-out-of-range"),
        pytest.param(-1, None, id="negative-integer"),
        pytest.param(" true ", None, id="spaced-string"),
        pytest.param("", None, id="empty-string"),
        pytest.param(None, None, id="none"),
        pytest.param([], None, id="list"),
        pytest.param({}, None, id="object"),
    ],
)
def test_portable_source_failure_boolean_coercion_matches_full_model(
    value: object,
    expected: bool | None,
) -> None:
    """Portable failed-source dossiers accept exactly the full JSON bool forms."""
    payload = _atomic_source("Synthetic source text.").model_dump(mode="json")
    payload.update(
        {
            "fetch_status": "failed",
            "error": {
                "category": "retrieval",
                "retryable": value,
                "message": "Failed.",
                "provider_status_code": 503,
            },
        }
    )
    try:
        full_source = SourceRecord.model_validate(payload)
    except ValueError:
        full_snapshot = None
        full_retryable = None
    else:
        full_snapshot = full_source.model_dump(mode="json")
        assert full_source.error is not None
        full_retryable = full_source.error.retryable
    portable_snapshot = portable._portable_source_record(payload)

    assert full_retryable is expected
    if expected is None:
        assert full_snapshot is None
        assert portable_snapshot is None
    else:
        assert portable_snapshot is not None
        portable_error = portable_snapshot["error"]
        assert isinstance(portable_error, dict)
        assert portable_error["retryable"] is expected
        assert canonical_json_bytes(full_snapshot) == portable._canonical_bytes(
            portable_snapshot
        )


def test_portable_atomic_target_index_resnapshots_normalized_source_ids() -> None:
    """Target lookup must use the full model's fresh, stripped source snapshot."""
    units, leads, payload, sources = _atomic_case("duty-exception")
    typed = AnalysisDraft.model_validate(payload)
    parsed = portable._draft(payload)
    sources = [sources[0].model_copy(update={"source_id": " src-atomic "})]
    source_payloads = [source.model_dump(mode="json") for source in sources]
    before = deepcopy((units, leads, parsed, source_payloads))

    full_review = evaluate_atomic_coverage(units, leads, typed, sources)
    portable_review = portable._evaluate_coverage_closure(
        leads, units, parsed, source_payloads
    )

    expected_codes = [
        "ATOMIC_EVIDENCE_OUTSIDE_TARGET",
        "ATOMIC_EVIDENCE_OUTSIDE_TARGET",
        "ATOMIC_EVIDENCE_OUTSIDE_TARGET",
        "ATOMIC_EVIDENCE_OUTSIDE_TARGET",
        "ATOMIC_EVIDENCE_OUTSIDE_TARGET",
        "ATOMIC_EVIDENCE_OUTSIDE_TARGET",
        "ATOMIC_EVIDENCE_OUTSIDE_TARGET",
        "ATOMIC_RELATIONSHIP_EVIDENCE_INVALID",
    ]
    assert [issue["code"] for issue in full_review["issues"]] == expected_codes
    assert canonical_json_bytes(full_review) == portable._canonical_bytes(portable_review)
    assert (units, leads, parsed, source_payloads) == before


@pytest.mark.parametrize(
    ("field", "value", "expected_codes"),
    [
        pytest.param(
            "source_id",
            " ",
            [
                "ATOMIC_EVIDENCE_OUTSIDE_TARGET",
                "ATOMIC_EVIDENCE_OUTSIDE_TARGET",
                "ATOMIC_EVIDENCE_OUTSIDE_TARGET",
                "ATOMIC_EVIDENCE_OUTSIDE_TARGET",
                "ATOMIC_EVIDENCE_OUTSIDE_TARGET",
                "ATOMIC_EVIDENCE_OUTSIDE_TARGET",
                "ATOMIC_EVIDENCE_OUTSIDE_TARGET",
                "ATOMIC_RELATIONSHIP_EVIDENCE_INVALID",
            ],
            id="blank-source-id",
        ),
        pytest.param(
            "quote",
            {},
            ["ATOMIC_EVIDENCE_INVALID"],
            id="falsy-object-quote",
        ),
    ],
)
def test_portable_atomic_citation_wrapper_boundary_matches_full_review(
    field: str,
    value: object,
    expected_codes: list[str],
) -> None:
    """Validation-bypassed typed citations retain the full build boundary."""
    units, leads, payload, sources = _atomic_case("duty-exception")
    typed = AnalysisDraft.model_validate(payload)
    parsed = portable._draft(payload)
    typed_finding = typed.findings[0]
    typed_claim = typed_finding.claims[0]
    typed_citation = typed_claim.proposed_citations[0]
    updated_citation = typed_citation.model_copy(update={field: deepcopy(value)})
    typed = typed.model_copy(
        update={
            "findings": [
                typed_finding.model_copy(
                    update={
                        "claims": [
                            typed_claim.model_copy(
                                update={"proposed_citations": [updated_citation]}
                            )
                        ]
                    }
                )
            ]
        }
    )
    parsed_citations = parsed["findings"][0]["claims"][0]["proposed_citations"]
    parsed_citations[0][field] = deepcopy(value)
    source_payloads = [source.model_dump(mode="json") for source in sources]
    before = deepcopy((units, leads, parsed, source_payloads))

    full_review = evaluate_atomic_coverage(units, leads, typed, sources)
    portable_review = portable._evaluate_coverage_closure(
        leads, units, parsed, source_payloads
    )

    assert [issue["code"] for issue in full_review["issues"]] == expected_codes
    assert canonical_json_bytes(full_review) == portable._canonical_bytes(portable_review)
    assert (units, leads, parsed, source_payloads) == before


def _mutate_atomic_invalid_payload(
    name: str,
    payload: dict[str, object],
) -> None:
    unit_reviews = payload["unit_reviews"]
    atoms = payload["rule_atoms"]
    relationships = payload["rule_relationships"]
    brief = payload["brief"]
    assert isinstance(unit_reviews, list) and isinstance(unit_reviews[0], dict)
    assert isinstance(atoms, list) and isinstance(atoms[0], dict)
    assert isinstance(brief, dict)
    dimensions = unit_reviews[0]["dimensions"]
    elements = atoms[0]["elements"]
    assert isinstance(dimensions, dict) and isinstance(elements, dict)
    if name == "missing-dimension":
        dimensions.pop("authority_status_timing")
    elif name == "list-dimension-disposition":
        dimensions["authority_status_timing"] = {"disposition": ["not_present"]}
    elif name == "unhashable-dimension-atom-id":
        dimensions["duties_rights_prohibitions"] = {
            "disposition": "mapped",
            "atom_ids": [["atom-duty"]],
        }
    elif name == "missing-atom-element":
        elements.pop("defined_meaning")
    elif name == "list-atom-status":
        elements["actor"] = {"status": ["stated"], "text": "controller"}
    elif name == "unhashable-atom-claim-id":
        elements["actor"] = {
            "status": "stated",
            "text": "controller",
            "claim_ids": [["claim-atomic"]],
        }
    elif name == "duplicate-atom-id":
        atoms.append(deepcopy(atoms[0]))
    elif name == "duplicate-relationship-id":
        assert isinstance(relationships, list) and relationships
        relationships.append(deepcopy(relationships[0]))
    elif name == "list-relationship-claim-id":
        assert isinstance(relationships, list) and isinstance(relationships[0], dict)
        relationships[0]["claim_ids"] = [["claim-atomic"]]
    elif name == "unknown-atom-field":
        atoms[0]["unexpected"] = True
    else:
        executive_summary = brief["executive_summary"]
        assert isinstance(executive_summary, list) and isinstance(executive_summary[0], dict)
        executive_summary[0]["atom_ids"] = [["atom-duty"]]


@pytest.mark.parametrize(
    "mutation",
    [
        "missing-dimension",
        "list-dimension-disposition",
        "unhashable-dimension-atom-id",
        "missing-atom-element",
        "list-atom-status",
        "unhashable-atom-claim-id",
        "duplicate-atom-id",
        "duplicate-relationship-id",
        "list-relationship-claim-id",
        "unknown-atom-field",
        "unhashable-visible-atom-id",
    ],
)
def test_portable_atomic_v2_parser_rejects_the_same_nested_invalid_inputs(
    mutation: str,
) -> None:
    _, _, payload, _ = _atomic_case(
        "duty-exception" if "relationship" in mutation else "non-english"
    )
    before = deepcopy(payload)
    assert portable._draft(before) == AnalysisDraft.model_validate(before).model_dump(
        mode="json"
    )
    _mutate_atomic_invalid_payload(mutation, payload)

    with pytest.raises(ValidationError):
        AnalysisDraft.model_validate(payload)
    with pytest.raises(portable.PortableInputError):
        portable._draft(payload)
    assert before != payload


@pytest.mark.parametrize("legacy_field", ["lead_reviews", "proposition_coverage"])
def test_portable_and_full_v2_parsers_reject_nonempty_legacy_ledgers(
    legacy_field: str,
) -> None:
    _, _, payload, _ = _atomic_case("non-english")
    payload[legacy_field] = (
        [
            {
                "lead_id": "lead-legacy",
                "disposition": "not_material",
                "rationale": "Legacy review data cannot coexist with atomic coverage.",
            }
        ]
        if legacy_field == "lead_reviews"
        else [
            {
                "coverage_id": "coverage-legacy",
                "unit_ids": ["unit-atomic"],
                "category": "other",
                "proposition_type": "other",
                "disposition": "not_material",
                "rationale": "Legacy coverage data cannot coexist with atomic coverage.",
            }
        ]
    )

    with pytest.raises(
        ValidationError,
        match=(
            "proposition-coverage-v2 requires lead_reviews and "
            "proposition_coverage to be empty"
        ),
    ):
        AnalysisDraft.model_validate(payload)
    with pytest.raises(
        portable.PortableInputError,
        match=(
            "proposition-coverage-v2 requires lead_reviews and "
            "proposition_coverage to be empty"
        ),
    ):
        portable._draft(payload)


@pytest.mark.parametrize("bypass_method", ["model_copy", "model_construct"])
@pytest.mark.parametrize("legacy_field", ["lead_reviews", "proposition_coverage"])
def test_portable_atomic_v2_evaluator_rejects_legacy_ledgers_with_bypass_parity(
    bypass_method: str, legacy_field: str,
) -> None:
    units, leads, payload, sources = _atomic_case("non-english")
    valid_typed = AnalysisDraft.model_validate(payload)
    legacy_review = DraftLeadReview(
        lead_id="lead-legacy",
        disposition="not_material",
        rationale="Legacy review data cannot coexist with atomic coverage.",
    )
    legacy_coverage = DraftPropositionCoverage(
        coverage_id="coverage-legacy",
        unit_ids=["unit-atomic"],
        category="other",
        proposition_type="other",
        disposition="not_material",
        rationale="Legacy coverage data cannot coexist with atomic coverage.",
    )
    legacy_rows = [legacy_review] if legacy_field == "lead_reviews" else [legacy_coverage]
    if bypass_method == "model_copy":
        typed = valid_typed.model_copy(update={legacy_field: legacy_rows})
    else:
        values = {
            field_name: getattr(valid_typed, field_name)
            for field_name in AnalysisDraft.model_fields
        }
        values[legacy_field] = legacy_rows
        typed = AnalysisDraft.model_construct(**values)
    parsed = portable._draft(payload)
    parsed[legacy_field] = [row.model_dump(mode="json") for row in legacy_rows]
    source_payloads = [source.model_dump(mode="json") for source in sources]
    typed_before = deepcopy(typed.model_dump(mode="python", warnings=False))
    portable_before = deepcopy((units, leads, parsed, source_payloads))

    full_review = evaluate_atomic_coverage(units, leads, typed, sources)
    portable_review = portable._evaluate_portable_atomic_coverage(
        units, leads, parsed, source_payloads
    )

    assert full_review["valid"] is False
    assert full_review["issues"] == [
        {
            "code": "ATOMIC_REVIEW_INVALID",
            "message": (
                "A proposition-coverage-v2 draft cannot include legacy "
                "lead_reviews or proposition_coverage rows."
            ),
            "related_ids": [],
        }
    ]
    assert canonical_json_bytes(full_review) == portable._canonical_bytes(
        portable_review
    )
    assert typed.model_dump(mode="python", warnings=False) == typed_before
    assert (units, leads, parsed, source_payloads) == portable_before


@pytest.mark.parametrize(
    "mutation",
    [
        "malformed-unit-review",
        "malformed-atom",
        "malformed-relationship",
        "malformed-gap",
        "malformed-brief",
        "malformed-nested-brief",
        "duplicate-unit-target",
        "inventory-contract-mismatch",
    ],
)
def test_portable_atomic_validation_bypasses_have_full_bounded_review_parity(
    mutation: str,
) -> None:
    units, leads, payload, sources = _atomic_case("duty-exception")
    typed = AnalysisDraft.model_validate(payload)
    parsed = portable._draft(payload)
    if mutation == "malformed-unit-review":
        typed = typed.model_copy(update={"unit_reviews": [{"unit_id": ["unit-atomic"]}]})
        parsed["unit_reviews"] = [{"unit_id": ["unit-atomic"]}]
    elif mutation == "malformed-atom":
        typed = typed.model_copy(update={"rule_atoms": [{"atom_id": ["atom-duty"]}]})
        parsed["rule_atoms"] = [{"atom_id": ["atom-duty"]}]
    elif mutation == "malformed-relationship":
        typed = typed.model_copy(
            update={"rule_relationships": [{"relationship_id": ["relationship-exception"]}]}
        )
        parsed["rule_relationships"] = [
            {"relationship_id": ["relationship-exception"]}
        ]
    elif mutation == "malformed-gap":
        typed = typed.model_copy(update={"gaps": [{"code": ["BAD"]}]})
        parsed["gaps"] = [{"code": ["BAD"]}]
    elif mutation == "malformed-brief":
        typed = typed.model_copy(update={"brief": {"executive_summary": []}})
        parsed["brief"] = {"executive_summary": []}
    elif mutation == "malformed-nested-brief":
        assert typed.brief is not None
        typed = typed.model_copy(
            update={"brief": typed.brief.model_copy(update={"sections": None})}
        )
        assert isinstance(parsed["brief"], dict)
        parsed["brief"]["sections"] = None
    elif mutation == "duplicate-unit-target":
        raw_units = units["units"]
        assert isinstance(raw_units, list)
        raw_units.append(deepcopy(raw_units[0]))
        units["unit_count"] = 2
        units["required_unit_count"] = 2
    else:
        units["inventory_version"] = ["source-units-v1"]
    source_payloads = [source.model_dump(mode="json") for source in sources]
    before = deepcopy((units, leads, parsed, source_payloads))

    full_review = evaluate_atomic_coverage(units, leads, typed, sources)
    portable_review = portable._evaluate_coverage_closure(
        leads, units, parsed, source_payloads
    )

    assert full_review["valid"] is False
    assert canonical_json_bytes(full_review) == portable._canonical_bytes(portable_review)
    assert (units, leads, parsed, source_payloads) == before


@pytest.mark.parametrize(
    "issues_value",
    [
        pytest.param(None, id="none"),
        pytest.param(True, id="true"),
        pytest.param(False, id="false"),
        pytest.param(0, id="zero"),
        pytest.param(1, id="one"),
        pytest.param("x", id="string"),
        pytest.param([[]], id="nested-empty-list"),
        pytest.param([["x"]], id="nested-string-list"),
    ],
)
def test_portable_atomic_malformed_issues_have_full_fail_closed_parity(
    issues_value: object,
) -> None:
    """A malformed issue collection must fail at the exact-evidence boundary."""
    units, leads, payload, sources = _atomic_case("duty-exception")
    typed = AnalysisDraft.model_validate(payload).model_copy(
        update={"issues": deepcopy(issues_value)}
    )
    parsed = portable._draft(payload)
    parsed["issues"] = deepcopy(issues_value)
    source_payloads = [source.model_dump(mode="json") for source in sources]
    before = deepcopy((units, leads, parsed, source_payloads))

    full_review = evaluate_atomic_coverage(units, leads, typed, sources)
    portable_review = portable._evaluate_coverage_closure(
        leads, units, parsed, source_payloads
    )

    assert full_review["valid"] is False
    assert full_review["issues"] == [
        {
            "code": "ATOMIC_EVIDENCE_INVALID",
            "message": "The analysis draft could not be reconciled into exact evidence.",
            "related_ids": [],
        }
    ]
    assert canonical_json_bytes(full_review) == portable._canonical_bytes(portable_review)
    assert (units, leads, parsed, source_payloads) == before


_CORE_DRAFT_BYPASSES = (
    ("raw-issue-row", "issue", None, None),
    ("issue-id", "issue", "issue_id", None),
    ("issue-title", "issue", "title", " "),
    ("issue-description", "issue", "description", []),
    ("issue-jurisdictions", "issue", "jurisdictions", None),
    ("issue-category", "issue", "category", []),
    ("issue-presentation-role", "issue", "presentation_role", []),
    ("raw-finding-row", "finding", None, None),
    ("finding-id", "finding", "finding_id", None),
    ("finding-issue-id", "finding", "issue_id", None),
    ("finding-title", "finding", "title", None),
    ("finding-jurisdiction", "finding", "jurisdiction", None),
    ("finding-authority", "finding", "authority", None),
    ("finding-severity", "finding", "severity", "invalid"),
    ("finding-practical-implication", "finding", "practical_implication", None),
    ("finding-claims", "finding", "claims", None),
    ("raw-claim-row", "claim", None, None),
    ("claim-id", "claim", "claim_id", None),
    ("claim-text", "claim", "text", None),
    ("claim-kind", "claim", "kind", "invalid"),
    ("claim-enforcement-roles", "claim", "enforcement_roles", None),
    ("claim-confidence", "claim", "confidence", 2),
    ("claim-proposed-citations", "claim", "proposed_citations", None),
    ("raw-citation-row", "citation", None, None),
    ("citation-source-id", "citation", "source_id", None),
    ("citation-quote", "citation", "quote", None),
    ("citation-occurrence", "citation", "occurrence", 0),
)


def _mutate_atomic_core_draft_bypass(
    typed: AnalysisDraft,
    parsed: dict[str, object],
    target: str,
    field: str | None,
    value: object,
) -> AnalysisDraft:
    if target == "issue":
        typed_row = typed.issues[0]
        parsed_rows = parsed["issues"]
        assert isinstance(parsed_rows, list) and isinstance(parsed_rows[0], dict)
        if field is None:
            parsed_rows[0] = dict(parsed_rows[0])
            return typed.model_copy(
                update={"issues": [typed_row.model_dump(mode="python")]}
            )
        parsed_rows[0][field] = deepcopy(value)
        return typed.model_copy(
            update={"issues": [typed_row.model_copy(update={field: deepcopy(value)})]}
        )

    typed_finding = typed.findings[0]
    parsed_findings = parsed["findings"]
    assert isinstance(parsed_findings, list) and isinstance(parsed_findings[0], dict)
    parsed_finding = parsed_findings[0]
    if target == "finding":
        if field is None:
            parsed_findings[0] = dict(parsed_finding)
            return typed.model_copy(
                update={"findings": [typed_finding.model_dump(mode="python")]}
            )
        parsed_finding[field] = deepcopy(value)
        return typed.model_copy(
            update={
                "findings": [
                    typed_finding.model_copy(update={field: deepcopy(value)})
                ]
            }
        )

    typed_claim = typed_finding.claims[0]
    parsed_claims = parsed_finding["claims"]
    assert isinstance(parsed_claims, list) and isinstance(parsed_claims[0], dict)
    parsed_claim = parsed_claims[0]
    if target == "claim":
        if field is None:
            parsed_claims[0] = dict(parsed_claim)
            updated_claim: object = typed_claim.model_dump(mode="python")
        else:
            parsed_claim[field] = deepcopy(value)
            updated_claim = typed_claim.model_copy(update={field: deepcopy(value)})
        return typed.model_copy(
            update={
                "findings": [
                    typed_finding.model_copy(update={"claims": [updated_claim]})
                ]
            }
        )

    typed_citation = typed_claim.proposed_citations[0]
    parsed_citations = parsed_claim["proposed_citations"]
    assert isinstance(parsed_citations, list) and isinstance(parsed_citations[0], dict)
    parsed_citation = parsed_citations[0]
    if field is None:
        parsed_citations[0] = dict(parsed_citation)
        updated_citation: object = typed_citation.model_dump(mode="python")
    else:
        parsed_citation[field] = deepcopy(value)
        updated_citation = typed_citation.model_copy(update={field: deepcopy(value)})
    updated_claim = typed_claim.model_copy(
        update={"proposed_citations": [updated_citation]}
    )
    return typed.model_copy(
        update={
            "findings": [typed_finding.model_copy(update={"claims": [updated_claim]})]
        }
    )


@pytest.mark.parametrize(
    ("name", "target", "field", "value"),
    _CORE_DRAFT_BYPASSES,
    ids=[row[0] for row in _CORE_DRAFT_BYPASSES],
)
def test_portable_atomic_core_draft_resnapshot_has_full_fail_closed_parity(
    name: str,
    target: str,
    field: str | None,
    value: object,
) -> None:
    units, leads, payload, sources = _atomic_case("duty-exception")
    typed = AnalysisDraft.model_validate(payload)
    parsed = portable._draft(payload)
    typed = _mutate_atomic_core_draft_bypass(
        typed, parsed, target, field, value
    )
    source_payloads = [source.model_dump(mode="json") for source in sources]
    before = deepcopy((units, leads, parsed, source_payloads))

    full_review = evaluate_atomic_coverage(units, leads, typed, sources)
    portable_review = portable._evaluate_coverage_closure(
        leads, units, parsed, source_payloads
    )

    assert full_review["valid"] is False
    if target != "citation" or name in {"raw-citation-row", "citation-source-id"}:
        assert {issue["code"] for issue in full_review["issues"]} == {
            "ATOMIC_EVIDENCE_INVALID"
        }
    else:
        assert full_review["issues"]
    assert canonical_json_bytes(full_review) == portable._canonical_bytes(portable_review)
    assert (units, leads, parsed, source_payloads) == before


_GAP_BYPASSES = (
    ("raw-gap-row", None, None),
    ("gap-code", "code", None),
    ("gap-message", "message", []),
    ("gap-category", "category", []),
    ("gap-presentation-role", "presentation_role", []),
    ("gap-jurisdiction", "jurisdiction", []),
    ("gap-source-ids-empty-list", "source_ids", [[]]),
    ("gap-source-ids-string-list", "source_ids", [["x"]]),
)


@pytest.mark.parametrize(
    ("name", "field", "value"),
    _GAP_BYPASSES,
    ids=[row[0] for row in _GAP_BYPASSES],
)
def test_portable_atomic_gap_resnapshot_is_bounded_with_full_byte_parity(
    name: str,
    field: str | None,
    value: object,
) -> None:
    del name
    units, leads, payload, sources = _atomic_case("gap")
    typed = AnalysisDraft.model_validate(payload)
    parsed = portable._draft(payload)
    typed_gap = typed.gaps[0]
    parsed_gaps = parsed["gaps"]
    assert isinstance(parsed_gaps, list) and isinstance(parsed_gaps[0], dict)
    if field is None:
        typed = typed.model_copy(
            update={"gaps": [typed_gap.model_dump(mode="python")]}
        )
        parsed_gaps[0] = dict(parsed_gaps[0])
    else:
        typed = typed.model_copy(
            update={"gaps": [typed_gap.model_copy(update={field: deepcopy(value)})]}
        )
        parsed_gaps[0][field] = deepcopy(value)
    source_payloads = [source.model_dump(mode="json") for source in sources]
    before = deepcopy((units, leads, parsed, source_payloads))

    full_review = evaluate_atomic_coverage(units, leads, typed, sources)
    portable_review = portable._evaluate_coverage_closure(
        leads, units, parsed, source_payloads
    )

    assert full_review["valid"] is False
    assert {issue["code"] for issue in full_review["issues"]} == {
        "ATOMIC_GAP_INVALID"
    }
    assert canonical_json_bytes(full_review) == portable._canonical_bytes(portable_review)
    assert (units, leads, parsed, source_payloads) == before


def test_portable_atomic_cycle_diagnostics_are_bounded() -> None:
    text = "A controller must maintain a synthetic register."
    units, leads = _atomic_inventories(text)
    sources = [_atomic_source(text)]
    source_payloads = [source.model_dump(mode="json") for source in sources]

    def review(reference_count: int) -> tuple[dict[str, object], dict[str, object]]:
        atom_types = [(f"atom-{index:02d}", "exception") for index in range(reference_count)]
        relationships = [
            (
                f"relationship-{index:02d}",
                "exception_to",
                f"atom-{index:02d}",
                f"atom-{(index + 1) % reference_count:02d}",
            )
            for index in range(reference_count)
        ]
        payload = _atomic_payload(text, atom_types, relationships)
        typed = AnalysisDraft.model_validate(payload)
        parsed = portable._draft(payload)
        return (
            evaluate_atomic_coverage(units, leads, typed, sources),
            portable._evaluate_coverage_closure(leads, units, parsed, source_payloads),
        )

    one_full, one_portable = review(2)
    fifty_full, fifty_portable = review(50)

    assert canonical_json_bytes(one_full) == portable._canonical_bytes(one_portable)
    assert canonical_json_bytes(fifty_full) == portable._canonical_bytes(fifty_portable)
    assert sum(
        issue["message"] == "Atomic rule relationships contain a prohibited cycle."
        for issue in fifty_full["issues"]
    ) == 1


@pytest.mark.parametrize("bypass_row", ["typed", "raw"])
def test_portable_malformed_atom_diagnostics_do_not_scale_with_references(
    bypass_row: str,
) -> None:
    text = "A controller must maintain a synthetic register."
    sources = [_atomic_source(text)]
    source_payloads = [source.model_dump(mode="json") for source in sources]

    def review(reference_count: int) -> tuple[dict[str, object], dict[str, object]]:
        units, leads = _atomic_inventories(text)
        lead_ids = [f"lead-{index:02d}" for index in range(reference_count)]
        lead_rows = [
            {
                "lead_id": lead_id,
                "source_id": "src-atomic",
                "topic": f"synthetic topic {lead_id}",
                "issue_category": "requirements",
                "start_char": 0,
                "end_char": len(text),
                "heading": None,
                "excerpt": text,
                "signals": ["must"],
                "review_required": True,
            }
            for lead_id in lead_ids
        ]
        leads.update(
            {
                "lead_count": reference_count,
                "priority_lead_count": reference_count,
                "priority_topic_counts": {
                    f"synthetic topic {lead_id}": 1 for lead_id in lead_ids
                },
                "topic_counts": {
                    f"synthetic topic {lead_id}": 1 for lead_id in lead_ids
                },
                "leads": lead_rows,
            }
        )
        payload = _atomic_payload(text, [("atom-duty", "duty")], [])
        unit_reviews = payload["unit_reviews"]
        assert isinstance(unit_reviews, list)
        dimensions = unit_reviews[0]["dimensions"]
        assert isinstance(dimensions, dict)
        dimensions["duties_rights_prohibitions"] = {"disposition": "not_present"}
        atoms = payload["rule_atoms"]
        assert isinstance(atoms, list) and isinstance(atoms[0], dict)
        atoms[0]["unit_ids"] = []
        atoms[0]["lead_ids"] = lead_ids
        payload["lead_dispositions_v2"] = [
            {
                "lead_id": lead_id,
                "disposition": "mapped",
                "atom_ids": ["atom-duty"],
            }
            for lead_id in lead_ids
        ]
        valid_typed = AnalysisDraft.model_validate(payload)
        typed_atom = valid_typed.rule_atoms[0]
        malformed_payload = typed_atom.model_dump(mode="python", warnings=False)
        malformed_payload["unit_ids"] = [["unit-atomic"]]
        malformed_typed: object = (
            typed_atom.model_copy(update={"unit_ids": [["unit-atomic"]]})
            if bypass_row == "typed"
            else malformed_payload
        )
        typed = valid_typed.model_copy(update={"rule_atoms": [malformed_typed]})
        parsed = portable._draft(payload)
        parsed_atom = deepcopy(parsed["rule_atoms"][0])
        parsed_atom["unit_ids"] = [["unit-atomic"]]
        parsed["rule_atoms"] = [
            portable._PortableRuleAtom(parsed_atom)
            if bypass_row == "typed"
            else parsed_atom
        ]
        typed_before = deepcopy(typed.model_dump(mode="python", warnings=False))
        portable_before = deepcopy((units, leads, parsed, source_payloads))

        full_review = evaluate_atomic_coverage(units, leads, typed, sources)
        portable_review = portable._evaluate_portable_atomic_coverage(
            units, leads, parsed, source_payloads
        )

        assert canonical_json_bytes(full_review) == portable._canonical_bytes(
            portable_review
        )
        assert typed.model_dump(mode="python", warnings=False) == typed_before
        assert (units, leads, parsed, source_payloads) == portable_before
        return full_review, portable_review

    one_full, _ = review(1)
    fifty_full, _ = review(50)

    expected_issues = [
        {
            "code": "ATOMIC_REVIEW_INVALID",
            "message": "The atomic rule atom collection contains a malformed row.",
            "related_ids": ["atom-duty"],
        },
        {
            "code": "ATOMIC_RULE_INVALID",
            "message": "The atomic rule atom collection contains a malformed row.",
            "related_ids": ["atom-duty"],
        },
    ]
    assert one_full["issues"] == fifty_full["issues"] == expected_issues
    assert one_full["valid"] is fifty_full["valid"] is False
    for review_result, reference_count in ((one_full, 1), (fifty_full, 50)):
        frozen = dict(review_result)
        review_hash = frozen.pop("coverage_review_hash")
        assert review_hash == portable._sha256(portable._canonical_bytes(frozen))
        assert review_result["rule_graph"]["rule_counts"] == {
            "atom_rows": 1,
            "atoms": 1,
            "invalid_atoms": 1,
            "relationship_rows": 0,
            "relationships": 0,
            "invalid_relationships": 0,
        }
        leads = review_result["target_review"]["leads"]
        assert len(leads) == reference_count
        assert all(row["valid"] is False for row in leads)


def test_portable_runner_blocks_private_network_sources() -> None:
    """An offline fallback must not weaken the full engine's SSRF boundary."""
    private_url = urlunsplit(("http", "127.0.0.1", "/source", "", ""))
    with pytest.raises(ValueError, match="non-public"):
        portable._validate_public_url(private_url)


def test_portable_canonical_url_accepts_public_ipv6() -> None:
    """The fallback provenance parser must preserve valid public IPv6 URLs."""
    url = "https://[2606:4700:4700::1111]/rule"

    assert portable._canonical_public_url(url, "source.canonical_url") == url


@pytest.mark.parametrize("matter_title", [None, "   "])
def test_portable_charter_requires_a_concrete_matter_title(
    matter_title: str | None,
) -> None:
    """The dependency-free parser must reject omitted or blank new-report titles."""
    charter = _charter(Path("rule.txt"))
    if matter_title is None:
        charter.pop("matter_title")
    else:
        charter["matter_title"] = matter_title

    with pytest.raises(portable.PortableInputError, match=r"charter\.matter_title"):
        portable._charter(charter)


def test_portable_prepare_source_units_preserve_canonical_provenance(tmp_path: Path) -> None:
    """The dependency-free runtime must not discard public provenance for a local capture."""
    source = tmp_path / "rule.txt"
    source.write_text("A controller must document risks.\n", encoding="utf-8")
    payload = _charter(source)
    payload["matter_title"] = "Example Regulation"
    payload["sources"][0].update(  # type: ignore[index,union-attr]
        {
            "canonical_url": "https://example.org/rules/current?download=1#section-2",
            "language": "en",
        }
    )
    charter = tmp_path / "charter.json"
    charter.write_text(json.dumps(payload), encoding="utf-8")
    matter = tmp_path / "matter"

    receipt = portable.prepare(charter, matter)

    dossier = json.loads((matter / "agent-dossier.json").read_text(encoding="utf-8"))
    record = dossier["sources"][0]
    assert record["origin"].startswith("inputs/")
    assert record["canonical_url"] == "https://example.org/rules/current"
    assert record["language"] == "en"
    inventory = dossier["evidence_inventory"]
    assert inventory["inventory_version"] == "provision-leads-v2"
    assert {lead["topic"] for lead in inventory["leads"]} == {"duties"}
    assert dossier["coverage_contract_version"] == "proposition-coverage-v2"
    source_units = dossier["source_unit_inventory"]
    assert source_units["inventory_version"] == "source-units-v1"
    assert source_units["required_unit_count"] >= 1
    assert receipt["source_unit_count"] == source_units["unit_count"]
    assert portable._build_source_unit_inventory([record]) == source_units
    for unit in source_units["units"]:
        assert unit["excerpt"] == record["normalized_text"][unit["start_char"] : unit["end_char"]]


def test_portable_v2_prepare_finalize_writes_atomic_review_and_receipt(
    tmp_path: Path,
) -> None:
    quote = "A controller must document risks."
    source = tmp_path / "rule.txt"
    source.write_text(quote + "\n", encoding="utf-8")
    charter = tmp_path / "charter.json"
    charter.write_text(json.dumps(_charter(source)), encoding="utf-8")
    matter = tmp_path / "matter"
    portable.prepare(charter, matter)
    dossier_path = matter / "agent-dossier.json"
    dossier = json.loads(dossier_path.read_text(encoding="utf-8"))
    source_id = dossier["sources"][0]["source_id"]
    payload: dict[str, object] = {
        "issues": [
            {
                "issue_id": "issue-requirements",
                "title": "Requirements",
                "category": "requirements",
                "jurisdictions": ["US"],
            }
        ],
        "findings": [
            {
                "finding_id": "finding-requirements",
                "issue_id": "issue-requirements",
                "title": "Documentation duty",
                "jurisdiction": "US",
                "authority": "Synthetic Rule",
                "severity": "info",
                "practical_implication": "Document risks.",
                "claims": [
                    {
                        "claim_id": "claim-requirements",
                        "text": quote,
                        "kind": "source_supported",
                        "proposed_citations": [
                            {"source_id": source_id, "quote": quote}
                        ],
                    }
                ],
            }
        ],
        "brief": _brief(
            "finding-requirements", "claim-requirements", quote
        ),
    }
    _attach_prepared_atomic_coverage(
        payload, dossier, quote, "claim-requirements"
    )
    draft = tmp_path / "draft.json"
    draft.write_text(json.dumps(payload), encoding="utf-8")

    receipt, status = portable.finalize(
        matter, draft, host_name="test-host", model_name="test-model"
    )

    review = json.loads(Path(receipt["coverage_review"]).read_text(encoding="utf-8"))
    assert status == 0
    assert review["schema_version"] == "3.0"
    assert review["coverage_contract_version"] == "proposition-coverage-v2"
    assert review["valid"] is True
    assert receipt["coverage_issue_count"] == 0
    assert receipt["proposition_coverage_valid"] is True
    assert receipt["provision_recall_valid"] is True
    assert Path(receipt["analysis_draft"]).is_file()
    assert Path(receipt["report"]).is_file()
    assert Path(receipt["audit"]).is_file()
    assert Path(receipt["bundle"]).is_file()


def test_portable_parser_preserves_optional_presentation_metadata() -> None:
    """The dependency-free path must retain the structure authored by the host."""
    charter = _charter(Path("rule.txt"))
    charter["matter_title"] = "Example Regulation"
    charter["sources"][0]["source_role"] = "official_primary"  # type: ignore[index]
    parsed_charter = portable._charter(charter)
    parsed_draft = portable._draft(
        {
            "issues": [
                {
                    "issue_id": "scope-activities",
                    "title": "Covered activities",
                    "category": "scope",
                    "presentation_role": "covered_activities",
                }
            ],
            "findings": [],
            "gaps": [
                {
                    "code": "CLIENT_FACTS_REQUIRED",
                    "message": "Client facts were not supplied.",
                    "category": "implementation",
                    "presentation_role": "client_facts",
                }
            ],
            "lead_reviews": [
                {
                    "lead_id": "lead_example",
                    "disposition": "not_material",
                    "rationale": "The synthetic lead is outside this parser-only example.",
                }
            ],
            "brief": {
                "structure_profile": "regulatory-walk-v1",
                "executive_summary": [
                    {
                        "kind": "paragraph",
                        "purpose": "client_fact",
                        "text": "Client deployment posture is unknown.",
                    }
                ],
                "sections": [
                    {
                        "section_id": "facts-needed",
                        "title": "Facts Needed",
                        "role": "other",
                        "blocks": [
                            {
                                "kind": "bullet_list",
                                "purpose": "client_fact",
                                "items": [{"text": "Confirm deployment date."}],
                            }
                        ],
                    }
                ],
            },
        }
    )

    assert parsed_charter["matter_title"] == "Example Regulation"
    assert parsed_charter["sources"][0]["source_role"] == "official_primary"
    assert parsed_draft["issues"][0]["presentation_role"] == "covered_activities"
    assert parsed_draft["gaps"][0]["presentation_role"] == "client_facts"
    assert parsed_draft["lead_reviews"] == [
        {
            "lead_id": "lead_example",
            "disposition": "not_material",
            "gap_codes": [],
            "rationale": "The synthetic lead is outside this parser-only example.",
        }
    ]
    assert parsed_draft["brief"]["structure_profile"] == "regulatory-walk-v1"
    assert parsed_draft["brief"]["sections"][0]["role"] == "other"
    assert parsed_draft["brief"]["sections"][0]["title"] == "Facts Needed"


def test_portable_draft_preserves_typed_enforcement_claim_roles() -> None:
    """The dependency-free parser must retain and constrain enforcement semantics."""
    payload = {
        "issues": [],
        "findings": [
            {
                "finding_id": "finding-enforcement",
                "issue_id": "issue-enforcement",
                "title": "Civil penalty",
                "jurisdiction": "US",
                "authority": "Synthetic Rule",
                "severity": "medium",
                "practical_implication": "Review the violation and penalty pair.",
                "claims": [
                    {
                        "claim_id": "claim-enforcement",
                        "text": "A violation may result in a civil penalty.",
                        "kind": "source_supported",
                        "enforcement_roles": ["trigger", "consequence"],
                    }
                ],
            }
        ],
    }

    parsed = portable._draft(payload)

    assert parsed["findings"][0]["claims"][0]["enforcement_roles"] == [
        "trigger",
        "consequence",
    ]
    payload["findings"][0]["claims"][0]["enforcement_roles"] = ["generic_requirement"]
    with pytest.raises(portable.PortableInputError, match="enforcement_roles"):
        portable._draft(payload)


def test_portable_draft_rejects_an_authored_brief_without_structure_profile() -> None:
    """The dependency-free new-draft boundary must enforce the same profile contract."""
    payload = {
        "issues": [],
        "findings": [],
        "brief": {
            "executive_summary": [
                {
                    "kind": "paragraph",
                    "purpose": "client_fact",
                    "text": "Facts remain open.",
                }
            ],
            "sections": [
                {
                    "section_id": "facts-needed",
                    "title": "Facts Needed",
                    "blocks": [
                        {
                            "kind": "paragraph",
                            "purpose": "client_fact",
                            "text": "Confirm deployment date.",
                        }
                    ],
                }
            ],
        },
    }

    with pytest.raises(portable.PortableInputError, match="structure_profile"):
        portable._draft(payload)


def test_portable_draft_rejects_renderer_owned_brief_heading() -> None:
    """The portable schema must preserve the deterministic report boundary."""
    payload = {
        "issues": [],
        "findings": [],
        "brief": {
            "executive_summary": [
                {
                    "kind": "paragraph",
                    "purpose": "client_fact",
                    "text": "Facts remain open.",
                }
            ],
            "sections": [
                {
                    "section_id": "forbidden",
                    "title": "Bottom Line",
                    "blocks": [
                        {
                            "kind": "paragraph",
                            "purpose": "client_fact",
                            "text": "Facts remain open.",
                        }
                    ],
                }
            ],
        },
    }

    with pytest.raises(portable.PortableInputError, match="owned"):
        portable._draft(payload)


def test_portable_finalize_requires_the_authored_attorney_brief(tmp_path: Path) -> None:
    """Portable fallback must not silently return to a generic issue outline."""
    quote = "A controller must document risks."
    source = tmp_path / "rule.txt"
    source.write_text(quote + "\n", encoding="utf-8")
    charter = tmp_path / "charter.json"
    charter.write_text(json.dumps(_charter(source)), encoding="utf-8")
    matter = tmp_path / "matter"
    portable.prepare(charter, matter)
    dossier = json.loads((matter / "agent-dossier.json").read_text(encoding="utf-8"))
    source_id = dossier["sources"][0]["source_id"]
    draft = tmp_path / "draft.json"
    draft.write_text(
        json.dumps(
            {
                "issues": [{"issue_id": "issue-1", "title": "Documentation"}],
                "findings": [
                    {
                        "finding_id": "finding-1",
                        "issue_id": "issue-1",
                        "title": "Documentation duty",
                        "jurisdiction": "US",
                        "authority": "Synthetic Rule",
                        "severity": "info",
                        "practical_implication": "Document risks.",
                        "claims": [
                            {
                                "claim_id": "claim-1",
                                "text": quote,
                                "kind": "source_supported",
                                "proposed_citations": [
                                    {"source_id": source_id, "quote": quote}
                                ],
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(portable.PortableInputError, match="attorney brief"):
        portable.finalize(
            matter,
            draft,
            host_name="test-host",
            model_name="test-model",
        )


def test_portable_finalization_writes_coverage_review_before_report_pipeline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    quote = "A controller must document risks."
    source = tmp_path / "rule.txt"
    source.write_text(quote + "\n", encoding="utf-8")
    charter = tmp_path / "charter.json"
    charter.write_text(json.dumps(_charter(source)), encoding="utf-8")
    matter = tmp_path / "matter"
    portable.prepare(charter, matter)
    dossier = json.loads((matter / "agent-dossier.json").read_text(encoding="utf-8"))
    source_id = dossier["sources"][0]["source_id"]
    payload: dict[str, object] = {
        "issues": [
            {
                "issue_id": "issue-requirements",
                "title": "Requirements",
                "category": "requirements",
            }
        ],
        "findings": [
            {
                "finding_id": "finding-requirements",
                "issue_id": "issue-requirements",
                "title": "Documentation duty",
                "jurisdiction": "US",
                "authority": "Synthetic Rule",
                "severity": "info",
                "practical_implication": "Document risks.",
                "claims": [
                    {
                        "claim_id": "claim-requirements",
                        "text": quote,
                        "kind": "source_supported",
                        "proposed_citations": [
                            {"source_id": source_id, "quote": quote}
                        ],
                    }
                ],
            }
        ],
        "brief": _brief(
            "finding-requirements",
            "claim-requirements",
            quote,
        ),
    }
    _attach_prepared_coverage(payload, dossier, quote, "claim-requirements")
    _use_explicit_v1_dossier(matter, dossier)
    draft = tmp_path / "draft.json"
    draft.write_text(json.dumps(payload), encoding="utf-8")
    original_build = portable._build_analysis
    call_count = 0

    def fail_report_build(
        draft_value: dict[str, object], sources: list[dict[str, object]]
    ) -> tuple[list[dict[str, object]], list[dict[str, object]], list[dict[str, object]]]:
        nonlocal call_count
        call_count += 1
        if call_count == 3:
            raise RuntimeError("synthetic portable report pipeline failure")
        return original_build(draft_value, sources)

    monkeypatch.setattr(portable, "_build_analysis", fail_report_build)
    with pytest.raises(RuntimeError, match="synthetic portable report pipeline failure"):
        portable.finalize(
            matter,
            draft,
            host_name="test-host",
            model_name="test-model",
        )

    review = json.loads((matter / "coverage-review.json").read_text(encoding="utf-8"))
    assert review["schema_version"] == "2.0"
    assert review["proposition_coverage"]["valid"] is True


def test_portable_infers_primary_quality_from_supported_official_provenance(
    tmp_path: Path,
) -> None:
    """The dependency-free path must not undercount verified official authority."""
    source = tmp_path / "rule.txt"
    source.write_text("A controller must document risks.\n", encoding="utf-8")
    payload = _charter(source)
    payload["sources"][0].update(  # type: ignore[index,union-attr]
        {
            "canonical_url": "https://www.legislation.gov.uk/ukpga/2024/1",
            "authority_type": "enacted statute",
        }
    )
    charter = tmp_path / "charter.json"
    charter.write_text(json.dumps(payload), encoding="utf-8")
    matter = tmp_path / "matter"

    portable.prepare(charter, matter)

    dossier = json.loads((matter / "agent-dossier.json").read_text(encoding="utf-8"))
    assert dossier["sources"][0]["source_quality"] == "primary"


@pytest.mark.parametrize(
    "canonical_url",
    [
        "file:///etc/passwd",
        "https://user:secret@example.org/rule",
        "http://" + "127.0.0.1/rule",
        "http://" + "localhost/rule",
        "https://" + "authority.internal/rule",
    ],
)
def test_portable_charter_rejects_unsafe_canonical_url(
    tmp_path: Path,
    canonical_url: str,
) -> None:
    """Portable provenance validation must match the full engine's safe public-URL rule."""
    source = tmp_path / "rule.txt"
    source.write_text("Synthetic rule.\n", encoding="utf-8")
    payload = _charter(source)
    payload["sources"][0]["canonical_url"] = canonical_url  # type: ignore[index]
    charter = tmp_path / "charter.json"
    charter.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(portable.PortableInputError, match="canonical_url"):
        portable.prepare(charter, tmp_path / "matter")


def test_portable_charter_strips_query_credentials_and_fragments(
    tmp_path: Path,
) -> None:
    source = tmp_path / "rule.txt"
    source.write_text("Synthetic rule.\n", encoding="utf-8")
    payload = _charter(source)
    payload["sources"][0]["canonical_url"] = (  # type: ignore[index]
        "https://example.org/rule?X-Amz-Credential=hidden&view=official#section"
    )
    charter = tmp_path / "charter.json"
    charter.write_text(json.dumps(payload), encoding="utf-8")

    portable.prepare(charter, tmp_path / "matter")

    dossier = json.loads(
        (tmp_path / "matter" / "agent-dossier.json").read_text(encoding="utf-8")
    )
    assert dossier["sources"][0]["canonical_url"] == "https://example.org/rule"


def test_portable_report_follows_attorney_contract_and_source_labels(tmp_path: Path) -> None:
    """The fallback report must match the full runtime's attorney review experience."""
    quote = "A controller must document material risks."
    source = tmp_path / "rule.txt"
    source.write_text(quote + "\n", encoding="utf-8")
    payload = _charter(source)
    payload["matter_title"] = "Example Regulation"
    payload["sources"][0].update(  # type: ignore[index,union-attr]
        {
            "canonical_url": "https://example.org/rule?view=official#section-4",
            "publisher": "Example Legislature",
            "jurisdiction": "US",
            "authority_type": "enacted regulation",
            "citation": "Example Rule section 4",
            "effective_date": "2026-01-01",
            "supersession": "No later amendment identified as of 2026-08-06.",
            "language": "en",
            "source_quality": "primary",
            "source_role": "official_primary",
        }
    )
    charter = tmp_path / "charter.json"
    charter.write_text(json.dumps(payload), encoding="utf-8")
    matter = tmp_path / "matter"
    portable.prepare(charter, matter)
    dossier = json.loads((matter / "agent-dossier.json").read_text(encoding="utf-8"))
    source_id = dossier["sources"][0]["source_id"]
    draft_payload = {
        "issues": [
            {
                "issue_id": "issue-requirements",
                "title": "Operative requirements",
                "category": "requirements",
                "jurisdictions": ["US"],
                "presentation_role": "requirement",
            }
        ],
        "findings": [
            {
                "finding_id": "finding-documentation",
                "issue_id": "issue-requirements",
                "title": "Controllers must document material risks",
                "jurisdiction": "US",
                "authority": "Example Rule section 4",
                "severity": "high",
                "practical_implication": "Create a risk record before deployment.",
                "claims": [
                    {
                        "claim_id": "claim-documentation",
                        "text": quote,
                        "kind": "source_supported",
                        "proposed_citations": [{"source_id": source_id, "quote": quote}],
                    }
                ],
            }
        ],
        "gaps": [
            {
                "code": "FACTUAL_CONTEXT_REQUIRED",
                "message": "The client's controller posture has not been confirmed.",
                "category": "implementation",
                "jurisdiction": "US",
                "source_ids": [source_id],
                "presentation_role": "client_facts",
            }
        ],
        "brief": {
            "structure_profile": "regulatory-walk-v1",
            "executive_summary": [
                {
                    "kind": "paragraph",
                    "purpose": "legal_analysis",
                    "text": quote,
                    "finding_ids": ["finding-documentation"],
                    "claim_ids": ["claim-documentation"],
                }
            ],
            "sections": [
                {
                    "section_id": "who-is-covered",
                    "title": "Who Is Covered",
                    "role": "other",
                    "blocks": [
                        {
                            "kind": "paragraph",
                            "purpose": "legal_analysis",
                            "text": quote,
                            "finding_ids": ["finding-documentation"],
                            "claim_ids": ["claim-documentation"],
                        }
                    ],
                    "subsections": [],
                },
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
                                        "text": quote,
                                        "finding_ids": ["finding-documentation"],
                                        "claim_ids": ["claim-documentation"],
                                }
                            ],
                        }
                    ],
                    "subsections": [],
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
                                "Not established: The evidence does not establish "
                                "penalties or enforcement mechanisms."
                            ),
                        }
                    ],
                    "subsections": [],
                },
                {
                    "section_id": "implementation-workplan",
                    "title": "Implementation Workplan",
                    "role": "implementation",
                    "blocks": [
                        {
                            "kind": "table",
                            "purpose": "application",
                            "columns": ["Action", "Timing"],
                            "rows": [
                                {
                                    "cells": ["Document material risks", "Before deployment"],
                                    "finding_ids": ["finding-documentation"],
                                }
                            ],
                        }
                    ],
                    "subsections": [],
                },
            ],
        },
    }
    _attach_prepared_coverage(
        draft_payload,
        dossier,
        quote,
        "claim-documentation",
    )
    _use_explicit_v1_dossier(matter, dossier)
    draft = tmp_path / "draft.json"
    draft.write_text(json.dumps(draft_payload), encoding="utf-8")

    receipt, status = portable.finalize(
        matter,
        draft,
        host_name="test-host",
        model_name="test-model",
    )

    assert status == 0
    coverage_review = json.loads(
        Path(receipt["coverage_review"]).read_text(encoding="utf-8")
    )
    assert receipt["evidence_precision_valid"] is True
    assert receipt["provision_recall_valid"] is True
    assert coverage_review["valid"] is True
    report = Path(receipt["report"]).read_text(encoding="utf-8")
    audit = Path(receipt["audit"]).read_text(encoding="utf-8")
    assert report.startswith("# Example Regulation")
    assert "## Bottom Line" not in report
    assert "## Priority and Posture" not in report
    assert "## Executive Summary" in report
    assert "## Who Is Covered" in report
    assert "## Key Requirements" in report
    assert "## Penalties and Enforcement" in report
    assert "## Implementation Workplan" in report
    assert quote in report
    assert "| Action | Timing |" in report
    assert "| Document material risks | Before deployment" in report
    assert "## Limitations and Open Questions" in report
    assert "## Sources Consulted" in report
    assert report.index("## Executive Summary") < report.index("## Who Is Covered")
    assert report.index("## Key Requirements") < report.index("## Penalties and Enforcement")
    assert report.index("## Penalties and Enforcement") < report.index(
        "## Implementation Workplan"
    )
    assert report.index("## Implementation Workplan") < report.index(
        "## Sources Consulted"
    )
    assert "## Evidence and Validation Appendix" not in report
    assert "What does the synthetic source say?" not in report
    assert "[S1](https://example.org/rule)" in report
    assert "#section-4" not in report
    assert "### Official and Primary Sources" in report
    assert "### Secondary Sources" not in report
    assert "# Example Regulation: Evidence and Validation Audit" in audit
    assert audit.count("What does the synthetic source say?") == 1
    assert quote in audit
    assert "Canonical source: <https://example.org/rule>" in audit
    assert "FACTUAL_CONTEXT_REQUIRED" in audit
    bundle = json.loads(Path(receipt["bundle"]).read_text(encoding="utf-8"))
    assert {gap["category"] for gap in bundle["gaps"]} >= {
        "status",
        "scope",
        "enforcement",
        "deadlines",
        "implementation",
    }


def test_portable_web_mode_requires_successful_primary_authority(tmp_path: Path) -> None:
    """The fallback runtime must enforce the same web authority boundary as the package."""
    source = tmp_path / "commentary.txt"
    source.write_text("A secondary summary of a proposed rule.\n", encoding="utf-8")
    payload = _charter(source)
    payload["source_mode"] = "web"
    payload["sources"][0]["source_quality"] = "secondary"  # type: ignore[index]
    charter = tmp_path / "charter.json"
    charter.write_text(json.dumps(payload), encoding="utf-8")
    matter = tmp_path / "matter"
    portable.prepare(charter, matter)
    dossier = json.loads((matter / "agent-dossier.json").read_text(encoding="utf-8"))
    source_id = dossier["sources"][0]["source_id"]
    draft = tmp_path / "draft.json"
    draft_payload = {
        "issues": [
            {"issue_id": "issue-status", "title": "Status", "category": "status"}
        ],
        "findings": [
            {
                "finding_id": "finding-status",
                "issue_id": "issue-status",
                "title": "Only secondary material was retained",
                "jurisdiction": "US",
                "authority": "Secondary summary",
                "severity": "info",
                "practical_implication": "Retrieve primary authority before relying.",
                "claims": [
                    {
                        "claim_id": "claim-status",
                        "text": "A secondary summary describes a proposed rule.",
                        "kind": "source_supported",
                        "proposed_citations": [
                            {
                                "source_id": source_id,
                                "quote": "A secondary summary of a proposed rule.",
                            }
                        ],
                    }
                ],
            }
        ],
        "gaps": [],
        "brief": _brief(
            "finding-status",
            "claim-status",
            "A secondary summary describes a proposed rule.",
            finding_category="status",
        ),
    }
    _attach_prepared_coverage(
        draft_payload,
        dossier,
        "A secondary summary of a proposed rule.",
        "claim-status",
        category="status",
        proposition_type="status",
    )
    _use_explicit_v1_dossier(matter, dossier)
    draft.write_text(json.dumps(draft_payload), encoding="utf-8")

    receipt, status = portable.finalize(
        matter,
        draft,
        host_name="test-host",
        model_name="test-model",
    )
    bundle = json.loads(Path(receipt["bundle"]).read_text(encoding="utf-8"))

    assert status == 4
    assert bundle["validation"]["valid"] is False
    assert "WEB_PRIMARY_AUTHORITY_MISSING" in {
        issue["code"] for issue in bundle["validation"]["issues"]
    }


def test_portable_runner_rejects_ambiguous_quotes_instead_of_guessing(
    tmp_path: Path,
) -> None:
    """Repeated text needs an explicit occurrence before a bundle can be completed."""
    source = tmp_path / "rule.txt"
    source.write_text("A controller must document risks. A controller must document risks.\n")
    charter = tmp_path / "charter.json"
    charter.write_text(json.dumps(_charter(source)), encoding="utf-8")
    matter = tmp_path / "matter"
    portable.prepare(charter, matter)
    dossier = json.loads((matter / "agent-dossier.json").read_text(encoding="utf-8"))
    source_id = dossier["sources"][0]["source_id"]
    quote = "A controller must document risks."
    draft = tmp_path / "draft.json"
    draft_payload = {
        "issues": [
            {
                "issue_id": "issue-1",
                "title": "Documentation",
                "category": "requirements",
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
                "practical_implication": "Document risks.",
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
        "brief": _brief(
            "finding-1", "claim-1", quote, finding_category="requirements"
        ),
    }
    _attach_prepared_coverage(draft_payload, dossier, quote, "claim-1")
    _use_explicit_v1_dossier(matter, dossier)
    draft.write_text(json.dumps(draft_payload), encoding="utf-8")

    receipt, status = portable.finalize(
        matter,
        draft,
        host_name="test-host",
        model_name="test-model",
    )

    assert status == 4
    assert receipt["status"] == "review-required"
    assert receipt["valid"] is False
    assert receipt["blocking_review_count"] == 1
    bundle = json.loads(Path(receipt["bundle"]).read_text(encoding="utf-8"))
    assert bundle["review_items"][0]["code"] == "PROPOSED_QUOTE_AMBIGUOUS"
    assert bundle["citations"] == []


def test_portable_runner_rejects_symlinked_managed_paths(tmp_path: Path) -> None:
    """Portable writes must not escape the selected matter through a symlink."""
    source = tmp_path / "rule.txt"
    source.write_text("Synthetic rule.\n", encoding="utf-8")
    charter = tmp_path / "charter.json"
    charter.write_text(json.dumps(_charter(source)), encoding="utf-8")
    matter = tmp_path / "matter"
    matter.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    try:
        os.symlink(outside, matter / "inputs", target_is_directory=True)
    except (NotImplementedError, OSError):
        pytest.skip("directory symlinks are unavailable")

    with pytest.raises(portable.PortableInputError, match="managed matter path"):
        portable.prepare(charter, matter)

    assert list(outside.iterdir()) == []
