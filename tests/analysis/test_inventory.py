import importlib.util
from itertools import pairwise
from pathlib import Path

from regulatory_harvest.analysis import (
    PROVISION_LEADS_VERSION,
    build_evidence_inventory,
)

ROOT = Path(__file__).parents[2]
SPEC = importlib.util.spec_from_file_location(
    "regulatory_harvest_portable_inventory",
    ROOT / "scripts" / "harvest_portable.py",
)
assert SPEC is not None and SPEC.loader is not None
portable = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(portable)


def _source(text: str, *, status: str = "succeeded") -> dict[str, object]:
    return {
        "source_id": "src_rule",
        "display_name": "Synthetic Comprehensive Rule",
        "fetch_status": status,
        "normalized_text": text,
    }


def test_inventory_finds_material_topic_families_with_exact_source_spans() -> None:
    text = """Article 1 - Status
This Rule takes effect on January 1, 2027.

Article 2 - Definitions and Scope
\"Covered operator\" means a person offering the service.
This Rule applies to each covered operator.

Article 3 - Duties
A covered operator must maintain a written register.

Article 4 - Exceptions
This Article does not apply when the emergency exception is satisfied.

Article 5 - Deadlines
The operator must respond within 30 days after receiving a request.

Article 6 - Enforcement
The Director may investigate a violation and bring an administrative action.

Article 7 - Penalties and Appeals
A violation is subject to a civil penalty of $10,000. A person may appeal the order within 20 days.

Article 8 - Implementation
The agency shall issue implementing regulations.
Covered operators must establish a compliance program.
"""

    inventory = build_evidence_inventory([_source(text)])

    assert inventory["inventory_version"] == PROVISION_LEADS_VERSION
    assert inventory["notice"] == "Heuristic research leads, not legal conclusions."
    topics = {lead["topic"] for lead in inventory["leads"]}
    assert {
        "status",
        "scope_actors",
        "definitions",
        "duties",
        "exceptions",
        "deadlines",
        "enforcement",
        "remedies_penalties",
        "appeals",
        "implementation",
    } <= topics
    for lead in inventory["leads"]:
        assert lead["source_id"] == "src_rule"
        assert lead["excerpt"] == text[lead["start_char"] : lead["end_char"]]
        assert lead["lead_id"].startswith("lead_")
        assert lead["signals"] == sorted(set(lead["signals"]))
    penalty_lead = next(
        lead for lead in inventory["leads"] if lead["topic"] == "remedies_penalties"
    )
    assert penalty_lead["issue_category"] == "enforcement"
    assert penalty_lead["heading"] == "Article 7 - Penalties and Appeals"
    assert "civil penalty" in penalty_lead["excerpt"]


def test_inventory_is_stable_and_excludes_failed_sources() -> None:
    text = "Section 4 - Duties\nA controller must document material risks."
    sources = [
        _source(text),
        {
            **_source("A violation incurs a fine.", status="failed"),
            "source_id": "src_failed",
        },
    ]

    first = build_evidence_inventory(sources)
    second = build_evidence_inventory(sources)

    assert first == second
    assert first["source_count"] == 1
    assert {lead["source_id"] for lead in first["leads"]} == {"src_rule"}
    assert first["topic_counts"]["duties"] >= 1


def test_inventory_keeps_distinct_duties_in_one_provision_independently_reviewable() -> None:
    text = (
        "Section 4 - Duties\n"
        "A controller must maintain a written register. "
        "The controller must notify affected persons. "
        "The controller must preserve supporting records."
    )

    inventory = build_evidence_inventory([_source(text)])
    duties = [lead for lead in inventory["leads"] if lead["topic"] == "duties"]

    assert len(duties) == 3
    assert [lead["start_char"] for lead in duties] == sorted(
        lead["start_char"] for lead in duties
    )
    assert all(
        first["end_char"] <= second["start_char"]
        for first, second in pairwise(duties)
    )
    assert portable._build_evidence_inventory([_source(text)]) == inventory


def test_full_and_portable_inventory_contracts_are_identical() -> None:
    text = (
        "Article 10 - Enforcement\n"
        "The Commission may impose a civil penalty for each violation.\n\n"
        "Article 11 - Review\nA respondent may appeal within 30 days."
    )
    sources = [_source(text)]

    assert portable._build_evidence_inventory(sources) == build_evidence_inventory(sources)


def test_inventory_keeps_broad_leads_but_caps_blocking_review_work() -> None:
    text = "\n\n".join(
        (
            f"Section {index} - Duty and Penalty\n"
            f"A covered operator must keep record {index}. "
            f"A violation is subject to a civil penalty of ${index},000."
        )
        for index in range(1, 21)
    )

    inventory = build_evidence_inventory([_source(text)])

    assert inventory["lead_count"] == 60
    assert inventory["priority_lead_count"] == 9
    assert inventory["priority_topic_counts"] == {
        "duties": 3,
        "remedies_penalties": 3,
        "scope_actors": 3,
    }
    assert all(isinstance(lead["review_required"], bool) for lead in inventory["leads"])
    assert sum(lead["review_required"] for lead in inventory["leads"]) == 9
    assert portable._build_evidence_inventory([_source(text)]) == inventory
