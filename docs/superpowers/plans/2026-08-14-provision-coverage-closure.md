# Strict Provision Coverage Closure Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make every authoritative source unit and every detected provision lead a blocking, source-derived coverage target while preserving the current attorney-facing report.

**Architecture:** `prepare` will add a language-agnostic source-unit inventory beside the existing heuristic lead inventory. The host-authored draft will persist a typed proposition coverage ledger, and finalization will reconcile source targets to exact source-supported claims, bounded gaps, and visible brief locations. The full and dependency-free portable runtimes will share the same versioned contract and canonical result bytes.

**Tech Stack:** Python 3.11+, Pydantic 2, standard-library `re`/`hashlib`/`json`, pytest, Ruff, mypy, deterministic JSON serialization, the existing COMBINE and skill packaging tools.

## Global Constraints

- New prepared matters use exactly `coverage_contract_version: "proposition-coverage-v1"`.
- Source-unit inventories use exactly `inventory_version: "source-units-v1"`.
- Every non-whitespace character of each successful, non-commentary, non-unusable source belongs to exactly one nonoverlapping required source unit.
- Every required source unit and every emitted provision lead must be dispositioned; the existing priority cap may order work but cannot waive the new gate.
- Deterministic code validates identities, exact source overlap, gap linkage, and brief visibility; it does not decide substantive legal meaning or materiality.
- The visible `regulatory-walk-v1` report structure and the separation between Key Requirements and Implementation Workplan do not change.
- Existing matters without the new contract retain legacy lead-recall behavior; existing completed artifacts are not rewritten.
- The full and portable runtimes must emit identical inventory objects, coverage outcomes, diagnostics, receipt fields, hashes, and canonical bytes.
- The public repository may contain only generic logic, synthetic fixtures, and public-safe documentation. No private sources, reports, mappings, scores, evaluator responses, local absolute paths, or answer keys may be added.
- No storage backend, MCP server, n8n workflow, model API dependency, publication, push, pull request, or release is part of implementation.
- Keep this exact disclaimer: `Results are AI Generated and may contain errors. Output must be validated by an attorney before the attorney delivers legal advice.`

---

## File structure

### New focused modules

- `src/regulatory_harvest/analysis/source_units.py` — deterministic, language-agnostic source partitioning and inventory construction.
- `src/regulatory_harvest/analysis/proposition_coverage.py` — proposition-ledger reconciliation and composite coverage-review construction.
- `tests/analysis/test_source_units.py` — partition, eligibility, stability, and multilingual source-unit tests.
- `tests/analysis/test_drafts.py` — strict proposition coverage schema and cardinality tests.
- `tests/analysis/test_proposition_coverage.py` — target closure, evidence overlap, gap, and brief-visibility tests.

### Existing files changed by responsibility

- `src/regulatory_harvest/analysis/drafts.py` and `src/regulatory_harvest/models/enums.py` — typed draft contract only.
- `src/regulatory_harvest/analysis/__init__.py` and `src/regulatory_harvest/models/__init__.py` — public exports only.
- `src/regulatory_harvest/analysis/coverage.py` — retain legacy lead recall; do not add source segmentation here.
- `scripts/harvest_skill.py` — full-runtime prepare/finalize orchestration and receipt fields.
- `scripts/harvest_portable.py` — dependency-free mirrors of the source-unit, draft, reconciliation, and orchestration contracts.
- `assets/analysis-draft.template.json`, `SKILL.md`, `references/draft-schema.md`, `references/research-protocol.md`, `src/regulatory_harvest/analysis/prompts/build-v1.md`, and `README.md` — host authoring and automatic repair instructions.
- `scripts/skill-package-files.txt` — allowlist the two new runtime modules.
- `tests/scripts/test_harvest_skill.py`, `tests/scripts/test_harvest_portable.py`, `tests/skill/test_skill_package.py`, and `tests/scripts/test_build_skill.py` — CLI, parity, clean-install, and package regression coverage.

---

### Task 1: Deterministic source-unit inventory

**Files:**
- Create: `src/regulatory_harvest/analysis/source_units.py`
- Create: `tests/analysis/test_source_units.py`
- Modify: `src/regulatory_harvest/analysis/__init__.py`

**Interfaces:**
- Consumes: source dictionaries produced by `SourceRecord.model_dump(mode="json")`.
- Produces: `SOURCE_UNIT_INVENTORY_VERSION = "source-units-v1"`.
- Produces: `build_source_unit_inventory(sources: Sequence[Mapping[str, object]]) -> dict[str, Any]`.
- Produces inventory units with `unit_id`, `source_id`, `start_char`, `end_char`, `heading`, `locator`, `excerpt`, and `coverage_required`.

- [ ] **Step 1: Write the failing partition and eligibility tests**

```python
from regulatory_harvest.analysis import (
    SOURCE_UNIT_INVENTORY_VERSION,
    build_source_unit_inventory,
)


def _source(
    text: str,
    *,
    source_id: str = "src_rule",
    source_role: str = "official_primary",
    source_quality: str = "primary",
) -> dict[str, object]:
    return {
        "source_id": source_id,
        "fetch_status": "succeeded",
        "source_role": source_role,
        "source_quality": source_quality,
        "normalized_text": text,
    }


def _assert_exact_partition(text: str, units: list[dict[str, object]]) -> None:
    claimed = [False] * len(text)
    for unit in units:
        start = unit["start_char"]
        end = unit["end_char"]
        assert isinstance(start, int) and isinstance(end, int)
        assert unit["excerpt"] == text[start:end]
        for index in range(start, end):
            if not text[index].isspace():
                assert claimed[index] is False
                claimed[index] = True
    assert all(character.isspace() or claimed[index] for index, character in enumerate(text))


def test_source_units_partition_every_nonblank_character_once() -> None:
    text = "Artículo 1\nLa autoridad ejercerá control.\n\n(1) La entidad conservará registros."
    inventory = build_source_unit_inventory([_source(text)])
    assert inventory["inventory_version"] == SOURCE_UNIT_INVENTORY_VERSION
    _assert_exact_partition(text, inventory["units"])
    assert all(unit["coverage_required"] is True for unit in inventory["units"])


def test_source_units_do_not_depend_on_english_legal_keywords() -> None:
    text = "第十二条\n事業者は記録を保存する。監督機関は命令を発する。"
    inventory = build_source_unit_inventory([_source(text)])
    assert inventory["required_unit_count"] >= 2
    _assert_exact_partition(text, inventory["units"])


def test_commentary_and_unusable_sources_emit_no_required_units() -> None:
    commentary = {**_source("A summary."), "source_role": "commentary_analysis"}
    unusable = {**_source("Unreadable."), "source_id": "src_bad", "source_quality": "unusable"}
    inventory = build_source_unit_inventory([commentary, unusable])
    assert inventory["required_unit_count"] == 0
    assert inventory["units"] == []
```

- [ ] **Step 2: Run the new tests and record RED**

Run: `.venv/bin/pytest tests/analysis/test_source_units.py -q`

Expected: collection fails because `SOURCE_UNIT_INVENTORY_VERSION` and `build_source_unit_inventory` do not exist.

- [ ] **Step 3: Implement the exact partition contract**

Create `source_units.py` with these constants and entrypoint:

```python
SOURCE_UNIT_INVENTORY_VERSION = "source-units-v1"
MAX_SOURCE_UNIT_CHARS = 1_600


def build_source_unit_inventory(
    sources: Sequence[Mapping[str, object]],
) -> dict[str, Any]:
    units: list[dict[str, Any]] = []
    eligible_source_count = 0
    for source in sources:
        if not _source_is_eligible(source):
            continue
        source_id = source.get("source_id")
        text = source.get("normalized_text")
        if not isinstance(source_id, str) or not source_id or not isinstance(text, str):
            continue
        eligible_source_count += 1
        for start, end, heading, locator in _partition_source(text):
            excerpt = text[start:end]
            units.append(
                {
                    "unit_id": _stable_unit_id(source_id, start, end, excerpt),
                    "source_id": source_id,
                    "start_char": start,
                    "end_char": end,
                    "heading": heading,
                    "locator": locator,
                    "excerpt": excerpt,
                    "coverage_required": True,
                }
            )
    units.sort(key=lambda unit: (unit["source_id"], unit["start_char"], unit["unit_id"]))
    return {
        "inventory_version": SOURCE_UNIT_INVENTORY_VERSION,
        "eligible_source_count": eligible_source_count,
        "unit_count": len(units),
        "required_unit_count": len(units),
        "units": units,
    }
```

Implement `_source_is_eligible` so it requires `fetch_status == "succeeded"`, rejects `source_role == "commentary_analysis"`, rejects `source_quality == "unusable"`, and otherwise fails toward coverage. Implement `_partition_source` in this order:

1. split nonblank paragraph blocks without dropping intervening non-whitespace;
2. split blocks at line-start numeric, alphabetic, Roman-numeral, or Unicode legal-clause enumerators;
3. split every resulting body at sentence or semicolon-level clause terminators
   `.`, `?`, `!`, `;`, `。`, `！`, `？`, `؛`, and `।`, preserving the terminator
   and all intervening non-whitespace;
4. split remaining units longer than 1,600 characters at the last punctuation or whitespace boundary at or before the limit, falling forward only when no earlier boundary exists;
5. coalesce a standalone heading with the immediately following body only when doing so remains within 1,600 characters; and
6. assert internally that spans are ordered, nonoverlapping, exact, and cover every non-whitespace character.

Use `sha256` over `source_id`, `start`, `end`, and exact excerpt for `unit_id`. Do not use topic keywords to decide whether a unit exists.

- [ ] **Step 4: Export the interface and run GREEN**

Add both names to `src/regulatory_harvest/analysis/__init__.py`, then run:

Run: `.venv/bin/pytest tests/analysis/test_source_units.py tests/analysis/test_inventory.py -q`

Expected: all tests pass, including the existing provision-lead inventory tests.

- [ ] **Step 5: Commit the independently testable inventory**

```bash
git add src/regulatory_harvest/analysis/source_units.py src/regulatory_harvest/analysis/__init__.py tests/analysis/test_source_units.py
git commit -m "feat: add deterministic source unit inventory"
```

---

### Task 2: Prepare-time coverage targets and portable parity

**Files:**
- Modify: `scripts/harvest_skill.py`
- Modify: `scripts/harvest_portable.py`
- Modify: `tests/scripts/test_harvest_skill.py`
- Modify: `tests/scripts/test_harvest_portable.py`

**Interfaces:**
- Consumes: `build_source_unit_inventory(sources: Sequence[Mapping[str, object]]) -> dict[str, Any]` from Task 1.
- Produces: dossier fields `coverage_contract_version` and `source_unit_inventory`.
- Produces: prepare receipt field `source_unit_count`.
- Produces portable mirror `_build_source_unit_inventory(sources: Sequence[Mapping[str, object]]) -> dict[str, Any]`.

- [ ] **Step 1: Add failing full/portable dossier contract tests**

Extend the existing prepare tests with these assertions:

```python
assert dossier["coverage_contract_version"] == "proposition-coverage-v1"
source_units = dossier["source_unit_inventory"]
assert source_units["inventory_version"] == "source-units-v1"
assert source_units["required_unit_count"] >= 1
assert receipt["source_unit_count"] == source_units["unit_count"]
for unit in source_units["units"]:
    source_text = dossier["sources"][0]["normalized_text"]
    assert unit["excerpt"] == source_text[unit["start_char"] : unit["end_char"]]
```

Add a parity test that runs full and portable preparation over the same synthetic multilingual source and asserts exact equality of `source_unit_inventory` and `coverage_contract_version`.

- [ ] **Step 2: Run the prepare tests and record RED**

Run: `.venv/bin/pytest tests/scripts/test_harvest_skill.py tests/scripts/test_harvest_portable.py -q -k 'prepare and (dossier or source_unit or parity)'`

Expected: failures show the dossier and receipt fields are absent and the portable builder is undefined.

- [ ] **Step 3: Add the full-runtime prepare fields**

In `scripts/harvest_skill.py`, define:

```python
COVERAGE_CONTRACT_VERSION = "proposition-coverage-v1"
```

Build `source_unit_inventory` immediately after `evidence_inventory`, persist both in `agent-dossier.json`, and add the count to the receipt:

```python
source_unit_inventory = build_source_unit_inventory(
    [source.model_dump(mode="json") for source in result.bundle.sources]
)
dossier = {
    "schema_version": "1.0",
    "coverage_contract_version": COVERAGE_CONTRACT_VERSION,
    "source_mode": charter.source_mode,
    "request": request,
    "sources": result.bundle.sources,
    "gaps": result.bundle.gaps,
    "evidence_inventory": evidence_inventory,
    "source_unit_inventory": source_unit_inventory,
}
```

Return `"source_unit_count": source_unit_inventory["unit_count"]` from `prepare`.

- [ ] **Step 4: Mirror the partitioner and prepare fields in the portable runtime**

Add dependency-free `_source_is_eligible`, `_partition_source`, `_stable_unit_id`, and `_build_source_unit_inventory` functions to `scripts/harvest_portable.py`. Copy the Task 1 constants and ordering rules exactly; do not import Pydantic or the package runtime. Add the same dossier and receipt fields in portable `prepare`.

- [ ] **Step 5: Run exact parity GREEN**

Run: `.venv/bin/pytest tests/analysis/test_source_units.py tests/scripts/test_harvest_skill.py tests/scripts/test_harvest_portable.py -q -k 'source_unit or prepare or parity'`

Expected: full and portable inventories are equal for ASCII, multilingual, long-block, commentary, unusable, and repeated-heading cases.

- [ ] **Step 6: Commit prepare-time target generation**

```bash
git add scripts/harvest_skill.py scripts/harvest_portable.py tests/scripts/test_harvest_skill.py tests/scripts/test_harvest_portable.py
git commit -m "feat: prepare strict coverage targets"
```

---

### Task 3: Typed proposition coverage draft contract

**Files:**
- Create: `tests/analysis/test_drafts.py`
- Modify: `src/regulatory_harvest/models/enums.py`
- Modify: `src/regulatory_harvest/models/__init__.py`
- Modify: `src/regulatory_harvest/analysis/drafts.py`
- Modify: `src/regulatory_harvest/analysis/__init__.py`
- Modify: `scripts/harvest_portable.py`

**Interfaces:**
- Produces enums `CoverageDisposition`, `CoverageElementStatus`, and `PropositionType`.
- Produces models `DraftCoverageElement`, `DraftCoverageElements`, and `DraftPropositionCoverage`.
- Extends `AnalysisDraft` with `coverage_contract_version: Literal["proposition-coverage-v1"] | None` and `proposition_coverage: list[DraftPropositionCoverage]`.
- Extends portable `_draft(value: object) -> dict[str, Any]` with the same normalized dictionary shape and rejection messages.

- [ ] **Step 1: Write failing schema/cardinality tests**

```python
import pytest
from pydantic import ValidationError

from regulatory_harvest.analysis import (
    AnalysisDraft,
    DraftCoverageElement,
    DraftCoverageElements,
    DraftPropositionCoverage,
)


def _elements(*, timing: str = "not_applicable") -> DraftCoverageElements:
    return DraftCoverageElements(
        subject=DraftCoverageElement(status="stated", text="covered operator"),
        operative_rule=DraftCoverageElement(status="stated", text="must keep a register"),
        object=DraftCoverageElement(status="stated", text="processing activities"),
        trigger_or_threshold=DraftCoverageElement(status="not_applicable"),
        conditions_or_exceptions=DraftCoverageElement(status="not_applicable"),
        timing=DraftCoverageElement(status=timing),
        consequence_or_remedy=DraftCoverageElement(status="not_applicable"),
        authority_or_route=DraftCoverageElement(status="not_applicable"),
    )


def test_covered_row_requires_targets_elements_claims_and_partial_gap_binding() -> None:
    row = DraftPropositionCoverage(
        coverage_id="coverage-register",
        unit_ids=["unit-one"],
        category="requirements",
        proposition_type="duty",
        disposition="covered",
        elements=_elements(timing="not_established"),
        claim_ids=["claim-register"],
        gap_codes=["REGISTER_TIMING_NOT_ESTABLISHED"],
    )
    assert row.coverage_id == "coverage-register"


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        ({"status": "stated", "text": None}, "stated"),
        ({"status": "not_applicable", "text": "invented"}, "text"),
        ({"status": "not_established", "text": "invented"}, "text"),
    ],
)
def test_coverage_element_status_controls_text(payload: dict[str, object], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        DraftCoverageElement.model_validate(payload)
```

Add separate tests proving:

- `covered` rejects missing elements, empty claim IDs, non-stated subject/rule, and gap codes without a `not_established` element;
- `gap` rejects claims, accepts matching gap IDs plus rationale, and rejects any stated element;
- `not_material` rejects elements, claims, and gaps and requires rationale;
- every row requires at least one unit or lead target;
- IDs within each row and coverage IDs within a draft are unique; and
- old drafts without the new fields remain parseable.

- [ ] **Step 2: Run model tests and record RED**

Run: `.venv/bin/pytest tests/analysis/test_drafts.py -q`

Expected: collection fails because the coverage models are not defined.

- [ ] **Step 3: Add enums and strict Pydantic models**

Add these enum values:

```python
class CoverageDisposition(StrEnum):
    COVERED = "covered"
    GAP = "gap"
    NOT_MATERIAL = "not_material"


class CoverageElementStatus(StrEnum):
    STATED = "stated"
    NOT_APPLICABLE = "not_applicable"
    NOT_ESTABLISHED = "not_established"


class PropositionType(StrEnum):
    STATUS = "status"
    DEFINITION = "definition"
    SCOPE = "scope"
    RIGHT = "right"
    DUTY = "duty"
    PROHIBITION = "prohibition"
    EXCEPTION = "exception"
    DEADLINE = "deadline"
    ENFORCEMENT_TRIGGER = "enforcement_trigger"
    ENFORCEMENT_ROUTE = "enforcement_route"
    REMEDY = "remedy"
    PENALTY = "penalty"
    APPEAL = "appeal"
    IMPLEMENTATION = "implementation"
    OTHER = "other"
```

Implement the three strict draft models in `drafts.py`. Use `model_validator(mode="after")` for disposition cardinality, `field_validator` for nonblank/unique IDs, and explicit eight-field `DraftCoverageElements`. Do not infer element text from claims and do not semantically score rationales.

Extend `AnalysisDraft` without requiring the version at parse time; finalization must be able to turn a missing or mismatched version into bounded coverage diagnostics for a newly prepared matter. Enforce only row-local validity and unique `coverage_id` values in the draft model.

- [ ] **Step 4: Mirror strict parsing in the portable runner**

Add controlled sets for the three enums. Add `_coverage_element`, `_coverage_elements`, and `_proposition_coverage_row` parsers. The portable normalized row must use exactly these keys:

```python
{
    "coverage_id": str,
    "unit_ids": list[str],
    "lead_ids": list[str],
    "category": str,
    "proposition_type": str,
    "disposition": str,
    "elements": dict[str, dict[str, str | None]] | None,
    "claim_ids": list[str],
    "gap_codes": list[str],
    "rationale": str | None,
}
```

Add optional draft keys `coverage_contract_version` and `proposition_coverage`, preserving old draft parsing when both are absent.

- [ ] **Step 5: Run full/portable schema parity GREEN**

Run: `.venv/bin/pytest tests/analysis/test_drafts.py tests/scripts/test_harvest_portable.py -q -k 'coverage or draft'`

Expected: every valid vector normalizes identically and every invalid vector fails in both runtimes.

- [ ] **Step 6: Commit the draft contract**

```bash
git add src/regulatory_harvest/models/enums.py src/regulatory_harvest/models/__init__.py src/regulatory_harvest/analysis/drafts.py src/regulatory_harvest/analysis/__init__.py scripts/harvest_portable.py tests/analysis/test_drafts.py tests/scripts/test_harvest_portable.py
git commit -m "feat: add proposition coverage draft contract"
```

---

### Task 4: Full-runtime proposition reconciliation

**Files:**
- Create: `src/regulatory_harvest/analysis/proposition_coverage.py`
- Create: `tests/analysis/test_proposition_coverage.py`
- Modify: `src/regulatory_harvest/analysis/__init__.py`

**Interfaces:**
- Consumes: `evidence_inventory`, `source_unit_inventory`, `AnalysisDraft`, and built `SourceRecord` objects.
- Produces: `COVERAGE_CONTRACT_VERSION = "proposition-coverage-v1"` as the full-runtime canonical constant.
- Produces: `evaluate_proposition_coverage(source_unit_inventory: Mapping[str, object], evidence_inventory: Mapping[str, object], draft: AnalysisDraft, sources: Sequence[SourceRecord]) -> dict[str, Any]`.
- Produces: `evaluate_coverage_closure(evidence_inventory: Mapping[str, object], source_unit_inventory: Mapping[str, object], draft: AnalysisDraft, sources: Sequence[SourceRecord]) -> dict[str, Any]`.
- Preserves: `evaluate_provision_recall(inventory: Mapping[str, object], draft: AnalysisDraft, sources: Sequence[SourceRecord]) -> dict[str, Any]` as the unchanged legacy lead-recall evaluator.

- [ ] **Step 1: Write failing target-closure tests**

Start the test file with these complete helpers:

```python
from datetime import UTC, datetime

from regulatory_harvest.analysis import (
    AnalysisDraft,
    DraftClaim,
    DraftCoverageElement,
    DraftCoverageElements,
    DraftFinding,
    DraftIssue,
    DraftPropositionCoverage,
    ProposedCitation,
    build_evidence_inventory,
    build_source_unit_inventory,
    evaluate_proposition_coverage,
)
from regulatory_harvest.models import (
    AttorneyBrief,
    BriefBlock,
    BriefSection,
    ClaimKind,
    Severity,
    SourceRecord,
)
from regulatory_harvest.storage import sha256_digest

FIRST_DUTY = "A controller must maintain a written register."
SECOND_DUTY = "The controller must notify affected persons."


def _source(text: str) -> SourceRecord:
    return SourceRecord(
        source_id="src_rule",
        origin="rule.txt",
        display_name="Synthetic Rule",
        retrieved_at=datetime(2026, 8, 14, tzinfo=UTC),
        content_hash=sha256_digest(text.encode()),
        media_type="text/plain",
        normalized_text=text,
        jurisdiction="US",
    )


def _elements() -> DraftCoverageElements:
    not_applicable = DraftCoverageElement(status="not_applicable")
    return DraftCoverageElements(
        subject=DraftCoverageElement(status="stated", text="controller"),
        operative_rule=DraftCoverageElement(status="stated", text="must act"),
        object=DraftCoverageElement(status="stated", text="the regulated record or notice"),
        trigger_or_threshold=not_applicable,
        conditions_or_exceptions=not_applicable,
        timing=not_applicable,
        consequence_or_remedy=not_applicable,
        authority_or_route=not_applicable,
    )


def _target_ids(
    inventory: dict[str, object], quote: str, *, key: str, id_key: str
) -> list[str]:
    items = inventory[key]
    assert isinstance(items, list)
    return [str(item[id_key]) for item in items if quote in str(item["excerpt"])]


def _draft(
    source: SourceRecord,
    *,
    claims: list[DraftClaim],
    rows: list[DraftPropositionCoverage],
    visible_claim_ids: list[str],
) -> AnalysisDraft:
    return AnalysisDraft(
        coverage_contract_version="proposition-coverage-v1",
        proposition_coverage=rows,
        issues=[
            DraftIssue(
                issue_id="issue-requirements",
                title="Requirements",
                category="requirements",
                jurisdictions=["US"],
            )
        ],
        findings=[
            DraftFinding(
                finding_id="finding-requirements",
                issue_id="issue-requirements",
                title="Requirements",
                jurisdiction="US",
                authority="Synthetic Rule",
                severity=Severity.INFO,
                practical_implication="Assess the supported requirements.",
                claims=claims,
            )
        ],
        brief=AttorneyBrief(
            structure_profile="regulatory-walk-v1",
            executive_summary=[
                BriefBlock(
                    kind="paragraph",
                    purpose="legal_analysis",
                    text="The rule imposes the supported requirements.",
                    claim_ids=visible_claim_ids,
                )
            ],
            sections=[
                BriefSection(
                    section_id="requirements",
                    title="Requirements Walk",
                    role="other",
                    blocks=[
                        BriefBlock(
                            kind="paragraph",
                            purpose="legal_analysis",
                            text="The controller must comply with the stated duties.",
                            claim_ids=visible_claim_ids,
                        )
                    ],
                )
            ],
        ),
    )
```

Then add tests with these exact outcomes:

```python
def test_every_required_unit_and_every_lead_must_be_dispositioned() -> None:
    source = _source(f"{FIRST_DUTY}\n\n{SECOND_DUTY}")
    source_payload = source.model_dump(mode="json")
    units = build_source_unit_inventory([source_payload])
    leads = build_evidence_inventory([source_payload])
    first_unit_ids = _target_ids(units, FIRST_DUTY, key="units", id_key="unit_id")
    first_lead_ids = _target_ids(leads, FIRST_DUTY, key="leads", id_key="lead_id")
    claim = DraftClaim(
        claim_id="claim-first",
        text=FIRST_DUTY,
        kind=ClaimKind.SOURCE_SUPPORTED,
        proposed_citations=[ProposedCitation(source_id="src_rule", quote=FIRST_DUTY)],
    )
    row = DraftPropositionCoverage(
        coverage_id="coverage-first",
        unit_ids=first_unit_ids,
        lead_ids=first_lead_ids,
        category="requirements",
        proposition_type="duty",
        disposition="covered",
        elements=_elements(),
        claim_ids=["claim-first"],
    )
    review = evaluate_proposition_coverage(
        units,
        leads,
        _draft(source, claims=[claim], rows=[row], visible_claim_ids=["claim-first"]),
        [source],
    )
    assert review["valid"] is False
    assert {issue["code"] for issue in review["issues"]} == {
        "COVERAGE_TARGET_UNRESOLVED"
    }


def test_neighboring_exact_citation_cannot_cover_another_target() -> None:
    source = _source(f"{FIRST_DUTY}\n\n{SECOND_DUTY}")
    source_payload = source.model_dump(mode="json")
    units = build_source_unit_inventory([source_payload])
    leads = build_evidence_inventory([source_payload])
    claim = DraftClaim(
        claim_id="claim-first",
        text=FIRST_DUTY,
        kind=ClaimKind.SOURCE_SUPPORTED,
        proposed_citations=[ProposedCitation(source_id="src_rule", quote=FIRST_DUTY)],
    )
    row = DraftPropositionCoverage(
        coverage_id="coverage-both",
        unit_ids=[str(item["unit_id"]) for item in units["units"]],
        lead_ids=[str(item["lead_id"]) for item in leads["leads"]],
        category="requirements",
        proposition_type="duty",
        disposition="covered",
        elements=_elements(),
        claim_ids=["claim-first"],
    )
    review = evaluate_proposition_coverage(
        units,
        leads,
        _draft(source, claims=[claim], rows=[row], visible_claim_ids=["claim-first"]),
        [source],
    )
    assert review["valid"] is False
    assert "COVERAGE_EVIDENCE_OUTSIDE_TARGET" in {
        issue["code"] for issue in review["issues"]
    }


def test_covered_claim_must_be_visible_in_attorney_brief() -> None:
    source = _source(FIRST_DUTY)
    source_payload = source.model_dump(mode="json")
    units = build_source_unit_inventory([source_payload])
    leads = build_evidence_inventory([source_payload])
    claim = DraftClaim(
        claim_id="claim-first",
        text=FIRST_DUTY,
        kind=ClaimKind.SOURCE_SUPPORTED,
        proposed_citations=[ProposedCitation(source_id="src_rule", quote=FIRST_DUTY)],
    )
    row = DraftPropositionCoverage(
        coverage_id="coverage-first",
        unit_ids=[str(item["unit_id"]) for item in units["units"]],
        lead_ids=[str(item["lead_id"]) for item in leads["leads"]],
        category="requirements",
        proposition_type="duty",
        disposition="covered",
        elements=_elements(),
        claim_ids=["claim-first"],
    )
    review = evaluate_proposition_coverage(
        units,
        leads,
        _draft(source, claims=[claim], rows=[row], visible_claim_ids=[]),
        [source],
    )
    assert review["valid"] is False
    assert "COVERAGE_CLAIM_NOT_VISIBLE" in {
        issue["code"] for issue in review["issues"]
    }
```

Add positive tests for a valid multi-unit cross-reference, a `covered` row with a matching partial gap, a pure `gap` row, and a `not_material` row. Add negative tests for unknown targets, analysis claims, category-mismatched leads, source-mismatched gaps, duplicate mapping IDs, and `not_established` elements without matching gaps.

- [ ] **Step 2: Run reconciliation tests and record RED**

Run: `.venv/bin/pytest tests/analysis/test_proposition_coverage.py -q`

Expected: collection fails because both evaluator functions are missing.

- [ ] **Step 3: Implement brief claim-location extraction**

Add a private helper that walks executive-summary blocks, section blocks,
subsection blocks, list items, and table rows. It must return sorted deterministic
paths for each referenced claim:

```python
def _brief_claim_locations(brief: AttorneyBrief | None) -> dict[str, list[str]]:
    locations: dict[str, list[str]] = defaultdict(list)
    if brief is None:
        return {}
    # Paragraph claim_ids live on the block; list claim_ids live on items;
    # table claim_ids live on rows. Record only purpose == legal_analysis.
    return {claim_id: sorted(paths) for claim_id, paths in sorted(locations.items())}
```

Use canonical JSON-style paths such as `brief.executive_summary[0]`,
`brief.sections[1].blocks[0].items[2]`, and
`brief.sections[2].subsections[0].blocks[1].rows[0]`.

- [ ] **Step 4: Implement target and row reconciliation**

In `evaluate_proposition_coverage`:

1. validate `draft.coverage_contract_version` against
   `COVERAGE_CONTRACT_VERSION`, the source-unit inventory version, and exact unit
   slices; emit `COVERAGE_ROW_INVALID` on a missing or mismatched draft contract;
2. index all units and all leads by ID;
3. build findings and exact citations with existing `build_analysis`;
4. index source-supported claims, their exact citation spans, authored gaps, and
   visible legal-analysis locations;
5. validate every row and emit one bounded issue per distinct defect;
6. require overlap with every referenced unit and lead; and
7. emit deterministic unit, lead, and row results plus sorted issues.

Use this issue shape:

```python
def _coverage_issue(code: str, message: str, *related_ids: str) -> dict[str, Any]:
    return {
        "code": code,
        "message": message,
        "related_ids": sorted(set(related_ids)),
    }
```

Use the nine codes from the design exactly. The result shape is:

```python
{
    "schema_version": "1.0",
    "valid": bool,
    "target_counts": {"units": int, "leads": int},
    "disposition_counts": dict[str, int],
    "units": list[dict[str, Any]],
    "leads": list[dict[str, Any]],
    "rows": list[dict[str, Any]],
    "issues": list[dict[str, Any]],
}
```

Each row result includes computed `brief_locations`; do not trust a host-authored report location.

- [ ] **Step 5: Compose legacy recall and strict coverage without changing legacy output**

Implement:

```python
def evaluate_coverage_closure(
    evidence_inventory: Mapping[str, object],
    source_unit_inventory: Mapping[str, object],
    draft: AnalysisDraft,
    sources: Sequence[SourceRecord],
) -> dict[str, Any]:
    lead_recall = evaluate_provision_recall(evidence_inventory, draft, sources)
    proposition = evaluate_proposition_coverage(
        source_unit_inventory, evidence_inventory, draft, sources
    )
    payload: dict[str, Any] = {
        "schema_version": "2.0",
        "coverage_contract_version": "proposition-coverage-v1",
        "valid": lead_recall["valid"] is True and proposition["valid"] is True,
        "lead_recall": lead_recall,
        "proposition_coverage": proposition,
    }
    payload["coverage_review_hash"] = sha256_digest(canonical_json_bytes(payload))
    return payload
```

Do not mutate the nested legacy review or include the composite hash while hashing itself.

- [ ] **Step 6: Run the full evaluator GREEN**

Run: `.venv/bin/pytest tests/analysis/test_proposition_coverage.py tests/analysis/test_coverage.py tests/analysis/test_build.py -q`

Expected: all new reconciliation tests pass and every legacy lead-recall test remains unchanged.

- [ ] **Step 7: Commit the full-runtime evaluator**

```bash
git add src/regulatory_harvest/analysis/proposition_coverage.py src/regulatory_harvest/analysis/__init__.py tests/analysis/test_proposition_coverage.py
git commit -m "feat: reconcile strict proposition coverage"
```

---

### Task 5: Portable reconciliation and finalization gate

**Files:**
- Modify: `scripts/harvest_skill.py`
- Modify: `scripts/harvest_portable.py`
- Modify: `tests/scripts/test_harvest_skill.py`
- Modify: `tests/scripts/test_harvest_portable.py`
- Modify: `tests/analysis/test_proposition_coverage.py`

**Interfaces:**
- Consumes: `evaluate_coverage_closure(evidence_inventory, source_unit_inventory, draft, sources)` from Task 4.
- Produces portable mirrors `_evaluate_proposition_coverage(source_unit_inventory: dict[str, Any], evidence_inventory: dict[str, Any], draft: dict[str, Any], sources: list[dict[str, Any]]) -> dict[str, Any]` and `_evaluate_coverage_closure(evidence_inventory: dict[str, Any], source_unit_inventory: dict[str, Any], draft: dict[str, Any], sources: list[dict[str, Any]]) -> dict[str, Any]`.
- Produces receipt field `proposition_coverage_valid: bool | None`.
- Redefines `provision_recall_valid` for new matters as the composite closure result while preserving legacy behavior for old matters.

- [ ] **Step 1: Add failing full CLI completion and repair tests**

Extend the full CLI tests with a source containing two nonpriority duties and make the draft cover only one. Assert:

```python
assert result.returncode == 4
receipt = json.loads(result.stdout)
review = json.loads(Path(receipt["coverage_review"]).read_text(encoding="utf-8"))
assert receipt["proposition_coverage_valid"] is False
assert receipt["provision_recall_valid"] is False
assert receipt["status"] == "review-required"
assert review["schema_version"] == "2.0"
assert review["proposition_coverage"]["valid"] is False
assert "COVERAGE_TARGET_UNRESOLVED" in {
    issue["code"] for issue in review["proposition_coverage"]["issues"]
}
```

Then submit a repaired draft that maps both targets to exact visible claims and assert status `0`, both coverage booleans true, and the same matter can be finalized normally after the failed attempt.

Add a legacy-matter test that removes both new dossier fields and submits an old draft. It must retain schema `1.0` lead review behavior and return `proposition_coverage_valid: null`.

- [ ] **Step 2: Add failing portable and canonical parity tests**

Run identical new-contract dossiers and drafts through full and portable finalization. Assert exact equality for:

- `coverage-review.json` bytes;
- `coverage_review_hash`;
- `proposition_coverage_valid`;
- `provision_recall_valid`;
- `coverage_issue_count`; and
- exit status.

Add a malformed/missing draft contract case and require both runtimes to return review-required with `COVERAGE_ROW_INVALID`, not silently use legacy behavior.

- [ ] **Step 3: Run the CLI/parity tests and record RED**

Run: `.venv/bin/pytest tests/scripts/test_harvest_skill.py tests/scripts/test_harvest_portable.py tests/analysis/test_proposition_coverage.py -q -k 'coverage or finalize or parity'`

Expected: new matters still use the legacy review artifact, portable reconciliation is absent, and the new receipt field is absent.

- [ ] **Step 4: Gate full finalization by the dossier contract**

In `scripts/harvest_skill.py`:

```python
contract_version = dossier.get("coverage_contract_version")
if contract_version == COVERAGE_CONTRACT_VERSION:
    raw_units = dossier.get("source_unit_inventory")
    if not isinstance(raw_units, dict):
        raise SkillInputError("INVALID_DOSSIER", "The prepared source-unit inventory is invalid.")
    coverage_review = evaluate_coverage_closure(
        raw_inventory, raw_units, draft, prepared_sources
    )
    proposition_coverage_valid: bool | None = (
        coverage_review["proposition_coverage"]["valid"] is True
    )
    provision_recall_valid = coverage_review["valid"] is True
    coverage_issue_count = len(coverage_review["lead_recall"]["issues"]) + len(
        coverage_review["proposition_coverage"]["issues"]
    )
else:
    coverage_review = evaluate_provision_recall(raw_inventory, draft, prepared_sources)
    proposition_coverage_valid = None
    provision_recall_valid = coverage_review["valid"] is True
    coverage_issue_count = len(coverage_review["issues"])
```

For a dossier declaring the new contract, a missing or mismatched draft version must be represented in proposition diagnostics and must not enter the legacy branch. Write the review before running the existing report pipeline so repair diagnostics survive. Keep `completed = evidence_precision_valid and provision_recall_valid`.

Import `COVERAGE_CONTRACT_VERSION` from
`regulatory_harvest.analysis.proposition_coverage` and remove the temporary local
full-runtime constant introduced in Task 2. The portable runtime retains its
same-valued dependency-free constant.

- [ ] **Step 5: Mirror evaluation and finalization in the portable runtime**

Copy Task 4's brief-location traversal, exact span indexing, issue ordering, result shapes, and composite hash into dependency-free portable helpers. Use only dictionaries and standard-library functions. Do not import package modules or alter report rendering.

Update portable finalization with the exact full-runtime branch and receipt fields. Compare canonical bytes, not only parsed objects.

- [ ] **Step 6: Update existing synthetic draft helpers for new prepared matters**

Add this test-only helper and change the existing `_draft` helper to receive the
dossier rather than only `source_id`:

```python
def _coverage_elements() -> dict[str, object]:
    return {
        "subject": {"status": "stated", "text": "controller"},
        "operative_rule": {"status": "stated", "text": "must comply"},
        "object": {"status": "stated", "text": "the stated requirement"},
        "trigger_or_threshold": {"status": "not_applicable", "text": None},
        "conditions_or_exceptions": {"status": "not_applicable", "text": None},
        "timing": {"status": "not_applicable", "text": None},
        "consequence_or_remedy": {"status": "not_applicable", "text": None},
        "authority_or_route": {"status": "not_applicable", "text": None},
    }


def _attach_covered_requirement(
    payload: dict[str, object],
    dossier: dict[str, Any],
    quote: str,
    claim_id: str,
) -> dict[str, object]:
    unit_ids = [
        str(unit["unit_id"])
        for unit in dossier["source_unit_inventory"]["units"]
        if quote in str(unit["excerpt"])
    ]
    lead_ids = [
        str(lead["lead_id"])
        for lead in dossier["evidence_inventory"]["leads"]
        if quote in str(lead["excerpt"])
    ]
    payload["coverage_contract_version"] = "proposition-coverage-v1"
    payload["proposition_coverage"] = [
        {
            "coverage_id": "coverage-requirement",
            "unit_ids": unit_ids,
            "lead_ids": lead_ids,
            "category": "requirements",
            "proposition_type": "duty",
            "disposition": "covered",
            "elements": _coverage_elements(),
            "claim_ids": [claim_id],
            "gap_codes": [],
            "rationale": None,
        }
    ]
    return payload


```

Make exactly three edits to the existing `_draft` helper: change its signature
to `def _draft(dossier: dict[str, Any], quote: str) -> dict[str, object]`, assign
`source_id = str(dossier["sources"][0]["source_id"])` before the current payload
literal, and replace its current final return with
`return _attach_covered_requirement(payload, dossier, quote, "claim-1")`. Leave
the existing payload literal unchanged.

Keep explicit incomplete-coverage vectors in the tests that are intended to fail. Do not make a global fixture auto-cover arbitrary targets, because that would hide the omissions these tests protect against.

- [ ] **Step 7: Run full/portable finalization GREEN**

Run: `.venv/bin/pytest tests/analysis/test_proposition_coverage.py tests/analysis/test_coverage.py tests/scripts/test_harvest_skill.py tests/scripts/test_harvest_portable.py -q`

Expected: all tests pass; new-contract artifacts are byte-identical; legacy matters still use their prior behavior.

- [ ] **Step 8: Commit the delivery gate**

```bash
git add scripts/harvest_skill.py scripts/harvest_portable.py tests/scripts/test_harvest_skill.py tests/scripts/test_harvest_portable.py tests/analysis/test_proposition_coverage.py
git commit -m "feat: enforce proposition coverage at finalization"
```

---

### Task 6: Skill authoring contract, package, and automatic repair guidance

**Files:**
- Modify: `assets/analysis-draft.template.json`
- Modify: `SKILL.md`
- Modify: `references/draft-schema.md`
- Modify: `references/research-protocol.md`
- Modify: `src/regulatory_harvest/analysis/prompts/build-v1.md`
- Modify: `README.md`
- Modify: `scripts/skill-package-files.txt`
- Modify: `tests/skill/test_skill_package.py`
- Modify: `tests/scripts/test_build_skill.py`

**Interfaces:**
- Consumes: all contract names and result fields from Tasks 1–5.
- Produces: one self-contained Codex/Claude skill archive containing both new runtime modules.
- Preserves: the attorney's natural-language workflow and current report structure.

- [ ] **Step 1: Add failing package and instruction contract tests**

Add assertions that the packaged skill:

```python
combined_skill_instructions = "\n".join(
    (ROOT / path).read_text(encoding="utf-8")
    for path in (
        "SKILL.md",
        "references/draft-schema.md",
        "references/research-protocol.md",
        "src/regulatory_harvest/analysis/prompts/build-v1.md",
    )
)
required_phrases = (
    "proposition-coverage-v1",
    "source_unit_inventory",
    "proposition_coverage",
    "every required source unit",
    "every provision lead",
    "COVERAGE_TARGET_UNRESOLVED",
    "proposition_coverage_valid",
)
for phrase in required_phrases:
    assert phrase in combined_skill_instructions
```

Assert the package manifest contains:

```python
manifest_entries = (ROOT / "scripts/skill-package-files.txt").read_text(
    encoding="utf-8"
).splitlines()
assert "src/regulatory_harvest/analysis/source_units.py" in manifest_entries
assert "src/regulatory_harvest/analysis/proposition_coverage.py" in manifest_entries
```

Extend clean-install generation tests so the template parses in both full and portable runtimes and reaches review-required, rather than invalid input, when targets are intentionally incomplete.

- [ ] **Step 2: Run package tests and record RED**

Run: `.venv/bin/pytest tests/skill/test_skill_package.py tests/scripts/test_build_skill.py -q -k 'coverage or manifest or template or generation'`

Expected: required instructions, template members, and manifest entries are missing.

- [ ] **Step 3: Update the strict template and schema reference**

Add `coverage_contract_version` and at least three synthetic rows to the template:

- one fully covered duty;
- one covered proposition with a `not_established` timing element and matching gap; and
- one `not_material` source-navigation unit.

In `references/draft-schema.md`, document every field, enum, cardinality rule, target-overlap rule, gap rule, and visible-brief rule from the approved design. Replace the old claim that the proposition table is merely internal. Retain a separate legacy subsection explaining `lead_reviews` only for pre-contract matters.

- [ ] **Step 4: Update host workflow and automatic repair instructions**

In `SKILL.md`, `research-protocol.md`, and `build-v1.md`, require this sequence:

1. read every successful source in full;
2. review every source unit and provision lead;
3. author the proposition ledger before report prose;
4. bind covered rows to exact source-supported claims;
5. bind those claims to visible legal-analysis units;
6. run finalize;
7. if exit status is review-required, read `coverage-review.json`, repair every finite coverage diagnostic, and rerun; and
8. deliver only after both coverage booleans and evidence precision are true.

State explicitly that the ledger is internal, the attorney does not operate it, and it must not be rendered as a database view in the report.

- [ ] **Step 5: Update public overview and package allowlist**

Add one concise README paragraph explaining that the skill now performs an internal fail-closed provision sweep with no added user setup. Add the two new modules to `scripts/skill-package-files.txt` in lexical order. Do not add release metadata or claim publication.

- [ ] **Step 6: Run package and instruction GREEN**

Run: `.venv/bin/pytest tests/skill/test_skill_package.py tests/scripts/test_build_skill.py tests/scripts/test_harvest_skill.py tests/scripts/test_harvest_portable.py -q`

Expected: templates validate, clean installs work in both runtimes, the archive allowlist is complete, and the existing report-shape instructions remain present.

- [ ] **Step 7: Commit the distributable authoring contract**

```bash
git add assets/analysis-draft.template.json SKILL.md references/draft-schema.md references/research-protocol.md src/regulatory_harvest/analysis/prompts/build-v1.md README.md scripts/skill-package-files.txt tests/skill/test_skill_package.py tests/scripts/test_build_skill.py
git commit -m "docs: require strict proposition coverage"
```

---

### Task 7: Clean verification, local installation, and locked-suite acceptance

**Files:**
- Verify only: all files changed in Tasks 1–6.
- Private output only: the existing locked-suite workspace outside this repository.
- Do not add: private receipts, paths, reports, scores, mappings, or evaluator artifacts to Git.

**Interfaces:**
- Consumes: committed public-safe implementation and existing private sealed controller.
- Produces: a locally installed skill archive and a private terminal receipt.
- Completion gate: three absolute Regulatory Harvest `PASS` results with valid integrity and exact-evidence precision.

- [ ] **Step 1: Run the focused regression suite**

```bash
.venv/bin/pytest \
  tests/analysis/test_source_units.py \
  tests/analysis/test_drafts.py \
  tests/analysis/test_proposition_coverage.py \
  tests/analysis/test_coverage.py \
  tests/analysis/test_inventory.py \
  tests/analysis/test_build.py \
  tests/scripts/test_harvest_skill.py \
  tests/scripts/test_harvest_portable.py \
  tests/skill/test_skill_package.py \
  tests/scripts/test_build_skill.py -q
```

Expected: zero failures.

- [ ] **Step 2: Run static and full-suite verification**

```bash
.venv/bin/ruff check .
.venv/bin/mypy src
.venv/bin/pytest -q
git diff --check 80e1ad5..HEAD
```

Expected: Ruff and mypy are clean; the full suite has zero failures; diff check is clean across every implementation and planning commit after the approved design.

- [ ] **Step 3: Build and audit from a clean committed snapshot**

```bash
RH_VERIFY_DIR="$(mktemp -d)"
git archive HEAD | tar -x -C "$RH_VERIFY_DIR"
python3 "$RH_VERIFY_DIR/scripts/build_skill.py" --output "$RH_VERIFY_DIR/regulatory-harvest-skill-a.zip"
python3 "$RH_VERIFY_DIR/scripts/build_skill.py" --output "$RH_VERIFY_DIR/regulatory-harvest-skill-b.zip"
cmp "$RH_VERIFY_DIR/regulatory-harvest-skill-a.zip" "$RH_VERIFY_DIR/regulatory-harvest-skill-b.zip"
python3 "$RH_VERIFY_DIR/scripts/audit_release.py" \
  --repo "$RH_VERIFY_DIR" \
  --archive "$RH_VERIFY_DIR/regulatory-harvest-skill-a.zip" \
  --json
```

Expected: the two archives are byte-identical and the audit returns `"ok": true` with only the standing manual publication requirement. Do not publish.

- [ ] **Step 4: Install the verified archive locally without deleting the prior installation**

Resolve the existing Regulatory Harvest skill directory, move that exact directory to a timestamped sibling backup, extract the verified archive into the same parent, and run the packaged quick validation. Confirm the installed `SKILL.md`, both new modules, and archive SHA-256 before proceeding. Do not use a broad home-directory or recursive deletion target.

Expected: Codex and Claude-compatible skill files are present under one `regulatory-harvest` directory, and the packaged full/portable smoke tests pass.

- [ ] **Step 5: Rerun the sealed three-case suite with fresh generation and evaluators**

Use the existing private controller and captured source packets outside the public repository. For each case:

1. create a fresh generation run from the same captured source packet;
2. require `evidence_precision_valid`, `proposition_coverage_valid`, and `provision_recall_valid` to be true;
3. initialize a fresh evaluation run against the unchanged sealed comparator;
4. service every evaluator request in a fresh isolated context using only its supplied packet;
5. preflight before every submit;
6. verify the terminal history and replay; and
7. record the result only in the private receipt.

Do not expose the evaluator ledger, comparator mapping, prior response, or grade to generation.

- [ ] **Step 6: Apply the absolute acceptance decision**

The iteration passes only when all three private terminal results satisfy:

```text
Regulatory Harvest absolute decision: PASS
Exact-evidence precision: valid
Proposition coverage: valid
Provision recall: valid
Terminal integrity and replay: valid
```

If any case is `FAIL`, stop and report the remaining generic omission cluster. Do not call the iteration complete, do not tune public code to private answer text, and do not publish.

- [ ] **Step 7: Preserve the implementation boundary**

Run `git status --short` and confirm only the known pre-existing unrelated documents remain dirty. No private artifact is staged. If verification required no code correction, create no additional commit. If a generic defect was corrected, repeat the relevant RED/GREEN task and all of Task 7 before committing only the scoped public-safe files.

---

## Final implementation review checklist

- [ ] Every approved design requirement maps to a task above.
- [ ] Every production change was preceded by a focused failing test.
- [ ] Full and portable output bytes match for new and legacy matters.
- [ ] The attorney-facing structure and disclaimer are unchanged.
- [ ] No private benchmark data entered the repository or skill archive.
- [ ] No publication or external release action occurred.
- [ ] The locked suite produced three absolute passes; otherwise the result is reported as incomplete.
