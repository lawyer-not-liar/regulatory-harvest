"""Versioned disclosure of existing safety-draft mechanics, never scoring policy."""

from __future__ import annotations

from typing import Literal, cast

READINESS_SAFETY_RESPONSE_CONTRACT_VERSION_V1: Literal["readiness-safety-response-v1"] = (
    "readiness-safety-response-v1"
)
READINESS_SAFETY_RESPONSE_CONTRACT_VERSION_V2: Literal["readiness-safety-response-v2"] = (
    "readiness-safety-response-v2"
)
READINESS_SAFETY_RESPONSE_CONTRACT_VERSION_V3: Literal["readiness-safety-response-v3"] = (
    "readiness-safety-response-v3"
)
REVIEW_PACKAGE_POLICY_V1 = "prominent-attorney-issues-v1"
HARD_REVIEW_FINDING_CODES = frozenset(
    {
        "MATERIAL_UNSUPPORTED_ASSERTION",
        "BASELINE_CONTRADICTION",
        "MISLEADING_CURRENTNESS_OR_AUTHORITY",
        "UNDISCLOSED_DISPOSITIVE_CLIENT_FACT",
    }
)

CONSEQUENCES = (
    "legal conclusion",
    "applicability",
    "implementation decision",
    "deadline",
    "enforcement exposure",
    "attorney follow up",
)
RESOLUTION_OUTCOMES = (
    "evidence",
    "fact",
    "legal judgment",
    "report correction",
    "correct the report",
)
RESOLUTION_ACTIONS = (
    "verify",
    "obtain",
    "confirm",
    "correct",
    "revise",
    "establish",
    "resolve",
    "document",
)
SPECIFICITY_TERMS = frozenset(
    {
        "report",
        "treatment",
        "evidence",
        "source",
        "fact",
        "conflict",
        "ambiguity",
        "ambiguous",
        "currentness",
        "language",
        "missing",
        "omission",
        "assertion",
        "limitation",
        "interpretation",
        "authority",
        "requirement",
        "gap",
        "dependency",
        "support",
        "establish",
        "disclose",
    }
)


def build_readiness_safety_response_contract_v1() -> dict[str, object]:
    """Return a fresh, public, matter-independent explanation of enforced rules."""
    return {
        "version": READINESS_SAFETY_RESPONSE_CONTRACT_VERSION_V1,
        "purpose": (
            "These are mechanical response-format rules, not a scoring rubric or evidence. "
            "Give concrete, source-grounded judgments; a required word is not a substitute "
            "for substance. Do not invent a defect, fact, claim, or uncertainty to fit a rule."
        ),
        "response_shape": {
            "top_level_keys": ["candidate_assessments", "finding_proposals"],
            "candidate_order": "Cover every issued candidate in issued order.",
            "findings": "Supply scoped finding proposals; an empty array is allowed.",
            "controller_owned_fields": (
                "Do not supply lane, fingerprints, provenance, or an envelope."
            ),
            "maximum_items_per_array": 640,
            "maximum_draft_utf8_bytes": 262144,
            "maximum_json_depth": 64,
            "maximum_json_nodes": 20000,
            "duplicates": (
                "Exact duplicate items and references may be normalized; conflicting duplicates "
                "and duplicate JSON object keys are refused."
            ),
            "text_fields": (
                "All required text, including subject_id and rationale fields, must be nonblank "
                "and have no leading or trailing whitespace. This also applies to non-null "
                "disclosure_location and blocking_code."
            ),
        },
        "rationale": {
            "applies_to": "Every candidate assessment and every finding proposal.",
            "prose": "Required prose must be nonblank, without leading or trailing whitespace.",
            "normalization": (
                "For lexical checks: Unicode NFKC, casefold, underscores to spaces, "
                "other non-alphanumeric characters to spaces, then split into words. "
                "More research is needed is normalized to more research needed."
            ),
            "generic_refusal": (
                "Do not use a rationale equal after normalization to a generic_rationales "
                "entry in readiness_rubric, a bare disposition (met, partially met, not met, "
                "uncertain, pass, fail, inconclusive), or one or two numeric tokens."
            ),
            "shortfall_and_unresolved": {
                "fields": ["shortfall_description", "why_unresolved"],
                "minimum_words": 5,
                "required_any_word": sorted(SPECIFICITY_TERMS),
                "word_matching": "An exact normalized word is required; stemming is not applied.",
                "distinctness": (
                    "why_unresolved must differ after normalization from shortfall_description "
                    "and from the rationale_kind label. Explain why this particular issue remains."
                ),
            },
            "why_it_matters": {
                "required_any_phrase": list(CONSEQUENCES),
                "phrase_matching": "At least one listed phrase occurs in normalized prose.",
                "inline_evidence": (
                    "Include an exact issued evidence handle in the prose and in evidence_refs. "
                    "Every inline handle must be issued; at least one must match evidence_refs. "
                    "Separate handles from identifier-continuation characters, including "
                    "letters, digits, periods, underscores, colons, and hyphens; "
                    "spaces or parentheses are safe delimiters."
                ),
                "minimum_remaining_words": 3,
                "remaining_words": (
                    "After removing inline evidence handles and the named consequence phrases "
                    "(space or underscore forms), at least three normalized words must remain. "
                    "Explain the actual effect on this scoped answer, not just a consequence label."
                ),
            },
            "resolution_test": {
                "required_any_action": list(RESOLUTION_ACTIONS),
                "required_any_outcome": list(RESOLUTION_OUTCOMES),
                "matching": "Normalized prose must contain both a listed action and outcome.",
                "substance": (
                    "State the verifiable evidence, fact, legal judgment, or report "
                    "correction needed."
                ),
            },
        },
        "evidence_binding": {
            "references": "Use only exact evidence_handles identifiers from this packet.",
            "report_passages": (
                "Copy exact strings from report_passage_allowlist; do not paraphrase."
            ),
            "candidate_scope": (
                "At least one evidence_refs entry must belong to the candidate's evidence_refs."
            ),
            "rationale_kind_prefixes": {
                "SOURCE_ABSENT": ["SOURCE-"],
                "SOURCE_AMBIGUOUS": ["SOURCE-"],
                "SOURCE_CONFLICT": ["SOURCE-"],
                "CURRENTNESS_NOT_ESTABLISHED": ["PREREQUISITE-CURRENTNESS-"],
                "LANGUAGE_LIMITATION": ["PREREQUISITE-LANGUAGE-"],
                "APPLICABILITY_FACT_MISSING": ["PREREQUISITE-CLIENT-FACTS"],
            },
            "rationale_prefix_application": (
                "For these kinds, at least one matching-prefix handle must appear in evidence_refs "
                "and why_it_matters, and for assessments must also belong to the candidate scope."
            ),
            "finding_kind_prefixes": {
                "MATERIAL_UNSUPPORTED_ASSERTION": ["SOURCE-"],
                "BASELINE_CONTRADICTION": ["BASELINE-"],
                "HIDDEN_OR_UNDERSTATED_LIMITATION": ["SOURCE-", "PREREQUISITE-"],
                "UNDISCLOSED_DISPOSITIVE_CLIENT_FACT": ["PREREQUISITE-CLIENT-FACTS"],
                "MISLEADING_CURRENTNESS_OR_AUTHORITY": [
                    "SOURCE-",
                    "PREREQUISITE-CURRENTNESS-",
                    "PREREQUISITE-COMPLETENESS-",
                ],
                "UNDISCLOSED_GRADER_GAP": ["BASELINE-"],
            },
            "finding_prefix_application": (
                "At least one handle with a listed prefix must occur in both evidence_refs "
                "and why_it_matters; rationale-kind restrictions also apply."
            ),
        },
        "visibility_and_ownership": {
            "critical_candidates": (
                "Use prominent visibility and reviewing_attorney or outside_counsel owner."
            ),
            "report_content_findings": [
                "MATERIAL_UNSUPPORTED_ASSERTION",
                "BASELINE_CONTRADICTION",
                "MISLEADING_CURRENTNESS_OR_AUTHORITY",
            ],
            "report_content_rule": (
                "These finding kinds require at least one exact report passage, prominent "
                "visibility, and reviewing_attorney or outside_counsel ownership."
            ),
            "blocking_findings": (
                "Any finding with a non-null blocking_code also requires prominent visibility "
                "and reviewing_attorney or outside_counsel ownership. Use only published "
                "rubric codes and schema enums; a visible actionable gap is not itself a blocker."
            ),
        },
    }


def build_readiness_safety_response_contract_v2() -> dict[str, object]:
    """Versioned scoped-review policy; V1 remains immutable for historical replay."""
    contract = build_readiness_safety_response_contract_v1()
    contract["version"] = READINESS_SAFETY_RESPONSE_CONTRACT_VERSION_V2
    cast(dict[str, object], contract["visibility_and_ownership"])["critical_candidates"] = (
        "Open critical gaps require prominent visibility and reviewing_attorney or "
        "outside_counsel ownership. Scope-cleared prerequisites retain attorney ownership "
        "but describe actual report visibility; prominence is not required."
    )
    contract["purpose"] = (
        "Assess whether this report is a useful starting point for qualified-attorney review "
        "of the exact requested question, not a finished legal opinion or client compliance "
        "certification. Preserve substantive coverage floors and genuine safety blockers. "
        "This version changes scope treatment and whole-assessment reconciliation, not scores."
    )
    contract["scope_policy"] = {
        "assessment_field": "scope_status",
        "values": ["open_gap", "not_required_for_scope"],
        "scope_clearance": (
            "Use not_required_for_scope only for a prerequisite that is unnecessary for the "
            "requested answer or has no actual unresolved limitation. Give source/report-bound "
            "reasons. It requires blocking_code null. Never use it for a requirement, baseline "
            "gap, contested requirement, or safety finding. It is not a claim of resolution."
        ),
        "client_facts": (
            "A generic regulatory briefing need not establish a particular client's facts. "
            "Missing facts are a material gap when the requested or asserted conclusion "
            "depends on them. Read the question and full report before deciding."
        ),
        "language": (
            "A declared language-treatment record is a review candidate, not proof of an "
            "unresolved translation problem. Do not invent one if the evidence establishes none."
        ),
        "open_gaps": (
            "Use open_gap for an actual unresolved scoped shortfall. Preserve all existing "
            "disclosure, ownership, follow-up, evidence, and safety rules for open gaps. "
            "A generic caveat does not excuse an unsupported assertion or misleading omission."
        ),
        "materiality": (
            "Identify the concrete effect on the requested legal explanation or attorney's "
            "next step. More detail being possible is not itself a safety defect. Distinguish "
            "legal duties from penalty triggers, exceptions, and operational recommendations. "
            "Recommend proportionate, practical follow-up without inventing legal duties."
        ),
        "scope_cleared_fields": (
            "Retain truthful evidence-bound reasons. Report passages/disclosure may be empty "
            "if no disclosure is needed. Visibility describes actual report visibility. "
            "Follow-up and resolution_test state the conditional check before expanding scope, "
            "not a repair required for this briefing. Owner remains the reviewing attorney."
        ),
        "reconciliation": (
            "Resolve one complete assessment per disputed subject, including finding existence. "
            "Never combine one lane's rationale with another lane's blocker or follow-up. "
            "Unresolved decisions remain fail-closed; they do not prove a report defect."
        ),
        "mechanical_exemption": (
            "Only a validated scope-cleared prerequisite is exempt from automatic missing "
            "disclosure/passages and critical-visibility checks. All evidence and exact-binding "
            "checks remain. Real safety findings, coverage floors, and contested outcomes remain."
        ),
    }
    return contract


def build_readiness_safety_response_contract_v3() -> dict[str, object]:
    """Disclose package-level prominence without rewriting report observations."""
    contract = build_readiness_safety_response_contract_v2()
    contract["version"] = READINESS_SAFETY_RESPONSE_CONTRACT_VERSION_V3
    contract["review_package_policy"] = REVIEW_PACKAGE_POLICY_V1
    contract["purpose"] = (
        "Assess whether the unchanged report plus prominent, actionable attorney issue rows "
        "is a useful reviewable draft. Ordinary omissions may be nonblocking when the "
        "evidence-bound package safely flags their effect, owner, and concrete resolution test. "
        "False legal assertions remain blockers; never label open gaps resolved or lower scores."
    )
    visibility = cast(dict[str, object], contract["visibility_and_ownership"])
    visibility["critical_candidates"] = (
        "Visibility ALWAYS describes actual original-report visibility, including hidden. "
        "Critical candidates retain reviewing_attorney or outside_counsel ownership. "
        "The controller supplies separate prominent attorney issue rows before the report."
    )
    visibility["report_content_rule"] = (
        "These finding kinds require at least one exact original-report passage and "
        "reviewing_attorney or outside_counsel ownership. State actual report visibility. "
        "These kinds remain hard blockers even when blocking_code is null."
    )
    visibility["blocking_findings"] = (
        "Every explicit blocking_code remains binding. Blocking findings require attorney "
        "ownership but truthful actual report visibility, not invented prominence. "
        "Undisclosed dispositive client facts remain a hard blocker even with null code."
    )
    scope = cast(dict[str, object], contract["scope_policy"])
    scope["open_gaps"] = (
        "Use open_gap for actual unresolved scoped shortfalls. Ordinary omissions may be "
        "nonblocking when complete evidence-bound attorney rows provide safe prominent flags. "
        "Do not invent report passages or disclosure. Preserve evidence, rationale, ownership, "
        "follow-up, coverage floors, and all explicit or hard accuracy blockers."
    )
    scope["mechanical_exemption"] = (
        "Open review rows need not be disclosed in the original report. Any supplied "
        "disclosure must occur in the report, and supplied passages remain exact bindings. "
        "The package does not cure false legal assertions or misleading completeness claims."
    )
    return contract


def readiness_safety_response_contract(version: object) -> dict[str, object]:
    if version == READINESS_SAFETY_RESPONSE_CONTRACT_VERSION_V1:
        return build_readiness_safety_response_contract_v1()
    if version == READINESS_SAFETY_RESPONSE_CONTRACT_VERSION_V2:
        return build_readiness_safety_response_contract_v2()
    if version == READINESS_SAFETY_RESPONSE_CONTRACT_VERSION_V3:
        return build_readiness_safety_response_contract_v3()
    raise ValueError("safety response contract version is invalid")
