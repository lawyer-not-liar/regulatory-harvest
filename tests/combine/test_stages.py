from importlib.resources import files

from regulatory_harvest.combine.stages import _model_request

from .support import request


def test_model_requests_use_the_versioned_attorney_briefing_prompts() -> None:
    map_request = _model_request("map", request(), [])
    build_request = _model_request("build", request(), [])

    prompt_package = files("regulatory_harvest.analysis.prompts")
    assert map_request.system_instructions == prompt_package.joinpath(
        "map-v1.md"
    ).read_text(encoding="utf-8")
    assert build_request.system_instructions == prompt_package.joinpath(
        "build-v1.md"
    ).read_text(encoding="utf-8")

    for prompt in (
        map_request.system_instructions,
        build_request.system_instructions,
    ):
        assert "status" in prompt.lower()
        assert "scope" in prompt.lower()
        assert "requirements" in prompt.lower()
        assert "enforcement" in prompt.lower()
        assert "deadlines" in prompt.lower()
        assert "implementation" in prompt.lower()
        assert "other" in prompt.lower()

    assert "nonoperative" in map_request.system_instructions.lower()
    assert "working translation" in build_request.system_instructions.lower()
    assert "finding or" in map_request.system_instructions.lower()
    assert "categorized gap" in map_request.system_instructions.lower()
    assert "executive summary" in build_request.system_instructions.lower()
    assert "matter-specific" in build_request.system_instructions.lower()
    assert "adaptive" in build_request.system_instructions.lower()
    assert "brief" in build_request.system_instructions.lower()
    assert "bottom line" in build_request.system_instructions.lower()
    assert "regulation-centered" in build_request.system_instructions.lower()
    assert "regulatory walk" in build_request.system_instructions.lower()
    assert "direct legal voice" in build_request.system_instructions.lower()
    assert "source sufficiency" in build_request.system_instructions.lower()
    assert "regulatory-walk-v1" in build_request.system_instructions
    assert "Key Requirements" in build_request.system_instructions
    assert "Penalties and Enforcement" in build_request.system_instructions
    assert "Implementation Workplan" in build_request.system_instructions
    assert "key_requirements" in build_request.system_instructions
    assert "penalties_enforcement" in build_request.system_instructions
    assert "Not established:" in build_request.system_instructions
    assert "matching categorized gap" in build_request.system_instructions.lower()
    assert "claim_ids" in build_request.system_instructions
    assert "enforcement_trigger_claim_ids" in build_request.system_instructions
    assert "enforcement_consequence_claim_ids" in build_request.system_instructions
    assert "enforcement_roles" in build_request.system_instructions
    assert "lexical" in build_request.system_instructions.lower()
    assert "other headings" in build_request.system_instructions.lower()
    for term in (
        "full normalized text",
        "provision sweep",
        "evidence inventory",
        "proposition coverage table",
        "coverage reconciliation",
        "defined-category fidelity check",
        "completeness challenge",
        "synthesis pass",
        "evidence-hardening pass",
        "adversarial omission review",
        "analysis claims",
    ):
        assert term in build_request.system_instructions.lower()
    for term in (
        "source_supported",
        "practical_implication",
        "provision-centered",
        "regulated actor or rights holder",
        "exact quotations",
        "audit.md",
    ):
        assert term in build_request.system_instructions.lower()
    for term in (
        "materiality challenge",
        "a citation quote is not coverage",
        "before retaining or finalizing",
        "provisional",
        "revisit",
        "survives only in the quotation",
        "map it to an atom or preserve a source-bound gap",
        "deterministic `completed` status",
        "substantively false `not_material` decision",
    ):
        assert term in build_request.system_instructions.casefold()
    assert "index, not a substitute" in build_request.system_instructions.lower()
    assert "before attaching exact quotations" in build_request.system_instructions.lower()
    assert (
        "lead with verified legal status and source limitations"
        not in build_request.system_instructions.lower()
    )
