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


def test_source_units_split_long_text_at_comma_boundaries_within_maximum() -> None:
    text = "a," * 900
    inventory = build_source_unit_inventory([_source(text)])
    units = inventory["units"]
    assert len(units) >= 2
    assert all(unit["end_char"] - unit["start_char"] <= 1_600 for unit in units)
    _assert_exact_partition(text, units)


def test_commentary_and_unusable_sources_emit_no_required_units() -> None:
    commentary = {**_source("A summary."), "source_role": "commentary_analysis"}
    unusable = {**_source("Unreadable."), "source_id": "src_bad", "source_quality": "unusable"}
    inventory = build_source_unit_inventory([commentary, unusable])
    assert inventory["required_unit_count"] == 0
    assert inventory["units"] == []
