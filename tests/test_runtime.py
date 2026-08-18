from regulatory_harvest.runtime import REQUIRED_RUNTIME_MODULES, runtime_available


def test_runtime_probe_checks_every_required_dependency() -> None:
    """A partial environment must select the portable runner before a late import failure."""
    imported: list[str] = []

    def partial_import(name: str) -> object:
        imported.append(name)
        if name == "httpx":
            raise ModuleNotFoundError(name)
        return object()

    assert runtime_available(partial_import) is False
    assert "pydantic" in imported
    assert "httpx" in imported


def test_runtime_probe_accepts_a_complete_environment() -> None:
    """A complete host runtime should retain the full packaged engine."""

    def importer(name: str) -> object:
        return object()

    assert runtime_available(importer) is True
    assert {"bs4", "httpx", "pydantic", "pypdf", "regulatory_harvest.api"} <= set(
        REQUIRED_RUNTIME_MODULES
    )
