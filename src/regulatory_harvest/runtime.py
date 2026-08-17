"""Standard-library-only probes for the bundled skill runtime."""

import importlib
from collections.abc import Callable

REQUIRED_RUNTIME_MODULES = (
    "pydantic",
    "httpx",
    "bs4",
    "pypdf",
    "regulatory_harvest.api",
)


def runtime_available(
    import_module: Callable[[str], object] = importlib.import_module,
) -> bool:
    """Return whether every mandatory runtime module imports successfully."""
    try:
        for module_name in REQUIRED_RUNTIME_MODULES:
            import_module(module_name)
    except ImportError:
        return False
    return True
