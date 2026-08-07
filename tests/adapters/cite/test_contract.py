import json
import subprocess
import sys
from pathlib import Path

from regulatory_harvest.adapters.cite import (
    CiteAnnotationPage,
    CiteDocument,
    CiteDocumentText,
)
from regulatory_harvest.adapters.cite.models import (
    CiteGraphQLIntrospection,
    CiteMcpToolListResponse,
)

FIXTURES = Path(__file__).parent / "fixtures"


def test_sanitized_fixtures_match_supported_public_response_shapes() -> None:
    """Contract drift in cite's documented response fields must fail visibly."""
    capabilities = json.loads(
        (FIXTURES / "capabilities.json").read_text(encoding="utf-8")
    )
    document = json.loads((FIXTURES / "document.json").read_text(encoding="utf-8"))
    annotations = json.loads(
        (FIXTURES / "annotations.json").read_text(encoding="utf-8")
    )

    tools = CiteMcpToolListResponse.model_validate(capabilities["mcp"])
    introspection = CiteGraphQLIntrospection.model_validate(capabilities["graphql"])
    summary = CiteDocument.model_validate(document["summary"])
    text = CiteDocumentText.model_validate(document["text"])
    annotation_page = CiteAnnotationPage.model_validate(annotations)

    assert {tool.name for tool in tools.result.tools} >= {
        "list_documents",
        "get_document_text",
        "list_annotations",
    }
    assert introspection.data.schema_.mutation_type is not None
    assert summary.slug == text.document_slug
    assert annotation_page.annotations[0].annotation_label is not None
    assert annotation_page.annotations[0].annotation_label.text == "requirement"


def test_importing_base_cli_does_not_eagerly_load_cite_adapter() -> None:
    """Base and offline commands must not acquire cite coupling at import time."""
    script = (
        "import sys; import regulatory_harvest.cli; "
        "assert 'regulatory_harvest.adapters.cite.client' not in sys.modules"
    )

    result = subprocess.run(
        [sys.executable, "-c", script],
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
