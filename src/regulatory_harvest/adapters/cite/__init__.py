"""Optional adapter for cite (formerly OpenContracts)."""

from .client import (
    CiteClient,
    CiteCompatibilityError,
    CiteError,
    CiteRequestError,
)
from .exporter import (
    CiteDocumentTarget,
    CiteExportEntry,
    CiteExportPlan,
    CiteExportResult,
    CiteExportValidationError,
    build_cite_export_plan,
    export_bundle_to_cite,
)
from .importer import (
    CiteAnnotationMapping,
    CiteImportResult,
    import_cite_corpus,
    map_cite_annotation,
    map_cite_document,
)
from .models import (
    CiteAnnotation,
    CiteAnnotationPage,
    CiteCapabilities,
    CiteDocument,
    CiteDocumentPage,
    CiteDocumentText,
    CiteMutationReceipt,
    CiteRelationship,
    CiteRelationshipPage,
)

__all__ = [
    "CiteAnnotation",
    "CiteAnnotationMapping",
    "CiteAnnotationPage",
    "CiteCapabilities",
    "CiteClient",
    "CiteCompatibilityError",
    "CiteDocument",
    "CiteDocumentPage",
    "CiteDocumentTarget",
    "CiteDocumentText",
    "CiteError",
    "CiteExportEntry",
    "CiteExportPlan",
    "CiteExportResult",
    "CiteExportValidationError",
    "CiteImportResult",
    "CiteMutationReceipt",
    "CiteRelationship",
    "CiteRelationshipPage",
    "CiteRequestError",
    "build_cite_export_plan",
    "export_bundle_to_cite",
    "import_cite_corpus",
    "map_cite_annotation",
    "map_cite_document",
]
