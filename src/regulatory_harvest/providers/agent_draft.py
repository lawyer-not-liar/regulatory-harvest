"""Provider bridge for analysis drafted by the host agent running the skill."""

from regulatory_harvest.analysis import AnalysisDraft
from regulatory_harvest.storage import canonical_json_bytes, sha256_digest

from .protocols import ModelRequest, ModelResponse


class AgentDraftModelProvider:
    """Return one prevalidated host-agent draft through the provider protocol."""

    def __init__(
        self,
        draft: AnalysisDraft,
        *,
        host_name: str = "host-agent",
        model_name: str = "host-configured-model",
    ) -> None:
        self._draft = draft
        self._host_name = host_name
        self._model_name = model_name

    async def complete(self, request: ModelRequest) -> ModelResponse:
        fingerprint = sha256_digest(
            canonical_json_bytes(
                {
                    "draft": self._draft,
                    "instructions_version": request.instructions_version,
                    "operation": request.operation,
                }
            )
        )
        return ModelResponse(
            parsed=self._draft,
            provider_name=self._host_name,
            model_name=self._model_name,
            response_id=f"agent-draft-{fingerprint[:16]}",
            prompt_fingerprint=fingerprint,
        )
