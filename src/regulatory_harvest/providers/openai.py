"""Optional OpenAI Responses API adapter."""

from __future__ import annotations

import importlib
import os
from collections.abc import Callable
from importlib.resources import files
from typing import Protocol, cast

from pydantic import ValidationError

from regulatory_harvest.analysis import AnalysisDraft
from regulatory_harvest.providers.protocols import ModelRequest, ModelResponse
from regulatory_harvest.storage import canonical_json_bytes, sha256_digest

from .errors import ProviderError


class _Usage(Protocol):
    input_tokens: int
    output_tokens: int
    total_tokens: int


class _ParsedResponse(Protocol):
    output_parsed: object
    id: str
    model: str
    usage: _Usage | None


class _ResponsesResource(Protocol):
    async def parse(self, **kwargs: object) -> _ParsedResponse: ...


class _OpenAIClient(Protocol):
    responses: _ResponsesResource


def _prompt(operation: str) -> str:
    return (
        files("regulatory_harvest.analysis.prompts")
        .joinpath(f"{operation}-v1.md")
        .read_text(encoding="utf-8")
    )


def _new_client(api_key: str) -> _OpenAIClient:
    try:
        module = importlib.import_module("openai")
    except ImportError as error:
        raise RuntimeError(
            "Install Regulatory Harvest with the openai extra to use this adapter."
        ) from error
    factory = cast(Callable[..., object], module.AsyncOpenAI)
    return cast(_OpenAIClient, factory(api_key=api_key))


def _status_code(error: Exception) -> int | None:
    value = getattr(error, "status_code", None)
    return value if isinstance(value, int) else None


class OpenAIModelProvider:
    """Convert a provider-neutral request through structured Responses output."""

    def __init__(
        self,
        *,
        model: str,
        client: _OpenAIClient | None = None,
    ) -> None:
        if not model.strip():
            raise ValueError("model must not be blank")
        if client is None:
            api_key = os.getenv("OPENAI_API_KEY")
            if not api_key:
                raise ValueError("OPENAI_API_KEY is required without an explicit client")
            client = _new_client(api_key)
        self._client = client
        self.model = model

    @property
    def configuration_fingerprint(self) -> str:
        return sha256_digest(
            canonical_json_bytes(
                {
                    "adapter": "openai-responses-v1",
                    "build_prompt": sha256_digest(_prompt("build").encode()),
                    "map_prompt": sha256_digest(_prompt("map").encode()),
                    "model": self.model,
                }
            )
        )

    async def complete(self, request: ModelRequest) -> ModelResponse:
        base_prompt = _prompt(request.operation)
        system_prompt = (
            f"{base_prompt.rstrip()}\n\n"
            f"Request instructions version: {request.instructions_version}\n"
            f"{request.system_instructions.strip()}"
        )
        prompt_fingerprint = sha256_digest(system_prompt.encode("utf-8"))
        payload = {
            "operation": request.operation,
            "safe_metadata": request.safe_metadata,
            "source_excerpts": [
                excerpt.model_dump(mode="json") for excerpt in request.source_excerpts
            ],
        }
        try:
            response = await self._client.responses.parse(
                model=self.model,
                input=[
                    {"role": "system", "content": system_prompt},
                    {
                        "role": "user",
                        "content": canonical_json_bytes(payload).decode("utf-8"),
                    },
                ],
                text_format=AnalysisDraft,
                store=False,
            )
        except Exception as error:
            status_code = _status_code(error)
            retryable = status_code is None or status_code == 429 or status_code >= 500
            raise ProviderError(
                "OpenAI request failed.",
                provider="openai",
                retryable=retryable,
                status_code=status_code,
            ) from None

        try:
            parsed = AnalysisDraft.model_validate(response.output_parsed)
        except ValidationError:
            raise ProviderError(
                "OpenAI returned an invalid structured response.",
                provider="openai",
                retryable=False,
            ) from None
        usage = response.usage
        usage_data = (
            {}
            if usage is None
            else {
                "input_tokens": usage.input_tokens,
                "output_tokens": usage.output_tokens,
                "total_tokens": usage.total_tokens,
            }
        )
        return ModelResponse(
            parsed=parsed,
            provider_name="openai",
            model_name=response.model or self.model,
            response_id=response.id,
            usage=usage_data,
            prompt_fingerprint=prompt_fingerprint,
        )
