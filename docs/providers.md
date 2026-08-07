# Optional providers

Regulatory Harvest runs locally without a model provider, search provider, server, database, network connection, or API key. Optional providers are explicit boundary adapters. They are not imported by the base package.

## OpenAI structured analysis

Install the extra:

```bash
pip install "regulatory-harvest[openai]"
```

Set `OPENAI_API_KEY`, then construct `OpenAIModelProvider` with an explicit model name. The adapter uses the Responses API structured-output helper with `AnalysisDraft` as the Pydantic output type, consistent with the [official structured outputs guide](https://developers.openai.com/api/docs/guides/structured-outputs). It sets `store=False` and sends the following material outside the local machine:

- the versioned Map or Build instructions;
- the research question, jurisdictions, and as-of date;
- normalized source excerpts and safe source metadata.

It does not send local source paths, artifact-store contents, prior run manifests, environment variables, or API keys in the request body. Provider response IDs, model name, token counts, and prompt fingerprint are retained. Credentials and raw provider errors are not serialized.

The adapter has no default model. Requiring an explicit model prevents a moving alias from silently changing a resumable run. Pass `provider.configuration_fingerprint` to `run_research` as `model_provider_fingerprint`.

## Tavily source discovery

The Tavily adapter uses the documented [`POST /search` endpoint](https://docs.tavily.com/documentation/api-reference/endpoint/search). Set `TAVILY_API_KEY` or pass a key explicitly. It uses an explicit search depth and result limit, and disables generated answers and raw page content. The research question, jurisdictions, and as-of date leave the local machine as search context.

Search results are only discovery candidates. COMBINE passes their URLs through the same public-address and redirect validation used for user-supplied URLs before retaining source content. Pass `provider.configuration_fingerprint` as `search_provider_fingerprint`.

## Custom providers

Implement the asynchronous `ModelProvider`, `SearchProvider`, or `SourceFetcher` protocol. Return only the provider-neutral Pydantic models. Supply a stable configuration fingerprint that includes behavior-affecting model, prompt, endpoint, or retrieval settings but excludes credentials. The pipeline uses that fingerprint to invalidate stale checkpoints.
