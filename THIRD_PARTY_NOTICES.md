# Third-party notices

Regulatory Harvest is licensed under Apache-2.0. Its Python package depends directly on these separately licensed projects:

| Project | Use | License | Project URL |
| --- | --- | --- | --- |
| Beautiful Soup | HTML text extraction | MIT | https://www.crummy.com/software/BeautifulSoup/ |
| HTTPX | HTTP client | BSD-3-Clause | https://www.python-httpx.org/ |
| Pydantic | Public data models and validation | MIT | https://github.com/pydantic/pydantic |
| pypdf | PDF text extraction | BSD-3-Clause | https://github.com/py-pdf/pypdf |
| OpenAI Python | Optional OpenAI adapter | Apache-2.0 | https://github.com/openai/openai-python |

Hatchling is used to build distributions under the MIT license. Pytest, pytest-asyncio, Hypothesis, respx, Ruff, and mypy are development and verification tools and are not runtime dependencies of the base package.

The Tavily adapter uses Tavily's hosted HTTP API and adds no Tavily code dependency. Use of that service is subject to the user's separate agreement with Tavily.

The cite adapter uses documented interfaces exposed by cite/OpenContracts and adds no cite code dependency. cite/OpenContracts is distributed under the MIT license at https://github.com/Open-Source-Legal/OpenContracts. Content and hosted-service use remain subject to the applicable operator, contributor, and data terms.

The LegalBench-RAG evaluator implements the public dataset shape and exact-character evaluation concept independently and adds no LegalBench-RAG code or data dependency. The official code is MIT-licensed at https://github.com/zeroentropy-ai/legalbenchrag. LegalBench-RAG data incorporates source datasets with separate terms; users must review the official project and each applicable source dataset before use.

## Project fixtures

`examples/offline/example-rule.txt` and the fixtures under `tests/fixtures` are synthetic text authored for Regulatory Harvest. They are not law and are made available under Apache-2.0 with the repository. Their local fixture manifests describe that status.

Regulatory Harvest does not redistribute cite/OpenContracts or LegalBench-RAG code or datasets. Optional integrations remain subject to their upstream licenses and any separate dataset terms.
