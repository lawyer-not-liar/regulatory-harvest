# Clean-room contribution boundary

Regulatory Harvest is independently implemented from its public design, public standards, public project interfaces, and synthetic fixtures.

## Prohibited inputs

Do not use, copy, paraphrase mechanically, or commit any non-public:

- source code, prompts, workflow exports, schemas, database records, infrastructure configuration, screenshots, logs, or test data;
- URLs, identifiers, credentials, secrets, personal data, client facts, matter facts, employer product facts, or operational metrics;
- corpus content, annotations, research results, or documents without clear redistribution permission;
- material obtained under an employment, confidentiality, data-use, or access restriction that prevents contribution.

Do not use private material as a hidden reference while rewriting it. If a feature cannot be explained and independently implemented from public requirements, stop and open a design issue without including the private material.

## Allowed inputs

- This repository's public design and issue history.
- Public API documentation and public source code used in compliance with its license.
- Statutes, regulations, cases, and government publications when their reuse status is understood and recorded.
- Synthetic fixtures authored for this project.
- Third-party data that is clearly redistributable, with provenance and license recorded next to the fixture.

## Contributor checklist

Before opening a change, confirm:

1. I wrote the contribution independently from allowed inputs.
2. I have authority to contribute the code and documentation.
3. Fixtures are synthetic or have a recorded redistribution basis.
4. No secret, personal, client, matter, employer, or private operational information is present.
5. New dependencies and copied code notices are recorded in `THIRD_PARTY_NOTICES.md`.
6. Examples do not imply that synthetic text is actual law.

If any answer is uncertain, do not submit the material until the uncertainty is resolved.

## Publication gate

Passing tests, completing documentation, or creating a local release artifact does not authorize public publication. The repository owner must separately confirm ownership, employment obligations, third-party license compliance, trademark choices, security posture, and authorization to publish. Preserve Git history for provenance review.

## Release enforcement

Run `uv run python scripts/audit_release.py --json` against the candidate commit before packaging or publication. The command audits tracked text for credential patterns, private-network URLs, absolute home paths, prohibited internal identifiers, n8n workflow fingerprints, unlicensed fixtures, and generated run exports. Its messages identify the finding class and location without reproducing matched values.

The scanner's narrow path-and-code exceptions exist only for synthetic security tests, audit self-tests, and an explicit public design example. An exception is not proof that content is safe; changes to the allowlist require human clean-room review.

The audit cannot establish ownership, employment authorization, confidentiality compliance, or permission to publish. It therefore always reports `MANUAL_CONFIRMATION_REQUIRED`. Follow [the release checklist](docs/release-checklist.md), and record the owner's approval outside the repository before creating a public remote.
