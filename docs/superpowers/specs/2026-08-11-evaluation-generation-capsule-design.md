# Evaluation Generation Capsule Design

**Date:** 2026-08-11
**Status:** Approved remediation to the fully automated attorney evaluation design

## Problem

An access receipt containing hashes is only a self-attested statement. If it is
created after a report exists from the common evaluation packet, hash equality
does not establish what the report generator received. Regulatory Harvest must
not turn that statement into a deterministic source-parity proof.

## Decision

Add a small runner-controlled generation capsule before comparative evaluation.
The capsule captures exact source, client-fact, instruction, and generator-build
bytes before it issues a one-use generation request. It then seals the exact
report response and call metadata in the same immutable local run.

The capsule proves a narrow local fact: this runner captured these exact inputs,
issued this bound request, and subsequently accepted this exact report response.
It does not prove that a model used no other context, that provider/model labels
are truthful, that the host obeyed the instructions, or that a machine owner did
not deliberately recreate a capsule after the fact. No nonce, local unsigned
key, or self-signature can create that stronger trust without an independent
trusted service. The documentation and result language must preserve this
boundary.

## Command surface

Both universal runners expose identical commands:

- `eval-gen-init --input INPUT --run CAPSULE --nonce-hex NONCE`
- `eval-gen-next --run CAPSULE`
- `eval-gen-submit --run CAPSULE --response RESPONSE`
- `eval-gen-status --run CAPSULE`
- `eval-gen-verify --run CAPSULE`

No command calls a provider. The host executes the one current generation packet
using its configured model and writes one strict response envelope.
`eval-gen-next` is an idempotent, read-only fetch of the already-issued request;
it does not create a new issuance event. An `awaiting-report` capsule is therefore
complete and verifiable even before a response is submitted.

## Input contract

The canonical generation input is schema `1.0` and contains only strict fields:

```json
{
  "schema_version": "1.0",
  "candidate_id": "synthetic-candidate",
  "question": "What does the supplied synthetic rule require?",
  "generation_instructions": "Produce an attorney briefing using only the supplied record.",
  "sources": [{"source_id": "rule", "path": "sources/rule.txt"}],
  "client_facts_path": null,
  "generator_artifacts": [{"artifact_id": "generator", "path": "generator/descriptor.txt"}]
}
```

Every path is relative to the input root. The runner reads every component by a
retained no-follow filesystem view, decodes source/client facts as strict UTF-8
without normalization, and preserves generator artifacts as exact bytes.
Identifiers use the portable ASCII identifier alphabet and are limited to 100
encoded bytes, so captured filenames remain within supported component limits.
The capsule run must be disjoint from the input root: it cannot equal that root
or be nested beneath it.

## State and artifacts

`eval-gen-init` creates an immutable capsule in `awaiting-report` state and
writes:

- `captured/sources/<source-id>.txt`;
- `captured/client-facts.txt` when supplied;
- `captured/generator/<artifact-id>.bin`;
- `generation-input.json` with path-free captured commitments;
- `generation-request.json`; and
- `generation-manifest.json`.

The request includes the exact source/client text, generator artifact hashes,
question, generation instructions, capture fingerprint, and a request
fingerprint bound to the caller-supplied random nonce fingerprint. It contains
no source filesystem paths.

The caller must generate a fresh random nonce for every capsule. Identical input
and the same nonce intentionally produce the same request and capsule roots; the
local runner has no global registry that could prove nonce uniqueness across
directories or machines. This determinism supports replay verification but does
not establish chronology or prevent a machine owner from recreating a capsule.

The strict response envelope is schema `1.0`:

```json
{
  "schema_version": "1.0",
  "operation": "generate_report",
  "request_fingerprint": "<64 lowercase hex>",
  "provider_name": "host-agent",
  "model_name": "host-configured-model",
  "generation_isolation": "fresh_context",
  "response_id": null,
  "usage": {},
  "payload": {"report_text": "# Report"}
}
```

`eval-gen-submit` accepts the response once, preserves its canonical raw bytes,
and writes `report.md` from `report_text.encode("utf-8")`,
`generation-record.json`, and the completed manifest. The record binds candidate,
capture, request, response, source, client-fact, generator-artifact, and report
hashes plus the declared provider, model, and isolation. The manifest inventory
binds every artifact and supplies the verified capsule root.

The response path must be outside the capsule. The runner rejects an equal or
nested path before taking the capsule's exclusive transition lock and captures
the external response through its retained no-follow view before locking the
capsule. This prevents overlapping filesystem locks from self-deadlocking.

Invalid input or response is rejected without advancing. A duplicate or
out-of-order submission fails closed. Initialization uses atomic directory
creation, and submission holds an exclusive capsule transition lock so two
concurrent callers cannot both succeed. Status, request fetch, and verification
are read-only and use shared locks.

## Evaluation integration

The filesystem evaluation case advances to schema `1.1`. Each candidate has the
same exact shape and exactly one report source:

```json
{
  "candidate_id": "synthetic-candidate",
  "role": "candidate",
  "generation_capsule_path": "capsules/candidate",
  "external_report_path": null
}
```

A capsule candidate is loaded only after complete capsule verification. The
candidate report bytes come from the capsule, and its copied provenance record
includes the capsule root. Common source and client-fact hashes must match the
capsule capture exactly.

An external preserved report uses `generation_capsule_path: null` and a nonnull
`external_report_path`. It is not retroactively upgraded by hashing it. One
external report may receive an absolute evaluation against the frozen common
record. A two-report formal comparison requires both reports to have verified
capsules with matching source and client-fact commitments; otherwise source
parity is unproven and no winner or tie is issued. The skill may automatically
run two one-report absolute evaluations to provide provision-level assessments
of historical reports, but it must describe the formal comparison as unavailable.

Legacy schema `1.0` cases remain readable only for verification of already
persisted runs. New initialization requires `1.1`; it never silently converts a
self-attested receipt into capsule provenance.

## Privacy and blindness

Capsules stay local and outside the public ZIP's examples. The public package
contains only fictional templates. The generation packet is not an evaluation
grader packet and may identify the requested generator build, but evaluation
admission and graders retain the existing source-only and anonymous boundaries.

## Release gates

- Full and portable artifacts and outputs are byte-identical on supported POSIX
  hosts.
- Exact whitespace, LF/CRLF, BOM, and final-newline changes alter commitments.
- Symlink, path traversal, replacement, injection, mutation, incomplete capsule,
  cross-capsule response, duplicate submit, and mixed-schema attacks fail closed.
- A capsule response cannot be accepted before initialization or after completion.
- New two-report formal comparison cannot be admitted from self-attested or
  external-only reports.
- The extracted ZIP completes a fictional capsule then a verified comparison.
- Live Windows support remains explicitly unverified and release-gated until the
  native secure-storage path is exercised.
