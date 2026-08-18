# Qualification Capsule Integrity Design

## Purpose

Make a source-only qualification capsule sufficient to verify which immutable build it qualifies, how source-language handling was bounded, and what judgment execution metadata the controller reported. The change closes a publication-readiness evidence gap without changing report generation, substantive scoring, or the five admission dimensions.

## Scope

This design changes only the qualification contract and its full and portable implementations. It also updates the fictional qualification template, public evaluator documentation, and package manifest/tests as needed.

It does not change:

- generation inputs, generation behavior, or report drafting;
- evaluation ledger, grading, refereeing, aggregation, or thresholds;
- the meaning of `ADMITTED` or `CASE_INVALID`;
- legacy qualification capsule replay;
- publication authorization.

The incomplete qualification cycle that exposed this gap is retained as stopped evidence and is never upgraded in place.

## Considered approaches

### 1. Versioned replay-sealed qualification metadata — selected

Add an explicit schema-1.1 qualification contract. The case and source record carry immutable build identity and source-language treatment. The response artifact uses the existing judge-response envelope so provider, model, and truthful isolation mode are hashed into the capsule. Replay recomputes every artifact and retains schema-1.0 compatibility.

This is the smallest approach that makes the evidence travel with the capsule and keeps full and portable behavior equivalent.

### 2. Controller-only sidecars — rejected

A controller can associate a capsule root with a commit, archive, and role log, but that association is mutable and outside the replay root. It cannot satisfy the requirement that the capsule itself bind the build and response metadata.

### 3. Overload existing text fields — rejected

Embedding build hashes in the legal question or translation notes in source titles would change legal evidence semantics and create ambiguous fingerprints. Existing fields retain their existing meanings.

## Qualification schema 1.1

### Build binding

`QualificationBuildBinding` contains:

- `commit`: exactly 40 lowercase hexadecimal characters;
- `archive_sha256`: exactly 64 lowercase hexadecimal characters.

The binding is required for qualification schema `1.1`, forbidden for `1.0`, included in the canonical source record, and therefore included in the case fingerprint, source-record fingerprint, request fingerprint, artifact hash, and capsule root.

### Language treatment

`QualificationLanguageTreatment` contains:

- `source_ids`: a nonempty unique list of source identifiers;
- `method`: a nonblank description of the method actually used, such as original-language review, official bilingual text, authoritative translation, or bounded assisted translation;
- `rationale`: a nonblank explanation of why the method is sufficient for admission;
- `limitations`: an optional nonblank limitation.

Schema `1.1` requires language-treatment rows to cover every source exactly once. The deterministic layer validates shape and coverage only. The source-only admission judge remains responsible for deciding whether the treatment resolves the material language issue.

This avoids hard-coding a narrow language-method taxonomy while preventing silent or unidentified treatment.

### Judgment response envelope

Schema-1.1 qualification submission uses the existing `JudgeResponse` outer envelope:

- `schema_version: "1.0"`;
- `operation: "admit_case"`;
- exact request fingerprint;
- nonblank provider and model names;
- truthful `judge_isolation`;
- `payload` containing the existing strict `CaseAdmissionJudgment`.

The capsule stores the complete envelope as `admission-response.json`. Replay validates the envelope, validates the inner judgment, recomputes readiness, and verifies the manifest root. The judgment fingerprint continues to identify the inner legal judgment; the response artifact hash seals the surrounding execution metadata.

The recorded isolation value is an attestation, consistent with the evaluator's existing proof boundary. It does not independently prove host isolation or provider identity. Documentation must say so.

## Compatibility

Qualification schema `1.0` remains accepted and replayed byte-identically:

- its case shape remains unchanged;
- its source-record and request bytes remain unchanged;
- its raw `CaseAdmissionJudgment` response remains accepted;
- its manifest, receipt, state, and root behavior remain unchanged.

Qualification schema `1.1` requires the new build/language metadata and judge-response envelope. Full and portable implementations must produce byte-identical canonical requests, stored artifacts, status, verification, and diagnostics for both valid and invalid inputs.

## Fail-closed behavior

Schema `1.1` rejects, without mutating capsule state:

- missing, malformed, or noncanonical build identity;
- missing, duplicate, unknown, or incomplete language-treatment coverage;
- raw inner judgments without the required outer envelope;
- request, operation, payload, or schema mismatches;
- blank or malformed provider/model/isolation metadata;
- response-envelope tampering after submission;
- commit or archive mismatch supplied by a qualification controller.

Stable diagnostic codes must be identical in full and portable paths.

## Qualification restart

After implementation and independent review:

1. Freeze the new commit.
2. Build twice from clean detached clones and retain one verified archive inside a new private cycle.
3. Audit and install that exact archive recoverably.
4. Create new schema-1.1 qualification cases and new empty capsules.
5. Obtain one fresh source-only judgment per case using the response envelope.
6. Require three replay-valid `ADMITTED` receipts before generation.

The stopped schema-1.0 publication cycle remains immutable and is not counted as a retry of any substantive report.

## Tests and acceptance

Acceptance requires:

- test-first proof that current code fails to seal build identity, response metadata, and language treatment;
- full and portable schema-1.1 request/artifact/status/verification byte parity;
- replay rejection for each tampered binding and envelope field;
- legacy schema-1.0 frozen-byte and replay regression coverage;
- guarded write-free refusal tests;
- package/template/help/install coverage;
- full pytest, Ruff, mypy, reproducible archive, ZIP integrity, release audit, privacy scan, and isolated portable smoke gates;
- a fresh three-case source-only qualification cycle with no generation until all three pass.

## Privacy and release boundary

Only generic fictional template values and public-safe documentation enter Git. Private sources, case identifiers beyond existing public-safe fixtures, judgments, roots, controller records, and qualification artifacts remain outside Git. No push, pull request, release, visibility change, or publication occurs without separate authorization.
