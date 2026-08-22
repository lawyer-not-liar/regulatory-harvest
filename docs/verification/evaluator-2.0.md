# Evaluator Protocol 2 Fictional Lifecycle Receipt

**Status:** Public, deterministic fictional-fixture verification only.

**Fixture:** `tests/fixtures/attorney-eval-v2/`

The fixture uses a fictional rule and two capsule-backed fictional reports. It
contains an obligation, deadline, declared-exercise exception, enforcement and
civil-penalty language, and an explicit filing-fee gap. Each report is sealed
in a deterministic generation capsule with the same fictional source record,
question, and generation instructions.

The automated proof drives the protocol through source review, a nonempty
source audit, material-dispute referee acceptance, deterministic baseline
compilation, two independent grades for label A, two for label B, reconciliation,
result, status, and replay. It binds each local scripted response to the actual
pending request fingerprint and requires exact stdout, stderr, exit status, and
artifact-tree parity between the full runner and `python3 -I -S` portable
runner. It also verifies that a tampered completed result is refused without a
write.

This receipt demonstrates only that the fictional protocol path and its
portable parity execute deterministically. It does not establish legal
correctness, currentness, applicability, private-evaluation readiness,
benchmark performance, model performance, or a fresh external evaluation. The
fictional reports and scripted responses require attorney review before any
real-world use.
