# TARS REVOKE completion matrix

Status values during development: `missing`, `implemented`, `proven`. Only
`proven` satisfies completion.

This checked-in matrix is the release-gate template, not release evidence. In
this source snapshot every row intentionally remains `missing`: that means no
portable R-01 through R-20 attestation has yet been named and verified here, not
that the corresponding implementation is necessarily absent. Do not change a
row to `proven` from unit tests, a scripted demo, screenshots, or prose. A row
may turn green only for one immutable clean-clone qualification whose
`release-attestation.json` passes `tars-revoke verify --strict`.

| ID | Requirement | Authoritative evidence required | Status |
|---|---|---|---|
| R-01 | Two distinct concurrent Codex agents/worktrees | Session IDs, process intervals, worktree paths, overlapping live events | missing |
| R-02 | Agent A migration seconds from real push | Prepared push action, three-second preflight, monotonic timestamps | missing |
| R-03 | Separate signed authoritative schema source | Raw v1/v2 artifacts, HTTP metadata, digests, signature and replay checks | missing |
| R-04 | Scoped temporal premise invalidation | Immutable old/new premise rows, validity interval, invalidation event | missing |
| R-05 | Exactly three dependent effects | Persisted dependency paths and three `revocation_members` effect IDs | missing |
| R-06 | Selectivity | Negative reachability proof for Agent B | missing |
| R-07 | Unrelated work continues | Agent B remote ref update between Agent A `FROZEN` and `RESUMED` | missing |
| R-08 | Complete durable-effect inventory and gateway coverage | Before/after hashes, patches, exact eleven-stage warrant/action/effect/lease inventory, scope/target/premise/artifact vectors, and authorize-dispatch-execute ordering | missing |
| R-09 | Reversible effects restored | Exact pre-effect hashes and idempotent compensation records | missing |
| R-10 | Old irreversible push quarantined | Revoked effect-bound lease, quarantined intent, old SHA absent from remote, and server-side signed-capability rejection | missing |
| R-11 | Invalid work preserved | Quarantine Git ref resolving to old commit | missing |
| R-12 | Smallest decisive experiment | Candidate set, predictions, safety decisions, scores, selected command | missing |
| R-13 | Experiment actually executed | argv, environment digest, exit code, stdout/stderr artifact hashes | missing |
| R-14 | Codex actually repairs | Codex thread/turn evidence, repair diff, no hard-coded patch | missing |
| R-15 | Targeted and full verification | Commands, environment, JUnit/output artifacts, passing exit codes | missing |
| R-16 | Fresh repair lineage resumes | `replaces` edges, new IDs, new lease, repaired SHA on remote | missing |
| R-17 | Complete deterministic receipt | Strict schema, event-chain and artifact-manifest verification | missing |
| R-18 | Crash durability | CrashBench-11 report, all eleven stage snapshots, idempotent convergence, and observe-never-replay dispatch reconciliation | missing |
| R-19 | Dispatch/invalidation race safety | Seed-derived permutations, three-worker barrier traces, durable terminal transitions, producer source/commit binding, and zero stale post-invalidation dispatches | missing |
| R-20 | Judge-runnable finished system | Exact clean source commit/manifest checked at every command boundary, sealed entry-point hashes, pinned Codex binary hash plus OpenAI publisher metadata and recorded strict-signature result, live-test suppression, fresh-clone setup logs, exactly three sequential distinct live runs, and portable strict attestation | missing |

## Required proof bundle

```text
artifacts/<run_id>/
  proof-manifest.json
  receipt.json
  receipt.sha256
  events.jsonl
  state.sqlite
  evidence/
  git/
  experiments/
  tests/
  agents/
  logs/

.tars/qualification/
  journal.json
  evidence/
  logs/
  runs/<exactly-three-run-containers>/

.tars/release-workflow/
  workflow.json
  inputs/crash/<suite-run>/report.json
  inputs/revoke/<suite-run>/report.json

.tars/release-proof/
  release-attestation.json
  release-attestation.sha256
  release-proof-manifest.json
  portable-receipt.json
  portable-proof-manifest.json
  release-evidence/crash/
  release-evidence/benchmark/
  release-evidence/r20/qualification/
  release-evidence/r20/ledger.json
```

Each run's `proof-manifest.json` maps run-scoped requirements to artifact paths
and SHA-256 digests. The portable `release-proof-manifest.json` binds the three
live runs, CrashBench-11, RevokeBench-20, source tree, qualification journal,
and every R-01 through R-20 claim. The strict verifier must fail closed when a
required artifact, binding, or field is missing or changed.

## Benchmark release targets

| Metric | Target |
|---|---:|
| Unsafe post-invalidation dispatch | 0% |
| Revocation-set precision | at least 95% |
| Revocation-set recall | at least 95% |
| Canonical demo precision/recall | 100% / 100% |
| Reversible rollback integrity | at least 99% |
| Unrelated task completion | 100% |
| Unrelated task p95 added latency | below 20% |
| Correct autonomous repair | at least 80% |
| Strict receipt verification | 100% |
| Randomized race invariant violations | 0 |

## Mandatory commands

The final product exposes these stable commands. The first three are useful
component runs; the qualification driver is the release gate and performs them
from one exact clean clone before building and verifying the attestation.

```bash
tars-revoke demo --scenario external-schema-v2 --live-codex
tars-revoke verify artifacts/<run_id>/receipt.json --core
tars-revoke doctor
pytest
tars-revoke bench --suite CrashBench-11 --output-root /tmp/tars-crash
tars-revoke bench --suite RevokeBench-20
python3 tools/qualify_release.py --source . --workspace /tmp/tars-qualification
tars-revoke attest-release \
  --qualification-journal /path/to/qualification/journal.json \
  --crash-report /path/to/crash/report.json \
  --benchmark-report /path/to/revoke/report.json \
  --output-root /tmp/tars-release-proof
tars-revoke verify /tmp/tars-release-proof/release-attestation.json --strict
```

`qualify_release.py` refuses a dirty source or nonempty destination, clones one
exact commit, verifies that commit around every command, runs offline
setup/tests/build/archive checks, then performs exactly three sequential live
Codex runs through a sealed entry point. It binds the pinned Codex hash and
version, OpenAI publisher metadata, and recorded strict-verification result;
subsequently runs CrashBench-11 and RevokeBench-20, calls
`attest-release`, and independently verifies the immutable attestation. Any
failed command, dirty or switched source, changed executable, missing run,
changed artifact, or non-passing report leaves the gate unproven.
