# TARS REVOKE raw-material map

Status: locked donor inventory, 2026-07-14.

This document records what is being carried forward from TARS and Martin, what is being rewritten, and what is explicitly excluded. It exists to prevent the new product from becoming a rename of either prototype.

## Safety boundary

| Tree | Role | Write policy |
|---|---|---|
| Original TARS research tree | Newest TARS research source, mixed with personal/runtime state | Read only; never copy wholesale |
| Sanitized TARS snapshot | Credential-free TARS reference | Read-only reference |
| Original Martin research tree | Richest Martin source, dirty and private | Read only; never copy wholesale |
| Sanitized Martin snapshot | Credential-free Martin donor | Read-only code donor |
| This repository | Clean duplicate created from a preserved baseline | The only writable product tree |

Never import `.env` files, session state, SQLite databases, JSON/JSONL runtime state, audio caches, model weights, logs, generated prompts, workshop outputs, SSH material, personal imports, or either original repository's `.git` directory.

## TARS salvage matrix

| Donor component | Keep | Replace |
|---|---|---|
| `tars_contracts.py` | Typed-domain style and evidence-ID vocabulary | New immutable Evidence, Premise, Warrant, Action, Effect, Revocation, Experiment, Repair, and Receipt contracts |
| `tars_belief_ledger.py` | SQLite WAL, provenance, evidence records, explicit lifecycle | Append-only premise revisions, validity intervals, scoped value semantics, as-of queries, and causal dependencies. The donor mutates history and incorrectly assumes every subject/relation is single-valued. |
| `tars_event_bus.py` | Typed event envelope and replayable-event intent | Transactional, hash-chained event journal and outbox. Authorization must never depend on fail-soft JSONL writes or swallowed subscriber failures. |
| `tars_workspace.py` | Inspectable suppression reasons and evidence references | Deterministic concurrent authorization. The donor is a heuristic single-winner attention contest and does not execute or selectively freeze actions. |
| `tars_autonomy.py` / `tars_build_policies.py` | Fail-closed result shape and a secondary danger-word scan | Live warrant evaluation, revision leases, typed effects, and mandatory gateway admission. Regex risk scoring is not authority. |
| `tars_build_control.py` | Staged plan, build, test, review, activate lifecycle vocabulary | Transactional state machine, argv-only execution, captured effects, cancellation, compensation, and replacement lineages. The donor uses mutable JSONL and manifest-controlled `shell=True`. |
| `tars_gemini_runner.py` | CWD isolation, timeout, subprocess adapter shape | Codex adapter with structured events, cancellation, output schemas, repair/resume, and exact model/session evidence. |
| `tars_skills_loader.py` | Environment scrubbing, argv execution, process-group termination | Durable per-action leases and selective cancellation. Donor quarantine is in-memory and skill-global. |
| `tars_memory.py` | Provenance fields, bounded evidence blocks, retrieval envelope | Authorization truth. Relevance and memory retrieval never authorize an action. |
| `tars_sleep.py` | Contradiction-candidate/report vocabulary | Continuous signed evidence ingestion and typed contradiction evaluation. Scheduled Jaccard/polarity heuristics are insufficient. |
| `tars_world_model.py` | Prediction-versus-observation receipt pattern | Falsifiable experiment predictions tied to explicit hypotheses. |
| `tars_goals.py` | Blocked/waiting state vocabulary | Typed dependency edges and action-goal lineage. |
| `tars_doctor.py` | Health-check CLI concept | Product doctor covering Git hooks, Codex, store integrity, effect adapters, worktree isolation, and receipt verification. |
| Voice, emotion, selfhood, sleep, inner-monologue, STT/TTS modules | Nothing in the execution kernel | Excluded from the new product. They do not contribute to continuous authorization. |

## Martin salvage matrix

Only the credential-free Martin snapshot was treated as an executable donor.

| Donor component | Keep | Replace |
|---|---|---|
| `src/services/sqliteQueue.js` | WAL-backed durable outbox, retry/dead-letter concepts | Dependency-injected store, atomic leases, idempotency constraints, encrypted/typed payloads, and a shared transaction with primary state |
| `src/services/localJsonlLogger.js` | Recursive secret redaction and structured append logs | Typed, hash-chained, fail-visible events with field-level secrecy |
| `src/services/hermesTaskService.js` | Persist-before-dispatch, stable idempotency, task/artifact/error envelope | Atomic claims, lease epochs, cancellation/result admission, evidence manifests, and no fire-and-forget authority |
| `src/services/hermesBridgeService.js` | No-shell spawning, validation, timeouts, health checks, retries, circuit breaker | Scoped capability lease, process-group cancellation, adapter-neutral contract, signed receipts. The embedded full-authority prompt is rejected. |
| `convex/schema.ts` task/tool/event tables | Task, tool-run, event, dependency, artifact, error, and dead-letter vocabulary | Strict enums, immutable revisions, premise vectors, cancellation epochs, effect inventory, compensation, receipt hashes |
| `convex/memoryRetrieval.ts` evidence envelope | Source ID, agent, time, confidence, category, and source-labelled evidence | Immutable content hashes, issuer/signature, validity interval, verification method, supersession and revocation |
| `convex/memory.ts` evidence-returning answer shape | Answer, evidence, missing evidence, search layers, sources | Explicit separation between retrieved, verified, supports-premise, and authorizes-action |
| `src/services/toolRegistry.js` / `toolService.js` | Typed capability metadata and execution lifecycle | Caller booleans are replaced by signed, scoped, expiring grants and per-attempt warrant evaluation |
| Provider/voice engine abstractions | Adapter lifecycle, events, health, reconnect | Agent runtime adapter: start, stream, checkpoint, cancel, resume, reconcile |
| Public UI | Instrumentation density and bounded event display | Causal graph, evidence drawer, selective revocation lanes, effects, experiment, repair, and verified receipt |
| Martin Recall prototype | Source-labelled/redacted ingestion concepts | Reimplemented with allowlists, content hashes, taint tracking, and permission-hardened storage; private code is not copied |

## Product-defining capabilities that do not exist in either donor

The following modules are greenfield and form the trust kernel:

1. Temporal, scoped premise revisions with signed evidence.
2. Persisted Evidence -> Premise -> Warrant -> Action -> Effect dependency graph.
3. Mandatory pre-action and mid-action warrant revalidation.
4. Revision leases and fencing tokens that close the dispatch/invalidation race.
5. Selective transitive revocation over hard dependencies.
6. Complete effect before/after inventory.
7. Idempotent compensation for reversible effects and honest containment for irreversible effects.
8. Bounded least-cost decisive experiment selection.
9. Codex test, repair, verification, and resume through new action IDs.
10. Canonical, independently verifiable, hash-chained receipts.
11. Concurrent agent execution where unrelated work is provably unaffected.
12. Real Git worktrees, a real isolated remote, and a real signed external schema source.

## Extraction rule

Donor code is not copied merely because it has a similar noun. A component is transplanted only when its invariants match the new trust boundary. Otherwise its tested pattern is reimplemented behind a new typed contract.
