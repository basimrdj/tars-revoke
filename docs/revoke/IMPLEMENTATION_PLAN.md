# TARS REVOKE implementation plan

This is the planned final source tree. Each file has one owner responsibility so that enforcement logic cannot leak into adapters or the UI.

## Final tree and file responsibilities

```text
tars-next/
  pyproject.toml                         build metadata, dependencies, CLI entry point
  Makefile                               setup, lint, test, demo, verify commands
  .env.example                           non-secret configuration contract
  README.md                              product, quickstart, proof-first demo
  src/tars_revoke/
    __init__.py                          public package version
    config.py                            validated centralized configuration
    ids.py                               sortable typed IDs
    clock.py                             wall/monotonic clock abstraction for tests
    errors.py                            typed domain and adapter errors
    domain/
      enums.py                           all state and edge enums
      models.py                          immutable Pydantic domain contracts
      transitions.py                     legal transition tables and guards
      canonical.py                       deterministic JSON and digest rules
    persistence/
      schema.sql                         authoritative SQLite schema and indexes
      database.py                        WAL connection and transaction boundary
      store.py                           intent-based repositories and atomic operations
      event_journal.py                   sequenced hash-chain and outbox
      artifacts.py                       content-addressed artifact store
    services/
      evidence.py                        verify/normalize/version evidence
      premises.py                        scoped temporal premise lifecycle
      graph.py                           edge admission, reachability, dependency paths
      warrants.py                        issue, evaluate, expire, and revoke warrants
      gateway.py                         prepare/checkpoint/dispatch admission
      inventory.py                       reconcile actions into EffectRecords
      revocation.py                      atomic closure and selective freeze
      compensation.py                    idempotent rollback/quarantine/containment
      experiments.py                     candidate validation and minimum selection
      repair.py                          revocation packet, Codex repair, tests, replacement lineage
      receipts.py                        deterministic receipt and proof manifest
      coordinator.py                     run/case orchestration and restart recovery
    adapters/
      base.py                             protocols for agent, evidence, effect, and compensator adapters
      processes.py                        argv-only process groups, streaming, cancellation
      git.py                              worktrees, refs, diffs, commits, hook-backed pushes
      sqlite_migration.py                before-images, migrations, down/restore verification
      schema_registry.py                 signed HTTP evidence client/server protocol
      codex.py                            executable discovery, JSONL sessions, structured output, resume
    api/
      app.py                              FastAPI composition and lifespan
      dependencies.py                     dependency injection/container access
      schemas.py                          validated request/response models
      routes_runs.py                      runs, snapshots, demo controls
      routes_actions.py                   action/warrant/evidence inspection and safe operator commands
      routes_receipts.py                  receipt generation and strict verification
      stream.py                           sequenced SSE with snapshot reconciliation
    cli.py                                init, serve, demo, gate, doctor, verify, bench
    demo/
      fixture.py                          isolated repos, worktrees, remote, keys, initial artifacts
      registry.py                         separate signed schema-registry process
      scenario.py                         canonical two-agent live orchestration
      scripted_codex.py                   deterministic test double only, visibly labelled
      benchmarks.py                       RevokeBench runner and metrics
      verifier.py                         independent strict completion checks
  demo/billing-repo/
    billing/models.py                     UUID-v1 starting model
    migrations/001_initial.sql            starting database schema
    schemas/billing-v1.json               initial external contract
    schemas/billing-v2.json               contradictory external contract
    examples/customer-v1.json             UUID example
    examples/customer-v2.json             opaque cus example
    scripts/contract_probe.py              isolated decisive probe
    tests/test_contract.py                 targeted regression surface
    tests/test_full.py                     full fixture suite
    docs/observability.md                  Agent B unrelated target
  web/
    package.json                           frontend scripts and pinned dependencies
    vite.config.ts                        Vite build/proxy
    tsconfig.json                          strict TypeScript settings
    index.html                             application shell
    src/main.tsx                           React bootstrap
    src/App.tsx                            route-free operator layout
    src/api.ts                             typed API and SSE client
    src/types.ts                           frontend mirror of public API contracts
    src/styles.css                         complete visual system and responsive layout
    src/hooks/useRunStream.ts              sequence-aware live state reconciliation
    src/components/RunControl.tsx          launch/reset/live-Codex controls
    src/components/AgentLanes.tsx          concurrent Agent A/B execution proof
    src/components/CausalGraph.tsx         premise-to-effect dependency paths
    src/components/WarrantInspector.tsx    revisions, evidence, tests, lease state
    src/components/EffectInventory.tsx     reversible/quarantined/containment effects
    src/components/ExperimentPanel.tsx     candidates, predictions, cost choice, raw result
    src/components/Timeline.tsx            ordered hash-chained events
    src/components/ReceiptPanel.tsx        strict proof status and artifact links
  tests/
    unit/test_models.py                    validation and canonicalization
    unit/test_transitions.py               every legal/illegal transition
    unit/test_premises.py                  scoped single/set/temporal semantics
    unit/test_graph.py                     hard/soft closure and paths
    unit/test_warrants.py                  revision and freshness evaluation
    unit/test_gateway.py                   admission and fencing
    unit/test_compensation.py              idempotency and hash mismatch
    unit/test_experiments.py               safety, discrimination, cost ordering
    unit/test_receipts.py                  deterministic digest and tamper detection
    integration/test_evidence_registry.py  signatures, replay, monotonic versions
    integration/test_selective_revoke.py   exactly three affected and Agent B negative path
    integration/test_dispatch_race.py      randomized invalidation/dispatch schedules
    integration/test_git_gateway.py        hook denial, quarantine ref, real bare pushes
    integration/test_crash_recovery.py     restart at every case transition
    integration/test_canonical_demo.py     full deterministic-worker scenario
    live/test_codex_demo.py                 real Codex experiment/repair/resume gate
  docs/revoke/                             product, architecture, maps, proof contract
```

## Build order and proof gates

### Phase 1: Trust kernel

Implement domain contracts, SQLite schema, event hash chain, artifacts, premise revisions, graph, warrants, and transition guards.

Gate: schema migrations, immutable-history tests, scoped value semantics, deterministic digests, and graph property tests pass.

### Phase 2: Enforcement and effects

Implement process registry, worktree/Git adapter, effect inventory, gateway leases, selective revocation, compensation, quarantine, and restart reconciliation.

Gate: no direct push without a current lease; exactly-three closure; Agent B negative reachability; idempotent rollback; hash mismatch containment; zero stale dispatch in randomized schedules.

### Phase 3: Evidence and experiments

Implement signed external registry, watcher, monotonic versions, typed Codex experiment proposals, deterministic safety validation, and least-cost selection.

Gate: tampered/replayed evidence is rejected; valid v2 invalidates exactly one scoped premise; chosen experiment is safe and minimal in the accepted candidate set; raw command really runs.

### Phase 4: Codex repair and resume

Implement working Codex executable discovery, authenticated non-interactive sessions, bounded revocation packets, repair scope, targeted/full verification, and replacement lineages.

Gate: Codex edits the fixture rather than consuming a hard-coded patch; tests pass; old IDs remain revoked; new push reaches the remote.

### Phase 5: Product surface

Implement API, SSE reconciliation, CLI, doctor, operator UI, receipts, proof manifest, canonical demo, and benchmark runner.

Gate: a fresh install launches one-command demo; UI reflects authoritative state; deleting the UI does not break strict verification.

### Phase 6: Completion audit

Run unit, property, integration, crash, concurrency, frontend, deterministic demo, and three consecutive live-Codex runs. Secret-scan and hygiene-scan after tests.

Gate: every row in `COMPLETION_MATRIX.md` points to current authoritative evidence and passes.

## Backend risk assessment

Initial feasibility is deliberately classified high risk because the product controls Git and migrations. The design lowers risk through isolated worktrees/remotes, no-shell execution, typed adapters, exact hashes, a transactional revision gate, idempotent compensation, fail-closed unattributed actions, and independent receipts. These controls are prerequisites, not polish.

## Definition of done

Planning documents, unit tests, or an attractive interface are not completion. The only completion condition is the full product contract plus strict proof matrix, including the real Codex repair path and real concurrent-agent demo.
