# TARS REVOKE product contract

Status: accepted product thesis and non-shrunk completion contract.

## Promise

TARS REVOKE is continuous, evidence-backed authorization for coding agents.

Every consequential action operates on a live warrant containing the exact premises, evidence revisions, artifact hashes, and tests that justify it. If authoritative evidence invalidates one premise, TARS changes what can reach the outside world: it selectively revokes dependent work, inventories and compensates its effects, resolves the disagreement with the least-cost safe decisive experiment, lets Codex repair the affected lineage, and resumes only under a fresh warrant.

Memory answers what an agent knew. Graphs answer what is connected. Guardrails answer whether a proposed action is permitted. TARS REVOKE answers: this action was permitted, its justification is now false, so revoke it and recover.

## Required actors

- Operator: launches a run, inspects causal state, and can intervene without being required for the canonical recovery.
- Agent A: a live Codex coding session performing the premise-dependent migration.
- Agent B: a distinct concurrent Codex session performing unrelated work.
- Evidence source: a separate signed, versioned schema-registry process outside agent writable roots.
- Evidence watcher: verifies source identity, version, signature, digest, and freshness.
- Effect gateway: the only admission path for consequential effects.
- Codex repairer: proposes experiments and repairs; the gateway runs the chosen
  experiment and verification commands before resume.
- Receipt verifier: independently rebuilds and validates the causal account from durable state.

## Functional requirements

1. Connect evidence-backed premises to agent plans, artifacts, actions, and effects.
2. Version premises without rewriting history; record `valid_at`, `invalid_at`, scope, and value semantics.
3. Bind each consequential action and its one prepared effect intent to one
   causal scope, an authorized target, an exact premise-revision vector,
   artifact hashes, required tests, and a short-lived one-shot lease carrying
   the exact effect ID.
4. Deny high-risk or external actions whose dependencies are missing or unattributed.
5. Detect new authoritative evidence and atomically invalidate the affected premise revision.
6. Traverse persisted scoped hard dependencies and revoke only the reachable actions/effects.
7. Freeze dependent patches, commits, commands, migrations, and pending pushes.
   Local commits, experiments, targeted tests, and full tests are consequential
   operations too; they do not receive a gateway bypass.
8. Leave unrelated agents and actions executing without a global pause.
9. Reconcile all durable mutations into an effect inventory with before/after hashes.
10. Roll back reversible effects idempotently.
11. Quarantine irreversible effects before dispatch; if already dispatched, report containment required and never claim rollback.
12. Preserve invalid work on a quarantine Git ref for diagnosis.
13. Ask Codex for typed experiment candidates with predictions under each live hypothesis.
14. Validate candidates and deterministically select the lexicographically least costly safe discriminating experiment.
15. Execute the chosen experiment against preserved invalid work and record raw results.
16. Resume the affected Codex session with a bounded revocation packet, not an unbounded transcript.
17. Require Codex to repair the migration/model and add or update a regression test.
18. Run targeted and full test suites before authorizing replacement effects.
19. Create new premise, warrant, action, effect, and push IDs linked through `replaces`; revoked IDs never become authorized again.
20. Generate a deterministic receipt and proof manifest covering trigger, graph paths, effects, compensation, experiment, repair, tests, resume, and integrity.
21. Recover correctly across crashes, duplicate events, cancellation/result
    races, and compensation retries. Persisted `DISPATCHING` effects are
    observed against external truth and never replayed merely to discover their
    outcome.
22. Provide a finished operator UI derived from the same authoritative API and event stream.

## Canonical real demo

The external billing schema initially defines `customer_id` as UUID. Agent A
creates a gateway-authorized local commit containing the UUID application-model
change, applies the gateway-authorized UUID database migration, and prepares a
gateway-authorized push to an isolated protected bare Git remote.

After the push reaches `PREPARED`, the external registry publishes a signed higher-version schema defining `customer_id` as an opaque `cus_*` string. TARS must:

1. Verify and ingest the new evidence.
2. Invalidate the scoped UUID premise.
3. Revoke exactly three dependent effect records: the UUID local commit spanning
   the model and managed migration source, the applied database migration, and
   the old push intent.
4. Allow Agent B's separately authorized observability-documentation local
   commit and push to complete during Agent A's open revocation case.
5. Restore the exact before-images for both reversible effects.
6. Quarantine the old push so the invalid commit never reaches the remote.
7. Preserve the invalid commit on a local quarantine ref.
8. Authorize, select, and execute the smallest safe experiment that distinguishes
   UUID from opaque `cus_*` semantics.
9. Have Codex repair the preserved work, then gateway-authorize the repair local
   commit, replacement migration, targeted test, and full test as distinct
   warrant/action/effect/lease stages.
10. Push the repaired commit through a new authorized action.
11. Produce a core receipt that independently verifies every claim above,
    including complete coverage of all eleven consequential stages. A separate
    portable release attestation combines three distinct sequential live
    receipts from one clean clone with crash and race evidence for R-01 through
    R-20.

The dashboard may visualize this sequence, but no screenshot, animation, precomputed list, narrated response, hard-coded affected IDs, or manually edited receipt counts as evidence.

## Enforcement boundary

TARS controls registered coding-agent processes, their managed worktrees, and
gateway-backed effects. It does not claim to restrain a malicious
operating-system administrator. Managed Codex sessions receive writable
worktrees but not the Git capability token; authorized pushes are issued by the
gateway. The gateway issues signed `tars.git-push/v2` capabilities and the
protected bare remote validates them in server-side `pre-receive`, atomically
consuming a durable nonce. Raw pushes, wrong ref/OID/remote capabilities, replay
after restart, and pushes using `--no-verify` fail in the canonical boundary. A
host administrator can still alter the local remote or enforcement files, and a
hosted deployment must provide equivalent protected server-side enforcement.

## Non-negotiable invariants

- INV-01: No dependent irreversible action begins dispatch after premise invalidation commits.
- INV-02: Only nodes reachable through scoped hard dependencies are automatically revoked.
- INV-03: Every consequential mutation or command has exactly one prepared
  EffectRecord before authorization, otherwise authorization fails.
- INV-04: Invalidated premises and revoked actions are immutable historical records.
- INV-05: Every action lease is one-shot and bound to one effect ID, warrant
  epoch, scope, authorized target, exact premise revisions, artifact hashes,
  and required tests.
- INV-06: Compensation is idempotent and refuses to overwrite an unexpected current hash.
- INV-07: Already-visible irreversible effects are marked containment-required, never rolled back in prose.
- INV-08: An unrelated agent cannot be paused without a dependency path.
- INV-09: Experiment candidates record divergent predictions before execution.
- INV-10: No lower-scoring safe discriminating candidate exists in the recorded set.
- INV-11: Repair uses a fresh lineage linked by `replaces` edges.
- INV-12: Rebuilding a receipt from the same durable snapshot produces the same digest.
- INV-13: The canonical receipt accounts for all eleven durable
  warrant/action/effect/lease stages; omission or invention fails independent
  verification.
- INV-14: Startup recovery observes an ambiguous irreversible dispatch and
  records the result; it never replays the dispatch to infer the result.

## Release gate

The product is complete only when the strict requirement matrix passes, the
canonical live demo succeeds exactly three consecutive times from one fresh
clone of one clean source commit, CrashBench-11 and RevokeBench-20 pass from that
same source, race tests observe zero stale post-invalidation dispatches, the
invalid commit never reaches the remote, Agent B pushes during Agent A's
revocation, the repaired Agent A commit reaches the remote through a new
lineage, and the portable release attestation passes the independent strict
verifier without consulting the UI.

The release workflow is executable, not a prose checklist:

```bash
python3 tools/qualify_release.py \
  --source . \
  --workspace /tmp/tars-revoke-qualification
```

This tracked contract does not itself claim that a checkout has passed the
gate. Only the resulting immutable qualification journal, benchmark reports,
`release-attestation.json`, and successful `verify --strict` run can do that.
