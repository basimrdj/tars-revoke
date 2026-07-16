# Security policy

TARS REVOKE is a single-host execution-control implementation with a deliberately
isolated canonical proof environment. The demo mutates generated Git worktrees,
a generated SQLite database, and a generated protected bare remote. Do not point
it at production repositories, databases, or credentials without a separate
deployment review.

## Security boundaries

- Every managed command is an argv vector; shell strings are rejected.
- Filesystem paths must resolve beneath registered run/worktree roots.
- Every consequential stage requires one prepared effect intent whose scope,
  target, type, and reversibility match its action and warrant. Authorization
  binds the exact premise and artifact vectors plus required tests.
- Execution leases are short-lived, one-shot, and bound to one action, one
  effect ID, one warrant, and one warrant epoch.
- Git pushes require signed `tars.git-push/v2` capabilities bound to action ID,
  epoch, repository, canonical worktree, remote URL, refspec, destination,
  exact source object ID, issue/expiry time, and a nonce. A client `pre-push`
  check provides early feedback; the protected bare remote's server-side
  `pre-receive` hook validates the actual update and atomically consumes the
  nonce in a private SQLite ledger. Skipping client hooks with `--no-verify`
  does not bypass the server check, and consumed capabilities remain rejected
  after process restart.
- Evidence artifacts are signed Ed25519 envelopes from a pinned source identity
  with monotonic versions and content digests.
- Revocation closure is computed only over persisted, scoped, hard `REQUIRES`
  edges. Model output and semantic similarity cannot authorize or revoke work.
- Reversible compensation verifies the current after-hash before restoring the
  exact before-image. A mismatch becomes containment-required.
- Receipts, event journals, and proof manifests are hash-verified independently
  of the operator UI.
- Release qualification binds one exact source commit at every command
  boundary, requires a clean tracked tree, executes a sealed and repeatedly
  hashed TARS entry point, suppresses inherited live-test activation, and
  records strict macOS code-signature results, OpenAI desktop publisher
  metadata, and an exact pinned Codex release hash and version.
- Startup recovery follows an observe-never-replay policy. A persisted
  `DISPATCHING` Git push is compared with the remote ref and recorded as applied,
  not applied, conflicting, or unknown; recovery never repeats the push to find
  out what happened. Ambiguous or inconsistent truth fails closed into
  containment.
- Child processes receive a small, named runtime-environment allowlist instead
  of the ambient host environment. Git, Python tests, experiments, and the
  schema registry cannot inherit API keys or unrelated credentials. Codex alone
  may inherit its named auth variables and home directory; its user config is
  ignored so unrelated MCP servers and plugins cannot join the proof run.
- Known credential patterns are rejected from action payloads and Codex
  structured output. The exact environment passed to each managed child is
  recorded with secret-bearing keys and values redacted, as are captured logs.
  Opaque artifact bytes are integrity-addressed but not content-scanned; review
  proof bundles before sharing them.

## Important limitations

- The canonical bare remote has server-side receive enforcement, but a user or
  administrator who controls that remote's filesystem can still replace the
  hook, signing secret, nonce ledger, database, or running program. A hosted
  deployment needs equivalent protected server-side integration whose
  enforcement files are outside agent and ordinary operator control.
- Codex sandboxing and process groups reduce accidental scope, but this project
  is not a hardened multi-tenant container boundary.
- The bundled demo proves the local protected bare-remote protocol, including
  raw-push, wrong-ref/OID/remote, `--no-verify`, nonce replay, and restart cases.
  It does not prove a hosted provider's credentials, branch rules, hook
  availability, or authorization model.
- SQLite provides single-host transactional truth. A distributed deployment
  needs an equivalent serializable revision fence and durable outbox.
- Startup observation currently has adapter-specific external-truth rules. An
  unrecognized or non-Git ambiguous dispatch fails closed; it is not evidence
  that an arbitrary production API supports safe reconciliation.
- Compensation is adapter-specific. An irreversible effect that already
  happened is reported as containment-required, never described as rolled back.
- Scripted demo mode is labelled and cannot satisfy live-Codex proof
  requirements.
- Qualification evidence remains host-owner-generated, as disclosed in the
  release receipt. The current vendor bundle's strict code-signature result is
  recorded even when it fails; in that case the gate relies on the exact pinned
  binary hash plus publisher metadata and adds an explicit receipt limitation.
  Neither mechanism is a remote witness for the surrounding host, journal, or
  clock.

## Keep out of Git

- `.env` files, API keys, bearer tokens, signing private keys, and capability
  secrets
- generated run directories, SQLite state, worktrees, remotes, receipts, and
  agent JSONL logs that may contain proprietary code
- shell histories, personal conversation exports, or production evidence

The repository ignore rules cover the canonical local paths, but operators are
responsible for reviewing artifacts before sharing them.

## Reporting a vulnerability

Use a private security report when possible. Do not post working credentials,
private source, raw agent transcripts, signed private evidence, or proof bundles
from a production environment in a public issue. Include the affected version,
minimal reproduction, and whether the issue can bypass a warrant, lease,
revocation fence, path boundary, signature check, or receipt verifier.
