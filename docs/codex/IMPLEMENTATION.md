# Codex integration delivery contract

## User experience

Install once, enable for a repository, review Codex's hook trust prompt, and use
Codex normally. Synchronous lifecycle hooks check registered requirements before
supported local tools execute. Changes produce a bounded recovery packet in
Codex. TARS never returns a permission approval or bypasses Codex's sandbox.

## Boundaries

The existing R-01–R-20 release attests the isolated canonical scenario. It does
not qualify this integration. Native hooks observe Codex execution; they cannot
provide the protected remote's atomic receive fence, undo arbitrary shell/API
side effects, or guarantee denial when Codex itself skips or fails a hook.
Native mode must be described as cooperative local protection until a protected
remote/CI integration has separately passed its qualification.

Automatic dependency discovery starts conservatively: configured requirements
files plus a session-scoped task revision. Plain-language changes are supplied
to Codex as recovery context; no heuristic may declare an authoritative semantic
contradiction. Developers can add watched requirements files during setup.

## Acceptance criteria

- Normal Codex sessions need no per-command registration.
- Session, prompt, tool preflight, tool observation, and stop events persist.
- Every admitted supported tool call has a warrant, action, effect intent and
  consumed one-shot lease in the existing kernel.
- Missing, changed, or unsafe watched paths deny before admission and request
  recovery; restoring old bytes cannot revive a superseded task revision.
- Separate sessions do not globally pause one another.
- Duplicate preflight never executes a second time. Duplicate observations
  cannot invent another effect. Unknown postflight is rejected.
- Restart never replays an ambiguous call. Incomplete dispatch is visible.
- Configuration merging preserves existing hooks; reinstall is idempotent.
- Backend/wrapper errors return a valid explicit denial for PreToolUse.
- No prompt/tool output contents or credentials are stored by default; only
  digests and bounded metadata are retained.
- Real hook wire fixtures, installed-wheel smoke tests, and a live Codex trial
  are required before claiming native compatibility.

## Subsequent production gates

- Scope-specific dependency declarations and independent signed evidence sources.
- Automatic exact-image compensation for verified supported file mutations.
- Broader recovery orchestration beyond native local repair/test gating, with
  fine-grained effect compensation and external truth adapters.
- Protected GitHub merge/deployment enforcement and bypass tests.
- Cross-platform/client/version matrix, hook trust UX, crash/race coverage,
  dependency audits, and public installation tests.

A partial gate is reported as partial. No native protection claim inherits the
canonical demo's release attestation.

## Implemented native preview

Native hooks, independent local test-gated recovery, fresh task revisions,
explicit unknown-effect containment, packaging, and installation merging are
implemented. The proof record distinguishes fixture tests from real Codex
sessions. The remaining gates above prevent a general production claim.
