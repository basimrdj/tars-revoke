# TARS REVOKE for Codex

**Developer preview: automatic local requirements checks and test-gated recovery.**

TARS attaches to Codex's supported local lifecycle hooks. Use Codex normally:
TARS records the task revision and tool admissions, detects watched requirement
changes, blocks stale work, lets Codex repair local files, and independently
runs the configured test suite before accepting the new baseline.

This integration is tested on macOS with Codex CLI 0.148.0 and Python 3.12. The preview requires Python 3.11+.
The original billing demo and its R-01–R-20 attestation remain separate.

## Install

Install a built wheel from the GitHub prerelease assets in an isolated tool
environment, then enable TARS in your project:

```bash
uv tool install /path/to/tars_revoke-0.2.0a1-py3-none-any.whl
cd /path/to/your/project
tars-revoke codex setup
```

Setup merges TARS's groups into `.codex/hooks.json`, preserving existing hooks
and retaining a backup. It stores private state under ignored `.tars/`.
Restart or resume Codex, then review and trust the hooks through `/hooks` in the
CLI or **Settings > Hooks** in the desktop app. Hooks provide no protection
until Codex trusts and runs them. Setup never bypasses that review.

By default TARS watches `AGENTS.md`, `TARS.md`, and `SPEC.md`, including later
creation or deletion. Specify the real requirements for your project when
needed:

```bash
tars-revoke codex setup --watch AGENTS.md --watch docs/requirements.md \
  --test 'python3 -m pytest -q'
```

`--test` is parsed into an argument array and executed without a shell. Configure
one bounded suite command, for example a script that runs targeted and full
tests. TARS can discover pytest in Python projects and `npm test` in JavaScript
projects. Review the discovered command in `.tars/codex.json`. Native recovery
runs it with a minimal environment and a 120-second timeout. Applications needing
longer tests, extra environment, databases, or external services need a dedicated
adapter; the integration does not silently inherit credentials.

Re-running setup preserves an existing watch policy. Edit `.tars/codex.json`
explicitly to change that policy. An explicit `--test` updates the suite.

## What happens automatically

1. Session startup records a baseline of watched requirement hashes.
2. New prompts get immutable session-scoped task revisions. Old turns cannot
   reuse the new turn's authorization.
3. Each supported local tool call gets a prepared effect, exact warrant,
   one-shot lease, and transactional dispatch through the existing TARS kernel.
   TARS never returns an approval that overrides Codex's permission rules.
4. Post-tool hooks record observations, not an invented command-success claim.
5. A requirement change blocks stale work and creates a fresh repair revision.
   Recovery permits local `apply_patch`, bounded `cat` reads, `pwd`, `git diff`,
   `git status --short`, and the configured test command. General shell commands,
   publishing, and edits to TARS policy or watched requirements are blocked in
   that recovery phase.
6. Codex repairs the local code. When Codex stops, TARS executes the configured
   suite itself, records real test results, and accepts the fresh baseline only
   after success. Failed verification sends bounded feedback to Codex for up to
   three attempts. Missing tests stop recovery without claiming success.

Plain-language prompt changes create new task revisions. TARS does not claim
it can independently infer every semantic contradiction or map every affected
file from conversation alone. Requirement-file changes are the deterministic
automatic trigger in this preview. All watched requirements conservatively
apply to their session; fine-grained per-action evidence dependencies remain a
production gate.

## Inspect and recover ambiguous effects

```bash
tars-revoke codex status
```

Status verifies the event chain and shows changed requirements, observed calls,
unobserved calls, containment records, and the test policy. Separate Codex
sessions have separate runs and task revisions.

If Codex or the host crashes between preflight and observation, TARS never
replays that command. An operator can record the missing completion as unknown:

```bash
tars-revoke codex contain --session SESSION_ID
```

Inspect the real filesystem, remote, database, or API before deciding how to
proceed. If the operator accepts the remaining partial-effect risk:

```bash
tars-revoke codex accept --session SESSION_ID --acknowledge-partial-effects
```

Ordinary `accept` is also an explicit operator escape hatch for a requirements
change that needs manual recovery. Acceptance never claims rollback or verified
repair. Codex must not invoke these commands itself to bypass a block.

To disable checks while preserving history and other hooks:

```bash
tars-revoke codex disable
```

Run setup again to re-enable.

## Optional manual plugin distribution

The repository includes `plugins/tars-revoke` and a GitHub marketplace at
`.agents/plugins/marketplace.json`. The plugin packages the recovery skill and
lifecycle hooks. Developers who install it manually need the same Python backend
and per-repository watch/test policy. After installing the plugin, configure
that policy without adding duplicate direct hooks:

```bash
tars-revoke codex setup --plugin
```

The backend must be available on Codex's `PATH` for plugin mode. Direct setup
uses an absolute interpreter path and is more reliable across desktop launch
environments.

Use either direct setup hooks or plugin hooks in a repository. Installing both
causes duplicate admission attempts, which TARS denies rather than executing
twice. Direct setup is the tested onboarding path in this preview.

OpenAI's current packaging rules exclude plugins containing lifecycle hooks
from the public plugin directory. GitHub/manual installation remains available:
[official plugin packaging documentation](https://developers.openai.com/plugins/build/plugins#bundled-mcp-servers-and-lifecycle-hooks).
This is a third-party integration, not an OpenAI endorsement.

## Protection boundary

Native mode is cooperative local protection. Codex executes a tool after its
pre-tool hook returns; requirements can change between those boundaries. Codex
can skip untrusted/disabled hooks, and some host-side hook errors can let a tool
run. The TARS entry point emits an explicit denial for handled backend errors,
but cannot control a hook that the host never executes.

TARS state and policy share the repository owner's trust boundary. An agent or
administrator with equivalent filesystem access can alter them. This is not a
malicious-agent isolation boundary. Hosted tools outside local hook coverage,
GitHub branch rules, arbitrary remote API effects, and remote credential
protection are not qualified by this integration.

Native recovery does not automatically reverse arbitrary existing edits,
commits, migrations, pushes, or API calls. It preserves work and coordinates a
fresh local repair. The original isolated scenario demonstrates exact
compensation and protected-remote enforcement; general production adapters
still need separate implementation and qualification.

Prompts, tool arguments, and tool responses are hashed rather than stored by the
native hook recorder. Test command arguments and bounded failure output are
recorded; avoid inline credentials. Treat `.tars/` as private project data.

See [the delivery contract](IMPLEMENTATION.md) for remaining production gates.
