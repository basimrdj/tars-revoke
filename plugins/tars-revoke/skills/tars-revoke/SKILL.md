---
name: tars-revoke
description: Follow automatic TARS requirements-change recovery, inspect durable tool observations, and repair local code under fresh task revisions in Codex.
---

TARS performs cooperative local checks through native Codex hooks. Its messages
are runtime observations; never claim that an admission proves command success,
that all effects were undone, or that a hosted push/deployment was fenced.

When requirements change, follow the hook's recovery packet:

1. Read the latest requirements with simple `cat` commands from the project root.
2. Inspect the affected local code and preserve user changes.
3. Repair local files with `apply_patch`. Use repository-relative paths. Do not
   modify watched requirements, `.tars/`, `.codex/`, or Git metadata to escape a
   block. General commands and publishing are blocked during recovery.
4. Stop when the local repair is ready. TARS independently executes its
   configured suite, persists real results, and accepts the new baseline after
   success. If it returns failing-test feedback, repair the cause and stop
   again. It permits up to three verification attempts.
5. Report actual verification evidence and any remaining uncertainty.

Never replay an unobserved call, reset user work, force push, or undo an external
API/database effect speculatively. Unknown effects require operator inspection.
Do not run `tars-revoke codex accept` or `contain` yourself to bypass protection.
Missing tests, exhausted attempts, and containment need operator attention.

Install the Python backend and use `tars-revoke codex setup` for direct setup.
Do not install both direct hooks and plugin hooks in the same repository.
Review/trust hooks through Codex's normal hook UI. See docs/codex/README.md in the
GitHub repository for the integration's exact scope and limitations.
