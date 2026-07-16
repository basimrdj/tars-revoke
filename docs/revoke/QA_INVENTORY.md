# Operator Console QA Inventory

This inventory is the browser sign-off contract for the API-fed TARS REVOKE
operator console. A screenshot is supporting evidence, not proof by itself; all
post-run claims must be backed by the persisted run snapshot and independent
receipt verification.

## User-visible claims

| Claim | Functional check | Visual state | Evidence |
| --- | --- | --- | --- |
| The console starts from real API state | Load a fresh server and observe the current-run request | Empty desktop and mobile views | Network log, accessibility snapshot, screenshots |
| A real live run can be started from the primary control | Click **Run live demo** and observe the POST followed by streamed snapshots | Starting and active states | API request, live snapshot sequence, screenshot |
| Exactly the affected Agent A effects are revoked while Agent B continues | Compare rendered lanes, graph closure, and effect inventory with the final snapshot | Dense post-revocation state | Final API snapshot, desktop screenshot |
| Every consequential stage is gateway-accounted | Compare the receipt authorization coverage with the durable warrant/action/effect/lease inventory for the exact eleven canonical stages | Completed receipt and inspector state | Final API snapshot, state database, independent verifier output |
| The smallest decisive experiment and result are inspectable | Match selected candidate and exit code to the persisted experiment record | Completed experiment panel | Final API snapshot, focused screenshot |
| Recovery produces a verifiable receipt | Click **Verify receipt** and require a successful verified state | Completed receipt panel | Verify response, receipt digest, screenshot |
| The interface remains usable at a realistic phone width | Repeat empty and dense-state inspection at 390 x 844 | Mobile empty and completed states | Mobile screenshots and overflow measurements |

## Controls and state transitions

| Control | Initial state | Interaction | Expected state |
| --- | --- | --- | --- |
| Run live demo | Enabled when idle | Mouse click | Disabled with `Starting...`, then active snapshots stream |
| Header receipt verification | Disabled without a receipt | Mouse click after completion | Receipt remains or becomes `verified` |
| Receipt-panel verification | Hidden without a receipt | Mouse click after completion | Same verified receipt digest is retained |
| Retry error action | Hidden normally | Induce an unavailable API or rejected concurrent start, then click | Snapshot refresh is attempted and alert remains actionable if the fault persists |
| Warrant selection | Empty before a run | Select an available warrant in a populated run | Inspector shows the corresponding premise, evidence, tests, and revocation reason |

## View and integrity checks

- Desktop viewport: 1600 x 900; inspect the empty view, active transition, and
  densest completed view.
- Mobile viewport: 390 x 844; inspect header controls, all panels through normal
  scrolling, and absence of horizontal overflow.
- Confirm readable contrast, stable layering, no clipped primary controls, no
  overlapping graph labels, and no content pretending that scripted mode is a
  live Codex run.
- Confirm every completed-state ID, count, digest, and status visible in the UI
  originates in `/api/runs/{id}` rather than a frontend constant.

## Exploratory checks

1. Double-click the run control quickly. The server must allow at most one active
   canonical run and the console must surface the rejection without losing the
   first run.
2. Attempt receipt verification before completion and after completion. The first
   attempt must be unavailable or rejected; the second must recompute the proof.
3. Reload during an active run. The console must reconnect to the current run and
   continue from durable sequence state rather than inventing a fresh timeline.
   If startup finds a persisted `DISPATCHING` push, it must render the durable
   observe-never-replay reconciliation outcome; reload must not cause another
   push.
4. Stop the API temporarily and use **Retry**. The connection failure must be
   visible and recovery must not create a new run.

## Executed browser evidence

The operator-console candidate was exercised against the packaged API shape with a
durably recovered completed scripted run. Scripted mode was visibly labelled;
no live-Codex or R-01 through R-20 release claim was inferred from this UI
fixture.

| Check | Result | Evidence |
| --- | --- | --- |
| Desktop dense state at 1600 x 900 | Passed; document width and height exactly matched the viewport, with the primary controls, focused graph, timeline, three affected effects, unrelated lane, experiment, and receipt visible | `web/design/qa-completed-desktop.png` |
| Independent receipt verification | Passed; the control issued `POST /api/runs/{id}/verify`, received HTTP 200, and retained `VERIFIED` | Browser network log and API integration tests |
| Current-load console health | Passed; zero new console errors or warnings after the final server restart and navigation | Browser console inspection |
| Mobile dense state at 390 x 844 | Passed; document `scrollWidth` equalled `clientWidth` (390 px), all panels were reachable by vertical scrolling, and the verification control remained fully inside the viewport | `web/design/qa-completed-mobile.png` |
| Mobile timeline reachability | Passed; the 1,236 px timeline track scrolled to its 846 px maximum and exposed the final `Receipt verified` milestone inside the viewport | Browser geometry inspection |
| Mobile independent verification | Passed; the bottom control recomputed the receipt and retained `VERIFIED` with `scrollX = 0` | Browser interaction and geometry inspection |
| Unknown API route behavior | Passed; `/api/not-a-real-route` returned JSON HTTP 404 rather than the frontend shell | Browser fetch and API integration test |

The live-run control is covered by API/run-manager integration tests. It was
intentionally not clicked during this scripted browser fixture because that
would start another metered Codex run and would mix two evidence scopes. The
checked-in screenshots therefore cannot satisfy the live-Codex requirement.

## Release qualification checks

Browser sign-off remains separate from strict release qualification. From a
clean source checkout, the release candidate must also pass:

```bash
make test-web
python3 tools/qualify_release.py \
  --source . \
  --workspace /tmp/tars-revoke-qualification
```

The qualification driver clones the exact source commit, executes build and
archive gates, performs exactly three sequential live Codex runs, runs
CrashBench-11 and RevokeBench-20, builds `release-attestation.json`, and invokes
the strict verifier. Only that resulting immutable proof can establish R-01
through R-20. Until it succeeds, this inventory records UI evidence and test
expectations only.
