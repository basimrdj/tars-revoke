# TARS REVOKE operator UI design system

Concept reference: `design/operator-concept.png`

## Composition

- Desktop target: 1728 x 1080, dense single-screen command center.
- Header: 56 px, wordmark, live run, elapsed time, run control, receipt verification.
- Primary grid: 320 px agent rail, fluid causal canvas, 360 px warrant inspector.
- Bottom: full-width event timeline followed by effects, experiment, and receipt rails.
- Containers use straight architectural rails and one-pixel dividers; avoid nested rounded cards.
- Mobile becomes an ordered vertical narrative: controls, agents, graph, warrant, timeline, proof panels.

## Tokens

- Canvas `#05090b`; surface `#0a1013`; raised `#0e1519`.
- Border `#263238`; strong border `#39474d`.
- Primary text `#eef2ef`; secondary `#97a3a8`; faint `#657278`.
- Revoked `#ff5c47`; warning `#f2a53b`; verified `#42d58b`; evidence `#4b9cff`.
- UI type: Inter/system sans, 12-14 px. IDs/times: JetBrains Mono/system monospace.
- Radius: 3 px controls, 5 px selected nodes only. No pill decoration.
- Motion: 160 ms state transitions; live pulse 1.8 s; disabled under reduced motion.

## Required information hierarchy

1. Exactly which premise changed.
2. Exactly which three effects were revoked.
3. Why Agent B continued.
4. What was restored versus quarantined.
5. Which experiment was selected and why.
6. Whether Codex repaired, tests passed, and a new lineage resumed.
7. Whether the receipt independently verifies.

All labels are populated from the API. The frontend may compute layout, never conclusions.
