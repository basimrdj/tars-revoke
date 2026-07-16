# Why TARS REVOKE is not another memory graph

Memory systems preserve context. Knowledge graphs preserve relationships. Agent
observability systems preserve traces. Policy engines decide whether a proposed
action matches a rule.

Those are useful inputs to TARS REVOKE, but none is the product boundary.

TARS turns current evidence into revocable execution authority. An action is
bound to exact premise revisions, artifact hashes, tests, a warrant epoch, and a
short-lived execution lease. The same transaction that invalidates a premise
also fences every reachable lease and materializes the affected hard-dependency
closure. A dispatch that loses that race cannot proceed.

The output is not a better answer from an agent. It is a changed execution
state in the real world:

- affected commands and pushes lose authority;
- unrelated agents retain authority and continue;
- completed effects are inventoried against external reality;
- reversible effects are restored only when their hashes still match;
- irreversible work is quarantined or honestly marked for containment;
- a bounded experiment resolves the disputed fact;
- repaired work receives new IDs, warrants, leases, and replacement edges;
- an independent receipt proves the entire sequence from durable records.

| Product category | Primary question | What it does not enforce |
|---|---|---|
| Memory | What did the agent know? | Whether an old justification may still authorize an effect |
| Knowledge graph | What is connected? | Which persisted edge types revoke live execution authority |
| Observability | What happened? | Whether a pending push must be fenced before it happens |
| Guardrail | Is this proposal allowed now? | Recovery when a previously valid action becomes invalid later |
| TARS REVOKE | Is this action still justified, and what must be undone if not? | — |

The causal graph is therefore an enforcement data structure, not the product.
The memory ledger is evidence, not the product. The wedge is continuous
authorization plus selective recovery across time.

## Claims we deliberately do not make

- Semantic similarity is never treated as causal dependency.
- A model cannot decide the enforcement-time revocation set.
- An already dispatched irreversible effect is never described as rolled back.
- A scripted agent cannot satisfy live-Codex proof requirements.
- A polished dashboard cannot mark a missing proof requirement as complete.

That boundary is what makes the architecture falsifiable and useful rather than
another graph-shaped wrapper.
