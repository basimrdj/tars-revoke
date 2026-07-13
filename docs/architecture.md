# Architecture

TARS is organized as a local voice-agent runtime plus cognitive bookkeeping
modules. The design is intentionally inspectable: each subsystem emits state or
metrics that can be checked without relying on subjective claims.

## Runtime Loop

1. Speech input is transcribed through the configured STT provider.
2. The orchestrator emits typed events to the event bus.
3. Appraisal scores events for urgency, uncertainty, valence, control, novelty,
   and related signals.
4. The global workspace scores candidates from events, memory, inner thoughts,
   and world-model updates, then broadcasts one winner.
5. The context governor builds a bounded prompt from the system card, recent
   events, memory retrieval, workspace state, world state, and self-model data.
6. The LLM response is cleaned for speech and sent to the configured TTS path.
7. Post-turn events update memory, the world model, the self-model, and metrics.

## Core Components

| Module | Responsibility | Public artifact |
| --- | --- | --- |
| `tars_event_bus.py` | Typed event bus and append-only event log | `tars_events.jsonl` |
| `tars_appraisal.py` | Deterministic event appraisal | event metadata |
| `tars_workspace.py` | Candidate scoring, winner selection, broadcast | `tars_workspace.jsonl` |
| `tars_memory.py` | Episodic/semantic memory, retrieval, hygiene filters | `tars_memory.db`, `tars_kg.jsonl` |
| `tars_sleep.py` | Offline consolidation and contradiction checks | generated reports |
| `tars_world_model.py` | Situation estimate and prediction error | `tars_world_state.json`, `tars_world_predictions.jsonl` |
| `tars_self_model.py` | Capability estimates and failure tracking | `tars_self_model.json` |
| `tars_mind_metrics.py` | Log-derived system metrics | markdown report |
| `tars_evolution.py` | Experimental desire/build worker | `tars_desires.json`, `tars_workshop/` |
| `tars_skills_loader.py` | Dynamic skill discovery and quarantine | loaded skill registry |

## Persistence Policy

Runtime JSON/JSONL/DB files are generated locally and ignored by git because
they may contain private utterances, provider errors, and local machine state.
The repository includes examples and documentation, not live memories.

## Failure Model

The voice path should fail clearly when credentials, quota, microphones, local
models, or provider endpoints are unavailable. Cognitive modules are intended
to fail soft so the assistant can continue with reduced capability rather than
fabricating state.

## Build-Control Boundary

The self-build pipeline is experimental. It should be treated as an untrusted
code-generation workflow until a generated artifact has passed manifest checks,
tests, review, quarantine policy, and explicit activation.
