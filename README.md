# TARS / MiMo Test Agent

TARS is a local voice-agent research prototype focused on durable memory,
reflection, and measurable agent-cognition scaffolding.

It combines a realtime voice loop with typed memory, an event bus, appraisal
signals, a global workspace, an inner-voice loop, sleep/consolidation reports,
a world model, a self-model, and capability-truth rules.

This repository does **not** claim consciousness or sentience. It demonstrates
engineering patterns for making an assistant more continuous, inspectable, and
honest about what it can and cannot do.

## Highlights

- Realtime voice loop with Deepgram STT, MiMo/OpenAI-compatible LLM providers,
  text cleanup, TTS chunking, and reconnection handling.
- SQLite-backed episodic memory with semantic retrieval hooks, salience decay,
  typed records, and provenance.
- Event bus plus appraisal variables for deciding which events deserve
  attention.
- Global workspace frames that select and broadcast high-salience candidates.
- Inner-voice loop with salience gates and runtime-noise quarantine.
- Sleep/consolidation reports and mind metrics for offline evaluation.
- World-model predictions and self-model state for measuring continuity over
  time.
- Profile-edit subsystem with logged, inspectable changes.

## Repository Map

```text
mimo_apple_realtime_assistant.py  # main voice-assistant runtime
tars_memory.py                    # episodic/semantic memory store
tars_event_bus.py                 # cognitive event bus
tars_appraisal.py                 # appraisal variable extraction
tars_workspace.py                 # global workspace selection
tars_inner_voice.py               # reflection loop
tars_sleep.py                     # consolidation passes
tars_world_model.py               # prediction tracking
tars_self_model.py                # quantitative self-model state
tars_mind_metrics.py              # offline metrics/report builder
tars_self.py                      # profile update/logging subsystem
scripts/                          # smoke tests, reports, probes
docs/                             # architecture and runtime research notes
```

## Setup

Create a local environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -U pip
```

Install the runtime dependencies you need for the integrations you enable.
Core offline inspection scripts use the Python standard library plus `numpy`.
Live voice integrations require additional packages and credentials.

```bash
cp .env.example .env
```

## Safe Verification

These commands do not require committing private state:

```bash
python -m py_compile \
  tars_memory.py \
  tars_event_bus.py \
  tars_appraisal.py \
  tars_workspace.py \
  tars_mind_metrics.py \
  tars_self.py

python scripts/smoke_memory_hygiene.py
python scripts/smoke_self_model_hygiene.py
```

If you provide sanitized sample data, you can also run:

```bash
python scripts/mind_report.py --json
```

## Optional Integrations

- OpenAI-compatible embeddings and chat providers
- Deepgram realtime STT
- MiMo TTS / MiMo Omni
- MLX local model server
- VibeVoice subprocess TTS
- Screen, calendar, and other local sensors

All sensors and external services should be opt-in. Runtime logs, memory DBs,
audio files, and personal state are intentionally gitignored.

## Public Demo Guidance

For a public portfolio demo, use sanitized sample memory and recorded terminal
output. Avoid publishing private conversations, raw audio, credentials, or
personal profile data.

## License

MIT. See `LICENSE`.
