# Project Roadmap

TARS is a local experimental voice-agent architecture for studying measurable
agent cognition and memory. The goal is not to prove consciousness. The goal is
to build and evaluate mechanisms that support continuity, self-observation, and
autonomous maintenance in a way a reviewer can inspect.

## Current Architecture Focus

1. Voice loop: STT, LLM, TTS, interruption handling, provider failure hygiene.
2. Event bus: typed append-only cognitive events with appraisal metadata.
3. Global workspace: candidate scoring, winner selection, broadcast, and
   duplicate suppression.
4. Memory: episodic/semantic storage, salience, retrieval, and privacy filters.
5. Sleep/consolidation: deduplicate, summarize, identify contradictions, and
   emit reports.
6. World model: current-situation estimate, next-state predictions, prediction
   error.
7. Self-model: numeric capability estimates, confidence calibration, drift,
   failures, and successes.
8. Build control: desire queue, sandbox/workshop generation, review, quarantine,
   and activation controls.

## Public Release Criteria

- No committed secrets, `.env` files, live logs, private transcripts, memory
  databases, generated workshop outputs, or bundled private audio/model assets.
- Public docs describe implemented mechanisms and tests, not subjective claims.
- Safe smoke tests compile/import without provider credentials.
- Provider-backed scripts fail clearly when credentials are absent.
- Autonomous build features are documented as experimental and disabled or
  constrained by explicit configuration.

## Near-Term Improvements

- Add a small fixture-driven evaluation suite for event/appraisal/workspace
  behavior.
- Add tests for memory hygiene filters and provider-error sanitization.
- Add CI that runs `py_compile` and safe smoke scripts.
- Split provider integrations behind clearer interfaces.
- Document exact dependency installation once the runtime environment is
  reduced to reproducible requirements.
