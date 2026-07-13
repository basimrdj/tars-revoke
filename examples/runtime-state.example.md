# Runtime State Examples

The agent creates local state files during normal use. They are ignored because
they can contain transcripts, user preferences, provider errors, local paths,
and generated code.

Typical generated files:

- `tars_events.jsonl`: typed event stream.
- `tars_workspace.jsonl`: global-workspace frames and winners.
- `tars_thoughts.jsonl`: local inner-model outputs.
- `tars_memory.db`: episodic/semantic memory store.
- `tars_kg.jsonl`: extracted semantic triples.
- `tars_world_state.json`: compact state estimate.
- `tars_world_predictions.jsonl`: predictions and resolution/error records.
- `tars_self_model.json`: capability estimates and failure notes.
- `tars_desires.json`: experimental build queue.
- `tars_workshop/`: generated skill drafts and review artifacts.

Minimal neutral examples:

```json
{"source":"user","kind":"user_turn","content":"What can you do offline?","severity":"info"}
```

```json
{
  "capabilities": {
    "voice_stability": 0.5,
    "stt_reliability": 0.5,
    "tts_consistency": 0.5,
    "memory_recall": 0.5,
    "inner_thought_quality": 0.5,
    "world_model_accuracy": 0.5,
    "goal_pursuit": 0.5,
    "skill_building": 0.5,
    "social_attunement": 0.5
  },
  "known_failure_modes": [],
  "active_uncertainties": ["No live evaluation has been run yet."]
}
```
