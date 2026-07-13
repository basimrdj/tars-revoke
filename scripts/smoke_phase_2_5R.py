import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from tars_context_governor import ContextGovernor

soul = """## Identity
I am TARS.
## Personality
Deadpan.
## Reality / Capability Discipline
I do not lie.
## Voice Rules
[Tone: Deadpan]
## Self-Modification Log
- 2026-05-01 14:40 — log 1
- 2026-05-01 14:40 — log 2
- 2026-05-01 14:40 — log 3
- 2026-05-01 14:40 — log 4
"""

ws_frame = {"winner": {"source": "user", "proposed_action": "think"}}
appraisal = {"uncertainty": 0.2}

governor = ContextGovernor()
core = governor.extract_soul_core(soul)
assert "Self-Modification Log" not in core, "Failed to strip soul log"
assert "Identity" in core, "Failed to keep identity"

print("ContextGovernor Budget Enforcement OK")
