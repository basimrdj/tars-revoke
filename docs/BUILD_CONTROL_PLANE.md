# Build Control Plane (Phase 2.6B)

## Overview
This document describes the Architecture-Aligned Build Control Plane for TARS's self-evolution mechanism. 
It closes the loop identified in the Phase 2.5 `TARS_ARCHITECTURE_MAP.md` missing bridge:
`desire → Gemini CLI plan → sandbox build → tests → patch review → skill activation`

## Components
- `tars_build_control.py`: The orchestrator for the build plane. Scans `tars_desires.json` and creates tasks in `tars_build_jobs.jsonl`.
- `tars_build_policies.py`: Manages the risk classification of capabilities (e.g. low, medium, high, critical) and default environment flags for sandbox isolation.
- `tars_gemini_runner.py`: A safe wrapper around the Gemini CLI that produces structured build directories inside `tars_workshop/jobs/`.
- `tars_patch_review.py`: Static analysis against generated skills looking for dangerous syntax like `rm -rf`, `os.system`, or credential leakage. 

## Job Lifecycle
Each build starts as a Desire and progresses through statuses:
1. `proposed` or `needs_clarification` (vague request)
2. `planned` -> `approved_for_build`
3. `building` (Gemini CLI in action)
4. `tests_running` (Sandbox verification)
5. `review_needed` (PatchReview static analysis)
6. `activation_pending` (Ready for production)
7. `active` (Loaded dynamically by `tars_skills_loader.py`)

Failed jobs fall into `failed` or `rejected` state if they don't pass the patch review or build cleanly.

## Risk Tiers
- **Tier 0**: Plan/Think only
- **Tier 1**: Sandbox build in `tars_workshop/jobs/<id>`
- **Tier 2**: Skill activation into `tars_skills/`
- **Tier 3**: Core TARS modifications
- **Tier 4**: Dangerous or critical commands

Low risk skills may automatically bypass manual activation triggers, depending on `TARS_BUILD_AUTO_ACTIVATE_LOW_RISK`.

## Integration
`mimo_apple_realtime_assistant.py` and `tars_evolution.py` instantiate `BuildControlPlane`. The EvolutionWorker delegates its legacy background builder loop to `BuildControlPlane.tick()`. This provides safe handoffs, transparent jsonl tracking, and robust static checking prior to dynamic loading.
