import sys
import os
import tempfile
import shutil

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from tars_self_model import SelfModel, _sanitize_note

def run_tests():
    temp_dir = tempfile.mkdtemp()
    try:
        sm = SelfModel(temp_dir, log_fn=lambda x: None)
        
        # Test 1: Sanitize
        note1 = _sanitize_note("[Tone: Dry] [pause] Hello world. [inhale]")
        assert note1 == "Hello world.", f"Failed to sanitize TTS tags: {note1}"
        
        note2 = _sanitize_note("Prediction error 0.65: world event is shaping the current context: Prediction error 0.55:")
        assert note2 == "", f"Failed to reject recursive prediction errors: {note2}"
        
        # Test 2: Classification & EWMA Stats
        sm.update_from_prediction_error({"prediction_error": 0.20, "situation": "Perfect match"}, "evt_1")
        state = sm.state()
        assert len(state.get("recent_successes", [])) == 1, f"Success len: {len(state.get('recent_successes', []))}"
        assert len(state.get("recent_failures", [])) == 0
        
        sm.update_from_prediction_error({"prediction_error": 0.50, "situation": "Neutral match"}, "evt_2")
        state = sm.state()
        assert len(state.get("recent_successes", [])) == 1 # unchanged
        assert len(state.get("recent_failures", [])) == 0  # unchanged
        
        sm.update_from_prediction_error({"prediction_error": 0.80, "situation": "Missed completely"}, "evt_3")
        state = sm.state()
        assert len(state.get("recent_successes", [])) == 1
        assert len(state.get("recent_failures", [])) == 1
        
        assert state["prediction_stats"]["count"] == 3
        assert abs(state["prediction_stats"]["avg_error"] - 0.50) < 0.01
        
        # Test 3: Deduplication
        sm.update_from_prediction_error({"prediction_error": 0.20, "situation": "Perfect match"}, "evt_1") # duplicate evt_id
        state = sm.state()
        assert len(state.get("recent_successes", [])) == 1 # unchanged
        
        # Test 4: Failure modes
        assert len(state.get("known_failure_modes", [])) == 3 # defaults + 1 from 0.8 error
        assert "World model badly missed a recent transition." in state.get("known_failure_modes")
        
        print("Self-Model Hygiene - Smoke Test PASSED.")
    finally:
        shutil.rmtree(temp_dir)

if __name__ == "__main__":
    run_tests()
