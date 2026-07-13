import json
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from tars_self_model import _sanitize_note

def clean_file(path: str):
    if not os.path.exists(path):
        print(f"File {path} not found.")
        return

    with open(path, "r", encoding="utf-8") as f:
        state = json.load(f)

    # 1. Clean known_failure_modes
    modes = state.get("known_failure_modes", [])
    new_modes = []
    for m in modes:
        clean = _sanitize_note(m)
        if clean and "Prediction error" not in clean and "World prediction error" not in clean:
            if clean not in new_modes:
                new_modes.append(clean)
    state["known_failure_modes"] = new_modes[:10]

    # 2. Clean lists with deduplication and bounds
    def clean_list(items, check_bounds=False, is_success=True):
        new_items = []
        for item in items:
            note = item.get("note", "")
            clean = _sanitize_note(note)
            if not clean: continue
            
            if check_bounds and "World prediction error=" in clean:
                try:
                    err_str = clean.split("=")[1].split(":")[0]
                    err = float(err_str)
                    if is_success and err > 0.30: continue
                    if not is_success and err < 0.70: continue
                except Exception:
                    pass
                    
            sid = item.get("source_event_id", "")
            is_dup = False
            for ex in new_items:
                if sid and ex.get("source_event_id") == sid:
                    is_dup = True
                    break
                if not sid and not ex.get("source_event_id") and ex.get("note") == clean:
                    is_dup = True
                    break
            if not is_dup:
                item["note"] = clean
                new_items.append(item)
        return new_items

    state["recent_successes"] = clean_list(state.get("recent_successes", []), check_bounds=True, is_success=True)
    state["recent_failures"] = clean_list(state.get("recent_failures", []), check_bounds=True, is_success=False)
    state["evidence"] = clean_list(state.get("evidence", []), check_bounds=False)

    with open(path, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2, ensure_ascii=False)
    print(f"Cleaned {path} successfully.")

if __name__ == "__main__":
    p = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'tars_self_model.json'))
    clean_file(p)
