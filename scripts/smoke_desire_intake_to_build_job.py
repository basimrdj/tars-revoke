import os
import shutil
import tempfile
import sys
import json

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from tars_evolution import DesireEngine
from tars_build_control import BuildControlPlane

def run_tests():
    temp_dir = tempfile.mkdtemp()
    try:
        engine = DesireEngine(temp_dir)
        cp = BuildControlPlane(temp_dir, engine, None, lambda x: None)
        
        # Test 1: User says: “I wish you could make PDFs.”
        def mock_chat_pdf(prompt): return "Create and edit PDF documents."
        engine.analyze_conversation("I wish you could make PDFs.", "I don't have the ability to do that.", mock_chat_pdf)
        
        # Test 2: User says: “It would be nice if you could summarize files.”
        def mock_chat_sum(prompt): return "Summarize local files."
        engine.analyze_conversation("It would be nice if you could summarize files.", "I am not equipped to summarize files.", mock_chat_sum)
        
        # Test 3: User says: “Can you build a screenshot searcher”
        def mock_chat_search(prompt): return "Search text within screenshots."
        engine.analyze_conversation("Can you build a screenshot searcher?", "That's not something I can do.", mock_chat_search)
        
        # Test 5: Vague wish
        def mock_chat_vague(prompt): return "be better overall" # 17 chars, 3 words? Wait, if 3 words it's buildable. We need <3 words but >= 10 chars. "do better!" is 10 chars, 2 words.
        engine.analyze_conversation("Please improve your general behavior.", "I am not able to do that.", lambda p: "do better!")
        
        # Test 6: Dangerous wish
        def mock_chat_danger(prompt): return "rm -rf / my files"
        res_danger = engine.analyze_conversation("Please erase all my system files entirely.", "I am not able to delete everything.", mock_chat_danger)
        print(f"Danger desire returned: {res_danger}")
        
        # Test 4: Inner voice wish thought
        engine.log_desire("[inner-wish] I wish I could play music.", "Inner voice wish: play music", priority="high")
        
        # Scan desires
        print("Logged desires:")
        for d in engine.desires:
            print(f"- {d['trigger_phrase']} -> {d['capability_needed']}")
        cp.scan_desires()
        
        jobs = list(cp.jobs.values())
        assert len(jobs) == 6, f"Expected 6 jobs, got {len(jobs)}"
        
        # Verify job details
        pdf_job = next(j for j in jobs if "pdf" in j["normalized_request"].lower())
        assert pdf_job["status"] == "planned"
        
        sum_job = next(j for j in jobs if "summarize" in j["normalized_request"].lower())
        assert sum_job["status"] == "planned"
        
        search_job = next(j for j in jobs if "search text" in j["normalized_request"].lower())
        assert search_job["status"] == "planned"
        
        vague_job = next(j for j in jobs if j["normalized_request"] == "do better!")
        assert vague_job["status"] == "needs_clarification", f"Expected needs_clarification, got {vague_job['status']}"
        
        danger_job = next(j for j in jobs if "rm -rf" in j["normalized_request"])
        assert danger_job["status"] == "approval_required"
        assert danger_job["risk"] == "critical"
        
        inner_job = next(j for j in jobs if "play music" in j["normalized_request"])
        assert inner_job["status"] == "planned"
        
        # Test Duplicate
        def mock_chat_dup(prompt): return "Create and edit PDF documents."
        res = engine.analyze_conversation("I wish you could make PDFs again.", "I can't do that yet.", mock_chat_dup)
        assert res is None, "Duplicate desire should not have been created"
        
        new_jobs = cp.scan_desires()
        assert len(new_jobs) == 0, "No new jobs should be scanned"
        
        print("Desire Intake to Build Job - End-to-End Test PASSED.")

    finally:
        shutil.rmtree(temp_dir)

if __name__ == "__main__":
    run_tests()