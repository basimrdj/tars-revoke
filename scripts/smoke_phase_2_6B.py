import sys
import os
import tempfile
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from tars_build_policies import BuildPolicy
from tars_gemini_runner import GeminiRunner
from tars_patch_review import PatchReview
from tars_build_control import BuildControlPlane

class MockDesireEngine:
    def __init__(self):
        self.desires = [{"id": "des_test", "capability_needed": "parse PDF file", "trigger_phrase": ""}]
    def get_pending(self):
        return self.desires
    def update_status(self, did, stat, **kwargs):
        for d in self.desires:
            if d["id"] == did:
                d["status"] = stat

class MockSkillsLoader:
    def rescan(self): pass

def run_tests():
    print("Testing Policies...")
    policy = BuildPolicy()
    assert policy.classify_risk("parse PDF file") == "medium"
    assert policy.classify_risk("rm -rf /") == "critical"
    assert policy.classify_risk("edit soul") == "high"

    print("Testing Runner...")
    runner = GeminiRunner(print)
    runner.available() # Just to ensure it doesn't crash

    print("Testing Patch Review...")
    rev = PatchReview(print)
    res = rev.review_job("/tmp")
    assert not res["approved"]
    
    print("Testing BuildControlPlane Initialization...")
    engine = MockDesireEngine()
    loader = MockSkillsLoader()
    with tempfile.TemporaryDirectory(prefix="tars-build-smoke-") as tmpdir:
        cp = BuildControlPlane(tmpdir, engine, loader, print)
        jobs = cp.scan_desires()
        assert len(jobs) == 1
        assert jobs[0]["risk"] == "medium"

    print("Smoke Test OK")

if __name__ == "__main__":
    run_tests()
