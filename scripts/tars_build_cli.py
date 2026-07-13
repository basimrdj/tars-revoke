import sys
import os
import json
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from tars_build_control import BuildControlPlane
from tars_evolution import DesireEngine

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 tars_build_cli.py [list|scan|plan <id>|build <id>|test <id>|review <id>|activate <id>]")
        return

    cmd = sys.argv[1]
    project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    desire_engine = DesireEngine(project_dir)
    cp = BuildControlPlane(project_dir, desire_engine, None, print)

    if cmd == "list":
        for jid, job in cp.jobs.items():
            print(f"{jid} - {job['status']} [{job['risk']}] - {job['normalized_request']}")
    elif cmd == "scan":
        jobs = cp.scan_desires()
        print(f"Scanned {len(jobs)} new desires into jobs.")
    elif cmd == "plan" and len(sys.argv) > 2:
        res = cp.plan_job(sys.argv[2])
        print("Planned:", res)
    elif cmd == "build" and len(sys.argv) > 2:
        res = cp.build_job(sys.argv[2])
        print("Built:", res)
    elif cmd == "test" and len(sys.argv) > 2:
        res = cp.run_tests(sys.argv[2])
        print("Tested:", res)
    elif cmd == "review" and len(sys.argv) > 2:
        res = cp.review_job(sys.argv[2])
        print("Reviewed:", res)
    elif cmd == "activate" and len(sys.argv) > 2:
        res = cp.activate_skill(sys.argv[2], require_approval=False)
        print("Activated:", res)
    else:
        print("Unknown command or missing job ID.")

if __name__ == "__main__":
    main()
