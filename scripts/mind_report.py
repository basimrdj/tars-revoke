#!/usr/bin/env python3
"""Print the Phase 2.5 mind metrics report without booting the assistant."""

from __future__ import annotations

import argparse
import json
import os
import sys


PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

from tars_mind_metrics import MindMetrics  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate TARS mind metrics report.")
    parser.add_argument("--json", action="store_true", help="emit raw JSON instead of markdown")
    parser.add_argument("--project-dir", default=PROJECT_DIR,
                        help="project directory containing TARS logs/state")
    args = parser.parse_args()

    metrics = MindMetrics(args.project_dir)
    report = metrics.report()
    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False, default=str))
    else:
        print(metrics.format_markdown(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
