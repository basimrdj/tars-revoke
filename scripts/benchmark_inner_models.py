#!/usr/bin/env python3
"""
Benchmark registered cognition models without starting any model servers.

This intentionally probes roles sequentially. It will not run two local MLX
models at once; disabled roles stay skipped unless explicitly requested.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

PROJECT_DIR = Path(__file__).resolve().parents[1]
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from tars_model_registry import ModelRegistry, ModelSpec


BENCHMARK_PROMPTS = [
    {
        "name": "thought_quality",
        "messages": [
            {
                "role": "system",
                "content": "Return JSON only. No prose.",
            },
            {
                "role": "user",
                "content": (
                    "Given this transcript and current goals, produce one private thought. "
                    "It must be specific, useful, and non-repetitive. Return JSON: "
                    '{"thought":"...","kind":"reflection|observation|wish|critique|fragment",'
                    '"salience":0.0,"why_useful":"..."}\n\n'
                    "Transcript: USER: Bro the voice got faster but less expressive. "
                    "ASSISTANT: I can tune the TTS model and keep the fast path.\n"
                    "Current goal: make the agent feel continuous without breaking runtime."
                ),
            },
        ],
    },
    {
        "name": "world_model",
        "messages": [
            {
                "role": "system",
                "content": "Return JSON only. No prose.",
            },
            {
                "role": "user",
                "content": (
                    "Given this current situation, predict likely next user states and "
                    "the best assistant action. Return JSON only: "
                    '{"situation":"...","likely_next_states":["..."],'
                    '"best_action":"...","prediction_confidence":0.0}\n\n'
                    "Situation: The user is reviewing a mind-simulation architecture and "
                    "is frustrated by shallow implementation."
                ),
            },
        ],
    },
    {
        "name": "self_model",
        "messages": [
            {
                "role": "system",
                "content": "Return JSON only. No prose.",
            },
            {
                "role": "user",
                "content": (
                    "Given these recent failures and successes, update the assistant's "
                    "self-model. Return measurable capability estimates only.\n"
                    "Failures: stale workspace winners, missing inner-thought candidates. "
                    "Successes: event bus persisted, appraisal compiled, typed memory added."
                ),
            },
        ],
    },
]


def _json_valid(text: str) -> bool:
    if not text:
        return False
    s = text.strip()
    if s.startswith("```"):
        s = s.strip("`").lstrip("json").strip()
    start = min([i for i in (s.find("{"), s.find("[")) if i >= 0], default=-1)
    if start < 0:
        return False
    s = s[start:]
    try:
        json.loads(s)
        return True
    except Exception:
        return False


def _chat_url(spec: ModelSpec) -> Optional[str]:
    if spec.provider == "mlx":
        return spec.endpoint
    if spec.provider == "openai":
        return "https://api.openai.com/v1/chat/completions"
    return spec.endpoint


def _headers(spec: ModelSpec, registry: ModelRegistry) -> Dict[str, str]:
    headers = {"Content-Type": "application/json"}
    key = registry.resolve_api_key(spec.role)
    if key:
        headers["Authorization"] = f"Bearer {key}"
    return headers


def run_task(spec: ModelSpec, registry: ModelRegistry,
             task: Dict[str, Any], timeout_s: float) -> Dict[str, Any]:
    url = _chat_url(spec)
    if not url:
        return {"name": task["name"], "ok": False, "error": "no endpoint"}
    payload = {
        "model": spec.model,
        "messages": task["messages"],
        "max_tokens": 260,
        "temperature": 0.2,
        "stream": False,
    }
    t0 = time.time()
    try:
        resp = requests.post(
            url, json=payload, headers=_headers(spec, registry), timeout=timeout_s
        )
        latency_ms = (time.time() - t0) * 1000.0
        if resp.status_code != 200:
            return {
                "name": task["name"], "ok": False,
                "latency_ms": round(latency_ms, 1),
                "status": resp.status_code,
                "error": resp.text[:300],
            }
        data = resp.json()
        text = (
            data.get("choices", [{}])[0].get("message", {}).get("content")
            or data.get("choices", [{}])[0].get("text")
            or ""
        ).strip()
        return {
            "name": task["name"],
            "ok": True,
            "latency_ms": round(latency_ms, 1),
            "json_valid": _json_valid(text),
            "chars": len(text),
            "sample": text[:500],
        }
    except Exception as exc:
        return {
            "name": task["name"],
            "ok": False,
            "latency_ms": round((time.time() - t0) * 1000.0, 1),
            "error": f"{exc.__class__.__name__}: {exc}",
        }


def benchmark_role(spec: ModelSpec, registry: ModelRegistry,
                   timeout_s: float) -> Dict[str, Any]:
    results = [run_task(spec, registry, task, timeout_s) for task in BENCHMARK_PROMPTS]
    ok = [r for r in results if r.get("ok")]
    json_ok = [r for r in ok if r.get("json_valid")]
    latencies = [float(r.get("latency_ms", 0.0)) for r in ok]
    return {
        "role": spec.role,
        "provider": spec.provider,
        "model": spec.model,
        "endpoint": spec.endpoint,
        "enabled": spec.enabled,
        "tasks": results,
        "summary": {
            "tasks_ok": len(ok),
            "tasks_total": len(results),
            "json_valid": len(json_ok),
            "json_total": len(ok),
            "avg_latency_ms": round(sum(latencies) / len(latencies), 1)
            if latencies else None,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--role", action="append",
                        help="Role to benchmark. Repeatable. Defaults to enabled roles.")
    parser.add_argument("--include-disabled", action="store_true",
                        help="Include disabled roles. Still runs sequentially.")
    parser.add_argument("--timeout", type=float, default=45.0)
    parser.add_argument("--no-write", action="store_true")
    args = parser.parse_args()

    project_dir = PROJECT_DIR
    registry = ModelRegistry(str(project_dir))
    roles = args.role or registry.enabled_roles()
    if args.include_disabled and not args.role:
        roles = registry.list_roles()

    report = {
        "created_at": datetime.now().isoformat(timespec="seconds"),
        "note": "Sequential probe only; this script does not start local model servers.",
        "results": [],
    }
    for role in roles:
        spec = registry.get(role)
        if spec is None:
            report["results"].append({"role": role, "error": "missing"})
            continue
        if not spec.enabled and not (args.include_disabled or args.role):
            report["results"].append({"role": role, "skipped": "disabled"})
            continue
        report["results"].append(benchmark_role(spec, registry, args.timeout))

    print(json.dumps(report, indent=2, ensure_ascii=False))
    if not args.no_write:
        out_dir = project_dir / "model_benchmarks"
        out_dir.mkdir(exist_ok=True)
        out = out_dir / f"inner_models_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        out.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"\nwrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
