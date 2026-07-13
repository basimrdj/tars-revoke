"""
TARS Cron + Heartbeat
=====================

A simple interval-based scheduler. Stores jobs in `tars_cron.json` so they
survive restarts. Runs in a single background thread.

Job schema:
    {
        "id":       "heartbeat",            # unique
        "action":   "heartbeat",            # name registered with the scheduler
        "every_s":  900,                    # interval in seconds
        "enabled":  true,
        "last_run": "ISO timestamp"|null,
        "kwargs":   {}                      # passed to the action
    }

Built-in actions (registered by the orchestrator):
    - heartbeat      — TARS reflects on recent activity, may queue desires
                       or self-modifications.
    - rescan_skills  — refresh dynamic skill loader from disk.
    - self_audit     — TARS reads his own SOUL.md and recent learnings,
                       decides whether anything needs revising.

The LLM can ALSO ask the scheduler to add jobs via the tag:

    [Cron Add: <id> every <N>m action=<action_name>]

…which is parsed by the orchestrator and forwarded to `add_job`.
"""

from __future__ import annotations

import json
import os
import re
import threading
import time
from datetime import datetime
from typing import Callable, Dict, List, Optional


CRON_FILE = "tars_cron.json"


DEFAULT_JOBS: List[Dict] = [
    {
        "id": "heartbeat",
        "action": "heartbeat",
        "every_s": 15 * 60,            # every 15 minutes
        "enabled": True,
        "last_run": None,
        "kwargs": {},
    },
    {
        "id": "rescan_skills",
        "action": "rescan_skills",
        "every_s": 5 * 60,
        "enabled": True,
        "last_run": None,
        "kwargs": {},
    },
    {
        "id": "self_audit",
        "action": "self_audit",
        "every_s": 6 * 60 * 60,        # every 6 hours
        "enabled": True,
        "last_run": None,
        "kwargs": {},
    },
]


class CronScheduler:
    """Interval-based scheduler that persists jobs to disk."""

    ADD_TAG_RE    = re.compile(
        r"\[Cron Add:\s*(?P<id>[\w\-]+)\s+every\s+(?P<n>\d+)(?P<u>[smh])\s+"
        r"action=(?P<act>[\w\-]+)\]",
        re.IGNORECASE,
    )
    REMOVE_TAG_RE = re.compile(r"\[Cron Remove:\s*(?P<id>[\w\-]+)\]", re.IGNORECASE)
    STRIP_ALL_RE  = re.compile(
        r"\[Cron (?:Add|Remove):[^\]]*\]", re.IGNORECASE,
    )

    # V8: don't fire cron jobs while a user turn is being processed.
    # The orchestrator passes in a callable that returns True if a turn is busy.
    MAX_DEFER_SECONDS = 30 * 60   # cron may wait up to 30 min for the user to be idle

    # Phase 0: circuit breaker. If an action raises 3 times in a row OR a job's
    # callable returns False (when bool-checked), disable the JOB until reload.
    CIRCUIT_BREAKER_THRESHOLD = 3

    def __init__(self, project_dir: str, log_fn,
                 busy_predicate: Optional[Callable[[], bool]] = None):
        self.project_dir = project_dir
        self.log = log_fn
        self.path = os.path.join(project_dir, CRON_FILE)
        self._lock = threading.Lock()
        self._actions: Dict[str, Callable[..., None]] = {}
        self.jobs: List[Dict] = self._load()
        self._thread: Optional[threading.Thread] = None
        self._running = False
        # If None, cron never defers. The orchestrator wires a real predicate.
        self._busy = busy_predicate or (lambda: False)
        # Track first-deferral timestamp per job (so we can break the lock after MAX_DEFER_SECONDS)
        self._defer_started: Dict[str, float] = {}
        # Phase 0: per-job consecutive-failure counters
        self._fail_counts: Dict[str, int] = {}

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------
    def _load(self) -> List[Dict]:
        if os.path.exists(self.path):
            try:
                with open(self.path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, list):
                    return data
            except Exception:
                pass
        return [dict(j) for j in DEFAULT_JOBS]

    def _save(self) -> None:
        try:
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self.jobs, f, indent=2, default=str)
            os.replace(tmp, self.path)
        except Exception as e:
            self.log(f"[cron] save failed: {e}")

    # ------------------------------------------------------------------
    # Action registry
    # ------------------------------------------------------------------
    def register_action(self, name: str, fn: Callable[..., None]) -> None:
        self._actions[name] = fn

    # ------------------------------------------------------------------
    # Mutators
    # ------------------------------------------------------------------
    def add_job(self, job_id: str, action: str, every_s: int,
                kwargs: Optional[Dict] = None, enabled: bool = True,
                defer_first: bool = False) -> None:
        first_run_anchor = datetime.now().isoformat() if defer_first else None
        with self._lock:
            for j in self.jobs:
                if j["id"] == job_id:
                    j["action"]   = action
                    j["every_s"]  = max(30, int(every_s))
                    j["kwargs"]   = kwargs or {}
                    j["enabled"]  = bool(enabled)
                    if defer_first and not j.get("last_run"):
                        j["last_run"] = first_run_anchor
                    self._save()
                    self.log(f"[cron] updated job {job_id!r}")
                    return
            self.jobs.append({
                "id": job_id,
                "action": action,
                "every_s": max(30, int(every_s)),
                "enabled": bool(enabled),
                "last_run": first_run_anchor,
                "kwargs": kwargs or {},
            })
            self._save()
            self.log(f"[cron] added job {job_id!r} (every {every_s}s, action={action})")

    def remove_job(self, job_id: str) -> bool:
        with self._lock:
            before = len(self.jobs)
            self.jobs = [j for j in self.jobs if j["id"] != job_id]
            removed = len(self.jobs) < before
            if removed:
                self._save()
                self.log(f"[cron] removed job {job_id!r}")
            return removed

    def list_jobs(self) -> List[Dict]:
        with self._lock:
            return [dict(j) for j in self.jobs]

    # ------------------------------------------------------------------
    # Tag parsing — the LLM can issue scheduler commands inline
    # ------------------------------------------------------------------
    def apply_tags_in(self, reply: str) -> str:
        """Parse [Cron Add:] / [Cron Remove:] tags and return a clean reply."""
        if not reply:
            return reply
        for m in self.ADD_TAG_RE.finditer(reply):
            n = int(m.group("n"))
            u = m.group("u").lower()
            secs = n * (1 if u == "s" else 60 if u == "m" else 3600)
            self.add_job(m.group("id"), m.group("act"), secs)
        for m in self.REMOVE_TAG_RE.finditer(reply):
            self.remove_job(m.group("id"))
        return self.STRIP_ALL_RE.sub("", reply).strip()

    # ------------------------------------------------------------------
    # Background loop
    # ------------------------------------------------------------------
    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run_loop, daemon=True,
                                        name="TarsCron")
        self._thread.start()
        self.log(f"[cron] started ({len(self.jobs)} job(s))")

    def stop(self) -> None:
        self._running = False

    def _run_loop(self) -> None:
        time.sleep(20)
        while self._running:
            try:
                now = time.time()
                with self._lock:
                    snapshot = [dict(j) for j in self.jobs]
                user_busy = False
                try:
                    user_busy = bool(self._busy())
                except Exception:
                    user_busy = False

                for job in snapshot:
                    if not job.get("enabled", True):
                        continue
                    last = job.get("last_run")
                    last_ts = self._parse_iso(last) if last else 0
                    if (now - last_ts) < job.get("every_s", 600):
                        continue
                    fn = self._actions.get(job["action"])
                    if not fn:
                        continue

                    # V8: defer if a user turn is in flight, but break the lock
                    # if we've been deferring this same job for too long.
                    if user_busy:
                        first_defer = self._defer_started.get(job["id"], now)
                        self._defer_started[job["id"]] = first_defer
                        if (now - first_defer) < self.MAX_DEFER_SECONDS:
                            continue
                        # else: we've waited long enough, fire anyway
                        self.log(f"[cron] {job['id']!r} firing despite busy "
                                 f"(deferred {int((now-first_defer)/60)} min)")

                    self._defer_started.pop(job["id"], None)
                    self.log(f"[cron] firing {job['id']!r} (action={job['action']})")
                    try:
                        fn(**(job.get("kwargs") or {}))
                        # Reset failure counter on success
                        self._fail_counts.pop(job["id"], None)
                    except Exception as e:
                        self.log(f"[cron] {job['id']} error: {e}")
                        # Phase 0: circuit breaker — N consecutive failures → disable job
                        n = self._fail_counts.get(job["id"], 0) + 1
                        self._fail_counts[job["id"]] = n
                        if n >= self.CIRCUIT_BREAKER_THRESHOLD:
                            self.log(f"[cron] CIRCUIT-BREAKER tripped for "
                                     f"{job['id']!r} after {n} failures — "
                                     f"disabling. Re-enable in tars_cron.json.")
                            with self._lock:
                                for j in self.jobs:
                                    if j["id"] == job["id"]:
                                        j["enabled"] = False
                                        j["last_error"] = str(e)[:200]
                                        break
                                self._save()
                    self._mark_run(job["id"])
            except Exception as e:
                self.log(f"[cron] loop error: {e}")
            time.sleep(15)

    def _mark_run(self, job_id: str) -> None:
        with self._lock:
            for j in self.jobs:
                if j["id"] == job_id:
                    j["last_run"] = datetime.now().isoformat()
                    break
            self._save()

    @staticmethod
    def _parse_iso(s: str) -> float:
        try:
            return datetime.fromisoformat(s).timestamp()
        except Exception:
            return 0.0
