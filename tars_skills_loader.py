"""
TARS Skill Loader
=================

Discovers, loads, dispatches, and life-cycles dynamic skills built by Codex.

A skill = directory in `tars_skills/<name>/` containing a `manifest.json`:

    {
      "name":        "document_creator",
      "description": "Create Word/PDF docs from text",
      "triggers":    ["\\bcreate (?:a )?(?:doc|document)\\b", ...],
      "type":        "inline" | "service" | "ui",
      "entry":       "python skill.py",
      "io":          "stdin_stdout" | "argv_stdout" | "json_file" | "rpc_socket",
      "long_running": false,
      "version":     "1.0",
      "rpc": { "host": "127.0.0.1", "port": 7331, "protocol": "http" }   # for service/ui
    }

Dispatch flow:
  1. detect(text) -> first matching skill (or None)
  2. dispatch(skill, text, context) -> result string (or None on failure)

Skill types:
  - inline:  subprocess.run(entry, input=text)               → stdout captured
  - service: subprocess.Popen(entry) once at boot, kept alive; commands sent
             via the manifest['rpc'] endpoint (HTTP POST /invoke {text})
  - ui:      same as service but only spawned on first invocation; designed for
             persistent visual UIs (avatar, overlay)

Hot reload: call rescan() after a skill is activated. The loader is thread-safe.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import signal
import subprocess
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import requests


# ---------------------------------------------------------------------------

@dataclass
class Skill:
    name: str
    description: str
    triggers: List[re.Pattern]
    type: str                           # inline | service | ui
    entry: str
    io: str
    long_running: bool
    version: str
    directory: str
    rpc: Optional[Dict] = None
    proc: Optional[subprocess.Popen] = field(default=None, repr=False)
    _started: bool = False
    # Phase 0: quarantine state
    _quarantined: bool = False
    _failure_times: List[float] = field(default_factory=list, repr=False)
    activated_at: float = 0.0          # for relevance-tie-breaking

    def matches(self, text: str) -> bool:
        return any(p.search(text) for p in self.triggers)

    def best_match_length(self, text: str) -> int:
        """Phase 0: return the length of the LONGEST matching trigger span,
        or 0 if no match. Used for relevance-scored dispatch."""
        best = 0
        for p in self.triggers:
            for m in p.finditer(text):
                span = m.end() - m.start()
                if span > best:
                    best = span
        return best


# ---------------------------------------------------------------------------

class SkillLoader:
    """Discovers, dispatches, and life-cycles dynamic skills."""

    # Phase 0: env allowlist for skill subprocesses — keeps API keys out of
    # third-party skill processes. Skills get only what they need to run.
    ENV_ALLOWLIST = (
        "PATH", "HOME", "USER", "LANG", "LC_ALL", "LC_CTYPE",
        "TMPDIR", "SHELL", "TERM", "PWD",
    )

    # Phase 0: quarantine after N RPC failures within a sliding window
    QUARANTINE_FAILURE_THRESHOLD = 3
    QUARANTINE_WINDOW_S          = 5 * 60

    def __init__(self, project_dir: str, log_fn):
        self.project_dir = project_dir
        self.skills_dir  = os.path.join(project_dir, "tars_skills")
        os.makedirs(self.skills_dir, exist_ok=True)
        self.log = log_fn
        self._skills: List[Skill] = []
        self._lock = threading.Lock()
        self._http = requests.Session()

    # ------------------------------------------------------------------
    # Discovery / hot reload
    # ------------------------------------------------------------------
    def rescan(self) -> int:
        """Re-read tars_skills/ from disk. Returns number of skills loaded."""
        loaded: List[Skill] = []
        with self._lock:
            previous = {s.name: s for s in self._skills}

            for entry in sorted(os.listdir(self.skills_dir)):
                skill_path = os.path.join(self.skills_dir, entry)
                manifest_path = os.path.join(skill_path, "manifest.json")
                if not os.path.isdir(skill_path) or not os.path.exists(manifest_path):
                    continue
                try:
                    skill = self._load_one(skill_path, manifest_path)
                    if skill is None:
                        continue
                    # Carry over running process if same name & still alive
                    prev = previous.get(skill.name)
                    if prev and prev.proc and prev.proc.poll() is None and skill.type == prev.type:
                        skill.proc = prev.proc
                        skill._started = prev._started
                    loaded.append(skill)
                except Exception as e:
                    self.log(f"[skills] failed to load {entry}: {e}")

            # Stop any previously-loaded skills that are no longer on disk
            current_names = {s.name for s in loaded}
            for prev in previous.values():
                if prev.name not in current_names and prev.proc and prev.proc.poll() is None:
                    self._stop_proc(prev)

            self._skills = loaded

        self.log(f"[skills] {len(loaded)} skill(s) loaded: "
                 f"{', '.join(s.name for s in loaded) or '(none)'}")
        return len(loaded)

    def _load_one(self, skill_path: str, manifest_path: str) -> Optional[Skill]:
        with open(manifest_path, "r", encoding="utf-8") as f:
            m = json.load(f)

        required = {"name", "description", "triggers", "type", "entry", "io"}
        missing = required - m.keys()
        if missing:
            self.log(f"[skills] {os.path.basename(skill_path)} manifest missing keys {missing}")
            return None

        try:
            triggers = [re.compile(p, re.IGNORECASE) for p in m["triggers"]]
        except re.error as e:
            self.log(f"[skills] {m.get('name')} invalid trigger regex: {e}")
            return None

        if m["type"] not in ("inline", "service", "ui"):
            self.log(f"[skills] {m.get('name')} unknown type {m['type']!r}")
            return None

        # Phase 0: capture activation time = directory mtime.
        # On tie in relevance scoring, the most-recently activated skill wins.
        try:
            activated_at = os.path.getmtime(skill_path)
        except OSError:
            activated_at = 0.0

        return Skill(
            name=str(m["name"]),
            description=str(m["description"]),
            triggers=triggers,
            type=m["type"],
            entry=str(m["entry"]),
            io=str(m["io"]),
            long_running=bool(m.get("long_running", m["type"] in ("service", "ui"))),
            version=str(m.get("version", "1.0")),
            directory=skill_path,
            rpc=m.get("rpc"),
            activated_at=activated_at,
        )

    # ------------------------------------------------------------------
    # Dispatch
    # ------------------------------------------------------------------
    def list_descriptions(self) -> List[Tuple[str, str]]:
        with self._lock:
            return [(s.name, s.description)
                    for s in self._skills if not s._quarantined]

    def detect(self, text: str) -> Optional[Skill]:
        """Phase 0: relevance-scored dispatch.
        Returns the skill with the LONGEST matching trigger span; ties broken
        by most recently activated. Quarantined skills are skipped."""
        with self._lock:
            best: Optional[Skill] = None
            best_score = 0
            best_recency = -1.0
            for skill in self._skills:
                if skill._quarantined:
                    continue
                score = skill.best_match_length(text)
                if score == 0:
                    continue
                if (score > best_score
                        or (score == best_score and skill.activated_at > best_recency)):
                    best = skill
                    best_score = score
                    best_recency = skill.activated_at
            return best

    def detect_and_dispatch(self, text: str, context: Optional[Dict] = None) -> Optional[str]:
        """Convenience: detect → dispatch. Returns formatted [Tool Result …] or None."""
        skill = self.detect(text)
        if not skill:
            return None
        try:
            result = self.dispatch(skill, text, context or {})
        except Exception as e:
            self.log(f"[skills] dispatch error in {skill.name}: {e}")
            return f"[Tool Result ({skill.name}): error — {e}]"
        if result is None:
            return None
        return f"[Tool Result ({skill.name}): {result}]"

    def dispatch(self, skill: Skill, text: str, context: Dict) -> Optional[str]:
        if skill.type == "inline":
            return self._dispatch_inline(skill, text, context)
        if skill.type in ("service", "ui"):
            return self._dispatch_rpc(skill, text, context)
        return None

    # ------------------------------------------------------------------
    # Inline dispatch
    # ------------------------------------------------------------------
    def _dispatch_inline(self, skill: Skill, text: str, context: Dict) -> Optional[str]:
        env = self._skill_env(skill, context)
        argv = shlex.split(skill.entry)

        if skill.io == "argv_stdout":
            argv.append(text)
            stdin_input = None
        elif skill.io == "json_file":
            payload_path = os.path.join(skill.directory, ".tars_input.json")
            with open(payload_path, "w", encoding="utf-8") as f:
                json.dump({"text": text, "context": context}, f)
            argv.append(payload_path)
            stdin_input = None
        else:  # stdin_stdout default
            stdin_input = text

        try:
            proc = subprocess.run(
                argv,
                cwd=skill.directory,
                input=stdin_input,
                capture_output=True,
                text=True,
                timeout=60,
                env=env,
            )
        except subprocess.TimeoutExpired:
            return "skill timed out after 60s"
        except FileNotFoundError as e:
            return f"skill entry not found: {e}"

        out = (proc.stdout or "").strip()
        err = (proc.stderr or "").strip()
        if proc.returncode != 0:
            return f"skill exited rc={proc.returncode}: {err[:200] or out[:200]}"
        return out[:500] if out else "(skill produced no output)"

    # ------------------------------------------------------------------
    # Service / UI dispatch (RPC)
    # ------------------------------------------------------------------
    def _dispatch_rpc(self, skill: Skill, text: str, context: Dict) -> Optional[str]:
        if not skill._started:
            self._start_proc(skill)
            # Give it a moment to bind its socket
            time.sleep(1.0)

        rpc = skill.rpc or {"host": "127.0.0.1", "port": 0, "protocol": "http"}
        host = rpc.get("host", "127.0.0.1")
        port = rpc.get("port")
        if not port:
            self._record_failure(skill, "no rpc.port in manifest")
            return f"{skill.name} has no rpc.port in manifest"
        url = f"http://{host}:{port}/invoke"
        try:
            r = self._http.post(url, json={"text": text, "context": context}, timeout=30)
            if r.status_code != 200:
                self._record_failure(skill, f"http {r.status_code}")
                return f"{skill.name} rpc {r.status_code}: {r.text[:200]}"
            try:
                data = r.json()
                if isinstance(data, dict):
                    return str(data.get("result", data))[:500]
                return str(data)[:500]
            except ValueError:
                return r.text.strip()[:500]
        except requests.RequestException as e:
            # Process may have died — try one restart
            self.log(f"[skills] {skill.name} rpc failed: {e}; restarting…")
            self._stop_proc(skill)
            self._start_proc(skill)
            time.sleep(1.0)
            try:
                r = self._http.post(url, json={"text": text, "context": context}, timeout=30)
                if r.ok:
                    return r.text.strip()[:500]
                self._record_failure(skill, f"retry http {r.status_code}")
                return f"rpc retry failed: {r.status_code}"
            except Exception as e2:
                self._record_failure(skill, f"retry exc {e2}")
                return f"rpc unavailable: {e2}"

    def _record_failure(self, skill: Skill, reason: str) -> None:
        """Phase 0: track RPC failures and quarantine the skill if the count
        within a 5-min window crosses the threshold."""
        now = time.time()
        cutoff = now - self.QUARANTINE_WINDOW_S
        skill._failure_times = [t for t in skill._failure_times if t > cutoff]
        skill._failure_times.append(now)
        if len(skill._failure_times) >= self.QUARANTINE_FAILURE_THRESHOLD:
            skill._quarantined = True
            self.log(f"[skills] QUARANTINED {skill.name!r} after "
                     f"{len(skill._failure_times)} failures in "
                     f"{self.QUARANTINE_WINDOW_S}s ({reason}). "
                     f"Recover with skill_loader.unquarantine() or rescan().")

    # ------------------------------------------------------------------
    # Process lifecycle
    # ------------------------------------------------------------------
    def start_persistent_skills(self) -> None:
        """Start any service-type skills at boot. UI skills start lazily."""
        with self._lock:
            skills = list(self._skills)
        for s in skills:
            if s.type == "service" and not s._started:
                self._start_proc(s)

    def shutdown_all(self) -> None:
        with self._lock:
            for s in self._skills:
                if s.proc and s.proc.poll() is None:
                    self._stop_proc(s)

    def _start_proc(self, skill: Skill) -> None:
        env = self._skill_env(skill, {})
        argv = shlex.split(skill.entry)
        try:
            skill.proc = subprocess.Popen(
                argv,
                cwd=skill.directory,
                env=env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            skill._started = True
            self.log(f"[skills] started {skill.type} skill {skill.name!r} (pid {skill.proc.pid})")
        except Exception as e:
            self.log(f"[skills] failed to start {skill.name}: {e}")
            skill._started = False

    def _stop_proc(self, skill: Skill) -> None:
        if not skill.proc:
            return
        try:
            os.killpg(os.getpgid(skill.proc.pid), signal.SIGTERM)
        except Exception:
            try:
                skill.proc.terminate()
            except Exception:
                pass
        try:
            skill.proc.wait(timeout=3)
        except Exception:
            try:
                skill.proc.kill()
            except Exception:
                pass
        skill.proc = None
        skill._started = False

    def unquarantine(self, name: Optional[str] = None) -> int:
        """Phase 0: clear quarantine state for one skill (by name) or all.
        Returns the number of skills affected."""
        affected = 0
        with self._lock:
            for s in self._skills:
                if name and s.name != name:
                    continue
                if s._quarantined:
                    s._quarantined = False
                    s._failure_times.clear()
                    affected += 1
        if affected:
            self.log(f"[skills] unquarantined {affected} skill(s)")
        return affected

    # ------------------------------------------------------------------
    # Env
    # ------------------------------------------------------------------
    def _skill_env(self, skill: Skill, context: Dict) -> Dict[str, str]:
        """Phase 0: scrubbed env — only the allowlisted keys + TARS_* are
        passed to skill subprocesses. Keeps API keys / secrets out of
        third-party (codex-generated) skill code."""
        env: Dict[str, str] = {}
        for key in self.ENV_ALLOWLIST:
            v = os.environ.get(key)
            if v is not None:
                env[key] = v
        env["TARS_PROJECT_DIR"] = self.project_dir
        env["TARS_SKILL_DIR"]   = skill.directory
        env["TARS_SKILL_NAME"]  = skill.name
        if context:
            try:
                env["TARS_CONTEXT_JSON"] = json.dumps(context)[:4000]
            except Exception:
                pass
        return env
