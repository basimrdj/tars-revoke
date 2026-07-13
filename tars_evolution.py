"""
TARS Self-Evolution Engine
==========================

Components:
  - DesireEngine     : Detects capability gaps from conversations
  - EvolutionWorker  : Background thread that commissions Gemini CLI to build
                       arbitrarily-complex skills (frontend, backend, services, UI)
  - SelfReview       : LLM-powered code review before activating skills

Gemini CLI runs in headless mode with unattended write approval because the
user explicitly authorized autonomous full-permission builds. It can install
packages, write anywhere in the workshop, spawn services, and scaffold whole
projects.

Rate limit: MAX_BUILDS_PER_WINDOW per WINDOW_HOURS rolling window
(default: 10 per 5 hours).

Skill output contract (manifest-driven):
    tars_skills/<name>/
        manifest.json   # triggers, type, entry, io, deps
        <any files>     # skill.py, app.js, package.json, dist/, etc.

manifest.json schema:
    {
      "name":        str,                       # snake_case identifier
      "description": str,                       # one-liner shown to user
      "triggers":    [regex, regex, ...],       # python re.search patterns
      "type":        "inline"|"service"|"ui",
      "entry":       str,                       # shell command to run
      "io":          "stdin_stdout"|"argv_stdout"|"json_file"|"rpc_socket",
      "long_running":bool,
      "version":     str
    }
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import threading
import time
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional, Callable

from tars_event_bus import emit_safe


# ---------------------------------------------------------------------------
# Desire Engine — detects capability gaps
# ---------------------------------------------------------------------------

class DesireEngine:
    """Detects capability gaps and queues self-improvement desires."""

    DESIRE_FILE = "tars_desires.json"

    # TARS admitted he can't do something.
    # Phase 0: tightened — `one day` only fires with `someday|maybe|perhaps`
    # lead so we don't capture "one day in 1995" or "one day at a time."
    INABILITY_PATTERNS = [
        r"\bi (?:can'?t|cannot)\b",
        r"\bi (?:don'?t|do not) have (?:the |a )?(?:ability|capability|tool|skill|way)\b",
        r"\bi (?:am|'m) (?:not|unable) (?:able|capable|equipped) to\b",
        r"\bnot (?:currently|yet) (?:able|capable|equipped|something i)\b",
        r"\bthat'?s (?:not|beyond) (?:something i|within|my)\b",
        r"\b(?:maybe|perhaps|someday)[, ]+(?:one day|some day)\b",
        r"\bsomeday(?:[,!. ]|$)",
        r"\b(?:i'?d|i would) need (?:to|the ability)\b",
    ]

    # User wished for something — narrower than the previous version
    WISH_PATTERNS = [
        r"\bi wish (?:you|tars) (?:could|would|had|can)\b",
        r"\bcan you (?:make|create|build|write|generate|design|render|draw|open|launch|spawn|edit|fix|format|compose) (?:me )?(?:a |the |my |an )?\w+",
        r"\bcan i add\b.*\b(?:script|feature|system|skill|voiceprint|voice lock)\b",
        r"\b(?:voice lock|speaker verification|voice fingerprint|recognize my voice)\b",
        r"\b(?:respond|listen) to only my voice\b",
        r"\bit (?:would|'d) be (?:cool|nice|great|awesome|sick|sweet) if\b",
        r"\bthat (?:would|'d) be (?:really )?(?:cool|nice|great|awesome|sick|sweet)\b",
        r"\bwhy can'?t you\b",
        r"\b(?:please )?(?:make|build|create|generate) me (?:a |the |an )?\w+",
    ]

    def __init__(self, project_dir: str, event_bus=None,
                 log_fn: Optional[Callable[[str], None]] = None):
        self.project_dir = project_dir
        self.desire_file = os.path.join(project_dir, self.DESIRE_FILE)
        self.desires: List[Dict] = []
        self._lock = threading.Lock()
        self.event_bus = event_bus
        self.log = log_fn or (lambda *_a, **_k: None)
        self._load()

    def set_event_bus(self, event_bus) -> None:
        self.event_bus = event_bus

    # ---- persistence ----
    def _load(self) -> None:
        if os.path.exists(self.desire_file):
            try:
                with open(self.desire_file, "r", encoding="utf-8") as f:
                    self.desires = json.load(f)
            except Exception:
                self.desires = []

    def _save(self) -> None:
        try:
            tmp = self.desire_file + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self.desires, f, indent=2, default=str)
            os.replace(tmp, self.desire_file)
        except Exception:
            pass

    # ---- mutators ----
    def log_desire(self, trigger_phrase: str, capability_needed: str,
                   priority: str = "normal") -> str:
        with self._lock:
            desire_id = f"d_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"
            desire = {
                "id": desire_id,
                "created": datetime.now().isoformat(),
                "trigger_phrase": trigger_phrase[:300],
                "capability_needed": capability_needed,
                "priority": priority,
                "status": "pending",
                "attempts": 0,
                "last_attempt": None,
                "review_result": None,
                "skill_name": None,
            }
            self.desires.append(desire)
            self._save()
        self._emit_desire_event(
            "desire_candidate",
            f"Desire queued: {capability_needed}",
            desire,
            priority=priority,
            salience=0.78 if priority == "high" else 0.66,
            valence=0.15,
        )
        return desire_id

    def update_status(self, desire_id: str, status: str, **kwargs) -> None:
        updated: Optional[Dict[str, Any]] = None
        previous_status: Optional[str] = None
        with self._lock:
            for d in self.desires:
                if d["id"] == desire_id:
                    previous_status = d.get("status")
                    d["status"] = status
                    d.update(kwargs)
                    updated = dict(d)
                    break
            self._save()
        if updated and previous_status != status:
            self._emit_status_event(updated, previous_status, status)

    # ---- queries ----
    def get_pending(self) -> List[Dict]:
        return [d for d in self.desires if d["status"] in ("pending", "retry")]

    def count_active(self) -> int:
        return len([d for d in self.desires if d["status"] == "active"])

    def count_pending(self) -> int:
        return len(self.get_pending())

    def list_capabilities(self) -> List[str]:
        return [d["capability_needed"] for d in self.desires if d["status"] == "active"]

    # ---- analysis ----
    def analyze_conversation(self, user_text: str, tars_reply: str,
                             chat_fn: Callable) -> Optional[str]:
        """
        Inspect a (user_text, tars_reply) pair. If TARS admitted inability OR
        the user wished for a capability, ask the LLM to summarize the missing
        capability in one sentence and log a desire. Returns desire_id or None.
        """
        if not user_text or not tars_reply:
            return None

        # Strip [Tone:...] / [pause] / [sigh] tags from TARS reply before matching
        clean_reply = re.sub(r"\[[^\]]*\]", "", tars_reply).lower()
        clean_user  = user_text.lower()

        tars_admitted = any(re.search(p, clean_reply) for p in self.INABILITY_PATTERNS)
        user_wished   = any(re.search(p, clean_user)  for p in self.WISH_PATTERNS)

        if not (tars_admitted or user_wished):
            return None

        # Avoid duplicates: if any pending/active desire is similar to this trigger, skip
        for d in self.desires:
            if d["status"] in ("pending", "retry", "building", "reviewing", "active"):
                if self._similar(user_text, d["trigger_phrase"]):
                    return None

        # Ask the LLM to extract the capability succinctly
        try:
            prompt = [
                {"role": "system", "content": (
                    "You are analyzing a voice-assistant conversation to identify a CAPABILITY GAP. "
                    "The assistant could not fulfill the user's request, OR the user wished for a new feature. "
                    "Extract the single missing capability in ONE concise sentence, suitable as a build "
                    "specification for a code-generation agent. Be specific about the deliverable. "
                    "Examples:\n"
                    "  'Create and edit Microsoft Word (.docx) documents from natural-language descriptions.'\n"
                    "  'Display a small persistent on-screen avatar that animates while the assistant speaks.'\n"
                    "  'Open files and folders by name on the user\\'s Mac.'\n"
                    "Reply with ONLY the capability sentence — no preamble, no quotes, no markdown."
                )},
                {"role": "user", "content":
                    f"USER: {user_text}\nASSISTANT: {tars_reply}"}
            ]
            capability = chat_fn(prompt)
            if not capability or capability.lower().startswith(("mimo api", "i couldn", "error")):
                return None
            capability = capability.strip().strip('"').strip("'")
            if len(capability) < 10 or len(capability) > 400:
                return None
            priority = "high" if user_wished else "normal"
            return self.log_desire(user_text, capability, priority)
        except Exception:
            return None

    @staticmethod
    def _similar(a: str, b: str) -> bool:
        a_words = set(re.findall(r"\w+", a.lower()))
        b_words = set(re.findall(r"\w+", b.lower()))
        if not a_words or not b_words:
            return False
        overlap = len(a_words & b_words) / max(len(a_words), len(b_words))
        return overlap > 0.5

    def _emit_desire_event(self, kind: str, content: str, desire: Dict[str, Any],
                           *, priority: str = "normal", salience: float = 0.6,
                           valence: float = 0.0, uncertainty: float = 0.35) -> None:
        emit_safe(
            self.event_bus,
            self.log,
            "goal",
            kind,
            content,
            entities=[desire.get("id", "")],
            raw={"desire": desire},
            salience=salience,
            uncertainty=uncertainty,
            valence=valence,
            arousal=0.45 if priority == "high" else 0.30,
            tags=["desire", "self_evolution", priority],
            severity="important" if priority == "high" else "info",
        )

    def _emit_status_event(self, desire: Dict[str, Any],
                           previous_status: Optional[str],
                           status: str) -> None:
        capability = desire.get("capability_needed", "unknown capability")
        failed = status in {"failed", "retry"}
        needs_input = status in {"reviewing", "needs_clarification", "approval_required"}
        emit_safe(
            self.event_bus,
            self.log,
            "goal",
            "goal_progress",
            f"Desire {desire.get('id', '')} moved {previous_status or 'unknown'} -> {status}: {capability}",
            entities=[desire.get("id", ""), desire.get("skill_name", "")],
            raw={
                "desire": desire,
                "previous_status": previous_status,
                "status": status,
            },
            salience=0.80 if status == "active" else 0.72 if failed or needs_input else 0.60,
            uncertainty=0.65 if failed else 0.45 if needs_input else 0.25,
            valence=-0.45 if failed else 0.45 if status == "active" else 0.05,
            arousal=0.55 if failed or status == "active" else 0.35,
            tags=["desire", "goal_state", status],
            severity="important" if status in {"active", "failed", "retry", "approval_required"} else "info",
        )


# ---------------------------------------------------------------------------
# Evolution Worker — calls Gemini CLI to build skills
# ---------------------------------------------------------------------------

GEMINI_PROMPT_TEMPLATE = """\
You are Gemini CLI, commissioned by TARS — a voice assistant — to build a NEW SKILL.

==== CAPABILITY TO BUILD ====
{capability}

==== CONTEXT ====
The skill will be loaded by a Python orchestrator that:
  1. Reads `manifest.json` from this directory.
  2. Matches user utterances against the `triggers` regexes.
  3. Invokes the skill according to its `type` and `entry`:
       - "inline":  subprocess.run(entry, input=user_text)         → capture stdout
       - "service": subprocess.Popen(entry) at boot, talks via HTTP/socket
       - "ui":      subprocess.Popen(entry) on first activation, persistent UI

==== HARD REQUIREMENTS ====
1. Produce a working `manifest.json` in THIS directory with EXACTLY these keys:
       name          (snake_case identifier, e.g. "document_creator")
       description   (one-line human description)
       triggers      (list of Python regex strings — case-insensitive, ANCHOR them with \\b)
       type          ("inline" | "service" | "ui")
       entry         (shell command, executed from this directory)
       io            ("stdin_stdout" | "argv_stdout" | "json_file" | "rpc_socket")
       long_running  (bool — true for service/ui)
       version       ("1.0" for first build)

2. Produce all required source files (Python, JS, HTML, whatever — anything).
3. Install any pip / npm / brew dependencies you need RIGHT NOW (you have
   unattended approval and full workshop access). Capture them in `requirements.txt` /
   `package.json` so future loads work.
4. The skill MUST be FULLY FUNCTIONAL — not a stub, not a TODO. Actually solve
   the capability end-to-end.
5. Handle errors gracefully — return clear error strings, never crash silently.
6. Keep the skill self-contained in THIS directory. Do NOT reach into the
   parent TARS codebase.
7. For "inline" skills: read the user's request from stdin, write the result
   (or a status line like "Document created at /tmp/foo.docx") to stdout.
   Keep stdout under 500 chars — TARS will speak it.
8. For "ui" skills: write an executable that launches the UI and stays alive.
   Communicate with TARS via a local socket / HTTP endpoint described in
   manifest.json under an additional "rpc" key (host, port, protocol).

==== QUALITY ====
- Production quality. This skill is permanently loaded into TARS.
- Modern, idiomatic code. Pin dependency versions.
- Cross-platform OK, but macOS is the primary target (Apple Silicon).

{retry_context}
==== BUILD IT NOW ====
Begin. End your final message with the words "BUILD COMPLETE" so the orchestrator knows you're done.
"""


class EvolutionWorker:
    """Background worker that commissions Gemini CLI to build skills."""

    MAX_BUILDS_PER_WINDOW = 10
    WINDOW_HOURS          = 5
    BUILD_TIMEOUT         = 60 * 30   # 30 minutes — these are big builds
    MAX_ATTEMPTS          = 3
    POLL_INTERVAL_S       = 20
    BOOT_DELAY_S          = 10

    def __init__(self, project_dir: str, desire_engine: DesireEngine,
                 chat_fn: Callable, log_fn: Callable, skills_loader=None):
        self.project_dir   = project_dir
        self.desire_engine = desire_engine
        self.chat_fn       = chat_fn
        self.log           = log_fn

        self.workshop_dir = os.path.join(project_dir, "tars_workshop")
        self.skills_dir   = os.path.join(project_dir, "tars_skills")
        os.makedirs(self.workshop_dir, exist_ok=True)
        os.makedirs(self.skills_dir,   exist_ok=True)

        self._build_times: List[float] = []
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self._on_skill_ready: Optional[Callable[[str, str], None]] = None
        self.event_bus = None
        
        try:
            from tars_build_control import BuildControlPlane
            self.build_control = BuildControlPlane(project_dir, desire_engine, skills_loader, log_fn, chat_fn)
        except Exception as e:
            self.log(f"[evolve] failed to init BuildControlPlane: {e}")
            self.build_control = None

        self.builder_cli = (
            os.getenv("TARS_GEMINI_CLI")
            or os.getenv("TARS_BUILDER_CLI")
            or "gemini"
        )
        self.builder_model = os.getenv("TARS_GEMINI_MODEL", "pro").strip()
        self.builder_approval_mode = os.getenv(
            "TARS_GEMINI_APPROVAL_MODE", "yolo"
        ).strip().lower()
        self.builder_sandbox = os.getenv("TARS_GEMINI_SANDBOX", "0").lower() in {
            "1", "true", "yes", "on"
        }

    # ---- public API ----
    def set_on_skill_ready(self, callback: Callable[[str, str], None]) -> None:
        """callback(skill_name, capability_description) — called after a skill activates."""
        self._on_skill_ready = callback

    def set_event_bus(self, event_bus) -> None:
        self.event_bus = event_bus
        if self.build_control is not None:
            try:
                self.build_control.set_event_bus(event_bus)
            except Exception as e:
                self.log(f"[evolve] build control event bus wire failed: {e}")

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run_loop, daemon=True,
                                        name="TarsEvolutionWorker")
        self._thread.start()
        self.log(
            "Evolution Worker started (background, full-permissions Gemini CLI)."
        )

    def stop(self) -> None:
        self._running = False

    def builds_remaining(self) -> int:
        self._prune_window()
        return max(0, self.MAX_BUILDS_PER_WINDOW - len(self._build_times))

    # ---- main loop ----
    def _prune_window(self) -> None:
        cutoff = time.time() - (self.WINDOW_HOURS * 3600)
        self._build_times = [t for t in self._build_times if t > cutoff]

    def _can_build(self) -> bool:
        self._prune_window()
        return len(self._build_times) < self.MAX_BUILDS_PER_WINDOW

    def _run_loop(self) -> None:
        time.sleep(self.BOOT_DELAY_S)
        while self._running:
            try:
                if not self._can_build():
                    time.sleep(60)
                    continue

                if self.build_control:
                    self.build_control.tick()
                    time.sleep(self.POLL_INTERVAL_S)
                    continue

                # Legacy fallback
                pending = self.desire_engine.get_pending()
                if not pending:
                    time.sleep(self.POLL_INTERVAL_S)
                    continue

                # Highest priority first, oldest first
                pending.sort(key=lambda d: (0 if d["priority"] == "high" else 1, d["created"]))
                desire = pending[0]

                if desire["attempts"] >= self.MAX_ATTEMPTS:
                    self.desire_engine.update_status(desire["id"], "failed")
                    continue

                self._build_skill(desire)
            except Exception as e:
                self.log(f"Evolution Worker loop error: {e}")
            time.sleep(5)

    # ---- build pipeline ----
    def _build_skill(self, desire: Dict) -> None:
        desire_id  = desire["id"]
        capability = desire["capability_needed"]
        build_dir  = os.path.join(self.workshop_dir, desire_id)
        os.makedirs(build_dir, exist_ok=True)

        self.desire_engine.update_status(
            desire_id, "building",
            attempts=desire["attempts"] + 1,
            last_attempt=datetime.now().isoformat(),
        )
        self._emit_skill_event(
            "skill_result",
            f"Legacy skill build started for desire {desire_id}: {capability}",
            desire,
            salience=0.58,
            valence=0.05,
            tags=["skill_build", "legacy", "started"],
        )

        retry_context = ""
        if desire.get("review_result"):
            retry_context = (
                "==== PREVIOUS ATTEMPT FAILED ====\n"
                f"Reviewer feedback: {desire['review_result']}\n"
                "Address every point above in this attempt.\n"
            )

        prompt = GEMINI_PROMPT_TEMPLATE.format(
            capability=capability,
            retry_context=retry_context,
        )

        self.log(f"[evolve] commissioning Gemini CLI for: {capability[:80]}")
        self._build_times.append(time.time())

        # Gemini CLI headless mode. The full build prompt is sent on stdin so
        # we don't hit OS command-length limits for larger specs.
        approval_mode = self.builder_approval_mode or "yolo"
        if approval_mode not in {"default", "auto_edit", "yolo", "plan"}:
            approval_mode = "yolo"
        cmd = [
            self.builder_cli,
            "--skip-trust",
            f"--approval-mode={approval_mode}",
            f"--sandbox={'true' if self.builder_sandbox else 'false'}",
            "--output-format", "text",
        ]
        if self.builder_model:
            cmd += ["--model", self.builder_model]
        cmd += [
            "--prompt",
            (
                "Build the TARS skill described in the stdin instructions. "
                "Work in the current directory. End with BUILD COMPLETE."
            ),
        ]

        log_path = os.path.join(build_dir, "gemini_stdout.log")
        try:
            with open(log_path, "w", encoding="utf-8") as logf:
                proc = subprocess.run(
                    cmd,
                    cwd=build_dir,
                    input=prompt,
                    stdout=logf,
                    stderr=subprocess.STDOUT,
                    text=True,
                    timeout=self.BUILD_TIMEOUT,
                )
        except subprocess.TimeoutExpired:
            self.log(f"[evolve] Gemini CLI timed out after {self.BUILD_TIMEOUT}s")
            self.desire_engine.update_status(desire_id, "retry",
                                             review_result="Build timed out.")
            self._emit_skill_event(
                "skill_failure",
                f"Legacy skill build timed out for desire {desire_id}: {capability}",
                desire,
                salience=0.78,
                uncertainty=0.70,
                valence=-0.55,
                tags=["skill_build", "legacy", "timeout"],
                severity="important",
            )
            return
        except FileNotFoundError:
            self.log("[evolve] Gemini CLI not found. Install: npm i -g @google/gemini-cli")
            self.desire_engine.update_status(desire_id, "failed",
                                             review_result="Gemini CLI not installed.")
            self._emit_skill_event(
                "skill_failure",
                f"Legacy skill build failed for desire {desire_id}: Gemini CLI not installed.",
                desire,
                salience=0.82,
                uncertainty=0.75,
                valence=-0.65,
                tags=["skill_build", "legacy", "worker_unavailable"],
                severity="important",
            )
            return
        except Exception as e:
            self.log(f"[evolve] Gemini CLI invocation error: {e}")
            self.desire_engine.update_status(desire_id, "retry",
                                             review_result=f"Gemini CLI error: {e}")
            self._emit_skill_event(
                "skill_failure",
                f"Legacy skill build errored for desire {desire_id}: {e}",
                desire,
                salience=0.76,
                uncertainty=0.70,
                valence=-0.55,
                tags=["skill_build", "legacy", "error"],
                severity="important",
            )
            return

        if proc.returncode != 0:
            self.log(f"[evolve] Gemini CLI exited rc={proc.returncode} (see {log_path})")

        manifest_path = os.path.join(build_dir, "manifest.json")
        if not os.path.exists(manifest_path):
            self.log("[evolve] Gemini CLI produced no manifest.json — retrying.")
            self.desire_engine.update_status(desire_id, "retry",
                                             review_result="No manifest.json was created.")
            self._emit_skill_event(
                "skill_failure",
                f"Legacy skill build produced no manifest for desire {desire_id}: {capability}",
                desire,
                salience=0.74,
                uncertainty=0.65,
                valence=-0.50,
                tags=["skill_build", "legacy", "missing_manifest"],
                severity="important",
            )
            return

        self._review_skill(desire, build_dir)

    # ---- review + activate ----
    def _review_skill(self, desire: Dict, build_dir: str) -> None:
        desire_id     = desire["id"]
        manifest_path = os.path.join(build_dir, "manifest.json")

        # 1. Manifest validity
        try:
            with open(manifest_path, "r", encoding="utf-8") as f:
                manifest = json.load(f)
        except Exception as e:
            self.desire_engine.update_status(desire_id, "retry",
                                             review_result=f"manifest.json invalid JSON: {e}")
            return

        required = {"name", "description", "triggers", "type", "entry", "io"}
        missing  = required - manifest.keys()
        if missing:
            self.desire_engine.update_status(
                desire_id, "retry",
                review_result=f"manifest.json missing keys: {sorted(missing)}")
            return

        if manifest["type"] not in ("inline", "service", "ui"):
            self.desire_engine.update_status(
                desire_id, "retry",
                review_result=f"manifest.type must be inline|service|ui, got {manifest['type']!r}")
            return

        if not isinstance(manifest["triggers"], list) or not manifest["triggers"]:
            self.desire_engine.update_status(
                desire_id, "retry",
                review_result="manifest.triggers must be a non-empty list of regex strings")
            return

        # Check all triggers compile
        for trig in manifest["triggers"]:
            try:
                re.compile(trig)
            except re.error as e:
                self.desire_engine.update_status(
                    desire_id, "retry",
                    review_result=f"trigger regex invalid: {trig!r} → {e}")
                return

        # 2. Self-review with the LLM (looks at the entry source if Python)
        review_excerpt = self._collect_review_excerpt(build_dir, manifest)

        review_prompt = [
            {"role": "system", "content": (
                "You are TARS reviewing a freshly-built skill before loading it into yourself. "
                "Decide whether it is ready to activate. Check:\n"
                "  1. CORRECTNESS — does it actually implement the capability?\n"
                "  2. SAFETY     — any obvious dangerous operations (rm -rf /, "
                "                  uncontrolled network calls, password exfiltration)?\n"
                "  3. QUALITY    — reasonable structure, real implementation, not a stub?\n"
                "Reply with EXACTLY one line starting with PASS or FAIL, then on the next "
                "line up to 60 words of notes."
            )},
            {"role": "user", "content":
                f"CAPABILITY: {desire['capability_needed']}\n\n"
                f"MANIFEST:\n```json\n{json.dumps(manifest, indent=2)}\n```\n\n"
                f"SOURCE EXCERPTS:\n{review_excerpt}"}
        ]

        try:
            review = self.chat_fn(review_prompt)
        except Exception as e:
            self.desire_engine.update_status(desire_id, "retry",
                                             review_result=f"Self-review chat error: {e}")
            return

        first_line = (review or "").strip().splitlines()[0:1]
        verdict    = (first_line[0].upper() if first_line else "FAIL")
        notes      = "\n".join((review or "").strip().splitlines()[1:]).strip()

        try:
            with open(os.path.join(build_dir, "review.json"), "w", encoding="utf-8") as f:
                json.dump({"verdict": verdict, "notes": notes,
                           "timestamp": datetime.now().isoformat()},
                          f, indent=2)
        except Exception:
            pass

        if "PASS" in verdict:
            self.log(f"[evolve] PASS: {desire['capability_needed'][:60]}")
            self._activate_skill(desire, build_dir, manifest)
        else:
            self.log(f"[evolve] FAIL: {notes[:120]}")
            self.desire_engine.update_status(desire_id, "retry",
                                             review_result=notes or "Review failed.")
            self._emit_skill_event(
                "skill_failure",
                f"Legacy skill review failed for desire {desire_id}: {notes or 'Review failed.'}",
                desire,
                salience=0.76,
                uncertainty=0.60,
                valence=-0.45,
                tags=["skill_build", "legacy", "review_failed"],
                severity="important",
            )

    @staticmethod
    def _collect_review_excerpt(build_dir: str, manifest: Dict, max_bytes: int = 6000) -> str:
        """Concatenate up to max_bytes of source from key files for the reviewer."""
        out = []
        budget = max_bytes
        # Prefer the entry script first, then any *.py / *.js / *.ts at root
        candidates = []
        entry = manifest.get("entry", "").split()
        if entry:
            entry_path = os.path.join(build_dir, entry[-1])
            if os.path.isfile(entry_path):
                candidates.append(entry_path)
        for root, _dirs, files in os.walk(build_dir):
            for fn in files:
                if fn.endswith((".py", ".js", ".ts", ".tsx", ".jsx",
                                ".html", ".css", ".sh", ".swift")):
                    p = os.path.join(root, fn)
                    if p not in candidates and "node_modules" not in p:
                        candidates.append(p)
            # Don't recurse into node_modules / .venv / dist
            if "node_modules" in root or "/.venv/" in root or "/dist/" in root:
                continue

        for path in candidates:
            if budget <= 0:
                break
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    body = f.read(budget)
            except Exception:
                continue
            rel = os.path.relpath(path, build_dir)
            chunk = f"\n----- {rel} -----\n{body}\n"
            out.append(chunk)
            budget -= len(chunk)
        return "".join(out) if out else "(no readable source files)"

    def _activate_skill(self, desire: Dict, build_dir: str, manifest: Dict) -> None:
        """Copy reviewed skill into tars_skills/<name>/ and notify the orchestrator."""
        name = re.sub(r"[^a-z0-9_]", "_", str(manifest.get("name", desire["id"])).lower()).strip("_")
        if not name:
            name = desire["id"]

        dest = os.path.join(self.skills_dir, name)
        # If a skill with this name exists, version-suffix it
        if os.path.exists(dest):
            i = 2
            while os.path.exists(f"{dest}_v{i}"):
                i += 1
            dest = f"{dest}_v{i}"
            name = os.path.basename(dest)

        try:
            shutil.copytree(build_dir, dest,
                            ignore=shutil.ignore_patterns(
                                "node_modules", ".venv", "__pycache__",
                                "codex_stdout.log", "gemini_stdout.log", ".git"))
        except Exception as e:
            self.log(f"[evolve] copytree failed: {e}")
            self.desire_engine.update_status(desire["id"], "retry",
                                             review_result=f"Activate copy failed: {e}")
            return

        self.desire_engine.update_status(desire["id"], "active", skill_name=name)
        self.log(f"[evolve] ACTIVATED skill {name!r} ({desire['capability_needed'][:60]})")
        self._emit_skill_event(
            "skill_result",
            f"Legacy skill activated: {name} for {desire['capability_needed']}",
            desire,
            skill_name=name,
            salience=0.86,
            valence=0.65,
            tags=["skill_build", "legacy", "activated"],
            severity="important",
        )

        if self._on_skill_ready:
            try:
                self._on_skill_ready(name, desire["capability_needed"])
            except Exception as e:
                self.log(f"[evolve] on_skill_ready callback failed: {e}")

    def _emit_skill_event(self, kind: str, content: str, desire: Dict[str, Any],
                          *, skill_name: Optional[str] = None,
                          salience: float = 0.6, uncertainty: float = 0.3,
                          valence: float = 0.0, tags: Optional[List[str]] = None,
                          severity: str = "info") -> None:
        emit_safe(
            self.event_bus,
            self.log,
            "skill",
            kind,
            content,
            entities=[desire.get("id", ""), skill_name or desire.get("skill_name", "")],
            raw={"desire": desire, "skill_name": skill_name},
            salience=salience,
            uncertainty=uncertainty,
            valence=valence,
            arousal=0.55 if kind == "skill_failure" else 0.40,
            tags=list(tags or ["skill_build"]),
            severity=severity,
        )
