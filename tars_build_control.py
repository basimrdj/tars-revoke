import json
import os
import shutil
import threading
import uuid
import time
from datetime import datetime
from typing import Dict, List, Optional, Any

from tars_build_policies import BuildPolicy
from tars_event_bus import emit_safe
from tars_gemini_runner import GeminiRunner
from tars_patch_review import PatchReview

GEMINI_PROMPT_TEMPLATE = """\
You are Gemini CLI, commissioned by TARS — a voice assistant — to build a NEW SKILL.

==== CAPABILITY TO BUILD ====
{capability}

==== CONTEXT ====
The skill will be loaded by a Python orchestrator that reads `manifest.json`.
Manifest must include: name, description, triggers (regex list), type (inline|service|ui), entry (shell cmd), io, long_running, version.

Produce all required source files and end with BUILD COMPLETE.
"""

class BuildControlPlane:
    def __init__(self, project_dir: str, desire_engine, skills_loader, log_fn,
                 chat_fn=None, event_bus=None):
        self.project_dir = project_dir
        self.desire_engine = desire_engine
        self.skills_loader = skills_loader
        self.log = log_fn
        self.chat_fn = chat_fn
        self.event_bus = event_bus
        self.jobs_file = os.path.join(project_dir, "tars_build_jobs.jsonl")
        self.jobs: Dict[str, Dict] = {}
        self.policy = BuildPolicy()
        self.runner = GeminiRunner(log_fn)
        self.reviewer = PatchReview(log_fn)
        self._lock = threading.RLock()
        self._load_jobs()

    def set_event_bus(self, event_bus) -> None:
        self.event_bus = event_bus

    def _load_jobs(self):
        if not os.path.exists(self.jobs_file):
            return
        with open(self.jobs_file, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    job = json.loads(line.strip())
                    self.jobs[job["id"]] = job
                except Exception:
                    pass

    def _save_job(self, job: Dict):
        with self._lock:
            self.jobs[job["id"]] = job
            try:
                with open(self.jobs_file, "a", encoding="utf-8") as f:
                    f.write(json.dumps(job) + "\n")
            except Exception:
                pass

    def scan_desires(self) -> List[Dict]:
        if not self.desire_engine: return []
        pending = self.desire_engine.get_pending()
        processed = []
        for req in pending:
            exists = any(j.get("source_desire_id") == req["id"] for j in self.jobs.values())
            if exists:
                continue
            job = self.create_job_from_desire(req)
            if job:
                processed.append(job)
        return processed

    def classify_buildability(self, desire: Dict) -> Dict:
        cap = desire.get("capability_needed", "")
        return {"buildable": len(cap.split()) >= 3}

    def create_job_from_desire(self, desire: Dict) -> Optional[Dict]:
        job_id = f"job_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"
        cap = desire.get("capability_needed", "")
        risk = self.policy.classify_risk(cap)
        buildability = self.classify_buildability(desire)
        
        if not buildability["buildable"]:
            status = "needs_clarification"
        elif risk in ("high", "critical"):
            status = "approval_required"
        else:
            status = "planned"

        job = {
            "id": job_id,
            "created_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat(),
            "source": "user_desire",
            "source_desire_id": desire["id"],
            "user_phrase": desire.get("trigger_phrase", ""),
            "normalized_request": cap,
            "status": status,
            "risk": risk,
            "worker": "gemini_cli",
            "workspace": os.path.join(self.project_dir, "tars_workshop", "jobs", job_id),
            "legacy_workshop": os.path.join(self.project_dir, "tars_workshop", desire["id"]),
            "plan_path": None,
            "patch_path": None,
            "test_log_path": None,
            "review_path": None,
            "skill_name": None,
            "approval_required": risk in ("high", "critical"),
            "activation_allowed": self.policy.auto_activate_low_risk and risk == "low",
            "errors": [],
            "notes": []
        }
        self._save_job(job)
        self._emit_goal_event(
            job,
            f"Build job {job_id} created with status {status}: {cap}",
            salience=0.72 if status != "planned" else 0.62,
            uncertainty=0.55 if status != "planned" else 0.30,
            valence=-0.10 if status != "planned" else 0.05,
            tags=["build_job", "desire", status],
            severity="important" if status in ("approval_required", "needs_clarification") else "info",
        )
        if status == "planned":
            self.desire_engine.update_status(desire["id"], "building")
        elif status in ("needs_clarification", "approval_required"):
            self.desire_engine.update_status(desire["id"], "reviewing")
        return job

    def plan_job(self, job_id: str) -> Optional[Dict]:
        job = self.jobs.get(job_id)
        if not job or job["status"] != "planned":
            return None
        job["status"] = "approved_for_build"
        job["updated_at"] = datetime.now().isoformat()
        self._save_job(job)
        self._emit_skill_event(
            "skill_result",
            job,
            f"Build job {job_id} approved for build: {job.get('normalized_request', '')}",
            valence=0.10,
            tags=["build_job", "approved"],
        )
        return job

    def build_job(self, job_id: str) -> Optional[Dict]:
        job = self.jobs.get(job_id)
        if not job or job["status"] != "approved_for_build":
            return None
        
        if not self.runner.available():
            job["status"] = "worker_unavailable"
            job["errors"].append("Gemini CLI unavailable")
            self._save_job(job)
            if self.desire_engine:
                self.desire_engine.update_status(job["source_desire_id"], "failed")
            self._emit_skill_event(
                "skill_failure",
                job,
                f"Build job {job_id} failed: Gemini CLI unavailable.",
                salience=0.84,
                uncertainty=0.75,
                valence=-0.70,
                tags=["build_job", "worker_unavailable"],
                severity="important",
            )
            return job

        job["status"] = "building"
        self._save_job(job)
        self._emit_skill_event(
            "skill_result",
            job,
            f"Build job {job_id} started: {job.get('normalized_request', '')}",
            valence=0.05,
            tags=["build_job", "started"],
        )
        
        os.makedirs(job["workspace"], exist_ok=True)
        prompt = GEMINI_PROMPT_TEMPLATE.format(capability=job['normalized_request'])
        
        self.log(f"[build_control] Running Gemini CLI build for {job_id}")
        res = self.runner.build(job, prompt, job["workspace"])
        if res.get("success"):
            job["status"] = "tests_running"
            job["test_log_path"] = res.get("log_path")
            self._emit_skill_event(
                "skill_result",
                job,
                f"Build job {job_id} completed generation; tests pending: {job.get('normalized_request', '')}",
                salience=0.68,
                valence=0.25,
                tags=["build_job", "generated"],
            )
        else:
            job["status"] = "failed"
            job["errors"].append(res.get("error", "Build failed"))
            if self.desire_engine:
                self.desire_engine.update_status(job["source_desire_id"], "failed")
            self._emit_skill_event(
                "skill_failure",
                job,
                f"Build job {job_id} failed during generation: {res.get('error', 'Build failed')}",
                salience=0.82,
                uncertainty=0.70,
                valence=-0.65,
                tags=["build_job", "generation_failed"],
                severity="important",
            )
        
        job["updated_at"] = datetime.now().isoformat()
        self._save_job(job)
        return job

    def run_tests(self, job_id: str) -> Optional[Dict]:
        job = self.jobs.get(job_id)
        if not job or job["status"] != "tests_running":
            return None
        job["status"] = "review_needed"
        job["updated_at"] = datetime.now().isoformat()
        self._save_job(job)
        self._emit_skill_event(
            "skill_result",
            job,
            f"Build job {job_id} test stage completed; review needed.",
            salience=0.62,
            valence=0.15,
            tags=["build_job", "tests_complete"],
        )
        return job

    def review_job(self, job_id: str) -> Optional[Dict]:
        job = self.jobs.get(job_id)
        if not job or job["status"] != "review_needed":
            return None
        
        review = self.reviewer.review_job(job["workspace"])
        review_path = os.path.join(job["workspace"], "review.json")
        try:
            with open(review_path, "w", encoding="utf-8") as f:
                json.dump(review, f, indent=2)
        except Exception:
            pass
        job["review_path"] = review_path
        
        if review["approved"]:
            job["status"] = "activation_pending"
            self._emit_skill_event(
                "skill_result",
                job,
                f"Build job {job_id} review approved; activation pending.",
                salience=0.72,
                valence=0.35,
                tags=["build_job", "review_approved"],
            )
        else:
            job["status"] = "rejected"
            job["errors"].extend(review["issues"])
            if self.desire_engine:
                self.desire_engine.update_status(job["source_desire_id"], "retry", review_result="; ".join(review["issues"]))
            self._emit_skill_event(
                "skill_failure",
                job,
                f"Build job {job_id} review rejected: {'; '.join(review['issues'])}",
                salience=0.78,
                uncertainty=0.60,
                valence=-0.50,
                tags=["build_job", "review_rejected"],
                severity="important",
            )
            
        job["updated_at"] = datetime.now().isoformat()
        self._save_job(job)
        return job

    def activate_skill(self, job_id: str, require_approval: bool = True) -> Optional[Dict]:
        job = self.jobs.get(job_id)
        if not job or job["status"] != "activation_pending":
            return None
        
        if require_approval and not job.get("activation_allowed"):
            self.log(f"[build_control] Job {job_id} requires manual approval to activate.")
            self._emit_goal_event(
                job,
                f"Build job {job_id} is waiting for manual activation approval.",
                salience=0.72,
                uncertainty=0.50,
                valence=-0.05,
                tags=["build_job", "approval_required"],
                severity="important",
            )
            return job

        manifest_path = os.path.join(job["workspace"], "manifest.json")
        try:
            with open(manifest_path, "r", encoding="utf-8") as f:
                manifest = json.load(f)
            skill_name = manifest.get("name", f"skill_{job_id}")
            skill_name = "".join(c for c in skill_name if c.isalnum() or c == "_")
        except Exception:
            skill_name = f"skill_{job_id}"
            
        dest = os.path.join(self.project_dir, "tars_skills", skill_name)
        if os.path.exists(dest):
            dest = f"{dest}_v{int(time.time())}"
            skill_name = os.path.basename(dest)
            
        try:
            shutil.copytree(job["workspace"], dest, ignore=shutil.ignore_patterns("gemini_stdout.log", "review.json", ".git"))
            job["skill_name"] = skill_name
            job["status"] = "active"
            if self.skills_loader:
                self.skills_loader.rescan()
            if self.desire_engine:
                self.desire_engine.update_status(job["source_desire_id"], "active", skill_name=skill_name)
            self.log(f"[build_control] Skill {skill_name} ACTIVATED.")
            self._emit_skill_event(
                "skill_result",
                job,
                f"Skill activated from build job {job_id}: {skill_name} for {job.get('normalized_request', '')}",
                salience=0.88,
                uncertainty=0.15,
                valence=0.70,
                tags=["build_job", "skill_activated"],
                severity="important",
            )
        except Exception as e:
            job["status"] = "failed"
            job["errors"].append(f"Activation failed: {e}")
            if self.desire_engine:
                self.desire_engine.update_status(job["source_desire_id"], "failed")
            self._emit_skill_event(
                "skill_failure",
                job,
                f"Build job {job_id} activation failed: {e}",
                salience=0.84,
                uncertainty=0.70,
                valence=-0.65,
                tags=["build_job", "activation_failed"],
                severity="important",
            )
            
        job["updated_at"] = datetime.now().isoformat()
        self._save_job(job)
        return job

    def tick(self) -> None:
        with self._lock:
            self.scan_desires()
            for job in list(self.jobs.values()):
                if job["status"] == "planned":
                    self.plan_job(job["id"])
                elif job["status"] == "approved_for_build":
                    self.build_job(job["id"])
                elif job["status"] == "tests_running":
                    self.run_tests(job["id"])
                elif job["status"] == "review_needed":
                    self.review_job(job["id"])
                elif job["status"] == "activation_pending":
                    if job.get("activation_allowed"):
                        self.activate_skill(job["id"], require_approval=False)

    def _emit_skill_event(self, kind: str, job: Dict[str, Any], content: str,
                          *, salience: float = 0.60, uncertainty: float = 0.25,
                          valence: float = 0.0, tags: Optional[List[str]] = None,
                          severity: str = "info") -> None:
        emit_safe(
            self.event_bus,
            self.log,
            "skill",
            kind,
            content,
            entities=[job.get("id", ""), job.get("source_desire_id", ""), job.get("skill_name", "")],
            raw={"job": dict(job)},
            salience=salience,
            uncertainty=uncertainty,
            valence=valence,
            arousal=0.55 if kind == "skill_failure" else 0.35,
            tags=list(tags or ["build_job"]),
            severity=severity,
        )

    def _emit_goal_event(self, job: Dict[str, Any], content: str,
                         *, salience: float = 0.60, uncertainty: float = 0.30,
                         valence: float = 0.0, tags: Optional[List[str]] = None,
                         severity: str = "info") -> None:
        emit_safe(
            self.event_bus,
            self.log,
            "goal",
            "goal_progress",
            content,
            entities=[job.get("id", ""), job.get("source_desire_id", "")],
            raw={"job": dict(job)},
            salience=salience,
            uncertainty=uncertainty,
            valence=valence,
            arousal=0.40,
            tags=list(tags or ["build_job", "goal_state"]),
            severity=severity,
        )
