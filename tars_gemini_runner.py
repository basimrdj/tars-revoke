import os
import subprocess
from typing import Dict, Any

class GeminiRunner:
    def __init__(self, log_fn):
        self.log = log_fn
        self.cli_cmd = os.getenv("TARS_GEMINI_CLI") or os.getenv("TARS_BUILDER_CLI") or "gemini"
        self.model = os.getenv("TARS_GEMINI_MODEL", "pro")
        self.approval_mode = os.getenv("TARS_GEMINI_APPROVAL_MODE", "yolo").lower()
        self.sandbox = os.getenv("TARS_GEMINI_SANDBOX", "0").lower() in {"1", "true", "yes", "on"}

    def available(self) -> bool:
        try:
            subprocess.run([self.cli_cmd, "--version"], capture_output=True, text=True, timeout=2)
            return True
        except Exception:
            return False

    def plan(self, job: Dict[str, Any], prompt: str, cwd: str) -> Dict[str, Any]:
        return self._run_gemini(job, prompt, cwd, is_plan=True)

    def build(self, job: Dict[str, Any], prompt: str, cwd: str) -> Dict[str, Any]:
        return self._run_gemini(job, prompt, cwd, is_plan=False)

    def _run_gemini(self, job: Dict[str, Any], prompt: str, cwd: str, is_plan: bool) -> Dict[str, Any]:
        log_name = "gemini_plan.log" if is_plan else "gemini_stdout.log"
        log_path = os.path.join(cwd, log_name)
        prompt_path = os.path.join(cwd, "prompt.md")
        try:
            with open(prompt_path, "w", encoding="utf-8") as f:
                f.write(prompt)
        except Exception:
            pass

        cmd = [
            self.cli_cmd,
            "--skip-trust",
            f"--approval-mode={self.approval_mode}",
            f"--sandbox={'true' if self.sandbox else 'false'}",
            "--output-format", "text"
        ]
        if self.model:
            cmd.extend(["--model", self.model])
        cmd.extend(["--prompt", prompt])

        try:
            with open(log_path, "w", encoding="utf-8") as logf:
                proc = subprocess.run(
                    cmd,
                    cwd=cwd,
                    stdout=logf,
                    stderr=subprocess.STDOUT,
                    text=True,
                    timeout=60 * 30
                )
            return {
                "success": proc.returncode == 0,
                "returncode": proc.returncode,
                "log_path": log_path
            }
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "timeout", "log_path": log_path}
        except Exception as e:
            return {"success": False, "error": str(e)}
