import os
import json
from typing import Dict, Any

class PatchReview:
    def __init__(self, log_fn):
        self.log = log_fn
        self.danger_patterns = [
            "rm -rf", "os.system", "shell=True", "eval(", "exec(", 
            "~/.ssh", "chmod 777", "curl | bash"
        ]

    def review_job(self, workspace_dir: str) -> Dict[str, Any]:
        manifest_path = os.path.join(workspace_dir, "manifest.json")
        if not os.path.exists(manifest_path):
            return {
                "approved": False,
                "risk": "high",
                "issues": ["Missing manifest.json"],
                "required_fixes": ["Create manifest.json"],
                "safe_to_activate": False
            }
        
        try:
            with open(manifest_path, "r", encoding="utf-8") as f:
                manifest = json.load(f)
            required = {"name", "description", "triggers", "type", "entry", "io"}
            missing = required - manifest.keys()
            if missing:
                return {
                    "approved": False,
                    "risk": "medium",
                    "issues": [f"Missing manifest keys: {missing}"],
                    "required_fixes": ["Add missing keys"],
                    "safe_to_activate": False
                }
        except Exception as e:
            return {
                "approved": False,
                "risk": "high",
                "issues": [f"Invalid manifest.json: {e}"],
                "required_fixes": ["Fix JSON syntax"],
                "safe_to_activate": False
            }

        issues = []
        for root, dirs, files in os.walk(workspace_dir):
            if "node_modules" in root or ".venv" in root or ".git" in root:
                continue
            for file in files:
                if file.endswith((".py", ".js", ".sh", ".ts")):
                    filepath = os.path.join(root, file)
                    try:
                        with open(filepath, "r", encoding="utf-8") as f:
                            content = f.read()
                            for pat in self.danger_patterns:
                                if pat in content:
                                    issues.append(f"Dangerous pattern '{pat}' found in {file}")
                    except Exception:
                        pass
        
        approved = len(issues) == 0
        return {
            "approved": approved,
            "risk": "medium" if not approved else "low",
            "issues": issues,
            "required_fixes": issues,
            "safe_to_activate": approved
        }
