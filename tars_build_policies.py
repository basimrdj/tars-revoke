import os

class BuildPolicy:
    def __init__(self):
        self.auto_plan = os.getenv("TARS_BUILD_AUTO_PLAN", "1") == "1"
        self.auto_sandbox = os.getenv("TARS_BUILD_AUTO_SANDBOX", "1") == "1"
        self.auto_activate_low_risk = os.getenv("TARS_BUILD_AUTO_ACTIVATE_LOW_RISK", "0") == "1"
        self.allow_core_edits = os.getenv("TARS_BUILD_ALLOW_CORE_EDITS", "0") == "1"
        self.allow_full_perms = os.getenv("TARS_BUILD_ALLOW_FULL_PERMS", "0") == "1"

    def classify_risk(self, capability: str) -> str:
        text = capability.lower()
        if any(w in text for w in ["rm -rf", "delete", "system", "os.system", "core", "kernel", "sudo", "chmod 777", "~/.ssh"]):
            return "critical"
        if any(w in text for w in ["modify tars", "edit soul", "update memory logic", "tars_"]):
            return "high"
        if any(w in text for w in ["read file", "parse", "fetch", "http"]):
            return "medium"
        return "low"
