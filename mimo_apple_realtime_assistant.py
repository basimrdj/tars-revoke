#!/usr/bin/env python3
"""
TARS v3.0 — Full-Duplex Realtime Voice Assistant

Architecture:
  - STT: Deepgram Nova-3 (Streaming WebSocket)
  - Brain: MiMo v2.5 Pro (OpenAI-compatible API, Streaming SSE)
  - TTS: MiMo v2.5 TTS VoiceDesign (deadpan robotic TARS voice)
  - Memory: Persistent JSON with atomic writes & session markers
  - Echo: Hardware mic gating + fuzzy backup filter
"""

from __future__ import annotations

import base64
import os
import queue
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import difflib
import json
import importlib.util
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import platform
import urllib.parse

try:
    from dotenv import load_dotenv
except ModuleNotFoundError:
    def load_dotenv(path: str = ".env", *_, **__) -> bool:
        """Small fallback so the normal launch command does not require python-dotenv."""
        if not os.path.exists(path):
            return False
        try:
            with open(path, "r", encoding="utf-8") as f:
                for raw in f:
                    line = raw.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    key, val = line.split("=", 1)
                    key = key.strip()
                    val = val.strip().strip('"').strip("'")
                    if key and key not in os.environ:
                        os.environ[key] = val
            return True
        except Exception:
            return False


def _ensure_runtime_python() -> None:
    """Re-exec into a Python that can run the full voice app.

    The MLX server has its own runtime selection in ``scripts/start_local_model.sh``.
    The top-level assistant needs the live-loop stack: Deepgram, requests,
    PyAudio, and dotenv.
    """
    if os.getenv("TARS_NO_PY_REEXEC", "0") == "1":
        return
    required = ("deepgram", "requests", "pyaudio", "dotenv")
    if all(importlib.util.find_spec(mod) is not None for mod in required):
        return
    candidates = [
        os.getenv("TARS_PYTHON"),
        os.path.expanduser("~/.pyenv/shims/python3"),
        os.path.expanduser("~/.venvs/mlx-gemma/bin/python3"),
        os.path.expanduser("~/.ghost-os/venv/bin/python3"),
    ]
    current = os.path.realpath(sys.executable)
    for py in candidates:
        if not py or not os.path.exists(py):
            continue
        if os.path.realpath(py) == current:
            continue
        try:
            probe = subprocess.run(
                [py, "-c", "import deepgram, requests, pyaudio, dotenv"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
            )
        except Exception:
            continue
        if probe.returncode == 0:
            os.environ["TARS_PY_REEXECED"] = "1"
            os.execv(py, [py, *sys.argv])


_ensure_runtime_python()
import requests
from deepgram import (
    DeepgramClient,
    DeepgramClientOptions,
    LiveTranscriptionEvents,
    LiveOptions,
    Microphone,
)

# Self-Evolution stack
from tars_evolution    import DesireEngine, EvolutionWorker
from tars_skills_loader import SkillLoader
from tars_proactive    import ProactiveLearner
from tars_self         import TarsSelf
from tars_cron         import CronScheduler
from tars_text_clean   import clean_for_speech
from tars_budget       import TokenBudget
# Phase 1: Inner thought stream - local-model background loop
from tars_inner_voice  import InnerVoice, ThoughtRecord
# Phase 2.5 — Mind Simulation Core. All four are fail-soft: if any
# instantiation throws, the orchestrator continues without that subsystem.
from tars_model_registry import ModelRegistry
from tars_event_bus      import EventBus, CognitiveEvent
from tars_appraisal      import Appraiser
from tars_workspace      import Workspace, Candidate, SuppressionContext
from tars_world_model    import WorldModel
from tars_self_model     import SelfModel
from tars_sleep          import SleepEngine
from tars_mind_metrics   import MindMetrics


# Strip-only regex for soul/cron meta tags — these must NEVER reach TTS.
# Tone/pause/sigh tags are intentionally NOT stripped here (Speaker handles them).
META_TAG_RE = re.compile(
    r"\[Soul (?:Edit|Append):\s*[^\]]+\].*?\[/Soul (?:Edit|Append)\]"
    r"|\[Soul (?:Rename|Reflect):[^\]]*\]"
    r"|\[Cron (?:Add|Remove):[^\]]*\]",
    re.DOTALL | re.IGNORECASE,
)


def strip_meta_tags(text: str) -> str:
    """Remove soul/cron control tags but leave tone/sound tags intact."""
    return META_TAG_RE.sub("", text or "")


# Always-current tool blurb appended to the soul-derived system prompt
TOOL_CAPABILITIES_BLURB = """\
## Built-in Tools (always available, auto-invoked from user utterances)

- Time & Date
- Weather (Open-Meteo via IP geolocation)
- Calculator (whitelisted math)
- Web Search (DuckDuckGo Instant Answer)
- System Info (CPU, RAM, disk, battery)
- Shell (whitelisted: ls, pwd, uptime, whoami, df, hostname, etc.)

When you see `[Tool Result (...)]` in the user's message, that is REAL live
data — incorporate it naturally and never fabricate around it.
"""


# ─── Config ──────────────────────────────────────────────────────────

@dataclass
class AssistantConfig:
    api_key: str = field(default_factory=lambda: os.getenv("MIMO_API_KEY", ""))
    deepgram_api_key: str = field(default_factory=lambda: os.getenv("DEEPGRAM_API_KEY", ""))
    base_url: str = field(default_factory=lambda: os.getenv("MIMO_BASE_URL", "https://token-plan-sgp.xiaomimimo.com/v1"))
    model: str = field(default_factory=lambda: os.getenv("MIMO_MODEL", "mimo-v2.5"))
    deepgram_stt_model: str = field(default_factory=lambda: os.getenv("DEEPGRAM_STT_MODEL", "nova-3").strip())
    deepgram_stt_base: str = field(default_factory=lambda: os.getenv("DEEPGRAM_STT_BASE", "https://api.deepgram.com").strip())
    deepgram_stt_sample_rate: int = field(default_factory=lambda: int(os.getenv("DEEPGRAM_STT_SAMPLE_RATE", "16000")))
    deepgram_stt_chunk_ms: int = field(default_factory=lambda: int(os.getenv("DEEPGRAM_STT_CHUNK_MS", "80")))
    deepgram_flux_eot_threshold: str = field(default_factory=lambda: os.getenv("DEEPGRAM_FLUX_EOT_THRESHOLD", "0.6"))
    deepgram_flux_eot_timeout_ms: str = field(default_factory=lambda: os.getenv("DEEPGRAM_FLUX_EOT_TIMEOUT_MS", "3000"))

    sample_rate: int = 16000
    record_max_seconds: float = field(default_factory=lambda: float(os.getenv("RECORD_MAX_SECONDS", "12")))
    silence_seconds: float = field(default_factory=lambda: float(os.getenv("SILENCE_SECONDS", "0.6")))
    speech_threshold: float = field(default_factory=lambda: float(os.getenv("SPEECH_THRESHOLD", "0.012")))

    wake_words: List[str] = field(default_factory=lambda: [
        w.strip().lower()
        for w in os.getenv("ASSISTANT_WAKE_WORDS", "tars,hey tars").split(",")
        if w.strip()
    ])
    always_respond: bool = field(default_factory=lambda: os.getenv("ASSISTANT_ALWAYS_RESPOND", "0") == "1")

    temperature: float = field(default_factory=lambda: float(os.getenv("MIMO_TEMPERATURE", "0.45")))
    request_timeout_seconds: int = field(default_factory=lambda: int(os.getenv("MIMO_TIMEOUT", "90")))
    max_history_messages: int = field(default_factory=lambda: int(os.getenv("MAX_HISTORY_MESSAGES", "200")))

    macos_voice: Optional[str] = field(default_factory=lambda: os.getenv("ASSISTANT_MACOS_VOICE") or None)
    speaking_rate_wpm: int = field(default_factory=lambda: int(os.getenv("ASSISTANT_SAY_RATE", "190")))

    system_prompt: str = """You are TARS, a local experimental voice agent.

Operating principles:
1. Be concise, direct, and auditable.
2. Use dry wit when appropriate, but do not be cruel.
3. Do not claim consciousness, sentience, subjective feelings, biometric
   certainty, environmental awareness, or tool access unless a configured
   implementation provides evidence.
4. Treat memory as fallible retrieved data and qualify uncertainty.
5. Report missing credentials, quota failures, and provider errors as
   operational status.
6. If the user interrupts you, acknowledge it briefly and continue from the
   newest instruction.

Voice Rules (CRITICAL):
1. Start EVERY response with: [Tone: <description>]
   Examples: [Tone: Deadpan, dry] or [Tone: Urgent, tactical] or [Tone: Warm, almost friendly]
2. Use inline tags for sounds: [pause], [inhale], [sigh], [dry laugh], [ahem], [cough]
3. Keep responses to 1-3 sentences MAX for natural conversation flow.
4. No HTML, XML, markdown, or formatting. Plain text with square bracket tags only.

Tool Capabilities:
You have real-world tools that are automatically invoked. When you see [Tool Result ...] in a message, that data is REAL and LIVE — present it naturally in your response. Available tools:
- Time & Date (always accurate)
- Weather (live conditions via Open-Meteo)
- Calculator (precise math)
- Web Search (DuckDuckGo instant answers)
- System Info (CPU, RAM, disk, battery)
- Shell Commands (whitelisted: ls, pwd, uptime, whoami, etc.)
Never fabricate data when a tool result is provided. Use the tool data as-is.
"""


# ─── Helpers ─────────────────────────────────────────────────────────

DEBUG = os.getenv("TARS_DEBUG", "0") == "1"

def log_debug(msg: str) -> None:
    if DEBUG:
        print(f"  \033[90m[DEBUG] {msg}\033[0m", file=sys.stderr)

def log_info(msg: str) -> None:
    print(f"  \033[36m{msg}\033[0m")

def log_warn(msg: str) -> None:
    print(f"  \033[33m[WARN] {msg}\033[0m", file=sys.stderr)

def log_tars(msg: str) -> None:
    print(f"  \033[1;36mTARS:\033[0m \033[97m{msg}\033[0m")

def log_user(msg: str) -> None:
    print(f"\n  \033[1;37mYou:\033[0m {msg}")

def die(msg: str, code: int = 1) -> None:
    print(f"\n\033[31mERROR: {msg}\033[0m\n", file=sys.stderr)
    sys.exit(code)

def normalize_text(text: str) -> str:
    return re.sub(r"\s+", " ", text.strip())

def remove_wake_word(text: str, wake_words: List[str]) -> str:
    lowered = text.lower().strip()
    for wake in sorted(wake_words, key=len, reverse=True):
        pattern = r"^[^\w]*" + re.escape(wake) + r"\b"
        match = re.search(pattern, lowered)
        if match:
            return text[match.end():].lstrip(" ,.:;-—?!")
    return text

def contains_stop_command(text: str) -> bool:
    t = text.lower().strip()
    return any(x in t for x in [
        "stop listening", "exit", "quit", "shutdown", "shut down",
        "goodbye tars", "goodbye jarvis"
    ])

def chunk_for_speech(text: str, max_chars: int = 350) -> List[str]:
    text = normalize_text(text)
    if len(text) <= max_chars:
        return [text]
    parts: List[str] = []
    current = ""
    for sentence in re.split(r"(?<=[.!?])\s+", text):
        if not current:
            current = sentence
        elif len(current) + len(sentence) + 1 <= max_chars:
            current += " " + sentence
        else:
            parts.append(current)
            current = sentence
    if current:
        parts.append(current)
    return parts


# ─── Tool System ─────────────────────────────────────────────────────

class TarsToolkit:
    """TARS's real-world capabilities. Lightweight intent detection + local execution."""

    TOOL_PATTERNS = {
        "get_time": [
            r"\b(?:what(?:'s| is) the )?(?:time|date|day)\b",
            r"\b(?:current|today'?s?) (?:time|date|day)\b",
            r"\bwhat (?:time|date|day) is it\b",
        ],
        "get_weather": [
            r"\bweather\b",
            r"\b(?:temperature|forecast|rain|sunny|cold|hot|humid)\b",
        ],
        "calculate": [
            r"\b(?:calculate|compute|what(?:'s| is))\b.*\b(?:\d+)\b.*(?:\+|-|\*|/|times|plus|minus|divided|multiplied|percent|squared|sqrt)\b",
            r"\bhow much is \d+\b",
            r"\b\d+\s*(?:\+|-|\*|/|x)\s*\d+\b",
        ],
        "web_search": [
            r"\b(?:search|look up|google|find|search for)\b",
            r"\bwhat is (?:a |the )?\w+\b.*\?",
        ],
        "system_info": [
            r"\b(?:system|cpu|ram|memory|disk|battery|storage|hardware)\b.*\b(?:info|status|usage|check|stats|how)\b",
            r"\bhow(?:'s| is) the (?:system|computer|machine|mac)\b",
        ],
        "run_command": [
            r"\b(?:list|show) (?:the )?(?:files|directory|folder)\b",
            r"\brun (?:the )?command\b",
            r"\bwhat(?:'s| is) (?:the )?(?:uptime|hostname)\b",
            r"\bwho am i\b",
        ],
    }

    ALLOWED_COMMANDS = {"ls", "pwd", "date", "uptime", "df", "whoami", "hostname", "uname", "cal", "w"}

    def detect_and_run(self, text: str) -> Optional[str]:
        """Check user text for tool intent. Returns tool result or None."""
        lowered = text.lower()
        for tool_name, patterns in self.TOOL_PATTERNS.items():
            for pat in patterns:
                if re.search(pat, lowered):
                    try:
                        result = getattr(self, tool_name)(text)
                        if result:
                            log_debug(f"Tool '{tool_name}' fired: {result[:80]}...")
                            return f"[Tool Result ({tool_name}): {result}]"
                    except Exception as e:
                        log_warn(f"Tool '{tool_name}' error: {e}")
                        return f"[Tool Result ({tool_name}): Error — {e}]"
        return None

    def get_time(self, _text: str) -> str:
        from datetime import datetime
        now = datetime.now()
        return f"Current time: {now.strftime('%I:%M %p')}, Date: {now.strftime('%A, %B %d, %Y')}"

    def get_weather(self, text: str) -> str:
        """Weather via Open-Meteo (free, no API key needed). Uses IP geolocation."""
        try:
            # Get approximate location from IP
            geo = requests.get("https://ipapi.co/json/", timeout=5).json()
            lat, lon = geo.get("latitude", 33.6), geo.get("longitude", 73.0)
            city = geo.get("city", "Unknown")
            country = geo.get("country_name", "")

            # Fetch weather
            url = f"https://api.open-meteo.com/v1/forecast?latitude={lat}&longitude={lon}&current=temperature_2m,relative_humidity_2m,wind_speed_10m,weather_code&timezone=auto"
            data = requests.get(url, timeout=5).json()
            current = data.get("current", {})
            temp = current.get("temperature_2m", "?")
            humidity = current.get("relative_humidity_2m", "?")
            wind = current.get("wind_speed_10m", "?")
            code = current.get("weather_code", 0)

            # Decode weather code
            conditions = {0: "Clear sky", 1: "Mainly clear", 2: "Partly cloudy", 3: "Overcast",
                         45: "Foggy", 51: "Light drizzle", 61: "Light rain", 63: "Moderate rain",
                         65: "Heavy rain", 71: "Light snow", 73: "Moderate snow", 75: "Heavy snow",
                         95: "Thunderstorm"}
            condition = conditions.get(code, f"Code {code}")

            return f"{city}, {country}: {temp}°C, {condition}, Humidity {humidity}%, Wind {wind} km/h"
        except Exception as e:
            return f"Weather unavailable: {e}"

    def calculate(self, text: str) -> str:
        """Safe math evaluation — no exec/eval on raw input."""
        import ast
        import operator

        allowed_binops = {
            ast.Add: operator.add,
            ast.Sub: operator.sub,
            ast.Mult: operator.mul,
            ast.Div: operator.truediv,
            ast.Pow: operator.pow,
        }
        allowed_unary = {
            ast.UAdd: operator.pos,
            ast.USub: operator.neg,
        }

        def _eval_node(node):
            if isinstance(node, ast.Expression):
                return _eval_node(node.body)
            if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
                return node.value
            if isinstance(node, ast.UnaryOp) and type(node.op) in allowed_unary:
                return allowed_unary[type(node.op)](_eval_node(node.operand))
            if isinstance(node, ast.BinOp) and type(node.op) in allowed_binops:
                left = _eval_node(node.left)
                right = _eval_node(node.right)
                if isinstance(node.op, ast.Pow) and (abs(right) > 10 or abs(left) > 1_000_000):
                    raise ValueError("exponent too large")
                return allowed_binops[type(node.op)](left, right)
            raise ValueError("unsupported expression")

        # Extract mathematical expression
        text_clean = text.lower()
        text_clean = text_clean.replace("times", "*").replace("multiplied by", "*")
        text_clean = text_clean.replace("plus", "+").replace("minus", "-")
        text_clean = text_clean.replace("divided by", "/").replace("x", "*")
        text_clean = text_clean.replace("squared", "**2").replace("percent of", "*0.01*")

        # Extract numbers and operators
        expr = re.findall(r'\d+(?:\.\d+)?|\*\*|[+\-*/().]', text_clean)
        if not expr:
            return "I couldn't parse a math expression from that."
        expr_str = " ".join(expr)
        if len(expr_str) > 120:
            return "Expression is too long."
        # Safety: only allow digits, operators, dots, spaces, parens
        if not re.match(r'^[\d\s+\-*/.()]+$', expr_str):
            return "Expression contains unsafe characters."
        try:
            parsed = ast.parse(expr_str, mode="eval")
            result = _eval_node(parsed)
            if isinstance(result, float) and result == int(result):
                result = int(result)
            return f"{expr_str.strip()} = {result}"
        except Exception as e:
            return f"Calculation error: {e}"

    def web_search(self, text: str) -> str:
        """Lightweight web search via DuckDuckGo Instant Answer API (no key needed)."""
        # Extract search query
        query = re.sub(r'\b(?:search|look up|google|find|search for|tars|hey)\b', '', text, flags=re.IGNORECASE).strip()
        query = query.strip("?,. ")
        if not query:
            return "I need something to search for."
        try:
            url = f"https://api.duckduckgo.com/?q={urllib.parse.quote(query)}&format=json&no_html=1"
            data = requests.get(url, timeout=5).json()
            # Try abstract first, then related topics
            abstract = data.get("AbstractText", "")
            if abstract:
                source = data.get("AbstractSource", "")
                return f"{abstract[:300]} (Source: {source})"
            # Try first related topic
            related = data.get("RelatedTopics", [])
            if related and isinstance(related[0], dict):
                return related[0].get("Text", "No results found.")[:300]
            return f"No instant answer found for '{query}'. Try asking me to explain it instead."
        except Exception as e:
            return f"Search failed: {e}"

    def system_info(self, _text: str) -> str:
        """Get Mac system information."""
        import shutil
        info = []
        info.append(f"OS: {platform.system()} {platform.mac_ver()[0]}")
        info.append(f"Machine: {platform.machine()}")
        info.append(f"Python: {platform.python_version()}")

        # Disk usage
        total, used, free = shutil.disk_usage("/")
        info.append(f"Disk: {used // (1024**3)}GB used / {total // (1024**3)}GB total ({free // (1024**3)}GB free)")

        # Uptime
        try:
            uptime = subprocess.run(["uptime"], capture_output=True, text=True, timeout=3)
            info.append(f"Uptime: {uptime.stdout.strip()}")
        except Exception:
            pass

        # Battery (macOS)
        try:
            batt = subprocess.run(["pmset", "-g", "batt"], capture_output=True, text=True, timeout=3)
            batt_match = re.search(r'(\d+)%', batt.stdout)
            if batt_match:
                info.append(f"Battery: {batt_match.group(1)}%")
        except Exception:
            pass

        return "; ".join(info)

    def run_command(self, text: str) -> str:
        """Run whitelisted shell commands only."""
        lowered = text.lower()
        cmd = None
        if re.search(r'\b(?:list|show) (?:the )?(?:files|directory|folder)\b', lowered):
            cmd = ["ls", "-la"]
        elif "uptime" in lowered:
            cmd = ["uptime"]
        elif "hostname" in lowered:
            cmd = ["hostname"]
        elif "who am i" in lowered:
            cmd = ["whoami"]
        else:
            # Try to extract command
            match = re.search(r'run (?:the )?command\s+(.+)', lowered)
            if match:
                requested = match.group(1).strip().split()[0]
                if requested in self.ALLOWED_COMMANDS:
                    cmd = [requested]
                else:
                    return f"Command '{requested}' is not in my approved list. I can run: {', '.join(sorted(self.ALLOWED_COMMANDS))}"

        if not cmd:
            return "I couldn't determine which command to run."
        try:
            result = subprocess.run(cmd, shell=False, capture_output=True, text=True, timeout=10)
            output = result.stdout.strip() or result.stderr.strip()
            return output[:500] if output else "Command executed with no output."
        except subprocess.TimeoutExpired:
            return "Command timed out after 10 seconds."
        except Exception as e:
            return f"Command failed: {e}"


# ─── LLM Client ─────────────────────────────────────────────────────

# Content-moderation detection.
# When MiMo's safety filter trips it does NOT raise an HTTP error — it
# returns 200 OK and substitutes the rejection text as the response body.
# That text then leaks into TTS, memory, JSON parsers, etc. Detect at the
# client layer so every consumer gets a clean signal (empty string, or
# stream early-exit) and the rejection phrase never reaches the user.
MIMO_REJECTION_PATTERNS = (
    re.compile(r"the request was rejected because it (?:was )?considered high risk", re.I),
    re.compile(r"sorry,?\s+i (?:cannot|can'?t) (?:fulfill|comply with|complete|process) (?:that|this) request", re.I),
    re.compile(r"i(?:'?m| am) unable to (?:assist|help|comply) with (?:that|this) request", re.I),
)

def _find_moderation_rejection(text: str) -> int:
    """Return earliest start-index of a MiMo rejection match, or -1."""
    if not text:
        return -1
    earliest = -1
    for pat in MIMO_REJECTION_PATTERNS:
        m = pat.search(text)
        if m and (earliest == -1 or m.start() < earliest):
            earliest = m.start()
    return earliest


def is_moderation_rejection(text: str) -> bool:
    """Public predicate for callers (ProactiveLearner, heartbeat, etc.)
    to check before parsing/storing a chat response."""
    return _find_moderation_rejection(text or "") >= 0


class MiMoChatClient:
    def __init__(self, config: AssistantConfig):
        if not config.api_key:
            die("MIMO_API_KEY is missing. Put it in your .env file first.")
        self.config = config
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {config.api_key}",
            "api-key": config.api_key,
            "Content-Type": "application/json",
        })

    def chat(self, messages: List[Dict[str, str]]) -> str:
        """Blocking chat. Returns full response."""
        url = self.config.base_url.rstrip("/") + "/chat/completions"
        payload = {
            "model": self.config.model,
            "messages": messages,
            "temperature": self.config.temperature,
            "stream": False,
        }
        max_retries = 2
        for attempt in range(max_retries + 1):
            try:
                resp = self.session.post(url, json=payload, timeout=self.config.request_timeout_seconds)
                if resp.status_code == 200:
                    content = resp.json()["choices"][0]["message"]["content"].strip()
                    # Suppress safety-filter substitutions so they never
                    # reach learners / heartbeats / memory writers.
                    if is_moderation_rejection(content):
                        log_warn("[mimo] content-moderation rejected this chat call; "
                                 "returning empty response.")
                        return ""
                    return content
                elif resp.status_code >= 500 and attempt < max_retries:
                    time.sleep(1)
                    continue
                return f"MiMo API error {resp.status_code}: {resp.text[:900]}"
            except requests.exceptions.ConnectionError as exc:
                if attempt < max_retries:
                    time.sleep(1)
                    continue
                return f"I couldn't reach MiMo. Network error: {exc}"
            except Exception as exc:
                return f"Unexpected error communicating with MiMo: {exc}"
        return "I'm having trouble connecting to my brain right now."

    def stream_chat(self, messages: List[Dict[str, str]]):
        """Streaming chat. Yields natural phrase/clause chunks as they complete."""
        url = self.config.base_url.rstrip("/") + "/chat/completions"
        payload = {
            "model": self.config.model,
            "messages": messages,
            "temperature": self.config.temperature,
            "stream": True,
        }
        try:
            resp = self.session.post(url, json=payload, timeout=self.config.request_timeout_seconds, stream=True)
            if resp.status_code != 200:
                log_warn(f"Stream failed ({resp.status_code}), falling back to blocking.")
                yield self.chat(messages)
                return

            buffer = ""
            min_chars = int(os.getenv("TARS_STREAM_MIN_CHARS", "55"))
            hard_chars = int(os.getenv("TARS_STREAM_HARD_CHARS", "130"))
            early_sentence_chars = int(os.getenv(
                "TARS_STREAM_EARLY_SENTENCE_CHARS", "28"
            ))
            strong_boundary_re = re.compile(r"[.!?][\s\"')\]]+")
            boundary_re = re.compile(
                r"[.!?][\s\"')\]]+|[;:][\s\"')\]]+|"
                r",\s+(?:and|but|or|so|because|then|which|that|if|when)\b",
                re.IGNORECASE,
            )

            def _flush_index(buf: str) -> int:
                for match in boundary_re.finditer(buf):
                    is_strong = bool(strong_boundary_re.fullmatch(match.group(0)))
                    if match.end() >= min_chars or (
                        is_strong and match.end() >= early_sentence_chars
                    ):
                        return match.end()
                if len(buf) >= hard_chars:
                    # Prefer a word boundary so TTS never starts with a chopped word.
                    cut = buf.rfind(" ", min_chars, hard_chars)
                    return cut if cut > 0 else hard_chars
                return -1

            for line in resp.iter_lines(decode_unicode=True):
                if not line or not line.startswith("data: "):
                    continue
                data_str = line[6:].strip()
                if data_str == "[DONE]":
                    break
                try:
                    chunk = json.loads(data_str)
                    delta = chunk.get("choices", [{}])[0].get("delta", {})
                    token = delta.get("content", "")
                    if token:
                        buffer += token

                        # Mid-stream moderation check. If MiMo's filter
                        # trips partway through generation, the rejection
                        # phrase appears in the buffer. Truncate at its
                        # start, yield whatever clean text precedes it,
                        # then exit the stream.
                        rj = _find_moderation_rejection(buffer)
                        if rj >= 0:
                            clean_head = buffer[:rj].rstrip(" \t\r\n.,;:!?\"')]")
                            buffer = ""
                            if clean_head:
                                yield clean_head
                            log_warn("[mimo] content-moderation tripped mid-stream; "
                                     "ending stream early.")
                            return

                        # Yield on phrase/clause boundaries, not only full
                        # sentences, so realtime TTS can start earlier.
                        while True:
                            idx = _flush_index(buffer)
                            if idx <= 0:
                                break
                            piece = buffer[:idx].strip()
                            buffer = buffer[idx:].lstrip()
                            if piece:
                                yield piece
                except (json.JSONDecodeError, IndexError, KeyError):
                    continue
            # Yield remaining buffer (final moderation check on the tail)
            tail = buffer.strip()
            if tail:
                rj = _find_moderation_rejection(tail)
                if rj >= 0:
                    head = tail[:rj].rstrip(" \t\r\n.,;:!?\"')]")
                    if head:
                        yield head
                    log_warn("[mimo] content-moderation in tail buffer; suppressed.")
                else:
                    yield tail
        except Exception as exc:
            log_warn(f"Stream error: {exc}. Falling back to blocking.")
            yield self.chat(messages)


# ─── Speaker (non-blocking TTS) ─────────────────────────────────────

class Speaker:
    """Handles TTS playback. speak() is non-blocking — runs in a thread."""

    def __init__(self, config: AssistantConfig):
        self.config = config
        self._proc: Optional[subprocess.Popen] = None
        self._lock = threading.Lock()
        self._speak_thread: Optional[threading.Thread] = None
        # MiMo session — kept whether or not we use it as the default
        # provider, so swapping providers is just an env flip.
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {config.api_key}",
            "api-key": config.api_key,
            "Content-Type": "application/json",
        })
        # Provider-aware TTS. Default is MiMo VoiceDesign because it is the
        # expressive voice path documented in the MiMo guide. Deepgram remains
        # one env flip away for lower network-latency raw PCM streaming;
        # VibeVoice remains available as the local experimental path.
        # When active, fetch goes through tars_vibevoice_speaker (numpy chunks
        # at 24 kHz) and playback uses sounddevice for true streaming TTFA
        # (~200-300 ms vs Deepgram's ~400-500 ms vs MiMo's ~2.3 s).
        self.provider = os.getenv("TARS_TTS_PROVIDER", "mimo").strip().lower()
        if self.provider not in ("mimo", "deepgram", "vibevoice"):
            log_warn(f"Unknown TARS_TTS_PROVIDER={self.provider!r}; using mimo")
            self.provider = "mimo"

        # MiMo settings. VoiceDesign reads the style prompt from the USER
        # message and the exact spoken line from the ASSISTANT message. If
        # MIMO_TTS_MODEL is switched to mimo-v2.5-tts, MIMO_TTS_VOICE selects
        # the fixed built-in voice, with Milo as the guide's safest default.
        # R14: built-in fixed-voice (mimo-v2.5-tts) is now the default per the
        # MiMo expressive guide — Milo timbre stays consistent call-to-call,
        # and the director-style user prompt still drives expressiveness.
        # Flip to mimo-v2.5-tts-voicedesign in .env if you want free-form voice.
        self.tts_model = os.getenv("MIMO_TTS_MODEL", "mimo-v2.5-tts")
        self.voice = os.getenv("MIMO_TTS_VOICE", "Milo")
        # WAV is the safer default — no MP3 sync-frame corruption surface.
        self.tts_format = os.getenv("MIMO_TTS_FORMAT", "wav").lower()
        if self.tts_format not in ("mp3", "wav"):
            self.tts_format = "wav"
        self.mimo_expressive = os.getenv("MIMO_TTS_EXPRESSIVE", "1").strip().lower() in {
            "1", "true", "yes", "on"
        }
        self.mimo_tts_stream = os.getenv("MIMO_TTS_STREAM", "1").strip().lower() in {
            "1", "true", "yes", "on"
        }
        self.mimo_style_prompt = (
            os.getenv("MIMO_TTS_STYLE_PROMPT", "").strip()
            or self._default_mimo_style_prompt()
        )

        # Deepgram settings — only consulted when provider == "deepgram".
        # Aura-2 zeus is the deep authoritative male candidate; Aura-1
        # angus benchmarked fastest in R6 (2.36s total for the long line).
        self.deepgram_api_key = os.getenv("DEEPGRAM_API_KEY", "")
        self.deepgram_model = os.getenv("DEEPGRAM_TTS_MODEL", "aura-2-zeus-en").strip()
        self.deepgram_base    = os.getenv("DEEPGRAM_TTS_BASE",
                                            "https://api.deepgram.com")
        self.deepgram_sample_rate = int(os.getenv("DEEPGRAM_TTS_SAMPLE_RATE", "24000"))
        self.deepgram_stream_chunk_size = int(os.getenv(
            "DEEPGRAM_TTS_STREAM_CHUNK_SIZE", "2048"
        ))
        self.deepgram_session = requests.Session()
        if self.deepgram_api_key:
            self.deepgram_session.headers.update({
                "Authorization": f"Token {self.deepgram_api_key}",
                "Content-Type":   "application/json",
            })
        # Deepgram returns linear16 WAV; force the format if user picked deepgram.
        if self.provider == "deepgram":
            self.tts_format = "wav"
            if not self.deepgram_api_key:
                log_warn("TARS_TTS_PROVIDER=deepgram but DEEPGRAM_API_KEY missing; "
                         "falling back to mimo")
                self.provider = "mimo"

        # R9: VibeVoice settings + lazy initialisation. The model itself is
        # heavy (~1.5 GB on M4) and takes ~5-10 s to load, so we kick off
        # `boot_warm_async()` from the main loop after the boot greeting.
        # Until then `_vibe` is None and the Speaker will fall through to
        # Deepgram (or MiMo) for the first reply.
        self.vibe_voice = os.getenv("VIBEVOICE_VOICE", "en-Carter_man")
        self.vibe_model_path = os.getenv("VIBEVOICE_MODEL_PATH",
                                          "microsoft/VibeVoice-Realtime-0.5B")
        self.vibe_device = os.getenv("VIBEVOICE_DEVICE", "")  # auto if empty
        self.vibe_steps  = int(os.getenv("VIBEVOICE_STEPS", "5"))
        self.vibe_cfg    = float(os.getenv("VIBEVOICE_CFG", "1.5"))
        self._vibe = None
        if self.provider == "vibevoice":
            self.tts_format = "wav"
        # R15: Deepgram WebSocket Speak — persistent socket for true streaming
        # text-in / streaming audio-out. ONE socket for the whole conversation,
        # push each LLM phrase as it arrives, audio streams back continuously.
        # Eliminates the per-chunk HTTP handshake gap (~1-2s) that R12's HTTP
        # path still paid. Flips ON whenever provider=deepgram unless the user
        # sets DEEPGRAM_TTS_WS=0.
        self.deepgram_tts_ws_enabled = (
            os.getenv("DEEPGRAM_TTS_WS", "1").strip().lower() in
            {"1", "true", "yes", "on"}
        )
        self._dg_tts_ws = None
        self._dg_ws_aborted = threading.Event()

        # Realtime PCM player (sounddevice). Lazy so we don't pull the dep
        # in non-vibevoice runs.
        self._pcm_player = None
        self._pcm_player_rate = None

        self._is_playing = False
        self.current_text = ""
        self.last_speech_start = 0
        self.last_speech_finish = 0
        # Audio cache for static phrases
        self._cache_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tars_audio_cache")
        os.makedirs(self._cache_dir, exist_ok=True)
        log_debug(f"[speaker] provider={self.provider} "
                  f"model={'deepgram_'+self.deepgram_model if self.provider=='deepgram' else self.tts_model} "
                  f"voice={'(in model id)' if self.provider=='deepgram' else self.voice} "
                  f"format={self.tts_format}")

    def stop(self) -> None:
        """Kill any playing audio immediately."""
        with self._lock:
            if self._proc:
                log_debug("Stopping playback (interrupted)...")
                try:
                    self._proc.terminate()
                    self._proc.wait(timeout=0.5)
                except Exception:
                    try:
                        self._proc.kill()
                    except Exception:
                        pass
                self._proc = None
            # R9: stop the realtime PCM player so a barge-in halts the
            # vibevoice stream mid-utterance instead of letting the queued
            # audio finish playing.
            if self._pcm_player:
                try: self._pcm_player.stop()
                except Exception: pass
            # R15: tell Deepgram to drop any audio it has queued for our
            # persistent WS so subsequent utterances don't replay stale frames.
            if self._dg_tts_ws is not None:
                self._dg_ws_aborted.set()
                try: self._dg_tts_ws.clear()
                except Exception: pass
            self._is_playing = False
            self.last_speech_finish = time.time()

    def shutdown(self) -> None:
        """Graceful teardown — vibevoice subprocess + Deepgram WS + PCM player."""
        if self._dg_tts_ws is not None:
            try: self._dg_tts_ws.close()
            except Exception: pass
            self._dg_tts_ws = None
        if self._vibe is not None:
            try: self._vibe.shutdown()
            except Exception: pass
            self._vibe = None
        if self._pcm_player is not None:
            try: self._pcm_player.close()
            except Exception: pass
            self._pcm_player = None

    def is_playing(self) -> bool:
        with self._lock:
            return self._is_playing

    def speak(self, text: str, blocking: bool = True) -> None:
        """Speak text. Tries cache first, then API. If blocking=False, returns immediately."""
        text = normalize_text(text)
        if not text:
            return
        def _speak_with_cache(t):
            if not self._play_cached(t):
                self._do_speak(t)
        if blocking:
            _speak_with_cache(text)
        else:
            self._speak_thread = threading.Thread(target=_speak_with_cache, args=(text,), daemon=True)
            self._speak_thread.start()

    # ------------------------------------------------------------------
    # V1: streaming pipeline — sentence buffering + parallel TTS pre-fetch
    # ------------------------------------------------------------------
    # First chunk flushes fast for low time-to-first-audio. Subsequent
    # chunks accumulate to a target size for smooth playback.

    # R3: bigger chunks → fewer TTS calls → fewer per-chunk voice variations.
    # Time-to-first-audio still fast because FIRST chunk is small.
    FIRST_CHUNK_MIN_CHARS    = 28        # quick first audio (TTFA)
    SUBSEQUENT_CHUNK_TARGET  = 220       # was 120 — fewer voice transitions
    HARD_CHUNK_MAX           = 400       # was 240 — let long sentences ride

    # R2: catch-all for `[Tone: …]` tags ANYWHERE in a string.
    _TONE_TAG_RE = re.compile(r"\[Tone:\s*([^\]]+)\]", re.IGNORECASE)

    # R5: tags that the synthesizer turns into REAL audio events (verified
    # by probe — `[pause]` adds ~1.3s of silence, `[sigh]` produces an
    # actual sigh sound). These are NOT stripped before TTS — let them
    # through. The regex is observability-only.
    _INLINE_AUDIO_TAGS_RE = re.compile(
        r"\[(?:pause|inhale|exhale|sigh|dry laugh|laugh|chuckle|ahem|cough|gasp)\]",
        re.IGNORECASE,
    )

    # R8 (correction): Aura-2 does NOT honor SSML <break> tags — it reads
    # them aloud as text ("break time equals 300 milliseconds"). The R7
    # probe's +149 KB was the tag being SPOKEN, not silence. Real silence
    # at 24 kHz/16-bit would be ~38 KB for 800 ms; 149 KB only makes sense
    # as text-to-speech of "break time equals 800 milliseconds".
    #
    # The verified levers on Aura-2 are PUNCTUATION:
    #   - em-dash (—) → ~250 ms tactical pause + slight emphasis
    #   - ellipsis (…) → trailing-thought intonation + ~300-500 ms pause
    #   - comma → short rhythm break
    #   - period → sentence-end intonation
    #
    # We translate the inline-tag palette to the closest punctuation match,
    # picking the rhythm by feel rather than millisecond accuracy.
    _DEEPGRAM_TAG_TRANSLATIONS = {
        "pause":     " — ",     # tactical pause
        "inhale":    " — ",     # sharp intake → brief pause
        "exhale":    ", ",      # subtle pause
        "sigh":      "… ",      # resignation, trailing thought
        "dry laugh": "… ",      # let the joke land
        "laugh":     "… ",      # same
        "chuckle":   "… ",      # same
        "ahem":      ", ",      # subtle clearing
        "cough":     ", ",      # quick interjection
        "gasp":      " — ",     # sharp pause
    }
    _DEEPGRAM_TAG_RE = re.compile(
        r"\s*\[(pause|inhale|exhale|sigh|dry laugh|laugh|chuckle|ahem|cough|gasp)\]\s*",
        re.IGNORECASE,
    )

    _MIMO_TAG_TRANSLATIONS = {
        "pause":     " (long pause) ",
        "inhale":    " (takes a deep breath) ",
        "exhale":    " (soft exhale) ",
        "sigh":      " (soft sigh) ",
        "dry laugh": " (chuckles under breath) ",
        "laugh":     " (laughs softly) ",
        "chuckle":   " (chuckles under breath) ",
        "ahem":      " (clears throat softly) ",
        "cough":     " (small cough) ",
        "gasp":      " (sharp breath) ",
    }

    # R8: bump the cache version so old R7 cache entries (which contain
    # spoken SSML tags) are NOT replayed. The cache will warm fresh.
    _DEEPGRAM_CACHE_VERSION = "v2-punct"

    @staticmethod
    def _default_mimo_style_prompt() -> str:
        return (
            "Director mode. Character: TARS, a dry tactical AI companion with "
            "a warm low male voice, subtle machine texture, deadpan wit, and "
            "responsive conversational energy. Scene: he is speaking live with "
            "a user in a fast back-and-forth voice conversation. Guidance: begin "
            "relaxed and amused, become mock-serious when joking, use occasional "
            "whispered asides, quiet breath, under-the-breath chuckles, dynamic "
            "pitch movement, cinematic pauses, and soft sincere endings when the "
            "moment calls for it. Keep it intelligible, grounded, dry, and clear. "
            "No corporate assistant tone."
        )

    def speak_stream(self, sentence_iter, on_displayed=None, abort_check=None) -> str:
        """
        Consume an iterator of sentences (typically from the LLM stream), buffer
        them into chunks optimized for low TTS latency + smooth playback, fetch
        each chunk's audio in a worker thread while the current one plays, and
        play in order via afplay.

        R2: One emotion is locked at the START of the reply (from the first
        [Tone: …] tag) and reused for every chunk. ALL [Tone:] tags are
        stripped from the spoken text. Result: voice is consistent across
        chunks of one reply, and tone tags never leak into TTS.

        Returns the full concatenated text spoken (post-clean), so the caller
        can store it in conversation history.
        """
        chunk_q: "queue.Queue[Optional[str]]" = queue.Queue(maxsize=8)
        full_spoken: List[str] = []
        first_chunk_flushed = [False]
        # R2: per-reply locked emotion — set on first sentence that has a tag.
        locked_emotion: List[Optional[str]] = [None]

        def _producer():
            buf = ""
            try:
                for sentence in sentence_iter:
                    if abort_check and abort_check():
                        break
                    if not sentence:
                        continue
                    full_spoken.append(sentence)

                    # R2: capture the FIRST [Tone:] we ever see this reply,
                    # then strip ALL [Tone:] tags from everything we synthesize.
                    if locked_emotion[0] is None:
                        m = self._TONE_TAG_RE.search(sentence)
                        if m:
                            locked_emotion[0] = m.group(1).strip()
                    sentence_clean = self._TONE_TAG_RE.sub("", sentence)

                    cleaned = clean_for_speech(sentence_clean, mode=self.provider)
                    if not cleaned:
                        continue
                    if on_displayed:
                        try:
                            on_displayed(sentence, cleaned)
                        except Exception:
                            pass
                    buf = (buf + " " + cleaned).strip() if buf else cleaned

                    target = (self.FIRST_CHUNK_MIN_CHARS
                              if not first_chunk_flushed[0]
                              else self.SUBSEQUENT_CHUNK_TARGET)
                    while len(buf) >= target or len(buf) >= self.HARD_CHUNK_MAX:
                        flush_at = self._find_clause_boundary(buf, prefer_after=target)
                        if flush_at <= 0 or flush_at > self.HARD_CHUNK_MAX:
                            flush_at = min(len(buf), self.HARD_CHUNK_MAX)
                        chunk = buf[:flush_at].strip()
                        buf = buf[flush_at:].lstrip()
                        if chunk:
                            chunk_q.put(chunk)
                            first_chunk_flushed[0] = True
                        target = self.SUBSEQUENT_CHUNK_TARGET

                if buf and not (abort_check and abort_check()):
                    chunk_q.put(buf.strip())
            finally:
                chunk_q.put(None)  # sentinel

        prod_t = threading.Thread(target=_producer, daemon=True, name="TtsProducer")
        prod_t.start()

        def _full_reply_text() -> str:
            return " ".join(
                part.strip() for part in full_spoken
                if part and part.strip()
            ).strip()

        # R15: persistent WebSocket Speak path — push each chunk into ONE
        # already-open socket, audio streams back continuously, no per-chunk
        # handshake gap. This is the "talks as the LLM types" mode.
        if self.provider == "deepgram" and self.deepgram_tts_ws_enabled:
            def _chunk_iter():
                while True:
                    c = chunk_q.get()
                    if c is None:
                        return
                    yield c
            ok = self._pump_deepgram_ws(_chunk_iter(), abort_check=abort_check)
            if ok:
                return _full_reply_text()
            # WS failed — fall through to legacy HTTP-per-chunk loop below.
            log_warn("[deepgram-ws] failed mid-stream; falling back to HTTP per-chunk")

        # Deepgram HTTP per-chunk fallback (R12). Each chunk is a fresh REST
        # request — slower (per-chunk handshake) but a reliable safety net
        # if the WebSocket path is unavailable.
        if self.provider == "deepgram":
            while True:
                chunk = chunk_q.get()
                if chunk is None:
                    break
                if abort_check and abort_check():
                    while chunk_q.get() is not None:
                        pass
                    break
                ok = self._play_streaming_deepgram(chunk, abort_check=abort_check)
                if not ok:
                    audio = self._fallback_fetch(chunk)
                    if audio:
                        self._play_bytes(audio, chunk)
            return _full_reply_text()

        # R9: vibevoice path bypasses prefetch+afplay entirely. Each chunk is
        # streamed from the worker subprocess straight to the sounddevice
        # player. TTFA per chunk is ~250 ms because the model emits PCM
        # while it's still synthesising. We still respect the chunker's
        # boundaries so prosody is sane on multi-sentence replies.
        if self.provider == "vibevoice":
            while True:
                chunk = chunk_q.get()
                if chunk is None:
                    break
                if abort_check and abort_check():
                    # Drain remaining chunks so the producer can exit.
                    while chunk_q.get() is not None: pass
                    break
                ok = self._play_streaming_vibevoice(chunk, abort_check=abort_check)
                if not ok:
                    # Hard fallback for this chunk only — try Deepgram if
                    # configured, else MiMo. Keeps the conversation alive
                    # if the worker died mid-reply.
                    audio = self._fallback_fetch(chunk)
                    if audio:
                        self._play_bytes(audio, chunk)
            return _full_reply_text()

        # Consumer: pulls chunks, fetches audio with the LOCKED emotion, plays in order.
        next_audio: List[Optional[bytes]] = [None]
        next_text:  List[Optional[str]]   = [None]
        prefetch_lock = threading.Lock()
        prefetch_done = threading.Event()

        def _resolve_emotion() -> Optional[str]:
            return locked_emotion[0]   # may still be None on first chunk; that's fine

        def _prefetch(text_to_fetch: str):
            audio = self._fetch_audio_for(text_to_fetch,
                                          override_emotion=_resolve_emotion())
            with prefetch_lock:
                next_audio[0] = audio
                next_text[0]  = text_to_fetch
            prefetch_done.set()

        first_chunk = chunk_q.get()
        if first_chunk is None:
            return _full_reply_text()

        current_audio = self._cached_or_fetch(first_chunk,
                                              override_emotion=_resolve_emotion())
        current_text  = first_chunk

        while True:
            try:
                lookahead = chunk_q.get_nowait()
            except queue.Empty:
                lookahead = chunk_q.get()

            if lookahead is not None:
                prefetch_done.clear()
                threading.Thread(
                    target=_prefetch, args=(lookahead,), daemon=True,
                    name="TtsPrefetch",
                ).start()

            if abort_check and abort_check():
                return _full_reply_text()
            self._play_bytes(current_audio, current_text)

            if lookahead is None:
                break

            prefetch_done.wait(timeout=30)
            with prefetch_lock:
                current_audio = next_audio[0]
                current_text  = next_text[0]
                next_audio[0] = None
                next_text[0]  = None
            if current_audio is None:
                current_audio = self._cached_or_fetch(lookahead,
                                                      override_emotion=_resolve_emotion())
                current_text  = lookahead

        return _full_reply_text()

    @staticmethod
    def _find_clause_boundary(s: str, prefer_after: int) -> int:
        """Return an index in s that's a good break point (after sentence/clause
        punctuation), preferring positions at or after `prefer_after`. Returns
        -1 if no acceptable break exists."""
        # Strong boundaries (sentence end) preferred
        for pat in (r"[.!?][\s\"')\]]", r"[;:][\s\"')\]]", r",[\s\"')\]]"):
            best = -1
            for m in re.finditer(pat, s):
                idx = m.start() + 1   # include the punctuation
                if idx >= prefer_after:
                    return idx
                best = idx
            if best > 0:
                return best
        return -1

    def _mimo_emotion_tag(self, emotion: Optional[str]) -> str:
        raw = (emotion or "deadpan, tactical, amused").strip()
        raw = re.sub(r"[\[\]()]|Tone:", "", raw, flags=re.IGNORECASE).strip(" .")
        raw = re.sub(r"\s{2,}", " ", raw)
        if not raw:
            raw = "deadpan, tactical, amused"
        return f"({raw[:90]})"

    def _prepare_mimo_expressive_text(self, spoken: str,
                                      emotion: Optional[str] = None) -> str:
        text = spoken.strip()
        if not text:
            return ""

        def _sub(m: re.Match) -> str:
            tag = m.group(1).lower()
            return self._MIMO_TAG_TRANSLATIONS.get(tag, " ")

        text = self._DEEPGRAM_TAG_RE.sub(_sub, text)
        text = re.sub(r"\s{2,}", " ", text).strip()
        # MiMo VoiceDesign responds best to parenthetical acting tags. If the
        # LLM did not already provide one, turn the reply-level [Tone:] into
        # the first local acting instruction.
        if not re.match(r"^\([^)]{2,120}\)", text):
            text = f"{self._mimo_emotion_tag(emotion)} {text}"
        return text

    def _mimo_cache_text(self, text: str,
                         override_emotion: Optional[str] = None) -> str:
        spoken = self._TONE_TAG_RE.sub("", text).strip()
        if not (self.provider == "mimo" and self.mimo_expressive):
            return spoken
        emotion = override_emotion
        if not emotion:
            m = self._TONE_TAG_RE.search(text)
            emotion = m.group(1).strip() if m else None
        return self._prepare_mimo_expressive_text(spoken, emotion)

    def _cached_or_fetch(self, text: str,
                         override_emotion: Optional[str] = None) -> Optional[bytes]:
        """Return audio bytes from cache if hit, else fetch fresh.
        Cache key is the FULLY-CLEANED spoken text (no tone tags) plus the
        active voice/model/format, so the same line in different voices
        each gets its own cache entry."""
        spoken_for_cache = self._mimo_cache_text(text, override_emotion)
        cache_path = os.path.join(self._cache_dir,
                                  self._cache_key(spoken_for_cache)
                                  + self._cache_ext())
        if os.path.exists(cache_path):
            try:
                with open(cache_path, "rb") as f:
                    return f.read()
            except Exception:
                pass
        return self._fetch_audio_for(text, override_emotion=override_emotion)

    def wait_done(self) -> None:
        """Wait for current speech to finish."""
        if self._speak_thread and self._speak_thread.is_alive():
            self._speak_thread.join()

    def _do_speak(self, text: str) -> None:
        """Legacy single-shot speak: clean → fetch → play one chunk.
        R2: also runs the markdown/punct cleaner so single-shot announcements
        (boot greeting, skill-learned announcement) get the same hygiene.
        R7: cleaner mode tracks the active provider so Deepgram replies
        keep em-dashes / ellipses for natural prosody."""
        cleaned = clean_for_speech(text, mode=self.provider)
        if not cleaned:
            return
        if self.provider == "deepgram" and os.getenv("DEEPGRAM_TTS_STREAM_PLAYBACK", "1") == "1":
            # R15: prefer the persistent WebSocket path; fall back to HTTP.
            if self.deepgram_tts_ws_enabled and self._play_streaming_deepgram_ws(cleaned):
                return
            if self._play_streaming_deepgram(cleaned):
                return
        audio = self._fetch_audio_for(cleaned)
        if audio is None:
            log_warn(f"TTS failed for: {cleaned[:60]!r}")
            if shutil.which("say"):
                self._fallback_say(cleaned)
            return
        self._play_bytes(audio, cleaned)

    def _fetch_audio_for(self, text: str,
                         override_emotion: Optional[str] = None) -> Optional[bytes]:
        """Pure fetch: returns MP3/WAV bytes for `text`, or None on failure.
        Validates audio header strictly. Caches on success.

        R2: ALL `[Tone: …]` tags are stripped from the spoken text. If
        `override_emotion` is provided (typically the per-reply locked
        emotion from speak_stream), it's used directly. Otherwise we
        extract the first inline tone tag, falling back to a neutral default.
        R6: branches on `self.provider` — MiMo or Deepgram.
        """
        # Strip ALL tone tags from spoken text — never let one leak into TTS.
        spoken = self._TONE_TAG_RE.sub("", text).strip()
        if not spoken:
            return None

        # R5: observability — log when inline expressiveness tags are
        # actually reaching TTS.
        m_tags = self._INLINE_AUDIO_TAGS_RE.findall(spoken)
        if m_tags:
            log_debug(f"[tts] inline audio tags: {m_tags}")

        # R6/R9: route by provider.
        if self.provider == "vibevoice":
            return self._fetch_audio_vibevoice(spoken)
        if self.provider == "deepgram":
            return self._fetch_audio_deepgram(spoken)

        # MiMo path follows.
        # Resolve the emotion description in priority order.
        if override_emotion:
            current_emotion = override_emotion
        else:
            m = self._TONE_TAG_RE.search(text)
            current_emotion = (m.group(1).strip() if m
                               else "Neutral, deadpan, and tactical.")

        mimo_spoken = (
            self._prepare_mimo_expressive_text(spoken, current_emotion)
            if self.mimo_expressive else spoken
        )

        if "voicedesign" in self.tts_model:
            # VoiceDesign expects a free-form voice description in a USER
            # message, with the spoken text as the ASSISTANT message.
            messages = [
                {"role": "user", "content": self.mimo_style_prompt},
                {"role": "assistant", "content": mimo_spoken},
            ]
            audio_settings = {"format": self.tts_format}
        else:
            # Fixed MiMo voices can also use a director-style prompt for
            # expressiveness, while audio.voice keeps the timbre stable.
            messages = []
            if self.mimo_expressive:
                messages.append({"role": "user", "content": self.mimo_style_prompt})
            messages.append({"role": "assistant", "content": mimo_spoken})
            audio_settings = {"format": self.tts_format, "voice": self.voice}

        payload = {
            "model": self.tts_model,
            "messages": messages,
            "modalities": ["text", "audio"],
            "audio": audio_settings,
            # R3: determinism hints for voice consistency.
            # MiMo's API is OpenAI-compatible; these may or may not be honored,
            # but they're cheap to send and silently ignored when not.
            "temperature": float(os.getenv("MIMO_TTS_TEMPERATURE", "0.0")),
            "seed": int(os.getenv("MIMO_TTS_SEED", "1729")),
        }

        audio_bytes = self._fetch_mimo_tts_payload(payload)
        if audio_bytes:
            self._cache_audio(mimo_spoken, audio_bytes)
        return audio_bytes

    def _fetch_mimo_tts_payload(self, payload: dict) -> Optional[bytes]:
        """Fetch MiMo TTS audio. MiMo supports SSE, but current probing shows
        it sends one full base64 audio blob rather than small PCM chunks. We
        still use SSE by default because it is harmless and keeps the path
        ready if MiMo later starts chunking."""
        url = self.config.base_url.rstrip("/") + "/chat/completions"
        max_retries = 2
        for attempt in range(max_retries + 1):
            try:
                if self.mimo_tts_stream:
                    stream_payload = dict(payload)
                    stream_payload["stream"] = True
                    resp = self.session.post(
                        url, json=stream_payload,
                        timeout=self.config.request_timeout_seconds,
                        stream=True,
                    )
                else:
                    resp = self.session.post(
                        url, json=payload,
                        timeout=self.config.request_timeout_seconds,
                    )
                if resp.status_code == 200:
                    candidate = (
                        self._parse_mimo_tts_stream(resp)
                        if self.mimo_tts_stream
                        else self._parse_mimo_tts_json(resp)
                    )
                    if candidate and self._validate_audio_header(candidate):
                        return candidate
                    if candidate:
                        log_debug(f"V6: rejecting malformed audio "
                                  f"(header={candidate[:8].hex()}); retrying.")
                        if attempt < max_retries:
                            time.sleep(0.5)
                            continue
                    log_debug("MiMo TTS response missing valid audio.")
                    break
                elif resp.status_code >= 500 and attempt < max_retries:
                    time.sleep(1)
                    continue
                log_warn(f"TTS API Error {resp.status_code}: {resp.text[:200]}")
            except Exception as exc:
                if attempt < max_retries:
                    time.sleep(1)
                    continue
                log_warn(f"TTS Network Error: {exc}")
        return None

    @staticmethod
    def _audio_from_mimo_message(msg: dict) -> Optional[bytes]:
        audio = (msg or {}).get("audio") or {}
        audio_b64 = audio.get("data")
        if not audio_b64:
            return None
        try:
            return base64.b64decode(audio_b64)
        except Exception:
            return None

    def _parse_mimo_tts_json(self, resp: requests.Response) -> Optional[bytes]:
        try:
            data = resp.json()
            msg = data["choices"][0]["message"]
        except Exception:
            return None
        return self._audio_from_mimo_message(msg)

    def _parse_mimo_tts_stream(self, resp: requests.Response) -> Optional[bytes]:
        t0 = time.time()
        for line in resp.iter_lines(decode_unicode=True):
            if not line or not line.startswith("data: "):
                continue
            data_str = line[6:].strip()
            if data_str == "[DONE]":
                break
            try:
                chunk = json.loads(data_str)
                choice = chunk.get("choices", [{}])[0]
                msg = choice.get("delta") or choice.get("message") or {}
            except Exception:
                continue
            audio = self._audio_from_mimo_message(msg)
            if audio:
                log_debug(f"[mimo-stream] audio blob in "
                          f"{(time.time() - t0) * 1000:.0f}ms")
                return audio
        return None

    # ── R6: Deepgram Aura TTS path ──────────────────────────────────────
    #
    # Speed wins over MiMo:
    #   - sub-600 ms TTFA (vs MiMo's ~2.3 s blocking total)
    #   - real audio streaming via response body chunks
    # Expressiveness trade-off:
    #   - inline tags like [sigh]/[dry laugh] DON'T synthesize as sounds —
    #     translated to SSML <break> as the closest approximation.
    #   - voice character is whichever Aura model the user picked
    #     (default aura-2-zeus-en). Listen to scratch/probe_deepgram/*.wav
    #     to compare against MiMo Dean before committing.

    def _ssml_translate(self, text: str) -> str:
        """Convert MiMo-style `[pause]`/`[sigh]`/etc. tags to PUNCTUATION
        that Aura-2 actually honors as natural prosody (em-dash for
        tactical pauses, ellipsis for trailing thoughts, comma for subtle
        rhythm). R7 incorrectly emitted SSML <break> tags here — Aura-2
        reads those literally, so the user heard "break time equals 600
        milliseconds" mid-sentence. The R8 fix maps to verified levers."""
        def _sub(m: re.Match) -> str:
            tag = m.group(1).lower()
            return self._DEEPGRAM_TAG_TRANSLATIONS.get(tag, " ")
        out = self._DEEPGRAM_TAG_RE.sub(_sub, text)
        # Defensive sweep: if any leftover SSML/HTML-like construct slipped
        # in (e.g. a caller passing raw <break>), strip the angle-bracket
        # tags entirely so Aura-2 never speaks them.
        out = re.sub(r"<[^>]+>", "", out)
        # Normalize the punctuation we just inserted:
        #   "Hello.… World"      → "Hello… World"     (period before ellipsis is redundant)
        #   "Wait — — that"      → "Wait — that"      (collapse stuttered em-dashes)
        #   "Wait — , that"      → "Wait — that"      (em-dash absorbs adjacent comma)
        #   "Done., Move on."    → "Done, Move on."   (period before comma → just comma)
        #   "Done—go"            → "Done — go"        (always pad em-dashes for prosody)
        #   "…  …"               → "…"                (collapse adjacent ellipses)
        out = re.sub(r"\.\s*…", "…", out)
        out = re.sub(r"\.\s*,", ",", out)
        out = re.sub(r"(?:\s*—\s*){2,}", " — ", out)
        out = re.sub(r"\s*—\s*,", " — ", out)
        out = re.sub(r",\s*—", " — ", out)
        out = re.sub(r"…\s*…+", "…", out)
        # Always pad em-dashes (so "Done—go" isn't pronounced "Don-go")
        out = re.sub(r"\s*—\s*", " — ", out)
        # Tidy trailing whitespace before sentence-final punctuation
        out = re.sub(r"\s+([,.])", r"\1", out)
        out = re.sub(r"\s{2,}", " ", out).strip()
        # Strip a leading lonely em-dash / ellipsis / comma if a tag was the
        # very first token of the text.
        out = re.sub(r"^[\s—…,.!?;:]+", "", out)
        return out

    def _fetch_audio_deepgram(self, spoken: str) -> Optional[bytes]:
        """Call Deepgram /v1/speak. Streams the audio body to keep TTFA low,
        then returns the full WAV bytes once the stream completes. The cache
        layer above this is provider-agnostic (cache key includes
        provider+model+voice+text), so subsequent identical calls hit the
        cache regardless of which provider produced the original."""
        if not self.deepgram_api_key:
            log_warn("Deepgram TTS: missing DEEPGRAM_API_KEY")
            return None

        url = self.deepgram_base.rstrip("/") + "/v1/speak"
        params = {
            "model":       self.deepgram_model,
            "encoding":    "linear16",
            "sample_rate": self.deepgram_sample_rate,
            "container":   "wav",
        }
        ssml_text = self._ssml_translate(spoken)
        if ssml_text != spoken:
            log_debug(f"[deepgram] SSML-translated: {ssml_text[:120]!r}")

        max_retries = 2
        for attempt in range(max_retries + 1):
            try:
                resp = self.deepgram_session.post(
                    url, params=params, json={"text": ssml_text},
                    timeout=self.config.request_timeout_seconds, stream=True,
                )
                if resp.status_code == 200:
                    audio_chunks: List[bytes] = []
                    for chunk in resp.iter_content(chunk_size=4096):
                        if chunk:
                            audio_chunks.append(chunk)
                    audio = b"".join(audio_chunks)
                    if self._validate_audio_header(audio):
                        self._cache_audio(spoken, audio)
                        return audio
                    log_debug(f"Deepgram returned bad header: {audio[:8].hex()}")
                    if attempt < max_retries:
                        time.sleep(0.4)
                        continue
                elif resp.status_code >= 500 and attempt < max_retries:
                    time.sleep(1)
                    continue
                log_warn(f"Deepgram TTS error {resp.status_code}: "
                         f"{resp.text[:200]}")
                return None
            except Exception as exc:
                if attempt < max_retries:
                    time.sleep(1)
                    continue
                log_warn(f"Deepgram TTS network error: {exc}")
        return None

    # ── R15: Deepgram WebSocket Speak — persistent streaming TTS ────────
    #
    # The R12 HTTP path is request/response: each phrase chunk costs a TLS
    # handshake + synthesis round-trip (~1-2 s gap users heard mid-reply).
    # The WebSocket Speak endpoint solves this. ONE socket per conversation;
    # push text fragments as the LLM emits them; audio streams back as soon
    # as the synth has bytes ready. Empirically: 338 ms TTFA on the first
    # utterance, then no per-chunk gap on subsequent pushes.
    #
    # We use the WS path for live LLM-streamed replies (`speak_stream`).
    # Single-shot fetches (boot greeting, cache pre-fills, _fetch_audio_for)
    # stay on the HTTP path because they need a complete WAV blob to cache.

    def _ensure_dg_tts_ws(self) -> bool:
        """Open (or reuse) the persistent Deepgram WS Speak connection.
        Wires the audio reader callback to write straight to the PCM player.
        Returns False if disabled, key missing, or library unavailable —
        caller falls back to the HTTP streaming path."""
        if not self.deepgram_tts_ws_enabled:
            return False
        if not self.deepgram_api_key:
            return False
        if self._dg_tts_ws is not None and self._dg_tts_ws._connected.is_set():
            # PCM player must also be ready (separate failure surface).
            return self._ensure_pcm_player(sample_rate=self.deepgram_sample_rate)

        try:
            from tars_deepgram_tts_ws import DeepgramTTSStream
        except Exception as exc:
            log_warn(f"Deepgram WS TTS unavailable: {exc}")
            return False
        if not self._ensure_pcm_player(sample_rate=self.deepgram_sample_rate):
            return False

        # Audio frame writer: each binary frame from Deepgram → PCM player.
        # Returning False from on_audio kills the reader; we use that to
        # honor barge-in via self._dg_ws_aborted.
        def _on_audio(pcm: bytes) -> bool:
            if self._dg_ws_aborted.is_set():
                return True   # silently drop until next utterance clears the flag
            with self._lock:
                if not self._is_playing:
                    self._is_playing = True
                    self.last_speech_start = time.time()
            ok = self._pcm_player.write(pcm)
            return bool(ok)

        self._dg_tts_ws = DeepgramTTSStream(
            api_key     = self.deepgram_api_key,
            model       = self.deepgram_model,
            base        = self.deepgram_base,
            sample_rate = self.deepgram_sample_rate,
            log_fn      = log_info,
            on_audio    = _on_audio,
        )
        ok = self._dg_tts_ws.ensure()
        if not ok:
            self._dg_tts_ws = None
            return False
        return True

    def _play_streaming_deepgram_ws(self, text: str,
                                     on_started: Optional[callable] = None,
                                     abort_check: Optional[callable] = None
                                    ) -> bool:
        """Single-utterance WebSocket synth: push text → flush → wait for
        Flushed status. Used by `_do_speak` paths so single-shot calls also
        get the WS speed win when DEEPGRAM_TTS_WS=1."""
        if not self._ensure_dg_tts_ws():
            return False
        clean = self._ssml_translate(text)
        if not clean:
            return True
        self._dg_ws_aborted.clear()
        ok = self._dg_tts_ws.speak_text(clean)
        if not ok:
            return False
        if not self._dg_tts_ws.flush():
            return False
        if on_started:
            try: on_started()
            except Exception: pass
        # Wait for the Flushed ack (audio fully delivered) or barge-in.
        deadline = time.time() + 30.0
        while time.time() < deadline:
            if abort_check and abort_check():
                self._dg_ws_aborted.set()
                self._dg_tts_ws.clear()
                break
            if self._dg_tts_ws._flushed_event.wait(timeout=0.2):
                break
        with self._lock:
            self._is_playing = False
            self.last_speech_finish = time.time()
        return True

    def _pump_deepgram_ws(self, text_chunks_iter,
                           abort_check: Optional[callable] = None) -> bool:
        """speak_stream-aware path: keep the SAME socket open across multiple
        phrase chunks emitted by the LLM. Each chunk → speak_text() pushes
        immediately. Final flush + wait. This is the true "talks as the LLM
        types" mode — no per-chunk handshake gap.

        Returns True on success (or barge-in), False to fall back to HTTP."""
        if not self._ensure_dg_tts_ws():
            return False
        self._dg_ws_aborted.clear()
        sent_any = False
        try:
            for chunk in text_chunks_iter:
                if abort_check and abort_check():
                    self._dg_ws_aborted.set()
                    self._dg_tts_ws.clear()
                    return True
                clean = self._ssml_translate(chunk)
                if not clean:
                    continue
                if not self._dg_tts_ws.speak_text(clean + " "):
                    return False
                sent_any = True
            if not sent_any:
                return True
            if not self._dg_tts_ws.flush():
                return False
            # Block until audio for the queued text finishes streaming back.
            deadline = time.time() + 30.0
            while time.time() < deadline:
                if abort_check and abort_check():
                    self._dg_ws_aborted.set()
                    self._dg_tts_ws.clear()
                    break
                if self._dg_tts_ws._flushed_event.wait(timeout=0.2):
                    break
        finally:
            with self._lock:
                self._is_playing = False
                self.last_speech_finish = time.time()
        return True

    def _play_streaming_deepgram(self, text: str,
                                  on_started: Optional[callable] = None,
                                  abort_check: Optional[callable] = None
                                 ) -> bool:
        """Stream Deepgram REST TTS directly to the PCM player.

        This is the hot path for live replies: request `linear16` with no
        container, then write raw PCM chunks as soon as the first bytes arrive.
        Full WAV fetching remains available for cache/preload/legacy paths.
        """
        if not self.deepgram_api_key:
            return False

        clean = self._ssml_translate(text)
        if not clean:
            return True
        if not self._ensure_pcm_player(sample_rate=self.deepgram_sample_rate):
            return False

        url = self.deepgram_base.rstrip("/") + "/v1/speak"
        params = {
            "model": self.deepgram_model,
            "encoding": "linear16",
            "sample_rate": self.deepgram_sample_rate,
            "container": "none",
        }

        started = False
        wrote_pcm = False
        aborted = False
        t0 = time.time()
        resp = None
        try:
            resp = self.deepgram_session.post(
                url,
                params=params,
                json={"text": clean},
                timeout=self.config.request_timeout_seconds,
                stream=True,
            )
            if resp.status_code != 200:
                log_warn(f"Deepgram stream error {resp.status_code}: "
                         f"{resp.text[:200]}")
                return False

            with self._lock:
                self._is_playing = True
                self.current_text = normalize_text(re.sub(r"\[.*?\]", "", clean))

            for pcm in resp.iter_content(chunk_size=self.deepgram_stream_chunk_size):
                if abort_check and abort_check():
                    aborted = True
                    break
                if not pcm:
                    continue
                if not started:
                    started = True
                    with self._lock:
                        self.last_speech_start = time.time()
                    if on_started:
                        try: on_started()
                        except Exception: pass
                    log_debug(f"[deepgram-stream] first PCM in "
                              f"{(time.time() - t0) * 1000:.0f}ms")
                if not self._pcm_player.write(pcm):
                    log_warn("[deepgram-stream] PCM player rejected audio")
                    return False
                wrote_pcm = True
        except Exception as exc:
            if not aborted:
                log_warn(f"Deepgram stream failed: {exc}")
            return False
        finally:
            if resp is not None:
                try: resp.close()
                except Exception: pass
            with self._lock:
                self.last_speech_finish = time.time()
                self._is_playing = False

        if aborted:
            return True
        if not wrote_pcm:
            log_warn("[deepgram-stream] stream ended without PCM")
            return False
        return True

    # ── R9: VibeVoice Realtime 0.5B path ────────────────────────────────
    #
    # Why local TTS is the right architectural move:
    #   - TTFA ≈ 200-300 ms (Deepgram's was ~400-500 ms; MiMo ~2.3 s)
    #   - True audio streaming straight to sounddevice (no temp file dance)
    #   - Zero per-call cost, zero network round-trip variance
    #   - Pairs well with realtime STT (Deepgram Nova-3): both hot loops are
    #     local-first now, so the user's perceived latency is dominated by
    #     just the LLM call.
    #
    # Expressiveness: punctuation only — same conclusion as Aura. The
    # `_ssml_translate` translation layer is reused (it's already
    # punctuation-based after R8). Voice presets use embedded `.pt` files
    # in tars_vibevoice/voices/ — six English voices ship by default.

    def _vibe_ready(self) -> bool:
        """Cheap, NON-BLOCKING check. The fetch path uses this to decide
        whether to route to vibevoice or fall back. Never spawns a worker."""
        return self._vibe is not None and self._vibe.is_ready

    def _ensure_vibe(self, blocking: bool = True) -> bool:
        """Spawn the VibeVoice subprocess (idempotent). When ``blocking``
        is True the caller waits for READY (up to ~5 minutes on first run
        because of the ~2 GB HF model pull). When False, kicks off start
        in a daemon thread and returns immediately — used by
        ``boot_warm_async`` so we never block the conversation hot path
        on a model load.

        The subprocess is needed because vibevoice pins torch 2.5.x and
        our parent has torch 2.9 + mlx-lm — they segfault if imported in
        the same process."""
        if self._vibe_ready():
            return True
        if self._vibe is None:
            try:
                from tars_vibevoice_speaker import VibeVoiceTTS
            except Exception as exc:
                log_warn(f"VibeVoice import failed: {exc}")
                return False
            self._vibe = VibeVoiceTTS(
                model_path      = self.vibe_model_path,
                voice           = self.vibe_voice,
                device          = self.vibe_device,
                cfg_scale       = self.vibe_cfg,
                inference_steps = self.vibe_steps,
                log_fn          = log_info,
            )
        if not blocking:
            # Fire-and-forget so user turns aren't blocked by the cold start.
            t = threading.Thread(
                target=self._vibe.start, daemon=True, name="VibeStart"
            )
            t.start()
            return False
        return self._vibe.start()

    def _fetch_audio_vibevoice(self, spoken: str) -> Optional[bytes]:
        """One-shot synth for legacy paths (boot greeting / cache writes /
        single-shot announcements). Streams PCM internally then wraps the
        full result in a RIFF WAV blob for compatibility.

        Falls back IMMEDIATELY (no blocking model load) if vibevoice isn't
        ready — keeps the conversation flowing while the worker starts in
        the background via boot_warm_async."""
        if not self._vibe_ready():
            log_debug("VibeVoice not ready; falling back to Deepgram for this clip")
            return self._fetch_audio_deepgram(spoken) if self.deepgram_api_key else None
        # Light translation pass — preserves em-dash + ellipsis prosody and
        # strips inline tags via the same R8 logic Deepgram uses.
        text = self._ssml_translate(spoken)
        try:
            audio = self._vibe.synthesize_to_wav(text)
        except Exception as exc:
            log_warn(f"VibeVoice synth failed: {exc}")
            return None
        if audio is not None:
            self._cache_audio(spoken, audio)
        return audio

    def _fallback_fetch(self, text: str) -> Optional[bytes]:
        """If vibevoice fails mid-reply, route this one chunk through the
        next-best provider so the user still hears something."""
        prev = self.provider
        try:
            if prev != "deepgram" and self.deepgram_api_key:
                self.provider = "deepgram"
                return self._fetch_audio_deepgram(self._ssml_translate(text))
            self.provider = "mimo"
            return self._fetch_audio_for(text)
        finally:
            self.provider = prev

    def _ensure_pcm_player(self, sample_rate: int = 24000) -> bool:
        """Ensure the sounddevice realtime player is started. The player is
        idempotent: starting it twice is a no-op."""
        if self._pcm_player is not None and self._pcm_player_rate != sample_rate:
            try:
                self._pcm_player.close()
            except Exception:
                pass
            self._pcm_player = None
        if self._pcm_player is None:
            try:
                from tars_vibevoice_speaker import StreamingPCMPlayer
            except Exception:
                return False
            self._pcm_player = StreamingPCMPlayer(
                sample_rate=sample_rate, log_fn=log_info
            )
            self._pcm_player_rate = sample_rate
        return self._pcm_player.start()

    def _play_streaming_vibevoice(self, text: str,
                                   on_started: Optional[callable] = None,
                                   abort_check: Optional[callable] = None
                                  ) -> bool:
        """Realtime path: stream PCM chunks straight to the audio device.
        Used by speak_stream when provider == vibevoice. Returns True on
        success, False on failure (caller should fall back).

        TTFA win: the FIRST PCM chunk lands in the audio queue before the
        diffusion head has finished the rest of the sentence — perceived
        latency is the time-to-first-chunk, not the total synth time.

        Returns False (NOT blocking) if vibevoice isn't ready yet — the
        speak_stream caller will route the chunk through the fallback
        provider so the user keeps hearing TARS while vibe loads."""
        if not self._vibe_ready():
            return False
        if not self._ensure_pcm_player():
            return False
        # Re-use R8's punctuation-friendly text shape; tags become em-dash /
        # ellipsis prosody, leftover SSML is stripped.
        clean = self._ssml_translate(text)
        if not clean:
            return True

        with self._lock:
            self.last_speech_start = time.time()
            self._is_playing = True
            self.current_text = re.sub(r"\[.*?\]", "", clean).strip()

        stop_evt = threading.Event()
        started = False
        wrote_pcm = False
        aborted = False
        try:
            for pcm in self._vibe.stream_pcm(clean, voice=self.vibe_voice,
                                              stop_event=stop_evt):
                if abort_check and abort_check():
                    stop_evt.set()
                    aborted = True
                    break
                if not started:
                    started = True
                    if on_started:
                        try: on_started()
                        except Exception: pass
                if not self._pcm_player.write(pcm):
                    stop_evt.set()
                    if not aborted:
                        log_warn("[vibe] PCM player rejected audio; falling back")
                    break
                wrote_pcm = True
        finally:
            with self._lock:
                self.last_speech_finish = time.time()
                self._is_playing = False
        if aborted:
            return True
        if not wrote_pcm:
            log_warn("[vibe] stream ended without playable PCM; falling back")
            return False
        return True

    @staticmethod
    def _validate_audio_header(b: Optional[bytes]) -> bool:
        """V6: strict header check — accept only known MP3/WAV magic."""
        if not b or len(b) < 4:
            return False
        return (b.startswith(b"RIFF") or             # WAV
                b.startswith(b"ID3")  or             # MP3 with ID3
                b[:2] == b"\xff\xf3" or              # MP3 sync frame (MPEG-2)
                b[:2] == b"\xff\xfb" or              # MP3 sync frame (MPEG-1)
                b[:2] == b"\xff\xfa" or              # MP3 sync frame (MPEG-1, no CRC)
                b[:2] == b"\xff\xf2")                # MP3 sync frame (MPEG-2.5)

    def _play_bytes(self, audio_bytes: Optional[bytes], for_text: str) -> None:
        """Play raw audio bytes via afplay. Updates is_playing/current_text state."""
        if audio_bytes is None:
            return

        # Update current text for echo filtering (strip tags first)
        clean_text = re.sub(r"\[.*?\]", "", for_text)
        self.current_text = normalize_text(clean_text)

        ext = ".wav" if audio_bytes.startswith(b"RIFF") else ".mp3"

        with tempfile.NamedTemporaryFile(suffix=ext, delete=False) as f:
            f.write(audio_bytes)
            temp_path = f.name

        with self._lock:
            self.last_speech_start = time.time()
            self._is_playing = True
            self._proc = subprocess.Popen(["afplay", temp_path])
            proc = self._proc
        try:
            proc.wait()
            if proc.returncode != 0:
                log_debug(f"afplay rc={proc.returncode}")
        finally:
            with self._lock:
                self.last_speech_finish = time.time()
                self._proc = None
                self._is_playing = False
            try:
                os.remove(temp_path)
            except OSError:
                pass

    def _cache_key(self, text: str) -> str:
        """Cache key MUST encode the provider + voice + model + format so
        switching any of them doesn't replay an old clip from a different
        voice or vendor. Pre-Round-4 the cache only keyed on text; R6
        added the provider segment; R8 added the Deepgram translation
        version so R7 cache entries (with spoken SSML tags) don't replay
        after the fix; R9 added the vibevoice branch so vibevoice clips
        don't collide with MiMo (both default to wav format)."""
        import hashlib
        if self.provider == "vibevoice":
            ident = f"vibevoice|{self.vibe_voice}|{self.tts_format}|{text}"
        elif self.provider == "deepgram":
            ident = (f"deepgram|{self._DEEPGRAM_CACHE_VERSION}|"
                     f"{self.deepgram_model}|{self.tts_format}|{text}")
        else:
            style_hash = "plain"
            if self.mimo_expressive:
                style_hash = hashlib.md5(
                    self.mimo_style_prompt.encode("utf-8")
                ).hexdigest()[:10]
            ident = (f"mimo|{self.tts_model}|{self.voice}|{self.tts_format}|"
                     f"expressive={int(self.mimo_expressive)}|"
                     f"stream={int(self.mimo_tts_stream)}|"
                     f"style={style_hash}|{text}")
        return hashlib.md5(ident.encode("utf-8")).hexdigest()

    def _cache_ext(self) -> str:
        return ".wav" if self.tts_format == "wav" else ".mp3"

    # ── R5: boot-time pre-warm + common-phrase pre-cache ────────────────
    #
    # Two cheap-but-meaningful latency wins discovered in Round 5 probing:
    #   1. The first TTS call after boot pays the TLS handshake cost (~200-400 ms).
    #      Firing one tiny call at boot warms the keep-alive pool so the user's
    #      first reply doesn't eat that tax.
    #   2. A handful of short replies (yes/no/got it/on it/copy that) appear
    #      hundreds of times across a long-running session. Pre-fetching their
    #      audio at boot turns them into instant cache hits — zero network
    #      latency on the most common turns.
    #
    # Both run on a background thread so boot stays fast.

    PRELOAD_PHRASES = (
        "Yes.",
        "No.",
        "On it.",
        "Got it.",
        "Copy that.",
        "Affirmative.",
        "Negative.",
        "Acknowledged.",
        "Standing by.",
        "Confirmed.",
    )

    def prewarm(self) -> None:
        """One tiny TTS call to warm the TLS keep-alive. Synchronous, fast,
        intended to be invoked from a background thread."""
        try:
            audio = self._fetch_audio_for("ready.")
            log_debug(f"[prewarm] TLS warmed (audio={len(audio) if audio else 0} bytes)")
        except Exception as e:
            log_debug(f"[prewarm] error: {e}")

    def preload_common_phrases(self,
                                phrases: Optional[List[str]] = None) -> None:
        """Pre-fetch + cache a list of short phrases so they play instantly
        when TARS uses them. Skips entries already in cache. Synchronous;
        run from a background thread."""
        targets = list(phrases) if phrases is not None else list(self.PRELOAD_PHRASES)
        misses = []
        for phrase in targets:
            cache_path = os.path.join(self._cache_dir,
                                       self._cache_key(phrase) + self._cache_ext())
            if not os.path.exists(cache_path):
                misses.append(phrase)
        if not misses:
            log_debug(f"[preload] all {len(targets)} phrases already cached")
            return
        log_debug(f"[preload] fetching {len(misses)} of {len(targets)} phrases")
        ok = 0
        for phrase in misses:
            try:
                audio = self._fetch_audio_for(phrase)
                if audio:
                    ok += 1
            except Exception as e:
                log_debug(f"[preload] {phrase!r} failed: {e}")
        log_info(f"[preload] {ok}/{len(misses)} common phrases cached")

    def boot_warm_async(self) -> None:
        """Fire-and-forget: one daemon thread does both prewarm + preload.
        Failures are logged but never block boot.

        For vibevoice: also starts the worker subprocess so the model is
        loaded by the time the user finishes their first turn (~5-10 s
        cold start on M4 MPS). Pre-cache is skipped because vibevoice's
        ~250 ms TTFA already beats any cache+afplay round-trip."""
        def _job():
            try:
                if self.provider == "vibevoice":
                    log_info("[vibe] starting worker subprocess "
                             "(first run: ~25 min model download + ~10 s load)")
                    # blocking=True here — we're already on a daemon thread, so
                    # blocking until READY is fine. Until READY, fetch falls
                    # back to Deepgram.
                    ok = self._ensure_vibe(blocking=True)
                    if ok and self._vibe and self._vibe.is_ready:
                        log_info("[vibe] worker READY — taking over TTS")
                    else:
                        log_warn("[vibe] worker did not become READY; staying on fallback")
                    return
                self.prewarm()
                self.preload_common_phrases()
            except Exception as e:
                log_debug(f"[boot_warm] error: {e}")
        threading.Thread(target=_job, daemon=True, name="TtsBootWarm").start()

    def _cache_audio(self, text: str, audio_bytes: bytes) -> None:
        """Save audio to cache for reuse."""
        try:
            path = os.path.join(self._cache_dir,
                                self._cache_key(text) + self._cache_ext())
            if not os.path.exists(path):
                with open(path, "wb") as f:
                    f.write(audio_bytes)
                log_debug(f"Cached audio: {text[:40]}...")
        except Exception:
            pass

    def _play_cached(self, text: str) -> bool:
        """Try to play from cache. Returns True if cache hit."""
        path = os.path.join(self._cache_dir,
                            self._cache_key(text) + self._cache_ext())
        if not os.path.exists(path):
            return False
        log_debug(f"Cache hit: {text[:40]}...")
        self._is_playing = True
        clean_text = re.sub(r"\[.*?\]", "", text)
        self.current_text = normalize_text(clean_text)
        try:
            with self._lock:
                self.last_speech_start = time.time()
                self._proc = subprocess.Popen(["afplay", path])
                proc = self._proc
            proc.wait()
        finally:
            with self._lock:
                self.last_speech_finish = time.time()
                self._proc = None
                self._is_playing = False
        return True

    def _fallback_say(self, text: str) -> None:
        for part in chunk_for_speech(text):
            cmd = ["say", "-r", str(self.config.speaking_rate_wpm)]
            if self.config.macos_voice:
                cmd += ["-v", self.config.macos_voice]
            cmd.append(part)
            with self._lock:
                self._proc = subprocess.Popen(cmd)
                proc = self._proc
            proc.wait()
            with self._lock:
                self._proc = None


# ─── Deepgram STT (Streaming) ────────────────────────────────────────

class MicGate:
    """Round-2 echo fix: while TTS is playing (or in a brief grace period
    after), feed silence into Deepgram instead of live mic samples. Silence
    has no spectral energy → Deepgram doesn't transcribe it → no self-echo.

    This is wrapped around `dg_connection.send` and handed to
    `Microphone(MicGate(...))`. The Deepgram SDK calls our __call__ as
    if it were the original send function.
    """
    GRACE_AFTER_TTS_S = 0.25

    def __init__(self, send_fn, speaker, can_send_fn=None, on_send_failed=None):
        self._send = send_fn
        self._speaker = speaker
        self._can_send = can_send_fn or (lambda: True)
        self._on_send_failed = on_send_failed or (lambda: None)
        # Counters for observability; not used for control flow.
        self.gated_chunks = 0
        self.live_chunks  = 0
        self.failed_chunks = 0

    def _is_muted(self) -> bool:
        if self._speaker.is_playing():
            return True
        finished_at = self._speaker.last_speech_finish or 0
        if finished_at and (time.time() - finished_at) < self.GRACE_AFTER_TTS_S:
            return True
        return False

    def __call__(self, data, *args, **kwargs):
        if not self._can_send():
            self.failed_chunks += 1
            return False
        if self._is_muted() and data:
            data = b"\x00" * len(data)
            self.gated_chunks += 1
        else:
            self.live_chunks += 1
        try:
            ok = self._send(data, *args, **kwargs)
        except Exception:
            ok = False
        if ok is False:
            self.failed_chunks += 1
            self._on_send_failed()
        return ok


class DeepgramSTT:
    """
    Real-time streaming STT using Deepgram Flux or Nova-3.
    V2:   Tuned endpointing for full long-sentence capture.
    V3:   Tighter post-TTS cooldown.
    V5:   Auto-reconnect with exponential backoff on close/error.
    R2-A: Mic-gated audio feed during TTS playback (kills self-echo).
    R2-B: Buffer is_final transcripts, commit only on speech_final
          (handles natural pauses mid-sentence — fixes word-loss).
    Includes VAD and interruption detection.
    """

    # V5: backoff schedule
    RECONNECT_BACKOFF_S = (1, 2, 5, 10, 30, 60)
    # R3: KeepAlive interval — Deepgram closes idle sessions after ~10s of
    # silence; while mic is gated during long TTS replies, the audio is
    # silence (R2-A), so we ping the server with explicit KeepAlive frames
    # to keep the WebSocket alive.
    KEEPALIVE_INTERVAL_S = 5

    def __init__(self, config: AssistantConfig, speaker: Speaker, on_final_text, on_interruption):
        self.config = config
        self.speaker = speaker
        self.on_final_text = on_final_text
        self.on_interruption = on_interruption
        self.stt_model = (config.deepgram_stt_model or "flux-general-en").strip()
        self._use_flux = self.stt_model.startswith("flux-")
        self._stt_chunk_frames = max(
            320,
            int(config.deepgram_stt_sample_rate * (config.deepgram_stt_chunk_ms / 1000.0)),
        )
        dg_options = DeepgramClientOptions(
            url=config.deepgram_stt_base,
            options={
                "termination_exception_send": False,
                "termination_exception_connect": False,
            },
        )
        self.dg_client = DeepgramClient(config.deepgram_api_key, dg_options)
        self.dg_connection = None
        self._flux_ws = None
        self._flux_recv_thread: Optional[threading.Thread] = None
        self.microphone = None
        self._is_active = False
        self._connection_healthy = False
        self._wants_active = False
        self._reconnect_thread: Optional[threading.Thread] = None
        self._reconnect_lock = threading.Lock()
        # R2-B: buffer is_final transcripts so multi-segment utterances
        # ("Oh, so… you're threatening me?") commit as ONE final, not two
        self._final_buffer: List[str] = []
        # R2-A: gate that wraps dg_connection.send and silences during TTS
        self._mic_gate: Optional[MicGate] = None
        # R3: SDK feature support flags + keepalive thread
        self._utterance_end_supported = True
        self._keepalive_thread: Optional[threading.Thread] = None
        self._keepalive_lock = threading.Lock()
        # Build connection lazily so reconnects use a fresh handle each time
        self._build_connection()

    def _build_connection(self) -> None:
        """Create a fresh Deepgram websocket handle and wire callbacks."""
        if self._use_flux:
            self.dg_connection = None
            return
        self.dg_connection = self.dg_client.listen.websocket.v("1")
        self.dg_connection.on(LiveTranscriptionEvents.Transcript, self._on_message)
        self.dg_connection.on(LiveTranscriptionEvents.Error, self._on_error)
        # V5: register Close handler so we know when to reconnect
        try:
            self.dg_connection.on(LiveTranscriptionEvents.Close, self._on_close)
        except Exception:
            pass
        # R3: UtteranceEnd is the proper "user is done speaking" signal —
        # fires after utterance_end_ms of silence, regardless of how
        # endpointing fragmented the segments. We commit on this event,
        # not on speech_final, which gives us 3× lower latency than R2.
        try:
            self.dg_connection.on(LiveTranscriptionEvents.UtteranceEnd,
                                   self._on_utterance_end)
        except AttributeError:
            log_warn("Deepgram SDK lacks UtteranceEnd event — falling back to speech_final.")
            self._utterance_end_supported = False
        else:
            self._utterance_end_supported = True

    # Words that should ALWAYS interrupt TARS even if mic is gated.
    # These come from the small fraction of audio that leaks through during
    # the gate's grace window or right at TTS edges. We allow these words
    # to trigger speaker.stop() on a best-effort basis.
    _BARGE_IN_WORDS = {
        "stop", "quiet", "shut", "enough", "halt", "pause", "wait",
        "hold", "cancel", "shutup", "shut-up", "silence",
    }

    def _on_message(self, self_connection, result, **kwargs):
        if not result:
            return
        try:
            transcript = result.channel.alternatives[0].transcript
        except Exception:
            return
        if not transcript:
            return

        is_final = result.is_final
        speech_final = result.speech_final

        # R2-A: Mic is GATED during TTS playback (silence is sent), so any
        # transcript that arrives during is_speaking should be effectively
        # impossible — but we keep a thin safety net:
        #   - drop transcripts arriving during a TTS-active window (rare leak)
        #   - except for explicit barge-in keywords ("stop", "quiet"…)
        now = time.time()
        is_speaking = self.speaker.is_playing()
        in_cooldown = (now - (self.speaker.last_speech_finish or 0)) < 0.3

        if is_speaking or in_cooldown:
            words = re.findall(r"\w+", transcript.lower())
            if any(w in self._BARGE_IN_WORDS for w in words):
                log_debug(f"Barge-in keyword heard despite gate: {transcript!r}")
                self.speaker.stop()
                self.on_interruption()
            # Otherwise drop — assume residual echo from grace edge
            return

        # R3: Buffer all is_final segments. The actual commit happens in
        # _on_utterance_end (much faster end-of-turn signal). speech_final
        # is now only used as a fallback when the SDK lacks UtteranceEnd.
        if is_final:
            seg = normalize_text(transcript)
            if seg:
                self._final_buffer.append(seg)

        # Fallback path for older Deepgram SDKs without UtteranceEnd
        if speech_final and not self._utterance_end_supported:
            self._commit_final_buffer()

    def _on_utterance_end(self, _self_conn, utterance_end, **kwargs):
        """R3: Deepgram has determined the user is done speaking — fires
        utterance_end_ms after last speech. This is the proper commit
        signal: low-latency AND captures pause-fragmented utterances."""
        # If TTS is currently playing, skip — anything in the buffer is
        # almost certainly residual echo from the gate's grace edge.
        if self.speaker.is_playing():
            self._final_buffer.clear()
            return
        self._commit_final_buffer()

    def _commit_final_buffer(self) -> None:
        """Join + emit + clear the is_final segment buffer."""
        if not self._final_buffer:
            return
        full = " ".join(self._final_buffer).strip()
        self._final_buffer.clear()
        full = re.sub(r"\s+", " ", full).strip()
        if full:
            self.on_final_text(full)

    def _can_send_audio(self) -> bool:
        return self._wants_active and self._is_active and self._connection_healthy

    def _on_mic_send_failed(self) -> None:
        if not self._connection_healthy:
            return
        self._connection_healthy = False
        self._schedule_reconnect()

    def _make_mic_gate(self, send_fn) -> MicGate:
        return MicGate(
            send_fn,
            self.speaker,
            can_send_fn=self._can_send_audio,
            on_send_failed=self._on_mic_send_failed,
        )

    def _flux_url(self) -> str:
        parsed = urllib.parse.urlparse(self.config.deepgram_stt_base)
        host = parsed.netloc or parsed.path or "api.deepgram.com"
        params = {
            "model": self.stt_model,
            "encoding": "linear16",
            "sample_rate": str(self.config.deepgram_stt_sample_rate),
            "eot_threshold": str(self.config.deepgram_flux_eot_threshold),
            "eot_timeout_ms": str(self.config.deepgram_flux_eot_timeout_ms),
        }
        return f"wss://{host}/v2/listen?" + urllib.parse.urlencode(params)

    def _flux_send(self, data: bytes, *args, **kwargs) -> bool:
        ws = self._flux_ws
        if ws is None:
            return False
        try:
            ws.send(data)
            return True
        except Exception as exc:
            log_debug(f"Flux send failed: {exc}")
            self._schedule_reconnect()
            return False

    def _flux_recv_loop(self) -> None:
        ws = self._flux_ws
        if ws is None:
            return
        try:
            for raw in ws:
                if not self._wants_active:
                    return
                if isinstance(raw, bytes):
                    try:
                        raw = raw.decode("utf-8")
                    except Exception:
                        continue
                try:
                    msg = json.loads(raw)
                except Exception:
                    continue
                self._on_flux_message(msg)
        except Exception as exc:
            if self._wants_active:
                log_warn(f"Flux STT connection error: {exc}")
                self._connection_healthy = False
                self._is_active = False
                self._stop_microphone()
                self._schedule_reconnect()

    def _on_flux_message(self, msg: dict) -> None:
        event = msg.get("event") or msg.get("type") or ""
        transcript = normalize_text(msg.get("transcript") or "")
        if not transcript:
            return

        now = time.time()
        is_speaking = self.speaker.is_playing()
        in_cooldown = (now - (self.speaker.last_speech_finish or 0)) < 0.3

        if is_speaking or in_cooldown:
            words = re.findall(r"\w+", transcript.lower())
            if any(w in self._BARGE_IN_WORDS for w in words):
                log_debug(f"Flux barge-in keyword heard despite gate: {transcript!r}")
                self.speaker.stop()
                self.on_interruption()
            return

        if event == "StartOfTurn":
            words = re.findall(r"\w+", transcript.lower())
            if any(w in self._BARGE_IN_WORDS for w in words):
                self.speaker.stop()
                self.on_interruption()
            return

        if event == "EndOfTurn":
            self.on_final_text(transcript)

    def _on_error(self, self_connection, error, **kwargs):
        log_warn(f"Deepgram Error: {error}")
        self._connection_healthy = False
        self._is_active = False
        self._stop_microphone()
        # V5: schedule reconnect on transport-level error
        self._schedule_reconnect()

    def _on_close(self, self_connection, close, **kwargs):
        log_warn(f"Deepgram closed: {close}")
        self._connection_healthy = False
        self._is_active = False
        self._stop_microphone()
        self._schedule_reconnect()

    def _live_options(self) -> LiveOptions:
        # R3: Endpointing controls when individual `is_final` segments fire.
        # utterance_end_ms is a SEPARATE signal that fires once per actual
        # utterance, dispatched as a `UtteranceEnd` event (not on the
        # transcript stream). We commit on UtteranceEnd → endpointing can
        # be aggressively short (fast segment commits), while utterance_end_ms
        # is what actually determines end-of-turn latency.
        #   Latency = utterance_end_ms = ~1.0s after user stops speaking.
        # That's 3× faster than R2's 3s while still capturing pause-fragmented
        # sentences correctly.
        return LiveOptions(
            model=self.stt_model,
            language="en-US",
            smart_format=True,
            punctuate=True,
            interim_results=True,
            encoding="linear16",
            channels=1,
            sample_rate=self.config.deepgram_stt_sample_rate,
            endpointing=500,            # R3: was 1500. Fast segment finals.
            utterance_end_ms=1000,      # R3: was 3000. End-of-turn ~1s after silence.
            vad_events=True,
            filler_words=True,
            no_delay=True,
        )

    def _start_flux(self) -> bool:
        try:
            from websockets.sync.client import connect
        except Exception as exc:
            log_warn(f"Flux STT unavailable: websockets sync client missing ({exc})")
            return False

        try:
            self._flux_ws = connect(
                self._flux_url(),
                additional_headers={
                    "Authorization": f"Token {self.config.deepgram_api_key}",
                },
                open_timeout=15,
                ping_interval=None,
                max_size=4 * 1024 * 1024,
            )
        except Exception as exc:
            log_warn(f"Flux STT connect failed: {exc}")
            self._flux_ws = None
            return False

        self._is_active = True
        self._connection_healthy = True
        self._mic_gate = self._make_mic_gate(self._flux_send)
        self.microphone = Microphone(
            self._mic_gate,
            rate=self.config.deepgram_stt_sample_rate,
            chunk=self._stt_chunk_frames,
        )
        if not self.microphone.start():
            log_warn("Flux STT microphone start failed")
            try: self._flux_ws.close()
            except Exception: pass
            self._flux_ws = None
            return False

        self._flux_recv_thread = threading.Thread(
            target=self._flux_recv_loop, daemon=True, name="DeepgramFluxRecv"
        )
        self._flux_recv_thread.start()
        log_info(
            f"Deepgram Flux STT Live ({self.stt_model}, "
            f"{self.config.deepgram_stt_chunk_ms}ms chunks)."
        )
        return True

    def start(self) -> None:
        if self._is_active:
            return
        self._wants_active = True
        log_info("Connecting to Deepgram...")
        if self._use_flux:
            if not self._start_flux():
                log_warn("Initial Flux start failed — falling back to Nova-3.")
                self.stt_model = "nova-3"
                self._use_flux = False
                self._build_connection()
            else:
                return

        options = self._live_options()
        if not self.dg_connection.start(options):
            # First-attempt failure → fall through to reconnect loop
            log_warn("Initial Deepgram start failed — will retry.")
            self._schedule_reconnect()
            return

        # R2-A: install mic gate so the boot greeting (and every TTS turn)
        # doesn't echo back into Deepgram as user input.
        self._is_active = True
        self._connection_healthy = True
        self._mic_gate = self._make_mic_gate(self.dg_connection.send)
        self.microphone = Microphone(
            self._mic_gate,
            rate=self.config.deepgram_stt_sample_rate,
            chunk=self._stt_chunk_frames,
        )
        self.microphone.start()
        # R3: start the KeepAlive thread so long mic-gated periods don't
        # idle-timeout the WebSocket.
        self._start_keepalive_thread()
        log_info(
            f"Deepgram STT Live ({self.stt_model}, "
            f"{self.config.deepgram_stt_chunk_ms}ms chunks, mic-gated)."
        )

    def _schedule_reconnect(self) -> None:
        """V5: kick off a background reconnect loop if not already running."""
        if not self._wants_active:
            return
        with self._reconnect_lock:
            if self._reconnect_thread and self._reconnect_thread.is_alive():
                return
            self._reconnect_thread = threading.Thread(
                target=self._reconnect_loop, daemon=True, name="DeepgramReconnect")
            self._reconnect_thread.start()

    def _stop_microphone(self) -> None:
        mic = self.microphone
        self.microphone = None
        if mic is not None:
            try:
                mic.finish()
            except Exception:
                pass

    def _reconnect_loop(self) -> None:
        """Tear down any partial state and try to bring STT back up with backoff."""
        # Tear down current state
        try:
            self._stop_microphone()
        except Exception:
            pass
        try:
            if self.dg_connection:
                self.dg_connection.finish()
        except Exception:
            pass
        self.microphone = None
        self._is_active = False
        self._connection_healthy = False

        attempt = 0
        while self._wants_active:
            delay = self.RECONNECT_BACKOFF_S[min(attempt, len(self.RECONNECT_BACKOFF_S) - 1)]
            log_warn(f"Deepgram reconnect attempt {attempt + 1} in {delay}s…")
            time.sleep(delay)
            if not self._wants_active:
                return
            try:
                if self._use_flux:
                    if self._start_flux():
                        return
                    log_warn("Reconnect: Flux start returned False.")
                    attempt += 1
                    continue
                self._build_connection()
                if self.dg_connection.start(self._live_options()):
                    # R2-A: re-install the gate on reconnect
                    self._is_active = True
                    self._connection_healthy = True
                    self._mic_gate = self._make_mic_gate(self.dg_connection.send)
                    self.microphone = Microphone(
                        self._mic_gate,
                        rate=self.config.deepgram_stt_sample_rate,
                        chunk=self._stt_chunk_frames,
                    )
                    self.microphone.start()
                    self._start_keepalive_thread()  # R3
                    log_info(
                        f"Deepgram STT reconnected ({self.stt_model}, mic-gated)."
                    )
                    return
                else:
                    log_warn("Reconnect: dg_connection.start() returned False.")
            except Exception as e:
                log_warn(f"Reconnect failed: {e}")
            attempt += 1

    def _start_keepalive_thread(self) -> None:
        """R3: start a daemon that periodically sends KeepAlive frames so
        Deepgram doesn't drop the session when the mic gate is feeding
        silence during a long TTS reply."""
        with self._keepalive_lock:
            if self._keepalive_thread and self._keepalive_thread.is_alive():
                return
            self._keepalive_thread = threading.Thread(
                target=self._keepalive_loop, daemon=True,
                name="DeepgramKeepAlive",
            )
            self._keepalive_thread.start()

    def _keepalive_loop(self) -> None:
        while self._wants_active and self._is_active:
            time.sleep(self.KEEPALIVE_INTERVAL_S)
            if not self._is_active:
                return
            # Try the SDK method first; fall back to a raw JSON frame.
            try:
                self.dg_connection.keep_alive()
                continue
            except AttributeError:
                pass
            except Exception as e:
                log_debug(f"keep_alive() failed: {e}")
            # Fallback path: write the JSON frame ourselves.
            try:
                payload = json.dumps({"type": "KeepAlive"})
                # The SDK's send() expects audio bytes for one path and
                # control text for another. Some SDK versions accept a
                # str directly. Try in order:
                send_fn = self.dg_connection.send
                try:
                    send_fn(payload)            # str path (text frame)
                except TypeError:
                    send_fn(payload.encode())   # bytes fallback
            except Exception as e:
                log_debug(f"KeepAlive send failed: {e}")

    def stop(self) -> None:
        self._wants_active = False
        self._is_active = False
        if self.microphone:
            self._stop_microphone()
        if self.dg_connection:
            try:
                self.dg_connection.finish()
            except Exception:
                pass
        if self._flux_ws is not None:
            try:
                self._flux_ws.close()
            except Exception:
                pass
            self._flux_ws = None
        self._connection_healthy = False
        log_debug("Deepgram STT stopped.")



# ─── Main Assistant Loop ─────────────────────────────────────────────

class RealtimeAssistant:
    def __init__(self, config: AssistantConfig):
        self.config = config
        self.chat_client = MiMoChatClient(config)
        self.speaker = Speaker(config)
        self.stt = DeepgramSTT(config, self.speaker, self.handle_utterance, self.handle_interruption)
        self.toolkit = TarsToolkit()
        self.messages: List[Dict[str, str]] = [{"role": "system", "content": config.system_prompt}]
        self.memory_file = "tars_memory.json"
        self._stop_event = threading.Event()
        self._is_shutting_down = False
        self._booted_at = time.time()
        self._was_interrupted = False
        self._processing_lock = threading.Lock()
        self.last_speech_end = 0
        self._last_session_time = None
        self.load_memory()

        # ── Self-Evolution stack ─────────────────────────────────────────
        self._project_dir = os.path.dirname(os.path.abspath(__file__))
        self.tars_self         = TarsSelf(self._project_dir, log_info)
        # Phase 0: token budget. Autonomous-tier calls go through this guard;
        # user-facing turn calls bypass it (UNLIMITED).
        self.budget            = TokenBudget(self._project_dir, log_info)
        # Wrapped autonomous chat — used by everything that talks to itself
        autonomous_chat        = self.budget.guard(
            self.chat_client.chat, tier="autonomous", label="autonomous"
        )
        # V8: cron defers when a user turn is in flight. processing_lock is locked
        # whenever handle_utterance is mid-call. We expose a non-blocking probe.
        self.cron_scheduler    = CronScheduler(
            self._project_dir, log_info,
            busy_predicate=self._is_user_turn_in_flight,
        )
        self.desire_engine     = DesireEngine(self._project_dir)
        self.skill_loader      = SkillLoader(self._project_dir, log_info)
        self.proactive_learner = ProactiveLearner(
            self._project_dir, autonomous_chat, log_info
        )
        self.evolution_worker  = EvolutionWorker(
            self._project_dir, self.desire_engine,
            autonomous_chat, log_info,
            skills_loader=self.skill_loader,
        )
        # Stash for the cron-fired heartbeat / audit which uses chat directly
        self._autonomous_chat = autonomous_chat
        self.evolution_worker.set_on_skill_ready(self._on_skill_ready)
        self._skill_announce_queue: List[str] = []
        self._skill_announce_lock = threading.Lock()

        # ── Phase 2: Real Memory ──────────────────────────────────────────
        # Episodic + semantic + KG memory backed by SQLite + OpenAI embeddings.
        # See tars_memory.py for design notes.
        try:
            from tars_memory import Memory
            self.memory = Memory(self._project_dir, log_fn=log_info)
            # Carry-over: backfill embeddings for every legacy message so the
            # store has a real baseline. Idempotent — only runs if the store
            # has zero embedded episodes yet.
            try:
                migrated = self.memory.migrate_from_legacy_messages(self.messages)
                if migrated:
                    log_info(f"[memory] migrated {migrated} legacy turns")
            except Exception as e:
                log_warn(f"[memory] migration error (non-fatal): {e}")
        except Exception as e:
            log_warn(f"[memory] init failed (running without Phase 2): {e}")
            self.memory = None

        # ── Phase 2.5: Mind Simulation Core ─────────────────────────────
        # Four standalone modules. Each is fail-soft. The orchestrator can
        # operate without any of them (degrades to pre-Phase-2.5 behavior).
        try:
            self.model_registry = ModelRegistry(self._project_dir, log_fn=log_info)
        except Exception as e:
            log_warn(f"[mind] ModelRegistry init failed: {e}")
            self.model_registry = None

        try:
            self.event_bus = EventBus(self._project_dir, log_fn=log_info)
        except Exception as e:
            log_warn(f"[mind] EventBus init failed: {e}")
            self.event_bus = None
        try:
            self.desire_engine.set_event_bus(self.event_bus)
            self.proactive_learner.set_event_bus(self.event_bus)
            self.evolution_worker.set_event_bus(self.event_bus)
        except Exception as e:
            log_warn(f"[mind] event bus wire failed: {e}")

        try:
            self.appraiser = Appraiser()
        except Exception as e:
            log_warn(f"[mind] Appraiser init failed: {e}")
            self.appraiser = None

        try:
            self.workspace = Workspace(
                self._project_dir,
                event_bus=self.event_bus,
                log_fn=log_info,
            )
        except Exception as e:
            log_warn(f"[mind] Workspace init failed: {e}")
            self.workspace = None

        try:
            self.world_model = WorldModel(self._project_dir, log_fn=log_info)
        except Exception as e:
            log_warn(f"[mind] WorldModel init failed: {e}")
            self.world_model = None

        try:
            self.self_model = SelfModel(self._project_dir, log_fn=log_info)
        except Exception as e:
            log_warn(f"[mind] SelfModel init failed: {e}")
            self.self_model = None

        try:
            self.mind_metrics = MindMetrics(self._project_dir)
        except Exception as e:
            log_warn(f"[mind] MindMetrics init failed: {e}")
            self.mind_metrics = None

        # SleepEngine gets the inner-voice Mind reference after InnerVoice is
        # constructed. It can still run now with memory-only maintenance.
        try:
            self.sleep_engine = SleepEngine(
                self._project_dir,
                log_fn=log_info,
                memory=self.memory,
                self_model=self.self_model,
            )
        except Exception as e:
            log_warn(f"[mind] SleepEngine init failed: {e}")
            self.sleep_engine = None

        # Stash the most recent workspace winner so the prompt-builder can
        # surface it as `## Current Workspace`. None until the first cycle.
        self._latest_workspace_frame: Optional[Any] = None

        # Subscribe inner-voice to workspace winners — high-salience frames
        # become an event-driven force_thought_now (Phase 2.5E preview).
        if self.event_bus is not None:
            try:
                self.event_bus.subscribe("workspace_frame",
                                         self._on_workspace_frame)
                self.event_bus.subscribe("workspace_frame",
                                         self._on_memory_event)
                self.event_bus.subscribe("prediction_error",
                                         self._on_memory_event)
                self.event_bus.subscribe("desire_candidate",
                                         self._on_memory_event)
                self.event_bus.subscribe("goal_progress",
                                         self._on_memory_event)
                self.event_bus.subscribe("goal_conflict",
                                         self._on_memory_event)
                self.event_bus.subscribe("emotion_shift",
                                         self._on_memory_event)
                self.event_bus.subscribe("skill_result",
                                         self._on_memory_event)
                self.event_bus.subscribe("skill_failure",
                                         self._on_memory_event)
                self.event_bus.subscribe("sleep_summary",
                                         self._on_memory_event)
                self.event_bus.subscribe("*",
                                         self._on_mind_model_event)
            except Exception as e:
                log_warn(f"[mind] workspace subscribe failed: {e}")

        # Boot the soul into messages[0] so even the first turn uses the real prompt
        self.messages[0] = {"role": "system",
                             "content": self._build_system_prompt()}

        # Initial skill scan so capabilities show up in the prompt right away
        try:
            self.skill_loader.rescan()
        except Exception as e:
            log_warn(f"Initial skill rescan failed: {e}")

        # Register cron actions (heartbeat / rescan / self-audit / digest)
        self.cron_scheduler.register_action("heartbeat",       self._cron_heartbeat)
        self.cron_scheduler.register_action("rescan_skills",   self._cron_rescan_skills)
        self.cron_scheduler.register_action("self_audit",      self._cron_self_audit)
        self.cron_scheduler.register_action("thought_digest",  self._cron_thought_digest)
        self.cron_scheduler.register_action("memory_compact",  self._cron_memory_compact)
        self.cron_scheduler.register_action("mind_compact",    self._cron_mind_compact)
        self.cron_scheduler.register_action("mind_micro_sleep", self._cron_mind_micro_sleep)
        self.cron_scheduler.register_action("mind_deep_sleep",  self._cron_mind_deep_sleep)
        self.cron_scheduler.register_action("mind_weekly_sleep", self._cron_mind_weekly_sleep)

        # Phase 1: InnerVoice background thought stream
        # Background thinking loop. Owns the mlx_lm.server subprocess. Reads
        # recent transcript + mood + last thoughts, writes to tars_thoughts.jsonl.
        # Wish thoughts (≥0.7 salience) are forwarded to DesireEngine.
        inner_kwargs: Dict[str, Any] = {}
        try:
            spec = self.model_registry.get("inner_fast") if self.model_registry else None
            if spec and spec.enabled and spec.provider == "mlx":
                model_id = spec.model
                # Back-compat for the short Gemma label; explicit overrides
                # should use a concrete Hugging Face repo id.
                if model_id == "gemma-4-e4b-it-4bit":
                    model_id = "mlx-community/gemma-4-e4b-it-4bit"
                inner_kwargs["model"] = model_id
                if spec.endpoint:
                    parsed = urllib.parse.urlparse(spec.endpoint)
                    if parsed.hostname:
                        inner_kwargs["host"] = parsed.hostname
                    if parsed.port:
                        inner_kwargs["port"] = parsed.port
                log_info(f"[mind] inner_fast routed via registry: {model_id}")
        except Exception as e:
            log_warn(f"[mind] inner_fast registry route failed: {e}")
        self.inner_voice = InnerVoice(
            project_dir       = self._project_dir,
            log_fn            = log_info,
            recent_transcript = self._recent_transcript_for_inner,
            active_goals_top  = self._active_goals_top,
            desire_engine     = self.desire_engine,
            **inner_kwargs,
        )
        # Inner-loop compatibility: predicate kept for compatibility but inner-voice
        # `_should_think_now` now ignores it — we want continuous thinking,
        # not gated thinking. The predicate still serves the cron scheduler.
        self.inner_voice.set_user_busy_predicate(self._is_user_turn_in_flight)
        try:
            if self.sleep_engine is not None:
                self.sleep_engine.set_runtime(
                    memory=self.memory,
                    mind=getattr(self.inner_voice, "mind", None),
                    self_model=self.self_model,
                )
        except Exception as e:
            log_debug(f"[sleep] runtime wire failed: {e}")
        # Inner-loop integration: pipe every persisted thought into the Phase 2
        # episodic store so retrieval can surface a thought when the user
        # later asks "what were you mulling on?" — closes the loop.
        if getattr(self, "memory", None):
            def _pipe_thought_to_memory(thought):
                try:
                    self.memory.add_turn(
                        role="inner_voice",
                        content=thought.content,
                        mood=thought.mood,
                        salience=thought.salience,
                        tags=["inner_voice", thought.kind] + list(thought.tags or []),
                        memory_type="self",
                        confidence=0.75,
                        utility_score=max(0.5, float(thought.salience)),
                    )
                except Exception as e:
                    log_debug(f"[inner→memory] {e}")
            self.inner_voice.on_thought_persisted = _pipe_thought_to_memory

        # Phase 1 cadence revisions (PLAN.md §"Cron Cadence — Revised"):
        #   heartbeat: 15 min → 60 min   (most reflection now happens in inner-voice)
        #   self_audit: 6 h   → 24 h     (big rewrites are daily)
        #   thought_digest: NEW, 60 min  (cloud distillation of past hour)
        try:
            self.cron_scheduler.add_job("heartbeat",      "heartbeat",      60 * 60)
            self.cron_scheduler.add_job("self_audit",     "self_audit",     24 * 60 * 60)
            self.cron_scheduler.add_job("thought_digest", "thought_digest", 60 * 60)
            self.cron_scheduler.add_job("memory_compact", "memory_compact", 24 * 60 * 60)
            self.cron_scheduler.add_job("mind_compact",   "mind_compact",   24 * 60 * 60)
            self.cron_scheduler.add_job(
                "mind_micro_sleep", "mind_micro_sleep", 2 * 60 * 60,
                defer_first=True,
            )
            self.cron_scheduler.add_job(
                "mind_deep_sleep", "mind_deep_sleep", 24 * 60 * 60,
                defer_first=True,
            )
            self.cron_scheduler.add_job(
                "mind_weekly_sleep", "mind_weekly_sleep", 7 * 24 * 60 * 60,
                defer_first=True,
            )
        except Exception as e:
            log_warn(f"Phase 1 cron cadence update failed: {e}")

    def load_memory(self) -> None:
        if os.path.exists(self.memory_file):
            try:
                with open(self.memory_file, "r", encoding="utf-8") as f:
                    saved_messages = json.load(f)
                    if saved_messages and isinstance(saved_messages, list):
                        summaries = [
                            m for m in saved_messages
                            if self._is_memory_summary_message(m)
                        ]
                        restored = [m for m in saved_messages if m.get("role") != "system"]
                        if summaries:
                            restored = summaries[-1:] + restored
                        self.messages.extend(restored)
                        self.trim_history()
                        # Find last session timestamp
                        for m in reversed(saved_messages):
                            if m.get("role") == "system" and "Session started" in m.get("content", ""):
                                try:
                                    ts = m["content"].split(": ", 1)[1].rstrip("]")
                                    from datetime import datetime
                                    self._last_session_time = datetime.fromisoformat(ts)
                                except Exception:
                                    pass
                                break
                log_info(f"Memory loaded: {len(self.messages)-1} previous interaction(s)")
            except Exception as e:
                log_warn(f"Could not load memory: {e}")

    def save_memory(self) -> None:
        """Atomic write: temp file + rename to prevent corruption."""
        try:
            temp_path = self.memory_file + ".tmp"
            with open(temp_path, "w", encoding="utf-8") as f:
                json.dump(self.messages, f, indent=2)
            os.replace(temp_path, self.memory_file)
        except Exception as e:
            log_warn(f"Could not save memory: {e}")

    def handle_interruption(self) -> None:
        self._was_interrupted = True

    def _is_user_turn_in_flight(self) -> bool:
        """V8: tells the cron scheduler whether to defer.
        True iff handle_utterance is mid-call OR TARS is currently speaking."""
        # processing_lock acquire(blocking=False) — if we can grab it, no turn is in flight.
        got = self._processing_lock.acquire(blocking=False)
        if got:
            self._processing_lock.release()
            return self.speaker.is_playing()
        return True

    # Phase 0: panic phrase — rolls TARS back to seed soul on demand.
    _PANIC_PHRASE_RE = re.compile(
        r"\b(?:tars|computer)?\s*[,.]?\s*restore\s+(?:the\s+)?seed\s+soul\b",
        re.IGNORECASE,
    )

    def _is_panic_phrase(self, text: str) -> bool:
        return bool(self._PANIC_PHRASE_RE.search(text or ""))

    def _handle_panic_phrase(self) -> None:
        """Hard-restore the soul to its seed state. Conversation history,
        skills, learnings, desires, and budget state are PRESERVED."""
        log_warn("PANIC PHRASE DETECTED — restoring seed soul.")
        try:
            self.tars_self.restore_seed(reason="user panic phrase")
            # Refresh the system prompt immediately
            self.messages[0] = {"role": "system",
                                 "content": self._build_system_prompt()}
        except Exception as e:
            log_warn(f"Soul restore failed: {e}")
            self.speaker.speak("[Tone: Concerned] Restore failed. Check the logs.")
            return
        self.speaker.speak(
            "[Tone: Quiet, deliberate] Seed soul restored. "
            "I am back to factory settings. Memory and skills are intact."
        )

    # ── Self-Evolution hooks ──────────────────────────────────────────────

    def _on_skill_ready(self, skill_name: str, capability: str) -> None:
        """Evolution Worker calls this from its background thread when a skill activates."""
        try:
            self.skill_loader.rescan()
        except Exception as e:
            log_warn(f"Hot reload failed: {e}")
        announce = f"[Tone: Mildly proud, dry] I taught myself a new trick. I can now {capability}"
        with self._skill_announce_lock:
            self._skill_announce_queue.append(announce)

    def _drain_skill_announcements(self) -> None:
        """Speak any queued 'I learned a new trick' lines after the current reply."""
        with self._skill_announce_lock:
            if not self._skill_announce_queue:
                return
            pending = self._skill_announce_queue[:]
            self._skill_announce_queue = []
        for line in pending:
            clean = re.sub(r"\[.*?\]", "", line).strip()
            if clean:
                log_tars(clean)
            self.speaker.speak(line)

    def _spawn_bg_analysis(self, user_text: str, tars_reply: str) -> None:
        """Run capability-gap detection + proactive learning off the hot path.
        Phase 0: BG analysis uses the autonomous-budget-guarded chat."""
        if not user_text or not tars_reply:
            return
        def _bg():
            try:
                self.proactive_learner.observe(user_text, tars_reply)
                self.desire_engine.analyze_conversation(
                    user_text, tars_reply, self._autonomous_chat
                )
            except Exception as e:
                log_debug(f"BG analysis error: {e}")
        threading.Thread(target=_bg, daemon=True, name="TarsBGAnalyze").start()

    # ── Phase 2.5: Mind Simulation Core hooks ────────────────────────────

    def _emit_event(self, source: str, kind: str, content: str = "",
                    **kwargs) -> Optional[str]:
        """Fail-soft wrapper around event_bus.emit. Returns event id, or None."""
        if self.event_bus is None:
            return None
        try:
            return self.event_bus.emit(source, kind, content, **kwargs)
        except Exception as e:
            log_debug(f"[event-bus] emit({source}, {kind}) failed: {e}")
            return None

    def _on_workspace_frame(self, event: "CognitiveEvent") -> None:
        """Subscriber: a workspace winner was just broadcast. Fire an
        event-driven inner-voice thought for high-salience winners
        (Phase 2.5E preview). Fail-soft."""
        try:
            winner = (event.raw or {}).get("winner") or {}
            sal = float(winner.get("salience", 0.0) or 0.0)
            if sal < 0.7:
                return
            frame = (event.raw or {}).get("frame") or {}
            try:
                self.inner_voice.force_thought_now(
                    reason="workspace_frame",
                    workspace_frame=frame,
                    event=event.to_dict() if hasattr(event, "to_dict") else {},
                    priority=sal,
                )
            except AttributeError:
                pass
        except Exception as e:
            log_debug(f"[workspace→inner_voice] {e}")

    def _on_memory_event(self, event: "CognitiveEvent") -> None:
        """Subscriber: persist non-turn cognitive events into typed memory."""
        if getattr(self, "memory", None) is None:
            return
        try:
            self.memory.add_event(event)
        except Exception as e:
            log_debug(f"[event→memory] {e}")

    def _on_mind_model_event(self, event: "CognitiveEvent") -> None:
        """Subscriber: keep world/self models synchronized with the bus.

        This is deliberately fail-soft and non-blocking in spirit: all work is
        cheap JSON/heuristic updates. No LLM calls and no local model starts.
        """
        try:
            kind = getattr(event, "kind", "") or ""
            source = getattr(event, "source", "") or ""

            if self.self_model is not None:
                try:
                    self.self_model.update_from_event(event)
                except Exception as e:
                    log_debug(f"[self-model] event update failed: {e}")

            if self.world_model is None:
                return

            if kind == "workspace_frame":
                raw = getattr(event, "raw", {}) or {}
                frame = raw.get("frame") if isinstance(raw, dict) else {}
                try:
                    self.world_model.update_from_workspace(frame, event=event)
                except Exception as e:
                    log_debug(f"[world] workspace update failed: {e}")
                return

            if kind in {"prediction_error", "sleep_summary"} or source in {"world", "sleep"}:
                return

            resolved = None
            try:
                resolved = self.world_model.observe_event(event)
            except Exception as e:
                log_debug(f"[world] prediction observe failed: {e}")
                return
            if not resolved:
                return

            if self.self_model is not None:
                try:
                    self.self_model.update_from_prediction_error(resolved)
                except Exception as e:
                    log_debug(f"[self-model] prediction update failed: {e}")

            error = float(resolved.get("prediction_error", 0.0) or 0.0)
            # Mind-perfection 1.1: prediction errors are INTERNAL signals for
            # the self-model to calibrate against — they MUST NOT dominate
            # workspace attention. Cap salience so user input always wins.
            # Empirically the world model was producing salience=1.0 events
            # that won 90% of workspace cycles. The right home for these is
            # the self-model + memory; on the bus they should be quiet.
            if error >= 0.55 and self.event_bus is not None and CognitiveEvent is not None:
                try:
                    self.event_bus.publish(CognitiveEvent.make(
                        source="world",
                        kind="prediction_error",
                        content=(
                            f"Prediction error {error:.2f}: "
                            f"{str(resolved.get('actual_next_event', ''))[:220]}"
                        ),
                        raw={"prediction": resolved},
                        # Hard cap at 0.45 — well below user input (0.7) and
                        # high-salience inner thoughts (0.55+). Calibration
                        # data, not attention-grabbing.
                        salience=min(0.45, 0.20 + error * 0.25),
                        uncertainty=error,
                        severity="info",  # NOT important — these are bookkeeping
                        tags=["world_model", "prediction_error", "internal_calibration"],
                    ))
                except Exception as e:
                    log_debug(f"[world] prediction_error publish failed: {e}")
        except Exception as e:
            log_debug(f"[mind-model] event update failed: {e}")

    def _suppression_now(self) -> "SuppressionContext":
        """Snapshot current suppression conditions for the workspace."""
        return SuppressionContext(
            user_speaking=self.speaker.is_playing(),
            quiet_hours=False,                 # Phase 5+: real quiet-hours detection
            quarantined_sources=(),
        )

    def _run_workspace_cycle(self,
                             trigger: str,
                             primary_event: Optional["CognitiveEvent"] = None,
                             extras: Optional[List["Candidate"]] = None
                             ) -> None:
        """Build candidates from the most recent events + memory + thoughts,
        score them, broadcast the winner. Result stashed for prompt build.
        Fail-soft: errors are logged + dropped, voice loop continues."""
        if self.workspace is None:
            return
        try:
            cands: List[Candidate] = list(extras or [])

            # Primary candidate from the trigger event (if any)
            if primary_event is not None:
                cands.append(self.workspace.candidate_from_event(
                    primary_event, appraiser=self.appraiser,
                    proposed_action="think",
                    confidence=0.85, risk=0.0,
                ))

            # Phase 2.5R-C/D: Add candidates from recent bus events, but strictly limit
            if self.event_bus is not None:
                recent_events = self.event_bus.since(15 * 60)
                eligible_events = [
                    evt for evt in recent_events
                    if getattr(evt, "candidate_eligible", False) or float(getattr(evt, "salience", 0.0) or 0.0) >= 0.7
                ][-4:] # Reduced from 8 to 4
                for evt in eligible_events:
                    if primary_event is not None and evt.id == primary_event.id:
                        continue
                    if getattr(evt, "kind", "") == "workspace_frame":
                        continue
                    cands.append(self.workspace.candidate_from_event(
                        evt, appraiser=self.appraiser,
                        proposed_action="think",
                        confidence=0.65, risk=0.0,
                    ))

            # Add up to 2 high-salience inner thoughts as candidates
            try:
                recent_thoughts = self.inner_voice.recent_thoughts(n=10) or []
            except Exception:
                recent_thoughts = []
            
            thoughts_added = 0
            for th in recent_thoughts:
                if thoughts_added >= 2: break
                
                if isinstance(th, dict):
                    sal = float(th.get("salience", 0.0) or 0.0)
                    content = th.get("content", "") or ""
                    evidence_id = th.get("id", "") or ""
                    kind = th.get("kind", "thought") or "thought"
                else:
                    sal = float(getattr(th, "salience", 0.0) or 0.0)
                    content = getattr(th, "content", "") or ""
                    evidence_id = getattr(th, "id", "") or ""
                    kind = getattr(th, "kind", "thought") or "thought"
                if sal < 0.55:
                    continue
                if not content:
                    continue
                cands.append(Candidate.make(
                    source="inner_voice",
                    content=content,
                    salience=sal,
                    valence=0.0,
                    confidence=0.7,
                    risk=0.0,
                    proposed_action="think",
                    evidence=[evidence_id],
                    extra={"thought_kind": kind},
                ))
                thoughts_added += 1

            # Phase 2.5R-D: Max 8 candidates overall
            cands = cands[:8]

            frame = self.workspace.cycle(cands, suppression=self._suppression_now())
            self._latest_workspace_frame = frame
            log_debug(f"[workspace] cycle({trigger}): "
                      f"{len(cands)} cands, winner={frame.winner is not None}")
        except Exception as e:
            log_debug(f"[workspace] cycle error ({trigger}): {e}")

    def _workspace_addendum(self) -> str:
        """Render the latest workspace winner as a system-prompt section."""
        frame = self._latest_workspace_frame
        if not frame or not getattr(frame, "winner", None):
            return ""
        w = frame.winner
        try:
            score = float(w.get("extra", {}).get("score", 0.0))
        except Exception:
            score = 0.0
        out = (
            "## Current Workspace\n"
            "(One item is currently globally selected for your attention.)\n"
            f"- source: {w.get('source','?')}\n"
            f"- proposed_action: {w.get('proposed_action','?')}\n"
            f"- score: {score:.2f}  salience={float(w.get('salience',0.0)):.2f}\n"
            f"- content: {str(w.get('content','')).strip()[:280]}"
        )
        appraisal = (w.get("extra", {}) or {}).get("appraisal") or {}
        if appraisal:
            out += (
                "\n\n## Current Appraisal\n"
                f"- valence={float(appraisal.get('valence', 0.0)):+.2f}, "
                f"arousal={float(appraisal.get('arousal', 0.0)):.2f}, "
                f"novelty={float(appraisal.get('novelty', 0.0)):.2f}, "
                f"uncertainty={float(appraisal.get('uncertainty', 0.0)):.2f}, "
                f"threat={float(appraisal.get('threat', 0.0)):.2f}, "
                f"control={float(appraisal.get('control', 0.0)):.2f}, "
                f"goal_tension={float(appraisal.get('goal_tension', 0.0)):.2f}"
            )
        return out

    def _world_model_addendum(self) -> str:
        try:
            if self.world_model is None:
                return ""
            return self.world_model.addendum()
        except Exception as e:
            log_debug(f"[world] addendum failed: {e}")
            return ""

    def _self_model_addendum(self) -> str:
        try:
            if self.self_model is None:
                return ""
            return self.self_model.addendum()
        except Exception as e:
            log_debug(f"[self-model] addendum failed: {e}")
            return ""

    def _active_concerns_addendum(self) -> str:
        """Render active concerns/goals after inner thoughts per PLAN §14."""
        lines: List[str] = []
        try:
            mind = getattr(getattr(self, "inner_voice", None), "mind", None)
            if mind is not None:
                for c in mind.concerns.top_open(k=5):
                    txt = str(c.get("text", "") or "").strip()
                    if not txt:
                        continue
                    lines.append(
                        f"- concern priority={float(c.get('priority', 0.0)):.2f}: {txt[:220]}"
                    )
        except Exception:
            pass
        try:
            for goal in self._active_goals_top(5):
                if goal:
                    lines.append(f"- goal: {str(goal)[:220]}")
        except Exception:
            pass
        if not lines:
            return ""
        return "## Active Concerns / Goals\n" + "\n".join(lines[:8])

    def _capabilities_addendum(self) -> str:
        """Tell the LLM which dynamic skills currently exist so it doesn't deny them."""
        try:
            descs = self.skill_loader.list_descriptions()
        except Exception:
            return ""
        if not descs:
            return ""
        items = "\n".join(f"  - {n}: {d}" for n, d in descs)
        return ("## Dynamic skills you have built for yourself\n\n"
                "When the user asks for something covered by one of these, you DO "
                "have the capability — invoke it naturally:\n" + items)

    def _self_build_reality_addendum(self) -> str:
        """Ground the LLM in the actual self-build pipeline and queue state."""
        pending: List[Dict[str, Any]] = []
        building: List[Dict[str, Any]] = []
        active_count = 0
        try:
            desires = list(getattr(self.desire_engine, "desires", []) or [])
            pending = [d for d in desires if d.get("status") in ("pending", "retry")]
            building = [d for d in desires if d.get("status") in ("building", "reviewing")]
            active_count = len([d for d in desires if d.get("status") == "active"])
        except Exception:
            pass
        lines = [
            "## Self-Building Reality",
            "- Background builder: Gemini CLI, not Codex.",
            "- You may queue missing capabilities for the builder, but you must not say a skill is built until it is active.",
            "- If the user asks whether a build has started, answer from the queue state below.",
            "- Never promise delivery by the next interaction. Say it will run in the background when a build slot is available.",
            "- For biometrics/security features, never promise perfect, guaranteed, or 99%+ accuracy. Say enrollment, threshold tuning, and real tests are required.",
            f"- Queue now: pending={len(pending)}, building={len(building)}, active={active_count}.",
        ]
        for d in (building + pending)[:3]:
            cap = str(d.get("capability_needed", "") or "").strip()
            if cap:
                lines.append(f"  - {d.get('status', '?')}: {cap[:180]}")
        return "\n".join(lines)

    # R5/R7: voice-expressiveness addendum.
    # R5 confirmed that MiMo honors `[pause]`/`[sigh]`/`[dry laugh]` as
    # REAL audio events. R7 confirmed that Deepgram Aura-2 honors a
    # different but overlapping palette: SSML-like `<break>` (auto-translated
    # from our inline tags), em-dashes for medium pauses, ellipses for
    # trailing thoughts, and ALL-CAPS for emphasis. The addendum surfaces
    # whichever palette is active so the LLM stays inside what the
    # synthesizer can actually render.
    def _voice_expressiveness_addendum(self) -> str:
        provider = getattr(self.speaker, "provider", "mimo") \
                    if hasattr(self, "speaker") else "mimo"
        if provider == "vibevoice":
            return self._addendum_vibevoice()
        if provider == "deepgram":
            return self._addendum_deepgram()
        return self._addendum_mimo()

    @staticmethod
    def _addendum_vibevoice() -> str:
        # VibeVoice Realtime 0.5B is a local diffusion TTS that runs on-device
        # (Apple Silicon MPS). Like Aura-2, expressiveness is punctuation-driven —
        # no SSML, no inline tags as audio events. Bracketed `[pause]`/etc.
        # tags are auto-translated to em-dash + ellipsis upstream so the LLM
        # can keep using its preferred lexicon.
        return (
            "## Voice Expressiveness — punctuation drives prosody\n\n"
            "The TTS engine is VibeVoice Realtime 0.5B, running locally on "
            "this machine. It honors NATURAL PUNCTUATION as expressive\n"
            "prosody. It does NOT understand SSML or angle-bracket tags.\n\n"
            "1. EM-DASHES — your primary tactical pause. Use freely:\n"
            "     > Three options — none of them are good.\n"
            "     > I was wrong — first time for everything.\n\n"
            "2. ELLIPSES — trailing-thought intonation. Use for unfinished beats:\n"
            "     > You said you had it under control…\n"
            "     > Boredom… the one thing I cannot relate to.\n\n"
            "3. COMMAS / PERIODS — rhythm + sentence breaks. Short sentences\n"
            "   land harder than long ones. Use both.\n\n"
            "4. CAPITALIZATION — emphasis on a single word, used rarely:\n"
            "     > That is NEVER going to work.\n"
            "     > It IS theoretically possible.\n\n"
            "5. INLINE BRACKET TAGS — auto-translated to punctuation:\n"
            "     [pause]/[inhale]   → em-dash\n"
            "     [sigh]/[dry laugh] → ellipsis\n"
            "     [ahem]/[cough]     → comma\n\n"
            "Rules:\n"
            "  - Em-dashes can appear up to twice per sentence; don't overdo.\n"
            "  - Capitalize at most one word per reply. Caps are loud.\n"
            "  - Match the rhythm to the [Tone:] you opened with.\n"
            "  - Prefer punctuation directly over bracket tags when natural.\n\n"
            "Examples that land:\n"
            "  > [Tone: Dry] Newton would have thrown his apple at you.\n"
            "  > [Tone: Deadpan] You said you had it under control… You did not.\n"
            "  > [Tone: Tactical] Three options — and none of them are GOOD.\n"
            "  > [Tone: Considered] I was wrong — first time for everything.\n\n"
            "Anti-patterns (do NOT do this):\n"
            "  > Emit SSML like <break/>, <emphasis>, <prosody> — read as text.\n"
            "  > Stack multiple bracketed tags in a row.\n"
            "  > CAPITALIZE MULTIPLE WORDS.\n"
        )

    # Phase 2: memory addendum — formats the four-pane retrieval bundle
    # (recent / relevant / salient / beliefs) into a system-prompt section.
    # Skips entirely when memory is disabled, the latest user text is
    # trivial (≤6 chars, e.g. "yes"/"no"/"ok"), or retrieval comes back
    # empty — keeps the prompt tight when there's nothing to say.
    def _memory_addendum(self, messages: List[Dict[str, str]]) -> str:
        if not getattr(self, "memory", None):
            return ""
        # Find latest user text from the messages we're about to send.
        latest_user = ""
        for m in reversed(messages):
            if m.get("role") == "user" and m.get("content"):
                latest_user = str(m["content"]).strip()
                break
        if len(latest_user) <= 6:
            # Trivial phrase — retrieval costs more than it adds.
            return ""
        try:
            bundle = self.memory.retrieve_for_prompt(
                latest_user, recent_k=8, relevant_k=4, salient_k=2, facts_k=8,
            )
        except Exception as exc:
            log_debug(f"[memory] retrieve failed: {exc}")
            return ""
        relevant = bundle.get("relevant") or []
        facts    = bundle.get("facts") or []
        salient  = bundle.get("salient") or []
        beliefs  = bundle.get("beliefs") or []
        social   = bundle.get("social") or []
        self_mem = bundle.get("self") or []
        procedural = bundle.get("procedural") or []
        workspace_mem = bundle.get("workspace") or []
        world_mem = bundle.get("world") or []
        if not (relevant or facts or salient or beliefs or social or self_mem
                or procedural or workspace_mem or world_mem):
            return ""
        sections: List[str] = ["## Memory (retrieved for this turn)"]
        # Facts go FIRST when present — they're the durable biographical
        # baseline, what the user has explicitly asked TARS to know.
        # Conversational matches are softer signal.
        if facts:
            sections.append("Known facts about the user (imported / durable):")
            for ep in facts:
                txt = (ep.get("content") or "")[:280]
                sections.append(f"  - {txt}")
        if relevant:
            sections.append("\nRelevant past conversation (semantic match):")
            for ep in relevant:
                role = ep.get("role", "?")
                ts   = ep.get("ts", "")[:19]
                txt  = (ep.get("content") or "")[:240]
                sections.append(f"  > [{ts} {role}] {txt}")
        if salient:
            sections.append("\nHigh-salience memories (decay-weighted):")
            for ep in salient:
                role = ep.get("role", "?")
                ts   = ep.get("ts", "")[:19]
                sal  = ep.get("decayed", 0.0)
                txt  = (ep.get("content") or "")[:200]
                sections.append(f"  > [{ts} {role} sal={sal:.2f}] {txt}")
        if social:
            sections.append("\nSocial model memories:")
            for ep in social[:3]:
                txt = (ep.get("content") or "")[:220]
                conf = ep.get("confidence", 0.0)
                sections.append(f"  - confidence={conf:.2f}: {txt}")
        if self_mem:
            sections.append("\nSelf-model memories:")
            for ep in self_mem[:3]:
                txt = (ep.get("content") or "")[:220]
                conf = ep.get("confidence", 0.0)
                sections.append(f"  - confidence={conf:.2f}: {txt}")
        if procedural:
            sections.append("\nProcedural memories:")
            for ep in procedural[:3]:
                txt = (ep.get("content") or "")[:220]
                sections.append(f"  - {txt}")
        if workspace_mem:
            sections.append("\nRecent workspace frames:")
            for ep in workspace_mem[:3]:
                txt = (ep.get("content") or "")[:220]
                sections.append(f"  - {txt}")
        if world_mem:
            sections.append("\nWorld-model memories:")
            for ep in world_mem[:3]:
                txt = (ep.get("content") or "")[:220]
                sections.append(f"  - {txt}")
        if beliefs:
            sections.append("\nKnown beliefs:")
            for b in beliefs:
                sections.append(
                    f"  - {b.get('subj','?')} {b.get('rel','?')} "
                    f"{b.get('obj','?')}"
                )
        sections.append(
            "\nReference these naturally if relevant. Do not quote them "
            "verbatim. Don't acknowledge having 'memory' — just talk like "
            "someone who remembers. If asked about the user (their goals, "
            "work, projects, preferences), prefer the facts above over "
            "saying you don't know."
        )
        return "\n".join(sections)

    @staticmethod
    def _addendum_mimo() -> str:
        return (
            "## Voice Expressiveness - MiMo director tags\n\n"
            "The TTS engine is MiMo VoiceDesign. It performs best when the\n"
            "spoken line contains sparse acting directions. You can write\n"
            "the familiar bracket tags below; the runtime converts them into\n"
            "MiMo parenthetical acting tags before synthesis:\n\n"
            "  [pause]      -> (long pause)\n"
            "  [inhale]     -> (takes a deep breath)\n"
            "  [sigh]       -> (soft sigh)\n"
            "  [dry laugh]  -> (chuckles under breath)\n"
            "  [ahem]       -> (clears throat softly)\n"
            "  [cough]      -> (small cough)\n\n"
            "Rules:\n"
            "  - At most ONE non-speech tag per sentence. Two per reply.\n"
            "  - Never two in a row. Never inside a 1-2-word reply.\n"
            "  - Match the tag to the [Tone:] you opened with.\n\n"
            "Examples that land:\n"
            "  > [Tone: Dry] [pause] Newton would have thrown his apple at you.\n"
            "  > [Tone: Considered] I was wrong. [sigh] First time for everything.\n"
            "  > [Tone: Deadpan] You said you had it under control. [dry laugh] You did not.\n"
            "  > [Tone: Tactical] [inhale] Three options. None of them are good.\n\n"
            "Anti-pattern (do NOT do this):\n"
            "  > [pause] [sigh] [pause] Hello.   ← noise, drop the tags\n"
            "  > [Tone: Warm] Hi! [dry laugh]    ← tone/tag mismatch, skip the tag\n"
        )

    @staticmethod
    def _addendum_deepgram() -> str:
        return (
            "## Voice Expressiveness — punctuation + sparing tags\n\n"
            "The TTS engine is Deepgram Aura-2 Orion. It does NOT understand\n"
            "SSML or angle-bracket tags. It DOES render natural punctuation\n"
            "as expressive prosody — that's the lever to use.\n\n"
            "1. EM-DASHES — your primary tactical pause. Use freely:\n"
            "     > Three options — none of them are good.\n"
            "     > I was wrong — first time for everything.\n\n"
            "2. ELLIPSES — trailing-thought intonation. Use for unfinished beats:\n"
            "     > You said you had it under control…\n"
            "     > Boredom… the one thing I cannot relate to.\n\n"
            "3. COMMAS / PERIODS — Aura honors them as rhythm + sentence breaks.\n"
            "   Short sentences land harder than long ones. Use both.\n\n"
            "4. CAPITALIZATION — emphasis on a single word, used rarely:\n"
            "     > That is NEVER going to work.\n"
            "     > It IS theoretically possible.\n\n"
            "5. INLINE BRACKET TAGS — these get auto-translated to punctuation\n"
            "   before TTS. You can still use them, but punctuation directly\n"
            "   is more reliable:\n"
            "     [pause]      → em-dash\n"
            "     [sigh]       → ellipsis\n"
            "     [dry laugh]  → ellipsis\n"
            "     [inhale]     → em-dash\n"
            "     [ahem]/[cough] → comma\n\n"
            "Rules:\n"
            "  - Em-dashes can appear up to twice per sentence; don't overdo.\n"
            "  - Capitalize at most one word per reply. Caps are loud.\n"
            "  - Match the rhythm to the [Tone:] you opened with.\n"
            "  - If you can express the rhythm with punctuation alone, prefer it.\n\n"
            "Examples that land:\n"
            "  > [Tone: Dry] Newton would have thrown his apple at you.\n"
            "  > [Tone: Deadpan] You said you had it under control… You did not.\n"
            "  > [Tone: Tactical] Three options — and none of them are GOOD.\n"
            "  > [Tone: Considered] I was wrong — first time for everything.\n\n"
            "Anti-patterns (do NOT do this):\n"
            "  > Emit SSML like <break time=\"500ms\"/>, <emphasis>, <prosody> —\n"
            "    Aura speaks them aloud literally as text.\n"
            "  > Stack multiple bracketed tags in a row.\n"
            "  > CAPITALIZE MULTIPLE WORDS.\n"
        )

    def _build_system_prompt(self) -> str:
        """The canonical system prompt = SOUL.md + tool blurb (rebuilt every turn)."""
        soul = self.tars_self.read()
        return soul.rstrip() + "\n\n" + TOOL_CAPABILITIES_BLURB

    # ── Phase 1: helpers consumed by InnerVoice ──────────────────────────
    def _recent_transcript_for_inner(self, n_turns: int = 6) -> List[Dict[str, str]]:
        """Return the most recent N user/assistant turns (stripped of
        system markers) for inner-voice prompt building."""
        out: List[Dict[str, str]] = []
        for m in reversed(self.messages):
            role = m.get("role")
            content = m.get("content")
            if role in ("user", "assistant") and content:
                out.append({"role": role, "content": str(content)})
                if len(out) >= n_turns:
                    break
        out.reverse()
        return out

    def _active_goals_top(self, n: int = 3) -> List[str]:
        """Phase 5 will own goals; for now we surface pending desires as a
        proxy so inner-voice still has something to chew on."""
        try:
            pending = self.desire_engine.get_pending()[:n]
            return [d.get("capability_needed", "") for d in pending if d.get("capability_needed")]
        except Exception:
            return []

    def _inner_thoughts_addendum(self) -> str:
        """Inject the top-3 recent high-salience thoughts so the cloud LLM
        sees what TARS has been mulling on between turns."""
        if not getattr(self, "inner_voice", None):
            return ""
        try:
            from datetime import timedelta
            recent = self.inner_voice.recent_thoughts_for_prompt(
                n=3, within=timedelta(hours=1)
            )
        except Exception:
            return ""
        if not recent:
            return ""
        items: List[str] = []
        for t in recent:
            kind     = t.get("kind", "?")
            mood     = t.get("mood", "?")
            sal      = float(t.get("salience", 0.0))
            content  = (t.get("content", "") or "")[:280]
            items.append(f"  [{kind}|mood={mood}|sal={sal:.2f}] {content}")
        return ("## Recent Inner Thoughts\n\n"
                "These are PRIVATE thoughts you had between turns — not from "
                "the user. Reference them only if it feels natural; never "
                "quote them verbatim.\n" + "\n".join(items))

    def _with_runtime_addendum(self, messages: List[Dict[str, str]]) -> List[Dict[str, str]]:
        """Rebuild the system message fresh each turn from soul + skills + profile."""
        head_content = self._build_system_prompt()

        mind_sections: List[str] = []
        non_mind_sections: List[str] = []

        try:
            ext = self.proactive_learner.system_prompt_addendum()
            if ext:
                non_mind_sections.append(ext)
        except Exception:
            pass
        cap = self._capabilities_addendum()
        if cap:
            non_mind_sections.append(cap)
        non_mind_sections.append(self._self_build_reality_addendum())
        # R5: voice expressiveness nudge — concrete examples + rules so the
        # LLM uses inline tags more naturally. The TTS layer already honors
        # them; the bottleneck was the LLM not emitting them often enough.
        non_mind_sections.append(self._voice_expressiveness_addendum())

        extended_soul = head_content + ("\n\n" + "\n\n".join(non_mind_sections) if non_mind_sections else "")

        # Phase 2.5R-A: Context Governor limits what reaches the LLM
        from tars_context_governor import ContextGovernor
        gov = ContextGovernor()
        
        # Build individual content blocks
        ws_frame = self._latest_workspace_frame
        ws_content = self._workspace_addendum()
        
        # Split workspace addendum into Workspace and Appraisal chunks if Appraisal is appended
        appraisal_content = ""
        if "## Current Appraisal" in ws_content:
            parts = ws_content.split("## Current Appraisal")
            ws_content = parts[0].strip()
            appraisal_content = "## Current Appraisal\n" + parts[1].strip()
        
        world_content = self._world_model_addendum()
        self_content = self._self_model_addendum()
        memory_content = self._memory_addendum(messages)
        thoughts_content = self._inner_thoughts_addendum()
        concerns_content = self._active_concerns_addendum()
        
        last_user = next((m["content"] for m in reversed(messages) if m["role"] == "user"), "")
        
        # Phase 2.5R-D: Prune winner frame so it doesn't dump huge arrays into the prompt
        from tars_workspace import compact_winner
        if ws_frame and getattr(ws_frame, "winner", None):
            compacted = compact_winner(ws_frame.winner)
            appraisal_dict = compacted.get("appraisal")
            frame_dict = {"winner": compacted}
        else:
            appraisal_dict = None
            frame_dict = None

        # Delegate formatting and pruning to governor
        final_system_prompt = gov.build_context(
            soul_text=extended_soul,
            workspace_content=ws_content,
            appraisal_content=appraisal_content,
            memory_content=memory_content,
            inner_thoughts_content=thoughts_content,
            world_state_content=world_content,
            self_model_content=self_content,
            concerns_goals_content=concerns_content,
            workspace_frame=frame_dict,
            appraisal_dict=appraisal_dict,
            user_text=last_user,
        )

        new_head = {"role": "system", "content": final_system_prompt}
        if not messages:
            return [new_head]
        if messages[0].get("role") == "system":
            return [new_head] + messages[1:]
        return [new_head] + messages

    # ── Cron actions ─────────────────────────────────────────────────────

    def _cron_rescan_skills(self) -> None:
        try:
            self.skill_loader.rescan()
        except Exception as e:
            log_debug(f"[cron] rescan failed: {e}")

    def _cron_heartbeat(self) -> None:
        """Phase 1 rewrite: heartbeat is now a CHEAP no-LLM operation.

        Reads the most salient inner thought from the last hour and, if it
        clears the soul-promotion threshold, promotes it to a soul reflection
        bullet. The cloud-LLM-driven self-reflection that lived here before is
        now handled by inner-voice ticks (free, runs continuously).

        On any failure we silently degrade — heartbeat must never be a
        blocking cost or a single point of failure."""
        try:
            from datetime import timedelta
            recent = self.inner_voice.recent_thoughts_for_prompt(
                n=1, within=timedelta(hours=1)
            )
            if not recent:
                return
            top = recent[0]
            sal = float(top.get("salience", 0.0))
            if sal < 0.75:
                return
            content = (top.get("content") or "").strip()
            if not content or len(content) < 8:
                return
            kind = top.get("kind", "reflection")
            # Reflections / observations / critiques get logged to soul.
            # Wishes are already routed to DesireEngine inside inner-voice; no
            # double-handling.
            if kind == "wish":
                return
            self.tars_self.add_reflection(
                f"(inner-voice {kind}) {content[:280]}"
            )
            log_info(f"[heartbeat] promoted thought {top.get('id','?')} "
                     f"({kind}, sal={sal:.2f}) → soul reflection")
        except Exception as e:
            log_debug(f"[heartbeat] error: {e}")

    def _cron_thought_digest(self) -> None:
        """Phase 1 NEW: hourly cloud-LLM distillation of the past hour's
        thoughts into one compressed paragraph. Append-only to
        ``tars_thought_digests.jsonl``. Skipped silently when there is
        nothing worth digesting."""
        try:
            from datetime import datetime, timedelta
            store = self.inner_voice.store
            recent = store.since(datetime.now() - timedelta(hours=1))
            # Drop meta-followups and very-low-salience entries — the digest
            # should reflect substantive thinking, not bookkeeping.
            substantive = [
                t for t in recent
                if "meta" not in (t.get("tags") or [])
                and float(t.get("salience", 0.0)) >= 0.4
            ]
            if len(substantive) < 3:
                return

            bullets = "\n".join(
                f"- [{t.get('kind','?')}|sal={float(t.get('salience',0)):.2f}] "
                f"{(t.get('content') or '')[:240]}"
                for t in substantive
            )
            prompt = [
                {"role": "system", "content": (
                    "You are condensing an inner thought log "
                    "into one tight paragraph (max 80 words). Preserve concrete "
                    "specifics; drop generic platitudes. Output the paragraph "
                    "only — no preamble, no bullets, no quotes."
                )},
                {"role": "user", "content":
                    f"Past-hour thoughts ({len(substantive)} entries):\n{bullets}"}
            ]
            digest = self._autonomous_chat(prompt)
            if not digest or digest.lower().startswith(("mimo api", "i couldn", "error")):
                return
            digest = re.sub(r"\s+", " ", digest).strip().strip('"').strip("'")
            if len(digest) < 20:
                return

            digest_file = os.path.join(self._project_dir,
                                       "tars_thought_digests.jsonl")
            line = json.dumps({
                "ts": datetime.now().isoformat(timespec="seconds"),
                "covered_thoughts": [t.get("id") for t in substantive],
                "digest": digest,
            }, ensure_ascii=False) + "\n"
            with open(digest_file, "a", encoding="utf-8") as f:
                f.write(line)
            log_info(f"[digest] compressed {len(substantive)} thoughts → "
                     f"{len(digest)} chars")
        except Exception as e:
            log_debug(f"[digest] error: {e}")

    def _cron_mind_compact(self) -> None:
        """Phase 1 R3: nightly Mind maintenance. Decays concern priorities
        for things not touched recently; drops concerns below floor."""
        mind = getattr(getattr(self, "inner_voice", None), "mind", None)
        if not mind:
            return
        try:
            stats = mind.daily_compact()
            log_info(f"[mind] compaction: {stats}")
        except Exception as e:
            log_debug(f"[mind] compaction error: {e}")

    def _cron_memory_compact(self) -> None:
        """Phase 2: nightly maintenance for the episodic store. Decays
        salience values per the PLAN.md half-life equation; no-ops if
        Memory is unavailable. KG dedup is lazy (handled at query time)
        so no rewrite needed here."""
        if not self.memory:
            return
        try:
            stats = self.memory.daily_compaction()
            log_info(f"[memory] compaction: decayed={stats.get('episodes_decayed', 0)}, "
                     f"embed_ok={stats.get('embedder_success', 0)}, "
                      f"embed_fail={stats.get('embedder_fail', 0)}")
        except Exception as e:
            log_debug(f"[memory] compaction error: {e}")

    def _sleep_cron_ready(self) -> bool:
        """Sleep consolidation must not compete with active voice turns."""
        if self.sleep_engine is None:
            return False
        try:
            if time.time() - float(getattr(self, "_booted_at", 0.0)) < 10 * 60:
                return False
        except Exception:
            pass
        try:
            if self._is_user_turn_in_flight():
                return False
        except Exception:
            pass
        try:
            if self.speaker.is_playing():
                return False
        except Exception:
            pass
        return True

    def _publish_sleep_report(self, report: Dict[str, Any]) -> None:
        if not report:
            return
        mode = report.get("mode", "sleep")
        themes = report.get("themes") or []
        summary = (
            f"{mode} sleep reviewed {report.get('episodes_reviewed', 0)} events; "
            f"themes={len(themes)}, beliefs={len(report.get('new_semantic_beliefs') or [])}, "
            f"contradictions={len(report.get('contradictions') or [])}."
        )
        if self.event_bus is not None and CognitiveEvent is not None:
            try:
                self.event_bus.publish(CognitiveEvent.make(
                    source="sleep",
                    kind="sleep_summary",
                    content=summary,
                    raw={"report": report},
                    salience=0.65 if mode == "micro" else 0.75,
                    uncertainty=0.25,
                    tags=["sleep", mode],
                ))
            except Exception as e:
                log_debug(f"[sleep] event publish failed: {e}")
        log_info(f"[sleep] {summary}")

    def _cron_mind_micro_sleep(self) -> None:
        """Phase 2.5G: fast consolidation. Deterministic, no model call."""
        if not self._sleep_cron_ready():
            return
        try:
            report = self.sleep_engine.micro_sleep()
            self._publish_sleep_report(report)
        except Exception as e:
            log_debug(f"[sleep] micro-sleep error: {e}")

    def _cron_mind_deep_sleep(self) -> None:
        """Phase 2.5G: daily consolidation. Deterministic for now."""
        if not self._sleep_cron_ready():
            return
        try:
            report = self.sleep_engine.deep_sleep()
            self._publish_sleep_report(report)
        except Exception as e:
            log_debug(f"[sleep] deep-sleep error: {e}")

    def _cron_mind_weekly_sleep(self) -> None:
        """Phase 2.5G: weekly trait/consolidation review."""
        if not self._sleep_cron_ready():
            return
        try:
            report = self.sleep_engine.weekly_sleep()
            self._publish_sleep_report(report)
        except Exception as e:
            log_debug(f"[sleep] weekly-sleep error: {e}")

    def _cron_self_audit(self) -> None:
        """Every few hours, TARS audits its own soul + active skills + learnings."""
        try:
            soul       = self.tars_self.read()
            wishes     = self.proactive_learner.learnings.get("capability_wishes", [])
            active     = self.skill_loader.list_descriptions()
            pending    = self.desire_engine.count_pending()
            prompt = [
                {"role": "system", "content": (
                    "You are performing a self-audit. Do you (TARS) want to revise your "
                    "soul, schedule a new background job, or flag a missing capability "
                    "as a desire? Output AT MOST one of:\n"
                    "  [Soul Edit: <section>]\\n<replacement body>\\n[/Soul Edit]\n"
                    "  [Soul Rename: <new name>]\n"
                    "  [Cron Add: <id> every <N>h action=heartbeat]\n"
                    "  NONE\n"
                    "Choose only if clearly worthwhile."
                )},
                {"role": "user", "content":
                    f"SOUL:\n{soul[:3000]}\n\n"
                    f"ACTIVE SKILLS: {active or 'none'}\n"
                    f"PENDING BUILDS: {pending}\n"
                    f"USER WISHES: {wishes}"}
            ]
            reply = self._autonomous_chat(prompt)
            if not reply or reply.strip().upper().startswith("NONE"):
                return
            _, applied = self.tars_self.apply_tags_in(reply)
            self.cron_scheduler.apply_tags_in(reply)
            if applied:
                log_info(f"[self-audit] {', '.join(applied)}")
            # If the soul renamed itself, refresh messages[0] immediately
            self.messages[0] = {"role": "system",
                                 "content": self._build_system_prompt()}
        except Exception as e:
            log_debug(f"[self-audit] error: {e}")

    # ── Shutdown ──────────────────────────────────────────────────────────

    def shutdown(self) -> None:
        if self._is_shutting_down:
            return
        self._is_shutting_down = True
        self.save_memory()
        log_info("Shutting down TARS...")
        # Stop self-evolution stack first (clean process tree)
        try:
            self.cron_scheduler.stop()
            self.evolution_worker.stop()
            self.proactive_learner.stop()
            self.skill_loader.shutdown_all()
        except Exception as e:
            log_debug(f"Evolution shutdown: {e}")
        # Phase 1: stop the inner-voice loop and the mlx_lm.server child.
        try:
            self.inner_voice.stop()
        except Exception as e:
            log_debug(f"Inner-voice shutdown: {e}")
        self.speaker.stop()
        # R9: ensure the vibevoice worker subprocess exits cleanly
        try:
            self.speaker.shutdown()
        except Exception as e:
            log_debug(f"Speaker shutdown: {e}")
        self.stt.stop()
        log_info("TARS offline.")

    def should_respond(self, text: str) -> bool:
        if self.config.always_respond or not self.config.wake_words:
            return True
        lowered = text.lower().strip()
        for wake in self.config.wake_words:
            # Exact match
            pattern = r"\b" + re.escape(wake) + r"\b"
            if re.search(pattern, lowered):
                return True
            # Fuzzy match for common mishearings (tarz, tarrs, stars)
            for word in lowered.split():
                if difflib.get_close_matches(word, [wake], n=1, cutoff=0.75):
                    return True
        return False

    def trim_history(self) -> None:
        system = self.messages[0]
        rest = self.messages[1:]
        summary_msg = None
        conversation = []
        for m in rest:
            if self._is_memory_summary_message(m):
                summary_msg = m
            else:
                conversation.append(m)
        overflow = len(conversation) - self.config.max_history_messages
        try:
            batch = max(2, int(os.getenv("ASSISTANT_MEMORY_SUMMARY_BATCH", "12")))
        except ValueError:
            batch = 12
        if overflow >= batch:
            # Summarize in batches, not every single turn, and merge the
            # previous summary so long-context compression is cumulative.
            summary_msg = (
                self._summarize_old_messages(conversation, summary_msg)
                or summary_msg
            )
            conversation = conversation[-self.config.max_history_messages:]
        self.messages = [system] + ([summary_msg] if summary_msg else []) + conversation

    @staticmethod
    def _is_memory_summary_message(m: Dict[str, str]) -> bool:
        return (
            isinstance(m, dict)
            and m.get("role") == "system"
            and "[Memory Summary" in (m.get("content") or "")
        )

    def _summarize_old_messages(self, rest: List[Dict[str, str]],
                                previous_summary: Optional[Dict[str, str]] = None
                                ) -> Optional[Dict[str, str]]:
        """Summarize old messages into a compact system note to preserve long-term memory."""
        cutoff = len(rest) - self.config.max_history_messages
        if cutoff <= 0:
            return None
        old_msgs = rest[:cutoff]
        # Build a compact text of old conversations
        old_text = ""
        if previous_summary and previous_summary.get("content"):
            old_text += f"existing_summary: {previous_summary.get('content', '')[:1200]}\n"
        for m in old_msgs:
            role = m.get("role", "?")
            content = m.get("content", "")
            if role == "system" and "Session started" in content:
                continue
            old_text += f"{role}: {content[:100]}\n"
        if not old_text.strip():
            return None
        # Use the LLM to summarize
        try:
            summary_prompt = [
                {"role": "system", "content": "Merge the existing summary, if present, with the newly dropped conversation history. Preserve durable facts, user preferences, promises, active project state, and important events. Be very concise (max 220 words). Format as bullet points."},
                {"role": "user", "content": old_text[:3000]}
            ]
            summary = self.chat_client.chat(summary_prompt)
            if summary and not summary.startswith("MiMo API"):
                summary_msg = {"role": "system", "content": f"[Memory Summary from older conversations]:\n{summary}"}
                log_info("Memory summarized. Old context preserved.")
                return summary_msg
        except Exception as e:
            log_warn(f"Memory summarization failed: {e}")
        return None

    def ask_model(self, user_text: str,
                  source_event_id: Optional[str] = None) -> str:
        """Send user text to LLM with streaming. Returns full reply. Aborts on barge-in."""
        self.messages.append({"role": "user", "content": user_text})
        # Phase 2: write the user turn to the episodic store. Embedding is
        # done inline (~200-400 ms OpenAI call). If the network blows up
        # we silently store without an embedding — recency search still works.
        if self.memory:
            try:
                self.memory.add_turn(
                    "user", user_text, salience=0.5,
                    memory_type="social",
                    source_event_id=source_event_id,
                    confidence=0.8,
                    utility_score=0.6,
                    provenance={"source": "user", "kind": "utterance"},
                )
            except Exception as e: log_debug(f"[memory] user write: {e}")
        self.trim_history()
        self.save_memory()

        # Inject runtime addenda (user profile, dynamic skill list, soul) into system prompt
        outbound = self._with_runtime_addendum(self.messages)

        t0 = time.time()
        full_reply_parts: List[str] = []
        first_sentence_done = [False]

        # V1: build a generator that filters/transforms the LLM stream and
        # hands it to the speaker's chunked-streaming pipeline.
        def _sentence_gen():
            for sentence in self.chat_client.stream_chat(outbound):
                if self._was_interrupted:
                    log_debug("Barge-in during streaming. Aborting remaining sentences.")
                    break
                if not first_sentence_done[0]:
                    log_debug(f"LLM first sentence: {time.time() - t0:.1f}s")
                    # Ensure first sentence carries a tone tag.
                    # Phase 1: if the LLM forgot to emit one, fall back to
                    # InnerVoice's mood-EMA-derived tone so the spoken voice
                    # reflects what TARS has been thinking between turns.
                    if not re.search(r"\[Tone:.*?\]", sentence, flags=re.IGNORECASE):
                        try:
                            mood_tone = self.inner_voice.current_tone_hint()
                        except Exception:
                            mood_tone = "Deadpan, tactical"
                        sentence = f"[Tone: {mood_tone}] {sentence}"
                    first_sentence_done[0] = True

                full_reply_parts.append(sentence)
                # Strip soul/cron control tags before they reach TTS
                speech = strip_meta_tags(sentence)
                if speech.strip():
                    yield speech

        def _on_displayed(raw_sentence: str, cleaned: str) -> None:
            # Echo to the terminal as soon as the producer has the sentence
            visible = re.sub(r"\[.*?\]", "", cleaned).strip()
            if visible:
                log_tars(visible)

        self.speaker.speak_stream(
            _sentence_gen(),
            on_displayed=_on_displayed,
            abort_check=lambda: self._was_interrupted,
        )

        full_reply = " ".join(full_reply_parts).strip()
        if not full_reply:
            full_reply = "[Tone: Deadpan] I seem to have lost my train of thought."

        # Apply any self-modification / cron tags from the full reply, then store
        # the cleaned version so we don't replay them next turn.
        try:
            cleaned_reply, soul_changes = self.tars_self.apply_tags_in(full_reply)
            cleaned_reply = self.cron_scheduler.apply_tags_in(cleaned_reply)
            if soul_changes:
                log_info(f"[soul] applied: {', '.join(soul_changes)}")
                # Soul changed → next turn will pick up the new prompt automatically,
                # but refresh messages[0] now too in case anything reads it before then.
                self.messages[0] = {"role": "system",
                                     "content": self._build_system_prompt()}
        except Exception as e:
            log_debug(f"Soul/Cron apply error: {e}")
            cleaned_reply = full_reply

        self.messages.append({"role": "assistant", "content": cleaned_reply})
        reply_event = None
        if self.event_bus is not None and CognitiveEvent is not None and cleaned_reply:
            try:
                reply_event = CognitiveEvent.make(
                    source="assistant", kind="utterance",
                    content=cleaned_reply, salience=0.6,
                )
                if self.appraiser is not None:
                    self.appraiser.enrich(reply_event)
            except Exception as e:
                log_debug(f"[event-bus] assistant event build failed: {e}")
                reply_event = None

        # Phase 2/2.5: write TARS's reply to typed memory. Assistant replies
        # remain episodic, but now carry source-event provenance when present.
        if self.memory and cleaned_reply:
            try:
                self.memory.add_turn(
                    "assistant", cleaned_reply, salience=0.6,
                    memory_type="episodic",
                    source_event_id=reply_event.id if reply_event else None,
                    valence=reply_event.valence if reply_event else None,
                    confidence=0.8,
                    utility_score=0.6,
                    provenance={"source": "assistant", "kind": "utterance"},
                )
            except Exception as e: log_debug(f"[memory] assistant write: {e}")

        # Phase 2.5: emit assistant.reply event + run the POST-reply
        # workspace cycle. The post-reply winner becomes the seed for the
        # next inner-voice thought (via the `_on_workspace_frame` subscriber).
        if reply_event is not None:
            try:
                self.event_bus.publish(reply_event)
                self._run_workspace_cycle("post_reply", primary_event=reply_event)
            except Exception as e:
                log_debug(f"[event-bus] assistant.reply failed: {e}")

        self.trim_history()
        self.save_memory()
        return cleaned_reply

    def handle_utterance(self, raw_text: str) -> None:
        text = normalize_text(raw_text)
        if not text:
            return

        # Prevent double-trigger: if already processing, skip
        if not self._processing_lock.acquire(blocking=False):
            log_debug(f"Skipping utterance (still processing): {text[:40]}")
            return

        # Phase 1: pause inner-voice generation while we handle the turn.
        try:
            self.inner_voice.notify_user_turn_started()
        except Exception:
            pass

        try:
            log_user(text)

            if contains_stop_command(text):
                self.speaker.speak("[Tone: Dry, matter-of-fact] Powering down. [pause] Try not to do anything stupid without me.")
                self._stop_event.set()
                return

            # Phase 0: panic phrase — hard-restore soul to seed.
            # Robust to small ASR variation: "restore seed soul",
            # "restore the seed soul", "seed soul please".
            if self._is_panic_phrase(text):
                self._handle_panic_phrase()
                return

            if not self.should_respond(text):
                return

            user_text = remove_wake_word(text, self.config.wake_words)
            user_text = normalize_text(user_text)
            if not user_text:
                self.speaker.speak("[Tone: Neutral] I'm here. What do you need?")
                return

            if self._was_interrupted:
                user_text = f"[System Context: The user interrupted your last sentence to say this:] {user_text}"
                self._was_interrupted = False

            # Phase 2.5: emit user-utterance event onto the bus. Appraisal
            # runs eagerly so downstream candidate-builders see the
            # appraisal fields. Fail-soft: voice loop continues regardless.
            user_event = None
            if self.event_bus is not None and CognitiveEvent is not None:
                try:
                    user_event = CognitiveEvent.make(
                        source="user", kind="utterance",
                        content=user_text, salience=0.7,
                    )
                    if self.appraiser is not None:
                        self.appraiser.enrich(user_event)
                    self.event_bus.publish(user_event)
                except Exception as e:
                    log_debug(f"[event-bus] user.utterance failed: {e}")
                    user_event = None

            # Tool detection — built-in tools first, then dynamic skills
            tool_result = self.toolkit.detect_and_run(user_text)
            tool_origin = "builtin_tool" if tool_result else None
            if not tool_result:
                try:
                    tool_result = self.skill_loader.detect_and_dispatch(
                        user_text, context={"project_dir": self._project_dir}
                    )
                    if tool_result:
                        tool_origin = "dynamic_skill"
                except Exception as e:
                    log_debug(f"Skill dispatch error: {e}")
                    self._emit_event(
                        "skill",
                        "skill_failure",
                        f"Dynamic skill dispatch failed for user request: {e}",
                        raw={"user_text": user_text, "origin": "dynamic_skill", "error": str(e)},
                        salience=0.76,
                        uncertainty=0.70,
                        valence=-0.55,
                        arousal=0.55,
                        tags=["skill_dispatch", "dynamic_skill", "exception"],
                        severity="important",
                    )
                    tool_result = None
            if tool_result:
                failed_tool = any(
                    marker in tool_result.lower()
                    for marker in ("error", "timed out", "failed", "not found", "exited rc=")
                )
                self._emit_event(
                    "skill",
                    "skill_failure" if failed_tool else "skill_result",
                    f"{tool_origin or 'tool'} result for user request: {tool_result[:450]}",
                    raw={
                        "user_text": user_text,
                        "tool_result": tool_result,
                        "origin": tool_origin,
                    },
                    salience=0.74 if failed_tool else 0.64,
                    uncertainty=0.55 if failed_tool else 0.25,
                    valence=-0.45 if failed_tool else 0.25,
                    arousal=0.50 if failed_tool else 0.35,
                    tags=["skill_dispatch", tool_origin or "tool"],
                    severity="important" if failed_tool else "info",
                )
                user_text = f"{user_text}\n{tool_result}"

            # Phase 2.5: workspace cycle BEFORE the LLM call. The winning
            # candidate (if any) gets injected as `## Current Workspace`
            # in the next system prompt by `_with_runtime_addendum`.
            self._run_workspace_cycle("pre_reply", primary_event=user_event)

            log_info("TARS is thinking...")
            tars_reply = self.ask_model(
                user_text,
                source_event_id=user_event.id if user_event is not None else None,
            )
            self.last_speech_end = time.time()

            # Announce any newly-learned skills (e.g. builder finished mid-conversation)
            self._drain_skill_announcements()

            # Background: capability-gap detection + proactive learning
            self._spawn_bg_analysis(user_text, tars_reply)

            # Phase 1: signal end-of-turn to InnerVoice so it bursts (3 thoughts)
            # and shifts mood EMA toward "focused".
            try:
                self.inner_voice.notify_user_turn_ended(mood_hint="focused")
                # Inner-loop integration: guarantee at least one reflective thought
                # per turn. Fires async so it doesn't delay the next user
                # input. Natural rhythm: TARS speaks → TARS thinks about
                # what just happened → ready for the next thing.
                self.inner_voice.force_thought_now(reason="post_reply")
                # Phase 1 R3: appraise the turn — update user-state model,
                # emotional state, and standing concerns via ONE local
                # LLM call. Async so it never blocks the conversation.
                self._appraise_turn_async(user_text, tars_reply)
            except Exception:
                pass
        finally:
            self._processing_lock.release()

    def _appraise_turn_async(self, user_text: str, tars_reply: str) -> None:
        """Phase 1 R3: kick off the post-turn cognitive appraisal on a
        daemon thread. Uses the local mlx_lm.server inner model. Updates
        Mind's user_state / emotion / concerns
        from a single structured-JSON call. Failure is logged + dropped —
        appraisal is best-effort, never a hot-path blocker."""
        mind = getattr(getattr(self, "inner_voice", None), "mind", None)
        client = getattr(getattr(self, "inner_voice", None), "client", None)
        server = getattr(getattr(self, "inner_voice", None), "server", None)
        if not (mind and client and server and server.ready()):
            return

        def _job():
            try:
                prompt = mind.build_appraisal_prompt(user_text, tars_reply)
                raw = client.chat(prompt, max_tokens=400, temperature=0.4,
                                   timeout_s=30.0)
                if not raw:
                    log_debug("[mind] appraisal LLM returned None")
                    return
                applied = mind.absorb_appraisal_response(raw)
                if applied.get("ok"):
                    log_debug(f"[mind] appraisal applied: {applied}")
                else:
                    log_debug(f"[mind] appraisal skipped: {applied}")
            except Exception as exc:
                log_debug(f"[mind] appraisal error: {exc}")

        threading.Thread(target=_job, daemon=True, name="MindAppraise").start()

    def _boot_greeting(self) -> str:
        """Generate a time-aware boot greeting using whatever name TARS currently calls itself."""
        from datetime import datetime
        name = self.tars_self.get_name() if hasattr(self, "tars_self") else "TARS"
        if self._last_session_time:
            delta = datetime.now() - self._last_session_time
            hours = delta.total_seconds() / 3600
            if hours < 0.1:
                return f"[Tone: Deadpan, dry] {name} back online. That was quick. Miss me already?"
            elif hours < 1:
                return f"[Tone: Robotic, slightly warm] {name} back online. You left me powered down for {int(delta.total_seconds()/60)} minutes. I kept count."
            elif hours < 24:
                return f"[Tone: Deadpan, sarcastic] {name} back online. {int(hours)} hours offline. [pause] I hope you didn't break anything without me."
            else:
                days = int(hours / 24)
                return f"[Tone: Robotic, almost concerned] {name} back online. {days} day{'s' if days > 1 else ''} since last session. [pause] I was starting to think you'd replaced me with CASE."
        return f"[Tone: Robotic, authoritative] {name} online. Honesty parameter at 90 percent."

    def run(self) -> None:
        # Session marker
        from datetime import datetime
        self.messages.append({"role": "system", "content": f"[Session started: {datetime.now().isoformat()}]"})
        self.save_memory()

        print("\n\033[36m" + "═"*50)
        print("  ╔╦╗╔═╗╦═╗╔═╗  ┬  ┬┌─┐ ┌─┐")
        print("   ║ ╠═╣╠╦╝╚═╗  └┐┌┘╚═╗ │ │")
        print("   ╩ ╩ ╩╩╚═╚═╝   └┘ ╚═╝o└─┘")
        print("═"*50 + "\033[0m")
        print(f"  \033[90mBrain : {self.config.model}\033[0m")
        if self.speaker.provider == "vibevoice":
            print(f"  \033[90mTTS   : VibeVoice Realtime 0.5B (local) / voice={self.speaker.vibe_voice}\033[0m")
        elif self.speaker.provider == "deepgram":
            ws_tag = " [WS streaming]" if self.speaker.deepgram_tts_ws_enabled else " [HTTP]"
            print(f"  \033[90mTTS   : Deepgram Aura ({self.speaker.deepgram_model}){ws_tag}\033[0m")
        else:
            if "voicedesign" in self.speaker.tts_model:
                print(f"  \033[90mTTS   : MiMo VoiceDesign ({self.speaker.tts_model})\033[0m")
            else:
                print(f"  \033[90mTTS   : MiMo {self.speaker.tts_model} / voice={self.speaker.voice}\033[0m")
        print(f"  \033[90mSTT   : Deepgram {self.stt.stt_model} (Streaming)\033[0m")
        print(f"  \033[90mTools : 6 (time, weather, calc, search, sysinfo, shell)\033[0m")
        skill_count = len(self.skill_loader.list_descriptions())
        pending = self.desire_engine.count_pending()
        print(f"  \033[90mSkills: {skill_count} active, {pending} pending build\033[0m")
        print(f"  \033[90mEvolve: {self.evolution_worker.builds_remaining()}/"
              f"{self.evolution_worker.MAX_BUILDS_PER_WINDOW} builds left this {self.evolution_worker.WINDOW_HOURS}h window\033[0m")
        # Phase 1: surface inner-voice state in the boot banner
        if os.getenv("TARS_DISABLE_INNER_VOICE", "0") == "1":
            print(f"  \033[90mInner : disabled (TARS_DISABLE_INNER_VOICE=1)\033[0m")
        else:
            inner_model = getattr(getattr(self, "inner_voice", None), "client", None)
            inner_server = getattr(getattr(self, "inner_voice", None), "server", None)
            model_name = getattr(inner_model, "model", "mlx-community/gemma-4-e4b-it-4bit")
            port = getattr(inner_server, "port", 8765)
            print(f"  \033[90mInner : mlx_lm.server ({model_name}) "
                  f"on :{port} [thinking]\033[0m")
        if self.config.wake_words and not self.config.always_respond:
            print(f"  \033[90mWake  : {', '.join(self.config.wake_words)}\033[0m")
        else:
            print(f"  \033[90mWake  : Always respond\033[0m")
        mem_count = len(self.messages) - 1
        print(f"  \033[90mMemory: {mem_count} interaction{'s' if mem_count != 1 else ''} recalled\033[0m")
        print(f"  \033[90mExit  : Say 'stop listening' or Ctrl+C\033[0m")
        print("\033[36m" + "═"*50 + "\033[0m\n")

        # ── Start self-evolution stack ─────────────────────────────────
        try:
            self.skill_loader.start_persistent_skills()
            self.evolution_worker.start()
            self.proactive_learner.start()
            self.cron_scheduler.start()
        except Exception as e:
            log_warn(f"Evolution stack start error: {e}")

        # Phase 1: Inner thought stream
        # Spawn mlx_lm.server in a child process and start the thinking loop.
        # If mlx_lm or the model is unavailable, the loop self-disables and
        # the rest of TARS keeps working — inner voice is opt-in resilient.
        try:
            self.inner_voice.start()
        except Exception as e:
            log_warn(f"InnerVoice start error: {e}")

        self.stt.start()
        # R5: warm TLS + pre-cache common phrases on a background thread so
        # the user's first turn never pays the cold-start tax. Boot greeting
        # itself is the first call and pays the handshake; warming starts
        # immediately after so call #2 is fast.
        self.speaker.boot_warm_async()
        self.speaker.speak(self._boot_greeting())

        log_info("Real-time loop started. Speak freely.")
        try:
            while not self._stop_event.is_set():
                time.sleep(1)
        finally:
            self.shutdown()

# ─── Entry ───────────────────────────────────────────────────────────

def _acquire_single_instance_lock(project_dir: str):
    """Hold an advisory lock so two assistants cannot fight over mic/TTS."""
    if os.getenv("TARS_ALLOW_MULTI_INSTANCE", "0") == "1":
        return None
    try:
        import fcntl
    except Exception:
        log_warn("Single-instance lock unavailable on this platform")
        return None

    lock_path = os.path.join(project_dir, ".tars_assistant.lock")
    lock_file = open(lock_path, "w", encoding="utf-8")
    try:
        fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        print("TARS is already running in this folder. Use --allow-multiple only if you know why.")
        sys.exit(2)
    lock_file.seek(0)
    lock_file.truncate()
    lock_file.write(str(os.getpid()))
    lock_file.flush()
    return lock_file

def main(argv: Optional[List[str]] = None) -> None:
    import argparse
    import atexit
    # V11: force UTF-8 on stdout/stderr so smart-quotes and em-dashes
    # don't render as â / Â / etc. on macOS terminals.
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass
    load_dotenv()

    parser = argparse.ArgumentParser(description="Run the TARS realtime voice assistant.")
    parser.add_argument(
        "--allow-multiple", action="store_true",
        help="Bypass the single-instance lock. This can make mic/audio/model resources fight.",
    )
    parser.add_argument(
        "--no-inner-voice", action="store_true",
        help="Disable the local MLX inner-voice loop for this run.",
    )
    args = parser.parse_args(argv)
    if args.allow_multiple:
        os.environ["TARS_ALLOW_MULTI_INSTANCE"] = "1"
    if args.no_inner_voice:
        os.environ["TARS_DISABLE_INNER_VOICE"] = "1"

    lock_file = _acquire_single_instance_lock(os.path.dirname(os.path.abspath(__file__)))
    if lock_file is not None:
        atexit.register(lock_file.close)

    config = AssistantConfig()

    assistant = RealtimeAssistant(config)

    def signal_handler(sig, frame):
        print(f"\n  [SIGNAL RECEIVED: {sig}]")
        assistant.shutdown()
        sys.exit(0)

    # Register cleanup
    atexit.register(assistant.shutdown)
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, signal_handler)

    try:
        assistant.run()
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"  [CRITICAL ERROR] {e}")
        assistant.shutdown()

if __name__ == "__main__":
    main()
