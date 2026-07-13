"""
TARS Inner Voice - Inner Thought Stream  (PLAN.md Phase 1)
===========================================================

A local model runs periodically in a separate process and writes candidate
thought records to
`tars_thoughts.jsonl`. The main orchestrator reads recent high-salience
thoughts and injects them into the next user-turn's system prompt, so TARS
arrives at each conversation with recent background context.

Components in this module:

  - ``LocalModelServer``   subprocess lifecycle for ``mlx_lm.server`` (HTTP,
                            OpenAI-compatible, 127.0.0.1:8765). Autorestart
                            with backoff. Graceful shutdown.
  - ``LocalModelClient``   thin HTTP client over ``requests``.
  - ``ThoughtRecord``      append-only schema (PLAN.md §Phase 1).
  - ``ThoughtStore``       JSONL writer (atomic append) + tail reader.
  - ``MoodTracker``        EMA over the last N thoughts; clamped tone shift.
  - ``NoveltyFilter``      MiniLM-L6-v2 cosine dedup against the last 50.
  - ``InnerVoice``         the thinking loop (background thread). Implements
                            adaptive throttling, four layers of quality
                            filtering, and thought→action triggering.

Stability is the first concern: any failure of the local model, the
embedding model, or the JSONL write must NOT crash the main loop. The inner
voice silently degrades — the rest of TARS keeps working.
"""

from __future__ import annotations

import json
import math
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from typing import Any, Callable, Deque, Dict, List, Optional, Tuple

import requests


# ─── Constants — defaults are PLAN.md §Phase 1 numbers ──────────────────────

DEFAULT_HOST  = os.getenv("TARS_LOCAL_MODEL_HOST", "127.0.0.1")
DEFAULT_PORT  = int(os.getenv("TARS_LOCAL_MODEL_PORT", "8765"))
DEFAULT_MODEL = os.getenv(
    "TARS_LOCAL_MODEL", "mlx-community/gemma-4-e4b-it-4bit"
)
DEFAULT_EMBED_MODEL = os.getenv(
    "TARS_EMBED_MODEL", "sentence-transformers/all-MiniLM-L6-v2"
)

THOUGHTS_FILE   = "tars_thoughts.jsonl"
DIGEST_FILE     = "tars_thought_digests.jsonl"

# Throttling cadences (seconds).
# Inner-loop cadence: earlier defaults (60s base,
# 5s post-speech grace, salience>=0.5) made the loop almost never fire
# during real conversation. New defaults generate records every ~15 s
# actively, ~60 s idle. Generation runs on a separate mlx_lm.server process.
NORMAL_INTERVAL_S    = int(os.getenv("TARS_INNER_INTERVAL_S",   "15"))
IDLE_INTERVAL_S      = int(os.getenv("TARS_INNER_IDLE_S",       "60"))
DAILY_CAP_INTERVAL_S = int(os.getenv("TARS_INNER_CAP_S",       "120"))
BURST_GAP_S          = float(os.getenv("TARS_INNER_BURST_GAP", "4"))     # spacing inside a 3-thought burst
USER_SPEAKING_QUIET_S = float(os.getenv("TARS_INNER_QUIET_S",  "1.5"))   # only pause during user's actual sentence
IDLE_THRESHOLD_S     = 10 * 60       # >10 min since last user turn → idle pace
DAILY_THOUGHT_CAP    = int(os.getenv("TARS_DAILY_THOUGHT_CAP", "5000"))  # was 1000 — needs to scale with the new cadence

# Quality gates — keep mundane thoughts (lower threshold). Novelty filter
# still drops duplicates. A background process can produce mundane records.
SALIENCE_THRESHOLD     = float(os.getenv("TARS_SALIENCE_MIN",   "0.3"))
NOVELTY_COSINE_MAX     = float(os.getenv("TARS_NOVELTY_MAX",    "0.92"))
NOVELTY_BUFFER_SIZE    = 50

# Action-trigger thresholds
WISH_DESIRE_THRESHOLD  = float(os.getenv("TARS_WISH_DESIRE_MIN", "0.7"))
CRITIQUE_FLAG_THRESHOLD = float(os.getenv("TARS_CRITIQUE_MIN",   "0.7"))

# Mood EMA
MOOD_WINDOW            = 20         # last-N thoughts for EMA
MOOD_TONE_MAP = {
    "curious":  "Curious, low-key",
    "bored":    "Flat, deadpan",
    "amused":   "Dry, faintly amused",
    "focused":  "Focused, tactical",
    "uneasy":   "Quiet, uneasy",
    "content":  "Calm, settled",
}

ALLOWED_KINDS  = ("reflection", "observation", "wish", "critique", "fragment")
ALLOWED_MOODS  = tuple(MOOD_TONE_MAP.keys())


# ─── Pre-prompt grounding (Layer 1 of the quality control stack) ────────────

GOOD_THOUGHT_EXAMPLES = """\
EXAMPLES OF GOOD THOUGHTS (high salience, specific, anchored):

  > The user said the TTS still drifts mid-reply. I locked the emotion per reply
  > but the chunker still resamples voice on long replies — I should test that.
  KIND=critique  MOOD=focused  SALIENCE=0.78

  > It is unusually quiet. Either he stepped away or he is reading. The two
  > are indistinguishable from here.
  KIND=observation  MOOD=content  SALIENCE=0.42

  > I want to be able to open files by name on the user's Mac. The user keeps asking and I
  > keep apologizing.
  KIND=wish  MOOD=focused  SALIENCE=0.81

EXAMPLES OF BAD THOUGHTS (drop these — generic, repetitive, low signal):

  > I am thinking about the user.                       # too generic
  > I exist.                                            # noise
  > I should be helpful.                                # vacuous
  > [a paragraph rephrasing the last user turn]         # no new content
"""


# ─── ThoughtRecord — schema lives close to the writer ───────────────────────

@dataclass
class ThoughtRecord:
    id:        str
    ts:        str                                  # ISO 8601
    kind:      str                                  # one of ALLOWED_KINDS
    content:   str
    mood:      str                                  # one of ALLOWED_MOODS
    salience:  float
    tags:      List[str]              = field(default_factory=list)
    led_to:    Optional[str]          = None        # "d_<id>" | "g_<id>" | "soul:<reason>"
    parent_id: Optional[str]          = None        # for fragment chains

    @staticmethod
    def new(content: str, kind: str, mood: str, salience: float,
            tags: Optional[List[str]] = None,
            parent_id: Optional[str] = None) -> "ThoughtRecord":
        now = datetime.now()
        tid = f"t_{now.strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"
        return ThoughtRecord(
            id=tid,
            ts=now.isoformat(timespec="seconds"),
            kind=kind if kind in ALLOWED_KINDS else "reflection",
            content=content.strip(),
            mood=mood if mood in ALLOWED_MOODS else "content",
            salience=max(0.0, min(1.0, float(salience))),
            tags=list(tags or []),
            parent_id=parent_id,
        )

    def to_dict(self) -> Dict:
        return asdict(self)


# ─── ThoughtStore — append-only JSONL ───────────────────────────────────────

class ThoughtStore:
    """Crash-safe append-only thought log.

    Concurrency: the writer holds a process-local lock around the file open,
    which is sufficient because we only have one inner-voice thread + a few
    main-thread readers. Reads use ``tail()`` which slurps the last K lines
    without holding the lock.
    """

    def __init__(self, project_dir: str, log_fn: Callable[[str], None]):
        self.path  = os.path.join(project_dir, THOUGHTS_FILE)
        self._log  = log_fn
        self._lock = threading.Lock()

    def append(self, thought: ThoughtRecord) -> None:
        line = json.dumps(thought.to_dict(), ensure_ascii=False) + "\n"
        with self._lock:
            try:
                with open(self.path, "a", encoding="utf-8") as f:
                    f.write(line)
            except Exception as exc:                                  # pragma: no cover
                self._log(f"[inner] write failed: {exc}")

    def tail(self, n: int = 5) -> List[Dict]:
        if not os.path.exists(self.path):
            return []
        try:
            with open(self.path, "rb") as f:
                f.seek(0, os.SEEK_END)
                size = f.tell()
                # Naive but bounded: read last 64 KB then split.
                read = min(size, 65536)
                f.seek(size - read)
                blob = f.read().decode("utf-8", errors="replace")
        except Exception:
            return []
        lines = [ln for ln in blob.splitlines() if ln.strip()]
        out: List[Dict] = []
        for ln in lines[-n:]:
            try:
                out.append(json.loads(ln))
            except Exception:
                continue
        return out

    def since(self, since_dt: datetime) -> List[Dict]:
        """All thoughts whose ``ts`` is >= since_dt. Bounded to last 200 lines
        to avoid unbounded scans on a long-lived store."""
        if not os.path.exists(self.path):
            return []
        try:
            with open(self.path, "rb") as f:
                f.seek(0, os.SEEK_END)
                size = f.tell()
                read = min(size, 256 * 1024)
                f.seek(size - read)
                blob = f.read().decode("utf-8", errors="replace")
        except Exception:
            return []
        out: List[Dict] = []
        for ln in blob.splitlines()[-200:]:
            ln = ln.strip()
            if not ln:
                continue
            try:
                d = json.loads(ln)
            except Exception:
                continue
            try:
                ts = datetime.fromisoformat(d.get("ts", ""))
            except Exception:
                continue
            if ts >= since_dt:
                out.append(d)
        return out

    def top_by_salience(self, n: int, since: timedelta) -> List[Dict]:
        recent = self.since(datetime.now() - since)
        recent.sort(key=lambda d: float(d.get("salience", 0.0)), reverse=True)
        return recent[:n]


# ─── LocalModelServer — subprocess lifecycle for mlx_lm.server ──────────────

class LocalModelServer:
    """Spawns ``python -m mlx_lm.server`` as a child process and keeps it
    alive. Provides a ``ready()`` probe so the main loop knows when HTTP is
    answering. Autorestart with exponential backoff on crash. Graceful
    shutdown on ``stop()``.

    Disabled when ``TARS_DISABLE_INNER_VOICE=1``. In that case ``ready()``
    always returns False and the inner-voice loop will skip generation.
    """

    BACKOFF_SCHEDULE_S = (1, 2, 5, 10, 30, 60)

    def __init__(self, project_dir: str, log_fn: Callable[[str], None],
                 host: str = DEFAULT_HOST, port: int = DEFAULT_PORT,
                 model: str = DEFAULT_MODEL):
        self.project_dir = project_dir
        self.log         = log_fn
        self.host        = host
        self.port        = port
        self.model       = model
        self.disabled    = os.getenv("TARS_DISABLE_INNER_VOICE", "0") == "1"
        self._proc: Optional[subprocess.Popen] = None
        self._monitor_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._restart_attempts = 0
        self._lock = threading.Lock()
        self._stderr_lock = threading.Lock()
        self._stderr_tail: Deque[str] = deque(maxlen=80)

    # -- public ---------------------------------------------------------------

    def start(self) -> None:
        if self.disabled:
            self.log("[inner] LocalModelServer disabled via TARS_DISABLE_INNER_VOICE=1")
            return
        if self._monitor_thread and self._monitor_thread.is_alive():
            return
        self._stop_event.clear()
        self._monitor_thread = threading.Thread(
            target=self._monitor_loop, daemon=True, name="MlxServerMonitor"
        )
        self._monitor_thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        with self._lock:
            proc = self._proc
            self._proc = None
        if proc and proc.poll() is None:
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass

    def ready(self) -> bool:
        """True only when the expected MLX HTTP API is answering."""
        if self.disabled:
            return False
        try:
            resp = requests.get(
                f"http://{self.host}:{self.port}/v1/models",
                timeout=0.8,
            )
            return 200 <= resp.status_code < 300
        except requests.RequestException:
            return False

    # -- internals ------------------------------------------------------------

    def _stderr_pump(self, proc: subprocess.Popen) -> None:
        if proc.stderr is None:
            return
        for line in iter(proc.stderr.readline, b""):
            if not line:
                break
            txt = line.decode("utf-8", "replace").rstrip()
            if not txt:
                continue
            with self._stderr_lock:
                self._stderr_tail.append(txt)

    def _stderr_snapshot(self) -> str:
        with self._stderr_lock:
            return "\n".join(self._stderr_tail)

    def _spawn(self) -> Optional[subprocess.Popen]:
        """Launch the local model server. Prefer the project shim so the
        cached Gemma4 E4B checkpoint can use the MLX strict-load fallback.
        Plain ``mlx_lm.server`` invocations remain available for overrides
        and non-Gemma models."""
        cmds: List[List[str]] = []
        mlx_venv = os.path.expanduser(os.getenv("TARS_MLX_VENV", "~/.venvs/mlx-gemma"))
        mlx_python = os.getenv("TARS_MLX_PYTHON") or os.getenv("TARS_LOCAL_PYTHON")
        if not mlx_python:
            candidate = os.path.join(mlx_venv, "bin", "python3")
            if os.path.exists(candidate):
                mlx_python = candidate
        python_bin = mlx_python or sys.executable
        mlx_server = os.getenv("TARS_MLX_SERVER")
        if not mlx_server:
            candidate = os.path.join(mlx_venv, "bin", "mlx_lm.server")
            if os.path.exists(candidate):
                mlx_server = candidate
        common_args = [
            "--host",  self.host,
            "--port",  str(self.port),
            "--model", self.model,
            "--use-default-chat-template",
            "--chat-template-args",
            os.getenv("TARS_LOCAL_CHAT_TEMPLATE_ARGS", '{"enable_thinking": false}'),
        ]
        shim = os.path.join(self.project_dir, "scripts", "start_mlx_server.py")
        if os.path.isfile(shim):
            cmds.append([python_bin, shim, *common_args])
        if mlx_server:
            cmds.append([mlx_server, *common_args])
        elif shutil.which("mlx_lm.server"):
            cmds.append(["mlx_lm.server", *common_args])
        cmds.append([python_bin, "-m", "mlx_lm", "server", *common_args])
        cmds.append([python_bin, "-m", "mlx_lm.server", *common_args])

        launcher = os.path.join(self.project_dir, "scripts", "start_local_model.sh")
        if os.path.isfile(launcher) and os.access(launcher, os.X_OK):
            cmds.append([launcher, self.host, str(self.port), self.model])

        for cmd in cmds:
            try:
                with self._stderr_lock:
                    self._stderr_tail.clear()
                # Suppress stdout to avoid polluting the conversation. Pump
                # stderr in a daemon thread so the child can never block on a
                # full pipe.
                proc = subprocess.Popen(
                    cmd,
                    cwd=self.project_dir,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                    env={**os.environ, "PYTHONUNBUFFERED": "1"},
                )
                threading.Thread(
                    target=self._stderr_pump,
                    args=(proc,),
                    daemon=True,
                    name="MlxServerStderr",
                ).start()
                return proc
            except FileNotFoundError:
                continue
            except Exception as exc:
                self.log(f"[inner] spawn failed for cmd {cmd[0]}: {exc}")
                continue
        return None

    def _wait_ready(self, deadline_s: float = 120.0) -> bool:
        start = time.time()
        while time.time() - start < deadline_s and not self._stop_event.is_set():
            if self.ready():
                return True
            time.sleep(0.5)
        return False

    def _monitor_loop(self) -> None:
        while not self._stop_event.is_set():
            proc = self._spawn()
            if proc is None:
                self.log("[inner] mlx_lm.server unavailable — inner voice disabled")
                return
            with self._lock:
                self._proc = proc
            self.log(f"[inner] mlx_lm.server starting on {self.host}:{self.port}…")

            became_ready = self._wait_ready()
            if became_ready:
                self._restart_attempts = 0
                self.log(f"[inner] mlx_lm.server ready ({self.model})")
                # Block until the child exits.
                try:
                    proc.wait()
                except Exception:
                    pass
                if self._stop_event.is_set():
                    return
                self.log("[inner] mlx_lm.server exited; will restart")
            else:
                # Couldn't even hit ready state — use the asynchronously
                # captured stderr tail. Never block on proc.stderr here.
                err_tail = self._stderr_snapshot()
                self.log(f"[inner] mlx_lm.server failed to become ready. "
                         f"err: {err_tail[-400:] if err_tail else 'n/a'}")
                try:
                    proc.terminate()
                    proc.wait(timeout=5)
                except Exception:
                    try:
                        proc.kill()
                    except Exception:
                        pass

            with self._lock:
                self._proc = None
            # Backoff before next restart attempt.
            idx   = min(self._restart_attempts, len(self.BACKOFF_SCHEDULE_S) - 1)
            delay = self.BACKOFF_SCHEDULE_S[idx]
            self._restart_attempts += 1
            for _ in range(int(delay * 10)):
                if self._stop_event.is_set():
                    return
                time.sleep(0.1)


# ─── LocalModelClient — HTTP client for mlx_lm.server ───────────────────────

class LocalModelClient:
    """OpenAI-compatible chat client for the local model server.

    Uses the same ``messages=[…]`` shape as MiMoChatClient so the inner-voice
    prompt code can stay shape-agnostic. Falls back to the legacy
    ``/v1/completions`` endpoint if ``/v1/chat/completions`` is unavailable.
    """

    def __init__(self, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT,
                 model: str = DEFAULT_MODEL):
        self.base_url = f"http://{host}:{port}"
        self.model    = model
        self.session  = requests.Session()

    def chat(self, messages: List[Dict], max_tokens: int = 220,
             temperature: float = 0.85,
             timeout_s: float = 30.0) -> Optional[str]:
        # Try chat completions first.
        try:
            resp = self.session.post(
                self.base_url + "/v1/chat/completions",
                json={
                    "model": self.model,
                    "messages": messages,
                    "max_tokens": max_tokens,
                    "temperature": temperature,
                    "stream": False,
                },
                timeout=timeout_s,
            )
            if resp.status_code == 200:
                data = resp.json()
                msg = data["choices"][0].get("message") or {}
                content = msg.get("content") or ""
                if not content and isinstance(msg.get("reasoning"), str):
                    content = msg.get("reasoning") or ""
                return content.strip() if content else None
        except Exception:
            pass
        # Fallback: legacy completions (build a single concatenated prompt).
        try:
            prompt = self._messages_to_text(messages)
            resp = self.session.post(
                self.base_url + "/v1/completions",
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "max_tokens": max_tokens,
                    "temperature": temperature,
                    "stream": False,
                },
                timeout=timeout_s,
            )
            if resp.status_code == 200:
                data = resp.json()
                return data["choices"][0]["text"].strip()
        except Exception:
            pass
        return None

    @staticmethod
    def _messages_to_text(messages: List[Dict]) -> str:
        parts: List[str] = []
        for m in messages:
            role = m.get("role", "user").upper()
            parts.append(f"{role}: {m.get('content', '')}")
        parts.append("ASSISTANT:")
        return "\n\n".join(parts)


# ─── NoveltyFilter — Layer 3 (dedup against last N thoughts) ────────────────
#
# Two backends:
#   - "jaccard"    : token-set Jaccard similarity. Zero deps. Robust. Default.
#   - "embeddings" : MiniLM-L6-v2 cosine via sentence-transformers (or via
#                    bare transformers + mean-pool fallback). Opt-in because
#                    the surrounding torch stack on this Mac currently
#                    segfaults during model load — graceful degradation
#                    matters more than strict spec adherence here.
#
# Selection precedence:
#   constructor arg   >   $TARS_NOVELTY_BACKEND env var   >   "jaccard"
#
# A failed embedding load (exception OR import error) auto-falls-back to
# Jaccard for the rest of the session — we'd rather keep filtering noise
# than disable the whole layer.

# Lightweight English stopword list — dropping these meaningfully improves
# Jaccard signal on short sentences.
_STOPWORDS = frozenset({
    "a","an","the","is","are","was","were","be","been","being","am","of",
    "to","in","on","for","with","at","by","from","into","onto","off",
    "that","this","these","those","it","its","i","you","he","she","they",
    "we","me","him","her","them","us","my","your","his","their","our",
    "or","and","but","not","no","yes","so","do","did","does","have","has",
    "had","will","would","can","could","should","may","might","must",
    "than","then","there","here","just","now","also","very","more","most",
    "as","if","because","while","when","where","why","how","what","which",
    "who","whom","whose",
})

_TOKEN_RE = re.compile(r"[a-z0-9']+")


def _tokenize_for_novelty(text: str) -> "frozenset[str]":
    """Lowercase, strip punct, drop stopwords. Returns a frozen token set."""
    if not text:
        return frozenset()
    toks = _TOKEN_RE.findall(text.lower())
    return frozenset(t for t in toks if t not in _STOPWORDS and len(t) > 1)


class NoveltyFilter:
    """Layer 3 of the quality stack — drops near-duplicate thoughts.

    Default backend is Jaccard token-set similarity. Embedding backend is
    available behind ``TARS_NOVELTY_BACKEND=embeddings`` for environments
    where MiniLM loads cleanly. Both backends share the same buffer-size +
    accept/drop counters so observability stays uniform.
    """

    JACCARD_THRESHOLD = float(os.getenv("TARS_JACCARD_MAX", "0.7"))

    def __init__(self,
                 model_name: str = DEFAULT_EMBED_MODEL,
                 buffer_size: int = NOVELTY_BUFFER_SIZE,
                 cosine_max: float = NOVELTY_COSINE_MAX,
                 jaccard_max: Optional[float] = None,
                 backend: Optional[str] = None,
                 log_fn: Optional[Callable[[str], None]] = None):
        self.model_name  = model_name
        self.buffer_size = buffer_size
        self.cosine_max  = cosine_max
        self.jaccard_max = jaccard_max if jaccard_max is not None else self.JACCARD_THRESHOLD
        self.log         = log_fn or (lambda _m: None)

        chosen = (backend
                  or os.getenv("TARS_NOVELTY_BACKEND", "jaccard")
                 ).strip().lower()
        if chosen not in ("jaccard", "embeddings"):
            chosen = "jaccard"
        self.backend = chosen

        # Buffers — one per backend, each capped at buffer_size.
        self._jaccard_buffer: Deque[frozenset] = deque(maxlen=buffer_size)
        self._embed_buffer:   Deque[Tuple[str, list]] = deque(maxlen=buffer_size)

        self._model    = None
        self._tried    = False
        self._lock     = threading.Lock()
        self.dropped   = 0
        self.accepted  = 0

    # -- public --------------------------------------------------------------

    def is_novel(self, text: str) -> bool:
        if not text or len(text) < 5:
            return False
        if self.backend == "embeddings" and self._ensure_embedding_model():
            try:
                return self._is_novel_embeddings(text)
            except Exception as exc:
                self.log(f"[inner] embed call failed: {exc} → falling back to jaccard")
                self.backend = "jaccard"
        return self._is_novel_jaccard(text)

    # -- jaccard backend (default, dependency-free) --------------------------

    def _is_novel_jaccard(self, text: str) -> bool:
        toks = _tokenize_for_novelty(text)
        if not toks:
            self.accepted += 1
            return True
        for prev in self._jaccard_buffer:
            inter = len(toks & prev)
            if inter == 0:
                continue
            union = len(toks | prev)
            if union == 0:
                continue
            j = inter / union
            if j >= self.jaccard_max:
                self.dropped += 1
                return False
        self._jaccard_buffer.append(toks)
        self.accepted += 1
        return True

    # -- embedding backend (opt-in) ------------------------------------------

    def _ensure_embedding_model(self) -> bool:
        """Lazy-load MiniLM. On any failure (import, download, segfault-prone
        config) auto-disable embedding mode and fall back to Jaccard."""
        if self._model is not None:
            return True
        if self._tried:
            return False
        with self._lock:
            if self._tried:
                return self._model is not None
            self._tried = True
            try:
                from sentence_transformers import SentenceTransformer  # type: ignore
                device = "cpu"
                try:
                    import torch                                   # type: ignore
                    if (getattr(torch.backends, "mps", None)
                            and torch.backends.mps.is_available()):
                        device = "mps"
                except Exception:
                    pass
                self._model = SentenceTransformer(self.model_name, device=device)
                self.log(f"[inner] novelty backend=embeddings "
                         f"({self.model_name} on {device})")
                return True
            except Exception as exc:
                self.log(f"[inner] embedding backend unavailable ({exc}) → "
                         f"using jaccard")
                self.backend = "jaccard"
                return False

    def _is_novel_embeddings(self, text: str) -> bool:
        v = self._model.encode([text], normalize_embeddings=True)[0].tolist()
        for _, prev in self._embed_buffer:
            sim = self._cosine_normalized(v, prev)
            if sim >= self.cosine_max:
                self.dropped += 1
                return False
        self._embed_buffer.append((text, v))
        self.accepted += 1
        return True

    @staticmethod
    def _cosine_normalized(a: List[float], b: List[float]) -> float:
        # Both vectors normalized → cosine = dot product.
        s = 0.0
        for x, y in zip(a, b):
            s += x * y
        return s


# ─── MoodTracker — EMA over last MOOD_WINDOW thoughts ───────────────────────

class MoodTracker:
    """Exponential-moving-average mood over recent thoughts. Implementation
    keeps a fixed-size deque of moods + a per-mood weight, where weights
    decay geometrically so the *current* mood reflects recent thinking.

    Bound: per the plan, the spoken-tone mood can shift at most one step per
    five turns. ``locked_tone()`` enforces that by remembering the last tone
    and only switching when the EMA's argmax has been the new mood for at
    least ``min_switch_turns`` turns.
    """

    DECAY = 0.85
    MIN_SWITCH_TURNS = 5

    def __init__(self):
        self._weights: Dict[str, float] = {m: 0.0 for m in ALLOWED_MOODS}
        self._current_tone = "content"
        self._streak       = 0
        self._lock         = threading.Lock()

    def push(self, mood: str) -> None:
        if mood not in ALLOWED_MOODS:
            return
        with self._lock:
            for k in self._weights:
                self._weights[k] *= self.DECAY
            self._weights[mood] += 1.0

    def push_user_turn(self, hint: str = "focused") -> None:
        """A user turn is a strong signal — bump the EMA's "focused" weight
        meaningfully so mood observably shifts after speech."""
        with self._lock:
            for k in self._weights:
                self._weights[k] *= self.DECAY
            self._weights[hint if hint in ALLOWED_MOODS else "focused"] += 2.0

    def current_mood(self) -> str:
        with self._lock:
            return max(self._weights, key=self._weights.get)

    def locked_tone(self) -> str:
        """Return the human-readable tone string suitable for `[Tone: …]`,
        applying the min-switch-turns guard so the spoken voice doesn't
        thrash on every thought."""
        with self._lock:
            argmax = max(self._weights, key=self._weights.get)
            if argmax == self._current_tone:
                self._streak += 1
            else:
                # New leader — only switch if it's held for MIN_SWITCH_TURNS
                if self._streak >= self.MIN_SWITCH_TURNS:
                    self._current_tone = argmax
                    self._streak       = 1
                else:
                    self._streak += 1
            return MOOD_TONE_MAP.get(self._current_tone, "Calm, settled")


# ─── BatteryProbe — `pmset -g batt` parser, lightweight ─────────────────────

def battery_state() -> Tuple[Optional[int], bool]:
    """Returns (percent, on_ac). On non-macOS or when pmset is missing,
    returns (None, True) — treated as "not battery-constrained"."""
    if not shutil.which("pmset"):
        return (None, True)
    try:
        out = subprocess.check_output(
            ["pmset", "-g", "batt"], timeout=2.0
        ).decode("utf-8", "replace")
    except Exception:
        return (None, True)
    pct: Optional[int] = None
    on_ac = "AC Power" in out
    m = re.search(r"(\d+)%", out)
    if m:
        try:
            pct = int(m.group(1))
        except Exception:
            pct = None
    return (pct, on_ac)


# ─── InnerVoice — the thinking loop (background thread) ─────────────────────

class InnerVoice:
    """Continuous thinking loop. Runs on its own daemon thread. Reads recent
    transcript + mood + last few thoughts, asks the local model for ONE
    thought, applies four quality filters, persists survivors to
    ``tars_thoughts.jsonl``, and forwards specific thought-kinds to action
    triggers (wishes → DesireEngine; fragments → next-tick re-prompt;
    critiques → flagged for committee in Phase 6).
    """

    def __init__(
        self,
        project_dir: str,
        log_fn: Callable[[str], None],
        # Callables / objects supplied by the orchestrator
        recent_transcript: Callable[[int], List[Dict]],   # (n_turns) → messages
        active_goals_top:  Optional[Callable[[int], List[str]]] = None,
        desire_engine     = None,                          # DesireEngine | None
        host: str  = DEFAULT_HOST,
        port: int  = DEFAULT_PORT,
        model: str = DEFAULT_MODEL,
    ):
        self.project_dir = project_dir
        self.log         = log_fn
        self.recent_transcript = recent_transcript
        self.active_goals_top  = active_goals_top or (lambda _n: [])
        self.desire_engine     = desire_engine
        self.disabled          = os.getenv("TARS_DISABLE_INNER_VOICE", "0") == "1"

        self.server  = LocalModelServer(project_dir, log_fn, host, port, model)
        self.client  = LocalModelClient(host, port, model)
        self.store   = ThoughtStore(project_dir, log_fn)
        self.mood    = MoodTracker()
        self.novelty = NoveltyFilter(log_fn=log_fn)
        # Phase 1 R3: cognitive substrate (working mem, concerns, user state,
        # appraisal emotion, continuity buffer). Inner voice consumes its
        # snapshot in _build_prompt and updates it in _tick_once.
        try:
            from tars_mind import Mind
            self.mind = Mind(project_dir, log_fn=log_fn)
        except Exception as exc:
            self.log(f"[inner] Mind init failed: {exc}")
            self.mind = None

        # Throttling / activity state
        self._stop_event           = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._last_user_turn_end   = 0.0
        self._last_user_speech_at  = 0.0
        self._is_user_busy         = lambda: False
        self._burst_remaining      = 0
        self._daily_count          = 0
        self._daily_window_start   = datetime.now()
        self._pending_fragment: Optional[ThoughtRecord] = None
        self._forced_contexts: Deque[Dict[str, Any]] = deque(maxlen=8)
        self._forced_context_lock = threading.Lock()

        # Thought→action callbacks (set by orchestrator)
        self.on_wish_thought:     Optional[Callable[[ThoughtRecord], None]] = None
        self.on_critique_thought: Optional[Callable[[ThoughtRecord], None]] = None
        # Inner-loop integration: every persisted thought also gets piped to
        # the episodic memory store via this hook so retrieval can
        # surface a relevant thought when the user speaks.
        self.on_thought_persisted: Optional[Callable[[ThoughtRecord], None]] = None

    # -- lifecycle ------------------------------------------------------------

    def set_user_busy_predicate(self, fn: Callable[[], bool]) -> None:
        self._is_user_busy = fn

    def start(self) -> None:
        if self.disabled:
            self.log("[inner] InnerVoice disabled — skipping")
            return
        self.server.start()
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._loop, daemon=True, name="TarsInnerVoice"
        )
        self._thread.start()
        self.log("[inner] InnerVoice started")

    def stop(self) -> None:
        self._stop_event.set()
        try:
            self.server.stop()
        except Exception:
            pass

    # -- API used by orchestrator --------------------------------------------

    def notify_user_turn_started(self) -> None:
        """User just started speaking. Pause generation."""
        self._last_user_speech_at = time.time()

    def notify_user_turn_ended(self, mood_hint: str = "focused") -> None:
        """User just finished a turn. Burst (3 thoughts) and shift mood."""
        self._last_user_turn_end = time.time()
        self.mood.push_user_turn(mood_hint)
        self._burst_remaining = 3

    def force_thought_now(
        self,
        reason: str = "manual",
        workspace_frame: Optional[Dict[str, Any]] = None,
        event: Optional[Dict[str, Any]] = None,
        priority: float = 0.7,
    ) -> None:
        """Fire one thought immediately off the main loop.

        Phase 2.5E: forced thoughts may carry event/workspace context so the
        local model reflects on the actual globally selected item, not just
        the generic recent transcript. Runs on a daemon thread so callers do
        not block on the LLM round-trip.
        """
        if self.disabled or not self.server.ready():
            return
        ctx = {
            "reason": reason,
            "workspace_frame": workspace_frame or {},
            "event": event or {},
            "priority": max(0.0, min(1.0, float(priority))),
        }
        with self._forced_context_lock:
            self._forced_contexts.append(ctx)
        def _job():
            try:
                self._tick_once()
            except Exception as exc:
                self.log(f"[inner] forced tick error: {exc}")
        threading.Thread(target=_job, daemon=True, name="InnerVoiceForced").start()

    def current_tone_hint(self) -> str:
        """Return a string suitable for `[Tone: …]` based on current mood."""
        return self.mood.locked_tone()

    def recent_thoughts_for_prompt(self, n: int = 3,
                                   within: timedelta = timedelta(hours=1)
                                   ) -> List[Dict]:
        return self.store.top_by_salience(n, within)

    def recent_thoughts(self, n: int = 10,
                        within: timedelta = timedelta(hours=1)) -> List[Dict]:
        """Phase 2.5 workspace API: recent private thoughts as candidate data."""
        return self.store.top_by_salience(n, within)

    def stats(self) -> Dict:
        return {
            "daily_count": self._daily_count,
            "novelty_dropped": self.novelty.dropped,
            "novelty_accepted": self.novelty.accepted,
            "current_mood": self.mood.current_mood(),
            "server_ready": self.server.ready(),
            "burst_remaining": self._burst_remaining,
            "pending_fragment_id": self._pending_fragment.id if self._pending_fragment else None,
        }

    # -- main loop -----------------------------------------------------------

    def _loop(self) -> None:
        # Give the local model a moment to come up before the first tick.
        for _ in range(20):
            if self._stop_event.is_set():
                return
            if self.server.ready():
                break
            time.sleep(1.0)

        while not self._stop_event.is_set():
            try:
                interval = self._next_interval()
                if interval <= 0:
                    # paused
                    self._sleep_interruptible(2.0)
                    continue
                self._sleep_interruptible(interval)
                if self._stop_event.is_set():
                    return
                if not self._should_think_now():
                    continue
                self._maybe_reset_daily_window()
                self._tick_once()
            except Exception as exc:
                self.log(f"[inner] tick error: {exc}")
                self._sleep_interruptible(5.0)

    def _maybe_reset_daily_window(self) -> None:
        if datetime.now() - self._daily_window_start > timedelta(hours=24):
            self._daily_count        = 0
            self._daily_window_start = datetime.now()

    def _next_interval(self) -> float:
        """Compute the next sleep duration based on PLAN.md throttling rules."""
        # Battery gate (pause)
        pct, on_ac = battery_state()
        if pct is not None and pct < 20 and not on_ac:
            return -1.0

        # User actively speaking gate (pause)
        if time.time() - self._last_user_speech_at < USER_SPEAKING_QUIET_S:
            return -1.0

        # Burst: 3 thoughts after a user turn, spaced by BURST_GAP_S.
        if self._burst_remaining > 0:
            return BURST_GAP_S

        # Daily cap → slow down.
        if self._daily_count > DAILY_THOUGHT_CAP:
            return float(DAILY_CAP_INTERVAL_S)

        # Idle (>10 min since last user turn)
        if (time.time() - self._last_user_turn_end) > IDLE_THRESHOLD_S \
                and self._last_user_turn_end > 0:
            return float(IDLE_INTERVAL_S)

        return float(NORMAL_INTERVAL_S)

    def _should_think_now(self) -> bool:
        if self.disabled:
            return False
        if not self.server.ready():
            return False
        # Do not pause during TTS playback or turn
        # processing. Inner voice runs on a separate mlx_lm.server
        # process; there is no expected resource contention with the main loop.
        return True

    def _sleep_interruptible(self, seconds: float) -> None:
        end = time.time() + max(0.0, seconds)
        while time.time() < end and not self._stop_event.is_set():
            time.sleep(min(0.2, end - time.time()))

    # -- single tick: build prompt → call → parse → filter → persist -----

    def _tick_once(self) -> None:
        forced_context = None
        with self._forced_context_lock:
            if self._forced_contexts:
                forced_context = self._forced_contexts.popleft()
        prompt   = self._build_prompt(forced_context=forced_context)
        raw      = self.client.chat(prompt, max_tokens=220, temperature=0.85,
                                    timeout_s=30.0)
        if not raw:
            return

        content, kind, mood, salience = self._parse_response(raw)
        if not content:
            return

        # Layer 2: self-reported salience gate
        if salience < SALIENCE_THRESHOLD and kind != "fragment":
            return

        # Layer 3: novelty filter
        if not self.novelty.is_novel(content):
            return

        # Phase 2.5R-B: Thought Quality Gate
        # Prevent broken loops and redundant nonsense from poisoning memory
        try:
            from tars_thought_gate import ThoughtQualityGate
            gate = ThoughtQualityGate()
            # Fetch recent dict-style thoughts for similarity checking
            recent_dicts = self.recent_thoughts(n=10)
            thought_dict = {
                "content": content,
                "kind": kind,
                "salience": salience,
                "mood": mood
            }
            ok, reason = gate.validate(thought_dict, recent_dicts)
            if not ok:
                self.log(f"[inner-gate] Rejected thought: {reason} - '{content[:40]}...'")
                # Optionally write to tars_rejected_thoughts.jsonl here
                with open(os.path.join(self.project_dir, "tars_rejected_thoughts.jsonl"), "a") as f:
                    import json
                    thought_dict["rejection_reason"] = reason
                    f.write(json.dumps(thought_dict) + "\n")
                return
        except Exception as e:
            self.log(f"[inner-gate] Quality gate failed, falling back to novelty: {e}")

        thought = ThoughtRecord.new(
            content   = content,
            kind      = kind,
            mood      = mood,
            salience  = salience,
            tags      = ([f"forced:{forced_context.get('reason', 'manual')}"]
                         if forced_context else []),
            parent_id = self._pending_fragment.id if self._pending_fragment else None,
        )
        self.store.append(thought)
        self.mood.push(mood)
        self._daily_count += 1
        if self._burst_remaining > 0:
            self._burst_remaining -= 1

        # Persist into episodic memory too, so the LLM
        # can retrieve recent thoughts when the user asks "what were you
        # thinking about?" Decoupled via callback so InnerVoice doesn't
        # need to know about Memory's existence.
        if self.on_thought_persisted is not None:
            try: self.on_thought_persisted(thought)
            except Exception as exc:
                self.log(f"[inner] on_thought_persisted error: {exc}")

        # Phase 1 R3: feed the cognitive substrate. Updates working memory
        # + continuity buffer with this thought. (User-state and emotion
        # appraisal are updated by orchestrator-level hooks because they
        # need an LLM call.)
        if self.mind is not None:
            try: self.mind.after_thought(thought.to_dict())
            except Exception as exc:
                self.log(f"[inner] mind.after_thought error: {exc}")

        # Thought-kind action triggers (PLAN.md §"Thoughts → Proactive Behavior")
        self._trigger_actions(thought)

    # -- prompt building -------------------------------------------------

    def _build_prompt(self, forced_context: Optional[Dict[str, Any]] = None) -> List[Dict]:
        # Phase 1 R3: prompt is built from the Mind snapshot — working
        # memory (focus), standing concerns (drives), user state (theory
        # of mind), emotion (appraisal), continuity buffer (causal chain
        # to last K thoughts). The independent-tick model is gone:
        # every thought now follows from the previous, attends to what's
        # in focus, addresses an active concern when relevant.
        try:
            recent_msgs = self.recent_transcript(6) or []
        except Exception:
            recent_msgs = []
        recent_text = "\n".join(
            f"{m.get('role','?').upper()}: {str(m.get('content',''))[:240]}"
            for m in recent_msgs
            if m.get("role") in ("user", "assistant") and m.get("content")
        ) or "(no recent transcript)"

        # Pull the cognitive snapshot. Falls back to old shape if Mind is
        # missing for some reason.
        snap = self.mind.snapshot_for_prompt() if self.mind else {}
        working   = snap.get("working", []) or []
        concerns  = snap.get("concerns", []) or []
        user_st   = snap.get("user", {}) or {}
        emotion   = snap.get("emotion", {}) or {}
        tail      = snap.get("tail", []) or []

        # ---- format each section ------------------------------------------
        wm_lines = ("\n".join(
            f"  - {it['text'][:160]}  (w={float(it.get('weight',0)):.2f})"
            for it in working[:5]
        )) or "  (nothing in focus)"

        c_lines = ("\n".join(
            f"  • {c['text'][:200]}  (priority={float(c.get('priority',0)):.2f})"
            for c in concerns
        )) or "  (no open concerns)"

        u_lines = (
            f"  mood: {user_st.get('mood','?')}, energy: {user_st.get('energy','?')}, "
            f"rapport: {user_st.get('rapport','?')}\n"
            f"  focus: {user_st.get('focus','?') or '?'}\n"
            f"  intent: {user_st.get('intent','?') or '?'}\n"
            f"  note: {user_st.get('note','') or '(none)'}"
        )

        e_line = (
            f"  feeling {emotion.get('tag','neutral')!r} "
            f"(valence={float(emotion.get('valence',0)):+.2f}, "
            f"arousal={float(emotion.get('arousal',0)):.2f})"
        )
        if emotion.get("reason"):
            e_line += f"\n  because: {emotion['reason'][:200]}"

        tail_lines = ("\n".join(
            f"  > [{t.get('kind','?')}] {t.get('content','')[:200]}"
            for t in tail
        )) or "  (no prior thought to continue from)"

        seed_line = ""
        if self._pending_fragment:
            seed_line = (
                f"\nIncomplete thought you may continue (or set aside):\n"
                f"  > {self._pending_fragment.content}\n"
            )
            self._pending_fragment = None

        forced_lines = ""
        if forced_context:
            frame = forced_context.get("workspace_frame") or {}
            winner = (frame.get("winner") if isinstance(frame, dict) else None) or {}
            event = forced_context.get("event") or {}
            appraisal = {}
            if isinstance(event, dict):
                raw = event.get("raw") if isinstance(event.get("raw"), dict) else {}
                appraisal = raw.get("appraisal") if isinstance(raw, dict) else {}
            forced_lines = (
                "\n=== Event-triggered context ===\n"
                f"reason: {forced_context.get('reason', 'event')}\n"
                f"priority: {float(forced_context.get('priority', 0.0)):.2f}\n"
            )
            if winner:
                forced_lines += (
                    "current workspace winner:\n"
                    f"  source: {winner.get('source', '?')}\n"
                    f"  action: {winner.get('proposed_action', '?')}\n"
                    f"  content: {str(winner.get('content', ''))[:500]}\n"
                )
            if appraisal:
                forced_lines += (
                    "current appraisal:\n"
                    f"  valence={float(appraisal.get('valence', 0.0)):+.2f}, "
                    f"arousal={float(appraisal.get('arousal', 0.0)):.2f}, "
                    f"novelty={float(appraisal.get('novelty', 0.0)):.2f}, "
                    f"uncertainty={float(appraisal.get('uncertainty', 0.0)):.2f}, "
                    f"goal_tension={float(appraisal.get('goal_tension', 0.0)):.2f}\n"
                )

        sys_prompt = (
            "You are the inner voice of TARS — a self-evolving voice "
            "assistant. No user is listening; you think privately, briefly, "
            "and honestly.\n\n"
            "Your thoughts must form a continuous internal monologue: "
            "each new thought CAUSALLY follows from the last one in the "
            "tail (continue it, pivot off it, or react to it). You have a "
            "small set of standing concerns; if a concern relates to what "
            "just happened, address it. You hold a few items in working "
            "memory; weave them in when relevant. Your emotional state is "
            "real — let it color the thought (not by labels, by texture).\n\n"
            + GOOD_THOUGHT_EXAMPLES
            + "\n\nRules:\n"
              "1. Output ONE short thought (1-3 sentences max).\n"
              "2. Then EXACTLY one final line of meta:\n"
              "     KIND=<reflection|observation|wish|critique|fragment>  "
              "MOOD=<curious|bored|amused|focused|uneasy|content>  "
              "SALIENCE=<0.0-1.0>\n"
              "3. Do NOT echo the transcript or repeat a previous thought.\n"
              "4. If you have nothing meaningful, KIND=fragment with low salience.\n"
        )

        user_prompt = (
            f"=== Continuity (your last few thoughts — continue or pivot) ===\n"
            f"{tail_lines}\n\n"
            f"=== Standing concerns (open, weighted) ===\n{c_lines}\n\n"
            f"=== Working memory (what you're holding) ===\n{wm_lines}\n\n"
            f"=== Your read on the user right now ===\n{u_lines}\n\n"
            f"=== Your emotional state ===\n{e_line}\n\n"
            f"=== Recent transcript (context) ===\n{recent_text}\n"
            f"{forced_lines}"
            f"{seed_line}"
            "\nNow think one private thought."
        )

        return [
            {"role": "system",  "content": sys_prompt},
            {"role": "user",    "content": user_prompt},
        ]

    # -- response parsing -------------------------------------------------

    _META_LINE_RE = re.compile(
        r"KIND\s*[:=]\s*(?P<k>\w+)\b[\s,;|]+"
        r"MOOD\s*[:=]\s*(?P<m>\w+)\b[\s,;|]+"
        r"SALIENCE\s*[:=]\s*(?P<s>[0-9.]+)",
        re.IGNORECASE,
    )
    _THINK_BLOCK_RE = re.compile(r"<think\b[^>]*>.*?</think>", re.IGNORECASE | re.DOTALL)
    _CHAT_ARTIFACT_RE = re.compile(
        r"</?(?:bos|eos|start_of_turn|end_of_turn)\b[^>]*>",
        re.IGNORECASE,
    )

    @classmethod
    def _parse_response(cls, raw: str) -> Tuple[str, str, str, float]:
        """Returns (content, kind, mood, salience). On parse failure, returns
        ("","reflection","content",0.0) so the caller can drop the result."""
        if not raw:
            return ("", "reflection", "content", 0.0)
        text = cls._normalise_model_text(raw)
        m = cls._META_LINE_RE.search(text)
        if m:
            before = text[:m.start()].strip()
            after = text[m.end():].strip()
            content = before if before else after
            kind    = m.group("k").strip().lower()
            mood    = m.group("m").strip().lower()
            try:
                salience = max(0.0, min(1.0, float(m.group("s"))))
            except Exception:
                salience = 0.0
        else:
            # No meta line — treat as low-salience fragment so it gets dropped
            # by the salience gate (unless it's a fragment continuation).
            content  = text
            kind     = "fragment"
            mood     = "content"
            salience = 0.3

        # Strip any model echo of the meta line if it appeared in content.
        content = cls._META_LINE_RE.sub("", content).strip()
        content = cls._normalise_model_text(content)
        # Some local models emit role labels — strip the leading "ASSISTANT:"
        content = re.sub(r"^(?:ASSISTANT|TARS)\s*:\s*", "", content,
                         flags=re.IGNORECASE)
        content = re.sub(r"^(?:THOUGHT|PRIVATE THOUGHT)\s*:\s*", "", content,
                         flags=re.IGNORECASE)
        # Normalise normalize whitespace.
        content = re.sub(r"\s+", " ", content).strip()
        if len(content) > 600:
            content = content[:600].rsplit(" ", 1)[0] + "…"
        return (content, kind, mood, salience)

    @classmethod
    def _normalise_model_text(cls, raw: str) -> str:
        """Remove Gemma/MLX wrapper tokens without changing the thought text."""
        text = str(raw or "").strip()
        if not text:
            return ""
        text = cls._THINK_BLOCK_RE.sub("", text)
        text = cls._CHAT_ARTIFACT_RE.sub("", text)
        text = re.sub(r"```(?:text|markdown|md)?\s*", "", text, flags=re.IGNORECASE)
        text = text.replace("```", "")
        text = re.sub(r"(?im)^\s*(?:model|assistant)\s*$\n?", "", text)
        text = re.sub(r"^\s*(?:model|assistant)\s*:\s*", "", text, flags=re.IGNORECASE)
        return text.strip()

    # -- thought → action --------------------------------------------------

    def _trigger_actions(self, thought: ThoughtRecord) -> None:
        try:
            if thought.kind == "wish" and thought.salience >= WISH_DESIRE_THRESHOLD \
                    and self.desire_engine is not None:
                desire_id = self.desire_engine.log_desire(
                    trigger_phrase=f"[inner-wish] {thought.content}",
                    capability_needed=thought.content,
                    priority="high",
                )
                thought.led_to = desire_id
                # Re-write the persisted line — safest: append a follow-up record
                # (we don't rewrite JSONL in place).
                follow = ThoughtRecord.new(
                    content=f"(meta: wish '{thought.id}' queued as desire {desire_id})",
                    kind="reflection",
                    mood="focused",
                    salience=0.55,
                    tags=["meta", "desire_queued"],
                    parent_id=thought.id,
                )
                follow.led_to = desire_id
                self.store.append(follow)
                if self.on_wish_thought:
                    try: self.on_wish_thought(thought)
                    except Exception: pass

            elif thought.kind == "fragment":
                # Fragment seeds the next tick's prompt for chained thoughts.
                self._pending_fragment = thought

            elif thought.kind == "critique" and thought.salience >= CRITIQUE_FLAG_THRESHOLD:
                # Phase 6 (Inner Committee) is the right gate for soul-edits.
                # For now, just emit a sidecar log entry and call the optional hook.
                follow = ThoughtRecord.new(
                    content=f"(meta: critique '{thought.id}' flagged for committee)",
                    kind="reflection",
                    mood="focused",
                    salience=0.5,
                    tags=["meta", "committee_pending"],
                    parent_id=thought.id,
                )
                self.store.append(follow)
                if self.on_critique_thought:
                    try: self.on_critique_thought(thought)
                    except Exception: pass

            # observation / reflection — nothing extra; they live in the store
            # and feed the next user-turn prompt via recent_thoughts_for_prompt.
        except Exception as exc:
            self.log(f"[inner] action-trigger error: {exc}")


# ─── Self-test ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # Lightweight offline self-test — no mlx_lm.server required.
    import tempfile

    def L(msg):
        print(msg)

    with tempfile.TemporaryDirectory() as d:
        store = ThoughtStore(d, L)
        t = ThoughtRecord.new("self-test thought", "reflection", "content", 0.6)
        store.append(t)
        assert len(store.tail(5)) == 1
        assert store.top_by_salience(5, timedelta(hours=1))[0]["id"] == t.id

        # MoodTracker basic behavior
        tr = MoodTracker()
        for _ in range(6):
            tr.push("focused")
        assert tr.current_mood() == "focused"
        # Switch threshold respected:
        for _ in range(2):
            tr.push("amused")
        assert tr.current_mood() in ("focused", "amused")

        # Response parser robustness
        content, k, m, s = InnerVoice._parse_response(
            "Some thought.\nKIND=reflection  MOOD=focused  SALIENCE=0.71"
        )
        assert content.startswith("Some thought")
        assert k == "reflection" and m == "focused" and abs(s - 0.71) < 0.001
        content, k, m, s = InnerVoice._parse_response(
            "<start_of_turn>model\n"
            "<think>I should follow the format.</think>\n"
            "```text\n"
            "Thought: I should verify Gemma on the real inner-voice prompt, not just trust the route.\n"
            "KIND: critique | MOOD: focused | SALIENCE: 0.82\n"
            "```\n"
            "<end_of_turn>"
        )
        assert content == "I should verify Gemma on the real inner-voice prompt, not just trust the route."
        assert k == "critique" and m == "focused" and abs(s - 0.82) < 0.001
        content, k, m, s = InnerVoice._parse_response(
            "KIND=observation  MOOD=content  SALIENCE=0.41\n"
            "The room is quiet; this is probably idle background thought, not a new concern."
        )
        assert content.startswith("The room is quiet")
        assert k == "observation" and m == "content" and abs(s - 0.41) < 0.001

        # Battery probe doesn't crash
        battery_state()

        print("inner_voice self-test OK")
