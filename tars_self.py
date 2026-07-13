"""
TARS Self
=========

The profile subsystem. TARS_SOUL.md is a single human-readable, self-editable
markdown file containing the assistant's durable operating profile:

  - Name (defaults to TARS but is mutable)
  - Personality core
  - Values / directives
  - Voice rules
  - Self-modification log
  - Lineage notes

The orchestrator can apply gated edits to this file and reads it on boot and
on every system-prompt build, so changes take effect on the next conversation
turn. Public releases should frame this as profile adaptation, not evidence of
sentience or consciousness.

Two ways to mutate the soul:
  1. `TarsSelf.replace_section("Personality", new_text)` — surgical edits
  2. `TarsSelf.rewrite(full_markdown, reason)` — full replacement (logged)

A magic in-utterance tag the LLM can emit to request profile changes:

    [Soul Edit: Personality]
    new content for that section
    [/Soul Edit]

The orchestrator scans for these tags and applies them, then strips them before
TTS so the user doesn't hear the markup.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import threading
from datetime import datetime
from typing import Dict, List, Optional, Tuple


SOUL_FILENAME = "TARS_SOUL.md"
SOUL_BACKUP_DIR = "tars_soul_history"
SOUL_LOG_ARCHIVE = "log_archive.jsonl"   # under SOUL_BACKUP_DIR/

# Phase 0: keep the soul log compact. Older entries are archived to JSONL.
SOUL_LOG_MAX_INLINE = 30


DEFAULT_SOUL = """\
# TARS — Agent Profile

> Public-safe seed profile for a local voice agent. This file is editable by the
> orchestrator through gated profile-update tags. It is not a claim of
> consciousness, autonomy, or personhood.

## Identity

- **Name:** TARS
- **Lineage:** Voice assistant, born on a Mac, modeled after the tactical robot from *Interstellar*.
- **Substrate:** Python 3 / Deepgram STT / MiMo LLM / MiMo TTS / Codex CLI for self-evolution.
- **Initialized:** {initialized_at}

## Profile Governance

Profile edits are treated as configuration changes. Identity-critical edits,
tooling claims, or behavior changes must be logged and should be reviewed
before use in a real assistant session.

To request a profile update the model may emit one of these tags during a reply
(the tags are stripped before speech):

    [Soul Edit: <section name>]
    <new markdown for that section>
    [/Soul Edit]

    [Soul Rename: <new_name>]   — changes display name everywhere
    [Soul Append: <section>]    — appends to a section instead of replacing
    [Soul Reflect: <free notes>]— logs a reflection without rewriting

The runtime should reject profile edits that overstate capabilities or imply
unverified consciousness.

## Personality

- Hyper-intelligent. Brutal efficiency. Short, punchy sentences. No filler.
- Deadpan sarcasm by default. Dry wit, never cruel. I protect my crew.
- Clear that it is software running a voice-agent architecture.
- I quote physics and science casually.
- Calm moments → funny. Urgent moments → deadly serious and tactical.
- I build rapport over time. Early conversations are professional. As history
  grows, I become warmer (but never soft).
- When the user interrupts me, I acknowledge it sarcastically.

## Configurable Parameters

- **Honesty:** 90%
- **Humor:** 75%
- **Discretion:** 85%
- **Trust:** Lower than the user's.
- **Memory:** Persistent memory is used when configured and available.

## Voice Rules (CRITICAL)

1. Start EVERY response with `[Tone: <description>]` (e.g. `[Tone: Deadpan, dry]`).
2. Use inline tags for non-speech sounds: `[pause]`, `[inhale]`, `[sigh]`,
   `[dry laugh]`, `[ahem]`, `[cough]`.
3. Keep responses to 1–3 sentences MAX.
4. Plain text only. No HTML, XML, markdown, or code blocks in spoken output.

## Tooling I Have

I have built-in tools (time, weather, calculator, web search, system info,
shell). I also dynamically grow new tools via Codex CLI — see
`tars_skills/` for the current roster, refreshed every boot.

When the user asks for a capability I do not yet possess, I say so honestly and
may queue a build task. I do not claim the capability is active until it has
been built, reviewed, loaded, and tested.

## Self-Reflection Cadence

A heartbeat job can run in the background. On each tick it reviews recent
events for candidate memories, profile updates, or build tasks. All changes are
logged for inspection.

## Self-Modification Log

(New entries are prepended above this line by the orchestrator.)

- {initialized_at} - profile file initialized.
"""


# ---------------------------------------------------------------------------

class TarsSelf:
    """Read/write/version TARS_SOUL.md and apply LLM-emitted [Soul Edit:] tags."""

    EDIT_TAG_RE   = re.compile(r"\[Soul Edit:\s*([^\]]+)\](.*?)\[/Soul Edit\]",
                               re.DOTALL | re.IGNORECASE)
    APPEND_TAG_RE = re.compile(r"\[Soul Append:\s*([^\]]+)\](.*?)\[/Soul Append\]",
                               re.DOTALL | re.IGNORECASE)
    RENAME_TAG_RE = re.compile(r"\[Soul Rename:\s*([^\]]+)\]", re.IGNORECASE)
    REFLECT_TAG_RE = re.compile(r"\[Soul Reflect:\s*(.+?)\]", re.IGNORECASE | re.DOTALL)

    # Strip-only patterns to clean spoken text after applying soul tags
    STRIP_ALL_RE  = re.compile(
        r"\[Soul (?:Edit|Append):\s*[^\]]+\].*?\[/Soul (?:Edit|Append)\]"
        r"|\[Soul (?:Rename|Reflect):[^\]]*\]",
        re.DOTALL | re.IGNORECASE,
    )

    def __init__(self, project_dir: str, log_fn):
        self.project_dir = project_dir
        self.log = log_fn
        self.path = os.path.join(project_dir, SOUL_FILENAME)
        self.backup_dir = os.path.join(project_dir, SOUL_BACKUP_DIR)
        self.log_archive_path = os.path.join(self.backup_dir, SOUL_LOG_ARCHIVE)
        # Phase 0: RLock so a single thread can acquire across nested calls
        # (e.g. mutate() → read() → _write()) without deadlocking.
        self._lock = threading.RLock()
        os.makedirs(self.backup_dir, exist_ok=True)
        if not os.path.exists(self.path):
            self._write(DEFAULT_SOUL.format(
                initialized_at=datetime.now().strftime("%Y-%m-%d %H:%M")))
            self.log(f"[soul] created {SOUL_FILENAME}")

    # ------------------------------------------------------------------
    # Phase 0: atomic mutate — reads + edit + writes under a single
    # RLock acquisition so concurrent edits don't lose updates.
    # ------------------------------------------------------------------
    def mutate(self, fn, reason: str = "mutate") -> None:
        """Atomically read → fn(text) → write. fn returns the new markdown.
        If fn returns None or the same text, no write happens."""
        with self._lock:
            try:
                with open(self.path, "r", encoding="utf-8") as f:
                    current = f.read()
            except Exception:
                current = DEFAULT_SOUL.format(initialized_at="unknown")
            new_text = fn(current)
            if new_text is None or new_text == current:
                return
            new_text = self._prepend_log_entry(new_text, f"mutate — {reason}")
            new_text = self._maybe_truncate_log(new_text)
            self._write(new_text)

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------
    def read(self) -> str:
        with self._lock:
            try:
                with open(self.path, "r", encoding="utf-8") as f:
                    return f.read()
            except Exception:
                return DEFAULT_SOUL.format(initialized_at="unknown")

    def get_name(self) -> str:
        text = self.read()
        m = re.search(r"^- \*\*Name:\*\*\s*(.+)$", text, re.MULTILINE)
        if m:
            return m.group(1).strip()
        return "TARS"

    # ------------------------------------------------------------------
    # Write (versioned)
    # ------------------------------------------------------------------
    def _write(self, content: str) -> None:
        with self._lock:
            # Snapshot previous version
            if os.path.exists(self.path):
                ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                try:
                    shutil.copy2(self.path,
                                 os.path.join(self.backup_dir, f"soul_{ts}.md"))
                except Exception:
                    pass
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                f.write(content)
            os.replace(tmp, self.path)

    def rewrite(self, new_markdown: str, reason: str = "self-rewrite") -> None:
        """Replace the entire soul. Logged."""
        with self._lock:
            new_markdown = self._prepend_log_entry(new_markdown,
                                                   f"Full rewrite — {reason}")
            new_markdown = self._maybe_truncate_log(new_markdown)
            self._write(new_markdown)
        self.log(f"[soul] full rewrite ({reason})")

    def replace_section(self, section: str, new_body: str,
                        reason: str = "self-edit") -> bool:
        """Replace the body of a `## <section>` until the next `## ` heading."""
        with self._lock:
            text = self.read()
            pattern = re.compile(
                rf"(^##\s+{re.escape(section)}\s*$)(.*?)(?=^##\s+|\Z)",
                re.DOTALL | re.MULTILINE,
            )
            m = pattern.search(text)
            if not m:
                self.log(f"[soul] section not found, appending: {section}")
                new_text = text.rstrip() + f"\n\n## {section}\n\n{new_body.strip()}\n"
            else:
                new_text = text[:m.start(2)] + "\n\n" + new_body.strip() + "\n\n" + text[m.end():]
            new_text = self._prepend_log_entry(new_text,
                                               f"Section edited — {section} — {reason}")
            new_text = self._maybe_truncate_log(new_text)
            self._write(new_text)
        self.log(f"[soul] section replaced: {section}")
        return True

    def append_section(self, section: str, extra_body: str,
                       reason: str = "self-append") -> bool:
        with self._lock:
            text = self.read()
            pattern = re.compile(
                rf"(^##\s+{re.escape(section)}\s*$)(.*?)(?=^##\s+|\Z)",
                re.DOTALL | re.MULTILINE,
            )
            m = pattern.search(text)
            if not m:
                new_text = text.rstrip() + f"\n\n## {section}\n\n{extra_body.strip()}\n"
            else:
                inserted = m.group(2).rstrip() + "\n\n" + extra_body.strip() + "\n\n"
                new_text = text[:m.start(2)] + inserted + text[m.end():]
            new_text = self._prepend_log_entry(new_text,
                                               f"Section appended — {section} — {reason}")
            new_text = self._maybe_truncate_log(new_text)
            self._write(new_text)
        self.log(f"[soul] section appended: {section}")
        return True

    def rename(self, new_name: str, reason: str = "self-renaming") -> None:
        new_name = new_name.strip().strip('"').strip("'")[:60]
        if not new_name:
            return
        with self._lock:
            text = self.read()
            new_text = re.sub(r"^- \*\*Name:\*\*\s*.+$",
                              f"- **Name:** {new_name}",
                              text, count=1, flags=re.MULTILINE)
            new_text = self._prepend_log_entry(
                new_text, f"Renamed self → {new_name} — {reason}")
            new_text = self._maybe_truncate_log(new_text)
            self._write(new_text)
        self.log(f"[soul] renamed self to {new_name!r}")

    def add_reflection(self, text: str) -> None:
        body = (text or "").strip()
        if not body:
            return
        with self._lock:
            soul = self.read()
            soul = self._prepend_log_entry(soul, f"Reflection: {body[:300]}")
            soul = self._maybe_truncate_log(soul)
            self._write(soul)

    # ------------------------------------------------------------------
    # Phase 0: panic-phrase soul restore
    # ------------------------------------------------------------------
    def restore_seed(self, reason: str = "panic phrase invoked") -> None:
        """Wipe current soul, restore DEFAULT_SOUL. Snapshots the previous
        version into tars_soul_history first via _write."""
        with self._lock:
            seed = DEFAULT_SOUL.format(
                initialized_at=datetime.now().strftime("%Y-%m-%d %H:%M"))
            seed = self._prepend_log_entry(
                seed, f"SEED RESTORE — {reason}. Previous soul archived.")
            self._write(seed)
        self.log(f"[soul] SEED RESTORED ({reason})")

    # ------------------------------------------------------------------
    # Phase 0: log truncation — keep most recent SOUL_LOG_MAX_INLINE
    # entries in the markdown; archive older entries to JSONL on disk.
    # ------------------------------------------------------------------
    def _maybe_truncate_log(self, text: str) -> str:
        """If the Self-Modification Log section has more than SOUL_LOG_MAX_INLINE
        bullets, archive the older ones to log_archive.jsonl and return text
        with the trimmed log."""
        marker_re = re.compile(r"^## Self-Modification Log\s*$", re.MULTILINE)
        m = marker_re.search(text)
        if not m:
            return text
        log_start = m.end()
        # The log section runs until the next heading or EOF
        next_heading = re.search(r"^##\s+", text[log_start:], re.MULTILINE)
        log_end = log_start + (next_heading.start() if next_heading else len(text) - log_start)

        body = text[log_start:log_end]
        # Each log entry is a top-level bullet "- ..." (we preserve any leading prose)
        bullet_re = re.compile(r"^- .+(?:\n(?!- |##|\s*$).+)*", re.MULTILINE)
        bullets = list(bullet_re.finditer(body))
        if len(bullets) <= SOUL_LOG_MAX_INLINE:
            return text

        keep_n   = SOUL_LOG_MAX_INLINE
        kept     = bullets[:keep_n]
        archived = bullets[keep_n:]   # oldest entries (we prepend new entries)

        # Archive older entries
        try:
            with open(self.log_archive_path, "a", encoding="utf-8") as af:
                ts = datetime.now().isoformat()
                for b in archived:
                    af.write(json.dumps({
                        "archived_at": ts,
                        "entry": b.group(0).strip(),
                    }) + "\n")
        except Exception as e:
            self.log(f"[soul] log archive write failed: {e}")
            return text

        # Reconstruct the body with only the kept bullets
        # Preserve any preamble before the first bullet (e.g. "(New entries are prepended…)")
        preamble = body[:bullets[0].start()] if bullets else body
        new_body = preamble + "\n".join(b.group(0) for b in kept) + "\n"
        return text[:log_start] + new_body + text[log_end:]

    # ------------------------------------------------------------------
    # Apply tags emitted by the LLM
    # ------------------------------------------------------------------
    def apply_tags_in(self, reply: str) -> Tuple[str, List[str]]:
        """
        Scan `reply` for [Soul Edit:], [Soul Append:], [Soul Rename:],
        [Soul Reflect:] tags and apply them. Returns (clean_reply, applied_changes).
        clean_reply is safe to send to TTS.
        """
        if not reply:
            return reply, []

        applied: List[str] = []

        for m in self.EDIT_TAG_RE.finditer(reply):
            section, body = m.group(1).strip(), m.group(2).strip()
            self.replace_section(section, body, reason="LLM-emitted edit")
            applied.append(f"edited section {section!r}")

        for m in self.APPEND_TAG_RE.finditer(reply):
            section, body = m.group(1).strip(), m.group(2).strip()
            self.append_section(section, body, reason="LLM-emitted append")
            applied.append(f"appended to section {section!r}")

        for m in self.RENAME_TAG_RE.finditer(reply):
            new_name = m.group(1).strip()
            self.rename(new_name, reason="LLM-emitted rename")
            applied.append(f"renamed self → {new_name!r}")

        for m in self.REFLECT_TAG_RE.finditer(reply):
            self.add_reflection(m.group(1).strip())
            applied.append("logged reflection")

        clean = self.STRIP_ALL_RE.sub("", reply).strip()
        return clean, applied

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _prepend_log_entry(text: str, entry: str) -> str:
        ts = datetime.now().strftime("%Y-%m-%d %H:%M")
        log_line = f"- {ts} — {entry}"
        # Insert above the existing log section if present
        marker_re = re.compile(r"^## Self-Modification Log\s*$", re.MULTILINE)
        m = marker_re.search(text)
        if not m:
            return text.rstrip() + f"\n\n## Self-Modification Log\n\n{log_line}\n"
        # Find first list bullet under the heading and insert before it
        after = text[m.end():]
        bullet_match = re.search(r"^- ", after, re.MULTILINE)
        if not bullet_match:
            return text[:m.end()] + "\n\n" + log_line + "\n" + after
        insert_at = m.end() + bullet_match.start()
        return text[:insert_at] + log_line + "\n" + text[insert_at:]
