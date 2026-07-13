"""
TARS Text Cleaner
=================

Sanitizes any string before it reaches the TTS engine, so the user never
hears literal asterisks, em-dashes, smart-quotes, markdown bullets, code
fences, or emojis.

Input:  whatever the LLM produced (with `[Tone:]` and `[pause]` already
        applied or stripped — we don't touch those).
Output: a string safe to send to the TTS engine that will sound natural.

R7: now supports two cleaning modes — ``"mimo"`` (default, original
behavior) and ``"deepgram"`` (preserves em-dash + ellipsis as natural
prosody, since Aura-2 honors them). Other normalization is shared.

Used by both the streaming Speaker path and the announce-queue path.
"""

from __future__ import annotations

import re
import unicodedata


# ---------------------------------------------------------------------------
# 1. Smart-quote / dash / ellipsis normalization
# ---------------------------------------------------------------------------
# MiMo TTS doesn't render em-dashes / ellipses as natural prosody — em-dash
# can come out as "double hyphen", ellipsis as silence-with-no-intonation.
# We convert them to safer ASCII equivalents on the MiMo path.
_PUNCT_MAP_MIMO = {
    "–": "-",   # en dash
    "—": ", ",  # em dash  → comma+space (cleaner pause than a hyphen)
    "―": ", ",  # horizontal bar
    "‘": "'",   # left single quote
    "’": "'",   # right single quote / apostrophe
    "‚": ",",   # single low-9 quote
    "‛": "'",
    "“": '"',   # left double quote
    "”": '"',   # right double quote
    "„": '"',
    "‟": '"',
    "…": "...", # ellipsis
    "«": '"',   # « »
    "»": '"',
    " ": " ",   # nbsp
    " ": " ",   # narrow nbsp
    " ": " ",   # thin space
    "​": "",    # zero-width space
    "‌": "",
    "‍": "",
    "﻿": "",    # BOM
    "•": ",",   # bullet • → comma (so "Item • Item" reads naturally)
    "‣": ",",
    "◦": ",",
    "⁃": ",",
}

# R7: Deepgram Aura-2 honors em-dash + ellipsis as REAL prosody — em-dash
# adds a natural ~250 ms pause, ellipsis adds trailing-thought intonation.
# Preserving them is a free expressiveness win on the Deepgram path.
# Everything else gets the same hygiene as the MiMo map.
_PUNCT_MAP_DEEPGRAM = dict(_PUNCT_MAP_MIMO)
_PUNCT_MAP_DEEPGRAM["—"] = "—"   # keep em-dash
_PUNCT_MAP_DEEPGRAM["―"] = "—"   # horizontal bar → em-dash
_PUNCT_MAP_DEEPGRAM["…"] = "…"   # keep ellipsis

_PUNCT_TRANS_MIMO     = str.maketrans(_PUNCT_MAP_MIMO)
_PUNCT_TRANS_DEEPGRAM = str.maketrans(_PUNCT_MAP_DEEPGRAM)


# ---------------------------------------------------------------------------
# 2. Emoji + symbol removal
#    Drops any character whose Unicode category is "So" (Symbol, other) or
#    "Sk" (Symbol, modifier) — covers ☑, ✅, ⚠️, ❤️, etc.
# ---------------------------------------------------------------------------
def _strip_emoji_symbols(s: str) -> str:
    out = []
    for ch in s:
        cat = unicodedata.category(ch)
        if cat in {"So", "Sk", "Cs", "Co", "Cn"}:
            continue
        # Variation selectors (FE00-FE0F) and zero-width joiners survive
        # the category filter — strip them too.
        cp = ord(ch)
        if 0xFE00 <= cp <= 0xFE0F or cp == 0x200D:
            continue
        # Misc symbols & pictographs / regional indicator block
        if 0x1F300 <= cp <= 0x1FAFF or 0x1F1E6 <= cp <= 0x1F1FF:
            continue
        out.append(ch)
    return "".join(out)


# ---------------------------------------------------------------------------
# 3. Markdown stripping
#    We DO NOT strip [Tone:] / [pause] / [sigh] etc — Speaker handles those.
#    We DO strip:
#      - **bold**, *italic*, _italic_, __bold__   → keep inner text
#      - `inline code`, ```fenced code```          → keep inner text
#      - ~~strike~~                                → keep inner text
#      - markdown headers ## / # / ###             → drop the markers
#      - markdown list bullets `- `, `* `, `1. `   → drop the bullet
#      - block-quote `> `                          → drop the marker
# ---------------------------------------------------------------------------
_MD_FENCE_RE       = re.compile(r"```[^\n]*\n?(.*?)```", re.DOTALL)
_MD_INLINE_CODE_RE = re.compile(r"`([^`\n]+)`")
_MD_BOLD_STAR_RE   = re.compile(r"\*\*([^*]+)\*\*")
_MD_BOLD_UND_RE    = re.compile(r"__([^_]+)__")
_MD_ITAL_STAR_RE   = re.compile(r"(?<![*\w])\*([^*\n]+)\*(?!\w)")
_MD_ITAL_UND_RE    = re.compile(r"(?<![_\w])_([^_\n]+)_(?!\w)")
_MD_STRIKE_RE      = re.compile(r"~~([^~]+)~~")
_MD_HEADER_RE      = re.compile(r"^\s{0,3}#{1,6}\s*", re.MULTILINE)
_MD_BULLET_RE      = re.compile(r"^\s*(?:[-*+]|\d+\.)\s+", re.MULTILINE)
_MD_QUOTE_RE       = re.compile(r"^\s*>\s?", re.MULTILINE)
_MD_HRULE_RE       = re.compile(r"^\s*[-*_]{3,}\s*$", re.MULTILINE)
_MD_LINK_RE        = re.compile(r"\[([^\]]+)\]\([^)]+\)")
_MD_IMAGE_RE       = re.compile(r"!\[([^\]]*)\]\([^)]+\)")
_HTML_TAG_RE       = re.compile(r"<[^>]+>")


def _strip_markdown(s: str) -> str:
    s = _MD_IMAGE_RE.sub(r"\1", s)                  # images: keep alt text
    s = _MD_LINK_RE.sub(r"\1", s)                   # links: keep label
    s = _MD_FENCE_RE.sub(r"\1", s)                  # fenced code blocks
    s = _MD_INLINE_CODE_RE.sub(r"\1", s)            # inline code
    s = _MD_BOLD_STAR_RE.sub(r"\1", s)
    s = _MD_BOLD_UND_RE.sub(r"\1", s)
    s = _MD_ITAL_STAR_RE.sub(r"\1", s)
    s = _MD_ITAL_UND_RE.sub(r"\1", s)
    s = _MD_STRIKE_RE.sub(r"\1", s)
    s = _MD_HEADER_RE.sub("", s)
    s = _MD_BULLET_RE.sub("", s)
    s = _MD_QUOTE_RE.sub("", s)
    s = _MD_HRULE_RE.sub("", s)
    s = _HTML_TAG_RE.sub("", s)
    return s


# ---------------------------------------------------------------------------
# 4. Common abbreviations that TTS gets wrong
# ---------------------------------------------------------------------------
_ABBREV_MAP = [
    (re.compile(r"\bvs\.",  re.I),    "versus"),
    (re.compile(r"\bi\.e\.", re.I),   "that is,"),
    (re.compile(r"\be\.g\.", re.I),   "for example,"),
    (re.compile(r"\betc\.", re.I),    "etcetera"),
    (re.compile(r"\bw/\b"),           "with"),
    (re.compile(r"\bw/o\b"),          "without"),
    (re.compile(r"\s&\s"),            " and "),
    (re.compile(r"\bAI\b"),           "A I"),         # otherwise pronounced "ay"
    (re.compile(r"\bTTS\b"),          "T T S"),
    (re.compile(r"\bSTT\b"),          "S T T"),
    (re.compile(r"\bAPI\b"),          "A P I"),
]


def _expand_abbrev(s: str) -> str:
    for pat, repl in _ABBREV_MAP:
        s = pat.sub(repl, s)
    return s


# ---------------------------------------------------------------------------
# 5. Whitespace collapse + leftover stray punctuation
# ---------------------------------------------------------------------------
_LEFTOVER_STARS_RE = re.compile(r"\*+")
_LEFTOVER_UNDS_RE  = re.compile(r"_{2,}")
_LEFTOVER_BACKTICKS_RE = re.compile(r"`+")
_MULTI_SPACE_RE    = re.compile(r"[ \t]{2,}")
_MULTI_NEWLINE_RE  = re.compile(r"\n{2,}")
_PUNCT_PILE_RE     = re.compile(r"([,.;:!?])\1+")


def _final_pass(s: str) -> str:
    s = _LEFTOVER_STARS_RE.sub("", s)
    s = _LEFTOVER_UNDS_RE.sub("", s)
    s = _LEFTOVER_BACKTICKS_RE.sub("", s)
    s = _PUNCT_PILE_RE.sub(r"\1", s)         # ".." → "."
    s = _MULTI_SPACE_RE.sub(" ", s)
    s = _MULTI_NEWLINE_RE.sub("\n", s)
    return s.strip()


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def clean_for_speech(text: str, mode: str = "mimo") -> str:
    """Make `text` safe and natural for TTS. Idempotent.

    ``mode``:
        ``"mimo"``     — collapses em-dash → ", " and ellipsis → "..." for
                          a TTS engine that doesn't render those characters
                          as prosody. Default for backward compatibility.
        ``"deepgram"`` — preserves em-dash + ellipsis as Unicode so
                          Aura-2's natural-prosody pass can use them.
    """
    if not text:
        return ""
    s = text
    # Defensive mojibake repair for occasional UTF-8 punctuation decoded as
    # Windows-1252 by an upstream stream/proxy. Prevents TTS from reading
    # "a circumflex" when the model meant an em dash or ellipsis.
    s = (s.replace("â€”", "—")
           .replace("â€“", "—")
           .replace("â€•", "—")
           .replace("â€¦", "…")
           .replace("â€˜", "'")
           .replace("â€™", "'")
           .replace("â€œ", '"')
           .replace("â€�", '"'))
    s = re.sub(r"\s+â\s+", " — ", s)
    if mode == "deepgram":
        s = s.translate(_PUNCT_TRANS_DEEPGRAM)
    else:
        s = s.translate(_PUNCT_TRANS_MIMO)
    s = _strip_markdown(s)
    s = _strip_emoji_symbols(s)
    s = _expand_abbrev(s)
    s = _final_pass(s)
    return s


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    samples = [
        "Hello — *world* — this is **bold** and `code`!",
        "Use vs. with i.e. — and `**emphasis**` should NOT survive.",
        "I'm 'thinking' about it… ",
        "## Heading line\n- bullet one\n- bullet two\n> quoted",
        "Mixed AI/STT/TTS API call ✅ done",
        "[Tone: Deadpan] Sometimes I add ⚠️ warnings, you see.",
        "Asterisks: ***triple***, doubles: **double**, ones: *one*.",
    ]
    for s in samples:
        print(f"IN  : {s!r}")
        print(f"MIMO: {clean_for_speech(s, mode='mimo')!r}")
        print(f"DG  : {clean_for_speech(s, mode='deepgram')!r}\n")
