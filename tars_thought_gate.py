"""
TARS Inner Thought Quality Gate
================================

Stops local-model slop from poisoning memory + workspace + prompt.

The 1.5B model produces specific failure modes that cheap regex catches:
  1. Mid-sentence truncation ("Not a hu", "and the system requires…")
  2. Exact-phrase loops ("Not a huge deal. Not a huge deal.")
  3. Self-narration templates ("User is X", "User requires X", "I will demonstrate…")
  4. Re-paraphrase of recent thoughts (Jaccard ≥ threshold)
  5. Empty platitudes ("Everything is fine.", "All systems normal.")
  6. The model parroting its own meta-tokens (`[salient moment]`, `[Tone:]`, `[note]`)

Mind-perfection upgrade: the previous gate caught (1)(2)(4) at Jaccard 0.72
and missed (3)(5)(6). Real recent thoughts on disk show the slop pattern:
    "User is pleased with..."
    "User is intrigued..."
    "User requires continuity..."
    "[salient moment] The system requires immediate attention..."
All of these get rejected now.

Gemma 4 E4B is stronger, but its main failure mode is different: it can leak
instruction-following traces ("I need to output...", "the prompt asks...") or
chat-template artifacts. Those are also rejected here.
"""

from __future__ import annotations

import re
from typing import Dict, List, Tuple


class ThoughtQualityGate:
    """Validates one local-model thought before it hits memory/workspace."""

    # ── Template patterns that indicate slop, not real cognition ────────
    # These match the literal failure modes seen in tars_thoughts.jsonl /
    # tars_rejected_thoughts.jsonl from the 1.5B model. Each pattern is
    # intentionally narrow to avoid catching real reflections.
    SLOP_TEMPLATES = [
        # Self-narration about the user instead of about TARS's own state
        re.compile(r"^\s*user (?:is|requires|wants|seems|appears|intends) ", re.I),
        # Meta-token leaks
        re.compile(r"^\s*\[(?:salient moment|note|tone|inhale|sigh|pause)\b", re.I),
        re.compile(r"<\s*/?\s*(?:think|start_of_turn|end_of_turn|bos|eos)\b", re.I),
        re.compile(r"\benable_thinking\b", re.I),
        # Gemma-style instruction-following chatter, not an inner thought.
        re.compile(
            r"^\s*(?:okay,?\s*)?i (?:need|will|should|must) (?:to )?"
            r"(?:produce|generate|write|craft|output|create|respond|answer|follow)\b",
            re.I,
        ),
        re.compile(
            r"^\s*(?:the )?(?:prompt|instruction|task|request) "
            r"(?:asks|requires|wants|says|tells)\b",
            re.I,
        ),
        re.compile(r"^\s*here(?:'s| is) (?:one |a )?(?:private )?thought\b", re.I),
        re.compile(r"^\s*as (?:an? )?(?:inner voice|assistant|ai)\b", re.I),
        # Empty platitudes
        re.compile(r"^\s*(?:everything|all systems?|nothing) (?:is|are) (?:fine|normal|stable|good|operational)\.?\s*$", re.I),
        # "I will demonstrate by repeating" — direct loop tell
        re.compile(r"\bdemonstrate by repeating\b", re.I),
        re.compile(r"\brepeating my last (?:reply|response|thought)\b", re.I),
        # Pure operational status reports — not real reflection
        re.compile(r"^\s*system (?:status|is|operates|operational)", re.I),
        re.compile(r"^\s*operational[, ]", re.I),
        # The 1.5B model's classic "Not a huge deal" / "Not really" hedge loop
        re.compile(r"^\s*not (?:a huge deal|really|much|sure)[. ]", re.I),
    ]

    # Stopwords for the Jaccard core
    STOPWORDS = {
        "the", "a", "an", "is", "are", "was", "were", "be", "been", "being",
        "and", "or", "but", "if", "in", "on", "at", "to", "for", "of",
        "it", "its", "that", "this", "these", "those", "as", "by", "with",
        "i", "i'm", "im", "me", "my", "we", "our", "you", "your",
        "have", "has", "had", "do", "does", "did", "will", "would",
        "should", "could", "can", "may", "might", "shall",
        "not", "no", "so", "just", "now", "still", "even",
    }

    # Sentence starts that indicate self-similar "User is …" templating —
    # detected separately because the meaningful nouns in slop sentences are
    # all different but the structure is identical.
    TEMPLATE_PREFIX_RE = re.compile(
        r"^(user (?:is|requires|wants|seems|appears|intends|needs|expects)|"
        r"i (?:will|am|have|need|should|must)|"
        r"the (?:user|system|conversation|interaction))\b",
        re.I,
    )

    JACCARD_THRESHOLD = 0.55          # was 0.72 — tighter
    PREFIX_DUP_LIMIT  = 2             # max same template-prefix in recent window

    def validate(self, thought: Dict, recent_thoughts: List[Dict]) -> Tuple[bool, str]:
        content = (thought.get("content") or "").strip()

        # ── 1. Length sanity ─────────────────────────────────────────
        if len(content) < 10:
            return False, "too_short"
        if len(content) > 320:
            return False, "too_long"

        # ── 2. Truncated ending — mid-word or no terminal punct + tiny tail
        last_token = content.split()[-1] if content.split() else ""
        if not content.endswith((".", "!", "?", '"', "'", ")", "]", "…")):
            # If the last word is short AND not a normal terminator, reject
            if len(last_token) <= 3 and last_token.lower() not in {"i", "a", "ok"}:
                return False, "truncated_ending"

        # ── 3. Slop-template patterns (the explicit kill list)
        for pat in self.SLOP_TEMPLATES:
            if pat.search(content):
                return False, f"slop_template:{pat.pattern[:30]}"

        # ── 4. Internal n-gram repetition (within the same thought)
        words = content.split()
        if len(words) >= 6:
            ngrams: dict = {}
            for i in range(len(words) - 2):
                ng = " ".join(words[i:i+3]).lower()
                ngrams[ng] = ngrams.get(ng, 0) + 1
                if ngrams[ng] > 1:
                    return False, f"repeated_3gram:{ng[:40]}"

        # ── 5. Same exact sentence appears twice
        sentences = [s.strip() for s in re.split(r"[.!?]+", content) if s.strip()]
        if len(sentences) > 1 and len(set(s.lower() for s in sentences)) < len(sentences):
            return False, "repeated_sentence"

        # ── 6. Known loop strings
        lc = content.lower()
        if lc.count("not a huge deal") > 1:
            return False, "known_loop:not_a_huge_deal"
        if "..." in content and lc.count("...") >= 3:
            return False, "ellipsis_spam"

        # ── 7. Template-prefix repetition vs recent thoughts
        # If the LAST `PREFIX_DUP_LIMIT` thoughts started with the same
        # templated prefix, this is rumination — kill it.
        if recent_thoughts:
            this_prefix = self._template_prefix(content)
            if this_prefix is not None:
                same = 0
                for rt in recent_thoughts[-10:]:
                    rt_prefix = self._template_prefix((rt.get("content") or "").strip())
                    if rt_prefix and rt_prefix == this_prefix:
                        same += 1
                if same >= self.PREFIX_DUP_LIMIT:
                    return False, f"template_prefix_loop:{this_prefix}"

        # ── 8. Jaccard similarity vs recent thoughts (tightened to 0.55)
        if recent_thoughts:
            content_core = self._core_tokens(content)
            if content_core:
                for rt in recent_thoughts[-25:]:
                    rt_core = self._core_tokens((rt.get("content") or "").strip())
                    if not rt_core:
                        continue
                    inter = len(content_core & rt_core)
                    union = len(content_core | rt_core)
                    j = inter / union if union else 0.0
                    if j >= self.JACCARD_THRESHOLD:
                        return False, f"jaccard_{j:.2f}"

        # ── 9. High salience but vague — needs concrete content
        salience = float(thought.get("salience", 0.0) or 0.0)
        if salience > 0.8:
            # Need at least one capitalized non-first word OR concrete length
            non_first_caps = any(w[0].isupper() for w in words[1:])
            if len(words) < 6 and not non_first_caps:
                return False, "high_salience_but_vague"

        return True, "ok"

    # ────────────────────────────────────────────────────────────────────
    @classmethod
    def _template_prefix(cls, text: str) -> str:
        """Return a normalized template-prefix string if `text` looks templated.
        Used to detect rumination loops where many thoughts share the same
        scaffolding ('User is X', 'User requires Y', …)."""
        if not text:
            return ""
        m = cls.TEMPLATE_PREFIX_RE.match(text.strip().lower())
        if not m:
            return ""
        return m.group(1).strip()

    @classmethod
    def _core_tokens(cls, text: str) -> set:
        toks = set(re.findall(r"\b[a-z]{2,}\b", text.lower()))
        return toks - cls.STOPWORDS


# ── Self-test ────────────────────────────────────────────────────────────
if __name__ == "__main__":
    g = ThoughtQualityGate()
    cases = [
        # (content, salience, recent, expected_ok, label)
        ("User is pleased with the system's response, thank you very much.", 0.3, [], False, "user-is template"),
        ("User requires immediate attention; I will demonstrate by repeating my last reply.", 0.3, [], False, "demonstrate by repeating"),
        ("[salient moment] The system requires immediate attention.", 0.3, [], False, "salient-moment leak"),
        ("Not a huge deal. Not a huge deal at all.", 0.3, [], False, "huge-deal loop"),
        ("Everything is fine.", 0.3, [], False, "platitude"),
        ("Okay, I need to output one private thought with KIND and MOOD.", 0.3, [], False, "gemma meta-plan"),
        ("The prompt asks for a short internal monologue.", 0.3, [], False, "gemma prompt echo"),
        ("Here's a private thought: the user seems focused.", 0.3, [], False, "gemma thought preface"),
        ("<think>I should comply.</think> I should answer now.", 0.3, [], False, "gemma think tag"),
        ("I keep restating the same point — repetition rate is climbing in my reflections.", 0.6, [], True, "real reflection"),
        ("The user mentioned a teammate earlier; I should remember to ask gently if they come up again.", 0.7, [], True, "real social mem"),
        ("operational, ready to go", 0.3, [], False, "operational status"),
        # Template-prefix loop detection
        ("User is intrigued by the depth.", 0.3,
            [{"content": "User is curious about TARS."},
             {"content": "User is happy with the test."}], False, "template-prefix loop"),
        # Truncated ending
        ("Not a hu", 0.3, [], False, "mid-word truncation"),
    ]
    fails = 0
    for content, sal, recent, want_ok, label in cases:
        ok, reason = g.validate({"content": content, "salience": sal}, recent)
        mark = "PASS" if ok == want_ok else "FAIL"
        if ok != want_ok:
            fails += 1
        print(f"  [{mark}] {label:36s} ok={ok}  reason={reason}")
    print()
    print(f"{'GATE OK' if fails == 0 else f'{fails} CASES FAILED'}")
