# MiMo TTS — Research Notes

> *Source corpus:* current `Speaker` impl in `mimo_apple_realtime_assistant.py`,
> `test_tts.py`, `scratch/test_mimo_api.py`, `.env`, observed live behavior in
> Live Test #1, and the API surface visible from request/response shapes.
>
> Goal: be precise enough that we can redesign the Speaker without guessing.
> **Status:** v0.1 — research from inside-out (no external docs available).
> When you have the official docs handy, paste the canonical schema into the
> "Authoritative Reference" section at the bottom and we'll reconcile.

---

## 0. TL;DR

- MiMo TTS rides on the OpenAI-compatible `/v1/chat/completions` endpoint with
  the audio modality extension — same shape OpenAI uses for `gpt-4o-audio-preview`.
- We are using the **`mimo-v2.5-tts-voicedesign`** model, which takes a
  free-form **voice-design prompt** in the `user` message and the **text to be
  spoken** in the `assistant` message. The legacy `mimo-v2.5-tts` model takes a
  fixed `voice` id instead.
- Audio comes back as **base64** under `choices[0].message.audio.data`.
- Format options confirmed in the wild: `mp3`, `wav`. WAV is preferable for
  reliability (no MP3 sync-frame edge cases).
- **No streaming endpoint observed** — we always get the full clip in one
  response. If a streaming variant exists we haven't found it yet.
- The existing Speaker uses MP3 + heuristic header sniffing, which is the
  source of V6 (occasional malformed audio / glitches).

---

## 1. Endpoint shape (verified from `scratch/test_mimo_api.py`)

```http
POST {MIMO_BASE_URL}/chat/completions
Authorization: Bearer {MIMO_API_KEY}
Content-Type: application/json

{
  "model": "mimo-v2.5-tts-voicedesign",
  "messages": [
    {"role": "user",      "content": "<voice-design prompt>"},
    {"role": "assistant", "content": "<exact text to be spoken>"}
  ],
  "modalities": ["text", "audio"],
  "audio": {
    "format": "mp3"            // or "wav"
  }
}
```

Response (verified):

```json
{
  "choices": [
    {
      "message": {
        "role": "assistant",
        "content": "...",       // sometimes empty / echoed
        "audio": {
          "id":   "...",
          "data": "<base64>",
          "expires_at": 1234567890
        }
      }
    }
  ]
}
```

The `audio` field IS the deliverable. `content` is incidental.

---

## 2. Models seen in the codebase

| Model id                        | Used by              | How it's prompted                                    |
|---------------------------------|----------------------|------------------------------------------------------|
| `mimo-v2.5-tts-voicedesign`     | live Speaker         | `user` = voice-design prompt, `assistant` = utterance |
| `mimo-v2.5-tts`                 | `test_tts.py` (alt)  | `assistant` = utterance, `audio.voice = "mimo_default"` |
| `mimo-v2.5-pro`                 | brain (LLM)          | normal chat                                          |

The VoiceDesign model's "user" message is the ONLY way we can steer voice/emotion
right now — it's interpreted as a free-form description of how the voice should
sound. Examples that are working:

> "A tactical robot. Deep, resonant male voice, extremely clear enunciation,
> slight metallic studio texture. Sounds highly intelligent and deliberate.
> CURRENT EMOTION: Deadpan, dry"

This is effectively the prompt-conditioning surface. There is no documented
parameter for pitch/rate/volume.

---

## 3. Audio header reality (V6 root cause)

We've seen these magic-byte prefixes in successful responses:

| Header bytes (hex) | Meaning                       |
|--------------------|-------------------------------|
| `52 49 46 46`      | `RIFF` — WAV container        |
| `49 44 33`         | `ID3` — MP3 with ID3v2 tags   |
| `FF FB`            | MP3 sync, MPEG-1 layer 3      |
| `FF FA`            | MP3 sync, MPEG-1 layer 3 no-CRC |
| `FF F3`            | MP3 sync, MPEG-2 layer 3      |
| `FF F2`            | MP3 sync, MPEG-2.5 layer 3    |

**V6 root cause hypothesis:** occasionally MiMo returns a base64 string that
decodes to bytes which start with a *partial* sync frame or junk preamble
(observed in logs as `Audio header unknown:` debug lines). `afplay` then
either plays static at the start or fails outright.

**Mitigation strategy (now implemented):**
- Strict header check (`_validate_audio_header`) — reject anything not in the
  table above and retry up to 2× before giving up.
- Prefer `wav` format when reliability matters (no sync-frame surface area).
- Cache only validated audio (we already do this via `_cache_audio`).

If we still see V6 after these mitigations, next steps are:
- Switch default `audio.format` to `wav` (slight bandwidth bump, near-zero corruption surface).
- Decode + re-encode through `ffmpeg` server-side check before play.

---

## 4. What we are currently NOT using (and probably should)

These are educated guesses based on common OpenAI-audio-API conventions —
**verify against MiMo's actual docs** before relying on any of them:

| Field / param           | Probable use                                    | Confidence |
|-------------------------|-------------------------------------------------|------------|
| `audio.voice`           | (legacy `mimo-v2.5-tts`) named voice id         | HIGH       |
| `audio.format = "wav"`  | reliable container                              | HIGH       |
| `audio.format = "opus"` | smaller payload                                 | MED        |
| `audio.format = "pcm"`  | raw frames for streaming                        | MED        |
| `temperature` on the TTS request | controls expressiveness                | MED        |
| `stream: true` on TTS   | server-sent event stream of audio chunks        | LOW (unverified) |
| `audio.speed` / `rate`  | playback speed multiplier                       | LOW        |
| Voice cloning via `voice` URL or upload | clone user-provided sample      | LOW (probably model-tier-locked) |

**Concrete next step for the research spike:**
1. Try `audio.format = "wav"` end-to-end and confirm the response decodes
   cleanly to a RIFF WAV file.
2. Try `stream: true` with the same payload — if the response comes back as
   `text/event-stream`, we have a streaming path. If it 400s, we don't.
3. Try `audio.voice = "mimo_default"` against `voicedesign` — does it ignore
   it (forcing voice-design prompt) or accept it as a fallback?

These are 30-min experiments to be run against your live API key.

---

## 5. Known failure modes (Live Test #1)

| Symptom                                         | Likely cause                          |
|-------------------------------------------------|---------------------------------------|
| 2-words-then-pause stuttering (V1)              | One TTS call per LLM-streamed sentence |
| Asterisks / em-dashes read aloud (V4)           | Speaker received un-sanitized text    |
| "â" in terminal logs                            | Stdout encoding (V11) — not TTS       |
| Occasional weird noise / cut-off speech (V6)    | Malformed MP3 sync frames at clip start |
| Latency to first audio ≈ 1.5–2.5 s              | Full LLM sentence + full TTS call before any audio plays |

All addressed by Phase −1 task list.

---

## 6. Recommended Speaker contract going forward

```python
class Speaker:
    # Single-shot
    def speak(text: str, blocking=True): ...

    # Streaming (V1)
    def speak_stream(sentence_iter, on_displayed=None, abort_check=None) -> str: ...

    # Internal
    def _fetch_audio_for(text: str) -> Optional[bytes]: ...   # validates header
    def _play_bytes(audio: bytes, for_text: str): ...         # writes tmp + afplay
    def _validate_audio_header(b: bytes) -> bool: ...
    def _cache_audio(text: str, b: bytes): ...
    def _play_cached(text: str) -> bool: ...
    def _cached_or_fetch(text: str) -> Optional[bytes]: ...
```

Behavior we want:
- **First-chunk fast**: flush the buffer at ~30 chars or first sentence-end,
  whichever comes first. Time-to-first-audio target: < 1 s after LLM first
  token.
- **Subsequent chunks smooth**: target ~100 chars per chunk, hard cap 220.
  Prefetch the NEXT chunk's audio while the CURRENT one plays.
- **Emotion routing**: tone tag in text → voice-design prompt augmentation.
  Smooth across chunks (don't change voice every sentence).
- **Strict header validation + retry**: never play malformed audio.
- **Cache hit on identical text**: short utterances (greetings, "yes", etc.)
  skip the API entirely on repeat.

---

## 7. Authoritative Reference  *(paste official docs here when you have them)*

> _placeholder — replace with the real schema when available_
>
> Specifically helpful:
> - Full `audio` object schema (all valid keys + types)
> - All available `audio.format` values
> - Whether streaming exists, and if so, the SSE chunk shape
> - The voice-design prompt grammar (if any) — does it understand emotion
>   keywords vs free-form? What's the max prompt length?
> - Rate limits and quotas

---

## 8. Open questions

1. **Does `mimo-v2.5-tts-voicedesign` support `stream: true`?** If yes, we can
   stream audio bytes during synthesis (lower latency). If no, we're stuck with
   buffer-and-prefetch (which is already implemented).
2. **What is the maximum input length per request?** The voice-design prompt +
   utterance combined. We currently cap our chunks at 400 chars; the API
   probably handles much more, but each chunk's TTS latency scales with text
   length, so chunking is right for prosody anyway.
3. **Is there a separate `/v1/audio/speech` endpoint** (OpenAI-style) we
   haven't tried? Worth probing.
4. **Custom voice cloning** — does MiMo support uploading a sample and
   referencing it? Could give TARS a unique voice the user trained. Out of
   Phase −1 scope but worth knowing for later.

---

## 9. Voice Consistency — what we tried, what worked, what's left

> Live Test #2 + #3 surfaced "voice changes per sentence." VoiceDesign
> models reinterpret the design prompt fresh on every call, so each chunk
> of one reply gets a slightly different voice. Three approaches converge
> on a fix:

### Tried
| Round | Change                                                  | Effect                       |
|-------|---------------------------------------------------------|------------------------------|
| R2-C  | Lock the `[Tone:]` emotion at the START of a reply      | Fewer per-chunk swings       |
| R2-D  | Strip ALL `[Tone:]` tags before TTS (was only stripping first) | No more spoken "tone amused" |
| R3    | Larger chunks (target 220 chars, hard max 400)          | ~½ as many TTS calls per reply → ½ as many voice transitions |
| R3    | `temperature: 0.0` + `seed: 1729` in TTS payload        | Determinism hint — if MiMo is OpenAI-compatible here, identical inputs produce identical outputs |

### What's left
1. **Verify the `temperature` / `seed` parameters are honored** — call the
   same chunk twice with `seed=1729` and check audio bytes for byte-equality.
   Trivial probe; do it next round.
2. **Try the legacy `mimo-v2.5-tts` model** with a fixed `voice` id —
   sacrifices emotional steering for consistency. If voice variance is
   STILL high there, the source of variance is server-side and we can't fix
   it client-side. Switch the env var: `MIMO_TTS_MODEL=mimo-v2.5-tts`.
3. **Voice-design prompt rigidity** — current prompt is verbose and
   emotional. Strip it down to a single sentence with a fixed prosody
   description and only use `CURRENT EMOTION:` as the variable axis. Less
   surface area for the model to reinterpret.
4. **Streaming TTS, if available** — would let us send the WHOLE reply as
   ONE call (no chunking) without losing TTFA. One call → one voice. Need
   to verify whether `stream: true` works on `mimo-v2.5-tts-voicedesign`.

### A/B harness
`scripts/voice_test.py` is the place to validate (1) and (2). Add a
`--ab` flag that fetches the SAME utterance N times under each candidate
config and reports byte-diff rate. Belongs in next round.

---

## 10. Cross-reference to Deepgram research

See `docs/DEEPGRAM_STT_RESEARCH.md` — the symmetric document for STT.
Together they capture our voice-pipeline architecture rationale.

---

## 11. Round 4 Findings — Voice Catalog Discovery (2026-04-30)

> Live API probed via `scripts/probe_mimo_tts.py`. All earlier guessing
> in §7 ("Authoritative Reference — placeholder") is now superseded by
> this section.

### 11.1 The voice catalog (verified)

When you POST to `mimo-v2.5-tts` with an unknown `voice`, the API returns
the canonical list in the error body:

```
"Available voices: [mimo_default, 冰糖, 茉莉, 苏打, 白桦, Mia, Chloe, Milo, Dean]"
```

| Voice ID    | Probable character                                  | Probe result |
|-------------|------------------------------------------------------|--------------|
| `mimo_default` | generic, neutral                                | ✓ works      |
| `Dean`      | deep male, English — best match for TARS persona    | ✓ works      |
| `Milo`      | male, English — slightly lighter than Dean          | ✓ works (most consistent) |
| `Mia`       | female, English                                     | ✓ works      |
| `Chloe`     | female, English                                     | ✓ works      |
| `冰糖`      | Chinese                                              | not probed   |
| `茉莉`      | Chinese                                              | not probed   |
| `苏打`      | Chinese                                              | not probed   |
| `白桦`      | Chinese                                              | not probed   |

### 11.2 Drift A/B (3 calls × same text × per config, WAV format)

```
config                 distinct   size_min   size_max  size_range  median_t
voicedesign-current           3    376,364    468,524      92,160     4.47s
fixed-Dean                    3    284,204    345,644      61,440     3.34s
fixed-Milo                    3    361,004    384,044      23,040     3.85s
```

Interpretation:
- All three configs return **distinct** byte-streams across calls (WAV
  containers carry timestamps + the synthesizer is non-deterministic in
  micro-timing, even with `seed=1729`).
- The **size_range** is the meaningful signal — it measures how much the
  synthesizer disagrees with itself about the *length* of the spoken
  audio across calls. Smaller = more stable pacing/intonation.
- Going `voicedesign → fixed-Dean → fixed-Milo` reduces size variance by
  **~75% (92K → 23K bytes)**. Milo is the most stable.

### 11.3 Streaming endpoint exists, but doesn't actually chunk audio

`stream: true` on `/chat/completions` (both models) returns
`Content-Type: text/event-stream` with this pattern:

```
chunk 1: opens   (role=assistant, audio=None)
chunk 2: AUDIO   (one big base64 blob — the WHOLE clip)
chunk 3: closes  (audio=None)
chunk 4: usage   (no choices array)
```

Streaming is functionally equivalent to non-streaming for this API —
audio still arrives in one ~340 KB chunk. **No latency win**, but also
no harm. We're keeping the buffered+prefetched chunker we already have.

### 11.4 Endpoint catalog (probed)

| Endpoint                 | Result                                      |
|--------------------------|---------------------------------------------|
| `/v1/chat/completions`   | ✓ both `mimo-v2.5-tts` and `voicedesign`    |
| `/v1/audio/speech` (OpenAI-style) | ✗ HTTP 404 (not implemented)        |

Use chat completions with `modalities: ["text","audio"]`. Forget about
`/v1/audio/speech`.

### 11.5 The "weird sometimes" hypothesis (not yet ruled out)

User-reported failure mode: "voice is very weird sometimes." Two
candidate causes survive Round 4:
1. **VoiceDesign re-interpretation drift** — the 92 KB size variance
   above corresponds to noticeably different intonation/pacing per call.
   Switching to a fixed voice removes this entirely.
2. **Tone-tag content leakage** — if a tone tag like `[Tone: Maniacal,
   theatrical]` reaches the VoiceDesign prompt, the synthesizer can
   produce a genuinely "weird" timbre. We strip tags BEFORE TTS
   (R2-D + the cleaner) but the prompt's `CURRENT EMOTION:` line is
   still passed through. With the fixed-voice model, emotion is no
   longer steerable via prompt — voice timbre is locked.

### 11.6 Final Round 4 default

```
MIMO_TTS_MODEL = mimo-v2.5-tts                # was: mimo-v2.5-tts-voicedesign
MIMO_TTS_VOICE = Dean                         # deep male, name-fits TARS
MIMO_TTS_FORMAT = wav                         # was: mp3 — V6 mitigation
```

User can flip:
- `MIMO_TTS_VOICE=Milo` for the most-consistent voice in the A/B.
- `MIMO_TTS_VOICE={Mia,Chloe}` for female voices.
- `MIMO_TTS_MODEL=mimo-v2.5-tts-voicedesign` to bring back emotion
  steering at the cost of consistency.

The boot-greeting + skill-announcement audio cache is now keyed on
`(model, voice, format, text)` so changing any of these doesn't replay
old clips in the wrong voice.

### 11.7 What we paid for this knowledge

~22 API calls during the probe pass (10 quick probes + 8 voice samples +
3 streaming probes + 9 A/B harness calls). All audio samples are saved
under `scratch/probe_audio/` and `scratch/ab/` for human listening.
