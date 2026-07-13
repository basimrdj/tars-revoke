# Deepgram Nova-3 STT — Research Notes

> *Source corpus:* deepgram-sdk-python 3.x source patterns, Deepgram public
> docs structure (event types, options), live-test failures from this
> project (Live Test #1 + Round 2 + Round 3), and the deltas observed
> across our three rounds of voice triage.
>
> Status: v0.1 — internal-knowledge synthesis. Replace with an
> "Authoritative Reference" section once you paste the canonical Deepgram
> docs.

---

## 0. TL;DR

- We were doing it wrong. Up through Round 2 we committed transcripts on
  `speech_final`, which is gated by the per-segment `endpointing` parameter
  (300–1500ms). To capture pause-fragmented sentences we kept BUMPING
  endpointing — but that made everything slow.
- The right pattern: commit on the `UtteranceEnd` event, gated by the
  separate `utterance_end_ms` parameter. **endpointing controls segment
  boundaries; utterance_end_ms controls turn boundaries — they're
  independent dials.** Round 3 uses both.
- WebSocket idle-timeout is real. Mic-gated silence during long TTS replies
  looks idle to the server. Send `{"type": "KeepAlive"}` JSON frames
  every ≤ 10 seconds via `dg_connection.keep_alive()` (or the raw fallback).

---

## 1. The two end-of-speech signals (THE key insight)

Deepgram's streaming API emits TWO independent end signals:

| Signal               | Carrier                              | Threshold knob       | Default | Meaning |
|----------------------|--------------------------------------|----------------------|---------|---------|
| `is_final` + `speech_final` | `Transcript` event           | `endpointing` (ms)   | 10 ms   | A speech *segment* is final. Often fires multiple times per utterance. |
| `UtteranceEnd`       | Separate `UtteranceEnd` event        | `utterance_end_ms`   | 1000 ms | The user has finished speaking the entire turn. Fires ONCE per turn. |

**Bug we had through Round 2:** committing on `speech_final`. To avoid
fragmenting "Hello, … world" into two transcripts, we cranked `endpointing`
up to 1500 ms — so every short utterance also waited 1.5 s before we
heard back. We THOUGHT lowering endpointing would fragment, so we lived
with the lag.

**Round 3 fix:** keep `endpointing` short (500 ms — segments commit fast),
keep `utterance_end_ms` short (1000 ms — turn ends fast), but commit
**only on `UtteranceEnd`**. Internal pauses ≤ 1 s no longer split a turn,
yet the latency is ~1 s end-of-speech instead of 3 s.

```
            user speaks ── pause ── user speaks ── silence
            ─────────┐    ┌────┐    ─────────┐
                     │    │    │             │
         endpointing │    │    │ endpointing │     ← per-segment
                     ▼    ▼    ▼             ▼
                  is_final   is_final     is_final + speech_final
                                                   │
                                            ──────────────── utterance_end_ms
                                                                    │
                                                                    ▼
                                                              UtteranceEnd
                                                              (commit here)
```

---

## 2. Critical LiveOptions (Round 3 settings)

```python
LiveOptions(
    model="nova-3",
    language="en-US",
    smart_format=True,        # punctuation + capitalization
    punctuate=True,
    interim_results=True,     # required so we get is_final segments early
    encoding="linear16",
    channels=1,
    sample_rate=16000,
    endpointing=500,          # 500 ms silence → is_final fires (was 1500)
    utterance_end_ms=1000,    # 1000 ms silence → UtteranceEnd fires (was 3000)
    vad_events=True,          # SpeechStarted events (used by future work)
    filler_words=True,        # captures uh/um (helps natural transcripts)
    no_delay=True,            # request lowest-latency formatting
)
```

`no_delay=True` is documented to skip server-side smart-format
buffering for lowest possible streaming latency. Trade-off: minor
formatting quality loss, but punctuation still works.

---

## 3. KeepAlive — the silent-killer fix

Deepgram closes a WebSocket if it sees no audio data for ~10 s of
*real silence* — but mic-gated zero bytes are sent during long TTS
replies (R2-A). Eventually the server treats this as idle and tears
down the connection. We saw this as:

```
ConnectionClosed in AbstractSyncWebSocketClient._listening:
  sent 1011 (internal error) keepalive ping timeout
```

**Fix:** spawn a daemon that calls `dg_connection.keep_alive()` every
5 s. Falls back to sending the raw `{"type": "KeepAlive"}` JSON frame
on older SDKs. Implementation lives in `DeepgramSTT._keepalive_loop`
in `mimo_apple_realtime_assistant.py`.

---

## 4. Mic-gating vs. barge-in (R2 design choice)

We replaced the fuzzy text-overlap echo filter with hard mic gating:
while `speaker.is_playing()` is True, the mic-callback sends silence
to Deepgram instead of live audio. **Echo is fully eliminated** at
the source.

Trade-off: no true conversational barge-in. We retain a thin
keyword-only override (`stop`, `quiet`, `shut`, `enough`, `halt`,
`pause`, `wait`, `hold`, `cancel`, `silence`) — these words, if
heard during the gate's grace edge, still cut TARS off.

For real barge-in later (Phase 5+): split the audio path into TWO
streams. One feeds Deepgram (gated). The other feeds a tiny on-device
VAD or wake-word detector that monitors raw mic for ≥ 200 ms of voiced
speech, and triggers `speaker.stop()` directly.

---

## 5. Other Deepgram features worth knowing

| Feature              | Use                                                 | Status here   |
|----------------------|-----------------------------------------------------|---------------|
| `keyterms` / `keywords` | bias toward domain-specific terms, e.g. names    | not used      |
| `diarize=True`       | per-speaker labels                                  | not used (single-speaker case) |
| `multichannel`       | independent channels per speaker                    | not applicable |
| `redact`             | redact PII (SSN, credit cards, etc)                 | future         |
| `profanity_filter`   | mask profanity                                      | not desired (TARS personality) |
| `search` / `replace` | server-side substring search/replace                | not used      |
| `tier="enhanced"`    | older tiered model selector — Nova-3 supersedes it  | unused        |
| `version="latest"`   | pin model version                                   | optional      |
| `callback`           | HTTP webhook for transcript delivery                | unused — we WS-stream |

`keyterms` worth trying for our use case — specifically for "TARS" and
the user's name so they're never mis-transcribed. Future enhancement.

---

## 6. Common pitfalls (from our experience)

1. **Treating `speech_final` as utterance end.** It's a segment end. See §1.
2. **Cranking endpointing > 1000 ms.** Slow as hell. Use UtteranceEnd instead.
3. **Forgetting KeepAlive when feeding silence.** Server thinks you're idle.
4. **Using fuzzy echo filtering instead of source elimination.** Always loses to real-world acoustic environments — mic gate is the right answer.
5. **Treating `is_final` as commit-worthy on its own.** Buffer all of them between speech-start and UtteranceEnd, then emit ONCE.
6. **Letting `interim_results=False` ride.** Without interims, segments don't commit until the entire utterance is done at server side, which is slower than a paced is_final stream.

---

## 7. Authoritative Reference  *(paste official Deepgram docs here)*

> _placeholder — when you have the canonical docs handy, drop the option
> reference + event payload schema here so we can fact-check our
> Round-3 design._

---

## 8. Performance targets (Round 3 vs prior)

| Metric                                            | Live #1 / Phase −1 | Round 2  | Round 3 (target) |
|--------------------------------------------------|--------------------|----------|------------------|
| End-of-utterance latency (silence → final text)  | 1.0–1.5 s          | 3.0 s    | **~1.0 s**       |
| Long-utterance fragmentation rate                | ~30%               | ~5%      | ~5%              |
| Echo transcripts as ghost user input             | many               | rare     | **~0**           |
| WebSocket idle disconnect rate (per long reply)  | occasional         | occasional | **0**          |
| Voice-timbre drift across one reply              | high               | medium   | **low**          |

Empirical validation TBD — needs a real conversation run with timing
instrumentation. Adding latency markers to `voice_test.py` is a
follow-up enhancement.
