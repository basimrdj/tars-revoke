# MiMo Expressive TTS Runtime

Default runtime TTS is now MiMo VoiceDesign:

```dotenv
TARS_TTS_PROVIDER=mimo
MIMO_TTS_MODEL=mimo-v2.5-tts-voicedesign
MIMO_TTS_VOICE=Milo
MIMO_TTS_FORMAT=wav
MIMO_TTS_EXPRESSIVE=1
MIMO_TTS_STREAM=1
TARS_STREAM_MIN_CHARS=55
TARS_STREAM_HARD_CHARS=130
TARS_STREAM_EARLY_SENTENCE_CHARS=28
```

## What The PDF Guide Changes

The guide's strongest pattern is:

- `user` message: a director-style voice and scene description.
- `assistant` message: the exact words to speak.
- Inline parenthetical acting tags for local emotion, breath, pause, and pace.

The runtime now follows that shape for `mimo-v2.5-tts-voicedesign`.
For fixed-voice `mimo-v2.5-tts`, the same director prompt is still sent, but
`audio.voice` remains controlled by `MIMO_TTS_VOICE`.

## Speed Model

MiMo accepts `stream: true` on `/chat/completions`, but current API probing
shows the audio still arrives as one complete base64 audio blob instead of
incremental PCM frames. The app still enables MiMo SSE by default so the path is
ready if MiMo starts chunking later.

Current perceived speed comes from the existing live TTS pipeline:

- the LLM reply is split into early clause/sentence chunks;
- the first chunk is requested as soon as it is usable;
- the next chunk is prefetched while the current chunk plays;
- each MiMo response is cached by provider, model, voice, format, expressive
  mode, stream mode, style prompt hash, and spoken text.

## Switching Providers

Use MiMo expressive voice:

```dotenv
TARS_TTS_PROVIDER=mimo
MIMO_TTS_MODEL=mimo-v2.5-tts-voicedesign
```

Use MiMo fixed built-in voice:

```dotenv
TARS_TTS_PROVIDER=mimo
MIMO_TTS_MODEL=mimo-v2.5-tts
MIMO_TTS_VOICE=Milo
```

Use Deepgram low-latency streaming:

```dotenv
TARS_TTS_PROVIDER=deepgram
DEEPGRAM_TTS_MODEL=aura-2-atlas-en
```

Override the built-in MiMo style prompt only when testing a new personality:

```dotenv
MIMO_TTS_STYLE_PROMPT=Director mode. Character: ...
```
