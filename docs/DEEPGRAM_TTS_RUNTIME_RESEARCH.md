# Deepgram/MiMo Runtime Speed Notes

Generated: 2026-04-30

## Decision

Keep VibeVoice out of the default path for now. Use Deepgram for speech and
MiMo for the brain:

- TTS provider: `deepgram`
- TTS voice model: `aura-2-zeus-en`
- TTS live playback: REST response streaming, `linear16`, `container=none`,
  `sample_rate=24000`
- Brain model: `mimo-v2.5`
- STT model: `nova-3` for the stable SDK path. Flux remains implemented as an
  opt-in env switch, but it timed out on this network during live boot.

## Why

Deepgram's docs recommend streaming TTS audio as soon as the first byte arrives
instead of waiting for the whole file. They also document sentence/chunked text
handling for lower perceived latency, and `linear16` output for both REST and
streaming. The previous app path requested Deepgram with `stream=True`, but it
still buffered the whole response into a WAV before playback. That threw away
the main latency win.

Reference docs:

- Streaming REST audio output:
  https://developers.deepgram.com/docs/streaming-the-audio-output
- TTS latency guidance:
  https://developers.deepgram.com/docs/text-to-speech-latency
- Text chunking:
  https://developers.deepgram.com/docs/tts-text-chunking
- Voice/model list:
  https://developers.deepgram.com/docs/tts-models
- Encoding/container/sample-rate settings:
  https://developers.deepgram.com/docs/tts-encoding
  https://developers.deepgram.com/docs/tts-container
  https://developers.deepgram.com/docs/tts-sample-rate

## Local Benchmarks

Short text benchmark with `linear16`, `sample_rate=24000`, `container=none`:

| Model | First byte | Total response |
|---|---:|---:|
| `aura-zeus-en` | 314 ms | 617 ms |
| `aura-orion-en` | 391 ms | 682 ms |
| `aura-2-zeus-en` | 354 ms | 2360 ms |
| `aura-2-pluto-en` | 390 ms | 1863 ms |
| `aura-2-orion-en` | 386 ms | 1963 ms |

MiMo chat benchmark, one short streamed reply:

| Model | First token | Total |
|---|---:|---:|
| `mimo-v2-omni` | 938 ms | 1201 ms |
| `mimo-v2.5` | 961 ms | 1340 ms |
| `mimo-v2.5-pro` | 1195 ms | 1574 ms |
| `mimo-v2-pro` | 1739 ms | 2128 ms |

`mimo-v2.5` is the current default because it keeps the newer 2.5 family while
cutting latency versus `mimo-v2.5-pro`.

## STT Decision

Deepgram Flux is architecturally the fastest fit for a voice agent because it
has model-native end-of-turn detection. In this local network run, Flux
handshakes timed out during boot, while Nova-3 connected reliably through the
same Deepgram edge host. The active default is therefore `nova-3` with 80 ms
microphone chunks; Flux remains available by setting
`DEEPGRAM_STT_MODEL=flux-general-en`.

## Implementation Notes

- `TARS_TTS_PROVIDER` is now stripped before parsing, so `deepgram ` does not
  accidentally miss the Deepgram branch.
- Deepgram live replies use `_play_streaming_deepgram()`, which streams raw
  PCM chunks directly into `sounddevice`.
- Full WAV fetching remains for cache/preload and fallback.
- `aura-2-zeus-en` is the active voice because Orion was fast but too flat.
  Aura-2 Zeus keeps a deep TARS-like tone while using the more expressive Aura-2
  model family. Because playback streams from first PCM, perceived start time
  remains close to the faster Aura-1 voices.
- On this network, the router resolver failed for `api.deepgram.com` while the
  Deepgram edge hostname still resolved. Runtime `.env` routes both STT and TTS
  through `https://api.sac1.deepgram.com`.
