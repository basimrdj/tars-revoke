# VibeVoice Realtime Runtime Notes

Generated: 2026-04-30

## Current Finding

VibeVoice Realtime loads on this Mac through PyTorch MPS, but generation is not
stable on the current local runtime. The worker reaches model/voice load, then
crashes during the first audio generation with an Apple MPSGraph matmul shape
error:

```text
LLVM ERROR: Failed to infer result type(s):
"mps.matmul"(...) : (tensor<1x14x1x64xf32>, tensor<1x2x64x322xf32>) -> ( ??? )
```

That means the old `READY` signal was too weak: it only proved the model loaded,
not that realtime PCM could be produced. The worker now runs a tiny boot-time
generation smoke check before sending `READ`. If MPS crashes, the parent sees
the subprocess exit before ready and keeps the assistant on fallback TTS.

## Official Reference Checked

- Microsoft VibeVoice Realtime docs:
  https://github.com/microsoft/VibeVoice/blob/main/docs/vibevoice-realtime-0.5b.md
- Official file inference demo:
  https://github.com/microsoft/VibeVoice/blob/main/demo/realtime_model_inference_from_file.py
- PyTorch MPS environment variables:
  https://docs.pytorch.org/docs/stable/mps_environment_variables.html

The official VibeVoice demo selects `mps` when available, uses `torch.float32`
and `sdpa` on MPS, and loads the model on CPU before moving it to MPS. The local
worker follows that pattern. The docs also call out NVIDIA T4 and Mac M4 Pro as
tested real-time targets, so weaker Apple Silicon machines may need more runtime
testing or fallback.

## Runtime Policy

- Default device remains auto: CUDA > Apple MPS > CPU.
- `VIBEVOICE_BOOT_SMOKE` defaults on so the worker must emit an audio chunk
  before it is marked ready.
- In auto-device mode, `VIBEVOICE_AUTO_CPU_FALLBACK=1` retries CPU if the MPS
  worker dies before `READ`.
- `VIBEVOICE_DEVICE=cpu` is supported for a stable local fallback path, but CPU
  is not expected to be truly realtime.
- `PYTORCH_ENABLE_MPS_FALLBACK=1` is set for the worker. This helps unsupported
  MPS ops, but it does not recover from the fatal MPSGraph shape crash observed
  above because that aborts in native code.

## Verification

```bash
python3 -m py_compile tars_vibevoice/worker.py tars_vibevoice_speaker.py

python3 - <<'PY'
from tars_vibevoice_speaker import VibeVoiceTTS
v = VibeVoiceTTS(log_fn=print)
print(v.start())
v.shutdown()
PY
```

Expected on the current Mac MPS runtime: worker exits before READY and returns
`False` for the MPS attempt, then auto-retries CPU unless disabled.

CPU override check:

```bash
VIBEVOICE_DEVICE=cpu VIBEVOICE_BOOT_SMOKE=0 python3 - <<'PY'
from tars_vibevoice_speaker import VibeVoiceTTS
v = VibeVoiceTTS(log_fn=print)
print(v.start())
v.shutdown()
PY
```

Expected: worker logs `device=cpu` and returns `True`.
