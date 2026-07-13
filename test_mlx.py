import numpy as np
import mlx_whisper
audio = np.zeros(16000, dtype=np.float32)
try:
    res = mlx_whisper.transcribe(audio, path_or_hf_repo="mlx-community/whisper-small-mlx")
    print("Success:", res)
except Exception as e:
    print("Error:", e)
