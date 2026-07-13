import os
import sys
import requests
import base64
from dotenv import load_dotenv

load_dotenv()

api_key = os.getenv("MIMO_API_KEY")
base_url = os.getenv("MIMO_BASE_URL", "https://token-plan-sgp.xiaomimimo.com/v1")

if not api_key:
    print("No MIMO_API_KEY")
    sys.exit(1)

url = base_url.rstrip("/") + "/chat/completions"
headers = {
    "Authorization": f"Bearer {api_key}",
    "Content-Type": "application/json"
}

payload = {
    "model": "mimo-v2.5-tts",
    "messages": [
        {"role": "assistant", "content": "Hello, this is a test of MiMo TTS."}
    ],
    "audio": {
        "format": "wav",
        "voice": "mimo_default"
    }
}

print(f"Testing TTS with model: MiMo-V2.5-TTS")
resp = requests.post(url, headers=headers, json=payload)
print(f"Status: {resp.status_code}")
if resp.status_code == 200:
    data = resp.json()
    if "choices" in data and "audio" in data["choices"][0]["message"]:
        print("Success! Audio data received.")
    else:
        print("No audio data in response.")
        print(data)
else:
    print("Error:", resp.text)
