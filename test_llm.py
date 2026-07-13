import os
import sys
import requests
from dotenv import load_dotenv

load_dotenv()

api_key = os.getenv("MIMO_API_KEY")
base_url = os.getenv("MIMO_BASE_URL", "https://token-plan-sgp.xiaomimimo.com/v1")

url = base_url.rstrip("/") + "/chat/completions"
headers = {
    "Authorization": f"Bearer {api_key}",
    "Content-Type": "application/json"
}

payload = {
    "model": "MiMo-V2.5-Pro",
    "messages": [
        {"role": "user", "content": "Hello"}
    ]
}

resp = requests.post(url, headers=headers, json=payload)
print(f"Status: {resp.status_code}")
print(resp.text)
