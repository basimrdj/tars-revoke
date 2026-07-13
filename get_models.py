import os
import requests
from dotenv import load_dotenv

load_dotenv()
api_key = os.getenv("MIMO_API_KEY")
base_url = os.getenv("MIMO_BASE_URL", "https://token-plan-sgp.xiaomimimo.com/v1")

url = base_url.rstrip("/") + "/models"
headers = {"Authorization": f"Bearer {api_key}"}

resp = requests.get(url, headers=headers)
if resp.status_code == 200:
    for m in resp.json().get("data", []):
        print(m["id"])
else:
    print(resp.text)
