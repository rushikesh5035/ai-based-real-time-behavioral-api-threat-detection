import random
import time

import requests

BASE_URL = "http://localhost:3000/api"
ROUTES = ["/products", "/profile"]
USER_TOKENS = ["user-alice", "user-bob", "user-charlie"]


def try_reset() -> None:
    try:
        requests.post(f"{BASE_URL}/security/reset", timeout=5)
    except Exception:
        pass


print("[NORMAL] Starting normal-user simulation")
try_reset()

for i in range(10):
    route = random.choice(ROUTES)
    url = BASE_URL + route
    token = random.choice(USER_TOKENS)
    headers = {"Authorization": f"Bearer {token}"}

    try:
        response = requests.get(url, headers=headers, timeout=5)
        body = response.json() if response.headers.get("content-type", "").startswith("application/json") else {}
        extra = ""
        if isinstance(body, dict) and body.get("action"):
            extra = f" | action={body.get('action')} prediction={body.get('prediction')}"
        print(f"[NORMAL] #{i+1:02d} {route} token={token} -> {response.status_code}{extra}")
    except Exception as exc:
        print(f"[NORMAL] #{i+1:02d} {route} -> ERROR: {exc}")

    # Human-like delay
    time.sleep(random.uniform(1.5, 4.0))
