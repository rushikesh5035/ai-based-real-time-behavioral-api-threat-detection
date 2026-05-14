import time

import requests

URL = "http://localhost:3000/api/login"
RESET_URL = "http://localhost:3000/api/security/reset"


def try_reset() -> None:
    try:
        requests.post(RESET_URL, timeout=5)
    except Exception:
        pass


print("[BRUTE] Starting brute-force simulation")
try_reset()

for i in range(60):
    try:
        response = requests.post(URL, headers={"x-login-failed": "1"}, timeout=5)
        body = response.json() if response.headers.get("content-type", "").startswith("application/json") else {}
        extra = ""
        if isinstance(body, dict) and body.get("action"):
            extra = f" | action={body.get('action')} prediction={body.get('prediction')}"
        print(f"[BRUTE] #{i+1:02d} -> {response.status_code}{extra}")

        if response.status_code in (403, 429):
            break
    except Exception as exc:
        print(f"[BRUTE] #{i+1:02d} -> ERROR: {exc}")

    time.sleep(0.08)
