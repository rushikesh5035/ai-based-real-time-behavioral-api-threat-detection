import requests

URL = "http://localhost:3000/api/products"
RESET_URL = "http://localhost:3000/api/security/reset"


def try_reset() -> None:
    try:
        requests.post(RESET_URL, timeout=5)
    except Exception:
        pass


print("[FLOOD] Starting API flood simulation")
try_reset()

for i in range(200):
    try:
        response = requests.get(URL, timeout=5)
        body = response.json() if response.headers.get("content-type", "").startswith("application/json") else {}
        extra = ""
        if isinstance(body, dict) and body.get("action"):
            extra = f" | action={body.get('action')} prediction={body.get('prediction')}"
        print(f"[FLOOD] #{i+1:03d} -> {response.status_code}{extra}")

        if response.status_code in (403, 429):
            break
    except Exception as exc:
        print(f"[FLOOD] #{i+1:03d} -> ERROR: {exc}")
