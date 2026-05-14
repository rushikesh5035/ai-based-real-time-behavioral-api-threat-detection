"""
Token Abuse Attack Simulator
Simulates a stolen/leaked token being reused across many requests to sensitive endpoints.

Expected escalation: ALLOW (warmup) -> ALERT (suspicious) -> RATE_LIMIT (escalation) -> BLOCK
"""

import time
import requests

BASE_URL = "http://localhost:3001/api"
RESET_URL = f"{BASE_URL}/security/reset"

STOLEN_TOKEN = "Bearer leaked-admin-token-xyz"
ENDPOINTS = ["/profile", "/products", "/profile", "/profile", "/products"]
NUM_REQUESTS = 20
DELAY = 0.5  # 500ms -- moderate speed, not a flood but persistent


def main():
    print("=" * 70)
    print("[TOKEN ABUSE] Starting token abuse simulation")
    print(f"[TOKEN ABUSE] Target: {BASE_URL}")
    print(f"[TOKEN ABUSE] Requests: {NUM_REQUESTS} reusing same stolen token")
    print("=" * 70)

    # Reset security state
    try:
        requests.post(RESET_URL, timeout=3)
        print("[TOKEN ABUSE] Security state reset OK")
    except Exception:
        print("[TOKEN ABUSE] Could not reset security state (continuing)")

    print("-" * 70)

    for i in range(1, NUM_REQUESTS + 1):
        endpoint = ENDPOINTS[i % len(ENDPOINTS)]
        url = f"{BASE_URL}{endpoint}"

        try:
            resp = requests.get(
                url,
                headers={
                    "Authorization": STOLEN_TOKEN,
                },
                timeout=5,
            )

            try:
                body = resp.json()
            except Exception:
                body = {}

            action = body.get("action", "ALLOW" if resp.status_code == 200 else "UNKNOWN")
            prediction = body.get("prediction", "-")
            confidence = body.get("confidence", "-")
            policy = body.get("policy_reason", body.get("message", "-"))

            print(
                f"[TOKEN] #{i:02d} {endpoint:12s} -> {resp.status_code} | "
                f"action={action:12s} prediction={str(prediction):15s} "
                f"confidence={confidence}  policy={policy}"
            )

            if resp.status_code == 403:
                print(f"\n[TOKEN ABUSE] IP BLOCKED after {i} requests -- token abuse fully stopped!")
                break

        except requests.exceptions.ConnectionError:
            print(f"[TOKEN] #{i:02d} Connection failed -- is backend running on port 3001?")
            break

        time.sleep(DELAY)

    print("-" * 70)
    print("[TOKEN ABUSE] Simulation complete")


if __name__ == "__main__":
    main()
