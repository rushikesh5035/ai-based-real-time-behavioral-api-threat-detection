"""
Brute Force Attack Simulator
Simulates rapid repeated login attempts -- classic credential stuffing attack.

Expected escalation: ALLOW (warmup) -> RATE_LIMIT -> BLOCK
"""

import time
import requests

BASE_URL = "http://localhost:3001/api"
RESET_URL = f"{BASE_URL}/security/reset"

LOGIN_URL = f"{BASE_URL}/login"
NUM_REQUESTS = 15
DELAY = 0.08  # 80ms between attempts -- very fast


def main():
    print("=" * 70)
    print("[BRUTE FORCE] Starting brute-force attack simulation")
    print(f"[BRUTE FORCE] Target: {LOGIN_URL}")
    print(f"[BRUTE FORCE] Requests: {NUM_REQUESTS} at {DELAY}s interval")
    print("=" * 70)

    # Reset security state
    try:
        requests.post(RESET_URL, timeout=3)
        print("[BRUTE FORCE] Security state reset OK")
    except Exception:
        print("[BRUTE FORCE] Could not reset security state (continuing)")

    print("-" * 70)

    for i in range(1, NUM_REQUESTS + 1):
        try:
            resp = requests.post(
                LOGIN_URL,
                headers={
                    "Authorization": "Bearer stolen-token-brute",
                    "X-Login-Failed": "1",
                },
                json={"username": "admin", "password": f"guess{i:04d}"},
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
                f"[BRUTE] #{i:02d} /login -> {resp.status_code} | "
                f"action={action:12s} prediction={str(prediction):15s} "
                f"confidence={confidence}  policy={policy}"
            )

            if resp.status_code == 403:
                print(f"\n[BRUTE FORCE] IP BLOCKED after {i} requests -- attack fully stopped!")
                break

        except requests.exceptions.ConnectionError:
            print(f"[BRUTE] #{i:02d} Connection failed -- is backend running on port 3001?")
            break

        time.sleep(DELAY)

    print("-" * 70)
    print("[BRUTE FORCE] Simulation complete")


if __name__ == "__main__":
    main()
