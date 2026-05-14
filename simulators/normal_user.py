import time
import random
import requests

BASE_URL = "http://localhost:3001/api"
RESET_URL = f"{BASE_URL}/security/reset"

ENDPOINTS = ["/products", "/profile", "/products", "/profile"]
TOKENS = ["user-alice", "user-bob", "user-charlie"]

NUM_REQUESTS = 15

def main():
    print("=" * 70)
    print("[NORMAL USER] Starting normal user simulation")
    print(f"[NORMAL USER] Target: {BASE_URL}")
    print(f"[NORMAL USER] Requests: {NUM_REQUESTS}")
    print("=" * 70)

    # Reset security state
    try:
        requests.post(RESET_URL, timeout=3)
        print("[NORMAL USER] Security state reset OK")
    except Exception:
        print("[NORMAL USER] Could not reset security state (continuing)")

    print("-" * 70)

    for i in range(1, NUM_REQUESTS + 1):
        endpoint = random.choice(ENDPOINTS)
        token = random.choice(TOKENS)
        url = f"{BASE_URL}{endpoint}"

        try:
            resp = requests.get(
                url,
                headers={
                    "Authorization": f"Bearer {token}",
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
                f"[NORMAL] #{i:02d} {endpoint:12s} -> {resp.status_code} | "
                f"action={action:12s} prediction={str(prediction):15s} "
                f"confidence={confidence}"
            )

            if resp.status_code == 403:
                print("[NORMAL] BLOCKED -- stopping")
                break
            if resp.status_code == 429:
                retry = body.get("retry_after_seconds", 10)
                print(f"[NORMAL] RATE LIMITED -- retry after {retry}s")
                break

        except requests.exceptions.ConnectionError:
            print(f"[NORMAL] #{i:02d} Connection failed -- is backend running on port 3001?")
            break

        delay = random.uniform(1.5, 4.0)
        time.sleep(delay)

    print("-" * 70)
    print("[NORMAL USER] Simulation complete")


if __name__ == "__main__":
    main()
