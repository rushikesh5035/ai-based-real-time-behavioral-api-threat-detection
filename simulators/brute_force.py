import requests
import time

URL = "http://localhost:3000/api/login"

print("🔴 Starting Brute Force Attack")

for i in range(100):
    try:
        response = requests.post(URL, timeout=5)
        status = response.status_code
    except Exception as e:
        status = str(e)

    print(f"[ATTACK] Request {i+1} ->", status)

    # Very small delay
    time.sleep(0.1)
