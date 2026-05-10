import requests
import time
import random

BASE_URL = "http://localhost:3000/api"

routes = [
    "/products",
    "/profile"
]

print("🟢 Starting Normal User Simulation")

for i in range(10):
    route = random.choice(routes)

    try:
        response = requests.get(BASE_URL + route, timeout=5)
        status = response.status_code
    except Exception as e:
        status = str(e)

    print(f"[NORMAL] {route} ->", status)

    # Human-like delay
    time.sleep(random.randint(5, 15))
