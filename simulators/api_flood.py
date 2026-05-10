import requests

URL = "http://localhost:3000/api/products"

print("🔥 Starting API Flood")

for i in range(500):
    try:
        response = requests.get(URL, timeout=5)
        status = response.status_code
    except Exception as e:
        status = str(e)

    print(f"[FLOOD] Request {i+1} ->", status)
