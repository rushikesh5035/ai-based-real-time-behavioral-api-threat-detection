# Simulators

These scripts generate demo traffic against the backend (`http://localhost:3001`).

## Prerequisites

- Backend running on port `3001`
- FastAPI model service running on port `8001`
- Python dependency:

```bash
pip install requests
```

## Scripts

### 1) Normal user simulation

```bash
python normal_user.py
```

- Sends mixed `/api/profile` and `/api/products` calls with human-like delays.
- Prints status and any decision metadata returned by backend.

### 2) Brute-force simulation

```bash
python brute_force.py
```

- Sends repeated `/api/login` with `x-login-failed: 1` header.
- Stops early when backend returns `429` or `403`.

### 3) API flood simulation

```bash
python api_flood.py
```

- Sends rapid `/api/products` traffic.
- Stops early when backend returns `429` or `403`.

### 4) Real-time behavioral burst demo

```bash
python behavioral_burst.py
```

- Runs normal traffic, brute-force hints, and flood bursts in one script.
- Best for showing how the backend responds to changing request behavior over time.

### 5) FastAPI 4-payload validation (Swagger-equivalent)

```bash
python fastapi_4_payloads.py
```

- Sends the same 4 payloads used in Swagger directly to FastAPI `/predict`.
- Use this for deterministic `ALLOW / ALERT / BLOCK` policy proof at ML-service level.

### 6) Backend 4-outcome behavioral run

```bash
python backend_4_outcomes.py
```

- Runs an exam-stable sequence:
  - `ALLOW` and `RATE_LIMIT` via backend middleware flow
  - `BLOCK` and `ALERT` via deterministic FastAPI payload proof
- Prints one compact result line per outcome.

## Notes

- Each script tries to call `/api/security/reset` before starting.
- The scripts default to `http://localhost:3001/api`; set `BACKEND_BASE_URL` if your backend runs somewhere else.
- If reset or test endpoints return `429`/`403`, verify backend middleware bypass for reset is active.
