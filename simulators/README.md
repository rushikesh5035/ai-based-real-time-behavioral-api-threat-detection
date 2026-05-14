# Simulators

These scripts generate demo traffic against the backend (`http://localhost:3000`).

## Prerequisites

- Backend running on port `3000`
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

## Notes

- Each script tries to call `/api/security/reset` before starting.
- If reset or test endpoints return `429`/`403`, verify backend middleware bypass for reset is active.
