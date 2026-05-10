# Simulators

These scripts are for demo traffic generation.

## Normal user simulation

```bash
python normal_user.py
```

## Brute force simulation

```bash
python brute_force.py
```

## API flood simulation

```bash
python api_flood.py
```

Notes:

- The scripts assume a backend listening on `http://localhost:3000`.
- Install the Python dependency used by the scripts:

```bash
pip install requests
```
