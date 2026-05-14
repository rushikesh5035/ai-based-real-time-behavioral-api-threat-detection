import argparse
import random
import time
from typing import Iterable

import requests


DEFAULT_BASE_URL = "http://localhost:3000/api"
RESET_PATH = "/security/reset"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Burst traffic demo for the backend behavioral threat detector."
    )
    parser.add_argument(
        "--base-url",
        default=DEFAULT_BASE_URL,
        help="Backend API base URL, for example http://localhost:3000/api",
    )
    parser.add_argument(
        "--mode",
        choices=("all", "normal", "brute", "flood"),
        default="all",
        help="Which phase to run.",
    )
    parser.add_argument(
        "--pause",
        type=float,
        default=0.1,
        help="Pause between requests in seconds for brute and flood phases.",
    )
    return parser.parse_args()


def try_reset(session: requests.Session, base_url: str) -> None:
    try:
        session.post(f"{base_url}{RESET_PATH}", timeout=5)
    except Exception:
        pass


def print_response(prefix: str, index: int, route: str, response: requests.Response) -> None:
    extra = ""
    try:
        body = response.json()
    except Exception:
        body = {}

    if isinstance(body, dict) and body.get("action"):
        extra = (
            f" | action={body.get('action')}"
            f" prediction={body.get('prediction')}"
            f" confidence={body.get('confidence')}"
        )

    print(f"[{prefix}] #{index:02d} {route} -> {response.status_code}{extra}")


def run_normal_phase(session: requests.Session, base_url: str) -> None:
    print("[NORMAL] Starting normal-behavior phase")
    routes = ["/products", "/profile"]
    for index in range(1, 11):
        route = random.choice(routes)
        try:
            response = session.get(f"{base_url}{route}", timeout=5)
            print_response("NORMAL", index, route, response)
        except Exception as exc:
            print(f"[NORMAL] #{index:02d} {route} -> ERROR: {exc}")
        time.sleep(random.uniform(1.0, 2.5))


def run_brute_phase(session: requests.Session, base_url: str, pause: float) -> None:
    print("[BRUTE] Starting failed-login burst phase")
    for index in range(1, 31):
        try:
            response = session.post(
                f"{base_url}/login",
                headers={"x-login-failed": "1"},
                timeout=5,
            )
            print_response("BRUTE", index, "/login", response)
            if response.status_code in (403, 429):
                break
        except Exception as exc:
            print(f"[BRUTE] #{index:02d} /login -> ERROR: {exc}")
        time.sleep(pause)


def run_flood_phase(session: requests.Session, base_url: str, pause: float) -> None:
    print("[FLOOD] Starting API flood phase")
    routes = ["/products", "/profile", "/products"]
    for index in range(1, 61):
        route = routes[(index - 1) % len(routes)]
        try:
            response = session.get(f"{base_url}{route}", timeout=5)
            print_response("FLOOD", index, route, response)
            if response.status_code in (403, 429):
                break
        except Exception as exc:
            print(f"[FLOOD] #{index:02d} {route} -> ERROR: {exc}")
        time.sleep(pause)


def main(phases: Iterable[str], base_url: str, pause: float) -> None:
    session = requests.Session()
    try_reset(session, base_url)

    if "normal" in phases:
        run_normal_phase(session, base_url)
        try_reset(session, base_url)

    if "brute" in phases:
        run_brute_phase(session, base_url, pause)
        try_reset(session, base_url)

    if "flood" in phases:
        run_flood_phase(session, base_url, pause)


if __name__ == "__main__":
    arguments = parse_args()
    if arguments.mode == "all":
        selected_phases = ("normal", "brute", "flood")
    else:
        selected_phases = (arguments.mode,)
    main(selected_phases, arguments.base_url, arguments.pause)