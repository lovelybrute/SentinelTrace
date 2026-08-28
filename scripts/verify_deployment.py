#!/usr/bin/env python3
"""Read-only deployment smoke tests for the SentinelTrace production stack."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Callable

DEFAULT_FRONTEND = "https://sentinel-trace.vercel.app"
DEFAULT_BACKEND = "https://sentineltrace-backend.onrender.com"
ALLOWED_VERDICTS = {"low_risk", "caution", "suspicious", "dangerous", "unknown"}


class CheckFailure(RuntimeError):
    pass


def fetch(url: str, attempts: int, delay: float) -> tuple[int, str, str]:
    last_error: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            request = urllib.request.Request(
                url,
                headers={
                    "Accept": "application/json, text/html;q=0.9",
                    "User-Agent": "SentinelTrace-E2E/1.0",
                },
            )
            with urllib.request.urlopen(request, timeout=45) as response:
                return response.status, response.headers.get("Content-Type", ""), response.read().decode("utf-8")
        except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
            last_error = exc
            if attempt < attempts:
                time.sleep(delay)
    raise CheckFailure(f"request failed after {attempts} attempts: {last_error}")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise CheckFailure(message)


def json_body(body: str, label: str) -> dict[str, Any]:
    try:
        value = json.loads(body)
    except json.JSONDecodeError as exc:
        raise CheckFailure(f"{label} did not return valid JSON: {exc}") from exc
    require(isinstance(value, dict), f"{label} must return a JSON object")
    return value


def check_frontend(frontend: str, attempts: int, delay: float) -> dict[str, Any]:
    status, content_type, body = fetch(frontend + "/", attempts, delay)
    require(status == 200, f"frontend returned HTTP {status}")
    require("text/html" in content_type.lower(), f"frontend returned {content_type!r}, expected HTML")
    require("sentinel" in body.lower(), "frontend HTML does not contain the SentinelTrace application marker")
    return {"status": status, "content_type": content_type}


def check_root(backend: str, attempts: int, delay: float) -> dict[str, Any]:
    status, _, body = fetch(backend + "/", attempts, delay)
    data = json_body(body, "backend root")
    require(status == 200, f"backend root returned HTTP {status}")
    require(str(data.get("status", "")).lower() == "online", "backend root is not online")
    require(data.get("project"), "backend root is missing project identity")
    return {"status": status, "project": data["project"], "version": data.get("version")}


def check_health(backend: str, attempts: int, delay: float) -> dict[str, Any]:
    status, _, body = fetch(backend + "/health", attempts, delay)
    data = json_body(body, "health endpoint")
    require(status == 200, f"health endpoint returned HTTP {status}")
    require(str(data.get("status", "")).lower() == "healthy", f"backend health is {data.get('status')!r}")
    return {"status": status, "database": data.get("database", data.get("database_status", "reported healthy"))}


def check_metrics(backend: str, attempts: int, delay: float) -> dict[str, Any]:
    status, _, body = fetch(backend + "/model/metrics", attempts, delay)
    data = json_body(body, "model metrics")
    require(status == 200, f"model metrics returned HTTP {status}")
    require(data.get("validation_status") == "VALIDATED_HOLDOUT", "model is not marked VALIDATED_HOLDOUT")
    require(int(data.get("dataset_records", 0)) > 0, "model metrics contain no dataset records")
    models = data.get("models", {})
    require(isinstance(models, dict) and models, "model metrics contain no evaluated models")
    return {
        "status": status,
        "validation_status": data["validation_status"],
        "dataset_records": data["dataset_records"],
        "selected_model": data.get("selected_model"),
    }


def check_guardian(backend: str, attempts: int, delay: float) -> dict[str, Any]:
    query = urllib.parse.urlencode({"domain": "example.org"})
    status, _, body = fetch(f"{backend}/guardian/check?{query}", attempts, delay)
    data = json_body(body, "Guardian endpoint")
    require(status == 200, f"Guardian endpoint returned HTTP {status}")
    require(data.get("domain") == "example.org", "Guardian returned a different normalized domain")
    require(data.get("verdict") in ALLOWED_VERDICTS, f"unsupported Guardian verdict: {data.get('verdict')!r}")
    score = data.get("risk_score")
    require(isinstance(score, (int, float)) and 0 <= score <= 100, "Guardian risk_score must be between 0 and 100")
    require(data.get("privacy"), "Guardian response is missing its privacy disclosure")
    return {"status": status, "verdict": data["verdict"], "risk_score": score, "cache": data.get("cache")}


def check_openapi(backend: str, attempts: int, delay: float) -> dict[str, Any]:
    status, _, body = fetch(backend + "/openapi.json", attempts, delay)
    data = json_body(body, "OpenAPI endpoint")
    require(status == 200, f"OpenAPI endpoint returned HTTP {status}")
    paths = data.get("paths", {})
    required = {"/", "/health", "/analyze", "/model/metrics", "/guardian/check"}
    missing = sorted(required.difference(paths))
    require(not missing, f"OpenAPI is missing required paths: {', '.join(missing)}")
    return {"status": status, "required_paths": sorted(required), "path_count": len(paths)}


def secure_base_url(value: str, allow_http: bool) -> str:
    value = value.rstrip("/")
    parsed = urllib.parse.urlparse(value)
    require(parsed.scheme in ({"http", "https"} if allow_http else {"https"}), "deployment URLs must use HTTPS")
    require(bool(parsed.netloc), f"invalid base URL: {value!r}")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--frontend", default=os.getenv("SENTINELTRACE_FRONTEND_URL", DEFAULT_FRONTEND))
    parser.add_argument("--backend", default=os.getenv("SENTINELTRACE_BACKEND_URL", DEFAULT_BACKEND))
    parser.add_argument("--attempts", type=int, default=6, help="Attempts per request; useful for Render cold starts")
    parser.add_argument("--delay", type=float, default=15.0, help="Seconds between attempts")
    parser.add_argument("--json-out", type=Path, help="Optional machine-readable report path")
    parser.add_argument("--allow-http", action="store_true", help="Allow HTTP for local testing only")
    args = parser.parse_args()

    try:
        frontend = secure_base_url(args.frontend, args.allow_http)
        backend = secure_base_url(args.backend, args.allow_http)
        require(args.attempts >= 1, "attempts must be at least 1")
        require(args.delay >= 0, "delay cannot be negative")
    except CheckFailure as exc:
        print(f"[FAIL] configuration: {exc}")
        return 2

    checks: list[tuple[str, Callable[[], dict[str, Any]]]] = [
        ("frontend", lambda: check_frontend(frontend, args.attempts, args.delay)),
        ("backend_root", lambda: check_root(backend, args.attempts, args.delay)),
        ("backend_health", lambda: check_health(backend, args.attempts, args.delay)),
        ("model_metrics", lambda: check_metrics(backend, args.attempts, args.delay)),
        ("guardian", lambda: check_guardian(backend, args.attempts, args.delay)),
        ("openapi_contract", lambda: check_openapi(backend, args.attempts, args.delay)),
    ]

    report: dict[str, Any] = {"frontend": frontend, "backend": backend, "checks": {}, "passed": True}
    for name, run in checks:
        try:
            detail = run()
            report["checks"][name] = {"passed": True, "detail": detail}
            print(f"[PASS] {name}: {detail}")
        except Exception as exc:
            report["checks"][name] = {"passed": False, "error": str(exc)}
            report["passed"] = False
            print(f"[FAIL] {name}: {exc}")

    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    print("Deployment verification passed." if report["passed"] else "Deployment verification failed.")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
