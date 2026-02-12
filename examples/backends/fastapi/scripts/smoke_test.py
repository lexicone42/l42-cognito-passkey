#!/usr/bin/env python3
"""Smoke test for a deployed L42 Token Handler backend.

Hits key endpoints and reports pass/fail status. Exits 0 if all pass, 1 otherwise.

Usage:
    python scripts/smoke_test.py --base-url http://localhost:3001

With authentication (requires valid tokens):
    python scripts/smoke_test.py --base-url http://localhost:3001 \
        --access-token <TOKEN> --id-token <TOKEN>
"""

from __future__ import annotations

import argparse
import json
import sys
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError


def _request(
    url: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: dict | None = None,
    cookies: str = "",
) -> tuple[int, dict, dict[str, str]]:
    """Make an HTTP request and return (status, body_dict, response_headers)."""
    headers = headers or {}
    if cookies:
        headers["Cookie"] = cookies

    data = None
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"

    req = Request(url, data=data, headers=headers, method=method)
    try:
        resp = urlopen(req)
        resp_body = json.loads(resp.read().decode())
        resp_headers = {k.lower(): v for k, v in resp.getheaders()}
        return resp.status, resp_body, resp_headers
    except HTTPError as e:
        try:
            resp_body = json.loads(e.read().decode())
        except Exception:
            resp_body = {"error": str(e)}
        return e.code, resp_body, {}


def _extract_cookies(headers: dict[str, str]) -> str:
    """Extract Set-Cookie values for reuse."""
    cookie = headers.get("set-cookie", "")
    if cookie:
        # Take just the cookie name=value part
        return cookie.split(";")[0]
    return ""


def main():
    parser = argparse.ArgumentParser(description="Smoke test for L42 Token Handler")
    parser.add_argument("--base-url", required=True, help="Base URL (e.g., http://localhost:3001)")
    parser.add_argument("--access-token", help="Valid access token for authenticated tests")
    parser.add_argument("--id-token", help="Valid ID token for authenticated tests")
    args = parser.parse_args()

    base = args.base_url.rstrip("/")
    results: list[tuple[str, bool, str]] = []
    cookies = ""

    # 1. Health check
    try:
        status, body, _ = _request(f"{base}/health")
        ok = status == 200 and body.get("status") == "ok"
        detail = f"status={status} cedar={body.get('cedar', '?')}"
        results.append(("GET /health", ok, detail))
    except (URLError, ConnectionError) as e:
        results.append(("GET /health", False, f"Connection failed: {e}"))
        _print_results(results)
        sys.exit(1)

    # Authenticated tests (optional)
    if args.access_token and args.id_token:
        # 2. POST /auth/session
        status, body, headers = _request(
            f"{base}/auth/session",
            method="POST",
            headers={"X-L42-CSRF": "1"},
            body={
                "access_token": args.access_token,
                "id_token": args.id_token,
            },
        )
        ok = status == 200 and body.get("success") is True
        results.append(("POST /auth/session", ok, f"status={status}"))
        cookies = _extract_cookies(headers)

        if ok and cookies:
            # 3. GET /auth/token
            status, body, _ = _request(f"{base}/auth/token", cookies=cookies)
            ok = status == 200 and "access_token" in body
            results.append(("GET /auth/token", ok, f"status={status}"))

            # 4. GET /auth/me
            status, body, _ = _request(f"{base}/auth/me", cookies=cookies)
            ok = status == 200 and "sub" in body
            results.append(("GET /auth/me", ok, f"status={status} sub={body.get('sub', '?')}"))

            # 5. POST /auth/logout
            status, body, _ = _request(
                f"{base}/auth/logout",
                method="POST",
                headers={"X-L42-CSRF": "1"},
                cookies=cookies,
            )
            ok = status == 200
            results.append(("POST /auth/logout", ok, f"status={status}"))

            # 6. Verify logged out
            status, body, _ = _request(f"{base}/auth/token", cookies=cookies)
            ok = status == 401
            results.append(("GET /auth/token (after logout)", ok, f"status={status}"))
    else:
        print("  (skipping authenticated tests — no tokens provided)\n")

    _print_results(results)
    sys.exit(0 if all(ok for _, ok, _ in results) else 1)


def _print_results(results: list[tuple[str, bool, str]]):
    print("\n--- Smoke Test Results ---\n")
    for name, ok, detail in results:
        icon = "PASS" if ok else "FAIL"
        print(f"  [{icon}] {name:<35} {detail}")

    passed = sum(1 for _, ok, _ in results if ok)
    total = len(results)
    print(f"\n  {passed}/{total} passed\n")


if __name__ == "__main__":
    main()
