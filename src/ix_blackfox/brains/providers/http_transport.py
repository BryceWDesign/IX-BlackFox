from __future__ import annotations

import json
import socket
from collections.abc import Callable
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

JsonPostTransport = Callable[
    [str, dict[str, str], dict[str, Any], float | None],
    dict[str, Any],
]
JsonGetTransport = Callable[
    [str, dict[str, str], float | None],
    dict[str, Any],
]


def build_json_post_transport(
    *,
    user_agent: str = "IX-BlackFox/0.1",
) -> JsonPostTransport:
    """
    Build a JSON POST transport backed by Python's standard library.
    """

    def transport(
        url: str,
        headers: dict[str, str],
        payload: dict[str, Any],
        timeout_seconds: float | None,
    ) -> dict[str, Any]:
        return _perform_json_request(
            method="POST",
            url=url,
            headers=headers,
            body=payload,
            timeout_seconds=timeout_seconds,
            user_agent=user_agent,
        )

    return transport


def build_json_get_transport(
    *,
    user_agent: str = "IX-BlackFox/0.1",
) -> JsonGetTransport:
    """
    Build a JSON GET transport backed by Python's standard library.
    """

    def transport(
        url: str,
        headers: dict[str, str],
        timeout_seconds: float | None,
    ) -> dict[str, Any]:
        return _perform_json_request(
            method="GET",
            url=url,
            headers=headers,
            body=None,
            timeout_seconds=timeout_seconds,
            user_agent=user_agent,
        )

    return transport


def _perform_json_request(
    *,
    method: str,
    url: str,
    headers: dict[str, str],
    body: dict[str, Any] | None,
    timeout_seconds: float | None,
    user_agent: str,
) -> dict[str, Any]:
    request_headers = dict(headers)
    request_headers.setdefault("Accept", "application/json")
    request_headers.setdefault("User-Agent", user_agent)

    data: bytes | None = None
    if body is not None:
        request_headers.setdefault("Content-Type", "application/json")
        data = json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode(
            "utf-8"
        )

    request = Request(
        url=url,
        data=data,
        headers=request_headers,
        method=method,
    )
    timeout = 60.0 if timeout_seconds is None else float(timeout_seconds)

    try:
        with urlopen(request, timeout=timeout) as response:
            payload = _decode_json_payload(response.read())
            if payload is None:
                return {}
            if not isinstance(payload, dict):
                return {"data": payload}
            return payload
    except HTTPError as exc:
        payload = _decode_json_payload(exc.read())
        if isinstance(payload, dict):
            payload.setdefault("status_code", exc.code)
            payload.setdefault("reason", str(exc.reason))
            return payload
        raise ConnectionError(f"HTTP {exc.code} returned from {url}.") from exc
    except URLError as exc:
        reason = exc.reason
        if isinstance(reason, TimeoutError | socket.timeout):
            raise TimeoutError(f"Request to {url} timed out.") from exc
        raise ConnectionError(f"Request to {url} failed: {reason}") from exc
    except TimeoutError as exc:
        raise TimeoutError(f"Request to {url} timed out.") from exc


def _decode_json_payload(raw: bytes) -> Any:
    if not raw:
        return {}

    text = raw.decode("utf-8", errors="replace").strip()
    if not text:
        return {}

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {"message": text}
