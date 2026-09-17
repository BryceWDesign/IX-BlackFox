from __future__ import annotations

import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Final


class UpstreamTransportError(RuntimeError):
    """Raised when the configured upstream cannot be reached safely."""


@dataclass(frozen=True, slots=True)
class UpstreamResponse:
    status: int
    headers: tuple[tuple[str, str], ...]
    body: bytes

    def header(self, name: str) -> str:
        lowered = name.lower()
        for key, value in self.headers:
            if key.lower() == lowered:
                return value
        return ""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: object,
        code: int,
        msg: str,
        headers: object,
        newurl: str,
    ) -> None:
        return None


_HOP_BY_HOP: Final[frozenset[str]] = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailers",
        "transfer-encoding",
        "upgrade",
        "host",
        "content-length",
    }
)


def request_upstream(
    *,
    url: str,
    method: str,
    headers: dict[str, str],
    body: bytes,
    timeout_seconds: float,
    max_response_bytes: int,
) -> UpstreamResponse:
    """Send one request to a fixed configured upstream without following redirects."""

    request_headers = {
        key: value
        for key, value in headers.items()
        if key.lower() not in _HOP_BY_HOP
    }
    request = urllib.request.Request(
        url=url,
        data=body if method.upper() not in {"GET", "HEAD"} else None,
        headers=request_headers,
        method=method.upper(),
    )
    opener = urllib.request.build_opener(_NoRedirect())
    try:
        with opener.open(request, timeout=timeout_seconds) as response:
            payload = _bounded_read(response, max_response_bytes)
            return UpstreamResponse(
                status=int(response.status),
                headers=tuple((key, value) for key, value in response.headers.items()),
                body=payload,
            )
    except urllib.error.HTTPError as exc:
        payload = _bounded_read(exc, max_response_bytes)
        return UpstreamResponse(
            status=int(exc.code),
            headers=tuple((key, value) for key, value in exc.headers.items()),
            body=payload,
        )
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise UpstreamTransportError(str(exc)) from exc


def _bounded_read(response: object, max_response_bytes: int) -> bytes:
    if max_response_bytes <= 0:
        raise ValueError("max_response_bytes must be positive.")
    reader = getattr(response, "read", None)
    if not callable(reader):
        raise UpstreamTransportError("Upstream response is not readable.")
    payload = reader(max_response_bytes + 1)
    if not isinstance(payload, bytes):
        raise UpstreamTransportError("Upstream response returned non-byte content.")
    if len(payload) > max_response_bytes:
        raise UpstreamTransportError("Upstream response exceeded configured size limit.")
    return payload
