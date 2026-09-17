from __future__ import annotations

import pytest

from ix_blackfox.live_gateway.http_server import (
    RequestBodyError,
    _duplicate_sensitive_headers,
    _validated_content_length,
)


def test_content_length_accepts_one_bounded_decimal_value() -> None:
    assert (
        _validated_content_length(
            content_length_values=["42"],
            transfer_encoding="",
            max_request_bytes=100,
        )
        == 42
    )


@pytest.mark.parametrize(
    ("values", "transfer_encoding", "expected_status"),
    [
        ([], "", 411),
        (["1", "1"], "", 400),
        (["-1"], "", 400),
        (["1.0"], "", 400),
        (["abc"], "", 400),
        (["10"], "chunked", 400),
        (["101"], "", 413),
    ],
)
def test_content_length_rejects_ambiguous_or_unsafe_framing(
    values: list[str],
    transfer_encoding: str,
    expected_status: int,
) -> None:
    with pytest.raises(RequestBodyError) as exc_info:
        _validated_content_length(
            content_length_values=values,
            transfer_encoding=transfer_encoding,
            max_request_bytes=100,
        )
    assert exc_info.value.status == expected_status


def test_duplicate_sensitive_headers_rejects_ambiguous_authority_metadata() -> None:
    duplicates = _duplicate_sensitive_headers(
        [
            ("X-BlackFox-Agent-Token", "first"),
            ("x-blackfox-agent-token", "second"),
            ("Mcp-Param-Revision", "abc"),
            ("mcp-param-revision", "def"),
            ("X-Unrelated", "a"),
            ("X-Unrelated", "b"),
        ]
    )
    assert duplicates == ("mcp-param-revision", "x-blackfox-agent-token")


def test_duplicate_sensitive_headers_allows_unrelated_duplicates() -> None:
    assert (
        _duplicate_sensitive_headers(
            [("X-Unrelated", "a"), ("X-Unrelated", "b"), ("Origin", "https://example.com")]
        )
        == ()
    )
