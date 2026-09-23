from __future__ import annotations

import time

import pytest

from ix_blackfox.live_gateway.enterprise_identity import _parse_delegation_chain


def test_child_delegation_may_narrow_parent_scope() -> None:
    now = int(time.time())
    chain = _parse_delegation_chain(
        [
            {
                "delegation_id": "parent",
                "delegated_by": "human-owner",
                "tools": ["filesystem.write_file", "filesystem.delete_file"],
                "repositories": ["ix-blackfox"],
                "path_roots": ["docs"],
                "expires_at": now + 300,
            },
            {
                "delegation_id": "child",
                "delegated_by": "parent",
                "tools": ["filesystem.write_file"],
                "repositories": ["ix-blackfox"],
                "path_roots": ["docs/release"],
                "expires_at": now + 120,
            },
        ],
        now=now,
    )
    assert [item.delegation_id for item in chain] == ["parent", "child"]


def test_child_delegation_cannot_expand_tool_scope() -> None:
    now = int(time.time())
    with pytest.raises(ValueError, match="expands tools authority"):
        _parse_delegation_chain(
            [
                {
                    "delegation_id": "parent",
                    "delegated_by": "human-owner",
                    "tools": ["filesystem.write_file"],
                    "repositories": ["ix-blackfox"],
                    "path_roots": ["docs"],
                    "expires_at": now + 300,
                },
                {
                    "delegation_id": "child",
                    "delegated_by": "parent",
                    "tools": ["filesystem.write_file", "filesystem.delete_file"],
                    "repositories": ["ix-blackfox"],
                    "path_roots": ["docs"],
                    "expires_at": now + 120,
                },
            ],
            now=now,
        )


def test_child_delegation_cannot_expand_path_or_lifetime() -> None:
    now = int(time.time())
    base = {
        "delegation_id": "parent",
        "delegated_by": "human-owner",
        "tools": ["filesystem.write_file"],
        "repositories": ["ix-blackfox"],
        "path_roots": ["docs/release"],
        "expires_at": now + 120,
    }
    with pytest.raises(ValueError, match="expands path authority"):
        _parse_delegation_chain(
            [base, {**base, "delegation_id": "child", "delegated_by": "parent", "path_roots": ["docs"]}],
            now=now,
        )
    with pytest.raises(ValueError, match="expires after its parent"):
        _parse_delegation_chain(
            [
                base,
                {
                    **base,
                    "delegation_id": "child",
                    "delegated_by": "parent",
                    "path_roots": ["docs/release"],
                    "expires_at": now + 180,
                },
            ],
            now=now,
        )
