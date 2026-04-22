from __future__ import annotations

import importlib


def test_governance_package_imports() -> None:
    module = importlib.import_module("ix_blackfox.governance")
    assert module is not None
