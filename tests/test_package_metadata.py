from __future__ import annotations

import importlib


def test_package_imports() -> None:
    module = importlib.import_module("ix_blackfox")
    assert module is not None


def test_cli_entrypoint_runs() -> None:
    cli = importlib.import_module("ix_blackfox.interface.cli")
    result = cli.main([])
    assert result == 0
