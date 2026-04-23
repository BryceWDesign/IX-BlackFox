from __future__ import annotations

import importlib


def test_package_imports() -> None:
    module = importlib.import_module("ix_blackfox")
    assert module is not None


def test_cli_entrypoint_runs() -> None:
    cli = importlib.import_module("ix_blackfox.interface.cli")
    result = cli.main([])
    assert result == 0


def test_runtime_public_surface_exports_governance_components() -> None:
    runtime = importlib.import_module("ix_blackfox.runtime")

    exported_names = {
        "BlackFoxRuntime",
        "RuntimeApprovalResolution",
        "RuntimeApprovalResolver",
        "RuntimeGovernancePreflightEngine",
        "RuntimeGovernancePreflightResult",
        "RuntimeGovernanceReceiptRecorder",
        "RuntimeGovernanceReceiptReport",
        "RuntimeRunReport",
        "RuntimeRunStatus",
    }

    for name in exported_names:
        assert hasattr(runtime, name), f"Missing runtime export: {name}"


def test_interface_package_exports_main() -> None:
    interface = importlib.import_module("ix_blackfox.interface")
    assert hasattr(interface, "main")
