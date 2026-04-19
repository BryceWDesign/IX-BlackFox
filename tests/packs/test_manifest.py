from __future__ import annotations

import pytest

from ix_blackfox.kernel import TaskKind
from ix_blackfox.packs import (
    PackCapability,
    PackCapabilityType,
    PackManifest,
    PackManifestRegistry,
)


def test_pack_manifest_normalizes_fields() -> None:
    manifest = PackManifest(
        pack_name=" Programming ",
        version="0.1.0",
        description="  Handles programming tasks.  ",
        supported_kinds=(TaskKind.PROGRAMMING,),
        labels=(" Code ", "patching", "code"),
        dependencies=(" Common ", "common"),
        entrypoint="  ix_blackfox.packs.programming.runtime:ProgrammingPack  ",
        capabilities=(
            PackCapability(
                name=" Patch Planner ",
                capability_type=PackCapabilityType.REASONING,
                description="  Creates patch plans.  ",
            ),
        ),
    )

    assert manifest.pack_name == "programming"
    assert manifest.version == "0.1.0"
    assert manifest.description == "Handles programming tasks."
    assert manifest.labels == ("code", "patching")
    assert manifest.dependencies == ("common",)
    assert (
        manifest.entrypoint
        == "ix_blackfox.packs.programming.runtime:ProgrammingPack"
    )
    assert manifest.capabilities[0].name == "patch planner"
    assert manifest.capabilities[0].description == "Creates patch plans."


def test_pack_manifest_support_and_capability_checks() -> None:
    manifest = PackManifest(
        pack_name="architecture",
        version="0.1.0",
        supported_kinds=(TaskKind.ARCHITECTURE, TaskKind.ANALYSIS),
        capabilities=(
            PackCapability(
                name="System Design",
                capability_type=PackCapabilityType.REASONING,
            ),
        ),
    )

    assert manifest.supports_task_kind(TaskKind.ARCHITECTURE) is True
    assert manifest.supports_task_kind(TaskKind.PROGRAMMING) is False
    assert manifest.declares_capability("system design") is True
    assert manifest.declares_capability("patch planning") is False


def test_pack_manifest_registry_registers_replaces_and_retrieves() -> None:
    registry = PackManifestRegistry()
    registry.register(
        PackManifest(
            pack_name="programming",
            version="0.1.0",
        )
    )
    registry.register(
        PackManifest(
            pack_name="programming",
            version="0.2.0",
        )
    )

    snapshot = registry.snapshot()
    assert snapshot.names() == ("programming",)
    assert registry.get("programming") is not None
    assert registry.get("programming").version == "0.2.0"


def test_pack_manifest_registry_unregister_and_clear() -> None:
    registry = PackManifestRegistry()
    registry.register(PackManifest(pack_name="programming", version="0.1.0"))
    registry.register(PackManifest(pack_name="architecture", version="0.1.0"))

    assert registry.unregister("programming") is True
    assert registry.unregister("programming") is False

    registry.clear()
    assert registry.snapshot().manifests == ()


@pytest.mark.parametrize(
    ("builder", "message"),
    [
        (
            lambda: PackManifest(pack_name="   ", version="0.1.0"),
            "Pack pack name must not be empty",
        ),
        (
            lambda: PackManifest(pack_name="programming", version="   "),
            "Pack version must not be empty",
        ),
        (
            lambda: PackCapability(
                name="   ",
                capability_type=PackCapabilityType.REASONING,
            ),
            "Pack capability name must not be empty",
        ),
    ],
)
def test_invalid_manifest_inputs_raise(builder, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        builder()
