from __future__ import annotations

import sys
from types import ModuleType

import pytest

from ix_blackfox.packs import EntrypointSpec, PackLoader, PackLoadError, PackManifest


def test_entrypoint_spec_parse_normalizes_parts() -> None:
    spec = EntrypointSpec.parse("  fake.module.path:PackRuntime  ")

    assert spec.module_path == "fake.module.path"
    assert spec.attribute_name == "PackRuntime"


@pytest.mark.parametrize(
    "entrypoint",
    [
        "",
        "   ",
        "moduleonly",
        "module:",
        ":attribute",
    ],
)
def test_entrypoint_spec_parse_rejects_invalid_values(entrypoint: str) -> None:
    with pytest.raises(ValueError, match="module.path:attribute"):
        EntrypointSpec.parse(entrypoint)


def test_pack_loader_loads_declared_entrypoint(monkeypatch: pytest.MonkeyPatch) -> None:
    module_name = "tests.fake_pack_module"
    fake_module = ModuleType(module_name)

    class FakePackRuntime:
        pass

    fake_module.FakePackRuntime = FakePackRuntime
    monkeypatch.setitem(sys.modules, module_name, fake_module)

    manifest = PackManifest(
        pack_name="programming",
        version="0.1.0",
        entrypoint=f"{module_name}:FakePackRuntime",
    )

    loaded = PackLoader().load(manifest)

    assert loaded.manifest == manifest
    assert loaded.implementation is FakePackRuntime


def test_pack_loader_requires_entrypoint() -> None:
    manifest = PackManifest(
        pack_name="programming",
        version="0.1.0",
    )

    with pytest.raises(PackLoadError, match="does not declare an entrypoint"):
        PackLoader().load(manifest)


def test_pack_loader_raises_for_missing_attribute(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_name = "tests.fake_pack_missing_attribute"
    fake_module = ModuleType(module_name)
    monkeypatch.setitem(sys.modules, module_name, fake_module)

    manifest = PackManifest(
        pack_name="architecture",
        version="0.1.0",
        entrypoint=f"{module_name}:MissingRuntime",
    )

    with pytest.raises(PackLoadError, match="was not found in module"):
        PackLoader().load(manifest)


def test_pack_loader_load_many_preserves_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_one_name = "tests.fake_pack_one"
    module_two_name = "tests.fake_pack_two"

    module_one = ModuleType(module_one_name)
    module_two = ModuleType(module_two_name)

    class PackOne:
        pass

    class PackTwo:
        pass

    module_one.PackOne = PackOne
    module_two.PackTwo = PackTwo

    monkeypatch.setitem(sys.modules, module_one_name, module_one)
    monkeypatch.setitem(sys.modules, module_two_name, module_two)

    manifests = (
        PackManifest(
            pack_name="one",
            version="0.1.0",
            entrypoint=f"{module_one_name}:PackOne",
        ),
        PackManifest(
            pack_name="two",
            version="0.1.0",
            entrypoint=f"{module_two_name}:PackTwo",
        ),
    )

    loaded = PackLoader().load_many(manifests)

    assert tuple(item.manifest.pack_name for item in loaded) == ("one", "two")
    assert loaded[0].implementation is PackOne
    assert loaded[1].implementation is PackTwo
