from __future__ import annotations

from dataclasses import dataclass
from importlib import import_module
from types import ModuleType
from typing import Any

from ix_blackfox.packs.manifest import PackManifest


class PackLoadError(RuntimeError):
    """
    Raised when a pack cannot be loaded from its declared entrypoint.
    """


@dataclass(frozen=True, slots=True)
class EntrypointSpec:
    """
    Parsed pack entrypoint reference.

    Attributes
    ----------
    module_path:
        Importable Python module path.
    attribute_name:
        Exported attribute within the module.
    """

    module_path: str
    attribute_name: str

    @classmethod
    def parse(cls, entrypoint: str) -> EntrypointSpec:
        """
        Parse a pack entrypoint string in the form ``module.path:attribute``.
        """
        raw_entrypoint = entrypoint.strip()
        if not raw_entrypoint:
            raise ValueError("Pack entrypoint must not be empty.")

        module_path, separator, attribute_name = raw_entrypoint.partition(":")
        normalized_module_path = module_path.strip()
        normalized_attribute_name = attribute_name.strip()

        if separator != ":" or not normalized_module_path or not normalized_attribute_name:
            raise ValueError(
                "Pack entrypoint must be in the form 'module.path:attribute'."
            )

        return cls(
            module_path=normalized_module_path,
            attribute_name=normalized_attribute_name,
        )


@dataclass(frozen=True, slots=True)
class LoadedPack:
    """
    Loaded pack binding.

    Attributes
    ----------
    manifest:
        Source pack manifest.
    implementation:
        Imported runtime implementation object.
    """

    manifest: PackManifest
    implementation: Any


class PackLoader:
    """
    Runtime loader for manifest-declared BlackFox packs.

    The loader currently resolves Python entrypoints into importable
    runtime objects. Later revisions can add constructor protocols,
    dependency injection, lifecycle hooks, or lazy loading without
    changing the basic manifest contract.
    """

    def load(self, manifest: PackManifest) -> LoadedPack:
        """
        Load a single pack from its manifest entrypoint.
        """
        if manifest.entrypoint is None:
            raise PackLoadError(
                f"Pack '{manifest.pack_name}' does not declare an entrypoint."
            )

        spec = EntrypointSpec.parse(manifest.entrypoint)
        module = self._import_module(spec.module_path)
        implementation = self._resolve_attribute(
            module=module,
            attribute_name=spec.attribute_name,
            pack_name=manifest.pack_name,
        )

        return LoadedPack(manifest=manifest, implementation=implementation)

    def load_many(self, manifests: tuple[PackManifest, ...]) -> tuple[LoadedPack, ...]:
        """
        Load multiple packs in the provided order.
        """
        return tuple(self.load(manifest) for manifest in manifests)

    def _import_module(self, module_path: str) -> ModuleType:
        try:
            return import_module(module_path)
        except ImportError as exc:
            raise PackLoadError(
                f"Failed to import pack module '{module_path}': {exc}"
            ) from exc

    def _resolve_attribute(
        self,
        *,
        module: ModuleType,
        attribute_name: str,
        pack_name: str,
    ) -> Any:
        if not hasattr(module, attribute_name):
            raise PackLoadError(
                f"Pack '{pack_name}' entrypoint attribute '{attribute_name}' "
                f"was not found in module '{module.__name__}'."
            )
        return getattr(module, attribute_name)
