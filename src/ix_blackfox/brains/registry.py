from __future__ import annotations

from threading import RLock

from ix_blackfox.brains.contracts import BrainCapability, BrainRole
from ix_blackfox.brains.manifest import BrainManifest, BrainManifestSnapshot


class BrainManifestRegistry:
    """
    Thread-safe registry for BlackFox brain manifests.

    This registry is intentionally declarative. It tracks installed brain
    metadata and lookup helpers before provider invocation is introduced.
    """

    def __init__(self) -> None:
        self._manifests: list[BrainManifest] = []
        self._lock = RLock()

    def register(self, manifest: BrainManifest) -> None:
        """
        Register or replace a manifest by brain name.
        """
        with self._lock:
            for index, existing in enumerate(self._manifests):
                if existing.brain_name == manifest.brain_name:
                    self._manifests[index] = manifest
                    return
            self._manifests.append(manifest)

    def unregister(self, brain_name: str) -> bool:
        """
        Remove a manifest by brain name.
        """
        normalized_name = brain_name.strip().lower().replace(" ", "-")
        if not normalized_name:
            raise ValueError("Brain name must not be empty.")

        with self._lock:
            for index, manifest in enumerate(self._manifests):
                if manifest.brain_name == normalized_name:
                    del self._manifests[index]
                    return True
            return False

    def get(self, brain_name: str) -> BrainManifest | None:
        """
        Retrieve a manifest by brain name.
        """
        normalized_name = brain_name.strip().lower().replace(" ", "-")
        if not normalized_name:
            raise ValueError("Brain name must not be empty.")

        with self._lock:
            for manifest in self._manifests:
                if manifest.brain_name == normalized_name:
                    return manifest
            return None

    def defaults(self) -> tuple[BrainManifest, ...]:
        """
        Return manifests marked as default candidates.
        """
        with self._lock:
            return tuple(manifest for manifest in self._manifests if manifest.is_default)

    def find_by_role(self, role: BrainRole) -> tuple[BrainManifest, ...]:
        """
        Return manifests that support the given cognitive role.
        """
        with self._lock:
            return tuple(manifest for manifest in self._manifests if manifest.supports_role(role))

    def find_by_capability(
        self,
        capability: BrainCapability,
    ) -> tuple[BrainManifest, ...]:
        """
        Return manifests that declare the given capability.
        """
        with self._lock:
            return tuple(
                manifest
                for manifest in self._manifests
                if manifest.declares_capability(capability)
            )

    def find_for_pack(self, pack_name: str) -> tuple[BrainManifest, ...]:
        """
        Return manifests that explicitly prefer the given pack.
        """
        normalized_pack_name = pack_name.strip().lower().replace(" ", "-")
        if not normalized_pack_name:
            raise ValueError("Pack name must not be empty.")

        with self._lock:
            return tuple(
                manifest
                for manifest in self._manifests
                if normalized_pack_name in manifest.preferred_packs
            )

    def snapshot(self) -> BrainManifestSnapshot:
        """
        Return an immutable snapshot of the registry.
        """
        with self._lock:
            return BrainManifestSnapshot(manifests=tuple(self._manifests))

    def clear(self) -> None:
        """
        Remove all registered manifests.
        """
        with self._lock:
            self._manifests.clear()
