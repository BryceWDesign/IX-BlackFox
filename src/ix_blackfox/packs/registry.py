from __future__ import annotations

from threading import RLock

from ix_blackfox.packs.manifest import PackManifest, PackManifestSnapshot


class PackManifestRegistry:
    """
    Thread-safe registry for BlackFox pack manifests.

    This registry provides a stable home for declarative pack metadata
    before runtime loading and execution wiring are added.
    """

    def __init__(self) -> None:
        self._manifests: list[PackManifest] = []
        self._lock = RLock()

    def register(self, manifest: PackManifest) -> None:
        """
        Register or replace a manifest by pack name.
        """
        with self._lock:
            for index, existing in enumerate(self._manifests):
                if existing.pack_name == manifest.pack_name:
                    self._manifests[index] = manifest
                    return
            self._manifests.append(manifest)

    def unregister(self, pack_name: str) -> bool:
        """
        Remove a manifest by pack name.
        """
        normalized_name = pack_name.strip().lower()
        if not normalized_name:
            raise ValueError("Pack name must not be empty.")

        with self._lock:
            for index, manifest in enumerate(self._manifests):
                if manifest.pack_name == normalized_name:
                    del self._manifests[index]
                    return True
            return False

    def get(self, pack_name: str) -> PackManifest | None:
        """
        Retrieve a manifest by pack name.
        """
        normalized_name = pack_name.strip().lower()
        if not normalized_name:
            raise ValueError("Pack name must not be empty.")

        with self._lock:
            for manifest in self._manifests:
                if manifest.pack_name == normalized_name:
                    return manifest
            return None

    def snapshot(self) -> PackManifestSnapshot:
        """
        Return an immutable snapshot of the registry.
        """
        with self._lock:
            return PackManifestSnapshot(manifests=tuple(self._manifests))

    def clear(self) -> None:
        """
        Remove all registered manifests.
        """
        with self._lock:
            self._manifests.clear()
