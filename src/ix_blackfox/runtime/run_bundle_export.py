from __future__ import annotations

import hashlib
import json
import shutil
import zipfile
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum, auto
from pathlib import Path
from typing import Any, Self

from ix_blackfox.runtime.run_bundle import RunBundleLayout, RunBundleManifest


class RunBundleExportFormat(StrEnum):
    """
    Supported export formats for an operator run bundle.
    """

    ZIP = auto()
    DIRECTORY = auto()


@dataclass(frozen=True, slots=True)
class RunBundleExportRequest:
    """
    Request to export one BlackFox run bundle.

    The request is intentionally filesystem-local. It does not upload, transmit,
    or mutate remote state. Exported bundles are written only below the supplied
    destination directory.
    """

    run_id: str
    bundle_root: Path
    destination_dir: Path
    export_format: RunBundleExportFormat = RunBundleExportFormat.ZIP
    export_name: str | None = None
    require_manifest: bool = True
    overwrite: bool = False
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "run_id", _normalize_identifier(self.run_id, label="run_id"))
        object.__setattr__(self, "bundle_root", self.bundle_root.expanduser().resolve())
        object.__setattr__(
            self,
            "destination_dir",
            self.destination_dir.expanduser().resolve(),
        )
        object.__setattr__(self, "export_name", _normalize_optional_export_name(self.export_name))
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def resolved_export_name(self) -> str:
        return self.export_name or self.run_id

    @classmethod
    def from_layout(
        cls,
        *,
        layout: RunBundleLayout,
        destination_dir: Path,
        export_format: RunBundleExportFormat = RunBundleExportFormat.ZIP,
        export_name: str | None = None,
        require_manifest: bool = True,
        overwrite: bool = False,
        metadata: Mapping[str, Any] | None = None,
    ) -> Self:
        return cls(
            run_id=layout.run_id,
            bundle_root=layout.bundle_root,
            destination_dir=destination_dir,
            export_format=export_format,
            export_name=export_name,
            require_manifest=require_manifest,
            overwrite=overwrite,
            metadata=dict(metadata or {}),
        )


@dataclass(frozen=True, slots=True)
class RunBundleExportResult:
    """
    Result of exporting one BlackFox run bundle.
    """

    run_id: str
    export_format: RunBundleExportFormat
    export_path: Path
    sha256: str
    size_bytes: int
    file_count: int
    manifest_digest: str | None = None
    exported_at: datetime = field(default_factory=lambda: datetime.now(tz=UTC))
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "run_id", _normalize_identifier(self.run_id, label="run_id"))
        object.__setattr__(self, "export_path", self.export_path.expanduser().resolve())
        object.__setattr__(self, "sha256", _normalize_digest(self.sha256))
        object.__setattr__(self, "manifest_digest", _normalize_optional_digest(self.manifest_digest))
        object.__setattr__(self, "metadata", dict(self.metadata))

        if self.size_bytes < 0:
            raise ValueError("RunBundleExportResult size_bytes must not be negative.")
        if self.file_count < 0:
            raise ValueError("RunBundleExportResult file_count must not be negative.")
        if self.exported_at.tzinfo is None:
            raise ValueError("RunBundleExportResult exported_at must be timezone-aware.")

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "export_format": self.export_format.value,
            "export_path": str(self.export_path),
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "file_count": self.file_count,
            "manifest_digest": self.manifest_digest,
            "exported_at": self.exported_at.isoformat(),
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class RunBundleExporter:
    """
    Export command for BlackFox operator run bundles.

    The exporter supports two local formats:
    - ZIP archive for forwarding or attachment.
    - Directory copy for local inspection.

    It refuses path traversal, absolute export names, missing bundle roots, and
    accidental overwrite unless the request explicitly allows overwrite.
    """

    def export(self, request: RunBundleExportRequest) -> RunBundleExportResult:
        self._validate_request(request)
        manifest = self._load_manifest(request)

        if request.export_format is RunBundleExportFormat.ZIP:
            return self._export_zip(request=request, manifest=manifest)

        if request.export_format is RunBundleExportFormat.DIRECTORY:
            return self._export_directory(request=request, manifest=manifest)

        raise ValueError(f"Unsupported run bundle export format: {request.export_format}")

    def _validate_request(self, request: RunBundleExportRequest) -> None:
        if not request.bundle_root.exists():
            raise FileNotFoundError(f"Run bundle root does not exist: {request.bundle_root}")
        if not request.bundle_root.is_dir():
            raise NotADirectoryError(f"Run bundle root is not a directory: {request.bundle_root}")

        if request.require_manifest and not (request.bundle_root / "manifest.json").is_file():
            raise FileNotFoundError(
                f"Run bundle manifest is required but missing: {request.bundle_root / 'manifest.json'}"
            )

        request.destination_dir.mkdir(parents=True, exist_ok=True)
        if not request.destination_dir.is_dir():
            raise NotADirectoryError(
                f"Run bundle export destination is not a directory: {request.destination_dir}"
            )

    def _load_manifest(self, request: RunBundleExportRequest) -> RunBundleManifest | None:
        manifest_path = request.bundle_root / "manifest.json"
        if not manifest_path.is_file():
            return None

        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
        if not isinstance(payload, Mapping):
            raise TypeError("Run bundle manifest payload must be a JSON object.")

        manifest = RunBundleManifest.from_dict(payload)

        if manifest.run_id != request.run_id:
            raise ValueError(
                "Run bundle manifest run_id does not match export request: "
                f"{manifest.run_id!r} != {request.run_id!r}."
            )

        return manifest

    def _export_zip(
        self,
        *,
        request: RunBundleExportRequest,
        manifest: RunBundleManifest | None,
    ) -> RunBundleExportResult:
        export_path = (request.destination_dir / f"{request.resolved_export_name}.zip").resolve()
        self._prepare_destination_path(
            export_path=export_path,
            destination_dir=request.destination_dir,
            overwrite=request.overwrite,
            is_directory=False,
        )

        file_paths = tuple(_iter_bundle_files(request.bundle_root))
        with zipfile.ZipFile(
            export_path,
            mode="w",
            compression=zipfile.ZIP_DEFLATED,
            compresslevel=9,
        ) as archive:
            for file_path in file_paths:
                archive.write(
                    file_path,
                    arcname=file_path.relative_to(request.bundle_root).as_posix(),
                )

        payload = export_path.read_bytes()
        return RunBundleExportResult(
            run_id=request.run_id,
            export_format=RunBundleExportFormat.ZIP,
            export_path=export_path,
            sha256=hashlib.sha256(payload).hexdigest(),
            size_bytes=len(payload),
            file_count=len(file_paths),
            manifest_digest=manifest.digest if manifest is not None else None,
            metadata={
                "bundle_root": str(request.bundle_root),
                "destination_dir": str(request.destination_dir),
                "export_name": request.resolved_export_name,
                "require_manifest": request.require_manifest,
                **dict(request.metadata),
            },
        )

    def _export_directory(
        self,
        *,
        request: RunBundleExportRequest,
        manifest: RunBundleManifest | None,
    ) -> RunBundleExportResult:
        export_path = (request.destination_dir / request.resolved_export_name).resolve()
        self._prepare_destination_path(
            export_path=export_path,
            destination_dir=request.destination_dir,
            overwrite=request.overwrite,
            is_directory=True,
        )

        shutil.copytree(request.bundle_root, export_path)
        file_paths = tuple(_iter_bundle_files(export_path))
        digest = _digest_directory(export_path, file_paths)
        size_bytes = sum(file_path.stat().st_size for file_path in file_paths)

        return RunBundleExportResult(
            run_id=request.run_id,
            export_format=RunBundleExportFormat.DIRECTORY,
            export_path=export_path,
            sha256=digest,
            size_bytes=size_bytes,
            file_count=len(file_paths),
            manifest_digest=manifest.digest if manifest is not None else None,
            metadata={
                "bundle_root": str(request.bundle_root),
                "destination_dir": str(request.destination_dir),
                "export_name": request.resolved_export_name,
                "require_manifest": request.require_manifest,
                **dict(request.metadata),
            },
        )

    def _prepare_destination_path(
        self,
        *,
        export_path: Path,
        destination_dir: Path,
        overwrite: bool,
        is_directory: bool,
    ) -> None:
        destination_dir = destination_dir.resolve()
        export_path = export_path.resolve()

        if not _is_relative_to(export_path, destination_dir):
            raise ValueError(f"Run bundle export path escapes destination: {export_path}")

        if not export_path.exists():
            return

        if not overwrite:
            raise FileExistsError(f"Run bundle export target already exists: {export_path}")

        if export_path.is_dir():
            shutil.rmtree(export_path)
            return

        if export_path.is_file():
            export_path.unlink()
            return

        if is_directory:
            shutil.rmtree(export_path)
        else:
            export_path.unlink()


def _iter_bundle_files(bundle_root: Path) -> Iterable[Path]:
    return tuple(
        sorted(
            (
                path
                for path in bundle_root.rglob("*")
                if path.is_file()
            ),
            key=lambda item: item.relative_to(bundle_root).as_posix(),
        )
    )


def _digest_directory(root: Path, file_paths: Iterable[Path]) -> str:
    digest = hashlib.sha256()

    for file_path in file_paths:
        relative_path = file_path.relative_to(root).as_posix()
        digest.update(relative_path.encode("utf-8"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(file_path.read_bytes()).hexdigest().encode("ascii"))
        digest.update(b"\0")

    return digest.hexdigest()


def _normalize_identifier(value: str, *, label: str) -> str:
    cleaned = value.strip().lower().replace(" ", "-")
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    return cleaned


def _normalize_optional_export_name(value: str | None) -> str | None:
    if value is None:
        return None

    cleaned = value.strip().replace("\\", "/")
    if not cleaned:
        return None
    if cleaned.startswith(("/", "~", ".")) or "/" in cleaned:
        raise ValueError("Run bundle export_name must be a simple non-hidden name.")
    if cleaned.endswith(".zip"):
        cleaned = cleaned[:-4]
    if not cleaned:
        raise ValueError("Run bundle export_name must not be empty.")

    return cleaned


def _normalize_digest(value: str) -> str:
    cleaned = value.strip().lower()
    if len(cleaned) != 64:
        raise ValueError("Digest must be a 64-character SHA-256 hex string.")
    int(cleaned, 16)
    return cleaned


def _normalize_optional_digest(value: str | None) -> str | None:
    if value is None:
        return None
    return _normalize_digest(value)


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True
