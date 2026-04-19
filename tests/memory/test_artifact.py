from __future__ import annotations

from pathlib import Path
from time import sleep

import pytest

from ix_blackfox.memory import ArtifactMemoryStore


def test_artifact_memory_upsert_get_and_update(tmp_path: Path) -> None:
    store = ArtifactMemoryStore()
    first_path = tmp_path / "report.json"
    second_path = tmp_path / "report-v2.json"

    first = store.upsert(
        logical_name="Plan Report",
        path=first_path,
        artifact_type="report",
        digest="abc123",
        source="planner",
        tags=("plan", "json"),
        metadata={"size": 120},
    )
    sleep(0.001)
    second = store.upsert(
        logical_name="plan report",
        path=second_path,
        artifact_type="report",
        digest="def456",
        source="forge",
        tags=("plan", "json", "plan"),
        metadata={"size": 180},
    )

    assert first.logical_name == "plan report"
    assert first.path == first_path.resolve()
    assert first.tags == ("plan", "json")
    assert second.artifact_id == first.artifact_id
    assert second.path == second_path.resolve()
    assert second.digest == "def456"
    assert second.source == "forge"
    assert second.metadata == {"size": 180}
    assert second.updated_at >= first.updated_at
    assert store.get("plan report") == second


def test_artifact_memory_snapshot_filters(tmp_path: Path) -> None:
    store = ArtifactMemoryStore()
    first = store.upsert(
        logical_name="patch report",
        path=tmp_path / "patch.txt",
        artifact_type="report",
        tags=("patch", "text"),
    )
    second = store.upsert(
        logical_name="workspace manifest",
        path=tmp_path / "manifest.json",
        artifact_type="manifest",
        tags=("json", "workspace"),
    )
    third = store.upsert(
        logical_name="patch bundle",
        path=tmp_path / "bundle.diff",
        artifact_type="patch",
        tags=("patch", "diff"),
    )

    snapshot = store.snapshot()

    assert snapshot.get("patch report") == first
    assert snapshot.filter_by_type("report") == (first,)
    assert snapshot.filter_by_tag("patch") == (third, first)
    assert second.logical_name == "workspace manifest"


def test_artifact_memory_delete_and_clear(tmp_path: Path) -> None:
    store = ArtifactMemoryStore()
    store.upsert(
        logical_name="trace bundle",
        path=tmp_path / "trace.log",
        artifact_type="report",
    )

    assert store.delete("trace bundle") is True
    assert store.delete("trace bundle") is False

    store.upsert(logical_name="a", path=tmp_path / "a.txt", artifact_type="file")
    store.upsert(logical_name="b", path=tmp_path / "b.txt", artifact_type="file")
    store.clear()

    assert store.count() == 0
    assert store.snapshot().records == ()


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        (
            {
                "logical_name": "   ",
                "path": Path("x.txt"),
                "artifact_type": "file",
            },
            "Artifact memory logical name must not be empty",
        ),
        (
            {
                "logical_name": "x",
                "path": Path("x.txt"),
                "artifact_type": "   ",
            },
            "Artifact memory artifact type must not be empty",
        ),
    ],
)
def test_artifact_memory_rejects_invalid_inputs(
    kwargs: dict[str, object],
    message: str,
) -> None:
    store = ArtifactMemoryStore()

    with pytest.raises(ValueError, match=message):
        store.upsert(**kwargs)
