from __future__ import annotations

import pytest

from ix_blackfox.eval import EvidenceRecorder


def test_evidence_recorder_records_and_filters_entries() -> None:
    recorder = EvidenceRecorder()

    first = recorder.record(
        subject_id="Task-001",
        evidence_type="artifact",
        summary="Captured regression report artifact.",
        source="forge",
        artifact_refs=(" report.json ", "report.json", "trace.log"),
        trace_ids=(" tr-1 ", "tr-2", "tr-1"),
        metadata={"status": "passed"},
    )
    second = recorder.record(
        subject_id="task-001",
        evidence_type="trace",
        summary="Captured routing trace.",
        source="switchboard",
    )
    third = recorder.record(
        subject_id="task-002",
        evidence_type="artifact",
        summary="Captured failure log.",
        source="forge",
    )

    snapshot = recorder.snapshot()

    assert first.evidence_id.startswith("ev-")
    assert first.subject_id == "task-001"
    assert first.evidence_type == "artifact"
    assert first.source == "forge"
    assert first.artifact_refs == ("report.json", "trace.log")
    assert first.trace_ids == ("tr-1", "tr-2")
    assert first.metadata == {"status": "passed"}

    assert snapshot.get(first.evidence_id) == first
    assert snapshot.filter_by_subject("task-001") == (first, second)
    assert snapshot.filter_by_type("artifact") == (first, third)


def test_evidence_recorder_count_and_clear() -> None:
    recorder = EvidenceRecorder()
    recorder.record(
        subject_id="task-001",
        evidence_type="artifact",
        summary="Stored artifact.",
    )
    recorder.record(
        subject_id="task-002",
        evidence_type="trace",
        summary="Stored trace.",
    )

    assert recorder.count() == 2

    recorder.clear()

    assert recorder.count() == 0
    assert recorder.snapshot().records == ()


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        (
            {
                "subject_id": "   ",
                "evidence_type": "artifact",
                "summary": "Stored artifact.",
            },
            "Evaluation evidence subject id must not be empty",
        ),
        (
            {
                "subject_id": "task-001",
                "evidence_type": "   ",
                "summary": "Stored artifact.",
            },
            "Evaluation evidence evidence type must not be empty",
        ),
        (
            {
                "subject_id": "task-001",
                "evidence_type": "artifact",
                "summary": "   ",
            },
            "Evaluation evidence summary must not be empty",
        ),
    ],
)
def test_evidence_recorder_rejects_invalid_inputs(
    kwargs: dict[str, str],
    message: str,
) -> None:
    recorder = EvidenceRecorder()

    with pytest.raises(ValueError, match=message):
        recorder.record(**kwargs)
