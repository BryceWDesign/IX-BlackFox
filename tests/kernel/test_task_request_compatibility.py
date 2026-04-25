from __future__ import annotations

from ix_blackfox.kernel import TaskKind, TaskPriority, TaskRequest


def test_task_request_exposes_prompt_metadata_and_attachments_compatibility_aliases() -> None:
    request = TaskRequest.create(
        prompt="Inspect the repo, prepare a patch, and run tests.",
        kind=TaskKind.PROGRAMMING,
        priority=TaskPriority.HIGH,
        metadata={
            "workspace": "blackfox-wave-2",
            "risk_level": "moderate",
        },
        attachments=("repo.zip", "failure-log.txt"),
        labels=("Patch", " Tests ", "patch"),
    )

    assert request.prompt == "Inspect the repo, prepare a patch, and run tests."
    assert request.metadata == {
        "workspace": "blackfox-wave-2",
        "risk_level": "moderate",
    }
    assert request.attachments == ("repo.zip", "failure-log.txt")
    assert request.kind is TaskKind.PROGRAMMING
    assert request.priority is TaskPriority.HIGH
    assert request.labels == ("patch", "tests")


def test_task_request_metadata_alias_returns_copy_not_mutable_internal_state() -> None:
    request = TaskRequest.create(
        prompt="Run governed execution.",
        metadata={"approval_required": True},
    )

    copied_metadata = request.metadata
    copied_metadata["approval_required"] = False
    copied_metadata["new_field"] = "should-not-leak"

    assert request.metadata == {"approval_required": True}
    assert request.input.metadata == {"approval_required": True}


def test_task_request_prompt_alias_tracks_normalized_task_input_prompt() -> None:
    request = TaskRequest.create(
        prompt="   Verify runtime receipts.   ",
    )

    assert request.input.prompt == "Verify runtime receipts."
    assert request.prompt == "Verify runtime receipts."
