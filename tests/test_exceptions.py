from __future__ import annotations

import pytest

from ix_blackfox import (
    BlackFoxError,
    ErrorContext,
    ForgeError,
)


def test_error_context_normalizes_fields() -> None:
    context = ErrorContext(
        component=" Forge ",
        operation=" Run Patch ",
        correlation_id=" task-001 ",
        data={"step": 3},
    )

    assert context.component == "forge"
    assert context.operation == "run patch"
    assert context.correlation_id == "task-001"
    assert context.data == {"step": 3}


def test_blackfox_error_to_dict_and_str_include_context() -> None:
    error = ForgeError(
        " Patch application failed. ",
        context=ErrorContext(
            component="forge",
            operation="apply patch",
            correlation_id="task-001",
            data={"path": "input/src/tool.py"},
        ),
    )

    assert isinstance(error, BlackFoxError)
    assert error.message == "Patch application failed."
    assert str(error) == (
        "Patch application failed. | component=forge | "
        "operation=apply patch | correlation_id=task-001"
    )
    assert error.to_dict() == {
        "error_type": "ForgeError",
        "message": "Patch application failed.",
        "context": {
            "component": "forge",
            "operation": "apply patch",
            "correlation_id": "task-001",
            "data": {"path": "input/src/tool.py"},
        },
    }


def test_blackfox_error_without_context_is_clean() -> None:
    error = BlackFoxError("Kernel boot failed.")

    assert str(error) == "Kernel boot failed."
    assert error.context is None
    assert error.to_dict() == {
        "error_type": "BlackFoxError",
        "message": "Kernel boot failed.",
        "context": None,
    }


@pytest.mark.parametrize(
    ("builder", "message"),
    [
        (
            lambda: ErrorContext(component="   ", operation="boot"),
            "BlackFox error component must not be empty",
        ),
        (
            lambda: ErrorContext(component="kernel", operation="   "),
            "BlackFox error operation must not be empty",
        ),
        (
            lambda: BlackFoxError("   "),
            "BlackFox error message must not be empty",
        ),
    ],
)
def test_exception_models_reject_invalid_inputs(builder, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        builder()
