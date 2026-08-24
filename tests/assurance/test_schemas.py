from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ix_blackfox.assurance.models import WAVE12_MANIFEST_SCHEMA_VERSION
from ix_blackfox.assurance.verify import WAVE12_VERIFICATION_SCHEMA_VERSION


def test_wave12_schemas_are_draft_2020_12_objects_with_stable_ids() -> None:
    for path in _schema_paths():
        schema = _load(path)
        assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
        assert schema["$id"].endswith(f"/schemas/{path.name}")
        assert schema["type"] == "object"
        assert schema["additionalProperties"] is False


def test_manifest_schema_matches_runtime_versions_and_core_shape() -> None:
    schema = _load(_schema_dir() / "wave12-assurance-manifest.schema.json")
    properties = schema["properties"]
    assert properties["schema_version"]["const"] == WAVE12_MANIFEST_SCHEMA_VERSION
    assert (
        properties["wave_schema_version"]["const"]
        == "wave12.certification_ready_evidence.v1"
    )
    assert set(schema["required"]) == set(properties)
    assert schema["$defs"]["profile"]["additionalProperties"] is False
    assert schema["$defs"]["evidence"]["additionalProperties"] is False
    assert schema["$defs"]["claims"]["additionalProperties"] is False
    assert schema["$defs"]["claims"]["properties"]["prohibited_hits"] == {
        "type": "array",
        "maxItems": 0,
    }


def test_verification_schema_preserves_unsigned_scope_and_all_states() -> None:
    schema = _load(_schema_dir() / "wave12-package-verification.schema.json")
    properties = schema["properties"]
    assert properties["schema_version"]["const"] == WAVE12_VERIFICATION_SCHEMA_VERSION
    assert properties["authenticated"]["const"] is False
    assert properties["readiness_status"]["enum"] == [
        "",
        "blocked",
        "review_required",
        "ready_for_external_assessment",
    ]
    assert set(schema["required"]) == set(properties)


def test_ci_summary_schema_requires_real_campaign_outputs() -> None:
    schema = _load(_schema_dir() / "wave12-assurance-ci-summary.schema.json")
    properties = schema["properties"]
    assert properties["schema_version"]["const"] == (
        "wave12.assurance_ci_summary.v1"
    )
    assert properties["wave"]["const"] == "12"
    for field in (
        "quality_gates_run",
        "quality_gates_passed",
        "prerequisites_run",
        "prerequisite_results",
        "manifest_digest",
        "crosswalk_digest",
        "archive_sha256",
        "verification_passed",
        "verification_issue_count",
        "outputs",
    ):
        assert field in schema["required"]
    assert set(properties["outputs"]["required"]) == {
        "package",
        "verification",
        "readiness",
        "crosswalk",
        "manifest",
        "evidence_spec",
        "summary",
    }


def test_schema_descriptions_do_not_claim_certification_or_authorization() -> None:
    for path in _schema_paths():
        description = str(_load(path)["description"]).lower()
        assert (
            "does not" in description
            or "is not" in description
            or "open human-review gate" in description
        )
        assert "certification granted" not in description
        assert "compliance achieved" not in description
        assert "authorized for production" not in description


def _schema_dir() -> Path:
    return Path(__file__).resolve().parents[2] / "schemas"


def _schema_paths() -> tuple[Path, ...]:
    return tuple(sorted(_schema_dir().glob("wave12-*.schema.json")))


def _load(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload
