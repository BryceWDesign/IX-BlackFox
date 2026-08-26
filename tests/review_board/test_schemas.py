from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ix_blackfox.review_board.models import (
    WAVE13_EVALUATION_SCHEMA_VERSION,
    WAVE13_HUMAN_REVIEW_SCHEMA_VERSION,
    WAVE13_MACHINE_ADVISORY_SCHEMA_VERSION,
    WAVE13_POLICY_SCHEMA_VERSION,
    WAVE13_SUBJECT_SCHEMA_VERSION,
)
from ix_blackfox.review_board.package import (
    WAVE13_ADVISORY_SET_SCHEMA_VERSION,
    WAVE13_CASE_SCHEMA_VERSION,
    WAVE13_CHALLENGE_SET_SCHEMA_VERSION,
    WAVE13_HUMAN_REVIEW_SET_SCHEMA_VERSION,
)
from ix_blackfox.review_board.verify import WAVE13_VERIFICATION_SCHEMA_VERSION


def test_wave13_schemas_are_draft_2020_12_objects_with_stable_ids() -> None:
    paths = _schema_paths()
    assert len(paths) == 7
    for path in paths:
        schema = _load(path)
        assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
        assert schema["$id"].endswith(f"/schemas/{path.name}")
        assert schema["type"] == "object"
        assert schema["additionalProperties"] is False


def test_review_case_schema_preserves_machine_zero_authority_and_human_gate() -> None:
    schema = _load(_schema_dir() / "wave13-review-case.schema.json")
    properties = schema["properties"]
    assert properties["schema_version"]["const"] == WAVE13_CASE_SCHEMA_VERSION
    assert properties["machine_authority"]["const"] is False
    assert properties["human_authority_required"]["const"] is True
    subject = properties["subject"]
    policy = properties["policy"]
    assert subject["properties"]["schema_version"]["const"] == WAVE13_SUBJECT_SCHEMA_VERSION
    assert policy["properties"]["schema_version"]["const"] == WAVE13_POLICY_SCHEMA_VERSION


def test_machine_and_human_set_schemas_match_runtime_versions() -> None:
    machine = _load(_schema_dir() / "wave13-machine-advisories.schema.json")
    human = _load(_schema_dir() / "wave13-human-reviews.schema.json")
    challenges = _load(_schema_dir() / "wave13-evidence-challenges.schema.json")

    assert machine["properties"]["schema_version"]["const"] == WAVE13_ADVISORY_SET_SCHEMA_VERSION
    machine_item = machine["properties"]["advisories"]["items"]
    assert machine_item["properties"]["schema_version"]["const"] == WAVE13_MACHINE_ADVISORY_SCHEMA_VERSION
    assert machine_item["properties"]["authoritative"]["const"] is False
    assert machine_item["properties"]["vote_weight"]["const"] == 0

    assert human["properties"]["schema_version"]["const"] == WAVE13_HUMAN_REVIEW_SET_SCHEMA_VERSION
    human_item = human["properties"]["reviews"]["items"]
    assert human_item["properties"]["schema_version"]["const"] == WAVE13_HUMAN_REVIEW_SCHEMA_VERSION

    assert challenges["properties"]["schema_version"]["const"] == WAVE13_CHALLENGE_SET_SCHEMA_VERSION


def test_evaluation_and_verification_schemas_expose_all_board_states() -> None:
    evaluation = _load(_schema_dir() / "wave13-board-evaluation.schema.json")
    verification = _load(_schema_dir() / "wave13-package-verification.schema.json")
    states = ["blocked", "human_review_required", "approved_for_next_gate"]

    assert evaluation["properties"]["schema_version"]["const"] == WAVE13_EVALUATION_SCHEMA_VERSION
    assert evaluation["properties"]["status"]["enum"] == states
    assert verification["properties"]["schema_version"]["const"] == WAVE13_VERIFICATION_SCHEMA_VERSION
    assert verification["properties"]["status"]["enum"] == ["", *states]


def test_ci_schema_forbids_fabricated_human_approval() -> None:
    schema = _load(_schema_dir() / "wave13-review-board-ci-summary.schema.json")
    properties = schema["properties"]
    assert properties["schema_version"]["const"] == "wave13.review_board_ci_summary.v1"
    assert properties["wave"]["const"] == "13"
    assert properties["human_review_supplied"]["const"] is False
    assert properties["external_verification_supplied"]["const"] is False
    assert properties["external_verification_count"]["const"] == 0
    assert properties["qualifying_human_approval_count"]["const"] == 0
    assert properties["machine_vote_weight"]["const"] == 0


def test_wave13_schema_descriptions_do_not_claim_external_authority() -> None:
    forbidden = (
        "certification granted",
        "deployment approved",
        "production authorized",
        "ato granted",
        "cato granted",
        "autonomous approval",
    )
    for path in _schema_paths():
        description = str(_load(path)["description"]).lower()
        assert not any(term in description for term in forbidden)


def _schema_dir() -> Path:
    return Path(__file__).resolve().parents[2] / "schemas"


def _schema_paths() -> tuple[Path, ...]:
    return tuple(sorted(_schema_dir().glob("wave13-*.schema.json")))


def _load(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload
