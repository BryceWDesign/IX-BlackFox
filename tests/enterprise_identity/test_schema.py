import json
from pathlib import Path


def test_wave15_ci_schema_is_draft_2020_12_and_fail_closed() -> None:
    root = Path(__file__).resolve().parents[2]
    schema = json.loads((root / "schemas" / "wave15-enterprise-identity-ci-summary.schema.json").read_text(encoding="utf-8"))
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["properties"]["static_credential_status"]["const"] == 401
    assert schema["properties"]["wrong_audience_status"]["const"] == 401
    assert schema["properties"]["missing_delegation_status"]["const"] == 401
    assert schema["properties"]["delegation_scope_status"]["const"] == 403
    assert schema["properties"]["upstream_count_after_denials"]["const"] == 0
    assert schema["properties"]["revoked_token_status"]["const"] == 401
