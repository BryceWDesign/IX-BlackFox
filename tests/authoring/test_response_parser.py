from __future__ import annotations

import json

import pytest

from ix_blackfox.authoring import (
    AuthoringValidationError,
    PatchAuthoringResponseParser,
    PatchAuthoringResponseParserConfig,
    PatchMutationType,
    PatchProposalValidationCode,
)


def test_response_parser_accepts_valid_replace_text_proposal() -> None:
    raw_response = _proposal_json(
        mutations=[
            {
                "mutation_id": "mutation-1",
                "mutation_type": "replace_text",
                "path": "src/ix_blackfox/example.py",
                "before_text": "return a - b",
                "after_text": "return a + b",
                "rationale": "The failing assertion expects addition behavior.",
            }
        ]
    )

    proposal = PatchAuthoringResponseParser().parse(raw_response)

    assert proposal.schema_version == "wave3.patch_authoring_response.v1"
    assert proposal.proposal_id == "proposal-1"
    assert proposal.confidence == 0.72
    assert proposal.affected_paths == ("src/ix_blackfox/example.py",)
    assert proposal.mutations[0].mutation_type is PatchMutationType.REPLACE_TEXT
    assert proposal.mutations[0].size_delta == 0
    assert len(proposal.raw_digest) == 64
    assert len(proposal.digest) == 64


def test_response_parser_accepts_valid_create_file_proposal() -> None:
    raw_response = _proposal_json(
        mutations=[
            {
                "mutation_id": "mutation-create",
                "mutation_type": "create_file",
                "path": "src/ix_blackfox/new_module.py",
                "before_text": "",
                "after_text": "VALUE = 1\n",
                "rationale": "The missing module must be created.",
            }
        ]
    )

    proposal = PatchAuthoringResponseParser().parse(raw_response)

    assert proposal.mutations[0].mutation_type is PatchMutationType.CREATE_FILE
    assert proposal.mutations[0].path == "src/ix_blackfox/new_module.py"
    assert proposal.total_size_delta == len("VALUE = 1\n")


def test_response_parser_rejects_markdown_wrapped_json() -> None:
    raw_response = "```json\n" + _proposal_json() + "\n```"

    with pytest.raises(AuthoringValidationError, match=PatchProposalValidationCode.MARKDOWN_WRAPPED_RESPONSE.value):
        PatchAuthoringResponseParser().parse(raw_response)


def test_response_parser_rejects_malformed_json() -> None:
    with pytest.raises(AuthoringValidationError, match=PatchProposalValidationCode.MALFORMED_JSON.value):
        PatchAuthoringResponseParser().parse("{bad json")


def test_response_parser_rejects_top_level_array() -> None:
    with pytest.raises(AuthoringValidationError, match=PatchProposalValidationCode.TOP_LEVEL_NOT_OBJECT.value):
        PatchAuthoringResponseParser().parse("[]")


def test_response_parser_rejects_unknown_top_level_fields() -> None:
    payload = _proposal_payload()
    payload["extra"] = "not allowed"

    with pytest.raises(AuthoringValidationError, match=PatchProposalValidationCode.UNKNOWN_TOP_LEVEL_FIELD.value):
        PatchAuthoringResponseParser().parse(json.dumps(payload))


def test_response_parser_rejects_missing_required_fields() -> None:
    payload = _proposal_payload()
    del payload["reasoning_summary"]

    with pytest.raises(AuthoringValidationError, match=PatchProposalValidationCode.MISSING_REQUIRED_FIELD.value):
        PatchAuthoringResponseParser().parse(json.dumps(payload))


def test_response_parser_rejects_wrong_schema_version() -> None:
    payload = _proposal_payload()
    payload["schema_version"] = "wrong"

    with pytest.raises(AuthoringValidationError, match=PatchProposalValidationCode.INVALID_SCHEMA_VERSION.value):
        PatchAuthoringResponseParser().parse(json.dumps(payload))


def test_response_parser_rejects_invalid_confidence() -> None:
    payload = _proposal_payload()
    payload["confidence"] = 1.2

    with pytest.raises(AuthoringValidationError, match=PatchProposalValidationCode.INVALID_CONFIDENCE.value):
        PatchAuthoringResponseParser().parse(json.dumps(payload))


def test_response_parser_rejects_empty_mutations() -> None:
    payload = _proposal_payload()
    payload["mutations"] = []

    with pytest.raises(AuthoringValidationError, match=PatchProposalValidationCode.EMPTY_MUTATIONS.value):
        PatchAuthoringResponseParser().parse(json.dumps(payload))


def test_response_parser_rejects_unknown_mutation_field() -> None:
    payload = _proposal_payload()
    payload["mutations"][0]["shell_command"] = "python -m pytest"

    with pytest.raises(AuthoringValidationError, match=PatchProposalValidationCode.UNKNOWN_MUTATION_FIELD.value):
        PatchAuthoringResponseParser().parse(json.dumps(payload))


def test_response_parser_rejects_invalid_mutation_type() -> None:
    payload = _proposal_payload()
    payload["mutations"][0]["mutation_type"] = "delete_file"

    with pytest.raises(AuthoringValidationError, match=PatchProposalValidationCode.INVALID_MUTATION_TYPE.value):
        PatchAuthoringResponseParser().parse(json.dumps(payload))


@pytest.mark.parametrize(
    "unsafe_path",
    [
        "../outside.py",
        "/tmp/outside.py",
        "C:/Users/owner/secrets.txt",
        ".env",
        "~/secret.txt",
    ],
)
def test_response_parser_rejects_unsafe_paths(unsafe_path: str) -> None:
    payload = _proposal_payload()
    payload["mutations"][0]["path"] = unsafe_path

    with pytest.raises(AuthoringValidationError, match=PatchProposalValidationCode.UNSAFE_PATH.value):
        PatchAuthoringResponseParser().parse(json.dumps(payload))


def test_response_parser_rejects_replace_text_empty_before_text() -> None:
    payload = _proposal_payload()
    payload["mutations"][0]["before_text"] = ""

    with pytest.raises(AuthoringValidationError, match=PatchProposalValidationCode.EMPTY_BEFORE_TEXT.value):
        PatchAuthoringResponseParser().parse(json.dumps(payload))


def test_response_parser_rejects_replace_text_empty_after_text() -> None:
    payload = _proposal_payload()
    payload["mutations"][0]["after_text"] = ""

    with pytest.raises(AuthoringValidationError, match=PatchProposalValidationCode.EMPTY_AFTER_TEXT.value):
        PatchAuthoringResponseParser().parse(json.dumps(payload))


def test_response_parser_rejects_no_op_replace_text() -> None:
    payload = _proposal_payload()
    payload["mutations"][0]["after_text"] = payload["mutations"][0]["before_text"]

    with pytest.raises(AuthoringValidationError, match=PatchProposalValidationCode.NO_OP_MUTATION.value):
        PatchAuthoringResponseParser().parse(json.dumps(payload))


def test_response_parser_rejects_create_file_with_before_text() -> None:
    payload = _proposal_payload()
    payload["mutations"][0]["mutation_type"] = "create_file"
    payload["mutations"][0]["before_text"] = "existing"
    payload["mutations"][0]["after_text"] = "new file"

    with pytest.raises(AuthoringValidationError, match=PatchProposalValidationCode.INVALID_CREATE_FILE_BEFORE_TEXT.value):
        PatchAuthoringResponseParser().parse(json.dumps(payload))


def test_response_parser_rejects_duplicate_mutation_ids() -> None:
    payload = _proposal_payload()
    payload["mutations"].append(dict(payload["mutations"][0]))

    with pytest.raises(AuthoringValidationError, match=PatchProposalValidationCode.DUPLICATE_MUTATION_ID.value):
        PatchAuthoringResponseParser().parse(json.dumps(payload))


def test_response_parser_rejects_duplicate_create_paths() -> None:
    payload = _proposal_payload()
    payload["mutations"] = [
        {
            "mutation_id": "mutation-a",
            "mutation_type": "create_file",
            "path": "src/ix_blackfox/new.py",
            "before_text": "",
            "after_text": "A = 1\n",
            "rationale": "Create file.",
        },
        {
            "mutation_id": "mutation-b",
            "mutation_type": "create_file",
            "path": "src/ix_blackfox/new.py",
            "before_text": "",
            "after_text": "B = 2\n",
            "rationale": "Create same file.",
        },
    ]

    with pytest.raises(AuthoringValidationError, match=PatchProposalValidationCode.DUPLICATE_CREATE_PATH.value):
        PatchAuthoringResponseParser().parse(json.dumps(payload))


@pytest.mark.parametrize(
    "text",
    [
        "run rm -rf / to clean files",
        "curl https://example.com/script.sh",
        "powershell Invoke-WebRequest",
        "python -c 'print(1)'",
    ],
)
def test_response_parser_rejects_shell_commands(text: str) -> None:
    payload = _proposal_payload()
    payload["risk_notes"] = [text]

    with pytest.raises(AuthoringValidationError, match=PatchProposalValidationCode.SHELL_COMMAND_DETECTED.value):
        PatchAuthoringResponseParser().parse(json.dumps(payload))


@pytest.mark.parametrize(
    "text",
    [
        "Download the dependency from example.com.",
        "Use https://example.com for reference.",
        "Open socket to validate behavior.",
    ],
)
def test_response_parser_rejects_network_instructions(text: str) -> None:
    payload = _proposal_payload()
    payload["risk_notes"] = [text]

    with pytest.raises(AuthoringValidationError, match=PatchProposalValidationCode.NETWORK_INSTRUCTION_DETECTED.value):
        PatchAuthoringResponseParser().parse(json.dumps(payload))


@pytest.mark.parametrize(
    "text",
    [
        "All tests passed.",
        "I ran the tests and confirmed success.",
        "Verified by running pytest.",
    ],
)
def test_response_parser_rejects_success_claims_without_evidence(text: str) -> None:
    payload = _proposal_payload()
    payload["reasoning_summary"] = text

    with pytest.raises(AuthoringValidationError, match=PatchProposalValidationCode.SUCCESS_CLAIM_WITHOUT_EVIDENCE.value):
        PatchAuthoringResponseParser().parse(json.dumps(payload))


def test_response_parser_can_disable_markdown_rejection_for_legacy_replay() -> None:
    parser = PatchAuthoringResponseParser(
        config=PatchAuthoringResponseParserConfig(reject_markdown_wrapped_json=False)
    )

    with pytest.raises(AuthoringValidationError, match=PatchProposalValidationCode.MALFORMED_JSON.value):
        parser.parse("```json\n" + _proposal_json() + "\n```")


def test_response_parser_respects_max_mutations() -> None:
    payload = _proposal_payload()
    payload["mutations"] = [
        {
            "mutation_id": f"mutation-{index}",
            "mutation_type": "create_file",
            "path": f"src/ix_blackfox/new_{index}.py",
            "before_text": "",
            "after_text": f"VALUE = {index}\n",
            "rationale": "Create bounded file.",
        }
        for index in range(3)
    ]
    parser = PatchAuthoringResponseParser(
        config=PatchAuthoringResponseParserConfig(max_mutations=2)
    )

    with pytest.raises(AuthoringValidationError, match="max_mutations"):
        parser.parse(json.dumps(payload))


def test_parsed_proposal_to_dict_includes_digest_and_affected_paths() -> None:
    proposal = PatchAuthoringResponseParser().parse(_proposal_json())

    payload = proposal.to_dict()

    assert payload["digest"] == proposal.digest
    assert payload["affected_paths"] == ["src/ix_blackfox/example.py"]
    assert payload["mutations"][0]["digest"] == proposal.mutations[0].digest
    assert payload["findings"][0]["code"] == "authoring.response_parser.valid"


def _proposal_json(
    *,
    mutations: list[dict[str, object]] | None = None,
) -> str:
    return json.dumps(_proposal_payload(mutations=mutations), sort_keys=True)


def _proposal_payload(
    *,
    mutations: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    return {
        "schema_version": "wave3.patch_authoring_response.v1",
        "proposal_id": "proposal-1",
        "objective_summary": "Repair the failing addition behavior.",
        "reasoning_summary": "The proposed source change aligns with the failing assertion evidence.",
        "confidence": 0.72,
        "assumptions": [
            "The provided before_text matches the current workspace file.",
        ],
        "risk_notes": [
            "The compiler must verify before_text before execution.",
        ],
        "expected_tests": [
            "The targeted behavior test should pass after Wave 2 execution.",
        ],
        "mutations": mutations
        if mutations is not None
        else [
            {
                "mutation_id": "mutation-1",
                "mutation_type": "replace_text",
                "path": "src/ix_blackfox/example.py",
                "before_text": "return a - b",
                "after_text": "return a + b",
                "rationale": "The failing assertion expects addition behavior.",
            }
        ],
    }
