from __future__ import annotations

import json

import pytest

from ix_blackfox.authoring import (
    AuthoringCompilationError,
    CompiledPatchCandidate,
    PatchAuthoringResponseParser,
    PatchCompilationFindingCode,
    PatchCompilationStatus,
    PatchProposalCompiler,
    PatchProposalCompilerConfig,
)
from ix_blackfox.tools import PatchFileChangeKind, ToolPathPolicy


def test_compiler_compiles_snippet_replace_text_into_whole_file_patch(tmp_path) -> None:
    workspace = tmp_path
    source_dir = workspace / "src" / "ix_blackfox"
    source_dir.mkdir(parents=True)
    target = source_dir / "example.py"
    target.write_text(
        "def add(a, b):\n    return a - b\n",
        encoding="utf-8",
    )

    proposal = PatchAuthoringResponseParser().parse(
        _proposal_json(
            mutations=[
                {
                    "mutation_id": "mutation-1",
                    "mutation_type": "replace_text",
                    "path": "src/ix_blackfox/example.py",
                    "before_text": "return a - b",
                    "after_text": "return a + b",
                    "rationale": "The failing assertion expects addition.",
                }
            ]
        )
    )

    candidate = PatchProposalCompiler(workspace_root=workspace).compile(proposal)

    assert candidate.status is PatchCompilationStatus.COMPILED
    assert candidate.proposal_id == proposal.proposal_id
    assert candidate.proposal_digest == proposal.digest
    assert candidate.patch_diff.created_by == "blackfox-authoring"
    assert candidate.patch_diff.changed_paths == ("src/ix_blackfox/example.py",)
    assert candidate.patch_diff.file_changes[0].change_kind is PatchFileChangeKind.MODIFY
    assert candidate.patch_diff.file_changes[0].before_text == "def add(a, b):\n    return a - b\n"
    assert candidate.patch_diff.file_changes[0].after_text == "def add(a, b):\n    return a + b\n"
    assert candidate.patch_diff.file_changes[0].metadata["before_match_mode"] == "snippet"


def test_compiler_compiles_whole_file_replace_text(tmp_path) -> None:
    workspace = tmp_path
    (workspace / "src").mkdir()
    target = workspace / "src" / "example.py"
    before = "VALUE = 1\n"
    after = "VALUE = 2\n"
    target.write_text(before, encoding="utf-8")

    proposal = PatchAuthoringResponseParser().parse(
        _proposal_json(
            mutations=[
                {
                    "mutation_id": "mutation-1",
                    "mutation_type": "replace_text",
                    "path": "src/example.py",
                    "before_text": before,
                    "after_text": after,
                    "rationale": "Update value.",
                }
            ]
        )
    )

    candidate = PatchProposalCompiler(workspace_root=workspace).compile(proposal)
    change = candidate.patch_diff.file_changes[0]

    assert change.before_text == before
    assert change.after_text == after
    assert change.metadata["before_match_mode"] == "whole_file"


def test_compiler_compiles_create_file_into_add_change(tmp_path) -> None:
    workspace = tmp_path
    (workspace / "src").mkdir()

    proposal = PatchAuthoringResponseParser().parse(
        _proposal_json(
            mutations=[
                {
                    "mutation_id": "mutation-create",
                    "mutation_type": "create_file",
                    "path": "src/new_module.py",
                    "before_text": "",
                    "after_text": "VALUE = 1\n",
                    "rationale": "Create missing module.",
                }
            ]
        )
    )

    candidate = PatchProposalCompiler(workspace_root=workspace).compile(proposal)
    change = candidate.patch_diff.file_changes[0]

    assert change.change_kind is PatchFileChangeKind.ADD
    assert change.path == "src/new_module.py"
    assert change.before_text is None
    assert change.after_text == "VALUE = 1\n"
    assert change.metadata["mutation_id"] == "mutation-create"


def test_compiler_rejects_create_file_when_target_exists(tmp_path) -> None:
    workspace = tmp_path
    (workspace / "src").mkdir()
    (workspace / "src" / "new_module.py").write_text("VALUE = 0\n", encoding="utf-8")

    proposal = PatchAuthoringResponseParser().parse(
        _proposal_json(
            mutations=[
                {
                    "mutation_id": "mutation-create",
                    "mutation_type": "create_file",
                    "path": "src/new_module.py",
                    "before_text": "",
                    "after_text": "VALUE = 1\n",
                    "rationale": "Create missing module.",
                }
            ]
        )
    )

    with pytest.raises(
        AuthoringCompilationError,
        match=PatchCompilationFindingCode.CREATE_TARGET_EXISTS.value,
    ):
        PatchProposalCompiler(workspace_root=workspace).compile(proposal)


def test_compiler_rejects_replace_when_target_missing(tmp_path) -> None:
    workspace = tmp_path
    (workspace / "src").mkdir()

    proposal = PatchAuthoringResponseParser().parse(_proposal_json())

    with pytest.raises(
        AuthoringCompilationError,
        match=PatchCompilationFindingCode.TARGET_NOT_FOUND.value,
    ):
        PatchProposalCompiler(workspace_root=workspace).compile(proposal)


def test_compiler_rejects_stale_before_text(tmp_path) -> None:
    workspace = tmp_path
    (workspace / "src" / "ix_blackfox").mkdir(parents=True)
    (workspace / "src" / "ix_blackfox" / "example.py").write_text(
        "def add(a, b):\n    return a + b\n",
        encoding="utf-8",
    )

    proposal = PatchAuthoringResponseParser().parse(_proposal_json())

    with pytest.raises(
        AuthoringCompilationError,
        match=PatchCompilationFindingCode.STALE_BEFORE_TEXT.value,
    ):
        PatchProposalCompiler(workspace_root=workspace).compile(proposal)


def test_compiler_rejects_non_unique_before_text_by_default(tmp_path) -> None:
    workspace = tmp_path
    (workspace / "src").mkdir()
    (workspace / "src" / "example.py").write_text(
        "value = 1\nvalue = 1\n",
        encoding="utf-8",
    )
    proposal = PatchAuthoringResponseParser().parse(
        _proposal_json(
            mutations=[
                {
                    "mutation_id": "mutation-1",
                    "mutation_type": "replace_text",
                    "path": "src/example.py",
                    "before_text": "value = 1",
                    "after_text": "value = 2",
                    "rationale": "Update value.",
                }
            ]
        )
    )

    with pytest.raises(
        AuthoringCompilationError,
        match=PatchCompilationFindingCode.NON_UNIQUE_BEFORE_TEXT.value,
    ):
        PatchProposalCompiler(workspace_root=workspace).compile(proposal)


def test_compiler_can_allow_multiple_replacements_when_configured(tmp_path) -> None:
    workspace = tmp_path
    (workspace / "src").mkdir()
    (workspace / "src" / "example.py").write_text(
        "value = 1\nvalue = 1\n",
        encoding="utf-8",
    )
    proposal = PatchAuthoringResponseParser().parse(
        _proposal_json(
            mutations=[
                {
                    "mutation_id": "mutation-1",
                    "mutation_type": "replace_text",
                    "path": "src/example.py",
                    "before_text": "value = 1",
                    "after_text": "value = 2",
                    "rationale": "Update repeated value.",
                }
            ]
        )
    )
    compiler = PatchProposalCompiler(
        workspace_root=workspace,
        config=PatchProposalCompilerConfig(require_unique_replace_text=False),
    )

    candidate = compiler.compile(proposal)

    assert candidate.patch_diff.file_changes[0].after_text == "value = 2\nvalue = 2\n"


def test_compiler_respects_path_policy_allowed_roots(tmp_path) -> None:
    workspace = tmp_path
    (workspace / "src").mkdir()
    (workspace / "docs").mkdir()
    (workspace / "docs" / "example.md").write_text("before\n", encoding="utf-8")

    proposal = PatchAuthoringResponseParser().parse(
        _proposal_json(
            mutations=[
                {
                    "mutation_id": "mutation-1",
                    "mutation_type": "replace_text",
                    "path": "docs/example.md",
                    "before_text": "before",
                    "after_text": "after",
                    "rationale": "Update docs.",
                }
            ]
        )
    )

    with pytest.raises(
        AuthoringCompilationError,
        match=PatchCompilationFindingCode.PATH_POLICY_VIOLATION.value,
    ):
        PatchProposalCompiler(
            workspace_root=workspace,
            path_policy=ToolPathPolicy(allowed_roots=("src",), blocked_roots=()),
        ).compile(proposal)


def test_compiler_rejects_blocked_path_even_when_file_exists(tmp_path) -> None:
    workspace = tmp_path
    (workspace / "run_bundles").mkdir()
    (workspace / "run_bundles" / "receipt.json").write_text("before\n", encoding="utf-8")

    proposal = PatchAuthoringResponseParser().parse(
        _proposal_json(
            mutations=[
                {
                    "mutation_id": "mutation-1",
                    "mutation_type": "replace_text",
                    "path": "run_bundles/receipt.json",
                    "before_text": "before",
                    "after_text": "after",
                    "rationale": "Should be blocked.",
                }
            ]
        )
    )

    with pytest.raises(
        AuthoringCompilationError,
        match=PatchCompilationFindingCode.PATH_POLICY_VIOLATION.value,
    ):
        PatchProposalCompiler(workspace_root=workspace).compile(proposal)


def test_compiler_rejects_compiled_file_size_limit(tmp_path) -> None:
    workspace = tmp_path
    (workspace / "src").mkdir()
    (workspace / "src" / "example.py").write_text("before\n", encoding="utf-8")

    proposal = PatchAuthoringResponseParser().parse(
        _proposal_json(
            mutations=[
                {
                    "mutation_id": "mutation-1",
                    "mutation_type": "replace_text",
                    "path": "src/example.py",
                    "before_text": "before",
                    "after_text": "x" * 100,
                    "rationale": "Large replacement.",
                }
            ]
        )
    )
    compiler = PatchProposalCompiler(
        workspace_root=workspace,
        config=PatchProposalCompilerConfig(max_compiled_file_bytes=20),
    )

    with pytest.raises(AuthoringCompilationError, match="compiled_file_too_large"):
        compiler.compile(proposal)


def test_compiled_candidate_round_trip_preserves_patch_diff(tmp_path) -> None:
    workspace = tmp_path
    (workspace / "src" / "ix_blackfox").mkdir(parents=True)
    (workspace / "src" / "ix_blackfox" / "example.py").write_text(
        "def add(a, b):\n    return a - b\n",
        encoding="utf-8",
    )

    proposal = PatchAuthoringResponseParser().parse(_proposal_json())
    candidate = PatchProposalCompiler(workspace_root=workspace).compile(proposal)

    restored = CompiledPatchCandidate.from_dict(candidate.to_dict())

    assert restored.candidate_id == candidate.candidate_id
    assert restored.status is PatchCompilationStatus.COMPILED
    assert restored.proposal_id == candidate.proposal_id
    assert restored.proposal_digest == candidate.proposal_digest
    assert restored.patch_diff.changed_paths == candidate.patch_diff.changed_paths
    assert restored.patch_diff.file_changes[0].after_text == candidate.patch_diff.file_changes[0].after_text


def test_compiler_findings_convert_to_authoring_findings(tmp_path) -> None:
    workspace = tmp_path
    (workspace / "src" / "ix_blackfox").mkdir(parents=True)
    (workspace / "src" / "ix_blackfox" / "example.py").write_text(
        "def add(a, b):\n    return a - b\n",
        encoding="utf-8",
    )

    proposal = PatchAuthoringResponseParser().parse(_proposal_json())
    candidate = PatchProposalCompiler(workspace_root=workspace).compile(proposal)

    authoring_findings = tuple(finding.to_authoring_finding() for finding in candidate.findings)

    assert authoring_findings
    assert all(finding.code.startswith("authoring.patch_compiler.") for finding in authoring_findings)


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
            "The compiler must verify before_text against the current workspace.",
        ],
        "risk_notes": [
            "The compiled patch must still pass Wave 2 governance.",
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
