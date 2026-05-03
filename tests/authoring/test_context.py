from __future__ import annotations

import hashlib

from ix_blackfox.authoring import (
    AuthoringContextBuilder,
    AuthoringContextBuilderConfig,
    ContextSkipReason,
)
from ix_blackfox.tools.manifest import ToolPathPolicy


def test_context_builder_collects_text_files_deterministically(tmp_path) -> None:
    workspace = tmp_path
    source_dir = workspace / "src"
    tests_dir = workspace / "tests"
    source_dir.mkdir()
    tests_dir.mkdir()

    (source_dir / "b.py").write_text("print('b')\n", encoding="utf-8")
    (source_dir / "a.py").write_text("print('a')\n", encoding="utf-8")
    (tests_dir / "test_a.py").write_text("def test_a():\n    assert True\n", encoding="utf-8")

    builder = AuthoringContextBuilder(
        workspace_root=workspace,
        config=AuthoringContextBuilderConfig(include_paths=("src", "tests")),
    )

    snapshot = builder.build()

    assert snapshot.context.paths == (
        "src/a.py",
        "src/b.py",
        "tests/test_a.py",
    )
    assert tuple(document.path for document in snapshot.documents) == snapshot.context.paths
    assert snapshot.context.total_bytes == sum(
        document.size_bytes for document in snapshot.documents
    )
    assert snapshot.context.digest is not None
    assert len(snapshot.context.digest) == 64


def test_context_builder_records_document_hashes(tmp_path) -> None:
    workspace = tmp_path
    path = workspace / "src"
    path.mkdir()
    file_path = path / "example.py"
    file_path.write_text("VALUE = 42\n", encoding="utf-8")

    builder = AuthoringContextBuilder(
        workspace_root=workspace,
        config=AuthoringContextBuilderConfig(include_paths=("src/example.py",)),
    )

    snapshot = builder.build()
    document = snapshot.document_by_path("src/example.py")

    assert document.text == "VALUE = 42\n"
    assert document.sha256 == hashlib.sha256(b"VALUE = 42\n").hexdigest()
    assert snapshot.context.files[0].sha256 == document.sha256


def test_context_builder_excludes_hidden_secret_and_blocked_paths(tmp_path) -> None:
    workspace = tmp_path
    (workspace / "src").mkdir()
    (workspace / ".git").mkdir()
    (workspace / ".hidden").mkdir()
    (workspace / "secrets").mkdir()

    (workspace / "src" / "ok.py").write_text("ok = True\n", encoding="utf-8")
    (workspace / ".git" / "config").write_text("private\n", encoding="utf-8")
    (workspace / ".hidden" / "note.py").write_text("hidden\n", encoding="utf-8")
    (workspace / ".env").write_text("TOKEN=abc\n", encoding="utf-8")
    (workspace / "secrets" / "api_token.txt").write_text("token\n", encoding="utf-8")

    builder = AuthoringContextBuilder(
        workspace_root=workspace,
        config=AuthoringContextBuilderConfig(
            include_paths=(".",),
            blocked_roots=(".git", "secrets"),
        ),
    )

    snapshot = builder.build()

    assert snapshot.context.paths == ("src/ok.py",)
    reasons = {item.reason for item in snapshot.skipped}
    assert ContextSkipReason.BLOCKED_PATH in reasons
    assert ContextSkipReason.HIDDEN_PATH in reasons
    assert ContextSkipReason.SECRET_LIKE_PATH in reasons


def test_context_builder_enforces_file_size_limit(tmp_path) -> None:
    workspace = tmp_path
    (workspace / "src").mkdir()
    (workspace / "src" / "small.py").write_text("x = 1\n", encoding="utf-8")
    (workspace / "src" / "large.py").write_text("x" * 50, encoding="utf-8")

    builder = AuthoringContextBuilder(
        workspace_root=workspace,
        config=AuthoringContextBuilderConfig(
            include_paths=("src",),
            max_file_bytes=10,
        ),
    )

    snapshot = builder.build()

    assert snapshot.context.paths == ("src/small.py",)
    assert any(
        item.path == "src/large.py"
        and item.reason is ContextSkipReason.FILE_TOO_LARGE
        for item in snapshot.skipped
    )


def test_context_builder_enforces_total_bytes_limit(tmp_path) -> None:
    workspace = tmp_path
    (workspace / "src").mkdir()
    (workspace / "src" / "a.py").write_text("aaaa\n", encoding="utf-8")
    (workspace / "src" / "b.py").write_text("bbbb\n", encoding="utf-8")
    (workspace / "src" / "c.py").write_text("cccc\n", encoding="utf-8")

    builder = AuthoringContextBuilder(
        workspace_root=workspace,
        config=AuthoringContextBuilderConfig(
            include_paths=("src",),
            max_total_bytes=10,
        ),
    )

    snapshot = builder.build()

    assert snapshot.truncated
    assert snapshot.context.paths == ("src/a.py", "src/b.py")
    assert any(
        item.reason is ContextSkipReason.TOTAL_BYTES_LIMIT
        for item in snapshot.skipped
    )


def test_context_builder_respects_tool_path_policy_allowed_roots(tmp_path) -> None:
    workspace = tmp_path
    (workspace / "src").mkdir()
    (workspace / "docs").mkdir()
    (workspace / "src" / "ok.py").write_text("ok = True\n", encoding="utf-8")
    (workspace / "docs" / "blocked.md").write_text("blocked\n", encoding="utf-8")

    builder = AuthoringContextBuilder(
        workspace_root=workspace,
        config=AuthoringContextBuilderConfig(include_paths=("src", "docs")),
        path_policy=ToolPathPolicy(allowed_roots=("src",), blocked_roots=()),
    )

    snapshot = builder.build()

    assert snapshot.context.paths == ("src/ok.py",)
    assert any(
        item.path == "docs"
        and item.reason is ContextSkipReason.PATH_POLICY_VIOLATION
        for item in snapshot.skipped
    )


def test_context_builder_rejects_binary_files(tmp_path) -> None:
    workspace = tmp_path
    (workspace / "src").mkdir()
    (workspace / "src" / "binary.bin").write_bytes(b"\x00\x01\x02\x03")
    (workspace / "src" / "ok.py").write_text("ok = True\n", encoding="utf-8")

    builder = AuthoringContextBuilder(
        workspace_root=workspace,
        config=AuthoringContextBuilderConfig(include_paths=("src",)),
    )

    snapshot = builder.build()

    assert snapshot.context.paths == ("src/ok.py",)
    assert any(
        item.path == "src/binary.bin"
        and item.reason is ContextSkipReason.BINARY_FILE
        for item in snapshot.skipped
    )


def test_context_builder_records_path_policy_violations(tmp_path) -> None:
    workspace = tmp_path
    (workspace / "src").mkdir()
    (workspace / "src" / "ok.py").write_text("ok = True\n", encoding="utf-8")

    builder = AuthoringContextBuilder(
        workspace_root=workspace,
        config=AuthoringContextBuilderConfig(include_paths=("../outside", "src")),
    )

    snapshot = builder.build()

    assert snapshot.context.paths == ("src/ok.py",)
    assert any(
        item.reason is ContextSkipReason.PATH_POLICY_VIOLATION
        for item in snapshot.skipped
    )


def test_context_snapshot_reports_skip_reason_counts(tmp_path) -> None:
    workspace = tmp_path
    (workspace / "src").mkdir()
    (workspace / "src" / "ok.py").write_text("ok = True\n", encoding="utf-8")
    (workspace / "src" / "large.py").write_text("x" * 50, encoding="utf-8")
    (workspace / ".env").write_text("TOKEN=abc\n", encoding="utf-8")

    builder = AuthoringContextBuilder(
        workspace_root=workspace,
        config=AuthoringContextBuilderConfig(
            include_paths=(".",),
            max_file_bytes=10,
        ),
    )

    snapshot = builder.build()

    assert snapshot.skip_reason_counts[ContextSkipReason.FILE_TOO_LARGE.value] == 1
    assert snapshot.skip_reason_counts[ContextSkipReason.SECRET_LIKE_PATH.value] == 1
    assert snapshot.to_manifest_dict()["document_count"] == 1
