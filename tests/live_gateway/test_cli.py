from __future__ import annotations

import io
import json
import os
from contextlib import redirect_stdout
from pathlib import Path

from ix_blackfox.interface import main


def test_interface_routes_gateway_check_and_subject_commands(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[2]
    source = root / "examples" / "wave14" / "blackfox.gateway.toml"
    config = tmp_path / "blackfox.gateway.toml"
    text = source.read_text(encoding="utf-8")
    config.write_text(text, encoding="utf-8")
    os.environ["BLACKFOX_WAVE14_CI_KEY"] = "test-ci-secret-0123456789abcdef0123456"
    os.environ["BLACKFOX_WAVE14_HUMAN_KEY"] = "test-human-secret-0123456789abcdef012"
    os.environ["BLACKFOX_WAVE14_AGENT_TOKEN"] = "test-agent-token-0123456789abcdef012345"
    os.environ["BLACKFOX_WAVE14_OPERATOR_TOKEN"] = "test-operator-token-0123456789abcdef012"

    check_buffer = io.StringIO()
    with redirect_stdout(check_buffer):
        exit_code = main(["gateway", "check", "--config", str(config)])
    status = json.loads(check_buffer.getvalue())
    assert exit_code == 0
    assert status["mode"] == "live_authority_gateway"

    subject_buffer = io.StringIO()
    with redirect_stdout(subject_buffer):
        exit_code = main(
            [
                "gateway",
                "subject",
                "--config",
                str(config),
                "--agent-id",
                "coding-agent-07",
                "--tool-name",
                "filesystem.write_file",
                "--protocol",
                "mcp/2026-07-28",
                "--arguments-json",
                '{"path":"docs/a.md","revision":"abc123","content":"x"}',
            ]
        )
    subject = json.loads(subject_buffer.getvalue())
    assert exit_code == 0
    assert subject["digest"]
    assert subject["path"] == "docs/a.md"
    assert subject["revision"] == "abc123"
