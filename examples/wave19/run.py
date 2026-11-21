"""Run a local engineering verification chain against a persistent quota service."""

from __future__ import annotations

import argparse
import os
import secrets
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from collections.abc import Iterator
from contextlib import closing, contextmanager
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from typing import Any

from ix_blackfox.authority_crypto.cli import generate_keys
from ix_blackfox.authority_crypto.encoding import canonical_bytes, digest, strict_json
from ix_blackfox.authority_crypto.verification import verify_receipt
from ix_blackfox.autonomy.contracts import OperationError
from ix_blackfox.live_gateway.config import load_gateway_config
from ix_blackfox.live_gateway.evidence import issue_signed_evidence
from ix_blackfox.live_gateway.http_server import BlackFoxGatewayHttpServer
from ix_blackfox.live_gateway.service import LiveAuthorityGateway
from ix_blackfox.verification.cli import gateway_request
from ix_blackfox.verification.contracts import CONTRACT, SOURCES

HERE = Path(__file__).resolve().parent
SOURCE_PASSWORD = "WAVE19_SOURCE_PASSWORD"


@contextmanager
def listener(server: ThreadingHTTPServer) -> Iterator[int]:
    thread = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02})
    thread.start()
    try:
        yield server.server_port
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


class QuotaService(ThreadingHTTPServer):
    def __init__(self, database: Path, read_token: str) -> None:
        self.database = database
        self.read_token = read_token
        self.gateway: LiveAuthorityGateway
        with closing(sqlite3.connect(database)) as db, db:
            db.execute(
                "CREATE TABLE quota (id INTEGER PRIMARY KEY, cap INTEGER, request_id TEXT)"
            )
            db.execute("INSERT INTO quota VALUES (1, 4, '')")
        super().__init__(("127.0.0.1", 0), QuotaHandler)


class QuotaHandler(BaseHTTPRequestHandler):
    def log_message(self, *_: Any) -> None:
        pass

    def respond(self, body: dict[str, Any]) -> None:
        raw = canonical_bytes(body)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_POST(self) -> None:  # noqa: N802
        service = self.server
        assert isinstance(service, QuotaService)
        if (
            self.path != "/submit"
            or self.headers.get("Authorization")
            != "Bearer " + os.environ["BLACKFOX_SERVICE_TOKEN"]
        ):
            self.send_error(403)
            return
        store = service.gateway.receipt_store
        envelope = store.get(self.headers["X-BlackFox-Authorization-Receipt"])
        assert envelope and store.signing
        receipt = verify_receipt(envelope, store.signing.current_policy())
        request_id = self.headers["Idempotency-Key"]
        if (
            receipt["record_type"] != "authorization"
            or receipt["subject"]["digest"] != self.headers["X-BlackFox-Subject-Digest"]
        ):
            self.send_error(403)
            return
        body = strict_json(self.rfile.read(int(self.headers["Content-Length"])))
        desired = body.get("limit")
        if type(desired) is not int or desired < 1:
            self.send_error(400)
            return
        # The service's maximum quota is a provider-side constraint.
        with closing(sqlite3.connect(service.database)) as db, db:
            db.execute(
                "UPDATE quota SET cap=?, request_id=? WHERE id=1",
                (min(desired, 10), request_id),
            )
        self.respond({"accepted": True, "request_id": request_id})

    def do_GET(self) -> None:  # noqa: N802
        service = self.server
        assert isinstance(service, QuotaService)
        if self.headers.get("Authorization") != "Bearer " + service.read_token:
            self.send_error(403)
            return
        with closing(sqlite3.connect(service.database)) as db:
            cap, request_id = db.execute(
                "SELECT cap, request_id FROM quota WHERE id=1"
            ).fetchone()
        if self.path == "/quota":
            self.respond({"limit": cap, "request_id": request_id})
        elif (
            self.path.startswith("/probe/")
            and self.path.removeprefix("/probe/").isdigit()
        ):
            self.respond(
                {
                    "allowed": int(self.path.removeprefix("/probe/")) <= cap,
                    "request_id": request_id,
                }
            )
        else:
            self.send_error(404)


def plan(operation: str, limit: int) -> dict[str, Any]:
    return {
        "operation_id": operation,
        "expires_at": until(),
        "max_attempts": 1,
        "max_cost": 1,
        "steps": [
            {
                "step_id": "apply",
                "agent_id": "engineering-agent",
                "tool_name": "service.submit",
                "arguments": {
                    "revision": digest({"limit": limit}),
                    "payload": {"limit": limit},
                },
                "depends_on": [],
                "preconditions": {"window_open": True},
                "expected_outcome": {"limit": limit},
                "cost": 1,
                "recovery": {
                    "instruction": "Apply the last approved quota and read it back.",
                    "expected_outcome": {"limit": 8},
                },
            }
        ],
    }


def until() -> str:
    return (datetime.now(UTC) + timedelta(minutes=5)).isoformat()


def criterion(
    name: str, source: str, check: str, expected: dict[str, Any]
) -> dict[str, Any]:
    return {
        "id": name,
        "version": 1,
        "description": check,
        "step_id": "apply",
        "source": source,
        "check": check,
        "expected": expected,
    }


def change(operation: str, limit: int, output: Path) -> dict[str, Any]:
    artifact = {"limit": limit}
    (output / f"{operation}-change.json").write_bytes(canonical_bytes(artifact))
    return {
        "id": operation,
        "version": 1,
        "summary": f"Apply quota {limit}.",
        "artifact_sha256": digest(artifact),
    }


class Scenario:
    def __init__(
        self,
        gateway: LiveAuthorityGateway,
        origin: str,
        service_port: int,
        keys: Path,
        source_passwords: dict[str, str],
        read_token: str,
        output: Path,
    ) -> None:
        self.gateway = gateway
        self.origin = origin
        self.service_port = service_port
        self.keys = keys
        self.source_passwords = source_passwords
        self.read_token = read_token
        self.output = output

    def call(
        self, action: str, data: dict[str, Any], *, agent: bool = False
    ) -> dict[str, Any]:
        header, env = (
            ("X-BlackFox-Agent-Token", "BLACKFOX_AGENT_TOKEN")
            if agent
            else (
                "X-BlackFox-Operator-Token",
                "BLACKFOX_OPERATOR_TOKEN",
            )
        )
        return gateway_request(self.origin, action, data, {header: os.environ[env]})

    def dispatch(self, operation: str) -> dict[str, Any]:
        op = {"operation_id": operation}
        snapshot = self.call(
            "conditions",
            {
                **op,
                "epoch": 0,
                "facts": {"window_open": True},
                "valid_until": until(),
                "reason": "Open the local change window.",
            },
        )
        self.call(
            "approve",
            {
                **op,
                "snapshot_digest": snapshot["snapshot_digest"],
                "reviewer": "local-operator",
            },
        )
        step = {**op, "step_id": "apply"}
        subject = self.call("subject", step, agent=True)
        arguments = snapshot["plan"]["steps"]["apply"]["arguments"]
        assert (
            type(arguments["payload"]["limit"]) is int
            and arguments["payload"]["limit"] > 0
        )
        assert arguments["revision"] == digest(arguments["payload"])
        for kind, issuer, key, env, status, details in [
            (
                "test_result",
                "ci",
                "ci-hmac-v1",
                "BLACKFOX_CI_KEY",
                "passed",
                {
                    "passed": True,
                    "checks": ["positive quota", "revision matches change digest"],
                },
            ),
            (
                "human_approval",
                "human-review",
                "human-hmac-v1",
                "BLACKFOX_HUMAN_KEY",
                "approved",
                {
                    "decision": "approve",
                    "reviewer_kind": "human",
                    "reviewer_id": "local-operator",
                },
            ),
        ]:
            self.gateway.evidence_store.write(
                issue_signed_evidence(
                    evidence_id=f"{operation}-{kind}",
                    kind=kind,
                    issuer=issuer,
                    key_id=key,
                    secret=os.environ[env].encode(),
                    status=status,
                    repository_id=subject["repository_id"],
                    revision=subject["revision"],
                    target_digest=subject["digest"],
                    payload=details,
                )
            )
        return self.call(
            "dispatch",
            {
                **step,
                "evidence_refs": [
                    f"{operation}-test_result",
                    f"{operation}-human_approval",
                ],
            },
            agent=True,
        )

    def observe(
        self, operation: str, name: str, *, reject_tampered: bool = False
    ) -> dict[str, Any]:
        data = {"operation_id": operation, "requirement_id": name}
        target = self.call("verification-target", data)
        role = target["criterion"]["source"]
        target_path = self.output / f"{operation}-{name}-target.json"
        target_path.write_bytes(canonical_bytes(target))
        artifact = self.output / f"{operation}-{name}-artifact.json"
        # The collector receives its own encrypted key and read credential only.
        source_env = {
            key: val
            for key, val in os.environ.items()
            if not key.startswith("BLACKFOX_")
        }
        source_env.update(
            {
                SOURCE_PASSWORD: self.source_passwords[role],
                "WAVE19_READ_TOKEN": self.read_token,
            }
        )
        process = subprocess.run(
            [
                sys.executable,
                str(HERE / "observe.py"),
                str(target_path),
                str(self.keys / role),
                str(self.service_port),
                str(artifact),
            ],
            env=source_env,
            check=True,
            capture_output=True,
            timeout=20,
        )
        envelope = strict_json(process.stdout)
        if reject_tampered:
            tampered = {**envelope, "signatures": [{"keyid": role, "sig": "AA=="}]}
            try:
                self.call("verification-evidence", {**data, "envelope": tampered})
            except OperationError as exc:
                assert exc.status == 403
            else:
                raise RuntimeError("Tampered provider evidence was accepted.")
        return self.call("verification-evidence", {**data, "envelope": envelope})

    def close(self, operation: str, decision: str) -> dict[str, Any]:
        op = {"operation_id": operation}
        report = self.call("verification-assess", op)
        return self.call(
            "verification-close",
            {
                **op,
                "epoch": report["epoch"],
                "assessment_digest": report["assessment_digest"],
                "decision": decision,
                "reviewer": "local-operator",
                "reason": "Reviewed retained requirement evidence.",
            },
        )

    def verify(self, operation: str) -> dict[str, Any]:
        bundle_path = self.output / f"{operation}-bundle.json"
        bundle_path.write_bytes(
            canonical_bytes(
                self.call("verification-export", {"operation_id": operation})
            )
        )
        command = [
            sys.executable,
            "-m",
            "ix_blackfox.verification.cli",
            "verify",
            str(bundle_path),
            "--operation",
            operation,
            "--authority",
            str(self.output / "authority.json"),
        ]
        for role in SOURCES:
            command.extend(["--" + role, str(self.output / f"{role}.json")])
        process = subprocess.run(command, check=True, capture_output=True, timeout=20)
        return strict_json(process.stdout)

    def execute(self) -> dict[str, Any]:
        for operation, limit in (("quota-8", 8), ("quota-20", 20)):
            self.call(
                "propose-verification",
                {
                    "plan": plan(operation, limit),
                    "contract": {
                        "schema_version": CONTRACT,
                        "change": change(operation, limit, self.output),
                        "requirements": [
                            criterion(
                                "quota", "provider", "applied-quota", {"limit": limit}
                            ),
                            criterion(
                                "boundary",
                                "test",
                                "quota-boundary",
                                {"boundary_ok": True},
                            ),
                            criterion(
                                "burst",
                                "simulation",
                                "burst-model",
                                {"blocked": 1 if limit == 8 else 0},
                            ),
                        ],
                        "rollback_requirements": [
                            criterion(
                                "restored", "provider", "applied-quota", {"limit": 8}
                            ),
                            criterion(
                                "restored-boundary",
                                "test",
                                "quota-boundary",
                                {"boundary_ok": True},
                            ),
                        ],
                    },
                },
                agent=True,
            )
            transport = self.dispatch(operation)
            assert transport["execution_state"] == "response_received"
            assert (
                transport["upstream_status"] == 200
                and transport["result"]["accepted"] is True
            )
            provider = self.observe(operation, "quota", reject_tampered=limit == 20)
            self.observe(operation, "boundary")
            self.observe(operation, "burst")
            if limit == 8:
                assert self.close(operation, "verified")["current"]
                good = self.verify(operation)
            else:
                assert provider["requirements"]["quota"]["status"] == "failed"
                applied = provider["requirements"]["quota"]["evidence"][0]["value"][
                    "limit"
                ]
                try:
                    self.close(operation, "verified")
                except OperationError as exc:
                    assert exc.status == 409
                else:
                    raise RuntimeError("A failed requirement was closed as verified.")

        recovery = "restore-quota-8"
        self.call(
            "propose-followup",
            {
                "plan": plan(recovery, 8),
                "parent_operation_id": "quota-20",
                "change": change(recovery, 8, self.output),
                "mode": "rollback",
            },
            agent=True,
        )
        self.dispatch(recovery)
        self.observe(recovery, "restored")
        self.observe(recovery, "restored-boundary")
        assert self.close(recovery, "verified")["current"]
        assert self.close("quota-20", "followup")["outcome_at_closure"] == "rolled_back"
        rolled_back = self.verify("quota-20")
        return {
            "verified": good["operation_id"],
            "failed_operation": "quota-20",
            "provider_acknowledged_failed_write": True,
            "requested_quota": 20,
            "independently_observed_quota": applied,
            "tampered_evidence_rejected": True,
            "verified_closure_blocked": True,
            "recovery_operation": rolled_back["terminal_operation_id"],
            "recovered_quota": rolled_back["requirements"]["restored"]["evidence"][0][
                "value"
            ]["limit"],
            "final_outcome": rolled_back["outcome_at_closure"],
        }


def run(output: Path) -> dict[str, Any]:
    output.mkdir(parents=True, exist_ok=False)
    template = (HERE.parent / "wave18" / "blackfox.gateway.toml").read_text(
        encoding="utf-8"
    )
    for name in (
        "SIGNING_PASSWORD",
        "CI_KEY",
        "HUMAN_KEY",
        "OBSERVER_KEY",
        "AGENT_TOKEN",
        "RELEASE_AGENT_TOKEN",
        "OPERATOR_TOKEN",
        "SERVICE_TOKEN",
    ):
        os.environ["BLACKFOX_" + name] = secrets.token_hex(32)
    with tempfile.TemporaryDirectory(prefix="blackfox-wave19-") as raw:
        root = Path(raw)
        generate_keys(
            root / "receipt-keys",
            "BLACKFOX_SIGNING_PASSWORD",
            "enterprise-authority",
            "local-gateway",
            "quota",
        )
        shutil.copyfile(
            root / "receipt-keys" / "trust-policy.json", output / "authority.json"
        )
        source_passwords = {}
        for role in SOURCES:
            source_passwords[role] = os.environ[SOURCE_PASSWORD] = secrets.token_hex(32)
            generate_keys(
                root / role, SOURCE_PASSWORD, role, f"quota-{role}", "local-proof"
            )
            shutil.copyfile(root / role / "trust-policy.json", output / f"{role}.json")
        del os.environ[SOURCE_PASSWORD]
        read_token = secrets.token_hex(32)
        provider = QuotaService(root / "provider.sqlite3", read_token)
        with listener(provider) as port:
            config = root / "gateway.toml"
            trust = "\n".join(
                f'{role} = "{role}/trust-policy.json"' for role in SOURCES
            )
            config.write_text(
                template.replace(
                    "[[mesh.connectors]]",
                    "[autonomy.verification]\n" + trust + "\n\n[[mesh.connectors]]",
                ).replace(
                    'base_url = "https://engineering.example.invalid"',
                    f'base_url = "http://127.0.0.1:{port}"\nallow_loopback_http = true',
                ),
                encoding="utf-8",
            )
            gateway = LiveAuthorityGateway.from_config(load_gateway_config(config))
            provider.gateway = gateway
            try:
                assert gateway.status()["ready"]
                with listener(
                    BlackFoxGatewayHttpServer(("127.0.0.1", 0), gateway)
                ) as gateway_port:
                    result = Scenario(
                        gateway,
                        f"http://127.0.0.1:{gateway_port}",
                        port,
                        root,
                        source_passwords,
                        read_token,
                        output,
                    ).execute()
            finally:
                gateway.receipt_store.close()
    (output / "result.json").write_bytes(canonical_bytes(result) + b"\n")
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    print(canonical_bytes(run(args.output.resolve())).decode())


if __name__ == "__main__":
    main()
