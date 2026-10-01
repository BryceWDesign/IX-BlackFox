from __future__ import annotations

import argparse
import hashlib
import importlib.machinery
import importlib.util
import json
import platform
import statistics
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from ix_blackfox.authority_crypto.cli import public_trust_document
from ix_blackfox.authority_crypto.signing import LocalSigner, SigningController
from ix_blackfox.authority_crypto.trust import TrustPolicy
from ix_blackfox.live_gateway.receipts import AuthorityReceiptStore


def payload() -> dict[str, Any]:
    return {
        "record_type": "denial",
        "recorded_at": "2026-09-30T00:00:00+00:00",
        "protocol": "blackfox-api/v1",
        "subject": {"agent_id": "benchmark", "tool_name": "filesystem.write_file"},
        "authority_decision": {"status": "block", "reason_codes": ["benchmark"]},
        "authenticated_principal": {},
        "evidence_refs": [],
        "evaluated_evidence_digests": {},
        "single_use_evidence_claims": [],
        "upstream_attempted": False,
        "upstream_status": 0,
        "upstream_response_sha256": "",
        "upstream_error": "benchmark",
        "execution_state": "not_attempted",
        "executed": False,
    }


def measure(store_class: Any, targets: list[int], batch: int) -> dict[str, Any]:
    key = ed25519.Ed25519PrivateKey.generate()
    pem = (
        key.public_key()
        .public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        .decode()
    )
    policy = TrustPolicy.from_dict(
        public_trust_document(pem, "benchmark", "benchmark", "benchmark")
    )
    controller = SigningController(LocalSigner("benchmark", "Ed25519", key), policy)
    with tempfile.TemporaryDirectory(prefix="blackfox-append-benchmark-") as directory:
        store = store_class(Path(directory) / "receipts.sqlite3", controller)
        samples = []
        count = 0
        started = time.perf_counter()
        for target in targets:
            while count < target:
                store.append(payload())
                count += 1
            times = []
            for _ in range(batch):
                before = time.perf_counter()
                store.append(payload())
                times.append((time.perf_counter() - before) * 1000)
                count += 1
            samples.append(
                {
                    "existing_receipts_before_batch": target,
                    "batch_size": batch,
                    "median_ms": statistics.median(times),
                    "min_ms": min(times),
                    "max_ms": max(times),
                }
            )
        append_seconds = time.perf_counter() - started
        before = time.perf_counter()
        audit = store.verify_chain()
        audit_seconds = time.perf_counter() - before
        if hasattr(store, "close"):
            store.close()
        if not audit.passed:
            raise RuntimeError(str(audit.issues))
        return {
            "samples": samples,
            "final_receipt_count": count,
            "append_seconds": append_seconds,
            "full_audit_seconds": audit_seconds,
            "full_audit_passed": audit.passed,
        }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Local signed SQLite append microbenchmark; no production throughput claim."
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--baseline-source", type=Path)
    parser.add_argument("--baseline-verifier", type=Path)
    parser.add_argument("--batch", type=int, default=25)
    args = parser.parse_args()
    if not 1 <= args.batch <= 100:
        parser.error("batch must be 1..100")
    result: dict[str, Any] = {
        "schema_version": "wave16.append_benchmark.v1",
        "python": sys.version,
        "platform": platform.platform(),
        "signer": "local Ed25519",
        "payload": "pre-evaluation denial",
        "storage": "temporary SQLite WAL, synchronous FULL",
        "clock": "time.perf_counter",
        "boundary": "One long-lived store; independent writers trigger conservative full replay. Local microbenchmark, not production throughput or remote KMS validation.",
    }
    if args.baseline_verifier and not args.baseline_source:
        parser.error("baseline-verifier requires baseline-source")
    if args.baseline_source:
        loader = importlib.machinery.SourceFileLoader(
            "wave16_original_receipts", str(args.baseline_source)
        )
        spec = importlib.util.spec_from_loader(loader.name, loader)
        if spec is None or spec.loader is None:
            raise RuntimeError("Cannot load baseline source")
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        if args.baseline_verifier:
            original_loader = importlib.machinery.SourceFileLoader(
                "wave16_original_verifier", str(args.baseline_verifier)
            )
            original_spec = importlib.util.spec_from_loader(
                original_loader.name, original_loader
            )
            if original_spec is None:
                raise RuntimeError("Cannot load original verifier")
            original = importlib.util.module_from_spec(original_spec)
            sys.modules[original_spec.name] = original
            original_loader.exec_module(original)
            module.verify_records = original.verify_records
        result["baseline_inputs"] = {
            "receipts_sha256": hashlib.sha256(
                args.baseline_source.read_bytes()
            ).hexdigest(),
            "verifier_sha256": hashlib.sha256(
                args.baseline_verifier.read_bytes()
            ).hexdigest()
            if args.baseline_verifier
            else "current verifier",
        }
        result["baseline"] = measure(
            module.AuthorityReceiptStore, [100, 500], args.batch
        )
    result["hardened_inputs"] = {
        name: hashlib.sha256(
            (Path(__file__).resolve().parents[1] / name).read_bytes()
        ).hexdigest()
        for name in [
            "src/ix_blackfox/live_gateway/receipts.py",
            "src/ix_blackfox/authority_crypto/verification.py",
        ]
    }
    result["hardened"] = measure(
        AuthorityReceiptStore, [100, 500, 1000, 5000], args.batch
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
