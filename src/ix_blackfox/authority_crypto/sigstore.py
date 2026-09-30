from __future__ import annotations

import os
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from ix_blackfox.authority_crypto.encoding import AuthorityProofError, read_document


@dataclass(frozen=True)
class CosignAdapter:
    executable: Path
    trusted_root: Path
    identity: str
    oidc_issuer: str
    timeout_seconds: float = 120

    def _validate(self, artifact: Path) -> None:
        if not self.executable.is_absolute() or not self.executable.is_file():
            raise AuthorityProofError(
                "A reviewed absolute Cosign executable path is required."
            )
        if (
            not self.identity
            or not self.oidc_issuer
            or not 0 < self.timeout_seconds <= 300
        ):
            raise AuthorityProofError(
                "Exact identity, issuer and bounded timeout are required."
            )
        read_document(self.trusted_root)
        read_document(artifact)

    def _run(self, args: list[str]) -> None:
        try:
            result = subprocess.run(
                [str(self.executable), *args],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=self.timeout_seconds,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise AuthorityProofError("Cosign operation is unavailable.") from exc
        if result.returncode != 0:
            raise AuthorityProofError("Cosign verification or signing failed.")

    def verify(self, artifact: Path, bundle: Path) -> None:
        self._validate(artifact)
        read_document(bundle)
        self._run(
            [
                "verify-blob",
                str(artifact.resolve()),
                "--bundle",
                str(bundle.resolve()),
                "--trusted-root",
                str(self.trusted_root.resolve()),
                "--certificate-identity",
                self.identity,
                "--certificate-oidc-issuer",
                self.oidc_issuer,
                "--offline",
            ]
        )

    def sign(self, artifact: Path, output: Path) -> None:
        self._validate(artifact)
        if output.exists():
            raise AuthorityProofError("Refusing to overwrite Sigstore bundle.")
        if not os.environ.get("SIGSTORE_ID_TOKEN") and not (
            os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL")
            and os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
        ):
            raise AuthorityProofError(
                "Non-interactive OIDC token configuration is required."
            )
        with tempfile.TemporaryDirectory(prefix="blackfox-cosign-") as directory:
            bundle = Path(directory) / "bundle.json"
            self._run(
                ["sign-blob", str(artifact.resolve()), "--bundle", str(bundle), "--yes"]
            )
            self.verify(artifact, bundle)
            output.parent.mkdir(parents=True, exist_ok=True)
            with output.open("xb") as stream:
                stream.write(bundle.read_bytes())
