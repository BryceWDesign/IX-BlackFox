"""Protect Wave 17's temporary SQLite cleanup order on every OS."""

import os
from pathlib import Path
from types import SimpleNamespace

from ix_blackfox.live_gateway.receipts import AuthorityReceiptStore
from scripts import run_wave17_integration_mesh_ci as mesh_ci


def test_wave17_closes_signed_receipt_store_before_temp_cleanup(
    monkeypatch, tmp_path: Path
) -> None:
    signed_stores: list[AuthorityReceiptStore] = []
    original_post_init = AuthorityReceiptStore.__post_init__
    original_tempdir = mesh_ci.tempfile.TemporaryDirectory

    def tracked_post_init(self: AuthorityReceiptStore) -> None:
        original_post_init(self)
        if self.signing is not None:
            signed_stores.append(self)

    class WindowsLikeTemporaryDirectory(original_tempdir):
        def cleanup(self) -> None:
            if self.name and Path(self.name).name.startswith("blackfox-wave17-"):
                if any(not store._closed for store in signed_stores):
                    raise PermissionError(
                        "Windows would refuse to unlink an open authority.sqlite3"
                    )
            super().cleanup()

    monkeypatch.setattr(AuthorityReceiptStore, "__post_init__", tracked_post_init)
    monkeypatch.setattr(
        mesh_ci,
        "tempfile",
        SimpleNamespace(TemporaryDirectory=WindowsLikeTemporaryDirectory),
    )
    root = Path(__file__).resolve().parents[2]
    monkeypatch.setenv(
        "PYTHONPATH", str(root / "src") + os.pathsep + os.environ.get("PYTHONPATH", "")
    )
    result = mesh_ci.run(root, samples=1, output=tmp_path / "public-proof")

    assert result["passed"], {k:v for k,v in result["checks"].items() if not v}
    assert len(signed_stores) == 1
    assert signed_stores[0]._closed
