from __future__ import annotations

import threading
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from ix_blackfox.live_gateway.service import LiveAuthorityGateway

from .conftest import authorized


def test_mesh_does_not_follow_redirects_with_service_credentials(
    gateway: LiveAuthorityGateway,
) -> None:
    seen: list[tuple[str, str]] = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            self.rfile.read(int(self.headers["Content-Length"]))
            seen.append((self.path, self.headers.get("Authorization", "")))
            self.send_response(302)
            self.send_header(
                "Location",
                f"http://127.0.0.1:{self.server.server_port}/credential-trap",
            )
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, format: str, *args: Any) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        mesh = gateway.config.mesh
        assert mesh is not None
        connectors = tuple(
            replace(c, base_url=f"http://127.0.0.1:{server.server_port}")
            if c.connector_id == "service"
            else c
            for c in mesh.connectors
        )
        gateway.config = replace(
            gateway.config, mesh=replace(mesh, connectors=connectors)
        )
        payload, headers = authorized(gateway)
        assert gateway.handle_api(payload=payload, headers=headers).status == 302
        assert seen == [("/submit", "Bearer " + "s" * 64)]
    finally:
        server.shutdown()
        server.server_close()
        worker.join(5)
