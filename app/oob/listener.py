"""OOBListener — standalone, dependency-free HTTP listener for the OOB callback
system.

Started via `sentinel oob listen` (app/cli/main.py) — a long-running process the
operator keeps running alongside any scan that has OOB enabled, pointed at the
SAME storage_path the scan itself uses. Deliberately built on raw `asyncio`
sockets rather than FastAPI/another framework: it needs to accept literally any
method/path/headers a target's HTTP client sends (which may not even be a real
browser — could be a minimal XML parser's entity-resolution HTTP client), and
logging "something hit this path" is the entire job — no routing, no templating,
no response content requirements beyond "respond 200 so the target's request
doesn't hang or retry."

SECURITY NOTE: this listener must be reachable from the TARGET application, not
from SENTINEL. For a local lab that's usually the same machine/network. For a
real remote target, the operator needs a real publicly-reachable IP/hostname
pointed at wherever this listener runs — SENTINEL does not provision that for
you. Binding this to 0.0.0.0 means it accepts connections from anywhere that can
reach that port; only run it somewhere you're comfortable exposing a bare HTTP
listener with no authentication (by design — the "auth" here is the
unguessability of the correlation ID in the path, not a login).
"""

from __future__ import annotations

import asyncio

from app.core.logging import get_logger
from app.storage.db import get_engine, init_db, make_session_factory, session_scope
from app.storage.repository import OOBRepository

logger = get_logger(__name__)

_HEADER_READ_TIMEOUT = 5.0
_MAX_HEADER_BYTES = 8192
_MAX_BODY_BYTES = 65536


def extract_correlation_id(path: str) -> str | None:
    """Expects paths shaped like /oob/<correlation_id>[/...] — anything else
    returns None (still logged by the caller for visibility, just not matched to
    a scan)."""
    parts = [p for p in path.split("/") if p]
    if len(parts) >= 2 and parts[0] == "oob":
        return parts[1]
    return None


async def parse_http_request(
    reader: asyncio.StreamReader,
) -> tuple[str, str, dict[str, str], bytes] | None:
    """Reads a minimal HTTP/1.x request (request line + headers + optional
    Content-Length body) directly off the stream. Returns (method, path, headers,
    body), or None if the connection sent nothing parseable / timed out. This is
    intentionally lenient — malformed requests (which a probing XML parser or a
    misconfigured client might send) should be logged as "something hit us," not
    crash the listener."""
    try:
        request_line = await asyncio.wait_for(reader.readline(), timeout=_HEADER_READ_TIMEOUT)
    except asyncio.TimeoutError:
        return None
    if not request_line:
        return None

    try:
        line = request_line.decode("latin-1").strip()
        method, path, _version = line.split(" ", 2)
    except ValueError:
        return None

    headers: dict[str, str] = {}
    total_header_bytes = 0
    while True:
        try:
            header_line = await asyncio.wait_for(reader.readline(), timeout=_HEADER_READ_TIMEOUT)
        except asyncio.TimeoutError:
            break
        if not header_line:
            break
        total_header_bytes += len(header_line)
        if total_header_bytes > _MAX_HEADER_BYTES:
            break
        decoded = header_line.decode("latin-1").strip()
        if not decoded:
            break  # blank line = end of headers
        if ":" in decoded:
            key, _, value = decoded.partition(":")
            headers[key.strip().lower()] = value.strip()

    body = b""
    content_length = headers.get("content-length")
    if content_length:
        try:
            length = min(int(content_length), _MAX_BODY_BYTES)
            body = await asyncio.wait_for(reader.readexactly(length), timeout=_HEADER_READ_TIMEOUT)
        except (ValueError, asyncio.TimeoutError, asyncio.IncompleteReadError):
            pass

    return method, path, headers, body


class OOBListener:
    def __init__(self, host: str, port: int, storage_path: str) -> None:
        self._host = host
        self._port = port
        self._storage_path = storage_path
        self._server: asyncio.Server | None = None

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        peer = writer.get_extra_info("peername")
        source_ip = peer[0] if peer else "unknown"

        try:
            parsed = await parse_http_request(reader)
            if parsed is None:
                return
            method, path, headers, _body = parsed

            correlation_id = extract_correlation_id(path)
            if correlation_id:
                await self._record(correlation_id, source_ip, method, path, headers)
                logger.info("oob_hit", correlation_id=correlation_id, source_ip=source_ip, path=path)
            else:
                logger.info(
                    "oob_unrecognized_request", source_ip=source_ip, path=path, method=method
                )

            response_body = b"ok"
            response = (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: text/plain\r\n"
                b"Content-Length: " + str(len(response_body)).encode() + b"\r\n"
                b"Connection: close\r\n\r\n" + response_body
            )
            writer.write(response)
            await writer.drain()
        except Exception as exc:
            logger.warning("oob_listener_client_error", error=str(exc))
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def _record(
        self, correlation_id: str, source_ip: str, method: str, path: str, headers: dict
    ) -> None:
        engine = get_engine(self._storage_path)
        await init_db(engine)
        session_factory = make_session_factory(engine)
        try:
            async with session_scope(session_factory) as session:
                repo = OOBRepository(session)
                await repo.record_interaction(
                    correlation_id=correlation_id,
                    protocol="http",
                    source_ip=source_ip,
                    method=method,
                    path=path,
                    headers=headers,
                )
        finally:
            await engine.dispose()

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle_client, self._host, self._port)
        logger.info(
            "oob_listener_started", host=self._host, port=self._port, storage_path=self._storage_path
        )

    async def serve_forever(self) -> None:
        if self._server is None:
            await self.start()
        assert self._server is not None
        async with self._server:
            await self._server.serve_forever()

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
