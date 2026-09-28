import asyncio

import pytest

from app.oob.listener import OOBListener, extract_correlation_id, parse_http_request
from app.storage.db import get_engine, init_db, make_session_factory, session_scope
from app.storage.repository import OOBRepository


def test_extract_correlation_id_from_standard_path():
    assert extract_correlation_id("/oob/sentinelabc123") == "sentinelabc123"


def test_extract_correlation_id_with_trailing_segments():
    assert extract_correlation_id("/oob/sentinelabc123/extra/stuff") == "sentinelabc123"


def test_extract_correlation_id_returns_none_for_unrelated_path():
    assert extract_correlation_id("/favicon.ico") is None
    assert extract_correlation_id("/") is None
    assert extract_correlation_id("/oob") is None  # no ID segment


class _FakeStreamReader:
    """Minimal fake satisfying the subset of asyncio.StreamReader's interface
    parse_http_request() actually uses, so the parser can be unit tested without
    real sockets."""

    def __init__(self, raw: bytes):
        self._lines = raw.split(b"\n")
        self._lines = [line + b"\n" if not line.endswith(b"\n") else line for line in self._lines]
        self._index = 0

    async def readline(self) -> bytes:
        if self._index >= len(self._lines):
            return b""
        line = self._lines[self._index]
        self._index += 1
        return line

    async def readexactly(self, n: int) -> bytes:
        remaining = b"".join(self._lines[self._index :])
        return remaining[:n]


@pytest.mark.asyncio
async def test_parse_http_request_basic_get():
    raw = b"GET /oob/abc123 HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n"
    reader = _FakeStreamReader(raw)
    result = await parse_http_request(reader)
    assert result is not None
    method, path, headers, body = result
    assert method == "GET"
    assert path == "/oob/abc123"
    assert headers["host"] == "example.com"
    assert body == b""


@pytest.mark.asyncio
async def test_parse_http_request_with_body():
    raw = (
        b"POST /oob/xyz789 HTTP/1.1\r\n"
        b"Content-Length: 11\r\n"
        b"\r\n"
        b"hello world"
    )
    reader = _FakeStreamReader(raw)
    result = await parse_http_request(reader)
    assert result is not None
    method, path, headers, body = result
    assert method == "POST"
    assert body == b"hello world"


@pytest.mark.asyncio
async def test_parse_http_request_empty_connection_returns_none():
    reader = _FakeStreamReader(b"")
    result = await parse_http_request(reader)
    assert result is None


@pytest.mark.asyncio
async def test_parse_http_request_permissively_accepts_nonstandard_but_three_token_line():
    """The parser is deliberately lenient (see its docstring: "log anything, don't
    crash") — a request line with 3 space-separated tokens is accepted even if
    those tokens aren't a real method/path/version, since a probing or malformed
    client should still show up as *something* logged, not be silently dropped."""
    reader = _FakeStreamReader(b"NOT A VALID REQUEST LINE AT ALL\r\n\r\n")
    result = await parse_http_request(reader)
    assert result is not None
    method, path, headers, body = result
    assert method == "NOT"
    assert path == "A"


@pytest.mark.asyncio
async def test_parse_http_request_returns_none_for_genuinely_unparseable_line():
    """Fewer than 3 space-separated tokens can't even be split into
    method/path/version — this is the actual malformed case that returns None."""
    reader = _FakeStreamReader(b"nonsense\r\n\r\n")
    result = await parse_http_request(reader)
    assert result is None


# --- real-socket integration tests -------------------------------------------


async def _find_free_port() -> int:
    server = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    server.close()
    await server.wait_closed()
    return port


@pytest.mark.asyncio
async def test_listener_records_real_incoming_request(tmp_path):
    db_path = str(tmp_path / "oob_test.db")
    port = await _find_free_port()
    listener = OOBListener("127.0.0.1", port, db_path)
    await listener.start()

    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"GET /oob/sentinel-test-correlation HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
        await writer.drain()

        response = await asyncio.wait_for(reader.read(1024), timeout=5.0)
        assert b"200 OK" in response

        writer.close()
        await writer.wait_closed()

        # give the server's background handler a moment to finish the DB write
        await asyncio.sleep(0.2)
    finally:
        await listener.stop()

    engine = get_engine(db_path)
    await init_db(engine)
    session_factory = make_session_factory(engine)
    async with session_scope(session_factory) as session:
        repo = OOBRepository(session)
        interactions = await repo.list_interactions_for_correlation("sentinel-test-correlation")

    assert len(interactions) == 1
    assert interactions[0].method == "GET"
    assert interactions[0].protocol == "http"
    assert interactions[0].source_ip == "127.0.0.1"

    await engine.dispose()


@pytest.mark.asyncio
async def test_listener_does_not_record_unrecognized_path(tmp_path):
    db_path = str(tmp_path / "oob_test.db")
    port = await _find_free_port()
    listener = OOBListener("127.0.0.1", port, db_path)
    await listener.start()

    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"GET /favicon.ico HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
        await writer.drain()
        await asyncio.wait_for(reader.read(1024), timeout=5.0)
        writer.close()
        await writer.wait_closed()
        await asyncio.sleep(0.2)
    finally:
        await listener.stop()

    engine = get_engine(db_path)
    await init_db(engine)
    session_factory = make_session_factory(engine)
    async with session_scope(session_factory) as session:
        repo = OOBRepository(session)
        interactions = await repo.list_interactions_for_correlation("favicon.ico")
    assert interactions == []
    await engine.dispose()


@pytest.mark.asyncio
async def test_listener_handles_malformed_request_without_crashing(tmp_path):
    db_path = str(tmp_path / "oob_test.db")
    port = await _find_free_port()
    listener = OOBListener("127.0.0.1", port, db_path)
    await listener.start()

    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"not even close to a valid http request\r\n\r\n")
        await writer.drain()
        writer.close()
        await writer.wait_closed()
        await asyncio.sleep(0.2)

        # listener should still be alive and accept a second, valid connection
        reader2, writer2 = await asyncio.open_connection("127.0.0.1", port)
        writer2.write(b"GET /oob/still-alive HTTP/1.1\r\nHost: x\r\n\r\n")
        await writer2.drain()
        response = await asyncio.wait_for(reader2.read(1024), timeout=5.0)
        assert b"200 OK" in response
        writer2.close()
        await writer2.wait_closed()
    finally:
        await listener.stop()
