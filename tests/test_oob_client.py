import asyncio

import pytest

from app.oob.client import OOBClient
from app.oob.listener import OOBListener
from app.storage.db import get_engine, init_db, make_session_factory, session_scope
from app.storage.repository import OOBRepository


def test_generate_correlation_id_is_unique_and_unguessable():
    ids = {OOBClient.generate_correlation_id() for _ in range(100)}
    assert len(ids) == 100  # no collisions
    for cid in ids:
        assert cid.startswith("sentinel")
        assert len(cid) >= 20  # prefix + enough entropy to not be brute-forceable


def test_build_callback_url():
    client = OOBClient("http://oob.example.com:8888", "test.db")
    url = client.build_callback_url("sentinelabc123")
    assert url == "http://oob.example.com:8888/oob/sentinelabc123"


def test_build_callback_url_strips_trailing_slash():
    client = OOBClient("http://oob.example.com:8888/", "test.db")
    url = client.build_callback_url("sentinelabc123")
    assert url == "http://oob.example.com:8888/oob/sentinelabc123"


@pytest.mark.asyncio
async def test_register_and_wait_returns_false_when_no_interaction(tmp_path):
    db_path = str(tmp_path / "test.db")
    client = OOBClient("http://127.0.0.1:1", db_path, wait_seconds=0.2)

    result = await client.register_and_wait(
        correlation_id="sentinel-no-hit",
        scan_id="scan-1",
        vulnerability_class="ssrf",
        matched_endpoint="https://app.example.com/fetch?url=x",
    )

    assert result is False

    engine = get_engine(db_path)
    await init_db(engine)
    session_factory = make_session_factory(engine)
    async with session_scope(session_factory) as session:
        repo = OOBRepository(session)
        corr = await repo.get_correlation("sentinel-no-hit")
    assert corr is not None
    assert corr.vulnerability_class == "ssrf"
    await engine.dispose()


@pytest.mark.asyncio
async def test_register_and_wait_returns_true_when_interaction_arrives_during_wait(tmp_path):
    """Full realistic sequence: client registers a correlation, then (simulating
    the target actually making the outbound request mid-wait) a real interaction
    is recorded via a real running OOBListener before the wait completes."""
    db_path = str(tmp_path / "test.db")

    server = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    server.close()
    await server.wait_closed()

    listener = OOBListener("127.0.0.1", port, db_path)
    await listener.start()

    client = OOBClient(f"http://127.0.0.1:{port}", db_path, wait_seconds=1.5)
    correlation_id = "sentinel-hit-test"

    async def _fire_callback_after_delay():
        await asyncio.sleep(0.3)
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(f"GET /oob/{correlation_id} HTTP/1.1\r\nHost: x\r\n\r\n".encode())
        await writer.drain()
        await reader.read(1024)
        writer.close()
        await writer.wait_closed()

    try:
        result, _ = await asyncio.gather(
            client.register_and_wait(
                correlation_id=correlation_id,
                scan_id="scan-1",
                vulnerability_class="ssrf",
                matched_endpoint="https://app.example.com/fetch?url=x",
            ),
            _fire_callback_after_delay(),
        )
    finally:
        await listener.stop()

    assert result is True
