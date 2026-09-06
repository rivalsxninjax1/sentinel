import pytest

import app.scanners.websocket_auth as websocket_auth_module
from app.scanners.base import ScanTarget
from app.scanners.websocket_auth import WebSocketAuthScanner


@pytest.mark.asyncio
async def test_skips_non_websocket_urls():
    scanner = WebSocketAuthScanner()
    target = ScanTarget(url="https://app.example.com/api/data")
    findings = await scanner.scan(target, http_client=None)
    assert findings == []


@pytest.mark.asyncio
async def test_degrades_gracefully_when_websockets_unavailable(monkeypatch):
    monkeypatch.setattr(websocket_auth_module, "websockets", None)
    scanner = WebSocketAuthScanner()
    target = ScanTarget(url="wss://app.example.com/socket")
    findings = await scanner.scan(target, http_client=None)
    assert findings == []


@pytest.mark.asyncio
async def test_flags_successful_unauthenticated_handshake(monkeypatch):
    class _FakeConnection:
        async def close(self):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

    class _FakeWebsocketsModule:
        @staticmethod
        def connect(url, open_timeout=10.0):
            return _FakeConnection()

    monkeypatch.setattr(websocket_auth_module, "websockets", _FakeWebsocketsModule())

    scanner = WebSocketAuthScanner()
    target = ScanTarget(url="wss://app.example.com/socket")
    findings = await scanner.scan(target, http_client=None)

    assert len(findings) == 1
    assert findings[0].severity == "info"


@pytest.mark.asyncio
async def test_no_finding_when_handshake_rejected(monkeypatch):
    class _FakeWebsocketsModule:
        @staticmethod
        def connect(url, open_timeout=10.0):
            raise ConnectionRefusedError("handshake rejected")

    monkeypatch.setattr(websocket_auth_module, "websockets", _FakeWebsocketsModule())

    scanner = WebSocketAuthScanner()
    target = ScanTarget(url="wss://app.example.com/socket")
    findings = await scanner.scan(target, http_client=None)

    assert findings == []
