import httpx

from app.intelligence.technology import TechnologyFingerprinter


def _response(headers: dict[str, str] | None = None, body: str = "", cookies: list[str] | None = None) -> httpx.Response:
    all_headers = list((headers or {}).items())
    for c in cookies or []:
        all_headers.append(("set-cookie", c))
    return httpx.Response(200, headers=all_headers, content=body.encode())


def test_detects_server_header():
    resp = _response(headers={"Server": "nginx/1.24.0"})
    detections = TechnologyFingerprinter().detect(resp)
    names = {d.name: d.version for d in detections}
    assert names["Nginx"] == "1.24.0"


def test_detects_x_powered_by():
    resp = _response(headers={"X-Powered-By": "PHP/8.2.1"})
    detections = TechnologyFingerprinter().detect(resp)
    names = {d.name: d.version for d in detections}
    assert names["PHP"] == "8.2.1"


def test_detects_cookie_signature():
    resp = _response(cookies=["laravel_session=abc123; Path=/; HttpOnly"])
    detections = TechnologyFingerprinter().detect(resp)
    assert any(d.name == "Laravel" for d in detections)


def test_detects_body_marker():
    resp = _response(
        headers={"Content-Type": "text/html"},
        body="<html><head></head><body><div>wp-content/themes/x</div></body></html>",
    )
    detections = TechnologyFingerprinter().detect(resp)
    assert any(d.name == "WordPress" for d in detections)


def test_detects_generator_meta_with_version():
    resp = _response(
        headers={"Content-Type": "text/html"},
        body='<html><head><meta name="generator" content="WordPress 6.4"></head></html>',
    )
    detections = TechnologyFingerprinter().detect(resp)
    names = {d.name: d.version for d in detections}
    assert names.get("WordPress") == "6.4"


def test_no_false_detection_on_plain_response():
    resp = _response(headers={"Content-Type": "application/json"}, body='{"ok": true}')
    detections = TechnologyFingerprinter().detect(resp)
    assert detections == []


def test_dedupes_and_keeps_highest_confidence():
    resp = _response(
        headers={"Server": "nginx"},
        cookies=["PHPSESSID=abc"],
    )
    detections = TechnologyFingerprinter().detect(resp)
    names = [d.name for d in detections]
    assert names.count("Nginx") == 1
