from app.intelligence.javascript import extract_from_js


def test_extracts_fetch_call_route():
    js = 'async function load() { const r = await fetch("/api/users/123"); }'
    result = extract_from_js(js)
    assert "/api/users/123" in result.routes


def test_extracts_axios_call_route():
    js = "axios.get('/api/orders').then(r => r.data);"
    result = extract_from_js(js)
    assert "/api/orders" in result.routes


def test_extracts_xhr_open_route():
    js = "xhr.open('POST', '/api/login');"
    result = extract_from_js(js)
    assert "/api/login" in result.routes


def test_extracts_generic_api_literal():
    js = 'const endpoint = "/v2/products";'
    result = extract_from_js(js)
    assert "/v2/products" in result.routes


def test_classifies_graphql_endpoint_separately():
    js = 'fetch("/graphql", { method: "POST" });'
    result = extract_from_js(js)
    assert result.graphql_endpoints == ["/graphql"]
    assert result.routes == []


def test_extracts_websocket_literal():
    js = 'const ws = new WebSocket("wss://app.example.com/socket");'
    result = extract_from_js(js)
    assert "wss://app.example.com/socket" in result.websocket_endpoints


def test_extracts_source_map_comment():
    js = "console.log('hi');\n//# sourceMappingURL=app.js.map"
    result = extract_from_js(js)
    assert result.source_map_url == "app.js.map"


def test_ignores_cross_origin_absolute_urls():
    js = 'fetch("https://other-service.example.com/api/data");'
    result = extract_from_js(js)
    assert result.routes == []


def test_no_false_positives_on_plain_js():
    js = "function add(a, b) { return a + b; }"
    result = extract_from_js(js)
    assert result.routes == []
    assert result.graphql_endpoints == []
    assert result.websocket_endpoints == []
    assert result.source_map_url is None


def test_dedupes_repeated_routes():
    js = 'fetch("/api/a"); fetch("/api/a"); fetch("/api/b");'
    result = extract_from_js(js)
    assert result.routes == ["/api/a", "/api/b"]
