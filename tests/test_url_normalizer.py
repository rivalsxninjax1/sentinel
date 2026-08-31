from app.discovery.url_normalizer import endpoint_key, normalize


def test_lowercases_scheme_and_host():
    assert normalize("HTTPS://App.Example.COM/x") == "https://app.example.com/x"


def test_strips_default_port():
    assert normalize("https://example.com:443/x") == "https://example.com/x"
    assert normalize("http://example.com:80/x") == "http://example.com/x"


def test_keeps_non_default_port():
    assert normalize("https://example.com:8443/x") == "https://example.com:8443/x"


def test_sorts_query_parameters():
    assert normalize("https://example.com/x?b=2&a=1") == normalize("https://example.com/x?a=1&b=2")


def test_drops_fragment():
    assert normalize("https://example.com/x#section") == "https://example.com/x"


def test_normalizes_trailing_slash_except_root():
    assert normalize("https://example.com/x/") == "https://example.com/x"
    assert normalize("https://example.com/") == "https://example.com/"


def test_empty_path_becomes_root():
    assert normalize("https://example.com") == "https://example.com/"


def test_endpoint_key_returns_host_and_path():
    assert endpoint_key("https://App.Example.com/foo/?a=1") == ("app.example.com", "/foo")
