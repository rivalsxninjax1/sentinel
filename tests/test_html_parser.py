from app.crawler.html_parser import extract


def test_extracts_links_and_resolves_relative_urls():
    html = """
    <html><body>
        <a href="/about">About</a>
        <a href="https://other.example.com/x">External</a>
        <a href="javascript:void(0)">Ignored</a>
        <a href="#section">Ignored anchor</a>
        <a href="mailto:test@example.com">Ignored mail</a>
    </body></html>
    """
    page = extract("https://app.example.com/", 200, html)
    assert "https://app.example.com/about" in page.links
    assert "https://other.example.com/x" in page.links
    assert not any("javascript:" in link for link in page.links)
    assert len(page.links) == 2


def test_extracts_form_fields_and_resolves_action():
    html = """
    <form method="post" action="/login">
        <input type="text" name="username" value="">
        <input type="password" name="password">
        <input type="hidden" name="csrf_token" value="abc123">
        <input type="submit" value="Login">
    </form>
    """
    page = extract("https://app.example.com/signin", 200, html)
    assert len(page.forms) == 1
    form = page.forms[0]
    assert form.method == "POST"
    assert form.action == "https://app.example.com/login"
    field_names = {p.name for p in form.parameters}
    assert field_names == {"username", "password", "csrf_token"}


def test_form_without_method_defaults_to_get():
    html = '<form action="/search"><input name="q"></form>'
    page = extract("https://app.example.com/", 200, html)
    assert page.forms[0].method == "GET"


def test_form_without_action_submits_to_current_page():
    html = '<form method="post"><input name="q"></form>'
    page = extract("https://app.example.com/page", 200, html)
    assert page.forms[0].action == "https://app.example.com/page"


def test_extracts_query_parameters_from_url():
    page = extract("https://app.example.com/search?q=test&page=2", 200, "<html></html>")
    names = {p.name: p.observed_value for p in page.query_parameters}
    assert names == {"q": "test", "page": "2"}


def test_extracts_external_script_urls():
    html = """
    <html><head>
        <script src="/static/app.js"></script>
        <script src="https://cdn.example.com/lib.js"></script>
    </head></html>
    """
    page = extract("https://app.example.com/", 200, html)
    assert "https://app.example.com/static/app.js" in page.script_urls
    assert "https://cdn.example.com/lib.js" in page.script_urls


def test_extracts_inline_script_content():
    html = """
    <html><body>
        <script>console.log("inline one");</script>
        <script src="/app.js"></script>
        <script>console.log("inline two");</script>
    </body></html>
    """
    page = extract("https://app.example.com/", 200, html)
    assert len(page.inline_scripts) == 2
    assert any("inline one" in s for s in page.inline_scripts)
    assert len(page.script_urls) == 1


def test_ignores_empty_inline_scripts():
    html = '<html><body><script src="/app.js"></script><script></script></body></html>'
    page = extract("https://app.example.com/", 200, html)
    assert page.inline_scripts == []
