from app.scanners.util import inject_query_param


def test_adds_parameter_when_absent():
    result = inject_query_param("https://app.example.com/search", "q", "test")
    assert result == "https://app.example.com/search?q=test"


def test_overwrites_existing_parameter():
    result = inject_query_param("https://app.example.com/search?q=old&page=2", "q", "new")
    assert "q=new" in result
    assert "page=2" in result
    assert "q=old" not in result


def test_preserves_other_parameters_and_path():
    result = inject_query_param("https://app.example.com/x/y?a=1&b=2", "c", "3")
    assert "/x/y" in result
    assert "a=1" in result
    assert "b=2" in result
    assert "c=3" in result


def test_url_encodes_special_characters_in_value():
    result = inject_query_param("https://app.example.com/x", "redirect", "https://evil.com/")
    assert "redirect=https%3A%2F%2Fevil.com%2F" in result
