import glob
import re

from app.reporting.knowledge_base import get_knowledge, known_vulnerability_classes


def test_get_knowledge_returns_entry_for_known_class():
    entry = get_knowledge("xss")
    assert entry is not None
    assert entry.cwe_id == "CWE-79"
    assert "encoding" in entry.remediation.lower()


def test_get_knowledge_returns_none_for_unknown_class():
    assert get_knowledge("not_a_real_vulnerability_class") is None


def test_every_scanner_vulnerability_class_has_a_knowledge_base_entry():
    """Guards against a new scanner being added with a vulnerability_class that
    nobody remembered to add reporting knowledge for."""
    scanner_files = glob.glob("app/scanners/*.py")
    found_classes: set[str] = set()
    pattern = re.compile(r'vulnerability_class\s*=\s*"([^"]+)"')
    for path in scanner_files:
        with open(path) as f:
            content = f.read()
        found_classes.update(pattern.findall(content))

    known = known_vulnerability_classes()
    missing = found_classes - known
    assert not missing, f"vulnerability classes with no knowledge base entry: {missing}"


def test_all_entries_have_non_empty_fields():
    for vuln_class in known_vulnerability_classes():
        entry = get_knowledge(vuln_class)
        assert entry.cwe_id.startswith("CWE-")
        assert entry.cwe_name
        assert entry.impact
        assert entry.remediation
