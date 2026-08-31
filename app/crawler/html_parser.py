"""Extracts links, forms, and query parameters from an HTML page.

Deliberately simple and dependency-light (BeautifulSoup only) — this is traditional
HTML crawling per docs/architecture.md §10. JavaScript-rendered content (SPA routes,
client-side-only forms, fetch() calls) is explicitly out of scope here and is handled
by JS intelligence (Phase 3) and browser-based crawling (Phase 3/28), not this module.
"""

from __future__ import annotations

from urllib.parse import parse_qsl, urljoin, urlparse

from bs4 import BeautifulSoup

from app.crawler.models import DiscoveredForm, DiscoveredParameter, PageExtraction


def extract(base_url: str, status_code: int, html: str) -> PageExtraction:
    soup = BeautifulSoup(html, "html.parser")

    links = _extract_links(base_url, soup)
    forms = _extract_forms(base_url, soup)
    query_parameters = _extract_query_parameters(base_url)
    script_urls, inline_scripts = _extract_scripts(base_url, soup)

    return PageExtraction(
        url=base_url,
        status_code=status_code,
        links=links,
        forms=forms,
        query_parameters=query_parameters,
        script_urls=script_urls,
        inline_scripts=inline_scripts,
    )


def _extract_links(base_url: str, soup: BeautifulSoup) -> list[str]:
    links: list[str] = []
    for tag in soup.find_all("a", href=True):
        href = tag["href"].strip()
        if not href or href.startswith(("javascript:", "mailto:", "tel:", "#")):
            continue
        links.append(urljoin(base_url, href))
    return links


def _extract_forms(base_url: str, soup: BeautifulSoup) -> list[DiscoveredForm]:
    forms: list[DiscoveredForm] = []
    for form_tag in soup.find_all("form"):
        method = (form_tag.get("method") or "GET").strip().upper()
        action = urljoin(base_url, (form_tag.get("action") or "").strip() or base_url)

        parameters: list[DiscoveredParameter] = []
        for field_tag in form_tag.find_all(["input", "textarea", "select"]):
            name = field_tag.get("name")
            if not name:
                continue
            value = field_tag.get("value", "") or ""
            parameters.append(
                DiscoveredParameter(name=name, location="form", observed_value=value)
            )

        forms.append(DiscoveredForm(method=method, action=action, parameters=parameters))
    return forms


def _extract_query_parameters(url: str) -> list[DiscoveredParameter]:
    query = urlparse(url).query
    return [
        DiscoveredParameter(name=name, location="query", observed_value=value)
        for name, value in parse_qsl(query, keep_blank_values=True)
    ]


def _extract_scripts(base_url: str, soup: BeautifulSoup) -> tuple[list[str], list[str]]:
    script_urls: list[str] = []
    inline_scripts: list[str] = []
    for tag in soup.find_all("script"):
        src = tag.get("src")
        if src:
            script_urls.append(urljoin(base_url, src.strip()))
            continue
        text = tag.string
        if text and text.strip():
            inline_scripts.append(text)
    return script_urls, inline_scripts
