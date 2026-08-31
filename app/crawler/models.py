"""Plain dataclasses describing what the crawler extracts from one page, before
anything gets written to the database. Keeps the crawler's HTML-parsing concerns
separate from storage concerns.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class DiscoveredParameter:
    name: str
    location: str  # "query" | "form"
    observed_value: str = ""


@dataclass
class DiscoveredForm:
    method: str
    action: str  # absolute URL the form submits to
    parameters: list[DiscoveredParameter] = field(default_factory=list)


@dataclass
class PageExtraction:
    url: str
    status_code: int
    links: list[str] = field(default_factory=list)
    forms: list[DiscoveredForm] = field(default_factory=list)
    query_parameters: list[DiscoveredParameter] = field(default_factory=list)
    script_urls: list[str] = field(default_factory=list)
    inline_scripts: list[str] = field(default_factory=list)
