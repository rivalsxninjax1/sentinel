"""Crawler — traditional (non-headless) BFS crawl within scope.

Deliberately does not execute JavaScript (that's Phase 3's browser-based discovery).
Every request goes through SentinelHTTPClient, which itself enforces scope and rate
limits — the crawler additionally enforces `max_crawl_depth` and `max_pages` so a
single crawl can't silently consume the whole scan's request budget.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

import httpx

from app.core.http_client import SentinelHTTPClient
from app.core.logging import get_logger
from app.crawler.html_parser import extract
from app.crawler.models import PageExtraction
from app.discovery.url_normalizer import normalize
from app.intelligence.technology import TechnologyDetection, TechnologyFingerprinter
from app.scope.engine import ScopeViolation

logger = get_logger(__name__)


@dataclass
class CrawlSummary:
    pages: list[PageExtraction] = field(default_factory=list)
    visited_count: int = 0
    skipped_out_of_scope: int = 0
    errors: list[str] = field(default_factory=list)
    # hostname -> detections observed on any page for that host
    technologies_by_host: dict[str, list[TechnologyDetection]] = field(default_factory=dict)


class Crawler:
    def __init__(
        self,
        http_client: SentinelHTTPClient,
        max_depth: int = 5,
        max_pages: int = 500,
        fingerprinter: TechnologyFingerprinter | None = None,
    ) -> None:
        self._http = http_client
        self._max_depth = max_depth
        self._max_pages = max_pages
        self._fingerprinter = fingerprinter or TechnologyFingerprinter()

    async def crawl(self, seed_urls: list[str]) -> CrawlSummary:
        summary = CrawlSummary()
        visited: set[str] = set()
        queue: deque[tuple[str, int]] = deque((url, 0) for url in seed_urls)

        while queue and summary.visited_count < self._max_pages:
            url, depth = queue.popleft()
            normalized = normalize(url)
            if normalized in visited:
                continue
            visited.add(normalized)

            if depth > self._max_depth:
                continue

            try:
                response = await self._http.get(url)
            except ScopeViolation:
                summary.skipped_out_of_scope += 1
                continue
            except httpx.HTTPError as exc:
                summary.errors.append(f"{url}: {exc}")
                continue

            summary.visited_count += 1

            hostname = httpx.URL(url).host
            detections = self._fingerprinter.detect(response)
            if detections:
                existing = summary.technologies_by_host.setdefault(hostname, [])
                known_names = {d.name for d in existing}
                existing.extend(d for d in detections if d.name not in known_names)

            content_type = response.headers.get("content-type", "")
            if "html" not in content_type:
                page = PageExtraction(url=url, status_code=response.status_code)
            else:
                page = extract(url, response.status_code, response.text)

            summary.pages.append(page)

            if depth < self._max_depth:
                for link in page.links:
                    link_normalized = normalize(link)
                    if link_normalized not in visited:
                        queue.append((link, depth + 1))

        return summary
