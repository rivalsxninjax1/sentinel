"""JSON renderer — the machine-readable format. Every field in ReportData is
included verbatim; this is the format other tools/scripts should consume, not the
Markdown/HTML ones (which are for humans and may summarize).
"""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime
from typing import Any

from app.reporting.models import ReportData


def _json_default(value: Any) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


def render(report: ReportData) -> str:
    return json.dumps(asdict(report), default=_json_default, indent=2)
