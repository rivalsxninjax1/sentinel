"""Structured logging with secret redaction.

Every log call goes through a processor that redacts values for keys that look like
credentials, per the non-negotiable "never log secrets" rule. This is a best-effort
denylist, not a substitute for simply not passing secrets into log calls.
"""

from __future__ import annotations

import logging
import re
from typing import Any

import structlog

_SECRET_KEY_PATTERN = re.compile(
    r"(password|passwd|secret|token|api[_-]?key|authorization|cookie|session[_-]?id)",
    re.IGNORECASE,
)
_REDACTED = "***REDACTED***"


def _redact_secrets(_logger: Any, _method_name: str, event_dict: dict[str, Any]) -> dict[str, Any]:
    for key in list(event_dict.keys()):
        if _SECRET_KEY_PATTERN.search(key):
            event_dict[key] = _REDACTED
    return event_dict


def configure_logging(level: str = "INFO") -> None:
    logging.basicConfig(format="%(message)s", level=getattr(logging, level.upper(), logging.INFO))
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            _redact_secrets,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, level.upper(), logging.INFO)
        ),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str = "sentinel") -> structlog.stdlib.BoundLogger:
    return structlog.get_logger(name)
