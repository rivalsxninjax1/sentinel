"""Quick-scan: lets the dashboard start a scan directly from a URL/IP typed into
the home page, instead of requiring the operator to hand-write a YAML config and
run six CLI commands manually.

This does NOT bypass any of SENTINEL's existing safety machinery — it automates
writing the same YAML config file structure `scan create`/`scan crawl`/etc.
already require, then invokes those exact same CLI commands as subprocesses in
sequence. Scope enforcement, mode gating, and lifecycle transitions all still
happen exactly as they do when run by hand; nothing here talks to the database or
the scope engine directly.

The dashboard's authorization checkbox (required client-side AND validated
server-side — see app/dashboard/app.py's quick_start route) does not replace the
operator's actual legal authorization to test a target; it exists so starting a
scan is never a single accidental click with no acknowledgment step at all.
"""

from __future__ import annotations

import re
import sys
import tempfile
import uuid
from pathlib import Path
from urllib.parse import urlparse

import yaml

from app.core.logging import get_logger
from app.tools.process import ProcessRunner, default_process_runner

logger = get_logger(__name__)

_SCAN_ID_PATTERN = re.compile(r"Created scan ([0-9a-f-]{36})")

# Matches the CLI's actual subcommand names under `scan` — see app/cli/main.py.
_PIPELINE_STAGES = ["crawl", "discover-js", "classify", "test", "verify", "report"]


class QuickScanError(Exception):
    pass


def parse_target_input(raw: str) -> tuple[str, str, str]:
    """Returns (target_name, hostname_scope_entry, seed_url) from operator input
    like "example.com", "10.0.0.5", or "https://app.example.com/login". Raises
    QuickScanError for empty/unparseable input."""
    raw = raw.strip()
    if not raw:
        raise QuickScanError("Target URL/IP is required.")

    if not raw.startswith(("http://", "https://")):
        raw = f"https://{raw}"

    parsed = urlparse(raw)
    if not parsed.hostname:
        raise QuickScanError(f"Could not parse a hostname from {raw!r}.")

    hostname = parsed.hostname
    target_name = f"quick-scan-{hostname}"
    seed_url = raw if parsed.path else raw.rstrip("/") + "/"
    return target_name, hostname, seed_url


def build_temp_config(
    target_name: str, hostname: str, seed_url: str, mode: str, storage_path: str
) -> Path:
    if mode not in ("passive", "safe", "active"):
        raise QuickScanError(f"Invalid mode: {mode!r}")

    config = {
        "target": {
            "name": target_name,
            "scope": {"allow": [hostname], "deny": []},
            "seed_urls": [seed_url],
        },
        "scan": {"mode": mode},
        "storage_path": storage_path,
        "log_level": "WARNING",
    }

    tmp_dir = Path(tempfile.gettempdir()) / "sentinel-quickscan"
    tmp_dir.mkdir(parents=True, exist_ok=True)
    config_path = tmp_dir / f"{uuid.uuid4()}.yaml"
    config_path.write_text(yaml.safe_dump(config))
    return config_path


async def run_scan_create(config_path: Path, runner: ProcessRunner | None = None) -> str:
    """Runs `sentinel scan create` and returns the new scan ID. Raises
    QuickScanError if creation failed or the scan ID couldn't be parsed from
    output."""
    runner = runner or default_process_runner
    args = [sys.executable, "-m", "app.cli.main", "scan", "create", "--config", str(config_path)]
    returncode, stdout, stderr = await runner(args, 30.0)
    if returncode != 0:
        raise QuickScanError(f"scan create failed: {(stderr or stdout).strip()}")

    match = _SCAN_ID_PATTERN.search(stdout)
    if not match:
        raise QuickScanError(f"Could not parse scan ID from output: {stdout!r}")
    return match.group(1)


async def run_remaining_pipeline(
    config_path: Path, scan_id: str, runner: ProcessRunner | None = None
) -> None:
    """Runs crawl -> discover-js -> classify -> test -> verify -> report in
    sequence, stopping early (and logging, not raising) if any stage fails.
    Intended to be scheduled as a FastAPI BackgroundTask so the initial HTTP
    request returns immediately after `scan create` completes.

    Cleans up the temp config file when the pipeline ends (success, early stop,
    or exception) — it's no longer needed once the last subprocess that reads it
    has finished."""
    runner = runner or default_process_runner
    try:
        for stage in _PIPELINE_STAGES:
            args = [
                sys.executable, "-m", "app.cli.main", "scan", stage, scan_id,
                "--config", str(config_path),
            ]
            try:
                returncode, stdout, stderr = await runner(args, 300.0)
            except Exception as exc:
                logger.warning(
                    "quickscan_stage_failed", stage=stage, scan_id=scan_id, error=str(exc)
                )
                return
            if returncode != 0:
                logger.warning(
                    "quickscan_stage_nonzero_exit",
                    stage=stage,
                    scan_id=scan_id,
                    returncode=returncode,
                    stderr=stderr[:500],
                )
                return
            logger.info("quickscan_stage_complete", stage=stage, scan_id=scan_id)
    finally:
        config_path.unlink(missing_ok=True)
