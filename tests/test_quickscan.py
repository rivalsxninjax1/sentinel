from pathlib import Path

import pytest
import yaml

from app.dashboard.quickscan import (
    QuickScanError,
    build_temp_config,
    parse_target_input,
    run_remaining_pipeline,
    run_scan_create,
)


def test_parse_full_url():
    name, hostname, seed_url = parse_target_input("https://app.example.com/login")
    assert hostname == "app.example.com"
    assert seed_url == "https://app.example.com/login"
    assert name == "quick-scan-app.example.com"


def test_parse_bare_domain_defaults_to_https():
    name, hostname, seed_url = parse_target_input("example.com")
    assert hostname == "example.com"
    assert seed_url == "https://example.com/"


def test_parse_bare_ip():
    name, hostname, seed_url = parse_target_input("10.0.0.5")
    assert hostname == "10.0.0.5"
    assert seed_url == "https://10.0.0.5/"


def test_parse_http_scheme_preserved():
    name, hostname, seed_url = parse_target_input("http://10.0.0.5:8080/app")
    assert seed_url == "http://10.0.0.5:8080/app"


def test_parse_strips_whitespace():
    name, hostname, seed_url = parse_target_input("  example.com  ")
    assert hostname == "example.com"


def test_parse_empty_input_raises():
    with pytest.raises(QuickScanError):
        parse_target_input("")


def test_parse_whitespace_only_raises():
    with pytest.raises(QuickScanError):
        parse_target_input("   ")


def test_parse_unparseable_input_raises():
    with pytest.raises(QuickScanError):
        parse_target_input("https:///no-host")


def test_build_temp_config_writes_valid_yaml(tmp_path):
    config_path = build_temp_config(
        "quick-scan-example.com", "example.com", "https://example.com/", "safe", str(tmp_path / "db.sqlite")
    )
    assert config_path.exists()
    data = yaml.safe_load(config_path.read_text())
    assert data["target"]["name"] == "quick-scan-example.com"
    assert data["target"]["scope"]["allow"] == ["example.com"]
    assert data["target"]["seed_urls"] == ["https://example.com/"]
    assert data["scan"]["mode"] == "safe"
    config_path.unlink()


def test_build_temp_config_rejects_invalid_mode(tmp_path):
    with pytest.raises(QuickScanError):
        build_temp_config("n", "example.com", "https://example.com/", "bogus-mode", str(tmp_path / "db.sqlite"))


@pytest.mark.asyncio
async def test_run_scan_create_parses_scan_id_from_output(tmp_path):
    async def fake_runner(args, timeout):
        return 0, "Created scan 11111111-1111-1111-1111-111111111111\n", ""

    config_path = tmp_path / "cfg.yaml"
    config_path.write_text("placeholder")
    scan_id = await run_scan_create(config_path, runner=fake_runner)
    assert scan_id == "11111111-1111-1111-1111-111111111111"


@pytest.mark.asyncio
async def test_run_scan_create_raises_on_nonzero_exit(tmp_path):
    async def fake_runner(args, timeout):
        return 1, "", "scope validation failed"

    config_path = tmp_path / "cfg.yaml"
    config_path.write_text("placeholder")
    with pytest.raises(QuickScanError):
        await run_scan_create(config_path, runner=fake_runner)


@pytest.mark.asyncio
async def test_run_scan_create_raises_when_scan_id_unparseable(tmp_path):
    async def fake_runner(args, timeout):
        return 0, "something unexpected happened", ""

    config_path = tmp_path / "cfg.yaml"
    config_path.write_text("placeholder")
    with pytest.raises(QuickScanError):
        await run_scan_create(config_path, runner=fake_runner)


@pytest.mark.asyncio
async def test_run_remaining_pipeline_runs_all_stages_in_order(tmp_path):
    calls = []

    async def fake_runner(args, timeout):
        calls.append(args[4])  # "scan", "<stage>", scan_id, "--config" -> args[4] is stage
        return 0, "ok", ""

    config_path = tmp_path / "cfg.yaml"
    config_path.write_text("placeholder")

    await run_remaining_pipeline(config_path, "scan-123", runner=fake_runner)

    assert calls == ["crawl", "discover-js", "classify", "test", "verify", "report"]
    assert not config_path.exists()  # cleaned up


@pytest.mark.asyncio
async def test_run_remaining_pipeline_stops_early_on_failure(tmp_path):
    calls = []

    async def fake_runner(args, timeout):
        stage = args[4]
        calls.append(stage)
        if stage == "classify":
            return 1, "", "boom"
        return 0, "ok", ""

    config_path = tmp_path / "cfg.yaml"
    config_path.write_text("placeholder")

    await run_remaining_pipeline(config_path, "scan-123", runner=fake_runner)

    assert calls == ["crawl", "discover-js", "classify"]  # stopped after classify failed
    assert not config_path.exists()


@pytest.mark.asyncio
async def test_run_remaining_pipeline_cleans_up_config_on_exception(tmp_path):
    async def fake_runner(args, timeout):
        raise RuntimeError("subprocess launch failed")

    config_path = tmp_path / "cfg.yaml"
    config_path.write_text("placeholder")

    await run_remaining_pipeline(config_path, "scan-123", runner=fake_runner)

    assert not config_path.exists()
