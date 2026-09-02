import pytest

from app.tools.process import ToolTimeoutError, default_process_runner


@pytest.mark.asyncio
async def test_runs_command_and_captures_stdout():
    returncode, stdout, stderr = await default_process_runner(
        ["python3", "-c", "print('hello from subprocess')"], timeout_seconds=5.0
    )
    assert returncode == 0
    assert "hello from subprocess" in stdout


@pytest.mark.asyncio
async def test_captures_nonzero_exit_code():
    returncode, stdout, stderr = await default_process_runner(
        ["python3", "-c", "import sys; sys.exit(3)"], timeout_seconds=5.0
    )
    assert returncode == 3


@pytest.mark.asyncio
async def test_captures_stderr():
    returncode, stdout, stderr = await default_process_runner(
        ["python3", "-c", "import sys; print('oops', file=sys.stderr)"], timeout_seconds=5.0
    )
    assert "oops" in stderr


@pytest.mark.asyncio
async def test_raises_on_timeout():
    with pytest.raises(ToolTimeoutError):
        await default_process_runner(
            ["python3", "-c", "import time; time.sleep(5)"], timeout_seconds=0.2
        )
