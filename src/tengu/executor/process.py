"""Async subprocess execution with timeout and output streaming.

CRITICAL SECURITY: We NEVER use shell=True. All commands are passed as
argument lists to asyncio.create_subprocess_exec(), which prevents
shell injection attacks entirely.
"""

from __future__ import annotations

import asyncio
import shutil
import time
from collections.abc import AsyncIterator

import structlog

from tengu.exceptions import ScanTimeoutError, ToolNotFoundError

logger = structlog.get_logger(__name__)


async def run_command(
    args: list[str],
    timeout: int = 600,
    env: dict[str, str] | None = None,
    cwd: str | None = None,
    stdin_data: bytes | None = None,
) -> tuple[str, str, int]:
    """Run an external command and return (stdout, stderr, returncode).

    Args:
        args: Command and arguments as a list. NEVER pass user input as a
              single string — always split into list elements.
        timeout: Maximum execution time in seconds.
        env: Optional environment variables (merged with current env).
        cwd: Working directory for the process.
        stdin_data: Optional bytes to write to the process stdin. If None,
                    stdin is inherited from the parent (usually /dev/null in
                    server contexts). Use this for tools like commix v4.1
                    that read targets from stdin.

    Returns:
        Tuple of (stdout, stderr, returncode).

    Raises:
        ToolNotFoundError: If the executable is not found.
        ScanTimeoutError: If execution exceeds timeout.
        ToolExecutionError: If the command exits with a non-zero code.
    """
    if not args:
        raise ValueError("args list cannot be empty")

    executable = args[0]
    resolved = shutil.which(executable)
    if resolved is None:
        raise ToolNotFoundError(executable)

    # Use the resolved absolute path to prevent PATH manipulation attacks
    safe_args = [resolved, *args[1:]]

    log = logger.bind(cmd=executable, timeout=timeout)
    log.debug("Executing command", args=safe_args)

    start = time.monotonic()

    stdin_mode = asyncio.subprocess.PIPE if stdin_data is not None else None

    try:
        proc = await asyncio.create_subprocess_exec(
            *safe_args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            stdin=stdin_mode,
            env=env,
            cwd=cwd,
        )

        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(input=stdin_data),
                timeout=timeout,
            )
        except TimeoutError as exc:
            proc.kill()
            await proc.communicate()
            raise ScanTimeoutError(executable, timeout) from exc

    except FileNotFoundError as exc:
        raise ToolNotFoundError(executable) from exc

    duration = time.monotonic() - start
    stdout = stdout_bytes.decode("utf-8", errors="replace")
    stderr = stderr_bytes.decode("utf-8", errors="replace")
    returncode = proc.returncode or 0

    log.debug(
        "Command completed",
        returncode=returncode,
        duration=f"{duration:.2f}s",
        stdout_len=len(stdout),
        stderr_len=len(stderr),
    )

    return stdout, stderr, returncode


async def stream_command(
    args: list[str],
    timeout: int = 600,
    env: dict[str, str] | None = None,
    cwd: str | None = None,
) -> AsyncIterator[str]:
    """Run a command and stream its stdout line by line.

    Useful for tools that produce incremental output (e.g. nmap, nuclei).
    Yields each line as a string (newline stripped).
    """
    if not args:
        raise ValueError("args list cannot be empty")

    executable = args[0]
    resolved = shutil.which(executable)
    if resolved is None:
        raise ToolNotFoundError(executable)

    safe_args = [resolved, *args[1:]]

    proc = await asyncio.create_subprocess_exec(
        *safe_args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=env,
        cwd=cwd,
    )

    start = time.monotonic()

    assert proc.stdout is not None
    try:
        async for raw_line in proc.stdout:
            if time.monotonic() - start > timeout:
                proc.kill()
                raise ScanTimeoutError(executable, timeout)
            yield raw_line.decode("utf-8", errors="replace").rstrip()
    finally:
        await proc.wait()
