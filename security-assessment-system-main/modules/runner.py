"""
modules/runner.py — Subprocess Wrapper
Handles execution of all external security tools with logging and error handling.
timeout=None means no time limit — tool runs until it finishes or errors.
"""
import subprocess
import logging
import shlex
import time
import os
from typing import Optional, Tuple

logger = logging.getLogger("assessor.runner")


def run_tool(
    cmd: list,
    tool_name: str,
    timeout: Optional[int] = None,
    env: Optional[dict] = None,
    cwd: Optional[str] = None,
) -> Tuple[int, str, str]:
    """
    Run an external tool via subprocess.

    Args:
        timeout: seconds before killing the process.
                 None = no limit (runs until tool finishes or errors).

    Returns:
        (returncode, stdout, stderr)
        Special return codes:
            -1 = timeout (only when timeout != None)
            -2 = tool binary not found
            -3 = unexpected OS/Python error
    """
    cmd_str = " ".join(shlex.quote(str(c)) for c in cmd)
    timeout_label = f"{timeout}s" if timeout is not None else "unlimited"
    logger.info(f"[{tool_name}] Running (timeout={timeout_label}): {cmd_str}")
    start = time.time()

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,           # None = no limit
            env={**os.environ, **(env or {})},
            cwd=cwd,
        )
        elapsed = time.time() - start
        logger.info(
            f"[{tool_name}] Finished in {elapsed:.1f}s "
            f"(exit={result.returncode})"
        )
        if result.stderr and result.returncode != 0:
            logger.warning(f"[{tool_name}] STDERR: {result.stderr[:500]}")
        return result.returncode, result.stdout, result.stderr

    except subprocess.TimeoutExpired:
        elapsed = time.time() - start
        logger.error(f"[{tool_name}] TIMEOUT after {elapsed:.1f}s (limit={timeout}s)")
        return -1, "", f"Tool timed out after {timeout} seconds"
    except FileNotFoundError:
        logger.error(f"[{tool_name}] Tool binary not found: {cmd[0]}")
        return -2, "", f"Tool not found: {cmd[0]}"
    except Exception as e:
        logger.error(f"[{tool_name}] Error running tool: {e}")
        return -3, "", str(e)
