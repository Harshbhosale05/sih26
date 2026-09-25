"""Safe invocation of external analysis tools.

Every external tool in this project (capinfos, tshark, editcap, later zeek) goes
through `run_tool`. The rules it enforces are not optional:

  * Arguments are always a list -- never a shell string. Uploaded filenames are
    attacker-controlled; `shell=True` anywhere here is a command injection.
  * Every invocation has a wall-clock timeout. A malformed capture can make a
    dissector spin forever, and an unbounded subprocess is a trivial DoS.
  * Non-zero exit is surfaced as a typed error, never swallowed.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from app.config import get_settings

logger = logging.getLogger(__name__)


class ToolError(RuntimeError):
    """An external tool failed, was missing, or timed out."""


class ToolNotFound(ToolError):
    pass


class ToolTimeout(ToolError):
    pass


@dataclass(frozen=True)
class ToolResult:
    command: list[str]
    returncode: int
    stdout: str
    stderr: str


def require_tool(name: str) -> str:
    path = shutil.which(name)
    if path is None:
        raise ToolNotFound(
            f"Required tool {name!r} is not installed in this container. "
            "The API image must provide tshark and wireshark-common."
        )
    return path


def run_tool(
    argv: list[str],
    *,
    timeout: int | None = None,
    cwd: Path | None = None,
    check: bool = True,
) -> ToolResult:
    if not argv:
        raise ValueError("argv must not be empty")

    binary = require_tool(argv[0])
    command = [binary, *argv[1:]]
    limit = timeout if timeout is not None else get_settings().tool_timeout_seconds

    logger.debug("running tool: %s", command)
    try:
        completed = subprocess.run(  # noqa: S603 - argv list, never shell
            command,
            capture_output=True,
            text=True,
            timeout=limit,
            cwd=str(cwd) if cwd else None,
            check=False,
            # Do not inherit the API's environment wholesale; dissectors read
            # a surprising number of env vars.
            env={"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": "/tmp"},
        )
    except subprocess.TimeoutExpired as exc:
        raise ToolTimeout(f"{argv[0]} exceeded {limit}s and was killed") from exc

    result = ToolResult(
        command=command,
        returncode=completed.returncode,
        stdout=completed.stdout or "",
        stderr=completed.stderr or "",
    )

    if check and result.returncode != 0:
        raise ToolError(
            f"{argv[0]} exited {result.returncode}: {result.stderr.strip()[:500]}"
        )
    return result
