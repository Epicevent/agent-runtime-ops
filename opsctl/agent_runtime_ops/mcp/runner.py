from __future__ import annotations

from dataclasses import dataclass
import subprocess


@dataclass(frozen=True)
class CommandResult:
    argv: list[str]
    returncode: int
    stdout: str = ""
    stderr: str = ""


class CommandRunner:
    def run(self, argv: list[str], *, input_text: str | None = None, timeout: int = 60) -> CommandResult:
        proc = subprocess.run(
            argv,
            input=input_text,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        return CommandResult(argv=argv, returncode=proc.returncode, stdout=proc.stdout, stderr=proc.stderr)
