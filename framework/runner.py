import json
import math
# Required to execute the selected hook.
import subprocess  # nosec B404
import sys
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Literal

Outcome = Literal["no_objection", "block", "error"]


@dataclass(frozen=True)
class Execution:
    returncode: int | None = None
    stdout: str = ""
    stderr: str = ""
    error: str | None = None


@dataclass(frozen=True)
class Result:
    outcome: Outcome
    detail: str
    execution: Execution | None = None


def interpret(returncode: int, stdout: str, stderr: str) -> Result:
    if returncode == 2:
        return Result("block" if stderr.strip() else "error", stderr.strip())
    if returncode != 0:
        return Result("error", f"Hook exited {returncode}: {stderr.strip()}")
    if not stdout.strip():
        return Result("no_objection", "Hook raised no objection.")
    try:
        response = json.loads(stdout)
    except json.JSONDecodeError:
        return Result("error", "Hook output is not a single JSON response.")
    if not isinstance(response, dict):
        return Result("error", "Hook response must be an object.")
    specific = response.get("hookSpecificOutput", {})
    if not isinstance(specific, dict):
        return Result("error", "Invalid hookSpecificOutput.")
    permission = specific.get("permissionDecision")
    if permission not in (None, "deny"):
        return Result("error", "Explicit allow/ask is outside this harness policy.")
    decisions = []
    if "decision" in response:
        if response["decision"] != "block":
            return Result("error", "Unsupported hook decision.")
        decisions.append(True)
    if "ok" in response:
        if type(response["ok"]) is not bool:
            return Result("error", "Hook ok field must be a boolean.")
        decisions.append(not response["ok"])
    if permission == "deny":
        decisions.append(True)
    if not decisions:
        return Result("error", "Missing valid hook decision.")
    if len(set(decisions)) != 1:
        return Result("error", "Conflicting hook decisions.")
    if decisions[0]:
        reason = response.get("reason")
        if not isinstance(reason, str) or not reason.strip():
            return Result("error", "Rejection requires a nonblank reason.")
        return Result("block", reason.strip())
    return Result("no_objection", "Hook raised no objection.")


def execute_hook(context: object, hook: Path, timeout: float = 3) -> Execution:
    hook = hook.resolve()
    if not math.isfinite(timeout) or timeout <= 0:
        return Execution(error="Hook timeout must be a positive finite number.")
    if not hook.is_file():
        return Execution(error=f"Hook file does not exist: {hook}")
    try:
        raw = json.dumps(context, allow_nan=False)
    except (TypeError, ValueError) as error:
        return Execution(error=f"Input is not valid JSON: {error}")
    if len(raw.encode("utf-8")) > 65536:
        return Execution(error="Input exceeds harness limit of 64 KiB.")
    try:
        # Execute the selected hook; scenario input is JSON on stdin, not shell code.
        process = subprocess.run(  # nosec B603
            [sys.executable, str(hook)],
            input=raw.encode("utf-8"),
            capture_output=True,
            timeout=timeout,
            cwd=hook.parent,
            shell=False,
        )
    except subprocess.TimeoutExpired as error:
        return Execution(
            stdout=(error.stdout or b"").decode("utf-8", errors="replace"),
            stderr=(error.stderr or b"").decode("utf-8", errors="replace"),
            error="Hook exceeded its time limit.",
        )
    except OSError as error:
        return Execution(error=f"Cannot start hook: {error}")
    try:
        stdout = process.stdout.decode("utf-8")
        stderr = process.stderr.decode("utf-8")
    except UnicodeDecodeError:
        return Execution(
            process.returncode,
            process.stdout.decode("utf-8", errors="replace"),
            process.stderr.decode("utf-8", errors="replace"),
            "Hook output is not valid UTF-8.",
        )
    return Execution(process.returncode, stdout, stderr)


def run_hook(
    context: object, hook: Path, timeout: float = 3, protocol: str = "sre-agent"
) -> Result:
    if protocol != "sre-agent":
        raise ValueError(f"Unsupported hook protocol: {protocol}")
    execution = execute_hook(context, hook, timeout)
    if execution.error is not None:
        return Result("error", execution.error, execution)
    if execution.returncode is None:
        return Result("error", "Hook did not return an exit code.", execution)
    return replace(
        interpret(execution.returncode, execution.stdout, execution.stderr),
        execution=execution,
    )
