import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import jsonschema
import yaml


HOOK = Path(__file__).resolve().parents[1] / "hooks" / "hook.py"
Outcome = Literal["pass", "block", "error"]


@dataclass(frozen=True)
class Result:
    outcome: Outcome
    detail: str


def interpret(returncode: int, stdout: str, stderr: str) -> Result:
    if returncode == 2:
        return Result("block" if stderr.strip() else "error", stderr.strip())
    if returncode != 0:
        return Result("error", f"Hook exited {returncode}: {stderr.strip()}")
    if not stdout.strip():
        return Result("pass", "Hook raised no objection.")
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
    if "decision" in response:
        rejected = response["decision"] == "block"
    elif type(response.get("ok")) is bool:
        rejected = not response["ok"]
    elif permission == "deny":
        rejected = True
    else:
        return Result("error", "Missing valid hook decision.")
    if rejected or permission == "deny":
        reason = response.get("reason")
        if not isinstance(reason, str) or not reason.strip():
            return Result("error", "Rejection requires a nonblank reason.")
        return Result("block", reason.strip())
    return Result("pass", "Hook raised no objection.")


def run_hook(context: object, hook: Path = HOOK, timeout: float = 3) -> Result:
    if not hook.is_file():
        return Result("error", f"Hook file does not exist: {hook}")
    raw = json.dumps(context, allow_nan=False)
    if len(raw.encode("utf-8")) > 65536:
        return Result("error", "Input exceeds harness limit of 64 KiB.")
    try:
        process = subprocess.run(
            [sys.executable, str(hook)],
            input=raw,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=timeout,
            cwd=hook.parent,
        )
    except subprocess.TimeoutExpired:
        return Result("error", "Hook exceeded its time limit.")
    except OSError as error:
        return Result("error", f"Cannot start hook: {error}")
    return interpret(process.returncode, process.stdout, process.stderr)


def load_catalogue(path: Path) -> dict:
    class UniqueLoader(yaml.SafeLoader):
        pass

    def mapping(loader, node):
        result = {}
        for key_node, value_node in node.value:
            key = loader.construct_object(key_node)
            if key in result:
                raise ValueError(f"Duplicate YAML key: {key}")
            result[key] = loader.construct_object(value_node)
        return result

    UniqueLoader.add_constructor(
        yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, mapping
    )
    catalogue = yaml.load(path.read_text(encoding="utf-8"), Loader=UniqueLoader)
    schema = json.loads(path.with_name("cases.schema.json").read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(schema).validate(catalogue)
    json.dumps(catalogue, allow_nan=False)
    criteria = {item["id"] for item in catalogue["criteria"]}
    if len(criteria) != len(catalogue["criteria"]):
        raise ValueError("Duplicate criterion IDs.")
    findings = {item["id"] for item in catalogue["findings"]}
    if len(findings) != len(catalogue["findings"]):
        raise ValueError("Duplicate finding IDs.")
    ids = set()
    for case in catalogue["cases"]:
        if case["id"] in ids:
            raise ValueError(f"Duplicate case ID: {case['id']}")
        ids.add(case["id"])
        if case["criterion"] not in criteria:
            raise ValueError(f"Unknown criterion: {case['criterion']}")
        if case["finding"] not in findings:
            raise ValueError(f"Unknown finding: {case['finding']}")
    tested = {case["finding"] for case in catalogue["cases"] if case["expected"] == "block"}
    if missing := findings - tested:
        raise ValueError(f"Findings without a blocking regression: {sorted(missing)}")
    return catalogue
