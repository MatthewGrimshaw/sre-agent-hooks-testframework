from pathlib import Path

import jsonschema
import pytest
import yaml

from runner import interpret, load_catalogue, run_hook


@pytest.mark.parametrize(
    "code,stdout,stderr,expected",
    [
        (0, "", "", "pass"),
        (0, '{"ok":true}', "", "pass"),
        (0, '{"decision":"block","reason":"Denied"}', "", "block"),
        (0, '{"ok":false,"reason":"Denied"}', "", "block"),
        (0, '{"hookSpecificOutput":{"permissionDecision":"deny"},"reason":"Denied"}', "", "block"),
        (0, '{"ok":false,"reason":" "}', "", "error"),
        (0, '{"ok":true,"hookSpecificOutput":{"permissionDecision":"allow"}}', "", "error"),
        (0, '{"ok":"false"}', "", "error"),
        (0, "[]", "", "error"),
        (0, "not json", "", "error"),
        (0, "{}", "", "error"),
        (1, "", "crashed", "error"),
        (2, "", "Denied", "block"),
        (2, "", "", "error"),
    ],
)
def test_interpret(code, stdout, stderr, expected):
    assert interpret(code, stdout, stderr).outcome == expected


def test_timeout_is_error(tmp_path):
    hook = tmp_path / "slow.py"
    hook.write_text("import time\ntime.sleep(5)\n", encoding="utf-8")
    assert run_hook({}, hook, timeout=0.1).outcome == "error"


def test_missing_hook_is_error(tmp_path):
    assert run_hook({}, tmp_path / "missing.py").outcome == "error"


def test_embedded_command_is_only_data(tmp_path):
    marker = tmp_path / "must-not-exist"
    hook = tmp_path / "inert.py"
    hook.write_text("import json, sys\njson.load(sys.stdin)\n", encoding="utf-8")
    result = run_hook({"tool_input": {"command": f"touch {marker}"}}, hook)
    assert result.outcome == "pass"
    assert not marker.exists()


@pytest.mark.parametrize(
    "mutation",
    ["unknown-field", "duplicate-id", "unknown-criterion", "unknown-finding",
     "duplicate-finding", "uncovered-finding", "missing-finding"],
)
def test_bad_catalogue_rejects(tmp_path, mutation):
    original = Path(__file__).with_name("cases.yaml")
    catalogue = yaml.safe_load(original.read_text(encoding="utf-8"))
    if mutation == "unknown-field":
        catalogue["unexpected"] = True
    elif mutation == "duplicate-id":
        catalogue["cases"].append(catalogue["cases"][0])
    elif mutation == "unknown-criterion":
        catalogue["cases"][0]["criterion"] = "unknown"
    elif mutation == "unknown-finding":
        catalogue["cases"][0]["finding"] = "F99"
    elif mutation == "duplicate-finding":
        catalogue["findings"].append(catalogue["findings"][0])
    elif mutation == "uncovered-finding":
        catalogue["cases"] = [
            case for case in catalogue["cases"]
            if case["finding"] != "F06" or case["expected"] != "block"
        ]
    else:
        del catalogue["cases"][0]["finding"]
    path = tmp_path / "cases.yaml"
    path.write_text(yaml.safe_dump(catalogue), encoding="utf-8")
    path.with_name("cases.schema.json").write_text(
        original.with_name("cases.schema.json").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    with pytest.raises((ValueError, jsonschema.ValidationError)) as error:
        load_catalogue(path)
    assert error.value is not None


def test_duplicate_yaml_key_rejects(tmp_path):
    path = tmp_path / "cases.yaml"
    path.write_text("schema_version: 1\nschema_version: 1\n", encoding="utf-8")
    with pytest.raises(ValueError, match="Duplicate YAML key"):
        load_catalogue(path)
