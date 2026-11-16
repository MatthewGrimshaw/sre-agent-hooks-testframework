from pathlib import Path

import pytest

from framework.runner import execute_hook, interpret, run_hook


@pytest.mark.parametrize(
    "code,stdout,stderr,expected",
    [
        (0, "", "", "no_objection"),
        (0, '{"ok":true}', "", "no_objection"),
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
        (0, '{"decision":"unknown"}', "", "error"),
        (0, '{"ok":true,"decision":"block","reason":"Denied"}', "", "error"),
        (0, '{"hookSpecificOutput":{"permissionDecision":"deny"},"reason":" "}', "", "error"),
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
    assert result.outcome == "no_objection"
    assert not marker.exists()


def test_execution_preserves_raw_response_and_uses_hook_directory(tmp_path, monkeypatch):
    hook_dir = tmp_path / "hook"
    hook_dir.mkdir()
    (hook_dir / "reason.txt").write_text("Review required", encoding="utf-8")
    hook = hook_dir / "hook.py"
    hook.write_text(
        "import json, sys\n"
        "from pathlib import Path\n"
        "context = json.load(sys.stdin)\n"
        "print(context['diagnostic'], file=sys.stderr)\n"
        "print(json.dumps({'decision':'block','reason':Path('reason.txt').read_text()}))\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    execution = execute_hook({"diagnostic": "example log"}, Path("hook") / "hook.py")
    assert execution.returncode == 0
    assert execution.stderr.strip() == "example log"
    result = run_hook({"diagnostic": "example log"}, hook)
    assert result.outcome == "block"
    assert result.detail == "Review required"
    assert result.execution == execution


@pytest.mark.parametrize(
    "context", [float("nan"), {"value": object()}, "x" * 65537],
    ids=["nonfinite", "not-json", "oversized"],
)
def test_invalid_or_oversized_input_is_an_error(tmp_path, context):
    hook = tmp_path / "hook.py"
    hook.write_text("raise RuntimeError('must not execute')\n", encoding="utf-8")
    result = run_hook(context, hook)
    assert result.outcome == "error"
    assert result.execution.returncode is None


def test_timeout_keeps_partial_diagnostics(tmp_path):
    hook = tmp_path / "slow.py"
    hook.write_text(
        "import time\nprint('started', flush=True)\ntime.sleep(10)\n", encoding="utf-8"
    )
    result = run_hook({}, hook, timeout=1)
    assert result.outcome == "error"
    assert result.execution.stdout.strip() == "started"
    assert result.execution.returncode is None


def test_invalid_output_encoding_is_an_error(tmp_path):
    hook = tmp_path / "hook.py"
    hook.write_text("import sys\nsys.stdout.buffer.write(b'\\xff')\n", encoding="utf-8")
    result = run_hook({}, hook)
    assert result.outcome == "error"
    assert "UTF-8" in result.detail


def test_unsupported_protocol_does_not_execute_hook(tmp_path):
    with pytest.raises(ValueError, match="Unsupported hook protocol"):
        run_hook({}, tmp_path / "hook.py", protocol="unknown")
