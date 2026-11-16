import jsonschema
import pytest
import yaml

from framework.catalogue import discover_suites, load_catalogue
from framework.runner import run_hook


@pytest.fixture
def catalogue(tmp_path):
    hook = tmp_path / "hooks" / "example" / "hook.py"
    hook.parent.mkdir(parents=True)
    hook.write_text("import json, sys\njson.load(sys.stdin)\n", encoding="utf-8")
    path = tmp_path / "tests" / "hooks" / "example" / "cases.yaml"
    path.parent.mkdir(parents=True)
    data = {
        "schema_version": 2,
        "suite": {
            "id": "example", "description": "A hook without SQL-specific metadata.",
            "hook": "hooks/example/hook.py", "protocol": "sre-agent",
            "timeout_seconds": 3,
        },
        "cases": [{
            "id": "basic", "description": "Accept a normal input.", "input": {},
            "expected": {"outcome": "no_objection"},
        }],
    }
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return path, data


def test_suite_without_findings_or_block_cases_loads_from_any_directory(
    tmp_path, catalogue, monkeypatch
):
    path, _ = catalogue
    monkeypatch.chdir(path.parent)
    suite = load_catalogue(path, tmp_path)
    assert suite.findings == {}
    assert suite.criteria == {}
    assert run_hook(suite.cases[0].input, suite.hook).outcome == "no_objection"


@pytest.mark.parametrize(
    "mutation",
    ["unknown-field", "duplicate-id", "unknown-criterion", "unknown-finding",
     "duplicate-finding", "duplicate-criterion", "empty-cases", "missing-hook",
     "outside-root", "absolute-hook", "invalid-protocol", "invalid-timeout",
     "invalid-expected", "old-schema"],
)
def test_bad_catalogue_rejects(tmp_path, catalogue, mutation):
    path, data = catalogue
    if mutation == "unknown-field":
        data["unexpected"] = True
    elif mutation == "duplicate-id":
        data["cases"].append(data["cases"][0])
    elif mutation == "unknown-criterion":
        data["cases"][0]["criterion"] = "missing"
    elif mutation == "unknown-finding":
        data["cases"][0]["finding"] = "missing"
    elif mutation == "duplicate-finding":
        data["findings"] = [{"id": "issue", "description": "Example"}] * 2
    elif mutation == "duplicate-criterion":
        data["criteria"] = [{"id": "rule", "requirement": "Example", "source": "Policy"}] * 2
    elif mutation == "empty-cases":
        data["cases"] = []
    elif mutation == "missing-hook":
        data["suite"]["hook"] = "missing.py"
    elif mutation == "outside-root":
        data["suite"]["hook"] = "../outside.py"
    elif mutation == "absolute-hook":
        data["suite"]["hook"] = str(tmp_path / "hooks" / "example" / "hook.py")
    elif mutation == "invalid-protocol":
        data["suite"]["protocol"] = "unknown"
    elif mutation == "invalid-timeout":
        data["suite"]["timeout_seconds"] = 0
    elif mutation == "invalid-expected":
        data["cases"][0]["expected"]["outcome"] = "error"
    else:
        data["schema_version"] = 1
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    with pytest.raises((ValueError, jsonschema.ValidationError)):
        load_catalogue(path, tmp_path)


def test_optional_metadata_allows_non_security_rules(tmp_path, catalogue):
    path, data = catalogue
    data["findings"] = [{"id": "explanation-required", "description": "Missing context."}]
    data["criteria"] = [{"id": "explain", "requirement": "Provide a purpose.", "source": "Policy"}]
    data["cases"][0].update(finding="explanation-required", criterion="explain")
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    suite = load_catalogue(path, tmp_path)
    assert suite.cases[0].finding == "explanation-required"
    assert "Provide a purpose." in suite.criteria["explain"]


def test_duplicate_yaml_key_rejects(tmp_path):
    path = tmp_path / "cases.yaml"
    path.write_text("schema_version: 2\nschema_version: 2\n", encoding="utf-8")
    with pytest.raises(ValueError, match="Duplicate YAML key"):
        load_catalogue(path, tmp_path)


def test_discovery_runs_distinct_hooks_with_reused_case_ids(tmp_path, catalogue):
    _, data = catalogue
    hook = tmp_path / "hooks" / "second.py"
    hook.write_text(
        "import json\nprint(json.dumps({'decision':'block','reason':'Second hook'}))\n",
        encoding="utf-8",
    )
    data["suite"].update(id="second", hook="hooks/second.py")
    data["cases"][0]["expected"]["outcome"] = "block"
    second = tmp_path / "tests" / "hooks" / "second" / "cases.yaml"
    second.parent.mkdir()
    second.write_text(yaml.safe_dump(data), encoding="utf-8")
    suites = discover_suites(tmp_path)
    assert [suite.id for suite in suites] == ["example", "second"]
    assert [
        run_hook(suite.cases[0].input, suite.hook).outcome for suite in suites
    ] == ["no_objection", "block"]


def test_duplicate_suite_ids_reject(tmp_path, catalogue):
    path, _ = catalogue
    duplicate = path.parent.parent / "duplicate" / "cases.yaml"
    duplicate.parent.mkdir()
    duplicate.write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
    with pytest.raises(ValueError, match="Duplicate suite ID"):
        discover_suites(tmp_path)


def test_empty_discovery_is_not_a_success(tmp_path):
    with pytest.raises(ValueError, match="No hook catalogues"):
        discover_suites(tmp_path)
