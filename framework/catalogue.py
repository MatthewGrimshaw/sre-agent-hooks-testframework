import json
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import jsonschema
import yaml


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = Path(__file__).parent / "schemas" / "cases.schema.json"


@dataclass(frozen=True)
class Case:
    id: str
    description: str
    input: object
    expected: Literal["no_objection", "block"]
    finding: str = "-"
    criterion: str = "-"


@dataclass(frozen=True)
class Suite:
    id: str
    description: str
    hook: Path
    protocol: str
    timeout_seconds: float
    cases: tuple[Case, ...]
    findings: dict[str, str]
    criteria: dict[str, str]


def load_catalogue(path: Path, root: Path = ROOT) -> Suite:
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

    UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, mapping)
    catalogue = yaml.load(path.read_text(encoding="utf-8"), Loader=UniqueLoader)
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(schema).validate(catalogue)
    json.dumps(catalogue, allow_nan=False)
    metadata = catalogue["suite"]
    relative_hook = Path(metadata["hook"])
    hook = (root / relative_hook).resolve()
    if relative_hook.is_absolute() or not hook.is_relative_to(root.resolve()):
        raise ValueError(f"Hook path must be relative to the repository root: {relative_hook}")
    if hook.suffix != ".py" or not hook.is_file():
        raise ValueError(f"Hook must be an existing Python file: {hook}")
    findings = {item["id"]: item["description"] for item in catalogue.get("findings", [])}
    criteria = {
        item["id"]: f"{item['requirement']} Source: {item['source']}"
        for item in catalogue.get("criteria", [])
    }
    if len(findings) != len(catalogue.get("findings", [])):
        raise ValueError("Duplicate finding IDs.")
    if len(criteria) != len(catalogue.get("criteria", [])):
        raise ValueError("Duplicate criterion IDs.")
    ids = set()
    cases = []
    for case in catalogue["cases"]:
        if case["id"] in ids:
            raise ValueError(f"Duplicate case ID: {case['id']}")
        ids.add(case["id"])
        if "finding" in case and case["finding"] not in findings:
            raise ValueError(f"Unknown finding: {case['finding']}")
        if "criterion" in case and case["criterion"] not in criteria:
            raise ValueError(f"Unknown criterion: {case['criterion']}")
        cases.append(Case(
            id=case["id"], description=case["description"], input=case["input"],
            expected=case["expected"]["outcome"], finding=case.get("finding", "-"),
            criterion=case.get("criterion", "-"),
        ))
    return Suite(
        metadata["id"], metadata["description"], hook, metadata["protocol"],
        metadata["timeout_seconds"], tuple(cases), findings, criteria,
    )


def discover_suites(root: Path = ROOT) -> tuple[Suite, ...]:
    suites = []
    ids = set()
    for path in sorted((root / "tests" / "hooks").rglob("cases.yaml")):
        suite = load_catalogue(path, root)
        if suite.id in ids:
            raise ValueError(f"Duplicate suite ID: {suite.id}")
        ids.add(suite.id)
        suites.append(suite)
    if not suites:
        raise ValueError("No hook catalogues found under tests/hooks.")
    return tuple(suites)
