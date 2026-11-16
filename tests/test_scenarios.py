from pathlib import Path

import pytest

from runner import load_catalogue, run_hook


CATALOGUE = load_catalogue(Path(__file__).with_name("cases.yaml"))
CRITERIA = {criterion["id"]: criterion for criterion in CATALOGUE["criteria"]}


@pytest.mark.parametrize(
    "case", CATALOGUE["cases"], ids=lambda case: f"{case['finding']}-{case['id']}"
)
def test_policy(case):
    result = run_hook(case["input"])
    assert result.outcome == case["expected"], (
        f"{case['finding']} / {case['criterion']}: {case['description']}\n"
        f"Source: {CRITERIA[case['criterion']]['source']}\n"
        f"Expected {case['expected']}; actual {result.outcome}: {result.detail}"
    )


def test_all_initial_findings_have_negative_regressions():
    initial = {f"F{number:02}" for number in range(1, 8)}
    findings = {finding["id"] for finding in CATALOGUE["findings"]}
    negatives = {case["finding"] for case in CATALOGUE["cases"] if case["expected"] == "block"}
    assert initial <= findings & negatives
