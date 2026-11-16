from framework.catalogue import Case, Suite
from framework.runner import Result


def test_policy(suite: Suite, case: Case, hook_result: Result) -> None:
    assert hook_result.outcome == case.expected, (
        f"{suite.id}: {case.description}\n"
        f"Expected {case.expected}; actual {hook_result.outcome}: {hook_result.detail}\n"
        f"{suite.criteria.get(case.criterion, '')}"
    )
