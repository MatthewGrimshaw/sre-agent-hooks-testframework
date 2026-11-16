import json
from html import escape
from pathlib import Path

import pytest
from pytest_html import extras

from framework.catalogue import Case, Suite, discover_suites
from framework.runner import Result, run_hook


HOOK_RESULT = pytest.StashKey[Result]()


def pytest_addoption(parser):
    parser.addoption(
        "--suite", action="append", default=[],
        help="Run a hook suite by catalogue ID; repeat to select multiple suites.",
    )


def pytest_generate_tests(metafunc):
    if not {"suite", "case"} <= set(metafunc.fixturenames):
        return
    suites = discover_suites()
    selected = set(metafunc.config.getoption("--suite"))
    unknown = selected - {suite.id for suite in suites}
    if unknown:
        raise pytest.UsageError(f"Unknown hook suites: {', '.join(sorted(unknown))}")
    metafunc.parametrize(
        ("suite", "case"),
        [
            pytest.param(suite, case, id=f"{suite.id}-{case.id}")
            for suite in suites if not selected or suite.id in selected
            for case in suite.cases
        ],
    )


def pytest_collection_modifyitems(config, items):
    selected = set(config.getoption("--suite"))
    if not selected:
        return
    kept, deselected = [], []
    for item in items:
        marker = item.get_closest_marker("suite")
        if marker is not None and marker.args[0] not in selected:
            deselected.append(item)
        else:
            kept.append(item)
    items[:] = kept
    config.hook.pytest_deselected(items=deselected)


@pytest.fixture
def hook_result(request, suite: Suite, case: Case) -> Result:
    result = run_hook(case.input, suite.hook, suite.timeout_seconds, suite.protocol)
    request.node.stash[HOOK_RESULT] = result
    if result.outcome == "error":
        pytest.fail(f"Hook execution or response error: {result.detail}", pytrace=False)
    return result


THEME_SCRIPT = """<script>
  (() => {
    const param = new URLSearchParams(window.location.search).get("scoutTheme");
    const theme =
      param || (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
    document.documentElement.setAttribute("data-theme", theme);
    document.addEventListener("click", (event) => {
      const button = event.target.closest("button.details-toggle");
      if (button) {
        event.stopPropagation();
        button.closest("td").click();
      }
    }, true);
  })();
</script>"""


@pytest.hookimpl(tryfirst=True)
def pytest_configure(config):
    if config.option.htmlpath == "reports/tests.html":
        config.option.htmlpath = str(Path(__file__).resolve().parents[1] / "reports" / "tests.html")


def pytest_html_report_title(report):
    report.title = "Python Hook Test Results"


def pytest_html_results_summary(prefix, summary, postfix):
    prefix.append(
        "<p>Failed means the hook's decision did not match the scenario. "
        "Error means the hook could not run correctly or returned an invalid response. "
        "No objection is not an explicit permission grant. "
        "Expand a row for its input, response, and supporting rule. "
        "Framework rows test the testing machinery itself. "
        "Passing tests are evidence, not a guarantee of safety.</p>"
    )


@pytest.hookimpl(wrapper=True)
def pytest_runtest_makereport(item, call):
    report = yield
    callspec = getattr(item, "callspec", None)
    case = callspec.params.get("case") if callspec is not None else None
    suite = callspec.params.get("suite") if callspec is not None else None
    marker = item.get_closest_marker("suite")
    report.suite = suite.id if isinstance(suite, Suite) else (
        marker.args[0] if marker is not None else "framework"
    )
    report.description = (
        case.description if isinstance(case, Case)
        else (item.obj.__doc__ or item.originalname.removeprefix("test_").replace("_", " ")).strip()
    )
    result = item.stash.get(HOOK_RESULT, None)
    report.expected = case.expected if isinstance(case, Case) else "-"
    report.actual = result.outcome if result is not None else "-"
    if isinstance(case, Case) and isinstance(suite, Suite) and result is not None:
        execution = result.execution
        evidence = {
            "suite": suite.id,
            "hook": str(suite.hook),
            "expected": case.expected,
            "actual": result.outcome,
            "explanation": result.detail,
            "input": case.input,
            "finding": suite.findings.get(case.finding),
            "rule": suite.criteria.get(case.criterion),
            "exit_code": execution.returncode if execution is not None else None,
            "stdout": execution.stdout if execution is not None else "",
            "stderr": execution.stderr if execution is not None else "",
        }
        report.extras = [
            *getattr(report, "extras", []),
            extras.html("<h3>Hook evidence</h3><pre>" + escape(
                json.dumps(evidence, indent=2, ensure_ascii=True)
            ) + "</pre>"),
        ]
    return report


def pytest_html_results_table_header(cells):
    cells[-1] = "<th>Details</th>"
    cells.insert(1, "<th>Hook / Suite</th>")
    cells.insert(2, "<th>Description</th>")
    cells.insert(3, "<th>Expected</th>")
    cells.insert(4, "<th>Actual</th>")


def pytest_html_results_table_row(report, cells):
    cells[-1] = (
        '<td class="col-details"><button type="button" class="details-toggle">'
        '<span class="details-show">Show details</span>'
        '<span class="details-hide">Hide details</span>'
        '</button></td>'
    )
    cells.insert(1, f"<td>{escape(getattr(report, 'suite', '-'))}</td>")
    cells.insert(2, f"<td>{escape(getattr(report, 'description', '-'))}</td>")
    cells.insert(3, f"<td>{escape(getattr(report, 'expected', '-'))}</td>")
    cells.insert(4, f"<td>{escape(getattr(report, 'actual', '-'))}</td>")


@pytest.hookimpl(wrapper=True)
def pytest_sessionfinish(session, exitstatus):
    result = yield
    if not session.config.option.htmlpath:
        return result
    report = Path(session.config.option.htmlpath)
    if report.is_file():
        html = report.read_text(encoding="utf-8")
        style = (Path(__file__).parent / "assets" / "report-theme.css").read_text(encoding="utf-8")
        html = html.replace("<head>", "<head>\n" + THEME_SCRIPT, 1)
        html = html.replace("</head>", "<style>\n" + style + "\n</style>\n</head>", 1)
        report.write_text(html, encoding="utf-8")
    return result
