from html import escape
from pathlib import Path

import pytest


THEME_SCRIPT = """<script>
  (() => {
    const param = new URLSearchParams(window.location.search).get("scoutTheme");
    const theme =
      param || (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
    document.documentElement.setAttribute("data-theme", theme);
  })();
</script>"""


@pytest.hookimpl(tryfirst=True)
def pytest_configure(config):
    if config.option.htmlpath == "reports/tests.html":
        config.option.htmlpath = str(Path(__file__).resolve().parents[1] / "reports" / "tests.html")


def pytest_html_report_title(report):
    report.title = "SRE Agent Hook Test Results"


def pytest_html_results_summary(prefix, summary, postfix):
    prefix.append(
        "<p>Policy failures identify inputs the hook did not reject as required. "
        "Errors are not successful blocks. Passing tests do not certify security. "
        "Bandit results are reported separately.</p>"
    )
    prefix.append(
        "<p>Findings F01-F07 are tracked in scenario IDs and the Finding column. "
        "F06 uses synthetic SQL destinations: it does not verify actual server "
        "identity, Azure permissions, or network isolation. F07 tests local "
        "decisions, not Azure's handling of hook failures.</p>"
    )


@pytest.hookimpl(wrapper=True)
def pytest_runtest_makereport(item, call):
    report = yield
    callspec = getattr(item, "callspec", None)
    case = callspec.params.get("case") if callspec is not None else None
    report.finding = case["finding"] if isinstance(case, dict) else "-"
    report.criterion = case["criterion"] if isinstance(case, dict) else "-"
    return report


def pytest_html_results_table_header(cells):
    cells.insert(1, "<th>Finding</th>")
    cells.insert(2, "<th>Criterion</th>")


def pytest_html_results_table_row(report, cells):
    cells.insert(1, f"<td>{escape(getattr(report, 'finding', '-'))}</td>")
    cells.insert(2, f"<td>{escape(getattr(report, 'criterion', '-'))}</td>")


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
