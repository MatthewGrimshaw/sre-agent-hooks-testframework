# Python hook testing framework

**This repository helps teams check that python hooks used in the Azure SRE Agent behave as intended before they are used in live operations, with repeatable tests and a readable results report.**

![Test report overview](./images/report-1.png)
![Expanded test report details](./images/report-2.png)

## What problem does this solve?

A *hook* is a small program that runs at a defined point in an automated
workflow. For example, it might check a proposed action before an assistant
carries it out, and stop the action if a required condition is missing.

This framework gives each hook a catalogue of example inputs and expected
decisions. It runs those examples, compares the actual decisions with the
expectations, and produces an HTML report. Teams can repeat the same checks
after a change and keep examples of previously discovered problems.

The framework is not tied to SQL, Azure, or security checks. Different hooks
can have different business rules while sharing the same test runner and
report. The current execution interface is described under
[Supported hooks](#supported-hooks).

### What the results tell a decision maker

| Result | Meaning | Next step |
|---|---|---|
| Passed | The hook behaved as expected for this example. | Review whether the examples cover the intended requirements. |
| Failed | The hook's decision differed from the expectation. | Investigate the rule, the hook, and the example before relying on that behaviour. |
| Error | The hook could not complete correctly, or its response could not be understood. | Investigate the execution or response problem; it does not count as a successful block. |

**Passing tests provide evidence, not a guarantee of safety or compliance.**
Coverage depends on the examples and requirements the team defines.
An expected **no objection** means the hook did not object; it is not an
explicit permission grant. Access controls and any other approvals still apply.

Framework self-tests also appear in the report, labelled `framework`. They
check the testing machinery, not a particular operational rule.

## Overall security boundary: how the protections work together

A hook is one checkpoint, not the whole security boundary. An automated
assistant should only be able to take actions that its settings, permissions,
and the systems it connects to all permit.

**Hooks complement access policies, cloud permissions, network restrictions,
and database permissions. They do not replace those protections or grant
additional access.** If a hook raises no objection, the action must still
satisfy every other applicable control.

For the included Azure SRE Agent SQL example, the layers are:

| Layer | What it should control |
|---|---|
| Agent settings and approvals | Which tools the assistant can use and when a person must approve an action. |
| Hook checks | Whether a proposed command meets the hook's rules before the tool runs. |
| Tool implementation | Which actions the tool supports and which approved system it connects to. |
| Azure permissions | Which cloud resources the assistant's identity can access or change. |
| Host and network controls | What can run on a machine and which systems it can reach. |
| Database permissions | Which data and database operations the connected identity can use. |

These are complementary layers, not a guaranteed execution order. This is a
conceptual model of protections to configure and verify; it does not mean this
repository implements or verifies every layer. Other hooks may need different
controls around them.

### Where this framework fits

The framework tests the **hook's decisions** against agreed examples. It does
not deploy the hook, configure permissions, or prove that the surrounding
systems enforce their controls.

The SQL guard aims to keep selected database commands focused on diagnosis,
with a limited exception for ending a database session outside production.
Its tests do not establish that a database destination is genuinely approved
or that production is isolated. Those boundaries need independent checks in
the deployed environment.

## Included examples

| Suite | Purpose | Status and limits |
|---|---|---|
| [SQL guard](./hooks/sql_guard/hook.py) | Checks selected Azure commands intended to perform database diagnosis, with a limited exception for ending a database session outside production. | Contains known failing tests. Uses text-pattern checks and placeholder subscription settings; it is not a production-ready security guarantee. |
| [Required field](./hooks/required_field/hook.py) | Demonstrates a different rule: an action must include a written purpose. | A small teaching example with no Azure or SQL dependency, not a check that the explanation is meaningful. |

The [SQL catalogue](./tests/hooks/sql_guard/cases.yaml) records local findings
F01-F07 and references relevant OWASP guidance. OWASP is a source of general
security practices, not a certification of this repository or a definition of
your organisation's rules. SQL-specific generated tests and finding-coverage
requirements live alongside that suite, not in the shared framework.

The SQL tests check decisions using example command strings. They do not
verify actual database destinations, network isolation, cloud permissions,
or how a deployed service handles a hook failure.

## Run the tests

Requires Python 3.11 or newer. From the repository root in PowerShell:

```powershell
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements-test.txt
.venv\Scripts\python.exe -m pytest --junitxml=reports\tests.xml
```

The SQL suite currently exposes unresolved issues, so a full run is expected
to include failures. These remain visible rather than being marked as acceptable.

Run just one hook suite and the framework self-tests:

```powershell
.venv\Scripts\python.exe -m pytest --suite required-field
.venv\Scripts\python.exe -m pytest --suite sql-guard
```

Repeat `--suite` to select multiple suites. An unknown suite ID is an error.
Run only the framework self-tests with:

```powershell
.venv\Scripts\python.exe -m pytest tests\framework
```

On Linux, use `.venv/bin/python` and forward slashes in paths.
The framework also supports running pytest from the `tests` directory using
`..\.venv\Scripts\python.exe -m pytest`; hook paths still resolve from the
repository root.

### Read the report

Open [reports/tests.html](./reports/tests.html) in a browser. It works offline.

- The table shows the suite, scenario description, expected decision, and
  actual decision. Failed and errored rows are highlighted in red.
- Details start collapsed. Each row has a **Show details / Hide details** button.
- Scenario details include the input, the hook's explanation, exit code,
  captured output, and any linked finding or rule. Technical failures retain
  their diagnostic details.
- `no_objection` is the hook decision, while **Passed** is the test result.
  A test expecting a block passes when the hook correctly blocks.
- Each run replaces the report. Add `--html=reports\another-run.html` to keep
  a separate report.
- The report follows the browser's light/dark preference. Add
  `&scoutTheme=dark` or `&scoutTheme=light` when the address already has a query
  string, or `?scoutTheme=dark` when it does not.
- Review inputs and captured output before sharing. Do not put credentials or
  sensitive operational data into catalogues.

Reports, caches, and the local Python environment are ignored by Git.
No automated GitHub Actions workflow is currently included.

## Add a hook or a scenario

### Add a hook

1. Put the reviewed Python script in `hooks/<name>/hook.py`.
2. Create `tests/hooks/<name>/cases.yaml`, using the example below.
3. Give the suite a unique ID and describe the behaviour to test.
4. Run pytest and review the report.

The framework discovers every `cases.yaml` beneath `tests/hooks/`.
No change to the shared runner is needed. Every catalogue uses the shared
[schema](./framework/schemas/cases.schema.json).

```yaml
schema_version: 2
suite:
  id: required-field
  description: Require an explanation before an action.
  hook: hooks/required_field/hook.py
  protocol: sre-agent
  timeout_seconds: 3

cases:
  - id: purpose-provided
    description: An action with a clear purpose raises no objection.
    input:
      purpose: Investigate a service alert
    expected:
      outcome: no_objection
  - id: purpose-missing
    description: An action without a purpose must be blocked.
    input: {}
    expected:
      outcome: block
```

Hook paths must identify existing `.py` files **relative to the repository
root**, not the catalogue directory, and cannot point outside the repository.
The runner uses the same Python interpreter as pytest and runs each hook in
the hook's own directory, so adjacent files can be read using relative paths.
The timeout must be a positive number of seconds.

### Add or change a scenario

Add a case to the appropriate catalogue. Each needs a unique `id` within
that suite, a plain-language `description`, an `input` JSON value, and an
`expected.outcome` of `no_objection` or `block`.

Choose the expectation from the agreed requirement, not simply whatever the
hook currently does. Include both inputs that should proceed and inputs that
should be rejected where applicable. A crash or timeout cannot satisfy an
expected block.

Optional `findings` and `criteria` lists can document issues and requirements.
Each finding has an `id` and `description`; each criterion has an `id`,
`requirement`, and `source`. Reference them with `finding` and `criterion` on
individual cases. IDs need not follow the SQL suite's F01-F07 naming.
Missing fields, duplicate IDs, unknown references, unsupported protocols,
and invalid hook paths stop collection with an error.

For generated checks or specialised assertions, add Python tests beneath
`tests/hooks/<name>/` and mark the module with
`pytestmark = pytest.mark.suite("your-suite-id")` so `--suite` selects it
correctly. The [SQL property tests](./tests/hooks/sql_guard/test_properties.py)
show how to call the runner with an explicit hook path.

## Supported hooks

The initial supported protocol, named `sre-agent`, is for standalone Python
scripts that read one JSON value from standard input. Input is limited to
64 KiB. Responses must be UTF-8.

| Hook response | Interpretation |
|---|---|
| Exit code 0, no output | No objection. |
| Exit code 0, `{"ok": true}` | No objection. |
| Exit code 0, `{"decision": "block", "reason": "..."}` or `{"ok": false, "reason": "..."}` | Block, with a nonblank explanation. |
| Exit code 0, `{"hookSpecificOutput": {"permissionDecision": "deny"}, "reason": "..."}` | Block, with a nonblank explanation. |
| Exit code 2 with nonblank standard error | Block, using standard error as the explanation. |
| Crash, timeout, malformed output, conflicting decisions, or an unsupported decision | Error, not a block. |

Explicit `allow` and `ask` responses are not currently supported. This is a
deliberately limited local testing contract, not support for every hook event
or every vendor's response format. Function-based hooks, command-line argument
interfaces, and other response protocols would need an explicit extension.

Execution and response interpretation are separate in the
[runner](./framework/runner.py). This allows another response protocol to be
added later without embedding business rules in the process runner.

**This is not a sandbox.** The runner executes the hook's Python code with
the current user's permissions and inherited environment. The framework does
not execute command strings from catalogues itself, but a hook could perform
real actions. Only run trusted, reviewed hooks. Use a disposable isolated
environment for hooks with side effects or external dependencies.

## Repository layout and tools

```text
framework/
  runner.py                 Process execution and response interpretation
  catalogue.py              Catalogue validation and suite discovery
  schemas/cases.schema.json Shared catalogue format
hooks/
  sql_guard/hook.py         Existing SQL-specific hook
  required_field/hook.py    Independent teaching example
tests/
  framework/                Tests of the shared testing machinery
  hooks/
    sql_guard/              SQL catalogue and generated checks
    required_field/         Example catalogue
  test_scenarios.py         Shared scenario assertions
  conftest.py               Suite selection and report customisation
  assets/                  Report styling
images/                     README screenshots
reports/                    Generated reports (not committed)
```

[pytest](https://docs.pytest.org/) runs the tests;
[Hypothesis](https://hypothesis.readthedocs.io/) generates variations for
specialised tests; [PyYAML](https://pyyaml.org/) and
[JSON Schema](https://json-schema.org/) load and validate the catalogues.
[pytest-html](https://pytest-html.readthedocs.io/) produces the report.
Dependencies are listed in [requirements-test.txt](./requirements-test.txt).

[Bandit](https://bandit.readthedocs.io/) is available as a separate source-code
check. Its results are not included in the behaviour report:

```powershell
.venv\Scripts\python.exe -m bandit -r hooks framework -f json -o reports\bandit.json
```

### Migration from the original single-hook layout

The original hook and catalogue moved into the `sql_guard` suite. Their
operational rules and expected decisions have not been weakened to remove
failures. Catalogue version 1 is replaced by version 2: add the `suite`
section, use `expected: {outcome: no_objection}` instead of `expected: pass`,
and `expected: {outcome: block}` instead of `expected: block`.
Callers of `run_hook` must now supply the hook path explicitly.

## Further reading

- [Azure SRE Agent hooks](https://sre.azure.com/docs/capabilities/agent-hooks)
- [Azure hook data contract](https://sre.azure.com/docs/reference/hook-data-contract)
- [OWASP Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)
- [OWASP Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)
