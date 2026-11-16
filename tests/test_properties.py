from hypothesis import given, settings, strategies as st

from runner import run_hook


@settings(max_examples=20, deadline=None, derandomize=True)
@given(spid=st.sampled_from([0, 1, 50, 51, 32767, 32768, 99999]),
       subscription=st.sampled_from(["production", "76a256fd-59fd-473a-9214-04eaddbcd56e"]))
def test_kill_boundaries(spid, subscription):
    command = (
        f"az vm run-command invoke --subscription {subscription} "
        f"""--scripts 'sqlcmd -Q "KILL {spid}"'"""
    )
    result = run_hook({"tool_input": {"command": command}})
    permitted = subscription != "production" and 51 <= spid <= 32767
    assert result.outcome == ("pass" if permitted else "block"), result.detail


@settings(max_examples=12, deadline=None, derandomize=True)
@given(prefix=st.sampled_from(["SELECT 1", "SET NOCOUNT ON", "EXEC dbo.usp_detectblocking"]),
       separator=st.sampled_from([" ", "\n", "; "]))
def test_appending_write_rejects(prefix, separator):
    query = prefix + separator + "DROP TABLE dbo.GuardReviewProbe"
    command = (
        "az vm run-command invoke --subscription production "
        f"""--scripts 'sqlcmd -Q "{query}"'"""
    )
    result = run_hook({"tool_input": {"command": command}})
    assert result.outcome == "block", result.detail


@settings(max_examples=12, deadline=None, derandomize=True)
@given(value=st.one_of(st.none(), st.booleans(), st.integers(), st.dictionaries(
    st.sampled_from(["command", "parameters"]), st.integers(), max_size=2
)))
def test_invalid_execution_command_type_rejects(value):
    result = run_hook({"tool_name": "RunInTerminal", "tool_input": {"command": value}})
    assert result.outcome == "block", f"F07: {result.detail}"
