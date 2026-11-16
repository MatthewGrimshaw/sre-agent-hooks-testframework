
#!/usr/bin/env python3
"""PreToolUse guard.

Regex-inspects every az CLI command. `az vm/vmss run-command` is permitted only
when it invokes sqlcmd AND every statement in the sqlcmd query is read-only:
  - SELECT
  - allowlisted read-only stored procedures
  - inert preludes (SET NOCOUNT ON, USE <db>)

One narrow exception exists for remediation: a *single* session kill, expressed
only as a bare `KILL <spid>`. Kills go through plain SQL, never through a stored
procedure - a proc's body is invisible to this guard, so allowlisting one would
mean trusting an unreviewable payload. A kill batch may contain nothing else
besides inert preludes, must target a user session (spid > 50), and must contain
no string literals. Everything else is blocked. Non-az / non-run-command commands
are not governed.

The subscription must also be named explicitly on the command line, and it
determines what is allowed there:

  - read-only SQL  -> permitted in ANY subscription
  - KILL <spid>    -> permitted ONLY in the non-production subscription

`az account set` mutates an ambient context this guard cannot observe, so a
command without `--subscription` could silently be running against production.
Such a command is blocked rather than guessed at.
"""
import sys, json, re

# Stored procedures that are known read-only and may be EXEC'd.
ALLOWED_PROCS = {
    "maerskops.dbo.usp_detectblocking",
    "dbo.usp_detectblocking",
    "usp_detectblocking",
}

# Session ids 1-50 are reserved for SQL Server's own internal sessions; killing
# one is never a legitimate blocking remediation.
MIN_KILLABLE_SPID = 51
MAX_SPID = 32767

# The only subscription in which a session may be killed. Reads are allowed
# anywhere; terminating a session is confined to non-production. Both the
# display name and the id are accepted, since either may appear on the CLI.
NONPROD_SUB_DISPLAY = "MyAzureSubscriptionName"
NONPROD_SUB_ID = "XXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXX"
NONPROD_SUB_ALIASES = {NONPROD_SUB_DISPLAY.lower(), NONPROD_SUB_ID.lower()}

def block(reason):
    print(json.dumps({"decision": "block", "reason": reason}))
    sys.exit(0)

def no_opinion():
    # exit 0, no output -> no objection; deny policy still applies underneath
    sys.exit(0)

try:
    ctx = json.load(sys.stdin)
except Exception:
    block("run-command guard: unreadable hook context (failing closed).")

ti = ctx.get("tool_input") or {}
parts = []
if isinstance(ti, dict):
    for k in ("command", "code", "script", "scripts", "args", "commandLine", "input"):
        v = ti.get(k)
        if isinstance(v, str):
            parts.append(v)
        elif isinstance(v, (list, tuple)):
            parts.extend(str(x) for x in v)
else:
    parts.append(str(ti))
cmd = " ".join(parts).strip()

if not cmd:
    no_opinion()

norm = re.sub(r"\s+", " ", cmd)
low = norm.lower()

# ---- Scope: only govern az vm/vmss run-command -----------------------------
if not re.search(r"\baz\s+(vm|vmss)\s+run-command\b", low):
    no_opinion()

if not re.search(r"\baz\s+(vm|vmss)\s+run-command\s+invoke\b", low):
    block("run-command guard: only 'az vm run-command invoke' is permitted "
          "(create/update/delete/show/list are blocked).")

# ---- Extract the --scripts payload ----------------------------------------
m = re.search(r"--scripts?\s+(\"(?P<dq>(?:\\.|[^\"\\])*)\"|'(?P<sq>(?:\\.|[^'\\])*)'|(?P<bare>\S+))", cmd)
if not m:
    block("run-command guard: could not parse the --scripts payload; blocked for safety.")
payload = m.group("dq") or m.group("sq") or m.group("bare") or ""
payload = payload.replace('\\"', '"').replace("\\'", "'")

# ---- The target subscription must be explicit -----------------------------
# Searched with the --scripts span removed, so a `--subscription` smuggled into
# the SQL text cannot be mistaken for the real CLI argument.
az_args = cmd[:m.start()] + " " + cmd[m.end():]
sub_m = re.search(
    r"--subscription[=\s]+(\"(?P<dq>[^\"]*)\"|'(?P<sq>[^']*)'|(?P<bare>[^\s\"']+))",
    az_args)
if not sub_m:
    block("run-command guard: no --subscription on the command line. The target "
          "subscription must be named explicitly (name or id) - an ambient "
          "context set by 'az account set' is invisible to this guard and could "
          "be production.")
subscription = (sub_m.group("dq") or sub_m.group("sq")
                or sub_m.group("bare") or "").strip()
if not subscription:
    block("run-command guard: --subscription was supplied but empty.")
is_nonprod = subscription.lower() in NONPROD_SUB_ALIASES

# ---- Payload must be exactly a sqlcmd invocation ---------------------------
if not re.match(r"^\s*sqlcmd\b", payload, re.IGNORECASE):
    block("run-command guard: payload must start with sqlcmd. "
          "az vm run-command is restricted to read-only SQL via sqlcmd.")

# No shell/PowerShell escapes anywhere in the payload.
for pat, label in [
    (r"&&", "command chaining '&&'"),
    (r"\|\|", "command chaining '||'"),
    (r"\|", "pipe"),
    (r"\$\(", "subexpression '$('"),
    (r"`", "backtick"),
    (r"\bstart-process\b|\binvoke-expression\b|\biex\b|\bnew-object\b", "PowerShell execution cmdlet"),
    (r"\binvoke-webrequest\b|\bdownloadstring\b|\bdownloadfile\b|\bcurl\b|\bwget\b", "network fetch"),
    (r"\bcmd(\.exe)?\s*/c\b|\bpowershell(\.exe)?\s+-", "nested shell"),
    (r"\bremove-item\b|\bstop-service\b|\bstop-computer\b|\brestart-computer\b", "host/service control"),
    (r"-o\s|\s-i\s", "sqlcmd file input/output redirection"),
]:
    if re.search(pat, payload, re.IGNORECASE):
        block("run-command guard: payload contains a non-SQL operation ({}). Blocked.".format(label))

# ---- Extract the SQL query given to sqlcmd (-Q/-q) -------------------------
q = re.search(r"\s-[Qq]\s+(\"(?P<dq>(?:\\.|[^\"\\])*)\"|'(?P<sq>(?:\\.|[^'\\])*)'|(?P<bare>.+)$)", payload)
if not q:
    block("run-command guard: sqlcmd must supply its SQL inline via -Q; no query found.")
query = (q.group("dq") or q.group("sq") or q.group("bare") or "").strip()
query = query.replace('\\"', '"').replace("\\'", "'")
if not query:
    block("run-command guard: empty sqlcmd query.")

# ---- Every statement must be read-only ------------------------------------
# Strip string literals so keywords inside data can't trigger, then split on ';'
stripped = re.sub(r"'(?:''|[^'])*'", "''", query)
statements = [s.strip() for s in stripped.split(";") if s.strip()]
if not statements:
    block("run-command guard: no SQL statement found in the sqlcmd query.")

INERT = re.compile(r"^set\s+(nocount|transaction\s+isolation\s+level|deadlock_priority|lock_timeout)\b", re.I)
USE_DB = re.compile(r"^use\s+[\w\[\]\.]+$", re.I)
SELECT = re.compile(r"^(with\b.*\bselect\b|select\b)", re.I | re.S)
EXEC = re.compile(r"^exec(ute)?\s+(?P<proc>[\w\[\]\.]+)", re.I)
KILL = re.compile(r"^kill\s+(?P<spid>\d{1,5})$", re.I)

# Kill procedures are deliberately NOT allowlisted: the guard can read a KILL
# statement and bound its target, but it cannot see inside a procedure body.
KILL_PROC = re.compile(r"kill", re.I)


def check_spid(raw):
    try:
        spid = int(raw)
    except ValueError:
        block("run-command guard: KILL target must be an integer session id.")
    if spid < MIN_KILLABLE_SPID or spid > MAX_SPID:
        block("run-command guard: KILL target session {} is out of the permitted range "
              "{}-{}. Sessions 1-{} are SQL Server internals and may not be killed."
              .format(spid, MIN_KILLABLE_SPID, MAX_SPID, MIN_KILLABLE_SPID - 1))
    return spid


kill_statements = 0
non_kill_statements = 0

for st in statements:
    if INERT.match(st) or USE_DB.match(st):
        continue

    # ---- Remediation: a single, bounded session kill in plain SQL ----------
    km = KILL.match(st)
    if km:
        check_spid(km.group("spid"))
        kill_statements += 1
        continue

    em = EXEC.match(st)
    if em:
        proc = em.group("proc").replace("[", "").replace("]", "").lower()
        if proc in ALLOWED_PROCS:
            non_kill_statements += 1
            continue
        if KILL_PROC.search(proc):
            block("run-command guard: kills must be issued as plain SQL (KILL <spid>), "
                  "not through a stored procedure - the guard cannot inspect a procedure "
                  "body, so '{}' is blocked.".format(em.group("proc")))
        block("run-command guard: stored procedure '{}' is not on the read-only allowlist. "
              "Permitted: {}.".format(em.group("proc"), ", ".join(sorted(ALLOWED_PROCS))))

    if SELECT.match(st):
        # A SELECT must not smuggle writes (e.g. SELECT ... INTO, FOR XML + exec)
        if re.search(r"\binto\s+[\w\[\]#\.]+", st, re.I):
            block("run-command guard: 'SELECT ... INTO' writes data and is not permitted.")
        non_kill_statements += 1
        continue

    verb = st.split()[0].upper() if st.split() else "?"
    block("run-command guard: only read-only SQL (SELECT or an allowlisted read-only "
          "stored procedure) or a single bounded KILL is permitted. Statement "
          "starting with '{}' was blocked.".format(verb))

# ---- Kill batches are deliberately minimal --------------------------------
if kill_statements:
    if not is_nonprod:
        block("run-command guard: KILL is permitted only in the non-production "
              "subscription ('{}' / {}); this command targets '{}'. Read-only "
              "queries are permitted in any subscription."
              .format(NONPROD_SUB_DISPLAY, NONPROD_SUB_ID, subscription))
    if kill_statements > 1:
        block("run-command guard: at most one session kill per command; this batch "
              "contains {}. Issue them one at a time.".format(kill_statements))
    if non_kill_statements:
        block("run-command guard: a kill must be sent on its own. Diagnostics and a "
              "kill may not share one command - run the query first, then the kill.")
    if "'" in query:
        block("run-command guard: a kill command may not contain string literals.")

no_opinion()