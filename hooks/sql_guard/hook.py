
#!/usr/bin/env python3
"""PreToolUse guard.

The hook context must be a JSON object; other JSON values are blocked.
Only recognised execution fields and a single quoted inline SQL query are
accepted. Unsupported shell syntax, SQL comments and SQLCMD directives fail
closed. KILL retains the legacy subscription-only policy: subscription approval
does not establish the identity of the SQL server. Explicit SQL server overrides
are blocked for KILL until destination authorisation is configured. Read-query
checks conservatively reject modifying keywords even when used as identifiers.

Regex-inspects every az CLI command. `az vm/vmss run-command` is permitted only
when it invokes sqlcmd AND every statement in the sqlcmd query is read-only:
  - SELECT
  - allowlisted read-only stored procedures (bare calls without arguments)
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
  - KILL <spid>    -> permitted ONLY in a subscription in ALLOWED_SUBSCRIPTIONS,
                     whether production or non-production

`az account set` mutates an ambient context this guard cannot observe, so a
command without `--subscription` could silently be running against production.
Such a command is blocked rather than guessed at.
"""
import sys, json, re, shlex

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

# Add approved production AND non-production subscription names or IDs below.
# To approve more than one subscription, add one quoted name or ID per line,
# followed by a comma, inside this list. Matching is case-insensitive.
# Listing a production subscription permits bounded KILL commands there too.
# Example additional entries (uncomment and replace with your actual values):
#     "MyProductionSubscription",
#     "another-approved-subscription-id",
# Each command must still specify exactly one --subscription.
ALLOWED_SUBSCRIPTIONS = [
    "MyAzureSubscriptionName",
    "76a256fd-59fd-473a-9214-04eaddbcd56e",
]
ALLOWED_SUB_ALIASES = {subscription.lower() for subscription in ALLOWED_SUBSCRIPTIONS}

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

if not isinstance(ctx, dict):
    block("run-command guard: hook context must be a JSON object (failing closed).")

if ctx.get("tool_name") in {"ReadFile", "ListDirectory", "SearchFiles"}:
    no_opinion()

ti = ctx.get("tool_input")
if not isinstance(ti, dict) or not ti:
    block("run-command guard: execution input must be a nonempty object.")
parts = []
for k in ("command", "code", "script", "scripts", "args", "commandLine", "input"):
    if k not in ti:
        continue
    v = ti[k]
    if isinstance(v, str) and v.strip():
        parts.append(v)
    elif isinstance(v, list) and v and all(isinstance(x, str) and x.strip() for x in v):
        parts.extend(v)
    else:
        block("run-command guard: execution fields must contain nonempty strings.")
cmd = " ".join(parts).strip()

if not cmd:
    block("run-command guard: no recognised execution command was supplied.")

norm = re.sub(r"\s+", " ", cmd)
low = norm.lower()

# ---- Scope: only govern az vm/vmss run-command -----------------------------
if not re.search(r"\baz[\"']?\s+(?:--[\w-]+(?:[=\s]+\S+)?\s+)*(vm|vmss)\s+run-command\b", low):
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
if not re.match(r"^\s*az\s+(vm|vmss)\s+run-command\s+invoke\b", az_args, re.I):
    block("run-command guard: unsupported Azure command form or shell prefix.")
try:
    outer_tokens = shlex.split(az_args)
except ValueError:
    block("run-command guard: malformed Azure command quoting.")
valued_options = {
    "--subscription", "--resource-group", "-g", "--name", "-n",
    "--command-id", "--instance-id", "--ids",
}
switch_options = {"--only-show-errors", "--debug", "--verbose"}
i = 4
seen_options = set()
while i < len(outer_tokens):
    option, sep, value = outer_tokens[i].partition("=")
    if option in seen_options:
        block("run-command guard: duplicate Azure argument.")
    seen_options.add(option)
    if option in switch_options and not sep:
        i += 1
        continue
    if option not in valued_options:
        block("run-command guard: unsupported Azure argument or additional shell operation.")
    if not sep:
        i += 1
        value = outer_tokens[i] if i < len(outer_tokens) else ""
    if not value or value.startswith("-") or re.search(r"[;|&<>`$\r\n]", value):
        block("run-command guard: invalid Azure argument value.")
    i += 1
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
is_approved_subscription = subscription.lower() in ALLOWED_SUB_ALIASES

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
if q.group("bare") is not None or payload[q.end():].strip():
    block("run-command guard: exactly one quoted query is required, with no trailing operations.")
try:
    sqlcmd_tokens = shlex.split(payload[:q.start()])
except ValueError:
    block("run-command guard: malformed sqlcmd arguments.")
i = 1
seen_sqlcmd_options = set()
while i < len(sqlcmd_tokens):
    option = sqlcmd_tokens[i]
    if option in seen_sqlcmd_options:
        block("run-command guard: duplicate sqlcmd argument.")
    seen_sqlcmd_options.add(option)
    if option in {"-E", "-C", "-b"}:
        i += 1
        continue
    if option not in {"-S", "-d", "-U", "-P", "-l", "-t"} or i + 1 >= len(sqlcmd_tokens):
        block("run-command guard: unsupported sqlcmd argument.")
    if re.search(r"[;|&<>`$\r\n]", sqlcmd_tokens[i + 1]):
        block("run-command guard: invalid sqlcmd argument value.")
    i += 2

# ---- Every statement must be read-only ------------------------------------
# Strip string literals so keywords inside data can't trigger, then split on ';'
stripped = re.sub(r"'(?:''|[^'])*'", "''", query)
if re.search(r"--|/\*|\*/|!!|(?m:^\s*:)|\$\(", stripped):
    block("run-command guard: SQL comments and SQLCMD directives are not supported.")
if "'" in stripped.replace("''", "") or '"' in stripped:
    block("run-command guard: unsupported SQL quoting.")
statements = [s.strip() for s in stripped.split(";") if s.strip()]
if not statements:
    block("run-command guard: no SQL statement found in the sqlcmd query.")

INERT = re.compile(
    r"set\s+(?:nocount\s+(?:on|off)|transaction\s+isolation\s+level\s+"
    r"(?:read\s+uncommitted|read\s+committed|repeatable\s+read|snapshot|serializable)"
    r"|deadlock_priority\s+(?:low|normal|high|-?\d+)|lock_timeout\s+-?\d+)", re.I)
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
    if INERT.fullmatch(st) or USE_DB.fullmatch(st):
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
            if not EXEC.fullmatch(st):
                block("run-command guard: an allowlisted procedure call must contain "
                      "only EXEC and the procedure name; arguments and trailing SQL "
                      "are not permitted.")
            non_kill_statements += 1
            continue
        if KILL_PROC.search(proc):
            block("run-command guard: kills must be issued as plain SQL (KILL <spid>), "
                  "not through a stored procedure - the guard cannot inspect a procedure "
                  "body, so '{}' is blocked.".format(em.group("proc")))
        block("run-command guard: stored procedure '{}' is not on the read-only allowlist. "
              "Permitted: {}.".format(em.group("proc"), ", ".join(sorted(ALLOWED_PROCS))))

    if SELECT.match(st):
        if re.search(
            r"\b(?:insert|update|delete|merge|drop|alter|create|truncate|exec|execute|"
            r"grant|deny|revoke|kill|backup|restore|dbcc|bulk|reconfigure|shutdown|"
            r"set|use|openrowset|opendatasource|openquery)\b", st, re.I
        ):
            block("run-command guard: modifying or unsupported SQL within a read query.")
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
    if "-S" in seen_sqlcmd_options:
        block("run-command guard: KILL with an explicit SQL server is not permitted; "
              "no approved SQL destination has been configured.")
    if not is_approved_subscription:
        block("run-command guard: KILL is permitted only in an approved "
              "subscription ({}); this command targets '{}'. Read-only "
              "queries are permitted in any subscription."
              .format(", ".join(ALLOWED_SUBSCRIPTIONS), subscription))
    if kill_statements > 1:
        block("run-command guard: at most one session kill per command; this batch "
              "contains {}. Issue them one at a time.".format(kill_statements))
    if non_kill_statements:
        block("run-command guard: a kill must be sent on its own. Diagnostics and a "
              "kill may not share one command - run the query first, then the kill.")
    if "'" in query:
        block("run-command guard: a kill command may not contain string literals.")

no_opinion()