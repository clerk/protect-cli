# clerk-protect

> [!IMPORTANT]
> **Early access only.** `clerk-protect` is for customers in the Clerk Protect early-access program. It signs in
> through Protect Labs, which Clerk turns on instance by instance for those customers, so without early access
> there is no way to sign in. Commands, flags and output can change between releases. Questions go to your shared
> Slack channel with Clerk.
>
> Looking for the Clerk CLI that adds Clerk to an app? That is [`clerk`](https://github.com/clerk/cli).

Manage Clerk Protect for your instance from the command line: custom rules, protections, investigations,
live decisions and replays.

## Install

### Homebrew

```bash
brew tap clerk/protect-cli https://github.com/clerk/protect-cli
brew install --cask clerk/protect-cli/clerk-protect       # macOS
brew install --formula clerk/protect-cli/clerk-protect    # Linux
```

Use the full name, `clerk/protect-cli/clerk-protect`. Recent Homebrew refuses to load anything from a tap
outside Homebrew's own until you name it or trust it, and stops with "Refusing to load … from untrusted tap"
otherwise; naming it is what trusts it. On Linux, the full name with `--formula` also keeps Homebrew from
trying the macOS cask first.

On macOS the cask installs a package signed with Clerk's Developer ID and notarized by Apple, and puts
`clerk-protect` in `/usr/local/bin`, so the installer asks for your administrator password. `brew upgrade`
updates either.

### A release download

From [the releases page](https://github.com/clerk/protect-cli/releases):

- **macOS:** the signed, notarized `.pkg` for your Mac (`arm64` for Apple silicon, `amd64` for Intel).
- **Linux and Windows:** the archive for your platform. Check it against `checksums.txt`, then put
  `clerk-protect` on your `PATH`.

### With Go, on Linux and Windows

```bash
go install github.com/clerk/protect-cli/cmd/clerk-protect@latest
```

Not on macOS: there the device key lives in the Secure Enclave, which needs a Swift shim that `go install` cannot
compile. Use Homebrew, a release archive, or `make install` below.

### From source

Requires Go 1.26 or newer. On macOS, the Xcode Command Line Tools (for `swiftc`).

```bash
git clone https://github.com/clerk/protect-cli
cd protect-cli
make install            # builds, checks and installs clerk-protect onto your PATH
```

Use `make` rather than a bare `go build`. On a Mac the Secure Enclave support is written in Swift and has to be
compiled first, and on every platform `make` builds the release way (no debug information, no build paths) and
checks the binary before installing it.

## Sign in

```bash
clerk-protect login
```

`login` opens Protect Labs in your browser and asks you to approve this computer.

1. If you are not signed in to Protect Labs, open it from the Clerk Dashboard for the instance you want to
   use: choose the application and instance, then **Configure → Protect → Labs → Open Labs**. Do it in the
   browser `login` opened, because that is where the waiting approval is kept. The page keeps it for ten
   minutes and your terminal waits about as long, but the two clocks are separate: if you approve after the
   terminal has given up, the approval goes nowhere, and you run `clerk-protect login` again.
2. Check that the key fingerprint on the page matches the one printed in your terminal.
3. Approve. Your terminal finishes signing in.

The browser has to be on this computer: the approval is handed back to `clerk-protect` on this computer's own
network address (`127.0.0.1`). If the page opened in a browser you don't use for the Clerk Dashboard, paste
the address `login` printed into the one you do (`--no-browser` prints it without opening anything).

No Labs under Protect in the Dashboard? Protect Labs is in early access; ask your Clerk contact to turn it on
for that instance.

You get the permissions you have in Protect Labs for that instance, and no more. The server requests access for the
time remaining in that Labs session, up to eight hours from when you opened it. A token can end earlier;
`clerk-protect whoami` shows both the token expiry and authorization deadline. The approval page and terminal
show when the authorization ends. If that is soon, open Labs fresh from the Clerk Dashboard before approving.
After the authorization ends, run `clerk-protect login` again. A shorter-lived token renews automatically
while it is still valid; if it expires while this computer is idle, sign in again.
Signing in again always needs a person at a browser, so a sign-in does not yet suit CI or an agent that runs
unattended for longer than that.

To work with more than one instance, sign in to each. A command acts on the first of: `--instance ins_…`; the
instance of the selected profile; the instance you signed in to last.

### Profiles

A profile names an instance, and optionally an API URL, so you do not repeat `--instance`:

```bash
clerk-protect profile set work                    # right after signing in: saves that instance
clerk-protect profile set staging --instance ins_…
clerk-protect profile use work                    # the default from now on
clerk-protect --profile staging rules list        # or CLERK_PROTECT_PROFILE=staging
clerk-protect profile show                        # what commands would act on, and why
```

A profile is not a sign-in. When a profile names an instance this computer has not signed in to, commands with
it fail and ask you to sign in; they never act on another instance instead. `login` signs in to the instance you
approve in the browser, and says so when that is not the profile's instance.

`clerk-protect logout` removes the stored sign-in for the current instance; it changes only this computer and
does not ask. `clerk-protect logout --all` removes every sign-in and deletes this computer's key, and asks first.

## Where your key lives

Every request is signed by a key created on this computer. Your stored sign-in cannot be used without it, so
where the key lives is what protects your access.

| Platform | Where the key lives | Can it be copied off the computer? |
|---|---|---|
| macOS (Apple silicon, or Intel with a T2 chip) | Secure Enclave | No |
| Windows with a TPM 2.0 | TPM | No |
| Windows without a TPM | Windows key storage, marked non-exportable | Not through Windows; protected by your Windows account rather than by hardware |
| Linux and other platforms | Not supported by default. `CLERK_PROTECT_KEY_BACKEND=file` stores it in a file (not available on Windows) | **Yes** — anyone who can read the file can use your access |

`clerk-protect keys status` shows which one you have.

On Linux, every command reads `CLERK_PROTECT_KEY_BACKEND` to find the key, not only `login`, so set it in your
shell profile (`export CLERK_PROTECT_KEY_BACKEND=file`) rather than on one command.

On a Mac the key signs without prompting while you are logged in. To require Touch ID (or your password) once
per command, create the key with `CLERK_PROTECT_KEY_PROTECTION=presence` before your first `login` — or run
`clerk-protect logout --all` and log in again with it set.

## Commands

| Command | What it does |
|---|---|
| `login`, `logout`, `whoami` | Sign in, sign out, and show who you are and what you may do |
| `keys status` | Where this computer's key lives |
| `keys list` | The computers signed in as you, with each key's fingerprint and when its sign-in ends. `*` marks this one |
| `profile list\|show\|set\|use\|delete` | Name the instance, and API URL, commands use by default — see [Profiles](#profiles) |
| `rulesets list` | The rulesets rules can be written into |
| `rules list [--ruleset R]` | Rules in evaluation order |
| `rules get ID --ruleset R` | One rule |
| `rules create --ruleset R --expression E --action block\|challenge` | Create a rule. Also `--description`, `--rate-limit-*`, `--challenge-*`, `--expires-at`/`--expires-in`, or `--file rule.json` |
| `rules update ID --ruleset R [flags]` | Change only what the flags name; `--file` replaces the whole rule |
| `rules enable\|disable ID --ruleset R` | Turn a rule on or off without deleting it |
| `rules delete ID --ruleset R` | Delete a rule |
| `rules reorder --ruleset R --move ID --top\|--bottom\|--to N\|--before ID\|--after ID` | Change evaluation order (or give every id in order); `--dry-run` to preview |
| `rules validate --ruleset R 'expression'` | Ask whether a rule is valid, without creating it. Exits 1 when it is not |
| `schema [event-type]`, `fields` | The fields rules can use |
| `protections list`, `protections show NAME` | Protections and their settings on this instance |
| `protections enable NAME [--bind name=expr]` | Turn a protection on. Existing settings are kept unless you change them |
| `protections bindings NAME --bind name=expr [--unbind name]` | Change a protection's settings |
| `protections disable NAME`, `protections reset NAME` | Turn off (keeping settings), or remove and discard settings |
| `tables list`, `tables get NAME` | The lookup tables your rules read with `in_table`, and a table's columns |
| `tables create NAME --column NAME:TYPE[:matchable][:required]` | Create a table. Types: STRING, INTEGER, IP, DOMAIN, ASN |
| `tables update NAME [--description] [--add-column\|--update-column SPEC] [--remove-column C] [--rename-column OLD=NEW]` | Change a table's description or columns |
| `tables delete NAME` | Delete a table and its rows. A rule that reads it then matches nothing |
| `tables rows list\|get TABLE [ID]` | A table's rows |
| `tables rows search TABLE --match COL=VALUE` | The live rows a rule would match for a value (a CIDR row for an IP inside it) |
| `tables rows search TABLE --contains TEXT` | Rows whose id, values or note contain some text |
| `tables rows add TABLE [--id ID] --value COL=V --matcher COL=KIND:V` | Add a row. Matchers: WILDCARD, REGEX, PREFIX, SUFFIX, RANGE, CIDR, SET. Or `--from-json FILE` |
| `tables rows update TABLE ID ...` | Change some columns and keep the rest; `--clear COL` empties one |
| `tables rows set TABLE ID ...` | Replace a row's values with exactly those given |
| `tables rows delete TABLE ID` | Delete a row |
| `insights dimensions\|facets\|timeseries\|search\|events` | Investigate decisions. `--since`, `--from`/`--to`, `--filter dim=v1,v2`, `--exclude`, `--expression`, or `--query`/`--file` with a JSON body |
| `insights fields` | Expression fields and compatible rule-path aliases, including fields that are not facet dimensions |
| `insights entity --dimension D --value V` | Profile one value of one dimension over the window |
| `insights flow --decision-id ID --at TIME` | Every decision in the flow one decision belonged to |
| `insights validate-filter 'expression'` | Check a filter expression |
| `investigate "question"` | Ask about this instance's decisions in plain language; see [Asking questions](#asking-questions-in-plain-language) |
| `investigate schema` | The tables and columns you can ask about |
| `trace [--filter field=value] [--columns a,b]` | Stream decisions live. In a terminal, an interactive view: pause and scroll back, open a decision, filter, choose columns (`?` for the keys). Piped, or with `--json` or `--no-tui`, one line per decision. Filters: `field=value`, `field!=value` and `field~text` ignore case; `field==value` is exact |
| `console open [--path /rules] [--no-sign-in] [--no-browser]` | Open Protect Labs in your browser, signed in as this computer's sign-in for the selected instance. The browser session ends when this computer's sign-in would, and cannot approve another computer's sign-in. `--no-browser` prints the address without signing in |
| `matches [--protection P] [--rule-id R] [--since 7d]` | How often protections or rules matched, as sparklines |
| `replay create --file change.json [--watch]` | Score a candidate change against recent traffic |
| `replay list\|get\|watch\|export\|apply` | Follow, inspect, download and apply replays |

Every command accepts `--json` for machine-readable output.

In a terminal, output is in colour. `--color auto|always|never` chooses (`auto`, the default, colours only a terminal), and `NO_COLOR` or `TERM=dumb` turn it off. `--json` output is never coloured, and neither is anything piped unless you ask with `--color always`.

## Searching decisions

`insights search --limit 1000` follows pages and returns up to 1,000 rows in one JSON response.
The default is 100 rows; each request asks for at most 500. The response's `next_cursor` continues
after the last returned row, and its `window` holds the absolute `from` and `to` that were searched,
even when the search started from `--since`. Continue with `--cursor` plus that window's `--from`
and `--to` and the same filters; when rows remain, the exact flags are also printed to stderr.
Rerunning `--since` later would start the window later and skip its oldest rows. A failed page prints no partial result. Buffered server responses must total less than
64 MiB; use smaller limits and continue with the cursor for larger exports. Formatting can make
the printed JSON larger.

`--filter` uses dimension names from `insights dimensions`. `--expression` accepts column names
and compatible rule paths: `asn_type == "hosting"` and `ip.asn.type == "hosting"` ask the same
question. `insights fields` lists those aliases when the server publishes them. A field whose
historical values differ from its rule values has no alias; check `schema` before turning a
historical filter into a rule. A field such as `flow_id` can be filtered even though it is not a
facet dimension.

```bash
clerk-protect insights fields
clerk-protect insights search --since 24h --limit 1000 \
  --expression 'ip.asn.type == "hosting"'
clerk-protect insights search --since 24h --flow-id sua_example
```

`--flow-id` also works on `insights facets` and `insights timeseries`, and combines with
`--expression` and `--filter`. It selects decisions belonging to that sign-in or sign-up;
it requires the decisions unit. Insights decisions currently have 14 days of retained history.
Increasing the search limit or window cannot recover decisions outside that history.

## Asking questions in plain language

`investigate` takes a question about this instance's decisions in plain language, works out the query,
checks it, runs it against **this instance's decisions only**, and streams the result back:

```bash
clerk-protect investigate schema                       # what you can ask about
clerk-protect investigate \
  --purpose "find what drove yesterday's blocked sign-ups" \
  --shape "one row per country with the blocked count, top 10" \
  "Which countries had the most blocked sign-ups yesterday?"
```

- **Be specific:** a time window, the flow (sign-in, sign-up, ...), the outcome, the grouping, and "top N".
- **Output:** progress, the query and a short summary go to stderr; the rows go to stdout as a table, or as
  `--format csv` (cells a spreadsheet would read as formulas are defused) or `--format json` (one JSON array
  per row). `--json` prints every event of the stream as one JSON line instead.
- **When more is needed:** in a terminal, `investigate` asks the questions and sends the request again with
  your answers. Otherwise, or with `--no-interactive`, it prints them and the request id and exits `5`. Send
  the same question again with `--prior-request <id>` and one `--context "Q: … A: …"` per answer.
- **Declined:** Protect can decline a question that isn't about this instance's decisions; the command
  exits `4` with the reason.
- **What is recorded:** each request is recorded with who asked, the question, `--purpose`, and, when
  given, `--justification` and `--investigating` (a ticket or case reference). A request an AI agent makes
  is recorded as made by one. That is detected from `AI_AGENT`, `CLERK_PROTECT_AGENT` or `CLAUDECODE`, or set
  with `--agent <name>`.
- **Agents:** an AI agent using `investigate` should ask you for the purpose, and any justification or
  reference, rather than write them itself, because they are recorded as yours.
- **Availability:** not every instance has it yet. Where it isn't available, the command says so.
- **Permissions:** it needs the permissions that let you run replays in Protect Labs.

## Scripts and automation

- **Changes need confirmation.** A command that changes your configuration — creating, updating, enabling,
  disabling, deleting or reordering rules, changing protections, starting or applying a replay — asks first, as
  does `logout --all`. When standard input is not a terminal it does not ask: it refuses unless you pass
  `--yes`, before sending anything. `profile` commands, and `logout` for one instance, change only this
  computer and do not ask.
- **Lifetime and renewal.** An idle computer can resume while its token is valid, up to the original
  authorization deadline. A shorter token renews on the next request once half its lifetime has
  passed, while it is still valid; `trace` reconnects before that token expires. If the token or
  authorization expires, sign in again. Renewal always keeps the original authorization end time.
  `profile`, `keys status`, and `console open --no-sign-in` or `--no-browser` never renew a token;
  use a command that talks to Protect, such as `whoami`, when a shorter token needs renewal.
- **Exit codes:** `0` success, `1` failure (including an invalid rule from `rules validate`), `2` a mistake
  in the command, `3` sign in again with `clerk-protect login`, `4` an investigation was declined, `5` an
  investigation needs more information.
- `CLERK_PROTECT_PROFILE` selects a profile, as `--profile` does. `CLERK_PROTECT_API_URL` points at another
  deployment, as `--api-url` does, and wins over a profile's API URL.
- `CLERK_PROTECT_CONFIG_DIR` moves everything this tool stores, profiles included.
