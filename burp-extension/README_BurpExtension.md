# WPT Checklist Scanner — Burp Suite extension (v1)

A Burp Suite tab that runs the WPT checklist's ~100 automatable, non-destructive
checks against your **current authenticated Burp session**, shows results grouped
by category right inside Burp, cross-references Burp's own Scanner findings, and
exports in the exact JSON/CSV/XLSX schema your ReportSystem "Import Auto-Scan
Results" page already accepts.

This is **v1** — it covers the same ~100/421 checklist items `checklist_auto_scan.py`
already covers (headers, TLS, cookies, CORS, clickjacking, email security, path
probes, basic IDOR), but now driven by your live Burp session instead of a
manually-typed cookie on the command line. It does **not** yet cover SQLi, XSS,
SSRF, and the other active-injection categories — see "Roadmap: external tool
integration" below for how those get added in later phases.

---

## 1. How it's built (read this first)

Burp only loads Python extensions through **Jython**, which is stuck on Python
2.7 syntax and has none of the third-party packages (`requests`, `pandas`,
`xlsxwriter`, `Pillow`, ...) that `checklist_auto_scan.py`'s ~100 checks and its
`.xlsx` writer depend on. Rewriting all of that in Jython would mean
reimplementing and re-testing logic that already works and that
`Checklist-AutoScan.ps1` and the Django portal both also rely on.

So this extension is a **thin Jython shell** that:

1. builds a tab and results table inside Burp (Swing UI),
2. pulls your target list and session Cookie/Authorization header from Burp's
   own Proxy history and scope — so every test runs as **you**, authenticated,
3. shells out to a **real Python 3** interpreter (the one you said is already
   installed on your remote machine) running `checklist_auto_scan.py` with that
   captured session, and
4. reads back the JSON it writes and renders it as the results table you see in
   Burp.

Nothing about `checklist_auto_scan.py`'s actual test logic changes — the
extension just drives it with real session data instead of you typing
`--cookie` by hand.

---

## 2. Files in this bundle

| File | Goes where |
|---|---|
| `WPTChecklistScanner.py` | The Burp extension itself. Load it directly in Burp — see Installation below. |
| `checklist_auto_scan.py` | The real scanner. Must sit on the SAME machine Burp is running on (the extension shells out to it locally, not over the network). Keep it next to `WPTChecklistScanner.py`, or point the extension at wherever it already lives (e.g. inside your `ReportSystem` folder) — the path is configurable in the extension's UI. |

---

## 3. Installation

### 3.1 Prerequisites

- **Burp Suite Professional or Community**, any recent version. (Professional
  is recommended overall for this project — see the coverage-expansion notes
  from earlier — but v1 itself works in Community too, since it only reads
  Proxy history/scope, which both editions have.)
- **Python 3** installed and on PATH (or know its full path) on the SAME
  machine Burp runs on — you already have this on your remote machine.
- **Jython standalone JAR** — this is what lets Burp load `.py` extensions at
  all. Download `jython-standalone-2.7.3.jar` (or newer) from
  https://www.jython.org/download — pick the **standalone** jar, not the
  installer.

### 3.2 Point Burp at Jython

1. In Burp: **Extensions → Extension settings** (older Burp versions: the
   **Options** sub-tab under **Extender**) → **Python Environment**.
2. Set **Location of Jython standalone JAR file** to the `.jar` you downloaded.
3. No restart needed — Burp picks it up immediately.

### 3.3 Load the extension

1. **Extensions → Installed → Add**.
2. **Extension type: Python**.
3. **Extension file**: browse to `WPTChecklistScanner.py`.
4. Click **Next**. The **Output** tab in that same screen should show:
   `WPT Checklist Scanner loaded. Open the 'WPT Checklist Scanner' tab to configure and run.`
   If you instead see a Python traceback, see Troubleshooting below.
5. A new **WPT Checklist Scanner** tab appears in Burp's main tab bar.

---

## 4. Configuration (top panel of the extension tab)

| Field | What to set it to |
|---|---|
| **Python 3 interpreter** | `python3` if it's on PATH, otherwise the full path (e.g. `C:\Python311\python.exe` on Windows, `/usr/bin/python3` on Linux/macOS). |
| **checklist_auto_scan.py path** | Full path to the script. Defaults to the same folder the extension was loaded from — use **Browse...** if you keep it elsewhere (e.g. your `ReportSystem/` folder). |
| **Output folder** | Where scan output (`.json`/`.csv`/`.xlsx`) gets written before you export it. Defaults to your system temp folder. |
| **Targets** | One URL per line. Type them directly, or click **Pull in-scope targets from Proxy history** to auto-populate from what you've already browsed through Burp (requires Target → Scope to be set first). |
| **Cookie header** | Your authenticated session's Cookie value. Click **Capture session (Cookie) from Proxy history** to grab it automatically from the most recent in-scope request, or paste your own. |
| **Extra header** | Optional — e.g. `Authorization: Bearer eyJ...` for token-based auth instead of/in addition to cookies. |

**Nothing is sent anywhere except to your own target** — the captured
Cookie/Authorization values are only used locally, passed straight through to
`checklist_auto_scan.py` as `--cookie`/`--header` on your own machine.

---

## 5. Using it

- **Run All Tests** — runs the full ~100-check suite against every target
  listed, using the captured/entered session. Populates both the **Summary**
  tab (category-by-category pass/fail counts) and **Detailed Results** tab
  (every row, color-coded PASS=green/FAIL=red/MANUAL=yellow/INFO=blue/
  ERROR=gray — same scheme as the `.xlsx` output).
- **Re-run Selected** — select one or more rows in **Detailed Results** first,
  then click this. Only those Checklist IDs are re-tested (against the same
  targets/session) and merged back into the existing results — everything else
  stays as it was. Useful after you've fixed something and want to confirm the
  retest without re-running the whole suite.
- **Export → ReportSystem JSON/CSV/XLSX** — copies the last scan's output files
  to a folder you choose. The JSON is in the exact schema your ReportSystem
  portal's **Import Auto-Scan Results** page already accepts — upload it there
  directly, no conversion needed.
- **Pull Burp Scanner findings for these targets** (third sub-tab) — reads
  Burp's own Scanner issues (requires Burp Pro's Scanner to have already run,
  actively or passively, against the target) and lists them for
  cross-reference. **These are informational only and are never included in
  the export** — they don't map to real WPT checklist IDs, so merging them in
  would corrupt your checklist data. Use this tab to sanity-check "did Burp's
  own scanner already flag something in this area" while you review results,
  not as an import source.

---

## 6. What v1 covers vs. what it doesn't

Covered (same ~100 items as `checklist_auto_scan.py`/`Checklist-AutoScan.ps1`,
now running authenticated via your live session): HTTP Security Headers,
SSL/TLS, Clickjacking, CORS, Information Gathering, Configuration Testing,
Session Management, Client-Side Testing (storage heuristic), Email Security,
Information Disclosure, HTTP Host Header Attacks, basic Access Control/IDOR
(force-browse always; the two-account horizontal-escalation checks still need
a second account's cookie, same as the command-line tool).

**Not covered yet** — SQL Injection, XSS, HTTP Request Smuggling, CSRF (beyond
basic token-presence checks), SSRF, XXE, Command Injection, Path Traversal,
Race Conditions, Web Cache Poisoning, Business Logic, JWT Attacks, and
everything else that needs active payload injection rather than a read-only
probe. See the roadmap below.

---

## 7. Roadmap: external tool integration (not built yet)

> **Update:** the CLI (`checklist_auto_scan.py`) now has a working, opt-in
> active-testing pipeline covering large parts of Phase 3 below (sqlmap,
> dalfox) plus nuclei/nikto — see **section 11**. It is **not yet wired into
> the Burp extension UI** (`WPTChecklistScanner.py`) — that's still Jython
> work and remains open. Everything below this line describes the original
> plan; section 11 describes what's actually implemented today.

This is the plan for closing the gap from ~100 to the ~220–260 items discussed
earlier, phased so each piece can be added and tested independently:

**Phase 2 — wrap existing free Burp extensions (no new dev work, just result
cross-referencing, similar to how the "Burp Scanner Findings" tab works today):**
- **Turbo Intruder** (BApp Store) → Race Conditions
- **HTTP Request Smuggler** (BApp Store) → HTTP Request Smuggling
- **Param Miner** (BApp Store) → Web Cache Poisoning / Web Cache Deception

**Phase 3 — external tool orchestration (the extension exports a captured
request + your session cookie, invokes the tool as a subprocess, parses its
output back into checklist rows):**
- **sqlmap** → SQL Injection, NoSQL Injection
- **Dalfox** → reflected/stored XSS
- **jwt_tool** → JWT Attacks (alg=none, weak secret, etc.)
- **Burp Collaborator** (built into Burp Pro) → out-of-band confirmation for
  blind SQLi, SSRF, blind command injection, XXE — no separate tool needed,
  just Collaborator client integration in the extension.

**Phase 4 — DOM confirmation:**
- **Playwright** (headless Chromium) → confirms DOM-based XSS actually
  executes in a real browser context, not just that a payload reflects
  unencoded — this is what separates "found a pattern" from "confirmed
  exploitable."

Each phase adds its own config fields (tool path, e.g.) and its own section in
this document once built — nothing above is implemented in this v1 file.

---

## 8. Troubleshooting

**Extension fails to load / traceback in the Output tab on load** — almost
always a Jython path problem. Re-check Extensions → Extension settings →
Python Environment points at a real, readable `jython-standalone-*.jar`
(not the installer jar).

**"checklist_auto_scan.py not found at: ..."** — the path field is wrong; use
**Browse...** next to it rather than typing the path by hand.

**Scan fails with a non-zero exit code and stderr text about a missing
module** — your `python3` needs `pandas`/`xlsxwriter` for the `.xlsx` output
(`pip3 install pandas xlsxwriter`, add `--break-system-packages` if your OS
complains about an externally-managed environment) and `Pillow` if you want
evidence screenshots (`pip3 install Pillow`). CSV/JSON output still works
without either.

**Export folder is missing the `.xlsx` (only `.csv`/`.json` show up)** — this
is the *same* missing-`pandas`/`xlsxwriter` situation above, but it does
**NOT** fail the scan or show a non-zero exit code — `checklist_auto_scan.py`
degrades gracefully and just skips writing the `.xlsx`, printing a warning to
stdout that used to only be visible in Extensions' **Output** console. The
extension's status bar (bottom of the tab) now says explicitly when this
happened after a scan, and the **Export** button's status message repeats it.
Fix: `pip3 install pandas xlsxwriter` on the SAME `python3` the "Python 3
interpreter" field above points at, then re-run.

**"No in-scope requests found in Proxy history yet"** when clicking Pull
targets / Capture session — set **Target → Scope** first, then browse the
target through Burp's Proxy (or just replay one request through Repeater) so
there's at least one in-scope entry in Proxy history to read from.

**"Pull in-scope targets from Proxy history" grabs way more targets/domains
than expected, and the checklist runs against all of them (a large,
unexpected total row/check count)** — this button trusts Burp's own
`isInScope()` check, which is driven entirely by **Target → Scope**. If you
haven't explicitly added your target there (or "Use advanced scope control"
is off), Burp treats *everything* it's seen in Proxy history as in-scope -
every CDN, analytics/tracker domain, third-party asset host, etc. that your
browser touched while proxied through Burp - and this button will happily
pull up to 50 of those distinct hosts, each then getting the full checklist
run against it. Fix: **Target → Scope** tab → tick **Use advanced scope
control** → **Add** → enter just your actual authorized target(s) (e.g.
`pentest-ground.com`) → re-click **Pull in-scope targets from Proxy
history**. You can also just hand-edit the **Targets** text box directly
before clicking **Run All Tests** - it's a plain text field, delete
whatever doesn't belong.

**Evidence column is truncated / can't see the actual request or response
for a row** — the Detailed Results grid caps each Evidence cell at 300
characters so the table stays readable. **Double-click any row** to open a
dialog with the full, untruncated evidence text - including the real `$
curl ...` command and response, if the **"Use command-line tools..."**
checkbox above the Targets box is ticked (it's on by default; earlier
builds of this extension always ran with that internally disabled, which
is why runs from inside Burp never showed real request/response evidence
the way the standalone CLI tool does).

**Subprocess hangs or never returns** — Jython's `subprocess` module has had
occasional platform-specific quirks in some Jython builds. If a scan seems
stuck, check the extension's **Output** tab for the exact command line being
run, and try running that exact command by hand in a terminal to isolate
whether the issue is in `checklist_auto_scan.py` itself (network/target
issue) or in Jython's process handling (report back with what you see either
way — this is the one part of v1 that's hardest to fully test outside a real
Burp installation, so feedback here is genuinely useful for a v1.1 fix).

**Results table doesn't color rows** — cosmetic only, doesn't affect the
data. Confirm you're on a Burp version with standard Swing table rendering
(this has been true for all recent Burp releases); if it persists, the Result
column values are still fully readable as text either way.

---

## 9. Full feature list (v1)

- Custom "WPT Checklist Scanner" tab inside Burp with three sub-tabs: Summary,
  Detailed Results, Burp Scanner Findings (context only).
- Pull in-scope targets directly from Burp's Proxy history.
- Capture the live session's Cookie/Authorization header from Proxy history,
  or enter your own.
- Run the full ~100-check suite against one or many targets, authenticated.
- Re-run just selected rows (by Checklist ID) without re-running everything.
- Category-by-category summary counts (Total/Pass/Fail/Manual-or-other).
- Full results table, color-coded by Result, matching the `.xlsx` scheme.
- Cross-reference Burp's own Scanner issues for the same targets (display
  only, never exported/merged into checklist data).
- One-click export of JSON/CSV/XLSX in the exact schema your ReportSystem
  "Import Auto-Scan Results" page already accepts — no new portal-side code
  needed.
- Runs scans on a background thread so the Burp UI never freezes.

## 10. Features planned but NOT in this v1 (see Roadmap, section 7)

- SQLi/XSS/SSRF/XXE/Command Injection/Path Traversal active testing — **now
  available from the CLI**, see section 11; not yet exposed in the Burp
  extension UI itself.
- HTTP Request Smuggling / Web Cache Poisoning (via wrapping existing BApp
  Store extensions)
- Race condition testing (via Turbo Intruder)
- JWT deep-testing (via jwt_tool)
- DOM-XSS confirmation (via headless browser)
- Direct push to ReportSystem's import endpoint (skipping the manual
  export-then-upload step)
- A persistent config (currently every field resets when the extension
  reloads — planned as a small settings-save feature once the above phases
  are further along)

---

## 11. Phased active-testing pipeline (`checklist_auto_scan.py`, CLI only)

`checklist_auto_scan.py` now has an **opt-in** pipeline on top of the
baseline ~100 checks (which still run by default, unchanged). It's driven
entirely by `--phases` and is CLI-only for now — the Burp extension UI
doesn't expose phase selection yet, so use the CLI directly (or shell out
to it the same way the extension already does for the baseline suite) to
reach these phases.

**Phases, in dependency order** (selecting a later one auto-includes the
ones before it — e.g. `--phases inject` also runs `discover` and `recon`):

| Phase | What it does |
|---|---|
| `recon` | Same-origin crawl (stdlib regex, bounded by `--crawl-max-pages`/`--crawl-depth`) — turns WA-OTG-276/277 from MANUAL into a real automated pass. |
| `discover` | Extracts candidate injection points (form fields + URL query params) from every page `recon` crawled → WA-DISC-001. |
| `extscan` | Runs **nuclei** and **nikto** if found on PATH (auto-detected, same pattern as curl/nmap) — findings come back as their own WA-EXT-NUCLEI-\* / WA-EXT-NIKTO rows, severity mapped from nuclei's own `info.severity`. |
| `inject` | Sends small built-in payload lists (XSS/SQLi/Command Injection/Path Traversal/SSTI — self-contained, no SecLists checkout needed) into every discovered field, applies a conservative response-oracle (reflected marker / DB error signature / timing) → WA-INJ-\* rows. A hit here means "a real signal came back," not "exploited." |
| `exploit` | **Opt-in, real exploitation.** For every `inject`-confirmed finding, hands off to **sqlmap** (SQLi — `--batch --dump`, genuinely extracts real rows) or **dalfox** (XSS PoC). Requires both `--exploit` **and** `--i-am-authorized`, or it refuses and logs a MANUAL row instead. This sends real attack traffic — only point it at a target you have explicit written authorization to actively exploit. |

A final **severity-weighted comprehensive report** (`<out>_comprehensive.json`
+ a console summary) is always written after any run, phases or not — total
FAIL count, an overall Critical/High/Medium/Low/Info risk rating (weighted:
Critical=40/High=20/Medium=5/Low=1 per FAIL row), a per-phase breakdown, and
the top findings by severity.

**Usage:**

```bash
# baseline only (default, unchanged from before this pipeline existed)
python3 checklist_auto_scan.py --url https://target.example.com

# recon through inject - safe, no real exploitation attempted
python3 checklist_auto_scan.py --url https://target.example.com \
    --phases recon,discover,extscan,inject

# everything, including REAL exploitation - requires explicit authorization
python3 checklist_auto_scan.py --url https://target.example.com \
    --phases all --exploit --i-am-authorized
```

Tool detection is automatic (PATH-based, like curl/nmap already are) for
`nuclei`, `nikto`, `sqlmap`, and `dalfox` — a missing tool degrades that one
row to MANUAL with an install pointer, it never breaks the rest of the scan.
Payload lists are curated subsets inspired by SecLists' `Fuzzing/*` files but
kept inline in the script itself — no external SecLists checkout needed.

Tuning flags: `--crawl-max-pages` / `--crawl-depth` (recon),
`--max-injection-fields` (inject, default 25 — caps request volume on
forms/APIs with a lot of fields), `--nuclei-timeout` / `--nikto-timeout` /
`--sqlmap-timeout` / `--dalfox-timeout`.
