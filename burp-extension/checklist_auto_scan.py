#!/usr/bin/env python3
"""
checklist_auto_scan.py
-----------------------------------------------------------------------
Automated pre-check scanner for the parts of the WPT master checklist
(~421 items, categories like SQL Injection / XSS / Business Logic / Auth
Testing / Race Conditions / etc.) that CAN safely be verified by a
read-only script: HTTP response headers, TLS handshake/certificate info,
DNS TXT records (SPF/DMARC/DKIM), and a small set of known-safe GET/OPTIONS
probes (robots.txt, common backup/dotfiles, crossdomain.xml, admin paths).

This is NOT a replacement for sqlmap / Burp / nuclei / manual testing -
those items still need the tool named in the checklist's "Tools" column,
or a human. Every checklist item this script does NOT test is listed in
the output as result=MANUAL with a note, so nothing looks silently
skipped or silently "passed".

DEFAULT BEHAVIOUR - READ THIS FIRST
  By default every URL you give is tested TWICE, automatically, with no
  flag needed:
    1. the EXACT URL you gave, including its sub-folder/path - e.g.
       https://127.0.0.1:4434/subfolder is tested as-is, and any
       path-based probe (robots.txt, backup files, .git exposure, admin
       paths, crossdomain.xml, dependency manifests, ...) is run UNDER
       that same sub-folder (https://127.0.0.1:4434/subfolder/robots.txt).
    2. the SITE ROOT of that same host - https://127.0.0.1:4434/ - since
       a lot of what the checklist is looking for (server config, TLS,
       admin interfaces, DNS/email records, backup files that were never
       meant to be reachable) usually lives at the root regardless of
       which page/app path you were given.
  Every result row says which of the two (url_role: "given-url" or
  "site-root") it came from, so nothing is ambiguous in the report. Pass
  --skip-root-pass if you only want the exact URL tested and not the
  automatic extra root pass.

  Every row where a check can't be verified automatically and needs a
  human/dedicated tool is marked result=MANUAL, and its comment always
  starts with the fixed phrase "Manual test required." (plus specifics
  after it) - so you can filter/search for exactly that phrase in the
  report to build your manual work queue.

USAGE
  # single URL - tests both the URL itself and its site root by default
  python3 checklist_auto_scan.py --url https://127.0.0.1:4434/subfolder

  # a list of URLs, one per line (# comments / blank lines ignored) -
  # EVERY url in the file gets the same full treatment (both passes)
  python3 checklist_auto_scan.py --url-file urls.txt --out results

  # self-signed / internal lab target, longer timeout
  python3 checklist_auto_scan.py --url https://10.0.0.5 --insecure --timeout 15

  # only test the exact URL given, skip the automatic site-root pass
  python3 checklist_auto_scan.py --url https://example.com/portal/ --skip-root-pass

  # also run the light common-admin-port scan (off by default, noisier)
  python3 checklist_auto_scan.py --url https://target.example.com --port-scan

  # skip auto-screenshots entirely (they're on by default for FAIL rows)
  python3 checklist_auto_scan.py --url https://target.example.com --screenshot none

  # also generate one for PASS rows (proof of a clean check), or for everything
  python3 checklist_auto_scan.py --url https://target.example.com --screenshot fail+pass
  python3 checklist_auto_scan.py --url https://target.example.com --screenshot all

AUTO-GENERATED "EVIDENCE SCREENSHOTS" - no manual screenshotting needed
  Taking a screenshot by hand for every one of ~77 automated checks x
  however many URLs you're testing doesn't scale. So by default, every
  FAIL row gets its own auto-generated evidence card - a rendered PNG
  showing the URL, checklist ID/test name, category/severity, the exact
  evidence text, and timestamp - the same information you'd otherwise be
  screenshotting from a terminal by hand. It's a rendered summary card,
  NOT a live browser screenshot of the target page - it's meant to stand
  in as the "Artefacts" evidence a report needs for an automated check,
  not to replace an actual browser screenshot of an exploited XSS/SQLi/etc.
  Needs Pillow (pip3 install Pillow); scanning still completes normally
  without it, just without screenshots (a warning is printed once).
  Control which rows get one with --screenshot {none,fail,fail+pass,all}
  (default: fail).

  Where the screenshots end up:
    - Embedded as base64 PNG in <out>.json (field: evidence_image_base64)
      on every row that got one - NOT written to .csv (keeps it readable;
      .csv instead gets a Screenshot: yes/no column).
    - Also embedded as real, viewable images directly in <out>.xlsx on a
      dedicated "Evidence" sheet (needs Pillow only - xlsxwriter embeds
      whatever image bytes it's given either way).
    - JUMP HOST / RESTRICTED-COPY WORKFLOW: if you're running this on a
      jump host where only clipboard text comes back to your real machine
      (no file transfer), copy the printed JSON (or just paste the
      relevant row's evidence_image_base64 value) back to your own
      machine and run the companion script to turn it back into real
      .png files:
        python3 extract_evidence_images.py results.json --out screenshots/
      See extract_evidence_images.py's own --help for details; it ships
      alongside this script.

OUTPUT
  Every run writes THREE files from the same results (no flag needed):
  <out>.csv, <out>.json, and <out>.xlsx - a color-coded, filterable
  workbook (PASS/FAIL/MANUAL/INFO/ERROR highlighted, autofilter + frozen
  header row) plus a Summary sheet, so it's easy to navigate as a
  tracking list. <out> defaults to checklist_scan_<timestamp>. The .xlsx
  needs "pandas" and "xlsxwriter" (pip3 install pandas xlsxwriter); if
  either is missing the script still writes .csv/.json and just skips
  .xlsx with a note.

REAL COMMAND-LINE TOOL INTEGRATION (curl / nmap / sslyze / sslscan / testssl.sh)
  Auto-detected via PATH, no flag/config needed - if a tool is installed,
  it's used automatically to capture REAL command output as evidence:
    - curl runs once per HTTP Security Headers check (WA-HDR-392..398,401)
      and its exact "$ curl ..." command + raw response headers is
      appended to the evidence text.
    - The first of nmap (--script ssl-enum-ciphers), sslyze, sslscan, or
      testssl.sh found on PATH runs once per HTTPS target and its output
      both becomes the evidence for WA-TLS-402/404 AND drives a real
      PASS/FAIL determination (weak-cipher/weak-protocol pattern
      matching) instead of leaving those two MANUAL.
  Rows carrying this kind of real command output get a TERMINAL-STYLE
  evidence screenshot (black background, monospace) instead of the usual
  summary card, so the screenshot itself looks like an actual terminal
  capture of the command that ran. Pass --no-cli-tools to disable all of
  this and use the pure-Python/MANUAL fallback only (e.g. for speed, or if
  you don't want subprocesses shelled out at all).

AUTHENTICATED SCANNING AND ACCESS CONTROL TESTING (opt-in, --cookie / --cookie2)
  This script NEVER logs in, brute-forces, guesses, or harvests
  credentials anywhere - it has no login flow at all. What it CAN do, if
  you hand it a session Cookie header value you already obtained yourself
  by logging in (e.g. copied from your browser's dev tools, or a Burp
  Proxy history entry), is use that pre-authenticated session to run
  EVERY check in the suite as that logged-in user, and automatically
  extend coverage as follows - this is "auto check": pass one cookie and
  it covers everything a single session can test; add a second and it
  covers the two-account checks too, with no extra flags needed:
    - --cookie alone: every one of the ~100 checks runs authenticated,
      PLUS WA-OTG-312 (auth bypass / force-browse) gets real testing -
      compares the SAME url with no session at all vs. with --cookie's
      session; byte-identical responses mean the page doesn't actually
      require login.
    - --cookie + --cookie2 (a SECOND, DIFFERENT account's own session):
      ALSO gets WA-SS-071 (horizontal privilege escalation) and
      WA-OTG-314 (IDOR) real testing - compares what account 1 (--cookie)
      and account 2 (--cookie2) each see at the same URL. Byte-identical
      responses are reported as MANUAL (not an automatic FAIL) since only
      a human can confirm the URL/resource is actually meant to be
      account-specific rather than shared/public.
    - A coverage report prints before scanning starts (what will be
      attempted) and again in the final summary (what was actually
      recorded), so you always know exactly which checklist IDs got real
      testing vs. stayed MANUAL for the run you just did.
  --account1-cookie/--account2-cookie/--account1-label/--account2-label
  still work exactly as before (and --cookie/--cookie2 auto-populate them
  unless you set those explicitly) - --cookie/--cookie2 are just the
  simpler names to reach for, since they also authenticate everything
  else in the suite. The cookie VALUES themselves are never written to
  evidence/JSON/CSV/screenshots - only status codes, byte lengths, and
  the pass/fail comparison outcome are.

REQUIREMENTS
  Python 3.7+, standard library only for the CSV/JSON scan itself. Uses
  the system "openssl" and "nslookup" command-line tools if present (both
  ship with macOS/Linux; nslookup also ships with Windows, but on Windows
  use the PowerShell script instead - Checklist_AutoScan.ps1 - which uses
  native .NET/PowerShell cmdlets and needs no external tools at all) to
  enrich the TLS and Email Security checks, and "curl"/"nmap"/"sslyze"/
  "sslscan"/"testssl.sh" if present to enrich Header and TLS checks with
  real command output (see above). Their absence degrades those specific
  checks to INFO/MANUAL - it does not break the rest of the scan.
"""

import argparse
import base64
import csv
import hashlib
import io
import json
import random
import re
import shutil
import socket
import ssl
import string
import subprocess
import sys
import textwrap
import time
import warnings
from datetime import datetime, timezone
from http.client import HTTPConnection, HTTPSConnection
from urllib.parse import urlparse, urljoin, parse_qsl, urlencode

# --------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------

DEFAULT_UA = "ReportSystem-ChecklistAutoScan/1.0 (+authorized-pentest-recon)"
STACK_TRACE_PATTERNS = [
    r"Traceback \(most recent call last\)", r"at System\.", r"Exception in thread",
    r"Fatal error:", r"Warning:\s+\w+\(\)", r"ORA-\d{5}", r"SQLSTATE\[",
    r"Microsoft OLE DB Provider", r"unhandled exception", r"Stack trace:",
    r"django\.core\.exceptions", r"NoMethodError", r"java\.lang\.\w+Exception",
    r"psql: error", r"Unhandled Exception", r"DEBUG = True", r"WSOD",
]
DEBUG_PAGES = ["/phpinfo.php", "/info.php", "/_profiler/", "/rails/info/properties",
               "/debug", "/elmah.axd", "/trace.axd", "/server-status", "/server-info"]
BACKUP_EXT_PROBES = ["/index.php.bak", "/index.html.bak", "/index.bak", "/config.php.bak",
                      "/web.config.bak", "/.env.bak", "/app.js.bak", "/wp-config.php.bak",
                      "/index.php.old", "/index.php.orig", "/index.php.swp"]
BACKUP_FILE_PROBES = ["/backup.zip", "/backup.tar.gz", "/site-backup.zip", "/db.sql",
                       "/database.sql", "/.env", "/config.php~", "/dump.sql", "/backup.sql.gz"]
GIT_SVN_PROBES = ["/.git/HEAD", "/.git/config", "/.svn/entries", "/.svn/wc.db",
                   "/.DS_Store", "/.hg/store", "/CVS/Root"]
DEPENDENCY_PROBES = ["/package.json", "/composer.json", "/requirements.txt", "/Gemfile",
                      "/pom.xml", "/Pipfile", "/yarn.lock"]
ADMIN_PATH_PROBES = ["/admin", "/administrator", "/wp-admin/", "/manager/html",
                      "/phpmyadmin/", "/adminer.php", "/cpanel", "/webmin/"]
COMMON_ADMIN_PORTS = [21, 22, 23, 3306, 3389, 5432, 6379, 8080, 8443, 9200, 27017, 5984, 2375]
COMMON_DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "dkim", "k1", "mail",
                          "s1", "s2", "smtp", "mandrill", "sendgrid"]
CLOUD_BUCKET_PATTERNS = [r"[\w.\-]+\.s3\.amazonaws\.com", r"s3\.amazonaws\.com/[\w.\-]+",
                          r"storage\.googleapis\.com/[\w.\-]+", r"[\w.\-]+\.blob\.core\.windows\.net"]
CDN_WAF_HEADER_HINTS = {
    "server": {"cloudflare": "Cloudflare", "akamaighost": "Akamai", "sucuri/cloudproxy": "Sucuri"},
    "cf-ray": {"": "Cloudflare"}, "x-amz-cf-id": {"": "Amazon CloudFront"},
    "x-sucuri-id": {"": "Sucuri"}, "x-cache": {"": "some CDN/reverse-proxy cache"},
    "x-akamai-transformed": {"": "Akamai"}, "x-varnish": {"": "Varnish cache"},
}

# --------------------------------------------------------------------------
# Phased pipeline payload lists (recon -> discover -> extscan -> inject ->
# exploit -> report). Small, curated, self-contained subsets "inspired by"
# the categories in SecLists' Fuzzing/* lists - kept inline in this file on
# purpose so running the inject/exploit phases needs NO external SecLists
# checkout/prerequisite, per direct request ("use basic seclist where ever
# required no need for prerequirtes"). Not exhaustive - this is a fast
# triage pass, not a replacement for a real fuzzer (ffuf/wfuzz) or sqlmap's
# own much larger payload set (which the exploit phase reaches for anyway
# once a field looks promising - see phase_exploit()).
# --------------------------------------------------------------------------

BASIC_XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "'><svg onload=alert(1)>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "\"onmouseover=\"alert(1)",
    "';alert(1);//",
    "<iframe src=javascript:alert(1)>",
]

BASIC_SQLI_PAYLOADS = [
    "'",
    "\"",
    "' OR '1'='1",
    "' OR '1'='1' -- -",
    "\" OR \"1\"=\"1",
    "1' ORDER BY 10000-- -",
    "' UNION SELECT NULL-- -",
    "' AND SLEEP(5)-- -",
    "'; WAITFOR DELAY '0:0:5'--",
    "1) AND SLEEP(5)-- -",
]

BASIC_CMD_INJECTION_PAYLOADS = [
    "; id",
    "| id",
    "`id`",
    "$(id)",
    "; sleep 5",
    "| sleep 5",
    "|| ping -c 3 127.0.0.1",
]

BASIC_PATH_TRAVERSAL_PAYLOADS = [
    "../../../../etc/passwd",
    "..\\..\\..\\..\\windows\\win.ini",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "....//....//....//etc/passwd",
    "/etc/passwd",
]

BASIC_SSTI_PAYLOADS = [
    "{{7*7}}",
    "${7*7}",
    "<%= 7*7 %>",
    "#{7*7}",
    "${{7*7}}",
]

# Response-oracle regexes used by classify_injection() (see phase_inject()
# below) - deliberately conservative, same "inconclusive -> don't guess a
# hit" philosophy as _parse_ssl_cli_output() elsewhere in this file.
SQL_ERROR_PATTERNS = re.compile(
    r"SQL syntax|mysql_fetch|ORA-\d{5}|SQLSTATE\[|PostgreSQL.*ERROR|SQLite3::|"
    r"Unclosed quotation mark|Microsoft OLE DB Provider|pg_query\(\)|"
    r"Warning: mysqli|syntax error at or near|System\.Data\.SqlClient",
    re.IGNORECASE)
UNIX_PASSWD_MARKER = re.compile(r"root:.*:0:0:")
WIN_INI_MARKER = re.compile(r"\[fonts\]|for 16-bit app support", re.IGNORECASE)
CMD_OUTPUT_MARKER = re.compile(r"uid=\d+\([\w-]+\)\s+gid=\d+")
TIME_BASED_DELTA_SEC = 4.0  # payload must add at least this much latency vs. baseline to count as a timing hit

# Same-origin crawler + form/param extraction regexes (recon/discover
# phases) - stdlib regex, not a real HTML parser or headless browser, so
# JS-rendered links/forms in an SPA are NOT seen here (same no-dependency
# tradeoff this script makes everywhere else - see module docstring).
CRAWL_LINK_RE = re.compile(r'(?:href|src|action)\s*=\s*["\']([^"\'#][^"\']*)["\']', re.IGNORECASE)
FORM_BLOCK_RE = re.compile(r'<form\b[^>]*>.*?</form>', re.IGNORECASE | re.DOTALL)
FORM_ATTR_RE = re.compile(r'<form\b([^>]*)>', re.IGNORECASE)
FIELD_TAG_RE = re.compile(r'<(?:input|textarea|select)\b([^>]*)>', re.IGNORECASE)
NAME_ATTR_RE = re.compile(r'name\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)
METHOD_ATTR_RE = re.compile(r'method\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)
ACTION_ATTR_RE = re.compile(r'action\s*=\s*["\']([^"\']*)["\']', re.IGNORECASE)

# Weighted risk scoring for the final comprehensive report (report phase) -
# only FAIL rows count (MANUAL/INFO/PASS/ERROR contribute 0 regardless of
# severity - an unconfirmed/manual item shouldn't move the needle the same
# way a confirmed FAIL does).
SEVERITY_WEIGHT = {"Critical": 40, "High": 20, "Medium": 5, "Low": 1, "Info": 0}

RESULTS = []
MANUAL_PREFIX = "Manual test required. "
# Set by scan_url()/run_full_suite() before each pass so add() can tag every
# row with which input URL it came from and which of the two passes
# (given-url / site-root) produced it, without threading two extra
# parameters through every one of the ~70 add() call sites below.
CTX = {"source_input": None, "url_role": "given-url", "phase": "baseline"}

# Populated from --cookie/--header by main() before scanning starts, then
# merged into every request raw_request() makes (see raw_request() below) -
# this is what lets an authenticated Burp session's cookie/Authorization
# header flow through to every one of the ~100 checks without touching each
# check function individually. A per-call extra_headers= (e.g. the
# account1/account2 IDOR cookie in _fetch_with_cookie()) always overrides
# these on a name collision - global session identity is the default, an
# explicit per-check identity always wins.
EXTRA_AUTH_HEADERS = {}

# Populated from (repeatable) --only <ID> by main() - when set, add() drops
# any row whose Checklist ID isn't in this set instead of recording it. The
# check itself still runs (these are all fast HTTP/TLS probes, not an
# expensive external scan), but only the requested IDs end up in the output
# - this is what powers a "re-run selected rows only" feature in a caller
# like a Burp extension, without needing every one of the ~30 check_*()
# functions to know how to skip themselves individually.
ONLY_IDS = None


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def add(url, cid, category, test, severity, priority, result, evidence):
    if ONLY_IDS is not None and cid not in ONLY_IDS:
        return
    evidence = evidence.strip() if evidence else ""
    if result == "MANUAL" and not evidence.startswith(MANUAL_PREFIX):
        evidence = MANUAL_PREFIX + evidence
    row = {
        "source_input": CTX.get("source_input") or url,
        "url_role": CTX.get("url_role") or "given-url",
        "phase": CTX.get("phase") or "baseline",
        "url": url, "id": cid, "category": category, "test": test,
        "severity": severity, "priority": priority, "result": result,
        "evidence": evidence, "checked_at": now_iso(),
        "evidence_image_base64": None,  # filled in by generate_screenshots() if this row qualifies
    }
    RESULTS.append(row)
    # Live-progress line for a caller (e.g. the Burp extension) reading
    # this process's stdout AS IT RUNS instead of waiting for it to exit -
    # one self-contained JSON row per line, distinctively prefixed so it's
    # easy to pick out from the scan's normal printed narration. Flushed
    # immediately so it isn't sitting in Python's buffered stdout when the
    # caller reads it. Never lets a print/encoding hiccup break the actual
    # scan - this is a nice-to-have side channel, not the source of truth
    # (RESULTS above, and the final .json, always have the real data).
    try:
        print("QUICKCHOP_ROW|" + json.dumps(row))
        sys.stdout.flush()
    except Exception:
        pass


def rand_token(n=10):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


# --------------------------------------------------------------------------
# Auto-generated "evidence screenshot" - a rendered PNG card standing in
# for the manual screenshot a report would otherwise need per finding. See
# module docstring "AUTO-GENERATED EVIDENCE SCREENSHOTS" for the full
# explanation. Degrades gracefully (whole scan still completes) if Pillow
# isn't installed - checked once via _pillow_available().
# --------------------------------------------------------------------------

_PILLOW_WARNED = False


def _pillow_available():
    global _PILLOW_WARNED
    try:
        import PIL  # noqa: F401
        return True
    except ImportError:
        if not _PILLOW_WARNED:
            print("\n[!] 'Pillow' not installed - skipping auto-generated evidence screenshots "
                  "(the rest of the scan is unaffected).")
            print("    Install with: pip3 install Pillow   "
                  "(add --break-system-packages if your Python reports an externally-managed-environment error)")
            _PILLOW_WARNED = True
        return False


_RESULT_COLORS = {
    "PASS": ("#1e7e34", "#eafaf1"),
    "FAIL": ("#a4262c", "#fdecea"),
    "MANUAL": ("#8a6d00", "#fff8e1"),
    "INFO": ("#1f4e78", "#eaf1fb"),
    "ERROR": ("#3b3b3b", "#eeeeee"),
}


def _wrap_by_pixel(draw, text, font, max_width_px):
    """Word-wraps by actually MEASURING each candidate line's pixel
    width against the font in use, instead of guessing a fixed
    character count - a char-count guess (e.g. width=128) silently
    overflows the image edge whenever the real glyph width doesn't
    match the guess (different font, bold vs regular, or the
    load_default() fallback when DejaVuSansMono isn't installed,
    which isn't even monospace). Falls back to a single character-by-
    character break only for one word too long to fit at all. Shared by
    render_evidence_image() and render_terminal_image() so every
    screenshot - curl/nmap-backed or not - wraps text identically."""
    words = text.split(" ")
    lines_out, cur = [], ""
    for word in words:
        candidate = word if not cur else f"{cur} {word}"
        if draw.textlength(candidate, font=font) <= max_width_px:
            cur = candidate
            continue
        if cur:
            lines_out.append(cur)
        if draw.textlength(word, font=font) <= max_width_px:
            cur = word
        else:
            # a single "word" (e.g. one long URL/token) wider than the
            # line itself - hard-break it character by character
            chunk = ""
            for ch in word:
                if draw.textlength(chunk + ch, font=font) > max_width_px:
                    lines_out.append(chunk)
                    chunk = ch
                else:
                    chunk += ch
            cur = chunk
    if cur:
        lines_out.append(cur)
    return lines_out or [""]


def _mono_fonts():
    """Loads the monospace font pair used by every terminal-style
    screenshot. Centralized so render_evidence_image() and
    render_terminal_image() always match."""
    from PIL import ImageFont

    mono_bold = mono = None
    for candidate in ("DejaVuSansMono-Bold.ttf",):
        try:
            mono_bold = ImageFont.truetype(candidate, 15)
            break
        except Exception:
            pass
    for candidate in ("DejaVuSansMono.ttf",):
        try:
            mono = ImageFont.truetype(candidate, 13)
            break
        except Exception:
            pass
    if mono_bold is None:
        mono_bold = ImageFont.load_default()
    if mono is None:
        mono = ImageFont.load_default()
    return mono_bold, mono


def render_evidence_image(row):
    """Returns (base64_png_str, raw_png_bytes) for one result row, or
    (None, None) if Pillow isn't available. Every screenshot now uses the
    same black/terminal look - requested directly: "screenshot for blac
    one authentica looks like command output insted of white one you
    shared, output shoudl be command line optut." Rows carrying real
    command-line tool output (curl/nmap/sslyze/...) still go through
    render_terminal_image() (real "$ " command + real output); rows
    without one (heuristic/manual-review checks) get a terminal-styled
    card built from this row's own fields instead of the old white
    "label:value" summary card."""
    if not _pillow_available():
        return None, None
    if CMD_BLOCK_MARKER in (row.get("evidence") or ""):
        return render_terminal_image(row)
    from PIL import Image, ImageDraw

    W, H = 980, 640
    fg, _bg = _RESULT_COLORS.get(row["result"], ("#333333", "#f5f5f5"))
    img = Image.new("RGB", (W, H), "#0c0c0c")
    draw = ImageDraw.Draw(img)
    mono_bold, mono = _mono_fonts()

    draw.rectangle([0, 0, W, 40], fill=fg)
    draw.text((16, 10), f"{row['result']} - {row['id']} - {row['test'][:70]}", font=mono_bold, fill="white")

    max_width_px = W - 32  # 16px margin each side
    y = 52

    def field_line(label, value, y):
        draw.text((16, y), f"{label}:", font=mono_bold, fill="#57e389")
        draw.text((150, y), str(value)[:110], font=mono, fill="#e0e0e0")
        return y + 19

    y = field_line("URL", row["url"], y)
    y = field_line("URL Role", row["url_role"], y)
    y = field_line("Category", row["category"], y)
    y = field_line("Severity", f"{row['severity']} ({row['priority']})", y)
    y = field_line("Checked At", row["checked_at"], y)
    y += 6
    draw.line([16, y, W - 16, y], fill="#3a3a3a", width=1)
    y += 12
    draw.text((16, y), "Evidence:", font=mono_bold, fill="#57e389")
    y += 20

    max_lines = max((H - 30 - y) // 17, 1)
    lines = []
    for raw_line in (row.get("evidence") or "").splitlines():
        lines.extend(_wrap_by_pixel(draw, raw_line, mono, max_width_px) if raw_line else [""])
    for line_txt in lines[:max_lines]:
        draw.text((16, y), line_txt, font=mono, fill="#d0d0d0")
        y += 17
    if len(lines) > max_lines:
        draw.text((16, y), f"... ({len(lines) - max_lines} more line(s) truncated - see JSON/CSV for full text)",
                   font=mono, fill="#888888")

    draw.text((16, H - 20), "Auto-generated evidence card (checklist_auto_scan.py) - not a live browser screenshot",
               font=mono, fill="#666666")

    buf = io.BytesIO()
    img.save(buf, format="PNG")
    raw = buf.getvalue()
    return base64.b64encode(raw).decode("ascii"), raw


def render_terminal_image(row):
    """Terminal-style screenshot for rows carrying real command-line tool
    output (curl/nmap/sslyze/...). Requested directly: "check wit hcommand
    line tools I have not seen sy screenshots for give findings" - this is
    what makes those screenshots look like an actual terminal capture of
    the real command + output, instead of the generic summary card."""
    from PIL import Image, ImageDraw

    W, H = 980, 640
    fg, _bg = _RESULT_COLORS.get(row["result"], ("#333333", "#f5f5f5"))
    img = Image.new("RGB", (W, H), "#0c0c0c")
    draw = ImageDraw.Draw(img)
    mono_bold, mono = _mono_fonts()

    draw.rectangle([0, 0, W, 40], fill=fg)
    draw.text((16, 10), f"{row['result']} - {row['id']} - {row['test'][:70]}", font=mono_bold, fill="white")

    evidence = row.get("evidence") or ""
    marker_pos = evidence.find(CMD_BLOCK_MARKER)
    summary = evidence[:marker_pos].strip() if marker_pos >= 0 else evidence.strip()
    cmd_block = evidence[marker_pos + 2:].strip() if marker_pos >= 0 else ""  # keep leading "$ "

    max_width_px = W - 32  # 16px margin each side

    y = 52
    draw.text((16, y), f"URL: {row['url']}  |  Role: {row['url_role']}  |  {row['checked_at']}",
              font=mono, fill="#9aa5b1")
    y += 22

    if summary:
        for line_txt in _wrap_by_pixel(draw, summary, mono, max_width_px)[:4]:
            draw.text((16, y), line_txt, font=mono, fill="#d0d0d0")
            y += 18
        y += 6

    draw.line([16, y, W - 16, y], fill="#3a3a3a", width=1)
    y += 10

    max_lines = max((H - 30 - y) // 17, 1)
    lines = []
    for raw_line in cmd_block.splitlines():
        lines.extend(_wrap_by_pixel(draw, raw_line, mono, max_width_px) if raw_line else [""])
    for line_txt in lines[:max_lines]:
        color = "#57e389" if line_txt.startswith("$ ") else "#e0e0e0"
        draw.text((16, y), line_txt, font=mono, fill=color)
        y += 17
    if len(lines) > max_lines:
        draw.text((16, y), f"... ({len(lines) - max_lines} more line(s) truncated - see JSON/CSV for full output)",
                  font=mono, fill="#888888")

    draw.text((16, H - 20), "Real command-line tool output (checklist_auto_scan.py) - not a live browser screenshot",
              font=mono, fill="#666666")

    buf = io.BytesIO()
    img.save(buf, format="PNG")
    raw = buf.getvalue()
    return base64.b64encode(raw).decode("ascii"), raw


def should_screenshot(result, policy):
    if policy == "none":
        return False
    if policy == "all":
        return result in ("PASS", "FAIL", "MANUAL", "INFO", "ERROR")
    if policy == "fail+pass":
        return result in ("PASS", "FAIL")
    return result == "FAIL"  # default policy: "fail"


def generate_screenshots(policy):
    """Runs once, after all scanning is done. Fills in
    row["evidence_image_base64"] for qualifying rows and returns
    {row_index: raw_png_bytes} for the ones written to disk (used by
    write_xlsx to embed real images) - image generation happens exactly
    once per row either way, base64 and raw bytes come from the same call."""
    if policy == "none":
        return {}
    image_bytes = {}
    generated = 0
    for idx, row in enumerate(RESULTS):
        if not should_screenshot(row["result"], policy):
            continue
        b64, raw = render_evidence_image(row)
        if b64 is None:
            break  # Pillow unavailable - no point retrying on every remaining row
        row["evidence_image_base64"] = b64
        image_bytes[idx] = raw
        generated += 1
    if generated:
        print(f"\n[*] Generated {generated} auto-evidence screenshot(s) (--screenshot {policy}).")
    return image_bytes


# --------------------------------------------------------------------------
# Low-level HTTP helper (stdlib only - no "requests" dependency, so this
# runs on a bare-bones Python install with nothing extra pip-installed)
# --------------------------------------------------------------------------

class HttpResult:
    def __init__(self, status=None, headers=None, body=b"", error=None, final_url=None):
        self.status = status
        self.headers = headers or {}
        self.body = body
        self.error = error
        self.final_url = final_url

    def header(self, name, default=""):
        for k, v in self.headers.items():
            if k.lower() == name.lower():
                return v
        return default

    def text(self, limit=200000):
        try:
            return self.body[:limit].decode("utf-8", errors="replace")
        except Exception:
            return ""


# Stable marker prefix stamped onto every HttpResult.error produced by the
# ssl.SSLCertVerificationError handler in raw_request() below - used only to
# reliably detect "this row failed because of a TLS chain-verify problem"
# from evidence/error text later (print_ssl_verify_summary_callout()),
# independent of whatever exact wording OpenSSL/Python happen to use for
# the underlying error on a given platform/version.
_SSL_VERIFY_HINT_MARKER = "[SSL-CERT-VERIFY-FAILED]"


def raw_request(url, method="GET", extra_headers=None, timeout=10, insecure=False,
                 follow_redirects=False, max_redirects=3, host_override=None, body=None):
    """Minimal HTTP client using http.client so we control raw headers
    exactly (needed for the Host-header probe and OPTIONS/TRACE checks) -
    urllib rewrites/normalizes some headers in ways that get in the way here.
    body= (bytes) is optional - only the injection phase's POST-field
    testing passes it; every existing GET/OPTIONS-only check is unaffected
    since body defaults to None, same as before this was added."""
    headers = {"User-Agent": DEFAULT_UA, "Accept": "*/*", "Connection": "close"}
    if EXTRA_AUTH_HEADERS:
        headers.update(EXTRA_AUTH_HEADERS)
    if extra_headers:
        headers.update(extra_headers)

    parsed = urlparse(url)
    scheme = parsed.scheme or "https"
    host = parsed.hostname
    port = parsed.port or (443 if scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    try:
        if scheme == "https":
            ctx = ssl.create_default_context()
            if insecure:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            conn = HTTPSConnection(host, port, timeout=timeout, context=ctx)
        else:
            conn = HTTPConnection(host, port, timeout=timeout)

        send_headers = dict(headers)
        if "Host" not in send_headers:
            send_headers["Host"] = host_override or (host if not parsed.port else f"{host}:{parsed.port}")
        else:
            pass

        if body is not None:
            send_headers.setdefault("Content-Length", str(len(body)))
            conn.request(method, path, body=body, headers=send_headers)
        else:
            conn.request(method, path, headers=send_headers)
        resp = conn.getresponse()
        status = resp.status
        resp_headers = dict(resp.getheaders())
        body = resp.read(500000)
        conn.close()

        result = HttpResult(status=status, headers=resp_headers, body=body, final_url=url)

        if follow_redirects and status in (301, 302, 303, 307, 308) and max_redirects > 0:
            location = resp_headers.get("Location") or resp_headers.get("location")
            if location:
                next_url = urljoin(url, location)
                return raw_request(next_url, method, extra_headers, timeout, insecure,
                                    follow_redirects, max_redirects - 1)
        return result
    except ssl.SSLCertVerificationError as e:
        # insecure=True sets verify_mode=CERT_NONE above, which means
        # OpenSSL never raises this in the first place when --insecure was
        # used - so reaching this branch always means verification was ON
        # and genuinely failed. The exact error text Python's ssl module
        # raises for a broken/self-signed/incomplete chain ("certificate
        # verify failed: unable to get local issuer certificate", etc.) is
        # accurate but doesn't say what to DO about it - every one of the
        # ~30 check_*() functions routes HTTPS requests through here, so
        # fixing the message once here fixes it everywhere it can surface,
        # instead of only wherever a check happened to print it. See also
        # the SSL cert-verify callout in print_summary(), which surfaces
        # this same class of failure as a single top-of-summary note when
        # it affects several rows, instead of it only appearing scattered
        # across individual evidence text.
        return HttpResult(error=f"{_SSL_VERIFY_HINT_MARKER} {e} - if this is an expected self-signed/internal/UAT "
                                 f"certificate, re-run with --insecure to skip verification and test anyway; if "
                                 f"you expected this to be a real, trusted certificate, this IS a legitimate "
                                 f"finding (WA-TLS-407-style chain issue) - or your machine's own CA bundle may "
                                 f"be out of date (try: pip3 install --upgrade certifi).")
    except Exception as e:
        return HttpResult(error=str(e))


def base_url_of(url):
    """scheme://host[:port]/ - always the SITE ROOT, dropping any path.
    Used once per input URL to compute the automatic second ("site-root")
    pass; see dir_of() below for the per-pass directory used for probes."""
    p = urlparse(url)
    port_part = f":{p.port}" if p.port and not ((p.scheme == "https" and p.port == 443) or
                                                  (p.scheme == "http" and p.port == 80)) else ""
    return f"{p.scheme}://{p.hostname}{port_part}/"


def dir_of(url):
    """scheme://host[:port]/<path>/ - the URL currently being tested,
    treated as a directory (trailing slash added if missing). Path-based
    probes are joined under THIS, so when the current pass's target is
    https://host/subfolder, probes land at https://host/subfolder/robots.txt
    etc.; when the current pass's target is the site root, they land at
    https://host/robots.txt - same helper, correct either way."""
    p = urlparse(url)
    port_part = f":{p.port}" if p.port and not ((p.scheme == "https" and p.port == 443) or
                                                  (p.scheme == "http" and p.port == 80)) else ""
    path = p.path or "/"
    if not path.endswith("/"):
        path += "/"
    return f"{p.scheme}://{p.hostname}{port_part}{path}"


def join_target(base, path):
    # path constants below are written as "/robots.txt" etc. for
    # readability; strip the leading "/" before joining so urljoin treats
    # them as relative to `base`'s directory instead of resetting to the
    # domain root (which is what a leading "/" means to urljoin).
    return urljoin(base, path.lstrip("/"))


# --------------------------------------------------------------------------
# Command-line tool integration (curl / nmap / sslyze / sslscan / testssl.sh)
# - used AUTOMATICALLY whenever the tool is found on PATH, no flag needed
#   (opt OUT with --no-cli-tools). Requested directly: "I have culs and
#   nmap and sslalyzer installed in the remote server ... check wit
#   hcommand line tools I have not seen sy screenshots for give findings."
#   Everything here is READ-ONLY (GET / TLS handshake probes only) - no
#   credentials are ever used, sent, or requested anywhere in this script,
#   per "never take the credetils also to navigate inside". When a tool
#   isn't installed, every caller below falls back to the exact same
#   Python-only/MANUAL behaviour this script always had - a missing tool
#   never breaks or blocks the scan.
# --------------------------------------------------------------------------

CMD_BLOCK_MARKER = "\n\n$ "  # render_evidence_image() switches to the terminal-style card on this marker
MAX_CMD_OUTPUT_CHARS = 4000


def _cli_available(name):
    return shutil.which(name) is not None


def _format_cmd_block(cmd_list, output_text, max_len=MAX_CMD_OUTPUT_CHARS):
    """Appends a real "$ <command>\\n<output>" block to an evidence string.
    This is what makes render_evidence_image() switch to a terminal-style
    screenshot instead of the generic summary card, and shows up verbatim
    in the JSON/CSV/XLSX evidence column as genuine command-line proof
    rather than a synthesized summary."""
    cmd_str = " ".join(cmd_list)
    out = (output_text or "").strip()
    if len(out) > max_len:
        out = out[:max_len] + f"\n... (truncated, {len(out) - max_len} more chars - see JSON for full output)"
    return f"{CMD_BLOCK_MARKER}{cmd_str}\n{out}"


def run_curl_with_host_header(url, host_value, timeout=10, insecure=False):
    """Same idea as run_curl_headers() but sends a custom Host: header via
    `curl -H "Host: ..."` - used by check_host_header() so THAT check also
    gets real command-line evidence/terminal screenshot instead of the
    generic summary card. Requested directly after seeing a Host Header
    finding's screenshot without command output: "give the commadn out
    put of proper out put"."""
    if not _cli_available("curl"):
        return None
    cmd = ["curl", "-sS", "-D", "-", "-o", "/dev/null", "--max-time", str(int(timeout) or 10),
           "-A", DEFAULT_UA, "-H", f"Host: {host_value}"]
    if insecure:
        cmd.append("-k")
    cmd.append(url)
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout + 10)
        out = proc.stdout.decode("utf-8", errors="replace")
        err = proc.stderr.decode("utf-8", errors="replace").strip()
        if err:
            out += ("\n" if out else "") + err
        return cmd, out
    except Exception as e:
        return cmd, f"(curl execution failed: {e})"


def run_curl_headers(url, timeout=10, insecure=False):
    """Runs `curl -sS -D - -o /dev/null ...` against `url` and returns
    (cmd_list, output_text), or None if curl isn't on PATH. A non-2xx/3xx
    HTTP status is NOT treated as failure here - curl still prints the
    real response headers either way, which is the point."""
    if not _cli_available("curl"):
        return None
    cmd = ["curl", "-sS", "-D", "-", "-o", "/dev/null", "--max-time", str(int(timeout) or 10),
           "-A", DEFAULT_UA]
    if insecure:
        cmd.append("-k")
    cmd.append(url)
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout + 10)
        out = proc.stdout.decode("utf-8", errors="replace")
        err = proc.stderr.decode("utf-8", errors="replace").strip()
        if err:
            out += ("\n" if out else "") + err
        return cmd, out
    except Exception as e:
        return cmd, f"(curl execution failed: {e})"


# Tried in this order - first one found on PATH is used. nmap is tried
# first since ssl-enum-ciphers output is what the parser below understands
# best, and the user confirmed nmap is installed; sslyze/sslscan/testssl.sh
# are used as-is if nmap isn't present.
_SSL_CLI_TOOLS = [
    ("nmap", lambda h, p, t: ["nmap", "-Pn", "--script", "ssl-enum-ciphers", "-p", str(p), h]),
    ("sslyze", lambda h, p, t: ["sslyze", f"{h}:{p}"]),
    ("sslscan", lambda h, p, t: ["sslscan", f"{h}:{p}"]),
    ("testssl.sh", lambda h, p, t: ["testssl.sh", "--fast", f"{h}:{p}"]),
]


def run_ssl_cli_scan(host, port, timeout=45):
    """Runs the FIRST available SSL/TLS CLI scanner (see _SSL_CLI_TOOLS)
    against host:port and returns (tool_name, cmd_list, output_text), or
    None if none of them are installed. Only one tool is run (not all
    four) to keep scan time reasonable."""
    for name, build_cmd in _SSL_CLI_TOOLS:
        if not _cli_available(name):
            continue
        cmd = build_cmd(host, port, timeout)
        try:
            proc = subprocess.run(cmd, capture_output=True, timeout=timeout)
            out = proc.stdout.decode("utf-8", errors="replace")
            err = proc.stderr.decode("utf-8", errors="replace").strip()
            if err:
                out += ("\n" if out else "") + err
            return name, cmd, out
        except subprocess.TimeoutExpired:
            return name, cmd, f"(scan timed out after {timeout}s - target may be slow/unreachable, try a longer --timeout)"
        except Exception as e:
            return name, cmd, f"({name} execution failed: {e})"
    return None


_WEAK_CIPHER_HINTS = re.compile(r"\b(RC4|DES|3DES|NULL|EXPORT|MD5|anon|IDEA|SEED)\b", re.IGNORECASE)
_WEAK_TLS_VERSION_HINTS = re.compile(r"\b(SSLv2|SSLv3|TLSv1\.0|TLSv1\.1|TLS 1\.0|TLS 1\.1)\b")


def _parse_ssl_cli_output(output_text):
    """Best-effort parse of whichever SSL CLI tool ran, used to turn
    WA-TLS-402/404 into a real PASS/FAIL instead of leaving them MANUAL.
    Deliberately conservative - an inconclusive parse falls back to
    INFO/MANUAL rather than guessing a PASS.

    Only scans lines that actually look like cipher-suite output (contain
    "_WITH_", start with TLS_/SSL_, or come from sslscan/testssl-style
    "Accepted ..." lines) - NOT the whole raw blob. nmap's ssl-enum-ciphers
    also prints an unrelated "compressors: NULL" line (NULL = no TLS
    compression negotiated, i.e. CRIME-safe - a GOOD thing), and matching
    "NULL" there as a weak-cipher hit would be a false positive."""
    if not output_text:
        return {"weak_ciphers": None, "weak_protocols": None, "least_strength": None}

    cipher_lines = "\n".join(
        line for line in output_text.splitlines()
        if "compress" not in line.lower()
        and ("_WITH_" in line or "TLS_" in line or "SSL_" in line
             or re.search(r"\b(Accepted|Preferred|Rejected)\b", line, re.IGNORECASE))
    )

    weak_ciphers = sorted(set(m.group(0) for m in _WEAK_CIPHER_HINTS.finditer(cipher_lines)))
    weak_protocols = sorted(set(m.group(0) for m in _WEAK_TLS_VERSION_HINTS.finditer(output_text)))
    m = re.search(r"least strength:\s*([A-Za-z]+)", output_text, re.IGNORECASE)  # nmap ssl-enum-ciphers
    least_strength = m.group(1) if m else None
    return {"weak_ciphers": weak_ciphers or None, "weak_protocols": weak_protocols or None,
            "least_strength": least_strength}


# --------------------------------------------------------------------------
# 1. HTTP Security Headers - WA-HDR-392..401
# --------------------------------------------------------------------------

def check_security_headers(full_url, args):
    r = raw_request(full_url, "GET", timeout=args.timeout, insecure=args.insecure)
    if r.error:
        for cid, name, sev, pri in [
            ("WA-HDR-392", "Content-Security-Policy present and strict", "Medium", "P2"),
            ("WA-HDR-393", "X-Frame-Options: SAMEORIGIN or DENY present", "Medium", "P2"),
            ("WA-HDR-394", "X-Content-Type-Options: nosniff present", "Low", "P3"),
            ("WA-HDR-395", "Strict-Transport-Security (HSTS) properly configured", "Medium", "P2"),
            ("WA-HDR-396", "Referrer-Policy header present", "Low", "P3"),
            ("WA-HDR-397", "Cache-Control: no-store on authenticated/sensitive pages", "Medium", "P2"),
            ("WA-HDR-398", "Permissions-Policy restricts sensitive browser APIs", "Low", "P3"),
            ("WA-HDR-399", "HTTPS enforced - HTTP redirects to HTTPS", "High", "P1"),
            ("WA-HDR-400", "Verbose error messages / stack traces on 4xx/5xx", "Medium", "P2"),
            ("WA-HDR-401", "Server version disclosure in response headers", "Low", "P3"),
        ]:
            add(full_url, cid, "HTTP Security Headers", name, sev, pri, "ERROR",
                f"Could not connect: {r.error}")
        return r, ""

    curl_result = None if getattr(args, "no_cli_tools", False) else run_curl_headers(
        full_url, timeout=args.timeout, insecure=args.insecure)
    curl_block = _format_cmd_block(curl_result[0], curl_result[1]) if curl_result else ""

    csp = r.header("Content-Security-Policy")
    if not csp:
        add(full_url, "WA-HDR-392", "HTTP Security Headers", "Content-Security-Policy present and strict",
            "Medium", "P2", "FAIL",
            "CONFIRMED BY: the response headers below contain no 'Content-Security-Policy' entry at all "
            "(checked case-insensitively across every header returned)." + curl_block)
    else:
        matched_tokens = [t for t in ("unsafe-inline", "unsafe-eval", "* ") if t in csp]
        loose = bool(matched_tokens) or csp.strip().endswith("*")
        if loose:
            reason = (f"CSP contains weak token(s) {matched_tokens}" if matched_tokens
                       else "CSP value ends with a bare wildcard '*'")
            evidence = f"CONFIRMED BY: {reason} - full header value: {csp[:300]}"
        else:
            evidence = f"CSP: {csp[:300]}"
        add(full_url, "WA-HDR-392", "HTTP Security Headers", "Content-Security-Policy present and strict",
            "Medium", "P2", "FAIL" if loose else "PASS", evidence + curl_block)

    xfo = r.header("X-Frame-Options")
    frame_ancestors = "frame-ancestors" in csp.lower() if csp else False
    if xfo and xfo.strip().upper() in ("DENY", "SAMEORIGIN"):
        add(full_url, "WA-HDR-393", "HTTP Security Headers", "X-Frame-Options: SAMEORIGIN or DENY present",
            "Medium", "P2", "PASS", f"X-Frame-Options: {xfo}" + curl_block)
    elif frame_ancestors:
        add(full_url, "WA-HDR-393", "HTTP Security Headers", "X-Frame-Options: SAMEORIGIN or DENY present",
            "Medium", "P2", "PASS", "No X-Frame-Options, but CSP frame-ancestors is set (covers modern browsers)." + curl_block)
    else:
        add(full_url, "WA-HDR-393", "HTTP Security Headers", "X-Frame-Options: SAMEORIGIN or DENY present",
            "Medium", "P2", "FAIL",
            f"CONFIRMED BY: X-Frame-Options header value is '{xfo or '(not present in response headers)'}' "
            "(expected DENY or SAMEORIGIN) and the CSP has no frame-ancestors directive either." + curl_block)

    xcto = r.header("X-Content-Type-Options")
    add(full_url, "WA-HDR-394", "HTTP Security Headers", "X-Content-Type-Options: nosniff present",
        "Low", "P3", "PASS" if xcto.lower() == "nosniff" else "FAIL",
        (f"X-Content-Type-Options: {xcto or 'missing'}" if xcto.lower() == "nosniff" else
         f"CONFIRMED BY: X-Content-Type-Options header value is '{xcto or '(not present in response headers)'}' "
         "(expected exactly 'nosniff').") + curl_block)

    hsts = r.header("Strict-Transport-Security")
    if full_url.startswith("https") and hsts:
        m = re.search(r"max-age=(\d+)", hsts)
        max_age_ok = m and int(m.group(1)) >= 15552000  # 180 days
        evidence = (f"HSTS: {hsts}" if max_age_ok else
                    f"CONFIRMED BY: Strict-Transport-Security max-age is {m.group(1) if m else 'missing/unparseable'} "
                    f"(recommend >= 15552000) - full header value: {hsts}")
        add(full_url, "WA-HDR-395", "HTTP Security Headers", "Strict-Transport-Security (HSTS) properly configured",
            "Medium", "P2", "PASS" if max_age_ok else "FAIL", evidence + curl_block)
    elif full_url.startswith("https"):
        add(full_url, "WA-HDR-395", "HTTP Security Headers", "Strict-Transport-Security (HSTS) properly configured",
            "Medium", "P2", "FAIL",
            "CONFIRMED BY: no Strict-Transport-Security header present in the response headers below, "
            "on an HTTPS response." + curl_block)
    else:
        add(full_url, "WA-HDR-395", "HTTP Security Headers", "Strict-Transport-Security (HSTS) properly configured",
            "Medium", "P2", "INFO", "URL is HTTP, not HTTPS - HSTS only meaningful over HTTPS." + curl_block)

    refpol = r.header("Referrer-Policy")
    add(full_url, "WA-HDR-396", "HTTP Security Headers", "Referrer-Policy header present",
        "Low", "P3", "PASS" if refpol else "FAIL",
        (f"Referrer-Policy: {refpol}" if refpol else
         "CONFIRMED BY: no Referrer-Policy header present in the response headers below.") + curl_block)

    cache_ctrl = r.header("Cache-Control")
    add(full_url, "WA-HDR-397", "HTTP Security Headers", "Cache-Control: no-store on authenticated/sensitive pages",
        "Medium", "P2", "MANUAL",
        f"Cache-Control on this page: {cache_ctrl or 'missing'}. Automated scan can't know if this "
        "specific page is authenticated/sensitive - confirm manually and check no-store is set if so." + curl_block)

    permpol = r.header("Permissions-Policy") or r.header("Feature-Policy")
    add(full_url, "WA-HDR-398", "HTTP Security Headers", "Permissions-Policy restricts sensitive browser APIs",
        "Low", "P3", "PASS" if permpol else "FAIL",
        (f"Permissions-Policy: {permpol}" if permpol else
         "CONFIRMED BY: no Permissions-Policy or Feature-Policy header present in the response headers below.") + curl_block)

    if full_url.startswith("http://"):
        redir_target = full_url.replace("http://", "https://", 1)
        r2 = raw_request(full_url, "GET", timeout=args.timeout, insecure=args.insecure, follow_redirects=False)
        loc = r2.header("Location")
        redirected_to_https = bool(loc and loc.lower().startswith("https"))
        curl_result_399 = None if getattr(args, "no_cli_tools", False) else run_curl_headers(
            full_url, timeout=args.timeout, insecure=args.insecure)
        curl_block_399 = _format_cmd_block(curl_result_399[0], curl_result_399[1]) if curl_result_399 else ""
        evidence399 = (f"HTTP response: {r2.status}, Location: {loc or 'none'}." if redirected_to_https else
                       f"CONFIRMED BY: plain http:// request returned status {r2.status} with "
                       f"Location: '{loc or '(no Location header at all)'}' - did not redirect to an https:// URL.")
        add(full_url, "WA-HDR-399", "HTTP Security Headers", "HTTPS enforced - HTTP redirects to HTTPS",
            "High", "P1", "PASS" if redirected_to_https else "FAIL", evidence399 + curl_block_399)
    else:
        add(full_url, "WA-HDR-399", "HTTP Security Headers", "HTTPS enforced - HTTP redirects to HTTPS",
            "High", "P1", "INFO", "URL given was already HTTPS - re-run with the http:// version to test the redirect.")

    base = dir_of(full_url)
    probe_path = join_target(base, "/this-path-should-not-exist-" + rand_token())
    r404 = raw_request(probe_path, "GET", timeout=args.timeout, insecure=args.insecure)
    trace_found = None
    trace_snippet = ""
    if not r404.error:
        body_text = r404.text()
        for pat in STACK_TRACE_PATTERNS:
            m404 = re.search(pat, body_text, re.IGNORECASE)
            if m404:
                trace_found = pat
                start = max(m404.start() - 40, 0)
                trace_snippet = body_text[start:m404.end() + 60].replace("\n", " ").strip()
                break
    add(full_url, "WA-HDR-400", "HTTP Security Headers", "Verbose error messages / stack traces on 4xx/5xx",
        "Medium", "P2", "FAIL" if trace_found else ("ERROR" if r404.error else "PASS"),
        (f"CONFIRMED BY: response body for the 404 probe ({probe_path}) matched known error-disclosure pattern "
         f"'{trace_found}' - excerpt around the match: \"...{trace_snippet}...\"" if trace_found else
         (r404.error or f"No known stack-trace pattern found on 404 probe (status {r404.status}).")))

    server_hdr = r.header("Server")
    xpb_hdr = r.header("X-Powered-By")
    server_match = re.search(r"\d+\.\d+", server_hdr) if server_hdr else None
    xpb_match = re.search(r"\d+\.\d+", xpb_hdr) if xpb_hdr else None
    version_leak = bool(server_match or xpb_match)
    if version_leak:
        which = []
        if server_match:
            which.append(f"Server: '{server_hdr}' (version-looking substring: '{server_match.group(0)}')")
        if xpb_match:
            which.append(f"X-Powered-By: '{xpb_hdr}' (version-looking substring: '{xpb_match.group(0)}')")
        evidence401 = "CONFIRMED BY: " + "; ".join(which)
    else:
        evidence401 = f"Server: {server_hdr or 'none'}, X-Powered-By: {xpb_hdr or 'none'}"
    add(full_url, "WA-HDR-401", "HTTP Security Headers", "Server version disclosure in response headers",
        "Low", "P3", "FAIL" if version_leak else "PASS", evidence401 + curl_block)

    return r, curl_block


# --------------------------------------------------------------------------
# 2. SSL / TLS - WA-TLS-402..409 (best-effort; several are MANUAL by design,
#    see module docstring - a real grade needs testssl.sh/sslyze/SSL Labs)
# --------------------------------------------------------------------------

def _openssl_available():
    try:
        subprocess.run(["openssl", "version"], capture_output=True, timeout=5)
        return True
    except Exception:
        return False


def check_tls(full_url, args):
    p = urlparse(full_url)
    if p.scheme != "https":
        for cid, name, sev, pri in [
            ("WA-TLS-402", "SSL/TLS scan - grade and cipher strength", "High", "P1"),
            ("WA-TLS-403", "SSLv2, SSLv3, TLSv1.0 disabled", "High", "P1"),
            ("WA-TLS-404", "No weak cipher suites (RC4, DES, NULL, EXPORT)", "High", "P1"),
            ("WA-TLS-405", "Certificate key strength >= 2048-bit RSA / 256-bit ECC", "Medium", "P2"),
            ("WA-TLS-406", "Certificate uses SHA-256+ signature algorithm", "Medium", "P2"),
            ("WA-TLS-407", "Certificate chain complete - no missing intermediates", "Medium", "P2"),
            ("WA-TLS-408", "HSTS preload list configured", "Medium", "P2"),
            ("WA-TLS-409", "WebSocket endpoints use WSS not WS", "High", "P1"),
        ]:
            add(full_url, cid, "SSL / TLS", name, sev, pri, "INFO", "URL is not HTTPS - TLS checks skipped.")
        return

    host = p.hostname
    port = p.port or 443

    ssl_cli = None if getattr(args, "no_cli_tools", False) else run_ssl_cli_scan(
        host, port, timeout=max(args.timeout, 45))
    if ssl_cli:
        ssl_tool, ssl_cmd, ssl_output = ssl_cli
        ssl_block = _format_cmd_block(ssl_cmd, ssl_output)
        parsed = _parse_ssl_cli_output(ssl_output)
        weak_ciphers = parsed["weak_ciphers"]
        least_strength = parsed["least_strength"]
        ran_but_empty = not ssl_output.strip() or ssl_output.lower().startswith("(")

        if least_strength:
            grade_result = "FAIL" if least_strength.lower() in ("weak", "insecure") else "PASS"
            grade_evidence = f"{ssl_tool} least cipher strength: {least_strength}."
        elif weak_ciphers:
            grade_result = "FAIL"
            grade_evidence = f"{ssl_tool} output flags weak cipher indicator(s): {', '.join(weak_ciphers)}."
        elif ran_but_empty:
            grade_result = "INFO"
            grade_evidence = f"{ssl_tool} ran but produced no conclusive cipher-strength output - review raw output below."
        else:
            grade_result = "PASS"
            grade_evidence = f"{ssl_tool} ran and found no weak-cipher indicators in its output - review raw output below to confirm."
        add(full_url, "WA-TLS-402", "SSL / TLS", "SSL/TLS scan - grade and cipher strength",
            "High", "P1", grade_result, grade_evidence + ssl_block)

        cipher_result = "FAIL" if weak_ciphers else ("INFO" if ran_but_empty else "PASS")
        cipher_evidence = (f"Weak cipher indicator(s) found by {ssl_tool}: {', '.join(weak_ciphers)}."
                            if weak_ciphers else f"No RC4/DES/3DES/NULL/EXPORT/MD5/anon indicators found in {ssl_tool} output.")
        add(full_url, "WA-TLS-404", "SSL / TLS", "No weak cipher suites (RC4, DES, NULL, EXPORT)",
            "High", "P1", cipher_result, cipher_evidence + ssl_block)
    else:
        add(full_url, "WA-TLS-402", "SSL / TLS", "SSL/TLS scan - grade and cipher strength",
            "High", "P1", "MANUAL",
            f"No SSL CLI scanner (nmap/sslyze/sslscan/testssl.sh) found on PATH. A real A-F grade needs one - run: "
            f"nmap --script ssl-enum-ciphers -p {port} {host}  OR  testssl.sh {host}:{port}  OR check "
            f"https://www.ssllabs.com/ssltest/analyze.html?d={host}")
        add(full_url, "WA-TLS-404", "SSL / TLS", "No weak cipher suites (RC4, DES, NULL, EXPORT)",
            "High", "P1", "MANUAL",
            f"No SSL CLI scanner found on PATH. Run: nmap --script ssl-enum-ciphers -p {port} {host}  OR  testssl.sh {host}:{port}")

    old_protocols = {}
    for name, ver in [("SSLv3", getattr(ssl.TLSVersion, "SSLv3", None)),
                       ("TLSv1.0", ssl.TLSVersion.TLSv1),
                       ("TLSv1.1", ssl.TLSVersion.TLSv1_1)]:
        if ver is None:
            old_protocols[name] = "not supported by local OpenSSL build - can't test"
            continue
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            # Deliberately setting min/max version to SSLv3/TLSv1.0/TLSv1.1
            # is exactly what this probe needs (we WANT to try connecting
            # with the old, weak protocol to see if the server still
            # accepts it) - but recent Python/OpenSSL builds raise a
            # DeprecationWarning on the assignment itself just for
            # referencing ssl.TLSVersion.SSLv3 at all. That's a warning
            # about OUR use of a deprecated Python API, not a finding
            # about the scanned target - suppressed here so it doesn't get
            # mistaken for one (asked directly: "in python i can see
            # deprecation warning ... is tis is findings or warning?").
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                ctx.minimum_version = ver
                ctx.maximum_version = ver
            with socket.create_connection((host, port), timeout=args.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    ssock.version()
            old_protocols[name] = "ACCEPTED by server (weak)"
        except ssl.SSLError:
            old_protocols[name] = "rejected by server (good)"
        except ValueError:
            old_protocols[name] = "not supported by local OpenSSL build - can't test"
        except Exception as e:
            old_protocols[name] = f"could not test ({e})"

    any_accepted = any("ACCEPTED" in v for v in old_protocols.values())
    any_untestable = any("can't test" in v for v in old_protocols.values())
    result = "FAIL" if any_accepted else ("INFO" if any_untestable and not any_accepted else "PASS")
    add(full_url, "WA-TLS-403", "SSL / TLS", "SSLv2, SSLv3, TLSv1.0 disabled",
        "High", "P1", result, "; ".join(f"{k}: {v}" for k, v in old_protocols.items()))

    # NOTE: WA-TLS-404 (weak cipher suites) is already fully handled above,
    # inside the `if ssl_cli: ... else: ...` block right after
    # run_ssl_cli_scan() - either a real PASS/FAIL/INFO from whichever SSL
    # CLI tool ran, or a MANUAL fallback with the exact command to run if
    # none is installed. A second, unconditional add(..., "WA-TLS-404",
    # ..., "MANUAL", ...) used to sit right here and silently OVERWRITE
    # that real result every single time (RESULTS is an append-only list -
    # see add()'s own definition - so this ran regardless of whether the
    # block above already produced a real PASS/FAIL), meaning WA-TLS-404
    # could never show anything but MANUAL even when nmap/sslyze/sslscan/
    # testssl.sh was installed and ran successfully. Removed.

    cert_text = None
    if _openssl_available():
        try:
            s_client = subprocess.run(
                ["openssl", "s_client", "-connect", f"{host}:{port}", "-servername", host],
                input=b"", capture_output=True, timeout=args.timeout)
            pem = s_client.stdout
            x509 = subprocess.run(["openssl", "x509", "-noout", "-text"], input=pem,
                                   capture_output=True, timeout=args.timeout)
            cert_text = x509.stdout.decode("utf-8", errors="replace")
        except Exception:
            cert_text = None

    if cert_text:
        km = re.search(r"Public-Key:\s*\((\d+)\s*bit\)", cert_text)
        key_bits = int(km.group(1)) if km else None
        is_ec = "id-ecPublicKey" in cert_text or "ECDSA" in cert_text
        min_ok = (key_bits and ((is_ec and key_bits >= 256) or (not is_ec and key_bits >= 2048)))
        add(full_url, "WA-TLS-405", "SSL / TLS", "Certificate key strength >= 2048-bit RSA / 256-bit ECC",
            "Medium", "P2", "PASS" if min_ok else "FAIL",
            f"Key type: {'EC' if is_ec else 'RSA/other'}, size: {key_bits or 'unknown'} bits")

        sigm = re.search(r"Signature Algorithm:\s*(\S+)", cert_text)
        sig_alg = sigm.group(1) if sigm else "unknown"
        weak_sig = any(w in sig_alg.lower() for w in ["md5", "sha1"])
        add(full_url, "WA-TLS-406", "SSL / TLS", "Certificate uses SHA-256+ signature algorithm",
            "Medium", "P2", "FAIL" if weak_sig else "PASS", f"Signature Algorithm: {sig_alg}")
    else:
        for cid, name in [("WA-TLS-405", "Certificate key strength >= 2048-bit RSA / 256-bit ECC"),
                           ("WA-TLS-406", "Certificate uses SHA-256+ signature algorithm")]:
            add(full_url, cid, "SSL / TLS", name, "Medium", "P2", "INFO",
                "Local 'openssl' CLI not available/failed - can't parse certificate details. "
                f"Run manually: openssl s_client -connect {host}:{port} -servername {host} | openssl x509 -noout -text")

    try:
        ctx = ssl.create_default_context()
        if args.insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=args.timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                der_chain = None
                try:
                    der_chain = ssock.session.get("peer_certificate_chain")
                except Exception:
                    pass
        add(full_url, "WA-TLS-407", "SSL / TLS", "Certificate chain complete - no missing intermediates",
            "Medium", "P2", "PASS",
            "Handshake completed with default trust store validation (chain resolves) - " +
            ("insecure mode was on, so this doesn't confirm trust." if args.insecure else
             "certificate chain is trusted by this machine's CA bundle."))
    except ssl.SSLCertVerificationError as e:
        add(full_url, "WA-TLS-407", "SSL / TLS", "Certificate chain complete - no missing intermediates",
            "Medium", "P2", "FAIL", f"Certificate verification failed: {e}")
    except Exception as e:
        add(full_url, "WA-TLS-407", "SSL / TLS", "Certificate chain complete - no missing intermediates",
            "Medium", "P2", "ERROR", str(e))

    hsts_header = ""
    r = raw_request(full_url, "GET", timeout=args.timeout, insecure=args.insecure)
    if not r.error:
        hsts_header = r.header("Strict-Transport-Security")
    preload_intent = "preload" in hsts_header.lower()
    preload_listed = None
    try:
        api = raw_request(f"https://hstspreload.org/api/v2/status?domain={host}", "GET", timeout=args.timeout)
        if not api.error and api.status == 200:
            data = json.loads(api.text())
            preload_listed = data.get("status")
    except Exception:
        preload_listed = None
    evidence = f"HSTS header includes 'preload': {preload_intent}."
    if preload_listed:
        evidence += f" hstspreload.org status: {preload_listed}."
        result = "PASS" if preload_listed == "preloaded" else "FAIL"
    else:
        evidence += " Could not reach hstspreload.org API to confirm actual list membership."
        result = "INFO" if preload_intent else "FAIL"
    add(full_url, "WA-TLS-408", "SSL / TLS", "HSTS preload list configured",
        "Medium", "P2", result, evidence)

    add(full_url, "WA-TLS-409", "SSL / TLS", "WebSocket endpoints use WSS not WS",
        "High", "P1", "MANUAL",
        "No websocket endpoint is known from a plain URL - identify ws:// vs wss:// usage via browser "
        "dev tools / Burp WebSockets history while using the app, then verify manually.")


# --------------------------------------------------------------------------
# 3. Clickjacking - WA-CS-161..165
# --------------------------------------------------------------------------

def check_clickjacking(full_url, headers_result):
    if headers_result.error:
        for cid, name in [
            ("WA-CS-161", "Clickjacking - basic UI redress attack (iframe overlay)"),
            ("WA-CS-162", "Clickjacking - form pre-fill attack"),
            ("WA-CS-163", "Clickjacking - frame-busting script bypass"),
            ("WA-CS-164", "Clickjacking - multistep attack (confirm + click)"),
            ("WA-CS-165", "Clickjacking - drag-and-drop UI attack"),
        ]:
            add(full_url, cid, "Clickjacking", name, "Medium", "P2", "ERROR", headers_result.error)
        return

    xfo = headers_result.header("X-Frame-Options")
    csp = headers_result.header("Content-Security-Policy")
    protected = (xfo.strip().upper() in ("DENY", "SAMEORIGIN")) or ("frame-ancestors" in csp.lower())
    add(full_url, "WA-CS-161", "Clickjacking", "Clickjacking - basic UI redress attack (iframe overlay)",
        "Medium", "P2", "PASS" if protected else "FAIL",
        f"X-Frame-Options: {xfo or 'missing'}, CSP frame-ancestors present: {'frame-ancestors' in csp.lower()}. " +
        ("Page can likely be framed - build an iframe PoC to confirm exploitability." if not protected else
         "Framing headers present - page is likely protected."))

    for cid, name in [
        ("WA-CS-162", "Clickjacking - form pre-fill attack"),
        ("WA-CS-163", "Clickjacking - frame-busting script bypass"),
        ("WA-CS-164", "Clickjacking - multistep attack (confirm + click)"),
        ("WA-CS-165", "Clickjacking - drag-and-drop UI attack"),
    ]:
        add(full_url, cid, "Clickjacking", name, "Medium", "P2", "MANUAL",
            "Needs an actual PoC HTML page + browser interaction to verify - not testable from headers alone.")


# --------------------------------------------------------------------------
# 4. CORS - WA-CS-158..160
# --------------------------------------------------------------------------

def check_cors(full_url, args):
    evil_origin = f"https://evil-cors-test-{rand_token(6)}.example"
    r1 = raw_request(full_url, "GET", extra_headers={"Origin": evil_origin},
                      timeout=args.timeout, insecure=args.insecure)
    if r1.error:
        for cid, name in [("WA-CS-158", "CORS - misconfig: wildcard/reflected origin trusts attacker"),
                           ("WA-CS-159", "CORS - null origin trusted (sandbox iframe bypass)"),
                           ("WA-CS-160", "CORS - intranet pivot via trusted whitelisted origin")]:
            add(full_url, cid, "CORS", name, "High", "P1", "ERROR", r1.error)
        return

    acao = r1.header("Access-Control-Allow-Origin")
    acac = r1.header("Access-Control-Allow-Credentials")
    reflected = acao == evil_origin
    wildcard_with_creds = acao == "*" and acac.lower() == "true"
    fail1 = reflected or wildcard_with_creds
    add(full_url, "WA-CS-158", "CORS", "CORS - misconfig: wildcard/reflected origin trusts attacker",
        "High", "P1", "FAIL" if fail1 else "PASS",
        f"Sent Origin: {evil_origin} -> Access-Control-Allow-Origin: {acao or 'none'}, "
        f"Access-Control-Allow-Credentials: {acac or 'none'}." +
        (" Arbitrary origin is reflected/trusted - likely exploitable." if fail1 else ""))

    r2 = raw_request(full_url, "GET", extra_headers={"Origin": "null"},
                      timeout=args.timeout, insecure=args.insecure)
    acao_null = r2.header("Access-Control-Allow-Origin") if not r2.error else ""
    null_trusted = acao_null.strip() == "null"
    add(full_url, "WA-CS-159", "CORS", "CORS - null origin trusted (sandbox iframe bypass)",
        "High", "P1", "FAIL" if null_trusted else "PASS",
        f"Sent Origin: null -> Access-Control-Allow-Origin: {acao_null or 'none'}." +
        (" 'null' origin is trusted - exploitable via sandboxed iframe/data: URI." if null_trusted else ""))

    add(full_url, "WA-CS-160", "CORS", "CORS - intranet pivot via trusted whitelisted origin",
        "High", "P1", "MANUAL",
        "Needs the app's actual whitelisted-origin list (e.g. internal subdomains) to test - "
        "can't be guessed generically. Review the CORS allow-list source/config manually.")


# --------------------------------------------------------------------------
# 5. Information Gathering - WA-OTG-273..282
# --------------------------------------------------------------------------

def check_information_gathering(full_url, headers_result, args):
    base = dir_of(full_url)

    add(full_url, "WA-OTG-273", "Information Gathering", "Conduct search engine recon (Google dorks, Shodan)",
        "Info", "P3", "MANUAL", "Needs external OSINT/search-engine/Shodan queries - not testable from the target directly.")

    server_hdr = headers_result.header("Server") if not headers_result.error else ""
    add(full_url, "WA-OTG-274", "Information Gathering", "Fingerprint web server (Server header, error pages)",
        "Low", "P3", "INFO", f"Server header: {server_hdr or 'not disclosed'}.")

    robots = raw_request(join_target(base, "/robots.txt"), "GET", timeout=args.timeout, insecure=args.insecure)
    sitemap = raw_request(join_target(base, "/sitemap.xml"), "GET", timeout=args.timeout, insecure=args.insecure)
    disallow_lines = []
    if not robots.error and robots.status == 200:
        disallow_lines = [l.strip() for l in robots.text().splitlines() if l.strip().lower().startswith("disallow")]
    sensitive_hint = any(re.search(r"admin|backup|config|private|internal|\.git|staging", l, re.I) for l in disallow_lines)
    add(full_url, "WA-OTG-275", "Information Gathering", "Review webserver metafiles (robots.txt, sitemap.xml)",
        "Low", "P3", "FAIL" if sensitive_hint else "INFO",
        f"robots.txt: {'200, ' + str(len(disallow_lines)) + ' Disallow entries' if not robots.error and robots.status == 200 else 'not found/error'}"
        f"{' (' + '; '.join(disallow_lines[:8]) + ')' if disallow_lines else ''}. "
        f"sitemap.xml: {'200' if not sitemap.error and sitemap.status == 200 else 'not found/error'}." +
        (" robots.txt Disallow list itself hints at sensitive paths - review them directly." if sensitive_hint else ""))

    for cid, name in [("WA-OTG-276", "Enumerate application entry points (all params/forms)"),
                       ("WA-OTG-277", "Map execution paths through application")]:
        add(full_url, cid, "Information Gathering", name, "Info", "P3", "MANUAL",
            "Needs full crawling/spidering (Burp Spider, katana, hakrawler) across the whole app - a single-page fetch isn't representative.")

    body_text = headers_result.text() if not headers_result.error else ""
    xpb = headers_result.header("X-Powered-By") if not headers_result.error else ""
    cookies_raw = headers_result.headers if not headers_result.error else {}
    cookie_names = []
    for k, v in cookies_raw.items():
        if k.lower() == "set-cookie":
            m = re.match(r"([^=]+)=", v)
            if m:
                cookie_names.append(m.group(1))
    fw_hints = []
    if xpb:
        fw_hints.append(f"X-Powered-By: {xpb}")
    for cn in cookie_names:
        if cn.upper() in ("PHPSESSID",):
            fw_hints.append("PHP (PHPSESSID cookie)")
        elif cn.upper() in ("JSESSIONID",):
            fw_hints.append("Java/JSP (JSESSIONID cookie)")
        elif "laravel_session" in cn.lower():
            fw_hints.append("Laravel (laravel_session cookie)")
        elif "django" in cn.lower() or "csrftoken" in cn.lower():
            fw_hints.append("Django (django/csrftoken cookie)")
    gen_match = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', body_text, re.I)
    if gen_match:
        fw_hints.append(f"meta generator tag: {gen_match.group(1)}")
    add(full_url, "WA-OTG-278", "Information Gathering", "Fingerprint web application framework",
        "Low", "P3", "INFO", "; ".join(fw_hints) if fw_hints else "No obvious framework fingerprint found in headers/cookies/homepage.")

    cdn_hints = []
    if not headers_result.error:
        for hk, hv in headers_result.headers.items():
            hk_l = hk.lower()
            if hk_l in CDN_WAF_HEADER_HINTS:
                for needle, label in CDN_WAF_HEADER_HINTS[hk_l].items():
                    if needle == "" or needle in hv.lower():
                        cdn_hints.append(f"{label} (via {hk}: {hv[:60]})")
    add(full_url, "WA-OTG-279", "Information Gathering", "Map application architecture (CDN, WAF, LB, proxy layers)",
        "Info", "P3", "INFO", "; ".join(cdn_hints) if cdn_hints else "No CDN/WAF/proxy header hints detected on this response.")

    dep_hits = []
    for path in DEPENDENCY_PROBES:
        rr = raw_request(join_target(base, path), "GET", timeout=args.timeout, insecure=args.insecure)
        if not rr.error and rr.status == 200:
            dep_hits.append(path)
    add(full_url, "WA-OTG-280", "Information Gathering", "Identify application dependencies (package.json, Gemfile, pom)",
        "Low", "P3", "FAIL" if dep_hits else "PASS",
        f"Publicly accessible dependency manifest(s): {', '.join(dep_hits)}" if dep_hits else
        f"None of the probed manifest paths ({', '.join(DEPENDENCY_PROBES)}) are publicly accessible at the site root.")

    emails = sorted(set(re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", body_text)))[:10]
    add(full_url, "WA-OTG-281", "Information Gathering", "Harvest emails, usernames, phone numbers from app",
        "Info", "P3", "INFO" if emails else "MANUAL",
        (f"Email address(es) found on this single page: {', '.join(emails)}. "
         "This is only a spot-check of one page, not a full harvest." if emails else
         "None found on this single page - a full harvest needs crawling the whole app."))

    bucket_hits = sorted(set(m for pat in CLOUD_BUCKET_PATTERNS for m in re.findall(pat, body_text, re.I)))[:10]
    add(full_url, "WA-OTG-282", "Information Gathering", "Identify cloud storage buckets (S3, GCS, Azure Blob)",
        "High", "P1", "INFO" if bucket_hits else "PASS",
        (f"Cloud storage reference(s) found on this page: {', '.join(bucket_hits)} - check each manually for "
         "public read/write/list access." if bucket_hits else "No cloud storage bucket URLs referenced on this single page."))


# --------------------------------------------------------------------------
# 6. Configuration Testing - WA-OTG-283..294
# --------------------------------------------------------------------------

def _port_scan(host, ports, timeout=2.0):
    open_ports = []
    for port in ports:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                open_ports.append(port)
        except Exception:
            pass
    return open_ports


def check_configuration(full_url, headers_result, hdr_curl_block, args):
    base = dir_of(full_url)
    host = urlparse(full_url).hostname

    if args.port_scan:
        open_ports = _port_scan(host, COMMON_ADMIN_PORTS, timeout=min(args.timeout, 3))
        add(full_url, "WA-OTG-283", "Configuration Testing", "Test network/infrastructure config (exposed admin ports)",
            "High", "P1", "FAIL" if open_ports else "PASS",
            f"Common admin/DB ports probed ({', '.join(map(str, COMMON_ADMIN_PORTS))}). "
            f"Open: {', '.join(map(str, open_ports)) if open_ports else 'none'}.")
    else:
        add(full_url, "WA-OTG-283", "Configuration Testing", "Test network/infrastructure config (exposed admin ports)",
            "High", "P1", "MANUAL", "Skipped by default (noisier scan). Re-run with --port-scan, or use nmap directly.")

    add(full_url, "WA-OTG-284", "Configuration Testing", "Test application platform configuration (default creds)",
        "High", "P1", "MANUAL", "Needs a known login endpoint + credential list - use hydra/manual testing against the actual login form.")

    bak_hits = []
    for path in BACKUP_EXT_PROBES:
        rr = raw_request(join_target(base, path), "GET", timeout=args.timeout, insecure=args.insecure)
        if not rr.error and rr.status == 200:
            bak_hits.append(path)
    add(full_url, "WA-OTG-285", "Configuration Testing", "Test file extension handling (.bak .old .orig .swp)",
        "High", "P1", "FAIL" if bak_hits else "PASS",
        f"Accessible: {', '.join(bak_hits)}" if bak_hits else f"None of {', '.join(BACKUP_EXT_PROBES)} accessible at site root.")

    backup_hits = []
    for path in BACKUP_FILE_PROBES:
        rr = raw_request(join_target(base, path), "GET", timeout=args.timeout, insecure=args.insecure)
        if not rr.error and rr.status == 200:
            backup_hits.append(path)
    add(full_url, "WA-OTG-286", "Configuration Testing", "Review backup and unreferenced files",
        "High", "P1", "FAIL" if backup_hits else "PASS",
        f"Accessible: {', '.join(backup_hits)}" if backup_hits else f"None of {', '.join(BACKUP_FILE_PROBES)} accessible at site root.")

    admin_hits = []
    for path in ADMIN_PATH_PROBES:
        rr = raw_request(join_target(base, path), "GET", timeout=args.timeout, insecure=args.insecure)
        if not rr.error and rr.status == 200:
            admin_hits.append(f"{path} (200 - publicly reachable)")
        elif not rr.error and rr.status in (401, 403):
            admin_hits.append(f"{path} ({rr.status} - exists, appears protected)")
    add(full_url, "WA-OTG-287", "Configuration Testing", "Enumerate infrastructure and admin interfaces",
        "Critical", "P1", "FAIL" if any("200" in h for h in admin_hits) else ("INFO" if admin_hits else "PASS"),
        "; ".join(admin_hits) if admin_hits else f"None of {', '.join(ADMIN_PATH_PROBES)} responded at site root.")

    ropts = raw_request(base, "OPTIONS", timeout=args.timeout, insecure=args.insecure)
    allow = ropts.header("Allow") if not ropts.error else ""
    risky_methods = [m for m in ["PUT", "DELETE", "TRACE", "CONNECT"] if m in allow.upper()]
    add(full_url, "WA-OTG-288", "Configuration Testing", "Test HTTP methods (PUT/DELETE/OPTIONS/TRACE)",
        "Medium", "P2", "FAIL" if risky_methods else ("ERROR" if ropts.error else "PASS"),
        (ropts.error or f"OPTIONS {base} -> Allow: {allow or 'not disclosed'}." +
         (f" Risky method(s) advertised: {', '.join(risky_methods)} - verify each is actually usable." if risky_methods else "")))

    # Reported directly, with a screenshot: "output is not a command line
    # or request response bases it just a statement please fix" - this and
    # WA-OTG-294 below re-read the SAME response check_security_headers()
    # already fetched (WA-OTG-289/294 are the OWASP Testing Guide IDs for
    # the identical HSTS/CSP header checks WA-HDR-395/392 cover under the
    # master checklist's own ID scheme - no need to re-request the page),
    # but used to only print a bare "(same check as WA-HDR-395)" sentence
    # instead of the real curl command + response that check_security_headers()
    # already captured for that exact request. hdr_curl_block (threaded in
    # from run_full_suite, sourced from check_security_headers()'s return
    # value) is that same real evidence block, reused here at zero extra
    # request cost instead of shelling out to curl a second time.
    hsts_for_289 = headers_result.header("Strict-Transport-Security") if not headers_result.error else ""
    add(full_url, "WA-OTG-289", "Configuration Testing", "Test HTTP Strict Transport Security (HSTS present?)",
        "Medium", "P2", "PASS" if hsts_for_289 else "FAIL",
        (f"Strict-Transport-Security: {hsts_for_289}" if hsts_for_289 else
         "CONFIRMED BY: no Strict-Transport-Security header present in the response headers below.") + hdr_curl_block)

    cdxml = raw_request(join_target(base, "/crossdomain.xml"), "GET", timeout=args.timeout, insecure=args.insecure)
    cap = raw_request(join_target(base, "/clientaccesspolicy.xml"), "GET", timeout=args.timeout, insecure=args.insecure)
    findings = []
    if not cdxml.error and cdxml.status == 200:
        wide_open = "domain=\"*\"" in cdxml.text() or "domain='*'" in cdxml.text()
        findings.append(f"crossdomain.xml present{' with wildcard domain (FAIL)' if wide_open else ''}")
    if not cap.error and cap.status == 200:
        wide_open2 = "domain=\"*\"" in cap.text() or "domain='*'" in cap.text()
        findings.append(f"clientaccesspolicy.xml present{' with wildcard domain (FAIL)' if wide_open2 else ''}")
    any_wildcard = any("wildcard" in f for f in findings)
    add(full_url, "WA-OTG-290", "Configuration Testing", "Test RIA cross domain policy (crossdomain.xml / clientaccesspolicy)",
        "Medium", "P2", "FAIL" if any_wildcard else ("INFO" if findings else "PASS"),
        "; ".join(findings) if findings else "Neither crossdomain.xml nor clientaccesspolicy.xml found - not applicable.")

    add(full_url, "WA-OTG-291", "Configuration Testing", "Test file permissions on web server",
        "Medium", "P2", "MANUAL",
        "Not testable remotely with certainty - see the .git/.svn/.DS_Store exposure check (WA-SS-059) for a related "
        "automated signal, but full file-permission review needs server access or a dedicated misconfig scanner.")

    cname_info = _resolve_cname(host)
    dangling_hint = None
    if cname_info and cname_info[1] is None:
        for svc in ["github.io", "herokuapp.com", "s3.amazonaws.com", "azurewebsites.net", "cloudfront.net",
                    "trafficmanager.net", "readthedocs.io", "readme.io"]:
            if svc in cname_info[0]:
                dangling_hint = svc
                break
    add(full_url, "WA-OTG-292", "Configuration Testing", "Test subdomain takeover",
        "High", "P1",
        "FAIL" if dangling_hint else ("MANUAL" if not cname_info else "PASS"),
        (f"CNAME -> {cname_info[0]}, resolves: {'no (NXDOMAIN/unresolvable)' if cname_info and cname_info[1] is None else 'yes'}."
         + (f" Points at a known takeover-prone service ({dangling_hint}) and doesn't resolve - investigate manually." if dangling_hint else ""))
        if cname_info else "No CNAME found for this host (nslookup unavailable or host has no CNAME) - full subdomain "
                            "enumeration across the whole domain still needs a dedicated tool (subfinder/amass + dnsx).")

    add(full_url, "WA-OTG-293", "Configuration Testing", "Test cloud storage permissions (public buckets/blobs)",
        "High", "P1", "MANUAL",
        "See WA-OTG-282 for buckets referenced by this page - check each with a HEAD/GET/list request manually or via "
        "a bucket-permission tool (s3scanner). Can't be tested generically without a bucket name.")

    csp_for_294 = headers_result.header("Content-Security-Policy") if not headers_result.error else ""
    if not csp_for_294:
        csp294_result, csp294_evidence = "FAIL", (
            "CONFIRMED BY: no Content-Security-Policy header present in the response headers below.")
    elif "unsafe-inline" in csp_for_294:
        csp294_result, csp294_evidence = "FAIL", (
            f"CONFIRMED BY: CSP contains 'unsafe-inline' - full header value: {csp_for_294[:300]}")
    else:
        csp294_result, csp294_evidence = "PASS", f"CSP: {csp_for_294[:300]}"
    add(full_url, "WA-OTG-294", "Configuration Testing", "Test content security policy (CSP header analysis)",
        "Medium", "P2", csp294_result, csp294_evidence + hdr_curl_block)


def _resolve_cname(host):
    """Returns (cname_target, resolved_ip_or_None) using nslookup, or None if unavailable."""
    try:
        out = subprocess.run(["nslookup", "-type=CNAME", host], capture_output=True, timeout=5,
                              text=True).stdout
        m = re.search(r"canonical name = (\S+)\.?", out)
        if not m:
            return None
        cname = m.group(1).rstrip(".")
        try:
            socket.gethostbyname(cname)
            return (cname, True)
        except Exception:
            return (cname, None)
    except Exception:
        return None


# --------------------------------------------------------------------------
# 7. Session Management Testing - WA-OTG-315..323
# --------------------------------------------------------------------------

def check_session_management(full_url, headers_result, args):
    if headers_result.error:
        for cid, name in [
            ("WA-OTG-315", "Test session management schema (token analysis)"),
            ("WA-OTG-316", "Test cookie attributes (Secure, HttpOnly, SameSite, Path)"),
            ("WA-OTG-317", "Test session fixation (token recycled after login)"),
            ("WA-OTG-318", "Test exposed session variables (in URL, logs)"),
            ("WA-OTG-319", "Test CSRF protection (token validation, SameSite)"),
            ("WA-OTG-320", "Test logout functionality (server-side session invalidation)"),
            ("WA-OTG-321", "Test session timeout (idle + absolute)"),
            ("WA-OTG-322", "Test session puzzling / overloading"),
            ("WA-OTG-323", "Test session hijacking (token theft via XSS/MitM)"),
        ]:
            add(full_url, cid, "Session Management Testing", name, "High", "P1", "ERROR", headers_result.error)
        return

    # Real "$ curl ..." command + the actual Set-Cookie header(s) it got
    # back, attached as evidence for the two checks below that are
    # DERIVED from those headers (WA-OTG-315/316) - fixed after being
    # reported directly, with a screenshot showing a Vulnerable cookie-
    # attributes finding with no output captured: "n o out put captured
    # you can use curl heders command to collect the cookies outut".
    # Previously this function only ever reused `headers_result` (the
    # Python-internal HttpResult object from check_security_headers()) to
    # DECIDE the PASS/FAIL verdict, but never ran/attached the actual curl
    # command+output the other HTTP-header checks (WA-HDR-392 etc.) show
    # as evidence - so a cookie-attributes FAIL had no reproducible
    # command a reviewer could re-run to see the real Set-Cookie value(s)
    # themselves, just the derived "X missing Secure/HttpOnly" sentence.
    curl_result = None if getattr(args, "no_cli_tools", False) else run_curl_headers(
        full_url, timeout=args.timeout, insecure=args.insecure)
    curl_block = _format_cmd_block(curl_result[0], curl_result[1]) if curl_result else ""

    set_cookies = [v for k, v in headers_result.headers.items() if k.lower() == "set-cookie"]
    cookie_names = [re.match(r"([^=]+)=", c).group(1) for c in set_cookies if re.match(r"([^=]+)=", c)]
    add(full_url, "WA-OTG-315", "Session Management Testing", "Test session management schema (token analysis)",
        "High", "P1", "INFO" if cookie_names else "MANUAL",
        (f"Cookie(s) seen on this response: {', '.join(cookie_names)}. Full entropy/predictability analysis needs "
         "multiple samples across sessions - out of scope for a single request." if cookie_names else
         "No Set-Cookie on this response - session may be issued after login; re-run this check on an authenticated page.")
        + curl_block)

    if set_cookies:
        issues = []
        is_https = full_url.startswith("https")
        for c in set_cookies:
            name = re.match(r"([^=]+)=", c).group(1)
            missing = []
            if is_https and "secure" not in c.lower():
                missing.append("Secure")
            if "httponly" not in c.lower():
                missing.append("HttpOnly")
            if "samesite" not in c.lower():
                missing.append("SameSite")
            if missing:
                issues.append(f"{name} missing {'/'.join(missing)}")
        add(full_url, "WA-OTG-316", "Session Management Testing", "Test cookie attributes (Secure, HttpOnly, SameSite, Path)",
            "Medium", "P2", "FAIL" if issues else "PASS",
            ("; ".join(issues) if issues else f"All cookie(s) ({', '.join(cookie_names)}) have Secure/HttpOnly/SameSite set appropriately.")
            + curl_block)
    else:
        add(full_url, "WA-OTG-316", "Session Management Testing", "Test cookie attributes (Secure, HttpOnly, SameSite, Path)",
            "Medium", "P2", "INFO", "No cookies set on this response to evaluate." + curl_block)

    add(full_url, "WA-OTG-317", "Session Management Testing", "Test session fixation (token recycled after login)",
        "High", "P1", "MANUAL", "Needs an authenticated login flow (capture pre-login vs post-login session token) - not testable from a single unauthenticated request.")

    parsed = urlparse(full_url)
    session_in_url = bool(re.search(r"(sid|session|token|phpsessid|jsessionid)=", parsed.query, re.I))
    add(full_url, "WA-OTG-318", "Session Management Testing", "Test exposed session variables (in URL, logs)",
        "Medium", "P2", "FAIL" if session_in_url else "PASS",
        f"Query string: {parsed.query or '(none)'}." +
        (" Session-like parameter name found in the URL - session tokens in URLs leak via logs/referrer/history." if session_in_url else ""))

    body_text = headers_result.text()
    forms = re.findall(r"<form\b[^>]*>(.*?)</form>", body_text, re.I | re.S)
    if forms:
        token_pattern = re.compile(r'name=["\'][^"\']*(csrf|token|authenticity)[^"\']*["\']', re.I)
        forms_missing_token = sum(1 for f in forms if not token_pattern.search(f))
        add(full_url, "WA-OTG-319", "Session Management Testing", "Test CSRF protection (token validation, SameSite)",
            "High", "P1", "FAIL" if forms_missing_token else "PASS",
            f"{len(forms)} <form> tag(s) found on this page, {forms_missing_token} with no obvious CSRF/token hidden "
            "field by name. This is a naming heuristic only - a form can still be protected via SameSite cookies or a "
            "custom header checked server-side; verify manually before reporting.")
    else:
        add(full_url, "WA-OTG-319", "Session Management Testing", "Test CSRF protection (token validation, SameSite)",
            "High", "P1", "INFO", "No <form> tags found on this page to inspect.")

    for cid, name in [
        ("WA-OTG-320", "Test logout functionality (server-side session invalidation)"),
        ("WA-OTG-321", "Test session timeout (idle + absolute)"),
        ("WA-OTG-322", "Test session puzzling / overloading"),
        ("WA-OTG-323", "Test session hijacking (token theft via XSS/MitM)"),
    ]:
        add(full_url, cid, "Session Management Testing", name, "High", "P1", "MANUAL",
            "Needs an authenticated session and a multi-step interaction over time - not testable from a single unauthenticated request.")


# --------------------------------------------------------------------------
# 7b. Client-Side Testing - WA-OTG-366 (static analysis only - no browser JS
#     execution, so this is automatable without ever needing a login: "never
#     take the credetils also to navigate inside")
# --------------------------------------------------------------------------

_SENSITIVE_KEY_PATTERN = re.compile(
    r"(token|jwt|auth|session|password|passwd|secret|apikey|api_key|ssn|creditcard|card_?number|\bpin\b)",
    re.IGNORECASE)
_STORAGE_CALL_PATTERN = re.compile(
    r"\b(?:localStorage|sessionStorage)\s*\.\s*setItem\s*\(\s*(['\"])(.*?)\1", re.IGNORECASE)
_STORAGE_USAGE_PATTERN = re.compile(r"\b(?:localStorage|sessionStorage)\b", re.IGNORECASE)


def check_client_storage(full_url, headers_result, args):
    """WA-OTG-366 - Test local storage / sessionStorage for sensitive data.
    Scans the page's inline <script> blocks and same-origin external JS it
    links to for localStorage/sessionStorage.setItem() calls, flagging
    sensitive-looking key names (token/session/auth/password/...). Can't
    see storage written only after login or by obfuscated/bundled code -
    those cases fall back to MANUAL/INFO rather than a false PASS."""
    if headers_result.error:
        add(full_url, "WA-OTG-366", "Client-Side Testing", "Test local storage / sessionStorage for sensitive data",
            "Medium", "P2", "ERROR", headers_result.error)
        return

    body_text = headers_result.text()
    combined_text = body_text
    combined_sources = ["page HTML/inline scripts"]

    script_srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', body_text, re.IGNORECASE)
    page_host = urlparse(full_url).hostname
    fetched = 0
    for src in script_srcs:
        if fetched >= 5:
            break
        js_url = urljoin(full_url, src)
        if urlparse(js_url).hostname != page_host:
            continue  # same-origin only - no reason to pull third-party/CDN JS for this heuristic
        r_js = raw_request(js_url, "GET", timeout=args.timeout, insecure=args.insecure)
        fetched += 1
        if not r_js.error and r_js.status and r_js.status < 400:
            combined_text += "\n" + r_js.text()
            combined_sources.append(js_url)

    matches = _STORAGE_CALL_PATTERN.findall(combined_text)
    keys_found = [m[1] for m in matches]
    sensitive_keys = sorted(set(k for k in keys_found if _SENSITIVE_KEY_PATTERN.search(k)))
    any_usage = bool(_STORAGE_USAGE_PATTERN.search(combined_text))
    sources_str = ", ".join(combined_sources)

    if sensitive_keys:
        add(full_url, "WA-OTG-366", "Client-Side Testing", "Test local storage / sessionStorage for sensitive data",
            "Medium", "P2", "FAIL",
            f"localStorage/sessionStorage.setItem() call(s) with sensitive-looking key name(s) found: "
            f"{', '.join(sensitive_keys)}. Scanned: {sources_str}. Confirm in browser DevTools > Application > "
            "Storage that the VALUE (not just the key name) actually holds sensitive data before reporting.")
    elif keys_found:
        add(full_url, "WA-OTG-366", "Client-Side Testing", "Test local storage / sessionStorage for sensitive data",
            "Medium", "P2", "INFO",
            f"localStorage/sessionStorage.setItem() call(s) found but key name(s) don't match common sensitive "
            f"patterns: {', '.join(sorted(set(keys_found))[:15])}. Scanned: {sources_str}. Static key-name "
            "matching only - verify actual stored values manually.")
    elif any_usage:
        add(full_url, "WA-OTG-366", "Client-Side Testing", "Test local storage / sessionStorage for sensitive data",
            "Medium", "P2", "MANUAL",
            f"localStorage/sessionStorage API is referenced in scanned source ({sources_str}) but with a dynamic/"
            "non-literal key name this static scan can't read - inspect via browser DevTools > Application > "
            "Storage while using the app to see what's actually stored.")
    else:
        add(full_url, "WA-OTG-366", "Client-Side Testing", "Test local storage / sessionStorage for sensitive data",
            "Medium", "P2", "INFO",
            f"No localStorage/sessionStorage usage found in this single unauthenticated page's static HTML/inline "
            f"scripts{f' or {fetched} same-origin external JS file(s)' if fetched else ''}. Static analysis of one "
            "unauthenticated page only - usage added after login, in bundled/minified/obfuscated JS, or on other "
            "pages can't be ruled out this way. Verify via browser DevTools during manual testing for full coverage.")


# --------------------------------------------------------------------------
# 8. Email Security - WA-MAIL-410..413
# --------------------------------------------------------------------------

def _nslookup_txt(name):
    try:
        out = subprocess.run(["nslookup", "-type=TXT", name], capture_output=True, timeout=6, text=True).stdout
        return re.findall(r'"([^"]*)"', out)
    except Exception:
        return None


def check_email_security(full_url, args):
    host = urlparse(full_url).hostname
    if not host:
        return
    txts = _nslookup_txt(host)
    if txts is None:
        for cid, name in [("WA-MAIL-410", "SPF record present and uses hard fail (-all)"),
                           ("WA-MAIL-411", "DMARC policy configured (reject or quarantine)"),
                           ("WA-MAIL-412", "DKIM signing configured and valid"),
                           ("WA-MAIL-413", "Email spoofing possible if SPF/DMARC absent or weak")]:
            add(full_url, cid, "Email Security", name, "Medium", "P2", "INFO",
                "'nslookup' not available on this machine - can't query DNS TXT records. Run manually: "
                f"nslookup -type=TXT {host}  and  nslookup -type=TXT _dmarc.{host}")
        return

    spf = next((t for t in txts if t.lower().startswith("v=spf1")), None)
    spf_hard_fail = bool(spf and "-all" in spf)
    add(full_url, "WA-MAIL-410", "Email Security", "SPF record present and uses hard fail (-all)",
        "Medium", "P2", "PASS" if spf_hard_fail else ("FAIL" if spf else "FAIL"),
        f"SPF: {spf or 'no v=spf1 TXT record found'}." +
        ("" if spf_hard_fail else (" Uses soft-fail/neutral/pass instead of -all." if spf else " No SPF record at all.")))

    dmarc_txts = _nslookup_txt(f"_dmarc.{host}") or []
    dmarc = next((t for t in dmarc_txts if t.lower().startswith("v=dmarc1")), None)
    pm = re.search(r"p=(\w+)", dmarc) if dmarc else None
    policy = pm.group(1).lower() if pm else None
    dmarc_ok = policy in ("reject", "quarantine")
    add(full_url, "WA-MAIL-411", "Email Security", "DMARC policy configured (reject or quarantine)",
        "Medium", "P2", "PASS" if dmarc_ok else "FAIL",
        f"DMARC: {dmarc or 'no v=DMARC1 TXT record found at _dmarc.' + host}." +
        (f" Policy: p={policy}." if policy else ""))

    dkim_found = None
    selectors_to_try = list(COMMON_DKIM_SELECTORS) + list(args.dkim_selector or [])
    for sel in selectors_to_try:
        dkim_txts = _nslookup_txt(f"{sel}._domainkey.{host}") or []
        if any(t.lower().startswith("v=dkim1") or "p=" in t.lower() for t in dkim_txts):
            dkim_found = sel
            break
    add(full_url, "WA-MAIL-412", "Email Security", "DKIM signing configured and valid",
        "Medium", "P2", "PASS" if dkim_found else "MANUAL",
        (f"Found a DKIM record under selector '{dkim_found}'." if dkim_found else
         f"No DKIM record found under common selectors ({', '.join(selectors_to_try)}). DKIM selectors are "
         "provider-specific and not guessable in general - confirm the real selector (check a raw email's "
         "DKIM-Signature header) and re-check with --dkim-selector <name>."))

    spoof_risk = (not spf_hard_fail) and (not dmarc_ok)
    add(full_url, "WA-MAIL-413", "Email Security", "Email spoofing possible if SPF/DMARC absent or weak",
        "High", "P1", "FAIL" if spoof_risk else "PASS",
        f"Derived from SPF (hard fail: {spf_hard_fail}) and DMARC (policy: {policy or 'none'}) above." +
        (" Both are weak/absent - spoofed mail as this domain is plausible; verify with a tool like mailspoof/spf-record.com." if spoof_risk else ""))


# --------------------------------------------------------------------------
# 9. Information Disclosure - WA-SS-055..059 (reuses several checks above)
# --------------------------------------------------------------------------

def check_information_disclosure(full_url, headers_result, args, hdr400_evidence, hdr401_evidence, otg286_evidence):
    base = dir_of(full_url)

    trace_fail = "FAIL" in [r["result"] for r in RESULTS if r["id"] == "WA-HDR-400" and r["url"] == full_url]
    add(full_url, "WA-SS-055", "Information Disclosure", "Information disclosure in error messages (stack trace)",
        "Medium", "P2", "FAIL" if trace_fail else "PASS",
        "(same underlying check as WA-HDR-400) " + hdr400_evidence)

    dbg_hits = []
    for path in DEBUG_PAGES:
        rr = raw_request(join_target(base, path), "GET", timeout=args.timeout, insecure=args.insecure)
        if not rr.error and rr.status == 200:
            dbg_hits.append(path)
    add(full_url, "WA-SS-056", "Information Disclosure", "Info disclosure - debug page (phpinfo/rails debug)",
        "High", "P1", "FAIL" if dbg_hits else "PASS",
        f"Accessible: {', '.join(dbg_hits)}" if dbg_hits else f"None of {', '.join(DEBUG_PAGES)} accessible at site root.")

    backup_fail = any(r["result"] == "FAIL" for r in RESULTS if r["id"] in ("WA-OTG-285", "WA-OTG-286") and r["url"] == full_url)
    add(full_url, "WA-SS-057", "Information Disclosure", "Info disclosure - source code via backup files",
        "High", "P1", "FAIL" if backup_fail else "PASS",
        "(same underlying probes as WA-OTG-285/286) " + otg286_evidence)

    add(full_url, "WA-SS-058", "Information Disclosure", "Info disclosure - version via response headers",
        "Low", "P3",
        next((r["result"] for r in RESULTS if r["id"] == "WA-HDR-401" and r["url"] == full_url), "INFO"),
        "(same underlying check as WA-HDR-401) " + hdr401_evidence)

    git_hits = []
    for path in GIT_SVN_PROBES:
        rr = raw_request(join_target(base, path), "GET", timeout=args.timeout, insecure=args.insecure)
        if not rr.error and rr.status == 200:
            git_hits.append(path)
    add(full_url, "WA-SS-059", "Information Disclosure", "Info disclosure - sensitive data in git/svn/.DS_Store",
        "High", "P1", "FAIL" if git_hits else "PASS",
        f"Accessible: {', '.join(git_hits)} - clone/extract these to recover source (e.g. git-dumper for /.git/)." if git_hits
        else f"None of {', '.join(GIT_SVN_PROBES)} accessible at site root.")


# --------------------------------------------------------------------------
# 10. HTTP Host Header Attacks - WA-ADV-218..224
# --------------------------------------------------------------------------

# --------------------------------------------------------------------------
# Access Control / Authorization (2-account) - WA-OTG-312, WA-SS-071,
# WA-OTG-314. Opt-in only, via --account1-cookie / --account2-cookie -
# this script NEVER logs in, brute-forces, or harvests credentials itself.
# Requested directly: "where ever required the two account ask as input
# for check ... never take the credetils also to navigate inside" - so
# these flags only ever hold a session cookie the operator already has
# from logging in themselves; the cookie value itself is never written to
# evidence/JSON/CSV/screenshots, only pass/fail comparison data is.
# --------------------------------------------------------------------------

def _fetch_with_cookie(url, cookie, timeout, insecure):
    if not cookie:
        return raw_request(url, "GET", timeout=timeout, insecure=insecure)
    return raw_request(url, "GET", extra_headers={"Cookie": cookie}, timeout=timeout, insecure=insecure)


def _resp_signature(r):
    if not r or r.error:
        return None
    return (r.status, len(r.body), hashlib.sha256(r.body).hexdigest()[:12])


def check_access_control_2fa(full_url, args):
    acct1_cookie = getattr(args, "account1_cookie", None)
    acct2_cookie = getattr(args, "account2_cookie", None)
    acct1_label = getattr(args, "account1_label", None) or "Account 1"
    acct2_label = getattr(args, "account2_label", None) or "Account 2"

    if not acct1_cookie and not acct2_cookie:
        for cid, cat, name in [
            ("WA-OTG-312", "Authorization Testing", "Test bypassing authorization schema (force browse)"),
            ("WA-SS-071", "Access Control", "Horizontal privilege escalation (access another user data)"),
            ("WA-OTG-314", "Authorization Testing", "Test insecure direct object references (IDOR)"),
        ]:
            add(full_url, cid, cat, name, "Critical", "P1", "MANUAL",
                "Needs an authenticated session to test - re-run with --cookie \"sessionid=...\" (this also "
                "authenticates every other check in the suite) and add --cookie2 \"sessionid=...\" (a SECOND, "
                "different account's own session) for the two-account IDOR/horizontal-escalation checks. Only "
                "pass a session cookie YOU already obtained by logging in yourself - this script never attempts "
                "to log in, guess, or harvest credentials.")
        return

    unauth = raw_request(full_url, "GET", timeout=args.timeout, insecure=args.insecure)
    acct1 = _fetch_with_cookie(full_url, acct1_cookie, args.timeout, args.insecure) if acct1_cookie else None

    if acct1_cookie and acct1 and not acct1.error and not unauth.error:
        sig_unauth, sig_acct1 = _resp_signature(unauth), _resp_signature(acct1)
        looks_same = bool(sig_unauth and sig_acct1 and sig_unauth[1:] == sig_acct1[1:])
        add(full_url, "WA-OTG-312", "Authorization Testing", "Test bypassing authorization schema (force browse)",
            "Critical", "P1", "FAIL" if looks_same else "PASS",
            f"Unauthenticated: HTTP {unauth.status}, {len(unauth.body)} bytes. With {acct1_label} session: "
            f"HTTP {acct1.status}, {len(acct1.body)} bytes." +
            (f" Both responses are byte-for-byte identical (same length+hash) - if this page is meant to require "
             f"login, it's reachable without one." if looks_same else
             " Responses differ between unauthenticated and authenticated requests - this page does appear to "
             "gate its content on the session."))
    else:
        add(full_url, "WA-OTG-312", "Authorization Testing", "Test bypassing authorization schema (force browse)",
            "Critical", "P1", "MANUAL" if not acct1_cookie else "ERROR",
            "Needs --cookie to compare against an unauthenticated request." if not acct1_cookie
            else ((unauth.error or (acct1.error if acct1 else "")) or "Could not complete both requests."))

    if not acct2_cookie:
        for cid, cat, name in [
            ("WA-SS-071", "Access Control", "Horizontal privilege escalation (access another user data)"),
            ("WA-OTG-314", "Authorization Testing", "Test insecure direct object references (IDOR)"),
        ]:
            add(full_url, cid, cat, name, "Critical", "P1", "MANUAL",
                f"Needs a SECOND account's session too - re-run with --cookie2 \"sessionid=...\" to test "
                f"whether {acct2_label} can see {acct1_label}'s content at this same URL.")
        return

    acct2 = _fetch_with_cookie(full_url, acct2_cookie, args.timeout, args.insecure)
    if acct1 is None and acct1_cookie:
        acct1 = _fetch_with_cookie(full_url, acct1_cookie, args.timeout, args.insecure)

    if acct1 and acct2 and not acct1.error and not acct2.error:
        sig1, sig2 = _resp_signature(acct1), _resp_signature(acct2)
        identical = bool(sig1 and sig2 and sig1[1:] == sig2[1:])
        evidence = (f"{acct1_label}: HTTP {acct1.status}, {len(acct1.body)} bytes. "
                    f"{acct2_label}: HTTP {acct2.status}, {len(acct2.body)} bytes.")
        if identical:
            result = "MANUAL"
            evidence += (f" Both accounts see byte-for-byte identical content (same length+hash) at this exact "
                         f"URL. If this URL/resource is meant to be specific to {acct1_label} (contains an "
                         f"account-specific ID, filename, or similar in the path/query), then {acct2_label} "
                         "successfully viewing it is a strong horizontal-privilege-escalation / IDOR indicator - "
                         "confirm the resource IS account-specific (not a shared/public page) before reporting.")
        else:
            result = "PASS"
            evidence += " Responses differ between the two accounts - no evidence of cross-account access at this URL."
        add(full_url, "WA-SS-071", "Access Control", "Horizontal privilege escalation (access another user data)",
            "Critical", "P1", result, evidence)
        add(full_url, "WA-OTG-314", "Authorization Testing", "Test insecure direct object references (IDOR)",
            "Critical", "P1", result, evidence)
    else:
        err = ((acct1.error if acct1 and acct1.error else "") or (acct2.error if acct2 and acct2.error else "")
               or "Could not complete both authenticated requests.")
        for cid, cat, name in [
            ("WA-SS-071", "Access Control", "Horizontal privilege escalation (access another user data)"),
            ("WA-OTG-314", "Authorization Testing", "Test insecure direct object references (IDOR)"),
        ]:
            add(full_url, cid, cat, name, "Critical", "P1", "ERROR", err)


def check_host_header(full_url, args):
    token = f"evil-host-header-test-{rand_token(8)}.example"
    r = raw_request(full_url, "GET", timeout=args.timeout, insecure=args.insecure, host_override=token)
    ids_and_names = [
        ("WA-ADV-218", "Host header - password reset poisoning",
         "If a password-reset email is ever sent, confirm manually whether the reset link uses the Host header value."),
        ("WA-ADV-219", "Host header - web cache poisoning via Host",
         "If this app sits behind a cache, confirm manually whether a poisoned response gets cached and served to other users."),
        ("WA-ADV-220", "Host header - SSRF via malformed Host header",
         "Try a malformed/internal Host value (e.g. 169.254.169.254) and check for any server-side fetch behavior manually."),
        ("WA-ADV-221", "Host header - bypass internal authentication (localhost)",
         "Try 'Host: localhost' specifically and check for different (e.g. admin/internal) behavior manually."),
        ("WA-ADV-222", "Host header - routing-based SSRF (ambiguous requests)",
         "Needs a load-balancer/proxy-chain-aware test (duplicate Host headers, mismatched Host vs. request line) - manual/Burp."),
        ("WA-ADV-223", "Host header - SSRF via connection header",
         "Needs a Connection/X-Forwarded-* header manipulation test against an internal target - manual/Burp."),
        ("WA-ADV-224", "Host header - X-Host / X-Forwarded-Server override",
         "Try X-Host / X-Forwarded-Host / X-Forwarded-Server headers specifically and compare responses manually."),
    ]
    if r.error:
        for cid, name, _ in ids_and_names:
            add(full_url, cid, "HTTP Host Header Attacks", name, "High", "P1", "ERROR", r.error)
        return

    body_text = r.text()
    loc = r.header("Location")
    reflected_in_body = token in body_text
    reflected_in_location = bool(loc and token in loc)
    reflected = reflected_in_body or reflected_in_location
    base_evidence = (f"Sent Host: {token} to {full_url} -> status {r.status}, "
                      f"reflected in body: {reflected_in_body}, reflected in Location header: {reflected_in_location}.")

    curl_result = None if getattr(args, "no_cli_tools", False) else run_curl_with_host_header(
        full_url, token, timeout=args.timeout, insecure=args.insecure)
    curl_block = _format_cmd_block(curl_result[0], curl_result[1]) if curl_result else ""

    for cid, name, extra in ids_and_names:
        add(full_url, cid, "HTTP Host Header Attacks", name, "High" if cid != "WA-ADV-221" else "Critical", "P1",
            "FAIL" if reflected else "INFO",
            (base_evidence + (" Server trusts/reflects an arbitrary Host header - " + extra if reflected else
             " Basic single-request probe did not show reflection, but that alone doesn't rule this out - " + extra))
            + curl_block)


# --------------------------------------------------------------------------
# Driver
# --------------------------------------------------------------------------

def read_url_list(path):
    urls = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            urls.append(line)
    return urls


# --------------------------------------------------------------------------
# --creds / --creds-file - a friendlier way to hand this script account 1/2
# for check_access_control_2fa() than typing --cookie/--cookie2 by hand.
#
# Since this script never logs in (see below), a password is NOT needed and
# is NOT read from these entries at all - typing one is wasted effort.
# Three forms are accepted per line/entry, in order of what's checked:
#
#   1. "label::cookie"            <- RECOMMENDED - no password, just a
#                                     readable name and the session cookie
#                                     you already obtained by logging in
#                                     yourself as that user.
#   2. "label:password::cookie"   <- legacy form, kept for compatibility.
#                                     Whatever is typed as "password" is
#                                     parsed out and thrown away unread -
#                                     it is never stored/logged/used.
#   3. "cookie_name=value"        <- bare cookie, no label at all (no "::",
#                                     but contains "=" so it's recognised
#                                     as a raw Cookie value, e.g. a line
#                                     that's just "JSESSIONID=abc123").
#
# A line with neither "::" nor "=" (just "label" or "label:password" and
# nothing else) has no cookie to test with and is reported as skipped.
#
# Multiple cookie values for ONE account (e.g. a session cookie plus a
# separate CSRF/XSRF cookie) go on the SAME line as one Cookie-header
# string, semicolon-separated - e.g.:
#   alice::JSESSIONID=abc123; XSRF-TOKEN=def456
# (If the second value must be sent as its own HTTP header rather than a
# cookie - e.g. a custom "X-CSRF-Token: ..." header - use --header instead/
# in addition; --cookie only ever fills in the Cookie header.)
#
# IMPORTANT - this does NOT add a login flow. This script still never logs
# in, brute-forces, or harvests credentials anywhere (see the module
# docstring). The label is used ONLY as a readable name in evidence text
# (e.g. "Alice" instead of "Account 1"). The only thing that actually
# authenticates any request is the cookie - if an entry has no cookie at
# all, there is nothing this script can test with for that account (no
# username/password alone ever produces a working session here), and it's
# reported as skipped rather than silently ignored.
# --------------------------------------------------------------------------

def _parse_creds_line(line):
    """One credential/cookie entry -> (label, cookie). cookie is None when
    the entry has no usable cookie value. Returns None for blank/comment
    lines. See the block comment above for the 3 accepted forms."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    if "::" in line:
        # Forms 1 and 2: "label::cookie" or "label:password::cookie".
        # Whatever is left of "::" is only ever used as a display label -
        # if it itself contains a ":" (the legacy "label:password" form),
        # everything after that first ":" is an unread, discarded password.
        left_part, cookie_part = line.split("::", 1)
        label, _, _unused_password = left_part.partition(":")
        # _unused_password is intentionally unread past this line - parsed
        # out and discarded on purpose, never stored/logged/written
        # anywhere. No password is required here at all (form 1).
        label = label.strip() or None
        cookie = cookie_part.strip() or None
        return (label, cookie)
    if "=" in line:
        # Form 3: no "::" marker, but this looks like a raw Cookie header
        # value (name=value) rather than a "label[:password]" placeholder -
        # use the whole line directly as the cookie, with no label.
        return (None, line)
    # No "::" and no "=" - just a bare label or "label:password" with
    # nothing usable as a cookie yet.
    userid, _, _unused_password = line.partition(":")
    label = userid.strip() or None
    return (label, None)


def load_creds_entries(args):
    """Collects up to 2 (label, cookie) account entries from --creds-file
    (one entry per non-comment/non-blank line - line 1 = account 1, line 2
    = account 2, a file with only one line means a single account) and/or
    --creds (repeatable, same 'userID:password[::cookie]' format, appended
    after any --creds-file entries). More than 2 entries total is trimmed
    to 2 with a warning - this script only ever compares two accounts."""
    entries = []
    if getattr(args, "creds_file", None):
        with open(args.creds_file, "r", encoding="utf-8-sig") as f:
            for line in f:
                parsed = _parse_creds_line(line)
                if parsed:
                    entries.append(parsed)
    if getattr(args, "creds", None):
        for c in args.creds:
            parsed = _parse_creds_line(c)
            if parsed:
                entries.append(parsed)
    if len(entries) > 2:
        print(f"[!] {len(entries)} credential entries given (from --creds-file/--creds combined) - only using "
              f"the first 2; this script only ever compares a two-account pair.", file=sys.stderr)
        entries = entries[:2]
    return entries


def apply_creds_entries(args):
    """Applies load_creds_entries() results onto args.cookie/args.cookie2/
    args.account1_label/args.account2_label, WITHOUT overwriting anything
    the operator already set explicitly via --cookie/--cookie2/
    --account1-label/--account2-label directly - explicit flags always
    win. Call this before the --cookie/--cookie2 -> account1_cookie/
    account2_cookie derivation in main() so the two features compose."""
    entries = load_creds_entries(args)
    for i, (label, cookie) in enumerate(entries):
        slot = 1 if i == 0 else 2
        who = label or ("account 1" if slot == 1 else "account 2")
        if not cookie:
            print(f"[!] Credential entry {i + 1} ({who}) has no cookie value - this script never logs in with a "
                  f"username/password (no password needed at all - don't bother typing one), so there's nothing "
                  f"to test with for this account. Add '::sessionid=...' after the label on that line/entry (a "
                  f"session cookie YOU already obtained by logging in yourself as {who}) to actually use it.",
                  file=sys.stderr)
            continue
        if slot == 1:
            if not args.cookie:
                args.cookie = cookie
            if label and not args.account1_label:
                args.account1_label = label
        else:
            if not args.cookie2:
                args.cookie2 = cookie
            if label and not args.account2_label:
                args.account2_label = label


def normalize_url(u):
    if not re.match(r"^https?://", u, re.I):
        u = "https://" + u
    return u


# ==========================================================================
# PHASED PIPELINE (opt-in via --phases, default "baseline" = the ~100
# checks above only, unchanged behaviour). Six stages:
#   recon -> discover -> extscan (nuclei/nikto) -> inject -> exploit -> report
# Selecting a later phase automatically pulls in the phases it depends on
# (see expand_phase_dependencies()). "report" isn't a --phases value - the
# comprehensive severity-weighted report is always written at the end of
# main() from whatever RESULTS every selected phase produced.
# ==========================================================================

# --------------------------------------------------------------------------
# Recon phase - same-origin crawl, turns WA-OTG-276/277 (entry points /
# execution paths - MANUAL in the baseline suite, "needs full crawling")
# into a real automated pass.
# --------------------------------------------------------------------------

def crawl_site(start_url, args, max_pages, max_depth):
    """Small same-origin BFS crawler, stdlib-only - sees only what's in raw
    HTML (CRAWL_LINK_RE), no JS-rendered links/routes, same no-dependency
    tradeoff as the rest of this script. Bounded by max_pages/max_depth so
    a large site can't turn one target into an unbounded crawl."""
    parsed_start = urlparse(start_url)
    origin = (parsed_start.scheme, parsed_start.hostname, parsed_start.port)
    seen = set()
    queue = [(start_url, 0)]
    pages = []
    while queue and len(pages) < max_pages:
        url, depth = queue.pop(0)
        norm = url.split("#")[0]
        if norm in seen:
            continue
        seen.add(norm)
        r = raw_request(norm, "GET", timeout=args.timeout, insecure=args.insecure)
        if r.error or not r.status or r.status >= 400:
            continue
        pages.append((norm, r))
        if depth >= max_depth:
            continue
        if "html" not in (r.header("Content-Type") or "").lower():
            continue
        for m in CRAWL_LINK_RE.finditer(r.text()):
            link = m.group(1)
            if link.startswith(("mailto:", "tel:", "javascript:", "data:")):
                continue
            abs_link = urljoin(norm, link).split("#")[0]
            p = urlparse(abs_link)
            if (p.scheme, p.hostname, p.port) != origin:
                continue
            if abs_link not in seen:
                queue.append((abs_link, depth + 1))
    return pages


def phase_recon(full_url, args):
    print(f"    [recon] crawling from {full_url} (max {args.crawl_max_pages} pages, depth {args.crawl_depth})...")
    pages = crawl_site(full_url, args, max_pages=args.crawl_max_pages, max_depth=args.crawl_depth)
    urls_found = [u for u, _ in pages]
    add(full_url, "WA-OTG-276", "Information Gathering", "Enumerate application entry points (all params/forms)",
        "Info", "P3", "INFO" if urls_found else "MANUAL",
        (f"Recon phase crawl found {len(urls_found)} same-origin page(s) (bounded by --crawl-max-pages "
         f"{args.crawl_max_pages} / --crawl-depth {args.crawl_depth}): " + ", ".join(urls_found[:15])
         + (" ..." if len(urls_found) > 15 else "")) if urls_found else
        "Recon phase crawl found no reachable same-origin pages beyond the given URL - JS-rendered/SPA routes "
        "aren't visible to a raw-HTML crawl, review those manually.")
    add(full_url, "WA-OTG-277", "Information Gathering", "Map execution paths through application",
        "Info", "P3", "INFO" if urls_found else "MANUAL",
        (f"{len(urls_found)} page(s) mapped this pass - see WA-OTG-276 for the list. JS-rendered/SPA routes not "
         "reachable from raw HTML links are NOT covered - those still need manual review or a headless-browser "
         "crawl.") if urls_found else "No pages to map - see WA-OTG-276.")
    return pages


# --------------------------------------------------------------------------
# Discover phase - "looking for finds": turns the recon phase's crawled
# pages into a concrete list of injectable (url, method, param) fields for
# the inject/exploit phases to actually test.
# --------------------------------------------------------------------------

TYPE_ATTR_RE = re.compile(r'type\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)
SKIP_FIELD_TYPES = {"submit", "button", "file", "image", "reset"}


def extract_fields_from_page(url, http_result):
    """One page's form fields + its own URL query-string params, via
    regex (not a real HTML parser - JS-added fields aren't seen). Returns
    a list of {url, method, location, param, source} dicts."""
    fields = []
    body = http_result.text() if not http_result.error else ""

    parsed = urlparse(url)
    if parsed.query:
        for pair in parsed.query.split("&"):
            name = pair.split("=")[0]
            if name:
                fields.append({"url": url, "method": "GET", "location": "query",
                                "param": name, "source": "URL query string"})

    for form_match in FORM_BLOCK_RE.finditer(body):
        form_html = form_match.group(0)
        attrs_match = FORM_ATTR_RE.search(form_html)
        method, action = "GET", url
        if attrs_match:
            m_method = METHOD_ATTR_RE.search(attrs_match.group(1))
            if m_method:
                method = m_method.group(1).strip().upper()
            m_action = ACTION_ATTR_RE.search(attrs_match.group(1))
            if m_action and m_action.group(1):
                action = urljoin(url, m_action.group(1))
        for field_match in FIELD_TAG_RE.finditer(form_html):
            attrs = field_match.group(1)
            type_match = TYPE_ATTR_RE.search(attrs)
            if type_match and type_match.group(1).strip().lower() in SKIP_FIELD_TYPES:
                continue
            name_match = NAME_ATTR_RE.search(attrs)
            if name_match:
                fields.append({"url": action, "method": method, "location": "form",
                                "param": name_match.group(1), "source": f"<form> on {url}"})
    return fields


def phase_discover(full_url, pages, args):
    all_fields = []
    for url, r in pages:
        all_fields.extend(extract_fields_from_page(url, r))
    seen, deduped = set(), []
    for f in all_fields:
        key = (f["url"], f["method"], f["location"], f["param"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(f)

    add(full_url, "WA-DISC-001", "Discovery", "Enumerate injectable parameters (form fields + query params)",
        "Info", "P3", "INFO" if deduped else "MANUAL",
        (f"Found {len(deduped)} candidate parameter(s) across {len(pages)} crawled page(s): " +
         "; ".join(f"{f['param']} ({f['location']}, {f['method']} on {f['url']})" for f in deduped[:20]) +
         (f" ... and {len(deduped) - 20} more" if len(deduped) > 20 else "")) if deduped else
        "No form fields or URL query-string parameters found on any crawled page - nothing for the inject/exploit "
        "phases to test here.")
    return deduped


# --------------------------------------------------------------------------
# Extscan phase - nuclei / nikto, auto-detected via PATH (same pattern as
# curl/nmap/sslyze above). A missing tool degrades to MANUAL, same
# graceful-degrade philosophy as everywhere else in this script.
# --------------------------------------------------------------------------

def run_nuclei(url, args):
    if not _cli_available("nuclei"):
        return None
    cmd = ["nuclei", "-u", url, "-jsonl", "-silent", "-timeout", str(int(args.timeout) or 10)]
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=args.nuclei_timeout)
        return cmd, proc.stdout.decode("utf-8", errors="replace"), proc.stderr.decode("utf-8", errors="replace").strip()
    except subprocess.TimeoutExpired:
        return cmd, "", f"(nuclei timed out after {args.nuclei_timeout}s - try a longer --nuclei-timeout)"
    except Exception as e:
        return cmd, "", f"(nuclei execution failed: {e})"


_NUCLEI_SEV_TO_WPT = {"critical": ("Critical", "P1"), "high": ("High", "P1"), "medium": ("Medium", "P2"),
                       "low": ("Low", "P3"), "info": ("Info", "P3"), "unknown": ("Info", "P3")}


def phase_extscan_nuclei(full_url, args):
    result = run_nuclei(full_url, args)
    if result is None:
        add(full_url, "WA-EXT-NUCLEI", "External Scanner", "nuclei template scan", "Info", "P3", "MANUAL",
            "nuclei not found on PATH - install it (https://github.com/projectdiscovery/nuclei) to enable "
            "automated CVE/misconfiguration template scanning for this phase.")
        return
    cmd, out, err = result
    lines = [l for l in out.splitlines() if l.strip().startswith("{")]
    if not lines:
        add(full_url, "WA-EXT-NUCLEI", "External Scanner", "nuclei template scan", "Info", "P3", "PASS",
            "nuclei ran, no findings." + (f" stderr: {err}" if err else "")
            + _format_cmd_block(cmd, out or err or "(no output)"))
        return
    for line in lines:
        try:
            finding = json.loads(line)
        except Exception:
            continue
        info = finding.get("info", {}) or {}
        sev = str(info.get("severity") or "unknown").lower()
        wpt_sev, wpt_pri = _NUCLEI_SEV_TO_WPT.get(sev, ("Info", "P3"))
        template_id = finding.get("template-id", "unknown-template")
        matched = finding.get("matched-at") or finding.get("host") or full_url
        add(matched, f"WA-EXT-NUCLEI-{template_id}", "External Scanner", info.get("name", template_id) or template_id,
            wpt_sev, wpt_pri, "FAIL",
            f"nuclei template {template_id!r} matched. {str(info.get('description') or '')[:300]}"
            + _format_cmd_block(cmd, line))


def run_nikto(url, args):
    if not _cli_available("nikto"):
        return None
    cmd = ["nikto", "-h", url, "-timeout", str(int(args.timeout) or 10)]
    if urlparse(url).scheme == "https":
        cmd.append("-ssl")
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=args.nikto_timeout)
        return cmd, proc.stdout.decode("utf-8", errors="replace"), proc.stderr.decode("utf-8", errors="replace").strip()
    except subprocess.TimeoutExpired:
        return cmd, "", f"(nikto timed out after {args.nikto_timeout}s - try a longer --nikto-timeout)"
    except Exception as e:
        return cmd, "", f"(nikto execution failed: {e})"


def phase_extscan_nikto(full_url, args):
    result = run_nikto(full_url, args)
    if result is None:
        add(full_url, "WA-EXT-NIKTO", "External Scanner", "nikto web server scan", "Info", "P3", "MANUAL",
            "nikto not found on PATH - install it (apt install nikto, or https://github.com/sullo/nikto) to enable "
            "automated web server misconfiguration scanning for this phase.")
        return
    cmd, out, err = result
    finding_lines = [l for l in out.splitlines() if l.strip().startswith("+")
                      and not l.startswith(("+ Target", "+ Start Time", "+ Server:", "+ End Time"))]
    if not finding_lines:
        add(full_url, "WA-EXT-NIKTO", "External Scanner", "nikto web server scan", "Info", "P3", "PASS",
            "nikto ran, no findings reported." + _format_cmd_block(cmd, out or err or "(no output)"))
        return
    add(full_url, "WA-EXT-NIKTO", "External Scanner", "nikto web server scan", "Medium", "P2", "FAIL",
        f"nikto reported {len(finding_lines)} finding(s):\n" + "\n".join(finding_lines[:40]) + _format_cmd_block(cmd, out))


# --------------------------------------------------------------------------
# Inject phase - sends the built-in payload lists (see top-of-file
# BASIC_*_PAYLOADS) into every discovered field and applies a conservative
# response-oracle heuristic per category. A CONFIRMED hit here means "a
# real signal came back" (error string / reflected marker / timing) - it
# does NOT mean data was extracted or code executed; that's the exploit
# phase's job.
# --------------------------------------------------------------------------

INJECTION_CATEGORIES = [
    ("XSS", "Cross-Site Scripting", BASIC_XSS_PAYLOADS),
    ("SQLI", "SQL Injection", BASIC_SQLI_PAYLOADS),
    ("CMDI", "Command Injection", BASIC_CMD_INJECTION_PAYLOADS),
    ("PATHT", "Path Traversal", BASIC_PATH_TRAVERSAL_PAYLOADS),
    ("SSTI", "Server-Side Template Injection", BASIC_SSTI_PAYLOADS),
]


def _inject_into_url(base_url, param, payload):
    p = urlparse(base_url)
    q = dict(parse_qsl(p.query, keep_blank_values=True))
    q[param] = payload
    return p._replace(query=urlencode(q)).geturl()


def _send_field_payload(field, payload, args):
    if field["method"] == "GET":
        target = _inject_into_url(field["url"], field["param"], payload)
        return raw_request(target, "GET", timeout=args.timeout, insecure=args.insecure), target
    body = urlencode({field["param"]: payload}).encode()
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    resp = raw_request(field["url"], field["method"] or "POST", extra_headers=headers,
                        timeout=args.timeout, insecure=args.insecure, body=body)
    return resp, field["url"]


def classify_injection(category, payload, baseline_text, resp, elapsed, baseline_elapsed):
    """Deliberately conservative - an inconclusive response falls back to
    'no hit' rather than guessing, same philosophy as
    _parse_ssl_cli_output() elsewhere in this file."""
    text = resp.text() if not resp.error else ""
    if category == "XSS":
        if payload in text:
            return True, "Payload reflected UNESCAPED verbatim in the response body."
        return False, None
    if category == "SQLI":
        m = SQL_ERROR_PATTERNS.search(text)
        if m:
            return True, f"Database error signature in response: {m.group(0)!r}."
        if ("SLEEP" in payload.upper() or "WAITFOR" in payload.upper()) and elapsed - baseline_elapsed >= TIME_BASED_DELTA_SEC:
            return True, f"Time-based: response took {elapsed:.1f}s vs a {baseline_elapsed:.1f}s baseline."
        return False, None
    if category == "CMDI":
        m = CMD_OUTPUT_MARKER.search(text)
        if m:
            return True, f"Command output ('id') found in response: {m.group(0)!r}."
        if ("sleep 5" in payload.lower() or "ping -c 3" in payload.lower()) and elapsed - baseline_elapsed >= TIME_BASED_DELTA_SEC:
            return True, f"Time-based: response took {elapsed:.1f}s vs a {baseline_elapsed:.1f}s baseline."
        return False, None
    if category == "PATHT":
        if UNIX_PASSWD_MARKER.search(text):
            return True, "File-disclosure marker (/etc/passwd contents) found in response."
        if WIN_INI_MARKER.search(text):
            return True, "File-disclosure marker (win.ini contents) found in response."
        return False, None
    if category == "SSTI":
        if "49" in text and "49" not in baseline_text:
            return True, "Template expression appears evaluated - '49' (7*7) present in response, absent from baseline."
        return False, None
    return False, None


def phase_inject(full_url, fields, args):
    if not fields:
        add(full_url, "WA-INJ-000", "Injection Testing", "Active payload injection", "Info", "P3", "MANUAL",
            "No fields discovered by the discover phase - nothing to inject into.")
        return []
    fields = fields[: args.max_injection_fields]
    confirmed = []
    for field in fields:
        t0 = time.time()
        baseline_resp, _ = _send_field_payload(field, "wptbase" + rand_token(4), args)
        baseline_elapsed = time.time() - t0
        baseline_text = baseline_resp.text() if not baseline_resp.error else ""

        for short_id, category_name, payloads in INJECTION_CATEGORIES:
            for payload in payloads:
                t0 = time.time()
                resp, target = _send_field_payload(field, payload, args)
                elapsed = time.time() - t0
                if resp.error:
                    continue
                is_hit, note = classify_injection(short_id, payload, baseline_text, resp, elapsed, baseline_elapsed)
                if is_hit:
                    add(field["url"], f"WA-INJ-{short_id}", "Injection Testing",
                        f"Active payload injection - {category_name}", "High", "P1", "FAIL",
                        f"Field '{field['param']}' ({field['location']}, {field['method']}) - source: {field['source']}. "
                        f"{note} Payload used: {payload!r}. "
                        + (f"Request URL: {target}" if field["method"] == "GET" else
                           f"POST body param: {field['param']}={payload!r}"))
                    confirmed.append({"url": field["url"], "method": field["method"], "location": field["location"],
                                       "param": field["param"], "category": short_id, "payload": payload})
                    break  # one confirmed payload per category per field is enough signal
    if not confirmed:
        add(full_url, "WA-INJ-SUMMARY", "Injection Testing", "Active payload injection - summary", "Info", "P3", "PASS",
            f"Tested {len(fields)} field(s) x {len(INJECTION_CATEGORIES)} categories with this script's built-in "
            "payload lists - no XSS/SQLi/command-injection/path-traversal/SSTI signal detected. This is a small "
            "curated payload set for fast triage, not exhaustive fuzzing - a MANUAL review with Burp Intruder/"
            "sqlmap/ffuf is still recommended for high-value targets.")
    return confirmed


# --------------------------------------------------------------------------
# Exploit phase - OPT-IN ONLY (--exploit / --phases exploit AND
# --i-am-authorized both required). For each confirmed injection finding,
# hands off to a real exploitation tool (sqlmap for SQLi, dalfox for XSS)
# to attempt full proof-of-impact - for SQLi this genuinely extracts real
# rows from the target's database (sqlmap --dump), per the explicit choice
# to build this as full exploitation rather than confirmation-only. This
# is the highest-risk phase in the script - it WILL send real attack
# traffic. Only run it against a target you have EXPLICIT WRITTEN
# AUTHORIZATION to actively exploit.
# --------------------------------------------------------------------------

def phase_exploit(full_url, confirmed_findings, args):
    if not args.i_am_authorized:
        print("\n[!] Exploit phase requested but --i-am-authorized was not passed - REFUSING to run it.")
        add(full_url, "WA-EXP-000", "Exploitation", "Active exploitation phase", "Info", "P3", "MANUAL",
            "Exploit phase requested (--exploit / --phases exploit) but --i-am-authorized was not passed - this "
            "phase attempts REAL exploitation (e.g. sqlmap --dump against confirmed SQLi, which pulls real rows "
            "out of the target's database) and only runs against a target you have EXPLICIT WRITTEN AUTHORIZATION "
            "to actively exploit. Re-run with --exploit --i-am-authorized once confirmed.")
        return
    if not confirmed_findings:
        add(full_url, "WA-EXP-000", "Exploitation", "Active exploitation phase", "Info", "P3", "PASS",
            "Exploit phase ran but the injection phase had no confirmed findings on this target to exploit.")
        return
    for finding in confirmed_findings:
        if finding["category"] == "SQLI":
            _exploit_sqli(finding, args)
        elif finding["category"] == "XSS":
            _exploit_xss(finding, args)
        else:
            add(finding["url"], f"WA-EXP-{finding['category']}", "Exploitation",
                f"Active exploitation - {finding['category']}", "High", "P1", "MANUAL",
                f"Injection phase confirmed a {finding['category']} signal on field '{finding['param']}' but no "
                "automated exploitation tool is wired up for this category yet (only SQLi/sqlmap and XSS/dalfox "
                "are) - confirm/exploit manually.")


def _exploit_sqli(finding, args):
    if not _cli_available("sqlmap"):
        add(finding["url"], "WA-EXP-SQLI", "Exploitation", "Active exploitation - SQL Injection", "Critical", "P1", "MANUAL",
            "sqlmap not found on PATH - install it (https://github.com/sqlmapproject/sqlmap) for automated "
            f"exploitation. Injection phase already confirmed a signal on field '{finding['param']}' - exploit "
            "manually with sqlmap or Burp in the meantime.")
        return
    if finding["method"] == "GET":
        cmd = ["sqlmap", "-u", _inject_into_url(finding["url"], finding["param"], "1")]
    else:
        cmd = ["sqlmap", "-u", finding["url"], "--data", urlencode({finding["param"]: "1"})]
    cmd += ["--batch", "--random-agent", "--level", "3", "--risk", "2", "--dump", "--threads", "4"]
    if EXTRA_AUTH_HEADERS.get("Cookie"):
        cmd += ["--cookie", EXTRA_AUTH_HEADERS["Cookie"]]
    print(f"    [exploit] running sqlmap against {finding['url']} (field '{finding['param']}') - this can take a while...")
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=args.sqlmap_timeout)
        out = proc.stdout.decode("utf-8", errors="replace")
    except subprocess.TimeoutExpired:
        out = f"(sqlmap timed out after {args.sqlmap_timeout}s - increase --sqlmap-timeout for a slower target)"
    except Exception as e:
        out = f"(sqlmap execution failed: {e})"
    dumped = bool(re.search(r"\bTable:\b|\bDatabase:\b|\d+ entries", out))
    add(finding["url"], "WA-EXP-SQLI", "Exploitation", "Active exploitation - SQL Injection",
        "Critical", "P1", "FAIL" if dumped else "MANUAL",
        (f"sqlmap CONFIRMED and extracted real data from field '{finding['param']}' - the output below may "
         "contain real sensitive data, handle this report accordingly." if dumped else
         "sqlmap ran against the field the injection phase flagged but did not confirm/extract - may be a false "
         "positive from the injection phase's lightweight heuristic, or sqlmap needs manual tuning "
         "(--technique/--dbms/--tamper).") + _format_cmd_block(cmd, out))


def _exploit_xss(finding, args):
    if not _cli_available("dalfox"):
        add(finding["url"], "WA-EXP-XSS", "Exploitation", "Active exploitation - XSS", "High", "P1", "MANUAL",
            "dalfox not found on PATH - install it (https://github.com/hahwul/dalfox) for automated XSS PoC "
            f"confirmation. Injection phase already confirmed a reflected payload on field '{finding['param']}'.")
        return
    cmd = ["dalfox", "url", finding["url"], "--silence"]
    if EXTRA_AUTH_HEADERS.get("Cookie"):
        cmd += ["-C", EXTRA_AUTH_HEADERS["Cookie"]]
    print(f"    [exploit] running dalfox against {finding['url']} (field '{finding['param']}')...")
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=args.dalfox_timeout)
        out = proc.stdout.decode("utf-8", errors="replace")
    except subprocess.TimeoutExpired:
        out = f"(dalfox timed out after {args.dalfox_timeout}s)"
    except Exception as e:
        out = f"(dalfox execution failed: {e})"
    poc_confirmed = "[POC]" in out or "vulnerable" in out.lower()
    add(finding["url"], "WA-EXP-XSS", "Exploitation", "Active exploitation - XSS",
        "High", "P1", "FAIL" if poc_confirmed else "MANUAL",
        (f"dalfox CONFIRMED an exploitable XSS PoC on field '{finding['param']}'." if poc_confirmed else
         "dalfox ran but did not report a confirmed PoC - the injection phase's reflected-payload signal may "
         "still need manual confirmation in a real browser.") + _format_cmd_block(cmd, out))


# --------------------------------------------------------------------------
# Phase orchestration - dependency expansion + the per-target driver called
# once from scan_url(), and the final severity-weighted comprehensive
# report written once from main() after every target has been scanned.
# --------------------------------------------------------------------------

PHASE_DEPENDENCIES = {"exploit": "inject", "inject": "discover", "discover": "recon"}


def expand_phase_dependencies(phases):
    """Selecting a later phase implies every phase it depends on - e.g.
    --phases inject also needs discover (for fields) and recon (for pages
    to discover fields on), so it's pulled in automatically instead of
    running inject against nothing."""
    phases = set(phases)
    changed = True
    while changed:
        changed = False
        for phase, dep in PHASE_DEPENDENCIES.items():
            if phase in phases and dep not in phases:
                phases.add(dep)
                changed = True
    return phases


def run_extended_phases(full_url, raw_url, args):
    """Runs whichever of recon/discover/extscan/inject/exploit were
    selected via --phases, once against the given URL only - NOT
    duplicated against the baseline suite's automatic site-root pass,
    since these phases generate real (and, for exploit, real ATTACK)
    traffic and shouldn't silently double just because the baseline
    dual-pass behaviour does."""
    phases = args.phases
    if not (phases & {"recon", "discover", "extscan", "inject", "exploit"}):
        return

    CTX["source_input"] = raw_url
    CTX["url_role"] = "given-url"

    pages = []
    if "recon" in phases:
        CTX["phase"] = "recon"
        print(f"\n[*] Recon phase: {full_url}")
        pages = phase_recon(full_url, args)
    if not pages:
        first = raw_request(full_url, "GET", timeout=args.timeout, insecure=args.insecure)
        if not first.error:
            pages = [(full_url, first)]

    fields = []
    if "discover" in phases:
        CTX["phase"] = "discover"
        print(f"[*] Discovery phase: {full_url}")
        fields = phase_discover(full_url, pages, args)

    if "extscan" in phases:
        CTX["phase"] = "extscan"
        print(f"[*] External scanner phase (nuclei/nikto): {full_url}")
        phase_extscan_nuclei(full_url, args)
        phase_extscan_nikto(full_url, args)

    confirmed = []
    if "inject" in phases:
        CTX["phase"] = "inject"
        print(f"[*] Injection phase: {full_url}")
        confirmed = phase_inject(full_url, fields, args)

    if "exploit" in phases:
        CTX["phase"] = "exploit"
        print(f"[*] Exploitation phase: {full_url}")
        phase_exploit(full_url, confirmed, args)


def compute_comprehensive_report():
    fails = [r for r in RESULTS if r["result"] == "FAIL"]
    score = sum(SEVERITY_WEIGHT.get(r["severity"], 0) for r in fails)
    if score >= 80:
        rating = "Critical"
    elif score >= 40:
        rating = "High"
    elif score >= 15:
        rating = "Medium"
    elif score > 0:
        rating = "Low"
    else:
        rating = "Info"

    by_phase = {}
    for r in RESULTS:
        phase = r.get("phase") or "baseline"
        bucket = by_phase.setdefault(phase, {"total": 0, "pass": 0, "fail": 0, "manual": 0, "info": 0, "error": 0})
        bucket["total"] += 1
        bucket[r["result"].lower()] = bucket.get(r["result"].lower(), 0) + 1

    top_findings = sorted(fails, key=lambda r: -SEVERITY_WEIGHT.get(r["severity"], 0))[:25]

    return {
        "generated_at": now_iso(),
        "overall_risk_score": score,
        "overall_risk_rating": rating,
        "total_checks": len(RESULTS),
        "total_fail": len(fails),
        "by_phase": by_phase,
        "top_findings": [
            {"id": r["id"], "url": r["url"], "category": r["category"], "test": r["test"],
             "severity": r["severity"], "phase": r.get("phase") or "baseline", "evidence": r["evidence"][:500]}
            for r in top_findings
        ],
    }


def write_comprehensive_report(path):
    report = compute_comprehensive_report()
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    return report


def print_comprehensive_report(report):
    print("\n" + "=" * 78)
    print("COMPREHENSIVE RESULT (all phases)")
    print("=" * 78)
    print(f"Overall risk rating: {report['overall_risk_rating']}  (weighted score: {report['overall_risk_score']})")
    print(f"Total checks run: {report['total_checks']}  |  Total FAIL: {report['total_fail']}")
    print("\nBy phase:")
    for phase, stats in report["by_phase"].items():
        print(f"  {phase:10s} total={stats['total']:<4d} fail={stats.get('fail', 0):<3d} "
              f"pass={stats.get('pass', 0):<3d} manual={stats.get('manual', 0):<3d} "
              f"info={stats.get('info', 0):<3d} error={stats.get('error', 0):<3d}")
    if report["top_findings"]:
        print("\nTop findings by severity:")
        for f in report["top_findings"][:10]:
            print(f"  [{f['severity']:8s}] {f['id']:22s} {f['test'][:50]:50s} {f['url']}")
    print("=" * 78)


def print_phase_plan(args):
    order = ["baseline", "recon", "discover", "extscan", "inject", "exploit"]
    selected = [p for p in order if p in args.phases]
    print(f"[*] Phases selected for this run: {', '.join(selected)}")
    if "exploit" in args.phases and not args.i_am_authorized:
        print("[!] 'exploit' is selected but --i-am-authorized was NOT passed - the exploit phase will refuse to "
              "run (see WA-EXP-000 in the output) until you add --i-am-authorized.")


def run_full_suite(target_url, args):
    """Runs every automated check against exactly one URL (either the
    given-url pass or the site-root pass - the caller has already set
    CTX so every add() call below tags itself correctly)."""
    headers_result, hdr_curl_block = check_security_headers(target_url, args)
    check_tls(target_url, args)
    check_clickjacking(target_url, headers_result)
    check_cors(target_url, args)
    check_information_gathering(target_url, headers_result, args)
    check_configuration(target_url, headers_result, hdr_curl_block, args)
    check_session_management(target_url, headers_result, args)
    check_client_storage(target_url, headers_result, args)
    check_email_security(target_url, args)

    hdr400 = next((r["evidence"] for r in RESULTS if r["id"] == "WA-HDR-400" and r["url"] == target_url), "")
    hdr401 = next((r["evidence"] for r in RESULTS if r["id"] == "WA-HDR-401" and r["url"] == target_url), "")
    otg286 = next((r["evidence"] for r in RESULTS if r["id"] == "WA-OTG-286" and r["url"] == target_url), "")
    check_information_disclosure(target_url, headers_result, args, hdr400, hdr401, otg286)
    check_host_header(target_url, args)
    check_access_control_2fa(target_url, args)


def scan_url(raw_url, args):
    """Every URL - whether given via --url or read from --url-file - goes
    through exactly this same path, so a batch of manually curated URLs in
    a file is captured identically to a single --url run: each one gets
    its own given-url pass, and (unless --skip-root-pass) its own
    automatic site-root pass too."""
    full_url = normalize_url(raw_url)
    root_url = base_url_of(full_url)
    same_as_root = root_url.rstrip("/") == full_url.rstrip("/")

    targets = [(full_url, "given-url (site root)" if same_as_root else "given-url")]
    if not same_as_root and not args.skip_root_pass:
        targets.append((root_url, "site-root"))

    for target_url, role in targets:
        CTX["source_input"] = raw_url
        CTX["url_role"] = role
        CTX["phase"] = "baseline"
        print(f"\n[*] Testing {target_url}   (role: {role}; from input: {raw_url})")
        run_full_suite(target_url, args)
        if args.delay:
            time.sleep(args.delay)

    # recon/discover/extscan/inject/exploit (see run_extended_phases()) -
    # run at most once per input URL, against the given URL only, never
    # duplicated against the automatic site-root pass above.
    run_extended_phases(full_url, raw_url, args)


OUTPUT_FIELDS = ["source_input", "url_role", "phase", "url", "id", "category", "test",
                  "severity", "priority", "result", "evidence", "checked_at"]
CSV_FIELDS = OUTPUT_FIELDS + ["screenshot"]

# Worst-case wins when the same checklist ID was tested against more than
# one URL/role (the default dual-pass, or a --url-file batch) - matches
# the same ranking utils_autoscan_import.py uses on the Django import side,
# so "what does the portal end up marking" and "what does this report show
# as the overall result" always agree.
RESULT_PRIORITY = {"FAIL": 5, "ERROR": 4, "MANUAL": 3, "INFO": 2, "PASS": 1}
CONSOLIDATED_FIELDS = ["id", "category", "test", "severity", "priority", "result",
                        "affected_url_count", "affected_urls", "total_urls_tested", "evidence",
                        "screenshot_count"]


def consolidate_by_id():
    """Groups every result row by checklist ID across ALL input URLs and
    ALL URL+role passes (given-url + site-root, and every URL in a
    --url-file batch) into ONE row per ID, with every URL that hit the
    worst-case result combined into a single cell. Requested directly:
    "same findigns ID WA-HDR-392 reported on <url1> and <url2> ... report
    one ID at once, club all the vulnerable URLs in one cells even for
    multiple URLs i pasted win URL text file." Does NOT replace the
    granular per-URL JSON (still needed for the Django import feature and
    extract_evidence_images.py) - this is an additional rolled-up view for
    the CSV/XLSX side."""
    by_id = {}
    for row in RESULTS:
        by_id.setdefault(row["id"], []).append(row)

    consolidated = []
    for cid, rows in sorted(by_id.items()):
        worst = max(rows, key=lambda r: RESULT_PRIORITY.get(r["result"], 0))
        worst_result = worst["result"]

        # Multiple affected URLs can each carry their OWN screenshot
        # (--screenshot fail/all generates one per qualifying row) -
        # requested directly: "screenshot should be multiple output will
        # be multiple so add image 1 image for image base code" - every
        # URL's image (if it has one) is kept, numbered in the same order
        # as url_results, instead of only the first URL's.
        #
        # The SAME applies to evidence text, fixed after being reported
        # directly: "for out put in eidace i ma ssseeting only the
        # message not actual output for on target wheni pass multiple
        # urls it give genric message not showing what exactly happend
        # for each url." Previously this row's "evidence" field was just
        # worst["evidence"] - ONE row's text (whichever the same-priority
        # tie-break happened to land on) - even though several different
        # URLs could be involved, each of which ran its OWN request and
        # got its OWN real output (different curl/nmap output, status
        # codes, etc. per URL). Now every URL's own evidence is kept and
        # shown labelled by URL, so nothing is genericized away.
        #
        # And EVERY tested URL - not just the ones matching the worst
        # result - is now listed with its OWN per-URL result, fixed after
        # being reported directly: "if any url passed you can mentione
        # 127.0.0.1:PASSED if oneserver failed under the vulnerability
        # tittle mar the status as failed nd give the output affected
        # urls tell creaely which url is passed which is failed."
        # Previously "Affected URL(s)" only listed the URL(s) that hit
        # the worst-case result - if URL A passed and URL B failed, only
        # B appeared, with no way to tell A was even tested, let alone
        # that it passed. The overall "result" for the ID is UNCHANGED -
        # still worst-case-wins (a FAIL on any URL still reports the ID
        # as FAIL overall) - but url_results/affected_urls now shows
        # EVERY tested URL with its own PASS/FAIL/etc. explicitly, so
        # it's never ambiguous which URL(s) actually failed vs. which
        # passed.
        seen = set()
        url_results = []
        screenshots = []
        for r in rows:
            key = (r["url"], r["url_role"])
            if key in seen:
                continue
            seen.add(key)
            url_results.append({
                "index": len(url_results) + 1,  # matches this URL's 1-based position in url_results
                "url": r["url"], "url_role": r["url_role"],
                "result": r["result"],
                "evidence": r["evidence"],
            })
            if r.get("evidence_image_base64"):
                screenshots.append({
                    "index": len(url_results),  # matches this URL's 1-based position in url_results
                    "url": r["url"], "url_role": r["url_role"],
                    "image_base64": r["evidence_image_base64"],
                })

        total_urls = len(url_results)
        affected_url_count = sum(1 for u in url_results if u["result"] == worst_result)

        # "Affected URL(s)" text now shows EVERY tested URL with its own
        # result appended (e.g. "https://a.example/ (given-url) - FAIL"),
        # not just the ones matching the worst-case result.
        affected_urls_lines = [f"{u['url']} ({u['url_role']}) - {u['result']}" for u in url_results]

        worst_matching = [u for u in url_results if u["result"] == worst_result]
        if len(worst_matching) > 1:
            # More than one URL hit the worst-case result - label each
            # one's own evidence so it's clear which output came from
            # which target, instead of collapsing to a single row's text.
            combined_evidence = "\n\n".join(
                f"[{u['url_role']}: {u['url']}]\n{u['evidence']}" for u in worst_matching)
        else:
            # Exactly one URL hit the worst-case result (the common case)
            # - no need for a "[url]" label on a single block.
            combined_evidence = worst["evidence"]

        consolidated.append({
            "id": cid,
            "category": worst["category"],
            "test": worst["test"],
            "severity": worst["severity"],
            "priority": worst["priority"],
            "result": worst_result,
            "affected_url_count": affected_url_count,
            "affected_urls": "\n".join(affected_urls_lines),
            "total_urls_tested": total_urls,
            "evidence": combined_evidence,
            "url_results": url_results,  # JSON-only - every tested URL + its own result/evidence
            "screenshot_count": len(screenshots),
            "screenshots": screenshots,  # JSON-only - see write_consolidated_json()/write_xlsx()
        })
    return consolidated


def write_consolidated_csv(path):
    rows = consolidate_by_id()
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=CONSOLIDATED_FIELDS)
        w.writeheader()
        for row in rows:
            # "screenshots" (the list of base64 images) is JSON-only - a
            # base64 PNG doesn't belong in a CSV cell; screenshot_count
            # (already in CONSOLIDATED_FIELDS) tells you how many exist.
            w.writerow({k: row[k] for k in CONSOLIDATED_FIELDS})
    return rows


def write_consolidated_json(path):
    rows = consolidate_by_id()
    # affected_urls is "\n"-joined for the CSV/XLSX single-cell view above;
    # JSON consumers generally want a real list instead of one newline-
    # delimited string, so it's expanded back out here. Each screenshot is
    # also flattened out to image_1_base64/image_2_base64/... top-level
    # keys (in addition to the structured "screenshots" list) for simple
    # consumers that just want "image N" by name, per the direct request:
    # "screenshot should be multiple ... add image 1 image for image base
    # code" - one row can now have more than one affected URL/screenshot.
    json_rows = []
    for row in rows:
        jr = dict(row)
        jr["affected_urls"] = [u for u in row["affected_urls"].split("\n") if u]
        for shot in row["screenshots"]:
            jr[f"image_{shot['index']}_base64"] = shot["image_base64"]
        json_rows.append(jr)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(json_rows, f, indent=2)
    return rows


def write_csv(path):
    # evidence_image_base64 is intentionally left out of the CSV (it would
    # make rows unreadable) - "screenshot: yes" tells you to check the
    # JSON (or the .xlsx Evidence sheet) for that row's image instead.
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        w.writeheader()
        for row in RESULTS:
            out_row = {k: row[k] for k in OUTPUT_FIELDS}
            out_row["screenshot"] = "yes" if row.get("evidence_image_base64") else "no"
            w.writerow(out_row)


def write_json(path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(RESULTS, f, indent=2)


def write_xlsx(path, image_bytes):
    """Color-coded, filterable workbook - the 'easy to navigate portal
    list to track' output. Needs pandas + xlsxwriter; degrades gracefully
    (CSV/JSON are unaffected) if either isn't installed."""
    try:
        import pandas as pd
    except ImportError:
        print("\n[!] 'pandas' not installed - skipping .xlsx output (CSV/JSON were still written).")
        print("    Install with: pip3 install pandas xlsxwriter   "
              "(add --break-system-packages if your Python reports an externally-managed-environment error)")
        return False
    try:
        import xlsxwriter  # noqa: F401
    except ImportError:
        print("\n[!] 'xlsxwriter' not installed - skipping .xlsx output (CSV/JSON were still written).")
        print("    Install with: pip3 install xlsxwriter   "
              "(add --break-system-packages if your Python reports an externally-managed-environment error)")
        return False

    if not RESULTS:
        return False

    rename_map = {
        "source_input": "Source Input", "url_role": "URL Role", "phase": "Phase", "url": "URL Tested",
        "id": "Checklist ID", "category": "Category", "test": "Test Name",
        "severity": "Severity", "priority": "Priority", "result": "Result",
        "evidence": "Evidence / Comments", "checked_at": "Checked At (UTC)",
    }
    df = pd.DataFrame(RESULTS)[OUTPUT_FIELDS].rename(columns=rename_map)
    col_order = list(rename_map.values())
    df = df[col_order]

    consolidated_rows = consolidate_by_id()
    cons_rename = {
        "id": "Checklist ID", "category": "Category", "test": "Test Name",
        "severity": "Severity", "priority": "Priority", "result": "Overall Result",
        "affected_url_count": "Affected URL Count", "affected_urls": "Affected URL(s)",
        "total_urls_tested": "Total URLs Tested", "evidence": "Evidence (worst-case URL)",
    }
    cons_df = pd.DataFrame(consolidated_rows)[CONSOLIDATED_FIELDS].rename(columns=cons_rename)
    cons_col_order = list(cons_rename.values())
    cons_df = cons_df[cons_col_order]

    with pd.ExcelWriter(path, engine="xlsxwriter") as writer:
        # Written FIRST so it's the sheet visible when the file opens -
        # one row per checklist ID, every affected URL clubbed into a
        # single cell instead of a separate row per URL/role pass.
        cons_df.to_excel(writer, sheet_name="Consolidated", index=False)
        workbook = writer.book
        cons_sheet = writer.sheets["Consolidated"]
        cons_header_fmt = workbook.add_format({"bold": True, "bg_color": "#D7E4BC", "border": 1, "text_wrap": True})
        cons_wrap_fmt = workbook.add_format({"text_wrap": True, "valign": "top"})
        for i, col in enumerate(cons_col_order):
            cons_sheet.write(0, i, col, cons_header_fmt)
        cons_widths = [12, 24, 36, 10, 10, 14, 10, 50, 12, 60]
        wrap_cols = ("Affected URL(s)", "Evidence (worst-case URL)")
        for i, w in enumerate(cons_widths):
            cons_sheet.set_column(i, i, w, cons_wrap_fmt if cons_col_order[i] in wrap_cols else None)
        cons_sheet.freeze_panes(1, 0)
        cons_sheet.autofilter(0, 0, len(cons_df), len(cons_col_order) - 1)
        cons_result_col_idx = cons_col_order.index("Overall Result")
        cons_color_fmts = {
            "PASS": workbook.add_format({"bg_color": "#C6EFCE", "font_color": "#006100"}),
            "FAIL": workbook.add_format({"bg_color": "#FFC7CE", "font_color": "#9C0006"}),
            "MANUAL": workbook.add_format({"bg_color": "#FFEB9C", "font_color": "#9C6500"}),
            "INFO": workbook.add_format({"bg_color": "#DCE6F1", "font_color": "#1F4E78"}),
            "ERROR": workbook.add_format({"bg_color": "#D9D9D9", "font_color": "#3B3B3B"}),
        }
        for val, fmt in cons_color_fmts.items():
            cons_sheet.conditional_format(1, cons_result_col_idx, len(cons_df), cons_result_col_idx,
                {"type": "cell", "criteria": "equal to", "value": f'"{val}"', "format": fmt})

        df.to_excel(writer, sheet_name="Scan Results (Detail)", index=False)
        sheet = writer.sheets["Scan Results (Detail)"]

        header_fmt = workbook.add_format({"bold": True, "bg_color": "#D7E4BC", "border": 1, "text_wrap": True})
        wrap_fmt = workbook.add_format({"text_wrap": True, "valign": "top"})
        for i, col in enumerate(col_order):
            sheet.write(0, i, col, header_fmt)

        widths = [22, 20, 34, 12, 24, 36, 10, 10, 10, 70, 20]
        for i, w in enumerate(widths):
            sheet.set_column(i, i, w, wrap_fmt if col_order[i] == "Evidence / Comments" else None)
        sheet.freeze_panes(1, 0)
        sheet.autofilter(0, 0, len(df), len(col_order) - 1)

        result_col_idx = col_order.index("Result")
        color_fmts = {
            "PASS": workbook.add_format({"bg_color": "#C6EFCE", "font_color": "#006100"}),
            "FAIL": workbook.add_format({"bg_color": "#FFC7CE", "font_color": "#9C0006"}),
            "MANUAL": workbook.add_format({"bg_color": "#FFEB9C", "font_color": "#9C6500"}),
            "INFO": workbook.add_format({"bg_color": "#DCE6F1", "font_color": "#1F4E78"}),
            "ERROR": workbook.add_format({"bg_color": "#D9D9D9", "font_color": "#3B3B3B"}),
        }
        for val, fmt in color_fmts.items():
            sheet.conditional_format(1, result_col_idx, len(df), result_col_idx,
                {"type": "cell", "criteria": "equal to", "value": f'"{val}"', "format": fmt})

        summary = workbook.add_worksheet("Summary")
        summary.hide_gridlines(2)
        title_fmt = workbook.add_format({"bold": True, "font_size": 14, "font_color": "#2B5797"})
        summary.write(0, 0, "Automated Checklist Scan - Summary", title_fmt)
        summary.write(1, 0, f"Generated: {now_iso()}")
        summary.write(2, 0, f"Total checklist rows: {len(df)}")
        summary.write(3, 0, f"Unique source URLs (from --url / --url-file): {df['Source Input'].nunique()}")
        summary.write(4, 0, f"Unique URL+role passes tested: {df['URL Tested'].astype(str).str.cat(df['URL Role'], sep=' | ').nunique()}")

        row = 6
        summary.write(row, 0, "Result", header_fmt)
        summary.write(row, 1, "Count", header_fmt)
        for i, (val, cnt) in enumerate(df["Result"].value_counts().items(), start=row + 1):
            summary.write(i, 0, val)
            summary.write(i, 1, int(cnt))

        row2 = row + len(df["Result"].value_counts()) + 3
        summary.write(row2, 0, "Category", header_fmt)
        summary.write(row2, 1, "Count", header_fmt)
        for i, (val, cnt) in enumerate(df["Category"].value_counts().items(), start=row2 + 1):
            summary.write(i, 0, val)
            summary.write(i, 1, int(cnt))

        summary.set_column(0, 0, 44)
        summary.set_column(1, 1, 12)

        if image_bytes:
            # Grouped by checklist ID (one heading per ID, "Image 1",
            # "Image 2", ... underneath) so an ID with more than one
            # affected URL - and therefore more than one screenshot -
            # reads the same way the Consolidated sheet groups it, instead
            # of just a flat list in scan order.
            evsheet = workbook.add_worksheet("Evidence")
            evsheet.hide_gridlines(2)
            evsheet.write(0, 0, f"Auto-Generated Evidence Screenshots ({len(image_bytes)})", title_fmt)
            evsheet.set_column(0, 0, 130)
            caption_fmt = workbook.add_format({"bold": True, "bg_color": "#F2F2F2"})
            id_header_fmt = workbook.add_format({"bold": True, "font_size": 12, "font_color": "#2B5797",
                                                  "bottom": 2})

            by_id_idx = {}
            for idx in sorted(image_bytes.keys()):
                by_id_idx.setdefault(RESULTS[idx]["id"], []).append(idx)

            row_cursor = 2
            for cid in sorted(by_id_idx.keys()):
                idxs = by_id_idx[cid]
                sample = RESULTS[idxs[0]]
                evsheet.write(row_cursor, 0, f"{cid} - {sample['test']}  ({len(idxs)} image{'s' if len(idxs) != 1 else ''})", id_header_fmt)
                row_cursor += 1
                for n, idx in enumerate(idxs, start=1):
                    r = RESULTS[idx]
                    evsheet.write(row_cursor, 0,
                        f"Image {n}: {r['result']}  |  {r['url']} ({r['url_role']})", caption_fmt)
                    row_cursor += 1
                    img_stream = io.BytesIO(image_bytes[idx])
                    evsheet.insert_image(row_cursor, 0, f"{cid}_{n}.png",
                                          {"image_data": img_stream, "x_scale": 0.55, "y_scale": 0.55})
                    row_cursor += 20  # roughly the scaled image height in default-size rows
                row_cursor += 1

    return True


# The 3 checklist items check_access_control_2fa() can turn from MANUAL
# into a real PASS/FAIL result, and how many distinct accounts each needs.
# Used by both coverage-report functions below so the two stay in sync.
AUTH_GATED_IDS = [
    ("WA-OTG-312", "Authorization Testing", "Test bypassing authorization schema (force browse)", 1),
    ("WA-SS-071", "Access Control", "Horizontal privilege escalation (access another user data)", 2),
    ("WA-OTG-314", "Authorization Testing", "Test insecure direct object references (IDOR)", 2),
]


def print_auth_coverage_plan(args):
    """Printed once, right before scanning starts - tells you upfront
    exactly what --cookie/--cookie2 will and won't cover, so you know
    whether you need a second session before the run even begins. This is
    the 'auto check' behavior: one cookie is enough to authenticate the
    ENTIRE suite (every check, not just the 3 below) plus WA-OTG-312;
    adding a second cookie is only needed for the two checks that
    specifically require comparing two different accounts against each
    other."""
    have1 = bool(args.cookie or args.account1_cookie)
    have2 = bool(args.cookie2 or args.account2_cookie)
    print()
    if not have1:
        print("[*] No --cookie given - every check runs unauthenticated. Add --cookie \"sessionid=...\" to test "
              "everything as a logged-in session sees it (recommended for most engagements).")
        return
    print("[*] --cookie given - ALL ~100 checks in this suite (headers, TLS, cookies, CORS, information")
    print("    gathering, etc.) run as that authenticated session, plus real (non-MANUAL) testing for:")
    print("      WA-OTG-312  Test bypassing authorization schema (force browse)")
    if have2:
        print("[*] --cookie2 also given - these ALSO get real testing, comparing account 1 vs account 2:")
        print("      WA-SS-071   Horizontal privilege escalation (access another user data)")
        print("      WA-OTG-314  Test insecure direct object references (IDOR)")
    else:
        print("[*] No --cookie2 - these stay MANUAL (need a SECOND, different account's session to compare")
        print("    against the first): WA-SS-071, WA-OTG-314. Add --cookie2 \"sessionid=...\" to cover them too.")
    print()


# These are literal prefixes of the two "we never even tried" MANUAL
# evidence strings check_access_control_2fa() writes when a cookie is
# missing (see that function). Matching on these - not just result ==
# "MANUAL" - is what lets print_auth_coverage_actual() tell "skipped,
# no cookie" apart from "ran for real, but the outcome itself needs a
# human judgment call" (e.g. two accounts saw byte-identical content -
# that's MANUAL by design even when both cookies WERE provided and the
# comparison genuinely ran). Keep these in sync if that evidence wording
# ever changes.
_AUTH_SKIP_NO_SESSION = "Manual test required. Needs an authenticated session to test"
_AUTH_SKIP_NO_SECOND_ACCOUNT = "Manual test required. Needs a SECOND account's session too"


def print_auth_coverage_actual():
    """Printed after scanning, as part of print_summary() - ground-truth
    confirmation of what actually got recorded as a real, automated
    comparison vs was skipped outright for lack of a cookie, read straight
    from RESULTS rather than just intent from the flags. A MANUAL result
    here can mean two different things and this reports them separately:
    (a) the check never ran at all because no cookie was given, or (b) it
    DID run - both accounts were actually compared - but the outcome
    itself needs a human judgment call (e.g. identical content between
    two accounts, which is reported MANUAL by design, not skipped)."""
    by_id = {}
    for r in RESULTS:
        by_id.setdefault(r["id"], []).append(r)
    if not any(cid in by_id for cid, *_ in AUTH_GATED_IDS):
        return
    print("-" * 70)
    print("ACCESS CONTROL / AUTH COVERAGE - what actually ran authenticated:")
    for cid, cat, name, accounts_needed in AUTH_GATED_IDS:
        rows = by_id.get(cid)
        if not rows:
            continue
        ran = skipped = error = 0
        for r in rows:
            res, ev = r["result"], r.get("evidence") or ""
            if res == "ERROR":
                error += 1
            elif res == "MANUAL" and (ev.startswith(_AUTH_SKIP_NO_SESSION) or ev.startswith(_AUTH_SKIP_NO_SECOND_ACCOUNT)):
                skipped += 1
            else:
                # PASS, FAIL, or a MANUAL that ran for real (human judgment
                # needed on the outcome, not a skip).
                ran += 1
        parts = []
        if ran:
            parts.append(f"{ran} tested for real")
        if skipped:
            need = "a 2nd account's cookie (--cookie2)" if accounts_needed == 2 else "a session cookie (--cookie)"
            parts.append(f"{skipped} SKIPPED - needs {need}")
        if error:
            parts.append(f"{error} ERROR (request failed - check --insecure/target reachability/cookie validity)")
        print(f"  {cid:12s} {name}: {', '.join(parts)}")
    print("-" * 70)


def print_ssl_verify_summary_callout():
    """One top-of-summary note when TLS certificate-chain verification
    failures (raw_request()'s ssl.SSLCertVerificationError handler) affected
    one or more rows - so this doesn't only show up scattered inside
    individual rows' evidence text, which is easy to miss when scanning
    many URLs. See _SSL_VERIFY_HINT_MARKER."""
    affected_ids = set()
    affected_rows = 0
    for r in RESULTS:
        ev = r.get("evidence") or ""
        if _SSL_VERIFY_HINT_MARKER in ev:
            affected_rows += 1
            affected_ids.add(r["id"])
    if not affected_rows:
        return
    print("-" * 70)
    print(f"TLS CERTIFICATE VERIFICATION FAILED on {affected_rows} row(s) across {len(affected_ids)} "
          f"checklist ID(s) - every check that needed an HTTPS request to this target got an SSL cert-verify")
    print("error instead of a real result for that request (see those rows' evidence for the exact reason).")
    print("If this is an expected self-signed/internal/UAT certificate, re-run with --insecure to skip")
    print("verification and get real results; if you expected a trusted certificate, this is itself a")
    print("legitimate finding (WA-TLS-407-style chain issue) worth reporting as-is.")
    print("-" * 70)


def print_summary(xlsx_ok):
    counts = {}
    for r in RESULTS:
        counts[r["result"]] = counts.get(r["result"], 0) + 1
    total = len(RESULTS)
    print("\n" + "=" * 70)
    print(f"SUMMARY - {total} checklist rows produced across "
          f"{len(set(r['source_input'] for r in RESULTS))} input URL(s) "
          f"({len(set((r['url'], r['url_role']) for r in RESULTS))} URL+role passes)")
    for k in ["FAIL", "PASS", "MANUAL", "INFO", "ERROR"]:
        if k in counts:
            print(f"  {k:8s}: {counts[k]}")
    screenshot_count = sum(1 for r in RESULTS if r.get("evidence_image_base64"))
    if screenshot_count:
        print(f"  Screenshots generated: {screenshot_count}")
    print_auth_coverage_actual()
    print_ssl_verify_summary_callout()
    print("-" * 70)
    print("This covers 13 checklist categories (~77 of the ~421 total master-checklist")
    print("items) that are safely, non-destructively testable by script: HTTP Security")
    print("Headers, SSL/TLS (partial - real grade/cipher-check via nmap/sslyze/sslscan/")
    print("testssl.sh if installed), Clickjacking (partial), CORS, Information Gathering")
    print("(partial), Configuration Testing (partial), Session Management (partial),")
    print("Client-Side Testing (local/session storage heuristic), Email Security,")
    print("Information Disclosure, HTTP Host Header Attacks (basic probe), and Access")
    print("Control / Authorization Testing (force-browse/IDOR/horizontal-escalation -")
    print("only runs for real when --cookie/--cookie2 (or --account1-cookie/--account2-")
    print("cookie) are given, otherwise MANUAL). Everything else in the master checklist - SQL Injection,")
    print("XSS, Business Logic, Race Conditions, etc. - still needs the tool named in")
    print("that item's 'Tools' column (sqlmap, Burp, nuclei, ...) or manual testing;")
    print("every row above with result=MANUAL starts with the fixed phrase 'Manual test")
    print("required.' so you can filter/search for it directly.")
    if not xlsx_ok:
        print("-" * 70)
        print("NOTE: .xlsx was NOT written this run (see message above) - .csv/.json are complete.")
    print("=" * 70)


def main():
    ap = argparse.ArgumentParser(description="Automated pre-check scanner for the WPT master checklist (see module docstring).",
                                  formatter_class=argparse.RawDescriptionHelpFormatter,
                                  epilog=__doc__)
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--url", help="Single target URL to test")
    src.add_argument("--url-file", help="Path to a text file with one URL per line (# comments/blank lines ignored) - every URL in it is tested")
    ap.add_argument("--out", help="Output base filename, WITHOUT extension - writes <out>.csv, <out>.json and <out>.xlsx. Default: checklist_scan_<timestamp>")
    ap.add_argument("--timeout", type=float, default=10, help="Per-request timeout in seconds (default: 10)")
    ap.add_argument("--insecure", action="store_true", help="Don't verify TLS certificates (self-signed/internal lab targets)")
    ap.add_argument("--skip-root-pass", action="store_true",
                     help="Only test the exact URL given - skip the automatic extra pass against that host's site root. Default: OFF (both are tested)")
    ap.add_argument("--port-scan", action="store_true", help="Also run the light common-admin-port scan (WA-OTG-283). Off by default - noisier.")
    ap.add_argument("--dkim-selector", action="append", help="Extra DKIM selector to try (repeatable), in addition to the built-in common list")
    ap.add_argument("--delay", type=float, default=0, help="Delay in seconds between each URL+role pass (default: 0)")
    ap.add_argument("--screenshot", choices=["none", "fail", "fail+pass", "all"], default="fail",
                     help="Which rows get an auto-generated evidence screenshot (needs Pillow). Default: fail")
    ap.add_argument("--no-cli-tools", action="store_true",
                     help="Don't shell out to curl/nmap/sslyze/sslscan/testssl.sh even if installed - "
                          "use the pure-Python/MANUAL fallback behaviour only")
    ap.add_argument("--account1-cookie", help="Session Cookie header value for account 1, e.g. \"sessionid=abc123\" - "
                     "YOUR OWN already-authenticated session, never harvested/guessed by this script. Enables real "
                     "auth-bypass testing (WA-OTG-312); add --account2-cookie too for horizontal-escalation/IDOR "
                     "checks. Usually you want --cookie instead (see above) - it does everything this does PLUS "
                     "authenticates every other check in the suite; use --account1-cookie only if you specifically "
                     "want JUST the access-control checks authenticated and everything else run anonymously.")
    ap.add_argument("--account1-label", help="Display label for account 1 in evidence text (default: 'Account 1')")
    ap.add_argument("--account2-cookie", help="Session Cookie header value for account 2 - a SECOND, DIFFERENT "
                     "user's own session - enables the two-account horizontal-privilege-escalation/IDOR checks "
                     "(WA-SS-071, WA-OTG-314). Usually you want --cookie2 instead (see above) - same effect, "
                     "named to pair with --cookie.")
    ap.add_argument("--account2-label", help="Display label for account 2 in evidence text (default: 'Account 2')")
    ap.add_argument("--cookie", help="Cookie header value to send with every request (your own already-"
                     "authenticated session), e.g. \"sessionid=abc123; csrftoken=xyz\". Applies to every single "
                     "check, so results reflect what an authenticated user sees - AND automatically also covers "
                     "the WA-OTG-312 auth-bypass check (same as passing this same value as --account1-cookie), so "
                     "you don't need to pass the same cookie twice. See the coverage report printed at the start "
                     "of every run for exactly what one cookie does/doesn't cover.")
    ap.add_argument("--cookie2", help="A SECOND, DIFFERENT account's own Cookie header value, e.g. "
                     "\"sessionid=xyz789\". Only meaningful together with --cookie - automatically extends "
                     "coverage to the two-account horizontal-privilege-escalation/IDOR checks (WA-SS-071, "
                     "WA-OTG-314), comparing --cookie's account against this one (same as passing this value as "
                     "--account2-cookie). Not sent with every request like --cookie is - only used for that "
                     "specific two-account comparison.")
    ap.add_argument("--header", action="append", metavar="'Name: Value'",
                     help="Extra header to send with every request (repeatable), e.g. --header \"Authorization: "
                          "Bearer eyJ...\". Applies everywhere --cookie does; a header named here always wins over "
                          "an identically-named one from --cookie if they somehow overlap.")
    ap.add_argument("--only", action="append", metavar="ID",
                     help="Restrict output to just this Checklist ID (repeatable, and/or comma-separated - e.g. "
                          "--only WA-HDR-392 --only WA-SS-001,WA-SS-002). Every check still runs (they're all fast "
                          "HTTP/TLS probes), but rows for any other ID are dropped before being written out. Meant "
                          "for a 'rerun selected rows only' workflow driven by another tool (e.g. a Burp extension) "
                          "rather than typical interactive use.")
    ap.add_argument("--creds", action="append", metavar="'label::cookie'",
                     help="A friendlier alternative to --cookie/--cookie2/--account1-label/--account2-label, "
                          "repeatable up to twice (1st = account 1, 2nd = account 2). This script has no login "
                          "flow at all (by design) and never uses a password, so RECOMMENDED format is just "
                          "\"label::sessionid=...\" - no password needed, don't waste time typing one. A bare "
                          "cookie with no label also works: \"sessionid=...\" on its own. (Legacy "
                          "\"label:password::sessionid=...\" is still accepted for compatibility - any "
                          "\"password\" typed there is parsed out and discarded, NEVER stored, logged, or "
                          "written to evidence/JSON/CSV anywhere, and never used to log in.) The label becomes "
                          "that account's readable name in evidence text. Only the part after \"::\" (or the "
                          "whole entry, for a bare cookie) is what actually authenticates requests - an entry "
                          "with no usable cookie is reported as skipped. Two cookie values for the SAME account "
                          "(e.g. a session cookie plus a separate CSRF/XSRF cookie) go on one line, "
                          "semicolon-separated: \"alice::JSESSIONID=abc123; XSRF-TOKEN=def456\". Examples: "
                          "--creds \"alice::sessionid=abc123\" --creds \"bob::sessionid=xyz789\"")
    ap.add_argument("--creds-file", metavar="PATH",
                     help="Same format as --creds, one entry per line, read from a text file instead of the "
                          "command line (# comments/blank lines ignored). One line = one account (account 1 "
                          "only); two lines = account 1 (line 1) and account 2 (line 2). Combine with --creds "
                          "to add more entries on top of the file's - entries beyond 2 total are dropped with a "
                          "warning, since this script only ever compares a two-account pair.")
    ap.add_argument("--phases", default="baseline",
                     help="Comma-separated pipeline phases to run, in addition to the default ~100-check suite: "
                          "recon,discover,extscan,inject,exploit - or 'all' for every phase. Default: 'baseline' "
                          "(today's behaviour, unchanged). Selecting a later phase auto-includes what it depends "
                          "on (e.g. --phases inject also runs discover and recon). recon=same-origin crawl "
                          "(fills WA-OTG-276/277 for real); discover=extract form fields + query params from "
                          "crawled pages; extscan=nuclei+nikto if installed (auto-detected on PATH); "
                          "inject=send built-in XSS/SQLi/CmdInjection/PathTraversal/SSTI payloads into discovered "
                          "fields; exploit=REAL exploitation via sqlmap/dalfox against confirmed inject-phase "
                          "findings - requires --i-am-authorized, see below.")
    ap.add_argument("--exploit", action="store_true",
                     help="Shorthand for including 'exploit' in --phases (and everything it depends on). "
                          "Still requires --i-am-authorized or the exploit phase refuses to run.")
    ap.add_argument("--i-am-authorized", action="store_true",
                     help="Required alongside --exploit / --phases exploit. Confirms you have EXPLICIT WRITTEN "
                          "AUTHORIZATION to actively exploit the target(s) given - the exploit phase sends real "
                          "attack traffic and, for confirmed SQLi, runs sqlmap --dump (pulls real rows out of the "
                          "target's database). Without this flag the exploit phase logs a MANUAL row and does "
                          "nothing else.")
    ap.add_argument("--crawl-max-pages", type=int, default=20,
                     help="Recon phase: max same-origin pages to crawl (default: 20)")
    ap.add_argument("--crawl-depth", type=int, default=2,
                     help="Recon phase: max link-following depth from the given URL (default: 2)")
    ap.add_argument("--max-injection-fields", type=int, default=25,
                     help="Inject phase: max discovered fields to actually test (default: 25) - keeps request "
                          "volume/runtime bounded on forms/APIs with a lot of fields")
    ap.add_argument("--nuclei-timeout", type=int, default=180,
                     help="Extscan phase: timeout in seconds for the nuclei subprocess (default: 180)")
    ap.add_argument("--nikto-timeout", type=int, default=300,
                     help="Extscan phase: timeout in seconds for the nikto subprocess (default: 300)")
    ap.add_argument("--sqlmap-timeout", type=int, default=300,
                     help="Exploit phase: timeout in seconds for the sqlmap subprocess (default: 300)")
    ap.add_argument("--dalfox-timeout", type=int, default=120,
                     help="Exploit phase: timeout in seconds for the dalfox subprocess (default: 120)")
    args = ap.parse_args()

    phase_set = {x.strip().lower() for x in args.phases.split(",") if x.strip()}
    if "all" in phase_set:
        phase_set = {"baseline", "recon", "discover", "extscan", "inject", "exploit"}
    if args.exploit:
        phase_set.add("exploit")
    args.phases = expand_phase_dependencies(phase_set) | {"baseline"}

    # --creds/--creds-file populate args.cookie/args.cookie2/account1_label/
    # account2_label (without overwriting anything set explicitly via those
    # flags directly) BEFORE the --cookie/--cookie2 -> account1_cookie/
    # account2_cookie derivation right below, so the two features compose:
    # a --creds-file with one line behaves exactly like --cookie, two lines
    # exactly like --cookie + --cookie2, just with readable labels attached.
    apply_creds_entries(args)

    # --cookie/--cookie2 double as --account1-cookie/--account2-cookie for
    # the 2-account access-control/IDOR checks (check_access_control_2fa)
    # UNLESS --account1-cookie/--account2-cookie were explicitly set to
    # something different. This is what makes coverage "automatic": pass
    # --cookie alone and every check in the suite runs authenticated,
    # including WA-OTG-312 for real; add --cookie2 and WA-SS-071/
    # WA-OTG-314 (which need a second, different account to compare
    # against) automatically get real testing too - no need to also repeat
    # the same cookie value on --account1-cookie/--account2-cookie.
    if args.cookie and not args.account1_cookie:
        args.account1_cookie = args.cookie
    if args.cookie2 and not args.account2_cookie:
        args.account2_cookie = args.cookie2

    global EXTRA_AUTH_HEADERS, ONLY_IDS
    if args.cookie:
        EXTRA_AUTH_HEADERS["Cookie"] = args.cookie
    if args.header:
        for h in args.header:
            if ":" not in h:
                print(f"[!] Ignoring malformed --header {h!r} - expected \"Name: Value\"", file=sys.stderr)
                continue
            name, _, value = h.partition(":")
            EXTRA_AUTH_HEADERS[name.strip()] = value.strip()
    if args.only:
        ONLY_IDS = set()
        for raw in args.only:
            ONLY_IDS.update(x.strip() for x in raw.split(",") if x.strip())

    urls = [args.url] if args.url else read_url_list(args.url_file)
    if not urls:
        print("No URLs to scan.", file=sys.stderr)
        sys.exit(1)

    if args.no_cli_tools:
        print("[*] --no-cli-tools set - curl/nmap/sslyze/sslscan/testssl.sh will NOT be used even if installed.")
    else:
        found = [t for t in ("curl", "nmap", "sslyze", "sslscan", "testssl.sh") if _cli_available(t)]
        if found:
            print(f"[*] Command-line tools detected on PATH and will be used automatically: {', '.join(found)}")
        else:
            print("[*] No curl/nmap/sslyze/sslscan/testssl.sh found on PATH - those checks stay MANUAL/Python-only.")
    print_auth_coverage_plan(args)
    print_phase_plan(args)
    if "exploit" in args.phases and args.i_am_authorized:
        print("\n[!!!] EXPLOIT phase is ENABLED and AUTHORIZED for this run - this WILL send real attack traffic, "
              "and for confirmed SQL Injection findings WILL run sqlmap --dump against the target's database. "
              "Make sure every URL you're about to scan is one you have explicit written authorization to "
              "actively exploit.")

    for u in urls:
        scan_url(u, args)

    image_bytes = generate_screenshots(args.screenshot)

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    out_base = args.out or f"checklist_scan_{stamp}"
    for ext in (".csv", ".json", ".xlsx"):
        if out_base.lower().endswith(ext):
            out_base = out_base[: -len(ext)]
    csv_path, json_path, xlsx_path = out_base + ".csv", out_base + ".json", out_base + ".xlsx"
    consolidated_csv_path = out_base + "_consolidated.csv"
    consolidated_json_path = out_base + "_consolidated.json"

    write_csv(csv_path)
    write_json(json_path)
    write_consolidated_csv(consolidated_csv_path)
    write_consolidated_json(consolidated_json_path)
    xlsx_ok = write_xlsx(xlsx_path, image_bytes)
    comprehensive_path = out_base + "_comprehensive.json"
    report = write_comprehensive_report(comprehensive_path)

    print_summary(xlsx_ok)
    print_comprehensive_report(report)
    print("\nResults written to:")
    print(f"  CSV  (per-URL detail):  {csv_path}")
    print(f"  CSV  (one row per ID):  {consolidated_csv_path}")
    print(f"  JSON (per-URL detail, use this one for the portal import - see README): {json_path}")
    print(f"  JSON (one row per ID):  {consolidated_json_path}")
    print(f"  JSON (severity-weighted comprehensive report, all phases): {comprehensive_path}")
    if xlsx_ok:
        print(f"  XLSX ('Consolidated' sheet + 'Scan Results (Detail)' sheet): {xlsx_path}")


if __name__ == "__main__":
    main()
