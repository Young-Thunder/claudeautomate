# -*- coding: utf-8 -*-
"""
WPTChecklistScanner.py - Burp Suite extension (v1)
=====================================================================
A Burp Suite Extender tab that drives the standalone checklist_auto_scan.py
WPT checklist scanner against your CURRENT, authenticated Burp session, and
shows results grouped by category right inside Burp - plus optional
cross-reference against Burp's own Scanner findings.

WHY THIS IS WRITTEN THE WAY IT IS (read this before editing)
---------------------------------------------------------------------
Burp only loads Python extensions via Jython, which is stuck on Python
2.7 language syntax and a limited standard library with none of the
third-party packages (requests, pandas, xlsxwriter, Pillow, ...) that
checklist_auto_scan.py's ~100 checks and its .xlsx writer depend on.
Rewriting all of that in Jython would mean reimplementing and re-testing
logic that already works. Instead, this extension is a thin Jython
shell that:
  1. builds a Swing UI tab inside Burp,
  2. pulls your target list + session cookie from Burp's own Proxy
     history/scope (so it always tests as YOU, authenticated),
  3. shells out to a real CPython 3 interpreter running
     checklist_auto_scan.py with that captured session (that's the
     "I have python installed on my remote machine" part - this
     extension calls that installation, it doesn't replace it), and
  4. reads back the JSON it writes and renders it as a results table.

This keeps the actual scanning logic in one place (checklist_auto_scan.py,
already built/tested/used from the command line and from
Checklist-AutoScan.ps1) instead of forking it into a third, Jython-only
copy that would drift out of sync.

See README_BurpExtension.md (ships alongside this file) for installation,
configuration, and the external-tool integration roadmap (sqlmap/Dalfox/
Turbo Intruder/etc. for the ~300 checklist items this v1 does NOT cover).
"""

from burp import IBurpExtender, ITab, IContextMenuFactory

from javax.swing import (JPanel, JTabbedPane, JButton, JLabel, JTextField, JTextArea,
                          JScrollPane, JTable, JFileChooser, BoxLayout, SwingUtilities,
                          JOptionPane, ListSelectionModel, BorderFactory, JCheckBox, JTextPane,
                          JProgressBar, RowFilter, JList, DefaultListModel, JToggleButton, ButtonGroup,
                          JComboBox, JMenuItem)
from javax.swing.event import ListSelectionListener, DocumentListener, ChangeListener
from javax.swing.table import DefaultTableModel, DefaultTableCellRenderer
from javax.swing.text import SimpleAttributeSet, StyleConstants
from java.awt import BorderLayout, FlowLayout, GridLayout, Color, Font, Dimension, Cursor
from java.awt.event import MouseAdapter
from java.lang import Object as JObject, Integer as JInteger

import subprocess
import json
import csv
import os
import tempfile
import threading
import time
import re

# Reported directly: "can we name this extention as lowchop? means low
# handing frouit tree to chooping" -> picked "QuickChop" from a short list
# of alternates offered back. This is the extension's DISPLAY name only
# (Burp's Extender tab list, the Suite tab caption, dialog titles, status
# messages). The file stays WPTChecklistScanner.py on disk so the
# existing --script-path/guessed-path logic and README don't need to
# change too - say the word if you'd rather rename the file itself.
EXT_NAME = "QuickChop"
# Reported directly: "after completing the scan it crashed or slow not
# working properly burp freezes" - a hung checklist_auto_scan.py
# subprocess (or a CLI tool it shells out to) used to block
# proc.communicate() forever with no way to recover. This caps a single
# scan run before it's force-killed; see _run_checklist_auto_scan.
SCAN_TIMEOUT_SECONDS = 20 * 60
# Reported directly: "no line by line URL read no 5-10 test perfored and
# captue progreess eaxly how i it was before" - checklist_auto_scan.py's
# add() (this rev onward) prints "QUICKCHOP_ROW|<json>" to stdout for
# every result the instant it's produced. _run_checklist_auto_scan reads
# that stream live (instead of blocking on proc.communicate() until the
# whole run finishes) and hands rows back to the UI in small batches of
# this size, so KPI cards / progress bar / Detailed Results grow
# gradually as the scan runs rather than jumping from 0 to 100% at once.
PROGRESS_FLUSH_EVERY = 8
RESULT_COLORS = {
    "PASS": Color(0xD9, 0xF2, 0xDF), "FAIL": Color(0xFB, 0xDA, 0xD8),
    "MANUAL": Color(0xFD, 0xF1, 0xC7), "INFO": Color(0xD9, 0xEC, 0xFB),
    "ERROR": Color(0xE6, 0xE6, 0xE6),
}
# Same accent colors checklist_auto_scan.py's terminal-style screenshots use
# for their top status bar (_RESULT_COLORS' first/dark element there) - reused
# here so the in-Burp detail popup and the exported evidence screenshots read
# as the same visual system. Reported directly: "no highlate for the findings"
# - the plain black-on-white popup didn't distinguish PASS/FAIL/etc at all.
RESULT_ACCENT_COLORS = {
    "PASS": Color(0x1E, 0x7E, 0x34), "FAIL": Color(0xA4, 0x26, 0x2C),
    "MANUAL": Color(0x8A, 0x6D, 0x00), "INFO": Color(0x1F, 0x4E, 0x78),
    "ERROR": Color(0x3B, 0x3B, 0x3B),
}
# Reported directly: "show colors differentils one line to other who
# critical first then high the n mediam last low" - the Summary tab's
# "Failed vulnerabilities" list (see _refresh_worst_findings) previously
# badged every row identically in FAIL-red regardless of severity, so
# rows were only distinguishable by reading the text. Each severity tier
# now gets its own color, darkest/most alarming for Critical down to a
# calmer blue-gray for Low, on top of the existing Critical-first sort.
SEVERITY_ACCENT_COLORS = {
    "Critical": Color(0x7B, 0x00, 0x00), "High": Color(0xA4, 0x26, 0x2C),
    "Medium": Color(0xB8, 0x56, 0x0F), "Low": Color(0x1F, 0x4E, 0x78),
    # Two spellings intentionally: "Informational" is the WPT checklist's
    # own severity value; Burp Scanner's IScanIssue.getSeverity() instead
    # returns the shorter "Information" for the same tier - both are
    # mapped here so _refresh_worst_findings and _show_burp_issue_detail
    # (which each only ever see ONE of the two vocabularies) both resolve
    # to a real color instead of falling back to plain FAIL-red.
    "Informational": Color(0x66, 0x66, 0x66), "Information": Color(0x66, 0x66, 0x66),
}
RESULT_COLUMNS = ["ID", "Category", "Test", "Severity", "Priority", "Result", "Evidence", "URL", "Source"]

# ---------------------------------------------------------------------
# OWASP Top 10 (2021) grouping for the Categories/Summary "OWASP Top 10"
# toggle. This maps checklist_auto_scan.py's actual category strings
# (the 13 automated categories - see its module docstring/print output)
# onto the 10 OWASP buckets. This is an ILLUSTRATIVE / best-effort
# mapping, not an official one - worth confirming against however
# ReportSystem itself classifies categories before relying on it for a
# real client-facing report. Any category NOT in this map (e.g. a future
# check category, or a MANUAL-only master-checklist category that ends
# up in a result row some other way) falls into the OWASP_OTHER bucket
# below instead of silently disappearing from the OWASP view.
# ---------------------------------------------------------------------
OWASP_GROUPS = [
    ("A01", "A01: Broken Access Control"),
    ("A02", "A02: Cryptographic Failures"),
    ("A03", "A03: Injection"),
    ("A04", "A04: Insecure Design"),
    ("A05", "A05: Security Misconfiguration"),
    ("A06", "A06: Vulnerable & Outdated Components"),
    ("A07", "A07: Identification & Authentication Failures"),
    ("A08", "A08: Software & Data Integrity Failures"),
    ("A09", "A09: Security Logging & Monitoring Failures"),
    ("A10", "A10: Server-Side Request Forgery (SSRF)"),
]
OWASP_OTHER_KEY = "OTHER"
OWASP_OTHER_LABEL = "Uncategorized / Not Yet Mapped"
# key -> human label lookup for OWASP_GROUPS, used by the Checklist
# Reference tab/export to show a real bucket name instead of a bare "A03"/
# "OTHER" key.
OWASP_GROUPS_BY_KEY = dict(OWASP_GROUPS)
OWASP_GROUPS_BY_KEY[OWASP_OTHER_KEY] = OWASP_OTHER_LABEL
OWASP_CATEGORY_MAP = {
    "Access Control": "A01",
    "Authorization Testing": "A01",
    "SSL / TLS": "A02",
    "Client-Side Testing": "A02",
    "HTTP Security Headers": "A05",
    "Configuration Testing": "A05",
    "Clickjacking": "A05",
    "CORS": "A05",
    "Email Security": "A05",
    "Information Gathering": "A06",
    "Session Management Testing": "A07",
    "Information Disclosure": "A09",
    "HTTP Host Header Attacks": "A10",
}
# Reported directly: "no categories listed owasp one fine" - the OWASP
# Top 10 view always lists all 10 fixed buckets (with 0s) even before a
# scan has run. KNOWN_CATEGORIES (redefined further below, once
# MASTER_CHECKLIST exists) gives the "All Categories" view the same
# "always show the full list" behavior.
# ---------------------------------------------------------------------
# Full master checklist (~421 items, "Web App Checklist" sheet from
# MasterChecklistMerged_2.xlsx) - the ~77 automated IDs above are a
# SUBSET of this same list (same WA-* ID scheme; verify with
# AUTOMATED_CHECKLIST_IDS below), the other ~344 are manual-testing-only
# items (SQL Injection, XSS, Business Logic, Race Conditions, etc.) that
# need a human + Repeater/Intruder/sqlmap/etc, never something
# checklist_auto_scan.py can verify unattended.
#
# Reported directly: "when I can confirm the test XSS in repeater or
# proxy or intruder selected output can be moved to quickchop for a
# record vulnerability list so we understand how many findings have
# been covered" - this list is what powers the new "Log finding to
# QuickChop" right-click menu (see IContextMenuFactory.createMenuItems
# below): it's the full searchable ID/name list the log-finding dialog
# picks from, so a MANUALLY confirmed finding from Repeater/Proxy/
# Intruder can be recorded against the correct checklist ID and show up
# in Detailed Results/Summary/Categories/Export right alongside the
# automated rows - one combined coverage picture instead of two.
#
# Tuple layout: (ID, Category, Test Name, Severity, Priority). To
# refresh this from a newer master spreadsheet: re-extract the "Web App
# Checklist" sheet's ID/Category/Test Name/Severity/Priority columns
# (openpyxl) and regenerate this whole list the same way.
# ---------------------------------------------------------------------
MASTER_CHECKLIST = [
    ("WA-SS-001", "SQL Injection", "Classic SQLi \u2014 WHERE clause bypass", "Critical", "P1"),
    ("WA-SS-002", "SQL Injection", "SQLi \u2014 error-based extraction", "Critical", "P1"),
    ("WA-SS-003", "SQL Injection", "SQLi \u2014 UNION-based column count", "Critical", "P1"),
    ("WA-SS-004", "SQL Injection", "SQLi \u2014 UNION retrieve data from other tables", "Critical", "P1"),
    ("WA-SS-005", "SQL Injection", "Blind SQLi \u2014 boolean-based", "Critical", "P1"),
    ("WA-SS-006", "SQL Injection", "Blind SQLi \u2014 time-based (SLEEP/WAITFOR)", "Critical", "P1"),
    ("WA-SS-007", "SQL Injection", "Blind SQLi \u2014 out-of-band DNS exfil", "High", "P1"),
    ("WA-SS-008", "SQL Injection", "SQLi \u2014 second-order (stored) injection", "High", "P1"),
    ("WA-SS-009", "SQL Injection", "SQLi \u2014 filter/WAF bypass (case, encoding)", "High", "P1"),
    ("WA-SS-010", "SQL Injection", "SQLi \u2014 login bypass via OR 1=1", "Critical", "P1"),
    ("WA-SS-011", "SQL Injection", "SQLi \u2014 stacked queries execution", "Critical", "P1"),
    ("WA-SS-012", "SQL Injection", "SQLi \u2014 file read (LOAD_FILE / COPY)", "High", "P1"),
    ("WA-SS-013", "SQL Injection", "SQLi \u2014 file write / webshell drop", "Critical", "P1"),
    ("WA-SS-014", "SQL Injection", "SQLi \u2014 XML/SOAP parameter injection", "High", "P1"),
    ("WA-SS-015", "SQL Injection", "SQLi \u2014 HTTP header injection (User-Agent/X-Forwarded-For)", "High", "P1"),
    ("WA-SS-016", "SQL Injection", "SQLi \u2014 cookie value injection", "High", "P1"),
    ("WA-SS-017", "SQL Injection", "SQLi \u2014 JSON body parameter injection", "High", "P1"),
    ("WA-SS-018", "SQL Injection", "SQLi \u2014 order-by / sort parameter injection", "Medium", "P2"),
    ("WA-SS-019", "Authentication", "Username enumeration via different responses", "High", "P1"),
    ("WA-SS-020", "Authentication", "Username enumeration via subtly different responses", "Medium", "P2"),
    ("WA-SS-021", "Authentication", "Username enumeration via response timing", "Medium", "P2"),
    ("WA-SS-022", "Authentication", "Password brute-force with rate-limit bypass", "High", "P1"),
    ("WA-SS-023", "Authentication", "2FA simple bypass (skip step 2)", "Critical", "P1"),
    ("WA-SS-024", "Authentication", "2FA brute-force (6-digit OTP)", "High", "P1"),
    ("WA-SS-025", "Authentication", "2FA broken logic (account takeover)", "Critical", "P1"),
    ("WA-SS-026", "Authentication", "Password reset \u2014 poisoning via Host header", "High", "P1"),
    ("WA-SS-027", "Authentication", "Password reset \u2014 broken logic / token reuse", "High", "P1"),
    ("WA-SS-028", "Authentication", "Password reset \u2014 link via referrer header leak", "Medium", "P2"),
    ("WA-SS-029", "Authentication", "Offline password cracking (stolen cookie hash)", "High", "P1"),
    ("WA-SS-030", "Authentication", "Stay logged in cookie predict / brute-force", "High", "P1"),
    ("WA-SS-031", "Authentication", "Account lockout \u2014 enumeration via lockout timing", "Medium", "P2"),
    ("WA-SS-032", "Authentication", "HTTP basic auth brute-force", "High", "P1"),
    ("WA-SS-033", "Path Traversal", "Path traversal \u2014 simple ../../etc/passwd", "High", "P1"),
    ("WA-SS-034", "Path Traversal", "Path traversal \u2014 absolute path bypass", "High", "P1"),
    ("WA-SS-035", "Path Traversal", "Path traversal \u2014 stripped non-recursively (....//)", "High", "P1"),
    ("WA-SS-036", "Path Traversal", "Path traversal \u2014 URL-encoded sequences (%2e%2e)", "High", "P1"),
    ("WA-SS-037", "Path Traversal", "Path traversal \u2014 null byte bypass (%00.png)", "High", "P1"),
    ("WA-SS-038", "Path Traversal", "Path traversal \u2014 start of path validation bypass", "High", "P1"),
    ("WA-SS-039", "Command Injection", "OS command injection \u2014 simple case (;whoami)", "Critical", "P1"),
    ("WA-SS-040", "Command Injection", "Blind command injection \u2014 time delay (sleep 10)", "Critical", "P1"),
    ("WA-SS-041", "Command Injection", "Blind command injection \u2014 output redirect to web root", "Critical", "P1"),
    ("WA-SS-042", "Command Injection", "Blind command injection \u2014 out-of-band (DNS/HTTP)", "Critical", "P1"),
    ("WA-SS-043", "Command Injection", "Blind command injection \u2014 shell metachar bypass", "High", "P1"),
    ("WA-SS-044", "Business Logic", "Excessive trust in client-side controls (price manipulation)", "High", "P1"),
    ("WA-SS-045", "Business Logic", "High-level logic vulnerability (order negative qty)", "High", "P1"),
    ("WA-SS-046", "Business Logic", "Low-level logic flaw (integer overflow on price)", "High", "P1"),
    ("WA-SS-047", "Business Logic", "Inconsistent security controls (email domain change)", "High", "P1"),
    ("WA-SS-048", "Business Logic", "Flawed enforcement of business rules (discount stacking)", "Medium", "P2"),
    ("WA-SS-049", "Business Logic", "Infinite money logic flaw (gift card loop)", "High", "P1"),
    ("WA-SS-050", "Business Logic", "Authentication bypass via flawed state machine", "Critical", "P1"),
    ("WA-SS-051", "Business Logic", "Flawed logic \u2014 weak isolation on dual-use endpoint", "High", "P1"),
    ("WA-SS-052", "Business Logic", "Insufficient workflow validation (skip steps)", "High", "P1"),
    ("WA-SS-053", "Business Logic", "Account takeover via password reset poisoning logic", "Critical", "P1"),
    ("WA-SS-054", "Business Logic", "Manipulation of hidden inputs/fields", "Medium", "P2"),
    ("WA-SS-055", "Information Disclosure", "Information disclosure in error messages (stack trace)", "Medium", "P2"),
    ("WA-SS-056", "Information Disclosure", "Info disclosure \u2014 debug page (phpinfo/rails debug)", "High", "P1"),
    ("WA-SS-057", "Information Disclosure", "Info disclosure \u2014 source code via backup files", "High", "P1"),
    ("WA-SS-058", "Information Disclosure", "Info disclosure \u2014 version via response headers", "Low", "P3"),
    ("WA-SS-059", "Information Disclosure", "Info disclosure \u2014 sensitive data in git/svn/.DS_Store", "High", "P1"),
    ("WA-SS-060", "Access Control", "Unprotected admin functionality (robots.txt leak)", "Critical", "P1"),
    ("WA-SS-061", "Access Control", "Unprotected admin \u2014 unpredictable URL via source", "High", "P1"),
    ("WA-SS-062", "Access Control", "Parameter-based access control (admin=true cookie)", "Critical", "P1"),
    ("WA-SS-063", "Access Control", "Broken access \u2014 relying on obscurity (security by header)", "High", "P1"),
    ("WA-SS-064", "Access Control", "URL-based access control bypass (X-Original-URL)", "High", "P1"),
    ("WA-SS-065", "Access Control", "Method-based access control bypass (GET\u2192POST/POST\u2192GET)", "High", "P1"),
    ("WA-SS-066", "Access Control", "IDOR \u2014 direct object reference (change user ID in URL)", "Critical", "P1"),
    ("WA-SS-067", "Access Control", "IDOR \u2014 in non-numeric IDs (GUID/UUID)", "High", "P1"),
    ("WA-SS-068", "Access Control", "IDOR \u2014 via redirect (302 still returns body)", "High", "P1"),
    ("WA-SS-069", "Access Control", "Multi-step process bypass (skip confirmation step)", "High", "P1"),
    ("WA-SS-070", "Access Control", "Referer-based access control bypass", "High", "P1"),
    ("WA-SS-071", "Access Control", "Horizontal privilege escalation (access another user data)", "Critical", "P1"),
    ("WA-SS-072", "Access Control", "Vertical privilege escalation (user \u2192 admin actions)", "Critical", "P1"),
    ("WA-SS-073", "File Upload", "File upload \u2014 unrestricted (webshell upload)", "Critical", "P1"),
    ("WA-SS-074", "File Upload", "File upload \u2014 content-type bypass (image/jpeg \u2192 PHP)", "Critical", "P1"),
    ("WA-SS-075", "File Upload", "File upload \u2014 blacklist bypass (.php5 / .phtml / .phar)", "Critical", "P1"),
    ("WA-SS-076", "File Upload", "File upload \u2014 obfuscated extension (.pHp / .%00.php)", "High", "P1"),
    ("WA-SS-077", "File Upload", "File upload \u2014 flawed validation of file contents", "High", "P1"),
    ("WA-SS-078", "File Upload", "File upload \u2014 polyglot webshell (JPEG + PHP)", "High", "P1"),
    ("WA-SS-079", "File Upload", "File upload \u2014 path traversal in filename", "High", "P1"),
    ("WA-SS-080", "Race Conditions", "Race condition \u2014 limit overrun (redeem coupon multiple times)", "High", "P1"),
    ("WA-SS-081", "Race Conditions", "Race condition \u2014 bypassing rate limits via parallel requests", "High", "P1"),
    ("WA-SS-082", "Race Conditions", "Race condition \u2014 single-endpoint TOCTOU", "High", "P1"),
    ("WA-SS-083", "Race Conditions", "Race condition \u2014 multi-endpoint state clash", "High", "P1"),
    ("WA-SS-084", "Race Conditions", "Race condition \u2014 partial construction attack", "Medium", "P2"),
    ("WA-SS-085", "Race Conditions", "Race condition \u2014 time-sensitive hidden token brute force", "High", "P1"),
    ("WA-SS-086", "SSRF", "SSRF against server itself (127.0.0.1 loopback)", "Critical", "P1"),
    ("WA-SS-087", "SSRF", "SSRF against backend internal systems", "Critical", "P1"),
    ("WA-SS-088", "SSRF", "SSRF bypass \u2014 blacklist filter (127.1 / 2130706433)", "High", "P1"),
    ("WA-SS-089", "SSRF", "SSRF bypass \u2014 whitelist filter via open redirect", "High", "P1"),
    ("WA-SS-090", "SSRF", "Blind SSRF \u2014 out-of-band detection (Referer header)", "High", "P1"),
    ("WA-SS-091", "SSRF", "Blind SSRF \u2014 shellshock exploit via User-Agent", "Critical", "P1"),
    ("WA-SS-092", "SSRF", "SSRF via cloud metadata endpoint (169.254.169.254)", "Critical", "P1"),
    ("WA-SS-093", "XXE Injection", "XXE \u2014 retrieve files via external entity", "Critical", "P1"),
    ("WA-SS-094", "XXE Injection", "XXE \u2014 SSRF via external entity", "Critical", "P1"),
    ("WA-SS-095", "XXE Injection", "Blind XXE \u2014 out-of-band interaction", "High", "P1"),
    ("WA-SS-096", "XXE Injection", "Blind XXE \u2014 out-of-band via XML parameter entity", "High", "P1"),
    ("WA-SS-097", "XXE Injection", "Blind XXE \u2014 data exfiltration via error message", "High", "P1"),
    ("WA-SS-098", "XXE Injection", "Blind XXE \u2014 out-of-band exfil via repurposed local DTD", "High", "P1"),
    ("WA-SS-099", "XXE Injection", "XXE \u2014 via file upload (SVG/Office formats)", "High", "P1"),
    ("WA-SS-100", "XXE Injection", "XXE \u2014 via modified content-type (JSON\u2192XML)", "High", "P1"),
    ("WA-SS-101", "XXE Injection", "XInclude attacks (when full XML doc control not possible)", "High", "P1"),
    ("WA-SS-102", "NoSQL Injection", "NoSQLi \u2014 detect / bypass authentication ($ne operator)", "Critical", "P1"),
    ("WA-SS-103", "NoSQL Injection", "NoSQLi \u2014 extract data via operator injection", "High", "P1"),
    ("WA-SS-104", "NoSQL Injection", "NoSQLi \u2014 timing-based blind injection", "High", "P1"),
    ("WA-SS-105", "NoSQL Injection", "NoSQLi \u2014 JavaScript injection ($where clause)", "High", "P1"),
    ("WA-SS-106", "API Testing", "API recon \u2014 discover hidden endpoints via JS/docs/wordlist", "High", "P1"),
    ("WA-SS-107", "API Testing", "API \u2014 find hidden params via mass assignment", "High", "P1"),
    ("WA-SS-108", "API Testing", "API \u2014 exploiting unused/debug endpoints", "High", "P1"),
    ("WA-SS-109", "API Testing", "API \u2014 HTTP verb tampering on REST endpoints", "Medium", "P2"),
    ("WA-SS-110", "API Testing", "API \u2014 server-side parameter pollution (SSPP)", "High", "P1"),
    ("WA-SS-111", "Web Cache Deception", "Cache deception \u2014 force cache of private data via path suffix", "High", "P1"),
    ("WA-SS-112", "Web Cache Deception", "Cache deception \u2014 delimiter-based (delimiter discrepancy)", "High", "P1"),
    ("WA-SS-113", "Web Cache Deception", "Cache deception \u2014 delimiter decoding discrepancy", "High", "P1"),
    ("WA-SS-114", "Web Cache Deception", "Cache deception \u2014 static extension path confusion", "High", "P1"),
    ("WA-SS-115", "Web Cache Deception", "Cache deception \u2014 normalization discrepancy", "Medium", "P2"),
    ("WA-CS-116", "Cross-Site Scripting (XSS)", "Reflected XSS \u2014 simple HTML context", "High", "P1"),
    ("WA-CS-117", "Cross-Site Scripting (XSS)", "Stored XSS \u2014 simple HTML context", "High", "P1"),
    ("WA-CS-118", "Cross-Site Scripting (XSS)", "DOM-based XSS \u2014 innerHTML sink", "High", "P1"),
    ("WA-CS-119", "Cross-Site Scripting (XSS)", "DOM-based XSS \u2014 document.write sink", "High", "P1"),
    ("WA-CS-120", "Cross-Site Scripting (XSS)", "DOM-based XSS \u2014 location.search AngularJS expression", "High", "P1"),
    ("WA-CS-121", "Cross-Site Scripting (XSS)", "Reflected DOM XSS via JSON injection", "High", "P1"),
    ("WA-CS-122", "Cross-Site Scripting (XSS)", "Stored DOM XSS via innerHTML", "High", "P1"),
    ("WA-CS-123", "Cross-Site Scripting (XSS)", "XSS via HTML attribute encoding bypass", "High", "P1"),
    ("WA-CS-124", "Cross-Site Scripting (XSS)", "XSS via href attribute (javascript:alert)", "High", "P1"),
    ("WA-CS-125", "Cross-Site Scripting (XSS)", "XSS via JS string escape with backslash", "High", "P1"),
    ("WA-CS-126", "Cross-Site Scripting (XSS)", "XSS into JS template literal", "High", "P1"),
    ("WA-CS-127", "Cross-Site Scripting (XSS)", "XSS \u2014 CSP bypass via dangling markup", "High", "P1"),
    ("WA-CS-128", "Cross-Site Scripting (XSS)", "XSS \u2014 bypass CSP via nonce reuse", "High", "P1"),
    ("WA-CS-129", "Cross-Site Scripting (XSS)", "XSS \u2014 bypass CSP via hash mismatch", "High", "P1"),
    ("WA-CS-130", "Cross-Site Scripting (XSS)", "XSS \u2014 SVG tag injection", "High", "P1"),
    ("WA-CS-131", "Cross-Site Scripting (XSS)", "XSS \u2014 polyglot payload", "High", "P1"),
    ("WA-CS-132", "Cross-Site Scripting (XSS)", "XSS \u2014 tag attribute context (event handler injection)", "High", "P1"),
    ("WA-CS-133", "Cross-Site Scripting (XSS)", "XSS \u2014 custom tag injection with autofocus/tabindex", "Medium", "P2"),
    ("WA-CS-134", "Cross-Site Scripting (XSS)", "XSS \u2014 onload iframe injection", "High", "P1"),
    ("WA-CS-135", "Cross-Site Scripting (XSS)", "XSS \u2014 Unicode / HTML entity bypass", "High", "P1"),
    ("WA-CS-136", "Cross-Site Scripting (XSS)", "XSS \u2014 WAF bypass using less-common event handlers", "High", "P1"),
    ("WA-CS-137", "Cross-Site Scripting (XSS)", "Reflected XSS \u2014 cookie extraction PoC", "High", "P1"),
    ("WA-CS-138", "Cross-Site Scripting (XSS)", "Stored XSS \u2014 keylogger injection PoC", "High", "P1"),
    ("WA-CS-139", "Cross-Site Scripting (XSS)", "XSS \u2014 account takeover via password change form", "Critical", "P1"),
    ("WA-CS-140", "Cross-Site Scripting (XSS)", "XSS \u2014 session hijacking via document.cookie exfil", "Critical", "P1"),
    ("WA-CS-141", "Cross-Site Scripting (XSS)", "XSS \u2014 clickjacking + XSS chained attack", "High", "P1"),
    ("WA-CS-142", "Cross-Site Scripting (XSS)", "XSS \u2014 DOM clobbering to bypass purification", "High", "P1"),
    ("WA-CS-143", "Cross-Site Scripting (XSS)", "XSS \u2014 open redirect via location.hash", "Medium", "P2"),
    ("WA-CS-144", "Cross-Site Scripting (XSS)", "DOM XSS \u2014 jQuery selector sink ($())", "High", "P1"),
    ("WA-CS-145", "Cross-Site Scripting (XSS)", "DOM XSS \u2014 jQuery attr() hashchange event", "High", "P1"),
    ("WA-CS-146", "CSRF", "CSRF \u2014 simple GET request no token", "High", "P1"),
    ("WA-CS-147", "CSRF", "CSRF \u2014 token validation depends on request method (GET ok)", "High", "P1"),
    ("WA-CS-148", "CSRF", "CSRF \u2014 token validation depends on token being present", "High", "P1"),
    ("WA-CS-149", "CSRF", "CSRF \u2014 token not tied to user session", "High", "P1"),
    ("WA-CS-150", "CSRF", "CSRF \u2014 token tied to non-session cookie", "High", "P1"),
    ("WA-CS-151", "CSRF", "CSRF \u2014 token duplicated in cookie", "High", "P1"),
    ("WA-CS-152", "CSRF", "CSRF \u2014 Referer-based defense bypass (remove header)", "High", "P1"),
    ("WA-CS-153", "CSRF", "CSRF \u2014 Referer header whitelist bypass", "High", "P1"),
    ("WA-CS-154", "CSRF", "CSRF \u2014 SameSite Lax bypass via GET method override", "High", "P1"),
    ("WA-CS-155", "CSRF", "CSRF \u2014 SameSite Strict bypass via sibling domain redirect", "High", "P1"),
    ("WA-CS-156", "CSRF", "CSRF \u2014 SameSite Lax bypass via cookie refresh", "Medium", "P2"),
    ("WA-CS-157", "CSRF", "CSRF \u2014 bypass via browser cookie injection (CRLF chain)", "High", "P1"),
    ("WA-CS-158", "CORS", "CORS \u2014 misconfig: wildcard/reflected origin trusts attacker", "High", "P1"),
    ("WA-CS-159", "CORS", "CORS \u2014 null origin trusted (sandbox iframe bypass)", "High", "P1"),
    ("WA-CS-160", "CORS", "CORS \u2014 intranet pivot via trusted whitelisted origin", "High", "P1"),
    ("WA-CS-161", "Clickjacking", "Clickjacking \u2014 basic UI redress attack (iframe overlay)", "Medium", "P2"),
    ("WA-CS-162", "Clickjacking", "Clickjacking \u2014 form pre-fill attack", "Medium", "P2"),
    ("WA-CS-163", "Clickjacking", "Clickjacking \u2014 frame-busting script bypass", "Medium", "P2"),
    ("WA-CS-164", "Clickjacking", "Clickjacking \u2014 multistep attack (confirm + click)", "Medium", "P2"),
    ("WA-CS-165", "Clickjacking", "Clickjacking \u2014 drag-and-drop UI attack", "Medium", "P2"),
    ("WA-CS-166", "DOM-based Vulnerabilities", "DOM-based open redirect (location.href taint)", "Medium", "P2"),
    ("WA-CS-167", "DOM-based Vulnerabilities", "DOM-based cookie manipulation", "Medium", "P2"),
    ("WA-CS-168", "DOM-based Vulnerabilities", "DOM-based XSS via web messages", "High", "P1"),
    ("WA-CS-169", "DOM-based Vulnerabilities", "DOM-based open redirect via web messages", "Medium", "P2"),
    ("WA-CS-170", "DOM-based Vulnerabilities", "DOM-based XSS via web messages and JSON.parse", "High", "P1"),
    ("WA-CS-171", "DOM-based Vulnerabilities", "DOM clobbering \u2014 bypass HTML sanitiser", "High", "P1"),
    ("WA-CS-172", "DOM-based Vulnerabilities", "Clobbering DOM attributes to bypass sanitisation", "High", "P1"),
    ("WA-CS-173", "WebSockets", "WebSocket \u2014 manipulating messages (stored XSS)", "High", "P1"),
    ("WA-CS-174", "WebSockets", "WebSocket \u2014 cross-site hijacking (CSWSH)", "High", "P1"),
    ("WA-CS-175", "WebSockets", "WebSocket \u2014 CSWSH to read sensitive messages", "High", "P1"),
    ("WA-ADV-176", "Insecure Deserialization", "Deserialization \u2014 modify serialized data (PHP object)", "High", "P1"),
    ("WA-ADV-177", "Insecure Deserialization", "Deserialization \u2014 modify data types (PHP loose comparison)", "High", "P1"),
    ("WA-ADV-178", "Insecure Deserialization", "Deserialization \u2014 arbitrary object injection", "Critical", "P1"),
    ("WA-ADV-179", "Insecure Deserialization", "Deserialization \u2014 magic method abuse", "Critical", "P1"),
    ("WA-ADV-180", "Insecure Deserialization", "Deserialization \u2014 PHP gadget chain (RCE)", "Critical", "P1"),
    ("WA-ADV-181", "Insecure Deserialization", "Deserialization \u2014 Java gadget chain (Commons Collections)", "Critical", "P1"),
    ("WA-ADV-182", "Insecure Deserialization", "Deserialization \u2014 Python pickle RCE", "Critical", "P1"),
    ("WA-ADV-183", "Insecure Deserialization", "Deserialization \u2014 PHAR PHP deserialization via file upload", "Critical", "P1"),
    ("WA-ADV-184", "Insecure Deserialization", "Deserialization \u2014 Ruby gadget chain RCE", "Critical", "P1"),
    ("WA-ADV-185", "Insecure Deserialization", "Deserialization \u2014 using pre-built gadget chains (tool-based)", "Critical", "P1"),
    ("WA-ADV-186", "Web LLM Attacks", "LLM \u2014 indirect prompt injection via stored content", "High", "P1"),
    ("WA-ADV-187", "Web LLM Attacks", "LLM \u2014 direct prompt injection (jailbreak system prompt)", "High", "P1"),
    ("WA-ADV-188", "Web LLM Attacks", "LLM \u2014 exploiting APIs via prompt injection", "Critical", "P1"),
    ("WA-ADV-189", "Web LLM Attacks", "LLM \u2014 data exfiltration via indirect injection", "High", "P1"),
    ("WA-ADV-190", "Web LLM Attacks", "LLM \u2014 SSRF via prompt injection (Markdown link exfil)", "High", "P1"),
    ("WA-ADV-191", "Web LLM Attacks", "LLM \u2014 insecure plugin/tool invocation", "High", "P1"),
    ("WA-ADV-192", "Web LLM Attacks", "LLM \u2014 training data extraction attack", "Medium", "P2"),
    ("WA-ADV-193", "GraphQL API Security", "GraphQL \u2014 introspection enabled (full schema exposure)", "Medium", "P2"),
    ("WA-ADV-194", "GraphQL API Security", "GraphQL \u2014 bypassing introspection defences", "Medium", "P2"),
    ("WA-ADV-195", "GraphQL API Security", "GraphQL \u2014 accidental data exposure via aliases", "High", "P1"),
    ("WA-ADV-196", "GraphQL API Security", "GraphQL \u2014 CSRF via GET request mutations", "High", "P1"),
    ("WA-ADV-197", "GraphQL API Security", "GraphQL \u2014 batching attack (rate-limit bypass / brute-force)", "High", "P1"),
    ("WA-ADV-198", "Server-Side Template Injection", "SSTI \u2014 detect ({{7*7}} / ${7*7} / #{7*7})", "Critical", "P1"),
    ("WA-ADV-199", "Server-Side Template Injection", "SSTI \u2014 Jinja2 / Python sandbox escape \u2192 RCE", "Critical", "P1"),
    ("WA-ADV-200", "Server-Side Template Injection", "SSTI \u2014 Twig (PHP) \u2192 code exec", "Critical", "P1"),
    ("WA-ADV-201", "Server-Side Template Injection", "SSTI \u2014 FreeMarker (Java) \u2192 RCE", "Critical", "P1"),
    ("WA-ADV-202", "Server-Side Template Injection", "SSTI \u2014 Velocity (Java) \u2192 RCE", "Critical", "P1"),
    ("WA-ADV-203", "Server-Side Template Injection", "SSTI \u2014 unknown engine identification", "High", "P1"),
    ("WA-ADV-204", "Server-Side Template Injection", "SSTI \u2014 sandbox escape via custom filter/method", "Critical", "P1"),
    ("WA-ADV-205", "Web Cache Poisoning", "Cache poisoning \u2014 basic via X-Forwarded-Host", "High", "P1"),
    ("WA-ADV-206", "Web Cache Poisoning", "Cache poisoning \u2014 unknown header (X-Forwarded-Scheme)", "High", "P1"),
    ("WA-ADV-207", "Web Cache Poisoning", "Cache poisoning \u2014 multiple headers required", "High", "P1"),
    ("WA-ADV-208", "Web Cache Poisoning", "Cache poisoning \u2014 targeted at specific user", "High", "P1"),
    ("WA-ADV-209", "Web Cache Poisoning", "Cache poisoning \u2014 via DOM-based vulnerability", "High", "P1"),
    ("WA-ADV-210", "Web Cache Poisoning", "Cache poisoning \u2014 chained with open redirect", "High", "P1"),
    ("WA-ADV-211", "Web Cache Poisoning", "Cache poisoning \u2014 via unkeyed query string", "High", "P1"),
    ("WA-ADV-212", "Web Cache Poisoning", "Cache poisoning \u2014 via unkeyed query parameters", "High", "P1"),
    ("WA-ADV-213", "Web Cache Poisoning", "Cache poisoning \u2014 parameter cloaking (delimiter discrepancy)", "High", "P1"),
    ("WA-ADV-214", "Web Cache Poisoning", "Cache poisoning \u2014 via fat GET request", "Medium", "P2"),
    ("WA-ADV-215", "Web Cache Poisoning", "Cache poisoning \u2014 URL normalization", "Medium", "P2"),
    ("WA-ADV-216", "Web Cache Poisoning", "Cache poisoning \u2014 response header injection (CRLF)", "High", "P1"),
    ("WA-ADV-217", "Web Cache Poisoning", "Cache poisoning \u2014 internal cache via request headers", "High", "P1"),
    ("WA-ADV-218", "HTTP Host Header Attacks", "Host header \u2014 password reset poisoning", "High", "P1"),
    ("WA-ADV-219", "HTTP Host Header Attacks", "Host header \u2014 web cache poisoning via Host", "High", "P1"),
    ("WA-ADV-220", "HTTP Host Header Attacks", "Host header \u2014 SSRF via malformed Host header", "High", "P1"),
    ("WA-ADV-221", "HTTP Host Header Attacks", "Host header \u2014 bypass internal authentication (localhost)", "Critical", "P1"),
    ("WA-ADV-222", "HTTP Host Header Attacks", "Host header \u2014 routing-based SSRF (ambiguous requests)", "High", "P1"),
    ("WA-ADV-223", "HTTP Host Header Attacks", "Host header \u2014 SSRF via connection header", "High", "P1"),
    ("WA-ADV-224", "HTTP Host Header Attacks", "Host header \u2014 X-Host / X-Forwarded-Server override", "High", "P1"),
    ("WA-ADV-225", "HTTP Request Smuggling", "Smuggling \u2014 detect CL.TE using timing", "High", "P1"),
    ("WA-ADV-226", "HTTP Request Smuggling", "Smuggling \u2014 detect TE.CL using timing", "High", "P1"),
    ("WA-ADV-227", "HTTP Request Smuggling", "Smuggling \u2014 CL.TE basic exploit", "Critical", "P1"),
    ("WA-ADV-228", "HTTP Request Smuggling", "Smuggling \u2014 TE.CL basic exploit", "Critical", "P1"),
    ("WA-ADV-229", "HTTP Request Smuggling", "Smuggling \u2014 TE.TE: obfuscating TE header", "Critical", "P1"),
    ("WA-ADV-230", "HTTP Request Smuggling", "Smuggling \u2014 bypass front-end security controls (access control)", "Critical", "P1"),
    ("WA-ADV-231", "HTTP Request Smuggling", "Smuggling \u2014 reveal front-end request rewriting", "High", "P1"),
    ("WA-ADV-232", "HTTP Request Smuggling", "Smuggling \u2014 capture other users' requests", "Critical", "P1"),
    ("WA-ADV-233", "HTTP Request Smuggling", "Smuggling \u2014 exploit reflected XSS via smuggled request", "High", "P1"),
    ("WA-ADV-234", "HTTP Request Smuggling", "Smuggling \u2014 turn reflected XSS into stored via smuggling", "High", "P1"),
    ("WA-ADV-235", "HTTP Request Smuggling", "Smuggling \u2014 SSRF via HTTP request smuggling", "High", "P1"),
    ("WA-ADV-236", "HTTP Request Smuggling", "Smuggling \u2014 poison web cache via differential response", "High", "P1"),
    ("WA-ADV-237", "HTTP Request Smuggling", "HTTP/2 \u2014 H2.CL request smuggling", "Critical", "P1"),
    ("WA-ADV-238", "HTTP Request Smuggling", "HTTP/2 \u2014 H2.TE request smuggling", "Critical", "P1"),
    ("WA-ADV-239", "HTTP Request Smuggling", "HTTP/2 \u2014 response queue poisoning via H2.TE", "Critical", "P1"),
    ("WA-ADV-240", "HTTP Request Smuggling", "HTTP/2 \u2014 request tunnel via header-based injection", "High", "P1"),
    ("WA-ADV-241", "HTTP Request Smuggling", "HTTP/2 \u2014 bypass front-end controls with H2 downgrade", "Critical", "P1"),
    ("WA-ADV-242", "HTTP Request Smuggling", "HTTP/2 \u2014 SSRF via CRLF injection in header name", "High", "P1"),
    ("WA-ADV-243", "HTTP Request Smuggling", "HTTP/2 \u2014 client-side desync exploitation", "High", "P1"),
    ("WA-ADV-244", "HTTP Request Smuggling", "HTTP/2 \u2014 server-side pause-based desync", "High", "P1"),
    ("WA-ADV-245", "HTTP Request Smuggling", "HTTP/2 \u2014 exploiting URL prefix injection", "High", "P1"),
    ("WA-ADV-246", "HTTP Request Smuggling", "HTTP/2 \u2014 browser-powered request smuggling (Chrome + JS)", "High", "P1"),
    ("WA-ADV-247", "OAuth 2.0", "OAuth \u2014 authentication bypass via implicit flow", "Critical", "P1"),
    ("WA-ADV-248", "OAuth 2.0", "OAuth \u2014 CSRF against OAuth state parameter", "High", "P1"),
    ("WA-ADV-249", "OAuth 2.0", "OAuth \u2014 stealing codes via open redirect", "High", "P1"),
    ("WA-ADV-250", "OAuth 2.0", "OAuth \u2014 stealing tokens via proxy page", "High", "P1"),
    ("WA-ADV-251", "OAuth 2.0", "OAuth \u2014 SSRF via dynamic client registration", "High", "P1"),
    ("WA-ADV-252", "OAuth 2.0", "OAuth \u2014 Account hijack via redirect_uri manipulation", "Critical", "P1"),
    ("WA-ADV-253", "JWT Attacks", "JWT \u2014 bypass via unverified signature", "Critical", "P1"),
    ("WA-ADV-254", "JWT Attacks", "JWT \u2014 bypass via alg:none", "Critical", "P1"),
    ("WA-ADV-255", "JWT Attacks", "JWT \u2014 brute-force weak HMAC secret", "High", "P1"),
    ("WA-ADV-256", "JWT Attacks", "JWT \u2014 algorithm confusion (RS256 \u2192 HS256 with public key)", "Critical", "P1"),
    ("WA-ADV-257", "JWT Attacks", "JWT \u2014 inject self-signed JWK via jwk header", "Critical", "P1"),
    ("WA-ADV-258", "JWT Attacks", "JWT \u2014 inject self-signed via jku parameter", "Critical", "P1"),
    ("WA-ADV-259", "JWT Attacks", "JWT \u2014 inject via kid path traversal (read /dev/null \u2192 empty)", "Critical", "P1"),
    ("WA-ADV-260", "JWT Attacks", "JWT \u2014 kid SQL injection to sign with null byte", "Critical", "P1"),
    ("WA-ADV-261", "Prototype Pollution", "Prototype pollution \u2014 client-side via query string", "High", "P1"),
    ("WA-ADV-262", "Prototype Pollution", "Prototype pollution \u2014 client-side via URL fragment", "High", "P1"),
    ("WA-ADV-263", "Prototype Pollution", "Prototype pollution \u2014 client-side via JSON (Object.assign)", "High", "P1"),
    ("WA-ADV-264", "Prototype Pollution", "Prototype pollution \u2014 bypassing flawed key sanitisation", "High", "P1"),
    ("WA-ADV-265", "Prototype Pollution", "Prototype pollution \u2014 gadget chain \u2192 DOM XSS", "High", "P1"),
    ("WA-ADV-266", "Prototype Pollution", "Prototype pollution \u2014 gadget chain \u2192 reflected XSS", "High", "P1"),
    ("WA-ADV-267", "Prototype Pollution", "Prototype pollution \u2014 server-side (Node.js) via JSON body", "Critical", "P1"),
    ("WA-ADV-268", "Prototype Pollution", "Prototype pollution \u2014 server-side via query string", "Critical", "P1"),
    ("WA-ADV-269", "Prototype Pollution", "Prototype pollution \u2014 server-side RCE gadget", "Critical", "P1"),
    ("WA-ADV-270", "Prototype Pollution", "Prototype pollution \u2014 detect server-side using timing attack", "High", "P1"),
    ("WA-ADV-271", "Essential Skills", "Obfuscating attacks \u2014 bypass filters via multiple encoding", "Medium", "P2"),
    ("WA-ADV-272", "Essential Skills", "Identify unknown vuln class via error messages + fuzzing", "Medium", "P2"),
    ("WA-OTG-273", "Information Gathering", "Conduct search engine recon (Google dorks, Shodan)", "Info", "P3"),
    ("WA-OTG-274", "Information Gathering", "Fingerprint web server (Server header, error pages)", "Low", "P3"),
    ("WA-OTG-275", "Information Gathering", "Review webserver metafiles (robots.txt, sitemap.xml)", "Low", "P3"),
    ("WA-OTG-276", "Information Gathering", "Enumerate application entry points (all params/forms)", "Info", "P3"),
    ("WA-OTG-277", "Information Gathering", "Map execution paths through application", "Info", "P3"),
    ("WA-OTG-278", "Information Gathering", "Fingerprint web application framework", "Low", "P3"),
    ("WA-OTG-279", "Information Gathering", "Map application architecture (CDN, WAF, LB, proxy layers)", "Info", "P3"),
    ("WA-OTG-280", "Information Gathering", "Identify application dependencies (package.json, Gemfile, pom)", "Low", "P3"),
    ("WA-OTG-281", "Information Gathering", "Harvest emails, usernames, phone numbers from app", "Info", "P3"),
    ("WA-OTG-282", "Information Gathering", "Identify cloud storage buckets (S3, GCS, Azure Blob)", "High", "P1"),
    ("WA-OTG-283", "Configuration Testing", "Test network/infrastructure config (exposed admin ports)", "High", "P1"),
    ("WA-OTG-284", "Configuration Testing", "Test application platform configuration (default creds)", "High", "P1"),
    ("WA-OTG-285", "Configuration Testing", "Test file extension handling (.bak .old .orig .swp)", "High", "P1"),
    ("WA-OTG-286", "Configuration Testing", "Review backup and unreferenced files", "High", "P1"),
    ("WA-OTG-287", "Configuration Testing", "Enumerate infrastructure and admin interfaces", "Critical", "P1"),
    ("WA-OTG-288", "Configuration Testing", "Test HTTP methods (PUT/DELETE/OPTIONS/TRACE)", "Medium", "P2"),
    ("WA-OTG-289", "Configuration Testing", "Test HTTP Strict Transport Security (HSTS present?)", "Medium", "P2"),
    ("WA-OTG-290", "Configuration Testing", "Test RIA cross domain policy (crossdomain.xml / clientaccesspolicy)", "Medium", "P2"),
    ("WA-OTG-291", "Configuration Testing", "Test file permissions on web server", "Medium", "P2"),
    ("WA-OTG-292", "Configuration Testing", "Test subdomain takeover", "High", "P1"),
    ("WA-OTG-293", "Configuration Testing", "Test cloud storage permissions (public buckets/blobs)", "High", "P1"),
    ("WA-OTG-294", "Configuration Testing", "Test content security policy (CSP header analysis)", "Medium", "P2"),
    ("WA-OTG-295", "Identity Management", "Test role definitions (RBAC enforcement)", "High", "P1"),
    ("WA-OTG-296", "Identity Management", "Test user registration process (self-registration flaws)", "Medium", "P2"),
    ("WA-OTG-297", "Identity Management", "Test account provisioning process", "Medium", "P2"),
    ("WA-OTG-298", "Identity Management", "Test account enumeration (registration / login / password reset)", "Medium", "P2"),
    ("WA-OTG-299", "Identity Management", "Test weak/default credentials policy", "High", "P1"),
    ("WA-OTG-300", "Identity Management", "Test username policy (predictability)", "Low", "P3"),
    ("WA-OTG-301", "Authentication Testing", "Test credentials over encrypted channel (HTTPS enforced)", "High", "P1"),
    ("WA-OTG-302", "Authentication Testing", "Test default credentials (admin/admin, admin/password)", "Critical", "P1"),
    ("WA-OTG-303", "Authentication Testing", "Test account lockout / brute-force protection", "High", "P1"),
    ("WA-OTG-304", "Authentication Testing", "Test for authentication bypass via parameter manipulation", "Critical", "P1"),
    ("WA-OTG-305", "Authentication Testing", "Test remember-me functionality", "Medium", "P2"),
    ("WA-OTG-306", "Authentication Testing", "Test browser cache for sensitive data after logout", "Medium", "P2"),
    ("WA-OTG-307", "Authentication Testing", "Test password policy (complexity, length, history)", "Medium", "P2"),
    ("WA-OTG-308", "Authentication Testing", "Test password reset / forgot password", "High", "P1"),
    ("WA-OTG-309", "Authentication Testing", "Test password change (old password required?)", "Medium", "P2"),
    ("WA-OTG-310", "Authentication Testing", "Test multi-factor authentication (bypass attempts)", "High", "P1"),
    ("WA-OTG-311", "Authorization Testing", "Test directory traversal / file include", "High", "P1"),
    ("WA-OTG-312", "Authorization Testing", "Test bypassing authorization schema (force browse)", "Critical", "P1"),
    ("WA-OTG-313", "Authorization Testing", "Test privilege escalation (horizontal + vertical)", "Critical", "P1"),
    ("WA-OTG-314", "Authorization Testing", "Test insecure direct object references (IDOR)", "High", "P1"),
    ("WA-OTG-315", "Session Management Testing", "Test session management schema (token analysis)", "High", "P1"),
    ("WA-OTG-316", "Session Management Testing", "Test cookie attributes (Secure, HttpOnly, SameSite, Path)", "Medium", "P2"),
    ("WA-OTG-317", "Session Management Testing", "Test session fixation (token recycled after login)", "High", "P1"),
    ("WA-OTG-318", "Session Management Testing", "Test exposed session variables (in URL, logs)", "Medium", "P2"),
    ("WA-OTG-319", "Session Management Testing", "Test CSRF protection (token validation, SameSite)", "High", "P1"),
    ("WA-OTG-320", "Session Management Testing", "Test logout functionality (server-side session invalidation)", "High", "P1"),
    ("WA-OTG-321", "Session Management Testing", "Test session timeout (idle + absolute)", "Medium", "P2"),
    ("WA-OTG-322", "Session Management Testing", "Test session puzzling / overloading", "Medium", "P2"),
    ("WA-OTG-323", "Session Management Testing", "Test session hijacking (token theft via XSS/MitM)", "High", "P1"),
    ("WA-OTG-324", "Input Validation Testing", "Test reflected XSS", "High", "P1"),
    ("WA-OTG-325", "Input Validation Testing", "Test stored XSS", "High", "P1"),
    ("WA-OTG-326", "Input Validation Testing", "Test HTTP verb tampering", "Medium", "P2"),
    ("WA-OTG-327", "Input Validation Testing", "Test HTTP parameter pollution (HPP)", "Medium", "P2"),
    ("WA-OTG-328", "Input Validation Testing", "Test SQL injection", "Critical", "P1"),
    ("WA-OTG-329", "Input Validation Testing", "Test LDAP injection", "High", "P1"),
    ("WA-OTG-330", "Input Validation Testing", "Test XML injection / XXE", "High", "P1"),
    ("WA-OTG-331", "Input Validation Testing", "Test SSI injection", "High", "P1"),
    ("WA-OTG-332", "Input Validation Testing", "Test XPath injection", "High", "P1"),
    ("WA-OTG-333", "Input Validation Testing", "Test IMAP/SMTP injection", "High", "P1"),
    ("WA-OTG-334", "Input Validation Testing", "Test code injection", "Critical", "P1"),
    ("WA-OTG-335", "Input Validation Testing", "Test OS command injection", "Critical", "P1"),
    ("WA-OTG-336", "Input Validation Testing", "Test format string injection", "High", "P1"),
    ("WA-OTG-337", "Input Validation Testing", "Test incubated / second-order injection", "High", "P1"),
    ("WA-OTG-338", "Input Validation Testing", "Test HTTP splitting / smuggling", "High", "P1"),
    ("WA-OTG-339", "Input Validation Testing", "Test template injection (SSTI)", "Critical", "P1"),
    ("WA-OTG-340", "Error Handling", "Test improper error handling (stack traces / debug info)", "Medium", "P2"),
    ("WA-OTG-341", "Error Handling", "Test error code disclosure (different HTTP error codes leak info)", "Low", "P3"),
    ("WA-OTG-342", "Weak Cryptography", "Test weak SSL/TLS config (SSLv3, TLS 1.0, weak ciphers)", "High", "P1"),
    ("WA-OTG-343", "Weak Cryptography", "Test insecure padding (POODLE, BEAST, LUCKY13)", "High", "P1"),
    ("WA-OTG-344", "Weak Cryptography", "Test encryption strength of sensitive data at rest", "High", "P1"),
    ("WA-OTG-345", "Weak Cryptography", "Test data encryption in transit (clear-text credentials)", "High", "P1"),
    ("WA-OTG-346", "Business Logic Testing", "Test business logic data validation", "High", "P1"),
    ("WA-OTG-347", "Business Logic Testing", "Test ability to forge requests", "High", "P1"),
    ("WA-OTG-348", "Business Logic Testing", "Test integrity checks (tamper-evident controls)", "High", "P1"),
    ("WA-OTG-349", "Business Logic Testing", "Test process timing (race conditions)", "High", "P1"),
    ("WA-OTG-350", "Business Logic Testing", "Test function usage limits (replay/reuse attacks)", "Medium", "P2"),
    ("WA-OTG-351", "Business Logic Testing", "Test workflow circumvention", "High", "P1"),
    ("WA-OTG-352", "Business Logic Testing", "Test defense against application misuse", "Medium", "P2"),
    ("WA-OTG-353", "Business Logic Testing", "Test upload of unexpected file types", "High", "P1"),
    ("WA-OTG-354", "Business Logic Testing", "Test upload of malicious files", "Critical", "P1"),
    ("WA-OTG-355", "Client-Side Testing", "Test DOM-based XSS", "High", "P1"),
    ("WA-OTG-356", "Client-Side Testing", "Test JavaScript execution", "High", "P1"),
    ("WA-OTG-357", "Client-Side Testing", "Test HTML injection", "Medium", "P2"),
    ("WA-OTG-358", "Client-Side Testing", "Test client-side URL redirect (open redirect)", "Medium", "P2"),
    ("WA-OTG-359", "Client-Side Testing", "Test CSS injection", "Medium", "P2"),
    ("WA-OTG-360", "Client-Side Testing", "Test client-side resource manipulation", "Medium", "P2"),
    ("WA-OTG-361", "Client-Side Testing", "Test cross-origin resource sharing (CORS)", "High", "P1"),
    ("WA-OTG-362", "Client-Side Testing", "Test cross-site flashing", "Medium", "P2"),
    ("WA-OTG-363", "Client-Side Testing", "Test clickjacking (X-Frame-Options / CSP frame-ancestors)", "Medium", "P2"),
    ("WA-OTG-364", "Client-Side Testing", "Test WebSockets security", "High", "P1"),
    ("WA-OTG-365", "Client-Side Testing", "Test web messaging (postMessage security)", "High", "P1"),
    ("WA-OTG-366", "Client-Side Testing", "Test local storage / sessionStorage for sensitive data", "Medium", "P2"),
    ("WA-LLM-367", "Prompt Injection", "LLM01 \u2014 Direct prompt injection (override system instructions)", "Critical", "P1"),
    ("WA-LLM-368", "Prompt Injection", "LLM01 \u2014 Indirect prompt injection via external content", "Critical", "P1"),
    ("WA-LLM-369", "Prompt Injection", "LLM01 \u2014 Jailbreak via role-play / fictional framing", "High", "P1"),
    ("WA-LLM-370", "Prompt Injection", "LLM01 \u2014 Multi-turn injection (across conversation turns)", "High", "P1"),
    ("WA-LLM-371", "Insecure Output Handling", "LLM02 \u2014 XSS via LLM output rendered in browser", "High", "P1"),
    ("WA-LLM-372", "Insecure Output Handling", "LLM02 \u2014 SQL injection via LLM-generated queries", "Critical", "P1"),
    ("WA-LLM-373", "Insecure Output Handling", "LLM02 \u2014 Code injection via LLM output executed server-side", "Critical", "P1"),
    ("WA-LLM-374", "Training Data Poisoning", "LLM03 \u2014 Extract training data / PII memorisation", "High", "P1"),
    ("WA-LLM-375", "Training Data Poisoning", "LLM03 \u2014 Probe for biased/backdoored outputs", "Medium", "P2"),
    ("WA-LLM-376", "Model Denial of Service", "LLM04 \u2014 Resource exhaustion via recursive/complex prompts", "Medium", "P2"),
    ("WA-LLM-377", "Model Denial of Service", "LLM04 \u2014 Context window flooding (DoS via large inputs)", "Medium", "P2"),
    ("WA-LLM-378", "Supply Chain Vulnerabilities", "LLM05 \u2014 Verify model provenance (signed model, hash check)", "High", "P1"),
    ("WA-LLM-379", "Supply Chain Vulnerabilities", "LLM05 \u2014 Third-party plugin/tool audit", "High", "P1"),
    ("WA-LLM-380", "Sensitive Information Disclosure", "LLM06 \u2014 Extract PII from LLM responses", "High", "P1"),
    ("WA-LLM-381", "Sensitive Information Disclosure", "LLM06 \u2014 System prompt extraction via probing", "High", "P1"),
    ("WA-LLM-382", "Sensitive Information Disclosure", "LLM06 \u2014 API key / secret extraction from model output", "Critical", "P1"),
    ("WA-LLM-383", "Insecure Plugin Design", "LLM07 \u2014 Plugin over-permission (access beyond scope)", "High", "P1"),
    ("WA-LLM-384", "Insecure Plugin Design", "LLM07 \u2014 Plugin input validation bypass", "High", "P1"),
    ("WA-LLM-385", "Insecure Plugin Design", "LLM07 \u2014 Chained plugin exploitation (multi-step tool abuse)", "High", "P1"),
    ("WA-LLM-386", "Excessive Agency", "LLM08 \u2014 LLM can perform unauthorized actions (write/delete)", "Critical", "P1"),
    ("WA-LLM-387", "Excessive Agency", "LLM08 \u2014 Identify overprivileged tool/API integrations", "High", "P1"),
    ("WA-LLM-388", "Overreliance on LLM Output", "LLM09 \u2014 Test for hallucinated content with security impact", "Medium", "P2"),
    ("WA-LLM-389", "Overreliance on LLM Output", "LLM09 \u2014 Test code generated by LLM for security vulnerabilities", "High", "P1"),
    ("WA-LLM-390", "Model Theft", "LLM10 \u2014 Model extraction via API probing / query attacks", "High", "P1"),
    ("WA-LLM-391", "Model Theft", "LLM10 \u2014 Membership inference attack", "Medium", "P2"),
    ("WA-HDR-392", "HTTP Security Headers", "Content-Security-Policy present and strict", "Medium", "P2"),
    ("WA-HDR-393", "HTTP Security Headers", "X-Frame-Options: SAMEORIGIN or DENY present", "Medium", "P2"),
    ("WA-HDR-394", "HTTP Security Headers", "X-Content-Type-Options: nosniff present", "Low", "P3"),
    ("WA-HDR-395", "HTTP Security Headers", "Strict-Transport-Security (HSTS) properly configured", "Medium", "P2"),
    ("WA-HDR-396", "HTTP Security Headers", "Referrer-Policy header present", "Low", "P3"),
    ("WA-HDR-397", "HTTP Security Headers", "Cache-Control: no-store on authenticated/sensitive pages", "Medium", "P2"),
    ("WA-HDR-398", "HTTP Security Headers", "Permissions-Policy restricts sensitive browser APIs", "Low", "P3"),
    ("WA-HDR-399", "HTTP Security Headers", "HTTPS enforced \u2014 HTTP redirects to HTTPS", "High", "P1"),
    ("WA-HDR-400", "HTTP Security Headers", "Verbose error messages / stack traces on 4xx/5xx", "Medium", "P2"),
    ("WA-HDR-401", "HTTP Security Headers", "Server version disclosure in response headers", "Low", "P3"),
    ("WA-TLS-402", "SSL / TLS", "SSL/TLS scan \u2014 grade and cipher strength", "High", "P1"),
    ("WA-TLS-403", "SSL / TLS", "SSLv2, SSLv3, TLSv1.0 disabled", "High", "P1"),
    ("WA-TLS-404", "SSL / TLS", "No weak cipher suites (RC4, DES, NULL, EXPORT)", "High", "P1"),
    ("WA-TLS-405", "SSL / TLS", "Certificate key strength >= 2048-bit RSA / 256-bit ECC", "Medium", "P2"),
    ("WA-TLS-406", "SSL / TLS", "Certificate uses SHA-256+ signature algorithm", "Medium", "P2"),
    ("WA-TLS-407", "SSL / TLS", "Certificate chain complete \u2014 no missing intermediates", "Medium", "P2"),
    ("WA-TLS-408", "SSL / TLS", "HSTS preload list configured", "Medium", "P2"),
    ("WA-TLS-409", "SSL / TLS", "WebSocket endpoints use WSS not WS", "High", "P1"),
    ("WA-MAIL-410", "Email Security", "SPF record present and uses hard fail (-all)", "Medium", "P2"),
    ("WA-MAIL-411", "Email Security", "DMARC policy configured (reject or quarantine)", "Medium", "P2"),
    ("WA-MAIL-412", "Email Security", "DKIM signing configured and valid", "Medium", "P2"),
    ("WA-MAIL-413", "Email Security", "Email spoofing possible if SPF/DMARC absent or weak", "High", "P1"),
    ("WA-SCAN-414", "Scan Tool Analysis", "Burp Suite active scan \u2014 triage all reported findings", "High", "P1"),
    ("WA-SCAN-415", "Scan Tool Analysis", "Nikto scan \u2014 dangerous files, outdated software, misconfigs", "Medium", "P2"),
    ("WA-SCAN-416", "Scan Tool Analysis", "Nuclei \u2014 run CVE, vulnerability and misconfiguration templates", "High", "P1"),
    ("WA-SCAN-417", "Scan Tool Analysis", "SQLMap \u2014 systematic injection testing on all parameters", "High", "P1"),
    ("WA-SCAN-418", "Scan Tool Analysis", "Vulnerable JS libraries \u2014 retire.js / npm audit", "Medium", "P2"),
    ("WA-LOG-419", "Insufficient Logging & Monitoring", "Failed login attempts not logged or triggering lockout", "Medium", "P2"),
    ("WA-LOG-420", "Insufficient Logging & Monitoring", "Sensitive operations not captured in audit log", "Medium", "P2"),
    ("WA-LOG-421", "Insufficient Logging & Monitoring", "No alerting on automated scanning or enumeration", "Medium", "P2"),
]
MASTER_CHECKLIST_BY_ID = {row[0]: row for row in MASTER_CHECKLIST}

# The ~77 IDs checklist_auto_scan.py's add() calls actually use (see its
# own module docstring) - re-extract any time the engine's checks change:
#   grep -oE '"WA-[A-Z0-9]+-[0-9]+"' checklist_auto_scan.py | sort -u
# Used to flag "(automated - already covered by Run All Tests)" in the
# Log Finding dialog's ID picker, so logging one manually is a deliberate
# choice (e.g. overriding/annotating an automated result), not confusion
# about which IDs still need manual coverage.
AUTOMATED_CHECKLIST_IDS = frozenset([
    "WA-ADV-218", "WA-ADV-219", "WA-ADV-220", "WA-ADV-221", "WA-ADV-222", "WA-ADV-223", "WA-ADV-224", "WA-CS-158",
    "WA-CS-159", "WA-CS-160", "WA-CS-161", "WA-CS-162", "WA-CS-163", "WA-CS-164", "WA-CS-165", "WA-HDR-392",
    "WA-HDR-393", "WA-HDR-394", "WA-HDR-395", "WA-HDR-396", "WA-HDR-397", "WA-HDR-398", "WA-HDR-399", "WA-HDR-400",
    "WA-HDR-401", "WA-MAIL-410", "WA-MAIL-411", "WA-MAIL-412", "WA-MAIL-413", "WA-OTG-273", "WA-OTG-274", "WA-OTG-275",
    "WA-OTG-276", "WA-OTG-277", "WA-OTG-278", "WA-OTG-279", "WA-OTG-280", "WA-OTG-281", "WA-OTG-282", "WA-OTG-283",
    "WA-OTG-284", "WA-OTG-285", "WA-OTG-286", "WA-OTG-287", "WA-OTG-288", "WA-OTG-289", "WA-OTG-290", "WA-OTG-291",
    "WA-OTG-292", "WA-OTG-293", "WA-OTG-294", "WA-OTG-312", "WA-OTG-314", "WA-OTG-315", "WA-OTG-316", "WA-OTG-317",
    "WA-OTG-318", "WA-OTG-319", "WA-OTG-320", "WA-OTG-321", "WA-OTG-322", "WA-OTG-323", "WA-OTG-366", "WA-SS-055",
    "WA-SS-056", "WA-SS-057", "WA-SS-058", "WA-SS-059", "WA-SS-071", "WA-TLS-402", "WA-TLS-403", "WA-TLS-404",
    "WA-TLS-405", "WA-TLS-406", "WA-TLS-407", "WA-TLS-408", "WA-TLS-409",
])

# Best-effort OWASP Top 10 (2021) mapping for the master checklist's
# other ~44 mappable categories (on top of the 13 automated ones already
# mapped above) - same "illustrative, not official" caveat applies.
# Categories intentionally left OUT (fall into OWASP_OTHER_KEY instead):
# the OWASP-Top-10-for-LLM-specific ones (Web LLM Attacks, Prompt
# Injection, Insecure Output Handling, Insecure Plugin Design, Training
# Data Poisoning, Model Denial of Service, Excessive Agency, Overreliance
# on LLM Output, Model Theft - these belong to a DIFFERENT OWASP list,
# forcing them into the web Top 10 would misclassify them) and pure
# testing-methodology labels that aren't a vulnerability class on their
# own (API Testing, Scan Tool Analysis, Essential Skills).
OWASP_CATEGORY_MAP.update({
    "SQL Injection": "A03",
    "Cross-Site Scripting (XSS)": "A03",
    "Command Injection": "A03",
    "NoSQL Injection": "A03",
    "XXE Injection": "A05",
    "Server-Side Template Injection": "A03",
    "DOM-based Vulnerabilities": "A03",
    "Prototype Pollution": "A03",
    "Path Traversal": "A01",
    "Insecure Deserialization": "A08",
    "Supply Chain Vulnerabilities": "A08",
    "Authentication": "A07",
    "Authentication Testing": "A07",
    "Identity Management": "A07",
    "OAuth 2.0": "A07",
    "JWT Attacks": "A07",
    "Business Logic": "A04",
    "Business Logic Testing": "A04",
    "Race Conditions": "A04",
    "File Upload": "A05",
    "CSRF": "A01",
    "SSRF": "A10",
    "Web Cache Poisoning": "A05",
    "Web Cache Deception": "A05",
    "Insufficient Logging & Monitoring": "A09",
    "Weak Cryptography": "A02",
    "Sensitive Information Disclosure": "A02",
    "Error Handling": "A05",
    "WebSockets": "A05",
    "GraphQL API Security": "A05",
    "Input Validation Testing": "A03",
})

# Reported directly: "when I can confirm the test XSS in repeater or
# proxy... understand how many findings have been covered" - the
# baseline category list now needs to be the FULL master checklist's
# categories, not just the 13 automatable ones, so Categories/Summary
# show every category (0-filled) whether or not anything's been logged
# against it yet - matches this feature's whole point (visualizing
# progress across all ~421 items, not just the ~77 automated ones).
KNOWN_CATEGORIES = sorted(set(row[1] for row in MASTER_CHECKLIST) | set(OWASP_CATEGORY_MAP.keys()))



# ---------------------------------------------------------------------
# Self-extracting scan engine: checklist_auto_scan.py's full source,
# base64-encoded, embedded directly in this file so the whole extension
# is ONE .py to download/install from the BApp Store / marketplace -
# no second file to lose, mismatch versions with, or have to explain
# how to co-locate. Reported directly: "make it one file instead of two
# python files so it is easy to share with burp extension marketplace
# without the dependency or need to share autoscan script separately."
#
# _materialize_engine_script() below decodes this and writes it out to a
# real .py file on disk at scan time (Jython can't execute this itself -
# see the module docstring at the top of this file for why the engine
# still runs as a separate CPython 3 subprocess) so nothing changes
# about HOW the engine runs, only about not needing a second file
# shipped/installed alongside this one.
#
# To update the bundled engine: replace checklist_auto_scan.py, then
# regenerate this constant from it (base64-encode the file). This copy
# is REV a25ffb67aa (first 10 hex chars of the source's sha256) - shown in
# the Configuration tab so it's obvious which engine build is bundled.
# REV a25ffb67aa adds the opt-in recon/discover/extscan/inject/exploit phase
# pipeline on top of the baseline ~100 checks (see checklist_auto_scan.py's
# --phases flag) - not yet exposed as its own UI control here, so this
# extension still only ever runs the baseline suite unless a future UI
# change passes --phases/--exploit/--i-am-authorized through explicitly.
ENGINE_SOURCE_REV = 'a25ffb67aa'
_ENGINE_SOURCE_B64 = (
    "IyEvdXNyL2Jpbi9lbnYgcHl0aG9uMwoiIiIKY2hlY2tsaXN0X2F1dG9fc2Nhbi5weQotLS0tLS0tLS0tLS0tLS0tLS0tLS0t"
    "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQpBdXRvbWF0ZWQgcHJlLWNoZWNrIHNj"
    "YW5uZXIgZm9yIHRoZSBwYXJ0cyBvZiB0aGUgV1BUIG1hc3RlciBjaGVja2xpc3QKKH40MjEgaXRlbXMsIGNhdGVnb3JpZXMg"
    "bGlrZSBTUUwgSW5qZWN0aW9uIC8gWFNTIC8gQnVzaW5lc3MgTG9naWMgLyBBdXRoClRlc3RpbmcgLyBSYWNlIENvbmRpdGlv"
    "bnMgLyBldGMuKSB0aGF0IENBTiBzYWZlbHkgYmUgdmVyaWZpZWQgYnkgYQpyZWFkLW9ubHkgc2NyaXB0OiBIVFRQIHJlc3Bv"
    "bnNlIGhlYWRlcnMsIFRMUyBoYW5kc2hha2UvY2VydGlmaWNhdGUgaW5mbywKRE5TIFRYVCByZWNvcmRzIChTUEYvRE1BUkMv"
    "REtJTSksIGFuZCBhIHNtYWxsIHNldCBvZiBrbm93bi1zYWZlIEdFVC9PUFRJT05TCnByb2JlcyAocm9ib3RzLnR4dCwgY29t"
    "bW9uIGJhY2t1cC9kb3RmaWxlcywgY3Jvc3Nkb21haW4ueG1sLCBhZG1pbiBwYXRocykuCgpUaGlzIGlzIE5PVCBhIHJlcGxh"
    "Y2VtZW50IGZvciBzcWxtYXAgLyBCdXJwIC8gbnVjbGVpIC8gbWFudWFsIHRlc3RpbmcgLQp0aG9zZSBpdGVtcyBzdGlsbCBu"
    "ZWVkIHRoZSB0b29sIG5hbWVkIGluIHRoZSBjaGVja2xpc3QncyAiVG9vbHMiIGNvbHVtbiwKb3IgYSBodW1hbi4gRXZlcnkg"
    "Y2hlY2tsaXN0IGl0ZW0gdGhpcyBzY3JpcHQgZG9lcyBOT1QgdGVzdCBpcyBsaXN0ZWQgaW4KdGhlIG91dHB1dCBhcyByZXN1"
    "bHQ9TUFOVUFMIHdpdGggYSBub3RlLCBzbyBub3RoaW5nIGxvb2tzIHNpbGVudGx5CnNraXBwZWQgb3Igc2lsZW50bHkgInBh"
    "c3NlZCIuCgpERUZBVUxUIEJFSEFWSU9VUiAtIFJFQUQgVEhJUyBGSVJTVAogIEJ5IGRlZmF1bHQgZXZlcnkgVVJMIHlvdSBn"
    "aXZlIGlzIHRlc3RlZCBUV0lDRSwgYXV0b21hdGljYWxseSwgd2l0aCBubwogIGZsYWcgbmVlZGVkOgogICAgMS4gdGhlIEVY"
    "QUNUIFVSTCB5b3UgZ2F2ZSwgaW5jbHVkaW5nIGl0cyBzdWItZm9sZGVyL3BhdGggLSBlLmcuCiAgICAgICBodHRwczovLzEy"
    "Ny4wLjAuMTo0NDM0L3N1YmZvbGRlciBpcyB0ZXN0ZWQgYXMtaXMsIGFuZCBhbnkKICAgICAgIHBhdGgtYmFzZWQgcHJvYmUg"
    "KHJvYm90cy50eHQsIGJhY2t1cCBmaWxlcywgLmdpdCBleHBvc3VyZSwgYWRtaW4KICAgICAgIHBhdGhzLCBjcm9zc2RvbWFp"
    "bi54bWwsIGRlcGVuZGVuY3kgbWFuaWZlc3RzLCAuLi4pIGlzIHJ1biBVTkRFUgogICAgICAgdGhhdCBzYW1lIHN1Yi1mb2xk"
    "ZXIgKGh0dHBzOi8vMTI3LjAuMC4xOjQ0MzQvc3ViZm9sZGVyL3JvYm90cy50eHQpLgogICAgMi4gdGhlIFNJVEUgUk9PVCBv"
    "ZiB0aGF0IHNhbWUgaG9zdCAtIGh0dHBzOi8vMTI3LjAuMC4xOjQ0MzQvIC0gc2luY2UKICAgICAgIGEgbG90IG9mIHdoYXQg"
    "dGhlIGNoZWNrbGlzdCBpcyBsb29raW5nIGZvciAoc2VydmVyIGNvbmZpZywgVExTLAogICAgICAgYWRtaW4gaW50ZXJmYWNl"
    "cywgRE5TL2VtYWlsIHJlY29yZHMsIGJhY2t1cCBmaWxlcyB0aGF0IHdlcmUgbmV2ZXIKICAgICAgIG1lYW50IHRvIGJlIHJl"
    "YWNoYWJsZSkgdXN1YWxseSBsaXZlcyBhdCB0aGUgcm9vdCByZWdhcmRsZXNzIG9mCiAgICAgICB3aGljaCBwYWdlL2FwcCBw"
    "YXRoIHlvdSB3ZXJlIGdpdmVuLgogIEV2ZXJ5IHJlc3VsdCByb3cgc2F5cyB3aGljaCBvZiB0aGUgdHdvICh1cmxfcm9sZTog"
    "ImdpdmVuLXVybCIgb3IKICAic2l0ZS1yb290IikgaXQgY2FtZSBmcm9tLCBzbyBub3RoaW5nIGlzIGFtYmlndW91cyBpbiB0"
    "aGUgcmVwb3J0LiBQYXNzCiAgLS1za2lwLXJvb3QtcGFzcyBpZiB5b3Ugb25seSB3YW50IHRoZSBleGFjdCBVUkwgdGVzdGVk"
    "IGFuZCBub3QgdGhlCiAgYXV0b21hdGljIGV4dHJhIHJvb3QgcGFzcy4KCiAgRXZlcnkgcm93IHdoZXJlIGEgY2hlY2sgY2Fu"
    "J3QgYmUgdmVyaWZpZWQgYXV0b21hdGljYWxseSBhbmQgbmVlZHMgYQogIGh1bWFuL2RlZGljYXRlZCB0b29sIGlzIG1hcmtl"
    "ZCByZXN1bHQ9TUFOVUFMLCBhbmQgaXRzIGNvbW1lbnQgYWx3YXlzCiAgc3RhcnRzIHdpdGggdGhlIGZpeGVkIHBocmFzZSAi"
    "TWFudWFsIHRlc3QgcmVxdWlyZWQuIiAocGx1cyBzcGVjaWZpY3MKICBhZnRlciBpdCkgLSBzbyB5b3UgY2FuIGZpbHRlci9z"
    "ZWFyY2ggZm9yIGV4YWN0bHkgdGhhdCBwaHJhc2UgaW4gdGhlCiAgcmVwb3J0IHRvIGJ1aWxkIHlvdXIgbWFudWFsIHdvcmsg"
    "cXVldWUuCgpVU0FHRQogICMgc2luZ2xlIFVSTCAtIHRlc3RzIGJvdGggdGhlIFVSTCBpdHNlbGYgYW5kIGl0cyBzaXRlIHJv"
    "b3QgYnkgZGVmYXVsdAogIHB5dGhvbjMgY2hlY2tsaXN0X2F1dG9fc2Nhbi5weSAtLXVybCBodHRwczovLzEyNy4wLjAuMTo0"
    "NDM0L3N1YmZvbGRlcgoKICAjIGEgbGlzdCBvZiBVUkxzLCBvbmUgcGVyIGxpbmUgKCMgY29tbWVudHMgLyBibGFuayBsaW5l"
    "cyBpZ25vcmVkKSAtCiAgIyBFVkVSWSB1cmwgaW4gdGhlIGZpbGUgZ2V0cyB0aGUgc2FtZSBmdWxsIHRyZWF0bWVudCAoYm90"
    "aCBwYXNzZXMpCiAgcHl0aG9uMyBjaGVja2xpc3RfYXV0b19zY2FuLnB5IC0tdXJsLWZpbGUgdXJscy50eHQgLS1vdXQgcmVz"
    "dWx0cwoKICAjIHNlbGYtc2lnbmVkIC8gaW50ZXJuYWwgbGFiIHRhcmdldCwgbG9uZ2VyIHRpbWVvdXQKICBweXRob24zIGNo"
    "ZWNrbGlzdF9hdXRvX3NjYW4ucHkgLS11cmwgaHR0cHM6Ly8xMC4wLjAuNSAtLWluc2VjdXJlIC0tdGltZW91dCAxNQoKICAj"
    "IG9ubHkgdGVzdCB0aGUgZXhhY3QgVVJMIGdpdmVuLCBza2lwIHRoZSBhdXRvbWF0aWMgc2l0ZS1yb290IHBhc3MKICBweXRo"
    "b24zIGNoZWNrbGlzdF9hdXRvX3NjYW4ucHkgLS11cmwgaHR0cHM6Ly9leGFtcGxlLmNvbS9wb3J0YWwvIC0tc2tpcC1yb290"
    "LXBhc3MKCiAgIyBhbHNvIHJ1biB0aGUgbGlnaHQgY29tbW9uLWFkbWluLXBvcnQgc2NhbiAob2ZmIGJ5IGRlZmF1bHQsIG5v"
    "aXNpZXIpCiAgcHl0aG9uMyBjaGVja2xpc3RfYXV0b19zY2FuLnB5IC0tdXJsIGh0dHBzOi8vdGFyZ2V0LmV4YW1wbGUuY29t"
    "IC0tcG9ydC1zY2FuCgogICMgc2tpcCBhdXRvLXNjcmVlbnNob3RzIGVudGlyZWx5ICh0aGV5J3JlIG9uIGJ5IGRlZmF1bHQg"
    "Zm9yIEZBSUwgcm93cykKICBweXRob24zIGNoZWNrbGlzdF9hdXRvX3NjYW4ucHkgLS11cmwgaHR0cHM6Ly90YXJnZXQuZXhh"
    "bXBsZS5jb20gLS1zY3JlZW5zaG90IG5vbmUKCiAgIyBhbHNvIGdlbmVyYXRlIG9uZSBmb3IgUEFTUyByb3dzIChwcm9vZiBv"
    "ZiBhIGNsZWFuIGNoZWNrKSwgb3IgZm9yIGV2ZXJ5dGhpbmcKICBweXRob24zIGNoZWNrbGlzdF9hdXRvX3NjYW4ucHkgLS11"
    "cmwgaHR0cHM6Ly90YXJnZXQuZXhhbXBsZS5jb20gLS1zY3JlZW5zaG90IGZhaWwrcGFzcwogIHB5dGhvbjMgY2hlY2tsaXN0"
    "X2F1dG9fc2Nhbi5weSAtLXVybCBodHRwczovL3RhcmdldC5leGFtcGxlLmNvbSAtLXNjcmVlbnNob3QgYWxsCgpBVVRPLUdF"
    "TkVSQVRFRCAiRVZJREVOQ0UgU0NSRUVOU0hPVFMiIC0gbm8gbWFudWFsIHNjcmVlbnNob3R0aW5nIG5lZWRlZAogIFRha2lu"
    "ZyBhIHNjcmVlbnNob3QgYnkgaGFuZCBmb3IgZXZlcnkgb25lIG9mIH43NyBhdXRvbWF0ZWQgY2hlY2tzIHgKICBob3dldmVy"
    "IG1hbnkgVVJMcyB5b3UncmUgdGVzdGluZyBkb2Vzbid0IHNjYWxlLiBTbyBieSBkZWZhdWx0LCBldmVyeQogIEZBSUwgcm93"
    "IGdldHMgaXRzIG93biBhdXRvLWdlbmVyYXRlZCBldmlkZW5jZSBjYXJkIC0gYSByZW5kZXJlZCBQTkcKICBzaG93aW5nIHRo"
    "ZSBVUkwsIGNoZWNrbGlzdCBJRC90ZXN0IG5hbWUsIGNhdGVnb3J5L3NldmVyaXR5LCB0aGUgZXhhY3QKICBldmlkZW5jZSB0"
    "ZXh0LCBhbmQgdGltZXN0YW1wIC0gdGhlIHNhbWUgaW5mb3JtYXRpb24geW91J2Qgb3RoZXJ3aXNlIGJlCiAgc2NyZWVuc2hv"
    "dHRpbmcgZnJvbSBhIHRlcm1pbmFsIGJ5IGhhbmQuIEl0J3MgYSByZW5kZXJlZCBzdW1tYXJ5IGNhcmQsCiAgTk9UIGEgbGl2"
    "ZSBicm93c2VyIHNjcmVlbnNob3Qgb2YgdGhlIHRhcmdldCBwYWdlIC0gaXQncyBtZWFudCB0byBzdGFuZAogIGluIGFzIHRo"
    "ZSAiQXJ0ZWZhY3RzIiBldmlkZW5jZSBhIHJlcG9ydCBuZWVkcyBmb3IgYW4gYXV0b21hdGVkIGNoZWNrLAogIG5vdCB0byBy"
    "ZXBsYWNlIGFuIGFjdHVhbCBicm93c2VyIHNjcmVlbnNob3Qgb2YgYW4gZXhwbG9pdGVkIFhTUy9TUUxpL2V0Yy4KICBOZWVk"
    "cyBQaWxsb3cgKHBpcDMgaW5zdGFsbCBQaWxsb3cpOyBzY2FubmluZyBzdGlsbCBjb21wbGV0ZXMgbm9ybWFsbHkKICB3aXRo"
    "b3V0IGl0LCBqdXN0IHdpdGhvdXQgc2NyZWVuc2hvdHMgKGEgd2FybmluZyBpcyBwcmludGVkIG9uY2UpLgogIENvbnRyb2wg"
    "d2hpY2ggcm93cyBnZXQgb25lIHdpdGggLS1zY3JlZW5zaG90IHtub25lLGZhaWwsZmFpbCtwYXNzLGFsbH0KICAoZGVmYXVs"
    "dDogZmFpbCkuCgogIFdoZXJlIHRoZSBzY3JlZW5zaG90cyBlbmQgdXA6CiAgICAtIEVtYmVkZGVkIGFzIGJhc2U2NCBQTkcg"
    "aW4gPG91dD4uanNvbiAoZmllbGQ6IGV2aWRlbmNlX2ltYWdlX2Jhc2U2NCkKICAgICAgb24gZXZlcnkgcm93IHRoYXQgZ290"
    "IG9uZSAtIE5PVCB3cml0dGVuIHRvIC5jc3YgKGtlZXBzIGl0IHJlYWRhYmxlOwogICAgICAuY3N2IGluc3RlYWQgZ2V0cyBh"
    "IFNjcmVlbnNob3Q6IHllcy9ubyBjb2x1bW4pLgogICAgLSBBbHNvIGVtYmVkZGVkIGFzIHJlYWwsIHZpZXdhYmxlIGltYWdl"
    "cyBkaXJlY3RseSBpbiA8b3V0Pi54bHN4IG9uIGEKICAgICAgZGVkaWNhdGVkICJFdmlkZW5jZSIgc2hlZXQgKG5lZWRzIFBp"
    "bGxvdyBvbmx5IC0geGxzeHdyaXRlciBlbWJlZHMKICAgICAgd2hhdGV2ZXIgaW1hZ2UgYnl0ZXMgaXQncyBnaXZlbiBlaXRo"
    "ZXIgd2F5KS4KICAgIC0gSlVNUCBIT1NUIC8gUkVTVFJJQ1RFRC1DT1BZIFdPUktGTE9XOiBpZiB5b3UncmUgcnVubmluZyB0"
    "aGlzIG9uIGEKICAgICAganVtcCBob3N0IHdoZXJlIG9ubHkgY2xpcGJvYXJkIHRleHQgY29tZXMgYmFjayB0byB5b3VyIHJl"
    "YWwgbWFjaGluZQogICAgICAobm8gZmlsZSB0cmFuc2ZlciksIGNvcHkgdGhlIHByaW50ZWQgSlNPTiAob3IganVzdCBwYXN0"
    "ZSB0aGUKICAgICAgcmVsZXZhbnQgcm93J3MgZXZpZGVuY2VfaW1hZ2VfYmFzZTY0IHZhbHVlKSBiYWNrIHRvIHlvdXIgb3du"
    "CiAgICAgIG1hY2hpbmUgYW5kIHJ1biB0aGUgY29tcGFuaW9uIHNjcmlwdCB0byB0dXJuIGl0IGJhY2sgaW50byByZWFsCiAg"
    "ICAgIC5wbmcgZmlsZXM6CiAgICAgICAgcHl0aG9uMyBleHRyYWN0X2V2aWRlbmNlX2ltYWdlcy5weSByZXN1bHRzLmpzb24g"
    "LS1vdXQgc2NyZWVuc2hvdHMvCiAgICAgIFNlZSBleHRyYWN0X2V2aWRlbmNlX2ltYWdlcy5weSdzIG93biAtLWhlbHAgZm9y"
    "IGRldGFpbHM7IGl0IHNoaXBzCiAgICAgIGFsb25nc2lkZSB0aGlzIHNjcmlwdC4KCk9VVFBVVAogIEV2ZXJ5IHJ1biB3cml0"
    "ZXMgVEhSRUUgZmlsZXMgZnJvbSB0aGUgc2FtZSByZXN1bHRzIChubyBmbGFnIG5lZWRlZCk6CiAgPG91dD4uY3N2LCA8b3V0"
    "Pi5qc29uLCBhbmQgPG91dD4ueGxzeCAtIGEgY29sb3ItY29kZWQsIGZpbHRlcmFibGUKICB3b3JrYm9vayAoUEFTUy9GQUlM"
    "L01BTlVBTC9JTkZPL0VSUk9SIGhpZ2hsaWdodGVkLCBhdXRvZmlsdGVyICsgZnJvemVuCiAgaGVhZGVyIHJvdykgcGx1cyBh"
    "IFN1bW1hcnkgc2hlZXQsIHNvIGl0J3MgZWFzeSB0byBuYXZpZ2F0ZSBhcyBhCiAgdHJhY2tpbmcgbGlzdC4gPG91dD4gZGVm"
    "YXVsdHMgdG8gY2hlY2tsaXN0X3NjYW5fPHRpbWVzdGFtcD4uIFRoZSAueGxzeAogIG5lZWRzICJwYW5kYXMiIGFuZCAieGxz"
    "eHdyaXRlciIgKHBpcDMgaW5zdGFsbCBwYW5kYXMgeGxzeHdyaXRlcik7IGlmCiAgZWl0aGVyIGlzIG1pc3NpbmcgdGhlIHNj"
    "cmlwdCBzdGlsbCB3cml0ZXMgLmNzdi8uanNvbiBhbmQganVzdCBza2lwcwogIC54bHN4IHdpdGggYSBub3RlLgoKUkVBTCBD"
    "T01NQU5ELUxJTkUgVE9PTCBJTlRFR1JBVElPTiAoY3VybCAvIG5tYXAgLyBzc2x5emUgLyBzc2xzY2FuIC8gdGVzdHNzbC5z"
    "aCkKICBBdXRvLWRldGVjdGVkIHZpYSBQQVRILCBubyBmbGFnL2NvbmZpZyBuZWVkZWQgLSBpZiBhIHRvb2wgaXMgaW5zdGFs"
    "bGVkLAogIGl0J3MgdXNlZCBhdXRvbWF0aWNhbGx5IHRvIGNhcHR1cmUgUkVBTCBjb21tYW5kIG91dHB1dCBhcyBldmlkZW5j"
    "ZToKICAgIC0gY3VybCBydW5zIG9uY2UgcGVyIEhUVFAgU2VjdXJpdHkgSGVhZGVycyBjaGVjayAoV0EtSERSLTM5Mi4uMzk4"
    "LDQwMSkKICAgICAgYW5kIGl0cyBleGFjdCAiJCBjdXJsIC4uLiIgY29tbWFuZCArIHJhdyByZXNwb25zZSBoZWFkZXJzIGlz"
    "CiAgICAgIGFwcGVuZGVkIHRvIHRoZSBldmlkZW5jZSB0ZXh0LgogICAgLSBUaGUgZmlyc3Qgb2Ygbm1hcCAoLS1zY3JpcHQg"
    "c3NsLWVudW0tY2lwaGVycyksIHNzbHl6ZSwgc3Nsc2Nhbiwgb3IKICAgICAgdGVzdHNzbC5zaCBmb3VuZCBvbiBQQVRIIHJ1"
    "bnMgb25jZSBwZXIgSFRUUFMgdGFyZ2V0IGFuZCBpdHMgb3V0cHV0CiAgICAgIGJvdGggYmVjb21lcyB0aGUgZXZpZGVuY2Ug"
    "Zm9yIFdBLVRMUy00MDIvNDA0IEFORCBkcml2ZXMgYSByZWFsCiAgICAgIFBBU1MvRkFJTCBkZXRlcm1pbmF0aW9uICh3ZWFr"
    "LWNpcGhlci93ZWFrLXByb3RvY29sIHBhdHRlcm4KICAgICAgbWF0Y2hpbmcpIGluc3RlYWQgb2YgbGVhdmluZyB0aG9zZSB0"
    "d28gTUFOVUFMLgogIFJvd3MgY2FycnlpbmcgdGhpcyBraW5kIG9mIHJlYWwgY29tbWFuZCBvdXRwdXQgZ2V0IGEgVEVSTUlO"
    "QUwtU1RZTEUKICBldmlkZW5jZSBzY3JlZW5zaG90IChibGFjayBiYWNrZ3JvdW5kLCBtb25vc3BhY2UpIGluc3RlYWQgb2Yg"
    "dGhlIHVzdWFsCiAgc3VtbWFyeSBjYXJkLCBzbyB0aGUgc2NyZWVuc2hvdCBpdHNlbGYgbG9va3MgbGlrZSBhbiBhY3R1YWwg"
    "dGVybWluYWwKICBjYXB0dXJlIG9mIHRoZSBjb21tYW5kIHRoYXQgcmFuLiBQYXNzIC0tbm8tY2xpLXRvb2xzIHRvIGRpc2Fi"
    "bGUgYWxsIG9mCiAgdGhpcyBhbmQgdXNlIHRoZSBwdXJlLVB5dGhvbi9NQU5VQUwgZmFsbGJhY2sgb25seSAoZS5nLiBmb3Ig"
    "c3BlZWQsIG9yIGlmCiAgeW91IGRvbid0IHdhbnQgc3VicHJvY2Vzc2VzIHNoZWxsZWQgb3V0IGF0IGFsbCkuCgpBVVRIRU5U"
    "SUNBVEVEIFNDQU5OSU5HIEFORCBBQ0NFU1MgQ09OVFJPTCBURVNUSU5HIChvcHQtaW4sIC0tY29va2llIC8gLS1jb29raWUy"
    "KQogIFRoaXMgc2NyaXB0IE5FVkVSIGxvZ3MgaW4sIGJydXRlLWZvcmNlcywgZ3Vlc3Nlcywgb3IgaGFydmVzdHMKICBjcmVk"
    "ZW50aWFscyBhbnl3aGVyZSAtIGl0IGhhcyBubyBsb2dpbiBmbG93IGF0IGFsbC4gV2hhdCBpdCBDQU4gZG8sIGlmCiAgeW91"
    "IGhhbmQgaXQgYSBzZXNzaW9uIENvb2tpZSBoZWFkZXIgdmFsdWUgeW91IGFscmVhZHkgb2J0YWluZWQgeW91cnNlbGYKICBi"
    "eSBsb2dnaW5nIGluIChlLmcuIGNvcGllZCBmcm9tIHlvdXIgYnJvd3NlcidzIGRldiB0b29scywgb3IgYSBCdXJwCiAgUHJv"
    "eHkgaGlzdG9yeSBlbnRyeSksIGlzIHVzZSB0aGF0IHByZS1hdXRoZW50aWNhdGVkIHNlc3Npb24gdG8gcnVuCiAgRVZFUlkg"
    "Y2hlY2sgaW4gdGhlIHN1aXRlIGFzIHRoYXQgbG9nZ2VkLWluIHVzZXIsIGFuZCBhdXRvbWF0aWNhbGx5CiAgZXh0ZW5kIGNv"
    "dmVyYWdlIGFzIGZvbGxvd3MgLSB0aGlzIGlzICJhdXRvIGNoZWNrIjogcGFzcyBvbmUgY29va2llIGFuZAogIGl0IGNvdmVy"
    "cyBldmVyeXRoaW5nIGEgc2luZ2xlIHNlc3Npb24gY2FuIHRlc3Q7IGFkZCBhIHNlY29uZCBhbmQgaXQKICBjb3ZlcnMgdGhl"
    "IHR3by1hY2NvdW50IGNoZWNrcyB0b28sIHdpdGggbm8gZXh0cmEgZmxhZ3MgbmVlZGVkOgogICAgLSAtLWNvb2tpZSBhbG9u"
    "ZTogZXZlcnkgb25lIG9mIHRoZSB+MTAwIGNoZWNrcyBydW5zIGF1dGhlbnRpY2F0ZWQsCiAgICAgIFBMVVMgV0EtT1RHLTMx"
    "MiAoYXV0aCBieXBhc3MgLyBmb3JjZS1icm93c2UpIGdldHMgcmVhbCB0ZXN0aW5nIC0KICAgICAgY29tcGFyZXMgdGhlIFNB"
    "TUUgdXJsIHdpdGggbm8gc2Vzc2lvbiBhdCBhbGwgdnMuIHdpdGggLS1jb29raWUncwogICAgICBzZXNzaW9uOyBieXRlLWlk"
    "ZW50aWNhbCByZXNwb25zZXMgbWVhbiB0aGUgcGFnZSBkb2Vzbid0IGFjdHVhbGx5CiAgICAgIHJlcXVpcmUgbG9naW4uCiAg"
    "ICAtIC0tY29va2llICsgLS1jb29raWUyIChhIFNFQ09ORCwgRElGRkVSRU5UIGFjY291bnQncyBvd24gc2Vzc2lvbik6CiAg"
    "ICAgIEFMU08gZ2V0cyBXQS1TUy0wNzEgKGhvcml6b250YWwgcHJpdmlsZWdlIGVzY2FsYXRpb24pIGFuZAogICAgICBXQS1P"
    "VEctMzE0IChJRE9SKSByZWFsIHRlc3RpbmcgLSBjb21wYXJlcyB3aGF0IGFjY291bnQgMSAoLS1jb29raWUpCiAgICAgIGFu"
    "ZCBhY2NvdW50IDIgKC0tY29va2llMikgZWFjaCBzZWUgYXQgdGhlIHNhbWUgVVJMLiBCeXRlLWlkZW50aWNhbAogICAgICBy"
    "ZXNwb25zZXMgYXJlIHJlcG9ydGVkIGFzIE1BTlVBTCAobm90IGFuIGF1dG9tYXRpYyBGQUlMKSBzaW5jZSBvbmx5CiAgICAg"
    "IGEgaHVtYW4gY2FuIGNvbmZpcm0gdGhlIFVSTC9yZXNvdXJjZSBpcyBhY3R1YWxseSBtZWFudCB0byBiZQogICAgICBhY2Nv"
    "dW50LXNwZWNpZmljIHJhdGhlciB0aGFuIHNoYXJlZC9wdWJsaWMuCiAgICAtIEEgY292ZXJhZ2UgcmVwb3J0IHByaW50cyBi"
    "ZWZvcmUgc2Nhbm5pbmcgc3RhcnRzICh3aGF0IHdpbGwgYmUKICAgICAgYXR0ZW1wdGVkKSBhbmQgYWdhaW4gaW4gdGhlIGZp"
    "bmFsIHN1bW1hcnkgKHdoYXQgd2FzIGFjdHVhbGx5CiAgICAgIHJlY29yZGVkKSwgc28geW91IGFsd2F5cyBrbm93IGV4YWN0"
    "bHkgd2hpY2ggY2hlY2tsaXN0IElEcyBnb3QgcmVhbAogICAgICB0ZXN0aW5nIHZzLiBzdGF5ZWQgTUFOVUFMIGZvciB0aGUg"
    "cnVuIHlvdSBqdXN0IGRpZC4KICAtLWFjY291bnQxLWNvb2tpZS8tLWFjY291bnQyLWNvb2tpZS8tLWFjY291bnQxLWxhYmVs"
    "Ly0tYWNjb3VudDItbGFiZWwKICBzdGlsbCB3b3JrIGV4YWN0bHkgYXMgYmVmb3JlIChhbmQgLS1jb29raWUvLS1jb29raWUy"
    "IGF1dG8tcG9wdWxhdGUgdGhlbQogIHVubGVzcyB5b3Ugc2V0IHRob3NlIGV4cGxpY2l0bHkpIC0gLS1jb29raWUvLS1jb29r"
    "aWUyIGFyZSBqdXN0IHRoZQogIHNpbXBsZXIgbmFtZXMgdG8gcmVhY2ggZm9yLCBzaW5jZSB0aGV5IGFsc28gYXV0aGVudGlj"
    "YXRlIGV2ZXJ5dGhpbmcKICBlbHNlIGluIHRoZSBzdWl0ZS4gVGhlIGNvb2tpZSBWQUxVRVMgdGhlbXNlbHZlcyBhcmUgbmV2"
    "ZXIgd3JpdHRlbiB0bwogIGV2aWRlbmNlL0pTT04vQ1NWL3NjcmVlbnNob3RzIC0gb25seSBzdGF0dXMgY29kZXMsIGJ5dGUg"
    "bGVuZ3RocywgYW5kCiAgdGhlIHBhc3MvZmFpbCBjb21wYXJpc29uIG91dGNvbWUgYXJlLgoKUkVRVUlSRU1FTlRTCiAgUHl0"
    "aG9uIDMuNyssIHN0YW5kYXJkIGxpYnJhcnkgb25seSBmb3IgdGhlIENTVi9KU09OIHNjYW4gaXRzZWxmLiBVc2VzCiAgdGhl"
    "IHN5c3RlbSAib3BlbnNzbCIgYW5kICJuc2xvb2t1cCIgY29tbWFuZC1saW5lIHRvb2xzIGlmIHByZXNlbnQgKGJvdGgKICBz"
    "aGlwIHdpdGggbWFjT1MvTGludXg7IG5zbG9va3VwIGFsc28gc2hpcHMgd2l0aCBXaW5kb3dzLCBidXQgb24gV2luZG93cwog"
    "IHVzZSB0aGUgUG93ZXJTaGVsbCBzY3JpcHQgaW5zdGVhZCAtIENoZWNrbGlzdF9BdXRvU2Nhbi5wczEgLSB3aGljaCB1c2Vz"
    "CiAgbmF0aXZlIC5ORVQvUG93ZXJTaGVsbCBjbWRsZXRzIGFuZCBuZWVkcyBubyBleHRlcm5hbCB0b29scyBhdCBhbGwpIHRv"
    "CiAgZW5yaWNoIHRoZSBUTFMgYW5kIEVtYWlsIFNlY3VyaXR5IGNoZWNrcywgYW5kICJjdXJsIi8ibm1hcCIvInNzbHl6ZSIv"
    "CiAgInNzbHNjYW4iLyJ0ZXN0c3NsLnNoIiBpZiBwcmVzZW50IHRvIGVucmljaCBIZWFkZXIgYW5kIFRMUyBjaGVja3Mgd2l0"
    "aAogIHJlYWwgY29tbWFuZCBvdXRwdXQgKHNlZSBhYm92ZSkuIFRoZWlyIGFic2VuY2UgZGVncmFkZXMgdGhvc2Ugc3BlY2lm"
    "aWMKICBjaGVja3MgdG8gSU5GTy9NQU5VQUwgLSBpdCBkb2VzIG5vdCBicmVhayB0aGUgcmVzdCBvZiB0aGUgc2Nhbi4KIiIi"
    "CgppbXBvcnQgYXJncGFyc2UKaW1wb3J0IGJhc2U2NAppbXBvcnQgY3N2CmltcG9ydCBoYXNobGliCmltcG9ydCBpbwppbXBv"
    "cnQganNvbgppbXBvcnQgcmFuZG9tCmltcG9ydCByZQppbXBvcnQgc2h1dGlsCmltcG9ydCBzb2NrZXQKaW1wb3J0IHNzbApp"
    "bXBvcnQgc3RyaW5nCmltcG9ydCBzdWJwcm9jZXNzCmltcG9ydCBzeXMKaW1wb3J0IHRleHR3cmFwCmltcG9ydCB0aW1lCmlt"
    "cG9ydCB3YXJuaW5ncwpmcm9tIGRhdGV0aW1lIGltcG9ydCBkYXRldGltZSwgdGltZXpvbmUKZnJvbSBodHRwLmNsaWVudCBp"
    "bXBvcnQgSFRUUENvbm5lY3Rpb24sIEhUVFBTQ29ubmVjdGlvbgpmcm9tIHVybGxpYi5wYXJzZSBpbXBvcnQgdXJscGFyc2Us"
    "IHVybGpvaW4sIHBhcnNlX3FzbCwgdXJsZW5jb2RlCgojIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t"
    "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiMgQ29uc3RhbnRzCiMgLS0tLS0tLS0tLS0tLS0tLS0tLS0t"
    "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KCkRFRkFVTFRfVUEgPSAiUmVw"
    "b3J0U3lzdGVtLUNoZWNrbGlzdEF1dG9TY2FuLzEuMCAoK2F1dGhvcml6ZWQtcGVudGVzdC1yZWNvbikiClNUQUNLX1RSQUNF"
    "X1BBVFRFUk5TID0gWwogICAgciJUcmFjZWJhY2sgXChtb3N0IHJlY2VudCBjYWxsIGxhc3RcKSIsIHIiYXQgU3lzdGVtXC4i"
    "LCByIkV4Y2VwdGlvbiBpbiB0aHJlYWQiLAogICAgciJGYXRhbCBlcnJvcjoiLCByIldhcm5pbmc6XHMrXHcrXChcKSIsIHIi"
    "T1JBLVxkezV9IiwgciJTUUxTVEFURVxbIiwKICAgIHIiTWljcm9zb2Z0IE9MRSBEQiBQcm92aWRlciIsIHIidW5oYW5kbGVk"
    "IGV4Y2VwdGlvbiIsIHIiU3RhY2sgdHJhY2U6IiwKICAgIHIiZGphbmdvXC5jb3JlXC5leGNlcHRpb25zIiwgciJOb01ldGhv"
    "ZEVycm9yIiwgciJqYXZhXC5sYW5nXC5cdytFeGNlcHRpb24iLAogICAgciJwc3FsOiBlcnJvciIsIHIiVW5oYW5kbGVkIEV4"
    "Y2VwdGlvbiIsIHIiREVCVUcgPSBUcnVlIiwgciJXU09EIiwKXQpERUJVR19QQUdFUyA9IFsiL3BocGluZm8ucGhwIiwgIi9p"
    "bmZvLnBocCIsICIvX3Byb2ZpbGVyLyIsICIvcmFpbHMvaW5mby9wcm9wZXJ0aWVzIiwKICAgICAgICAgICAgICAgIi9kZWJ1"
    "ZyIsICIvZWxtYWguYXhkIiwgIi90cmFjZS5heGQiLCAiL3NlcnZlci1zdGF0dXMiLCAiL3NlcnZlci1pbmZvIl0KQkFDS1VQ"
    "X0VYVF9QUk9CRVMgPSBbIi9pbmRleC5waHAuYmFrIiwgIi9pbmRleC5odG1sLmJhayIsICIvaW5kZXguYmFrIiwgIi9jb25m"
    "aWcucGhwLmJhayIsCiAgICAgICAgICAgICAgICAgICAgICAiL3dlYi5jb25maWcuYmFrIiwgIi8uZW52LmJhayIsICIvYXBw"
    "LmpzLmJhayIsICIvd3AtY29uZmlnLnBocC5iYWsiLAogICAgICAgICAgICAgICAgICAgICAgIi9pbmRleC5waHAub2xkIiwg"
    "Ii9pbmRleC5waHAub3JpZyIsICIvaW5kZXgucGhwLnN3cCJdCkJBQ0tVUF9GSUxFX1BST0JFUyA9IFsiL2JhY2t1cC56aXAi"
    "LCAiL2JhY2t1cC50YXIuZ3oiLCAiL3NpdGUtYmFja3VwLnppcCIsICIvZGIuc3FsIiwKICAgICAgICAgICAgICAgICAgICAg"
    "ICAiL2RhdGFiYXNlLnNxbCIsICIvLmVudiIsICIvY29uZmlnLnBocH4iLCAiL2R1bXAuc3FsIiwgIi9iYWNrdXAuc3FsLmd6"
    "Il0KR0lUX1NWTl9QUk9CRVMgPSBbIi8uZ2l0L0hFQUQiLCAiLy5naXQvY29uZmlnIiwgIi8uc3ZuL2VudHJpZXMiLCAiLy5z"
    "dm4vd2MuZGIiLAogICAgICAgICAgICAgICAgICAgIi8uRFNfU3RvcmUiLCAiLy5oZy9zdG9yZSIsICIvQ1ZTL1Jvb3QiXQpE"
    "RVBFTkRFTkNZX1BST0JFUyA9IFsiL3BhY2thZ2UuanNvbiIsICIvY29tcG9zZXIuanNvbiIsICIvcmVxdWlyZW1lbnRzLnR4"
    "dCIsICIvR2VtZmlsZSIsCiAgICAgICAgICAgICAgICAgICAgICAiL3BvbS54bWwiLCAiL1BpcGZpbGUiLCAiL3lhcm4ubG9j"
    "ayJdCkFETUlOX1BBVEhfUFJPQkVTID0gWyIvYWRtaW4iLCAiL2FkbWluaXN0cmF0b3IiLCAiL3dwLWFkbWluLyIsICIvbWFu"
    "YWdlci9odG1sIiwKICAgICAgICAgICAgICAgICAgICAgICIvcGhwbXlhZG1pbi8iLCAiL2FkbWluZXIucGhwIiwgIi9jcGFu"
    "ZWwiLCAiL3dlYm1pbi8iXQpDT01NT05fQURNSU5fUE9SVFMgPSBbMjEsIDIyLCAyMywgMzMwNiwgMzM4OSwgNTQzMiwgNjM3"
    "OSwgODA4MCwgODQ0MywgOTIwMCwgMjcwMTcsIDU5ODQsIDIzNzVdCkNPTU1PTl9ES0lNX1NFTEVDVE9SUyA9IFsiZGVmYXVs"
    "dCIsICJnb29nbGUiLCAic2VsZWN0b3IxIiwgInNlbGVjdG9yMiIsICJka2ltIiwgImsxIiwgIm1haWwiLAogICAgICAgICAg"
    "ICAgICAgICAgICAgICAgICJzMSIsICJzMiIsICJzbXRwIiwgIm1hbmRyaWxsIiwgInNlbmRncmlkIl0KQ0xPVURfQlVDS0VU"
    "X1BBVFRFUk5TID0gW3IiW1x3LlwtXStcLnMzXC5hbWF6b25hd3NcLmNvbSIsIHIiczNcLmFtYXpvbmF3c1wuY29tL1tcdy5c"
    "LV0rIiwKICAgICAgICAgICAgICAgICAgICAgICAgICByInN0b3JhZ2VcLmdvb2dsZWFwaXNcLmNvbS9bXHcuXC1dKyIsIHIi"
    "W1x3LlwtXStcLmJsb2JcLmNvcmVcLndpbmRvd3NcLm5ldCJdCkNETl9XQUZfSEVBREVSX0hJTlRTID0gewogICAgInNlcnZl"
    "ciI6IHsiY2xvdWRmbGFyZSI6ICJDbG91ZGZsYXJlIiwgImFrYW1haWdob3N0IjogIkFrYW1haSIsICJzdWN1cmkvY2xvdWRw"
    "cm94eSI6ICJTdWN1cmkifSwKICAgICJjZi1yYXkiOiB7IiI6ICJDbG91ZGZsYXJlIn0sICJ4LWFtei1jZi1pZCI6IHsiIjog"
    "IkFtYXpvbiBDbG91ZEZyb250In0sCiAgICAieC1zdWN1cmktaWQiOiB7IiI6ICJTdWN1cmkifSwgIngtY2FjaGUiOiB7IiI6"
    "ICJzb21lIENETi9yZXZlcnNlLXByb3h5IGNhY2hlIn0sCiAgICAieC1ha2FtYWktdHJhbnNmb3JtZWQiOiB7IiI6ICJBa2Ft"
    "YWkifSwgIngtdmFybmlzaCI6IHsiIjogIlZhcm5pc2ggY2FjaGUifSwKfQoKIyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t"
    "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQojIFBoYXNlZCBwaXBlbGluZSBwYXls"
    "b2FkIGxpc3RzIChyZWNvbiAtPiBkaXNjb3ZlciAtPiBleHRzY2FuIC0+IGluamVjdCAtPgojIGV4cGxvaXQgLT4gcmVwb3J0"
    "KS4gU21hbGwsIGN1cmF0ZWQsIHNlbGYtY29udGFpbmVkIHN1YnNldHMgImluc3BpcmVkIGJ5IgojIHRoZSBjYXRlZ29yaWVz"
    "IGluIFNlY0xpc3RzJyBGdXp6aW5nLyogbGlzdHMgLSBrZXB0IGlubGluZSBpbiB0aGlzIGZpbGUgb24KIyBwdXJwb3NlIHNv"
    "IHJ1bm5pbmcgdGhlIGluamVjdC9leHBsb2l0IHBoYXNlcyBuZWVkcyBOTyBleHRlcm5hbCBTZWNMaXN0cwojIGNoZWNrb3V0"
    "L3ByZXJlcXVpc2l0ZSwgcGVyIGRpcmVjdCByZXF1ZXN0ICgidXNlIGJhc2ljIHNlY2xpc3Qgd2hlcmUgZXZlcgojIHJlcXVp"
    "cmVkIG5vIG5lZWQgZm9yIHByZXJlcXVpcnRlcyIpLiBOb3QgZXhoYXVzdGl2ZSAtIHRoaXMgaXMgYSBmYXN0CiMgdHJpYWdl"
    "IHBhc3MsIG5vdCBhIHJlcGxhY2VtZW50IGZvciBhIHJlYWwgZnV6emVyIChmZnVmL3dmdXp6KSBvciBzcWxtYXAncwojIG93"
    "biBtdWNoIGxhcmdlciBwYXlsb2FkIHNldCAod2hpY2ggdGhlIGV4cGxvaXQgcGhhc2UgcmVhY2hlcyBmb3IgYW55d2F5CiMg"
    "b25jZSBhIGZpZWxkIGxvb2tzIHByb21pc2luZyAtIHNlZSBwaGFzZV9leHBsb2l0KCkpLgojIC0tLS0tLS0tLS0tLS0tLS0t"
    "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCgpCQVNJQ19YU1NfUEFZ"
    "TE9BRFMgPSBbCiAgICAiPHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0PiIsCiAgICAiXCI+PHNjcmlwdD5hbGVydCgxKTwvc2Ny"
    "aXB0PiIsCiAgICAiJz48c3ZnIG9ubG9hZD1hbGVydCgxKT4iLAogICAgIjxpbWcgc3JjPXggb25lcnJvcj1hbGVydCgxKT4i"
    "LAogICAgIjxzdmcvb25sb2FkPWFsZXJ0KDEpPiIsCiAgICAiXCJvbm1vdXNlb3Zlcj1cImFsZXJ0KDEpIiwKICAgICInO2Fs"
    "ZXJ0KDEpOy8vIiwKICAgICI8aWZyYW1lIHNyYz1qYXZhc2NyaXB0OmFsZXJ0KDEpPiIsCl0KCkJBU0lDX1NRTElfUEFZTE9B"
    "RFMgPSBbCiAgICAiJyIsCiAgICAiXCIiLAogICAgIicgT1IgJzEnPScxIiwKICAgICInIE9SICcxJz0nMScgLS0gLSIsCiAg"
    "ICAiXCIgT1IgXCIxXCI9XCIxIiwKICAgICIxJyBPUkRFUiBCWSAxMDAwMC0tIC0iLAogICAgIicgVU5JT04gU0VMRUNUIE5V"
    "TEwtLSAtIiwKICAgICInIEFORCBTTEVFUCg1KS0tIC0iLAogICAgIic7IFdBSVRGT1IgREVMQVkgJzA6MDo1Jy0tIiwKICAg"
    "ICIxKSBBTkQgU0xFRVAoNSktLSAtIiwKXQoKQkFTSUNfQ01EX0lOSkVDVElPTl9QQVlMT0FEUyA9IFsKICAgICI7IGlkIiwK"
    "ICAgICJ8IGlkIiwKICAgICJgaWRgIiwKICAgICIkKGlkKSIsCiAgICAiOyBzbGVlcCA1IiwKICAgICJ8IHNsZWVwIDUiLAog"
    "ICAgInx8IHBpbmcgLWMgMyAxMjcuMC4wLjEiLApdCgpCQVNJQ19QQVRIX1RSQVZFUlNBTF9QQVlMT0FEUyA9IFsKICAgICIu"
    "Li8uLi8uLi8uLi9ldGMvcGFzc3dkIiwKICAgICIuLlxcLi5cXC4uXFwuLlxcd2luZG93c1xcd2luLmluaSIsCiAgICAiJTJl"
    "JTJlJTJmJTJlJTJlJTJmJTJlJTJlJTJmZXRjJTJmcGFzc3dkIiwKICAgICIuLi4uLy8uLi4uLy8uLi4uLy9ldGMvcGFzc3dk"
    "IiwKICAgICIvZXRjL3Bhc3N3ZCIsCl0KCkJBU0lDX1NTVElfUEFZTE9BRFMgPSBbCiAgICAie3s3Kjd9fSIsCiAgICAiJHs3"
    "Kjd9IiwKICAgICI8JT0gNyo3ICU+IiwKICAgICIjezcqN30iLAogICAgIiR7ezcqN319IiwKXQoKIyBSZXNwb25zZS1vcmFj"
    "bGUgcmVnZXhlcyB1c2VkIGJ5IGNsYXNzaWZ5X2luamVjdGlvbigpIChzZWUgcGhhc2VfaW5qZWN0KCkKIyBiZWxvdykgLSBk"
    "ZWxpYmVyYXRlbHkgY29uc2VydmF0aXZlLCBzYW1lICJpbmNvbmNsdXNpdmUgLT4gZG9uJ3QgZ3Vlc3MgYQojIGhpdCIgcGhp"
    "bG9zb3BoeSBhcyBfcGFyc2Vfc3NsX2NsaV9vdXRwdXQoKSBlbHNld2hlcmUgaW4gdGhpcyBmaWxlLgpTUUxfRVJST1JfUEFU"
    "VEVSTlMgPSByZS5jb21waWxlKAogICAgciJTUUwgc3ludGF4fG15c3FsX2ZldGNofE9SQS1cZHs1fXxTUUxTVEFURVxbfFBv"
    "c3RncmVTUUwuKkVSUk9SfFNRTGl0ZTM6OnwiCiAgICByIlVuY2xvc2VkIHF1b3RhdGlvbiBtYXJrfE1pY3Jvc29mdCBPTEUg"
    "REIgUHJvdmlkZXJ8cGdfcXVlcnlcKFwpfCIKICAgIHIiV2FybmluZzogbXlzcWxpfHN5bnRheCBlcnJvciBhdCBvciBuZWFy"
    "fFN5c3RlbVwuRGF0YVwuU3FsQ2xpZW50IiwKICAgIHJlLklHTk9SRUNBU0UpClVOSVhfUEFTU1dEX01BUktFUiA9IHJlLmNv"
    "bXBpbGUociJyb290Oi4qOjA6MDoiKQpXSU5fSU5JX01BUktFUiA9IHJlLmNvbXBpbGUociJcW2ZvbnRzXF18Zm9yIDE2LWJp"
    "dCBhcHAgc3VwcG9ydCIsIHJlLklHTk9SRUNBU0UpCkNNRF9PVVRQVVRfTUFSS0VSID0gcmUuY29tcGlsZShyInVpZD1cZCtc"
    "KFtcdy1dK1wpXHMrZ2lkPVxkKyIpClRJTUVfQkFTRURfREVMVEFfU0VDID0gNC4wICAjIHBheWxvYWQgbXVzdCBhZGQgYXQg"
    "bGVhc3QgdGhpcyBtdWNoIGxhdGVuY3kgdnMuIGJhc2VsaW5lIHRvIGNvdW50IGFzIGEgdGltaW5nIGhpdAoKIyBTYW1lLW9y"
    "aWdpbiBjcmF3bGVyICsgZm9ybS9wYXJhbSBleHRyYWN0aW9uIHJlZ2V4ZXMgKHJlY29uL2Rpc2NvdmVyCiMgcGhhc2VzKSAt"
    "IHN0ZGxpYiByZWdleCwgbm90IGEgcmVhbCBIVE1MIHBhcnNlciBvciBoZWFkbGVzcyBicm93c2VyLCBzbwojIEpTLXJlbmRl"
    "cmVkIGxpbmtzL2Zvcm1zIGluIGFuIFNQQSBhcmUgTk9UIHNlZW4gaGVyZSAoc2FtZSBuby1kZXBlbmRlbmN5CiMgdHJhZGVv"
    "ZmYgdGhpcyBzY3JpcHQgbWFrZXMgZXZlcnl3aGVyZSBlbHNlIC0gc2VlIG1vZHVsZSBkb2NzdHJpbmcpLgpDUkFXTF9MSU5L"
    "X1JFID0gcmUuY29tcGlsZShyJyg/OmhyZWZ8c3JjfGFjdGlvbilccyo9XHMqWyJcJ10oW14iXCcjXVteIlwnXSopWyJcJ10n"
    "LCByZS5JR05PUkVDQVNFKQpGT1JNX0JMT0NLX1JFID0gcmUuY29tcGlsZShyJzxmb3JtXGJbXj5dKj4uKj88L2Zvcm0+Jywg"
    "cmUuSUdOT1JFQ0FTRSB8IHJlLkRPVEFMTCkKRk9STV9BVFRSX1JFID0gcmUuY29tcGlsZShyJzxmb3JtXGIoW14+XSopPics"
    "IHJlLklHTk9SRUNBU0UpCkZJRUxEX1RBR19SRSA9IHJlLmNvbXBpbGUocic8KD86aW5wdXR8dGV4dGFyZWF8c2VsZWN0KVxi"
    "KFtePl0qKT4nLCByZS5JR05PUkVDQVNFKQpOQU1FX0FUVFJfUkUgPSByZS5jb21waWxlKHInbmFtZVxzKj1ccypbIlwnXShb"
    "XiJcJ10rKVsiXCddJywgcmUuSUdOT1JFQ0FTRSkKTUVUSE9EX0FUVFJfUkUgPSByZS5jb21waWxlKHInbWV0aG9kXHMqPVxz"
    "KlsiXCddKFteIlwnXSspWyJcJ10nLCByZS5JR05PUkVDQVNFKQpBQ1RJT05fQVRUUl9SRSA9IHJlLmNvbXBpbGUocidhY3Rp"
    "b25ccyo9XHMqWyJcJ10oW14iXCddKilbIlwnXScsIHJlLklHTk9SRUNBU0UpCgojIFdlaWdodGVkIHJpc2sgc2NvcmluZyBm"
    "b3IgdGhlIGZpbmFsIGNvbXByZWhlbnNpdmUgcmVwb3J0IChyZXBvcnQgcGhhc2UpIC0KIyBvbmx5IEZBSUwgcm93cyBjb3Vu"
    "dCAoTUFOVUFML0lORk8vUEFTUy9FUlJPUiBjb250cmlidXRlIDAgcmVnYXJkbGVzcyBvZgojIHNldmVyaXR5IC0gYW4gdW5j"
    "b25maXJtZWQvbWFudWFsIGl0ZW0gc2hvdWxkbid0IG1vdmUgdGhlIG5lZWRsZSB0aGUgc2FtZQojIHdheSBhIGNvbmZpcm1l"
    "ZCBGQUlMIGRvZXMpLgpTRVZFUklUWV9XRUlHSFQgPSB7IkNyaXRpY2FsIjogNDAsICJIaWdoIjogMjAsICJNZWRpdW0iOiA1"
    "LCAiTG93IjogMSwgIkluZm8iOiAwfQoKUkVTVUxUUyA9IFtdCk1BTlVBTF9QUkVGSVggPSAiTWFudWFsIHRlc3QgcmVxdWly"
    "ZWQuICIKIyBTZXQgYnkgc2Nhbl91cmwoKS9ydW5fZnVsbF9zdWl0ZSgpIGJlZm9yZSBlYWNoIHBhc3Mgc28gYWRkKCkgY2Fu"
    "IHRhZyBldmVyeQojIHJvdyB3aXRoIHdoaWNoIGlucHV0IFVSTCBpdCBjYW1lIGZyb20gYW5kIHdoaWNoIG9mIHRoZSB0d28g"
    "cGFzc2VzCiMgKGdpdmVuLXVybCAvIHNpdGUtcm9vdCkgcHJvZHVjZWQgaXQsIHdpdGhvdXQgdGhyZWFkaW5nIHR3byBleHRy"
    "YQojIHBhcmFtZXRlcnMgdGhyb3VnaCBldmVyeSBvbmUgb2YgdGhlIH43MCBhZGQoKSBjYWxsIHNpdGVzIGJlbG93LgpDVFgg"
    "PSB7InNvdXJjZV9pbnB1dCI6IE5vbmUsICJ1cmxfcm9sZSI6ICJnaXZlbi11cmwiLCAicGhhc2UiOiAiYmFzZWxpbmUifQoK"
    "IyBQb3B1bGF0ZWQgZnJvbSAtLWNvb2tpZS8tLWhlYWRlciBieSBtYWluKCkgYmVmb3JlIHNjYW5uaW5nIHN0YXJ0cywgdGhl"
    "bgojIG1lcmdlZCBpbnRvIGV2ZXJ5IHJlcXVlc3QgcmF3X3JlcXVlc3QoKSBtYWtlcyAoc2VlIHJhd19yZXF1ZXN0KCkgYmVs"
    "b3cpIC0KIyB0aGlzIGlzIHdoYXQgbGV0cyBhbiBhdXRoZW50aWNhdGVkIEJ1cnAgc2Vzc2lvbidzIGNvb2tpZS9BdXRob3Jp"
    "emF0aW9uCiMgaGVhZGVyIGZsb3cgdGhyb3VnaCB0byBldmVyeSBvbmUgb2YgdGhlIH4xMDAgY2hlY2tzIHdpdGhvdXQgdG91"
    "Y2hpbmcgZWFjaAojIGNoZWNrIGZ1bmN0aW9uIGluZGl2aWR1YWxseS4gQSBwZXItY2FsbCBleHRyYV9oZWFkZXJzPSAoZS5n"
    "LiB0aGUKIyBhY2NvdW50MS9hY2NvdW50MiBJRE9SIGNvb2tpZSBpbiBfZmV0Y2hfd2l0aF9jb29raWUoKSkgYWx3YXlzIG92"
    "ZXJyaWRlcwojIHRoZXNlIG9uIGEgbmFtZSBjb2xsaXNpb24gLSBnbG9iYWwgc2Vzc2lvbiBpZGVudGl0eSBpcyB0aGUgZGVm"
    "YXVsdCwgYW4KIyBleHBsaWNpdCBwZXItY2hlY2sgaWRlbnRpdHkgYWx3YXlzIHdpbnMuCkVYVFJBX0FVVEhfSEVBREVSUyA9"
    "IHt9CgojIFBvcHVsYXRlZCBmcm9tIChyZXBlYXRhYmxlKSAtLW9ubHkgPElEPiBieSBtYWluKCkgLSB3aGVuIHNldCwgYWRk"
    "KCkgZHJvcHMKIyBhbnkgcm93IHdob3NlIENoZWNrbGlzdCBJRCBpc24ndCBpbiB0aGlzIHNldCBpbnN0ZWFkIG9mIHJlY29y"
    "ZGluZyBpdC4gVGhlCiMgY2hlY2sgaXRzZWxmIHN0aWxsIHJ1bnMgKHRoZXNlIGFyZSBhbGwgZmFzdCBIVFRQL1RMUyBwcm9i"
    "ZXMsIG5vdCBhbgojIGV4cGVuc2l2ZSBleHRlcm5hbCBzY2FuKSwgYnV0IG9ubHkgdGhlIHJlcXVlc3RlZCBJRHMgZW5kIHVw"
    "IGluIHRoZSBvdXRwdXQKIyAtIHRoaXMgaXMgd2hhdCBwb3dlcnMgYSAicmUtcnVuIHNlbGVjdGVkIHJvd3Mgb25seSIgZmVh"
    "dHVyZSBpbiBhIGNhbGxlcgojIGxpa2UgYSBCdXJwIGV4dGVuc2lvbiwgd2l0aG91dCBuZWVkaW5nIGV2ZXJ5IG9uZSBvZiB0"
    "aGUgfjMwIGNoZWNrXyooKQojIGZ1bmN0aW9ucyB0byBrbm93IGhvdyB0byBza2lwIHRoZW1zZWx2ZXMgaW5kaXZpZHVhbGx5"
    "LgpPTkxZX0lEUyA9IE5vbmUKCgpkZWYgbm93X2lzbygpOgogICAgcmV0dXJuIGRhdGV0aW1lLm5vdyh0aW1lem9uZS51dGMp"
    "LnN0cmZ0aW1lKCIlWS0lbS0lZCAlSDolTTolUyBVVEMiKQoKCmRlZiBhZGQodXJsLCBjaWQsIGNhdGVnb3J5LCB0ZXN0LCBz"
    "ZXZlcml0eSwgcHJpb3JpdHksIHJlc3VsdCwgZXZpZGVuY2UpOgogICAgaWYgT05MWV9JRFMgaXMgbm90IE5vbmUgYW5kIGNp"
    "ZCBub3QgaW4gT05MWV9JRFM6CiAgICAgICAgcmV0dXJuCiAgICBldmlkZW5jZSA9IGV2aWRlbmNlLnN0cmlwKCkgaWYgZXZp"
    "ZGVuY2UgZWxzZSAiIgogICAgaWYgcmVzdWx0ID09ICJNQU5VQUwiIGFuZCBub3QgZXZpZGVuY2Uuc3RhcnRzd2l0aChNQU5V"
    "QUxfUFJFRklYKToKICAgICAgICBldmlkZW5jZSA9IE1BTlVBTF9QUkVGSVggKyBldmlkZW5jZQogICAgcm93ID0gewogICAg"
    "ICAgICJzb3VyY2VfaW5wdXQiOiBDVFguZ2V0KCJzb3VyY2VfaW5wdXQiKSBvciB1cmwsCiAgICAgICAgInVybF9yb2xlIjog"
    "Q1RYLmdldCgidXJsX3JvbGUiKSBvciAiZ2l2ZW4tdXJsIiwKICAgICAgICAicGhhc2UiOiBDVFguZ2V0KCJwaGFzZSIpIG9y"
    "ICJiYXNlbGluZSIsCiAgICAgICAgInVybCI6IHVybCwgImlkIjogY2lkLCAiY2F0ZWdvcnkiOiBjYXRlZ29yeSwgInRlc3Qi"
    "OiB0ZXN0LAogICAgICAgICJzZXZlcml0eSI6IHNldmVyaXR5LCAicHJpb3JpdHkiOiBwcmlvcml0eSwgInJlc3VsdCI6IHJl"
    "c3VsdCwKICAgICAgICAiZXZpZGVuY2UiOiBldmlkZW5jZSwgImNoZWNrZWRfYXQiOiBub3dfaXNvKCksCiAgICAgICAgImV2"
    "aWRlbmNlX2ltYWdlX2Jhc2U2NCI6IE5vbmUsICAjIGZpbGxlZCBpbiBieSBnZW5lcmF0ZV9zY3JlZW5zaG90cygpIGlmIHRo"
    "aXMgcm93IHF1YWxpZmllcwogICAgfQogICAgUkVTVUxUUy5hcHBlbmQocm93KQogICAgIyBMaXZlLXByb2dyZXNzIGxpbmUg"
    "Zm9yIGEgY2FsbGVyIChlLmcuIHRoZSBCdXJwIGV4dGVuc2lvbikgcmVhZGluZwogICAgIyB0aGlzIHByb2Nlc3MncyBzdGRv"
    "dXQgQVMgSVQgUlVOUyBpbnN0ZWFkIG9mIHdhaXRpbmcgZm9yIGl0IHRvIGV4aXQgLQogICAgIyBvbmUgc2VsZi1jb250YWlu"
    "ZWQgSlNPTiByb3cgcGVyIGxpbmUsIGRpc3RpbmN0aXZlbHkgcHJlZml4ZWQgc28gaXQncwogICAgIyBlYXN5IHRvIHBpY2sg"
    "b3V0IGZyb20gdGhlIHNjYW4ncyBub3JtYWwgcHJpbnRlZCBuYXJyYXRpb24uIEZsdXNoZWQKICAgICMgaW1tZWRpYXRlbHkg"
    "c28gaXQgaXNuJ3Qgc2l0dGluZyBpbiBQeXRob24ncyBidWZmZXJlZCBzdGRvdXQgd2hlbiB0aGUKICAgICMgY2FsbGVyIHJl"
    "YWRzIGl0LiBOZXZlciBsZXRzIGEgcHJpbnQvZW5jb2RpbmcgaGljY3VwIGJyZWFrIHRoZSBhY3R1YWwKICAgICMgc2NhbiAt"
    "IHRoaXMgaXMgYSBuaWNlLXRvLWhhdmUgc2lkZSBjaGFubmVsLCBub3QgdGhlIHNvdXJjZSBvZiB0cnV0aAogICAgIyAoUkVT"
    "VUxUUyBhYm92ZSwgYW5kIHRoZSBmaW5hbCAuanNvbiwgYWx3YXlzIGhhdmUgdGhlIHJlYWwgZGF0YSkuCiAgICB0cnk6CiAg"
    "ICAgICAgcHJpbnQoIlFVSUNLQ0hPUF9ST1d8IiArIGpzb24uZHVtcHMocm93KSkKICAgICAgICBzeXMuc3Rkb3V0LmZsdXNo"
    "KCkKICAgIGV4Y2VwdCBFeGNlcHRpb246CiAgICAgICAgcGFzcwoKCmRlZiByYW5kX3Rva2VuKG49MTApOgogICAgcmV0dXJu"
    "ICIiLmpvaW4ocmFuZG9tLmNob2ljZXMoc3RyaW5nLmFzY2lpX2xvd2VyY2FzZSArIHN0cmluZy5kaWdpdHMsIGs9bikpCgoK"
    "IyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t"
    "LS0tLQojIEF1dG8tZ2VuZXJhdGVkICJldmlkZW5jZSBzY3JlZW5zaG90IiAtIGEgcmVuZGVyZWQgUE5HIGNhcmQgc3RhbmRp"
    "bmcgaW4KIyBmb3IgdGhlIG1hbnVhbCBzY3JlZW5zaG90IGEgcmVwb3J0IHdvdWxkIG90aGVyd2lzZSBuZWVkIHBlciBmaW5k"
    "aW5nLiBTZWUKIyBtb2R1bGUgZG9jc3RyaW5nICJBVVRPLUdFTkVSQVRFRCBFVklERU5DRSBTQ1JFRU5TSE9UUyIgZm9yIHRo"
    "ZSBmdWxsCiMgZXhwbGFuYXRpb24uIERlZ3JhZGVzIGdyYWNlZnVsbHkgKHdob2xlIHNjYW4gc3RpbGwgY29tcGxldGVzKSBp"
    "ZiBQaWxsb3cKIyBpc24ndCBpbnN0YWxsZWQgLSBjaGVja2VkIG9uY2UgdmlhIF9waWxsb3dfYXZhaWxhYmxlKCkuCiMgLS0t"
    "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0K"
    "Cl9QSUxMT1dfV0FSTkVEID0gRmFsc2UKCgpkZWYgX3BpbGxvd19hdmFpbGFibGUoKToKICAgIGdsb2JhbCBfUElMTE9XX1dB"
    "Uk5FRAogICAgdHJ5OgogICAgICAgIGltcG9ydCBQSUwgICMgbm9xYTogRjQwMQogICAgICAgIHJldHVybiBUcnVlCiAgICBl"
    "eGNlcHQgSW1wb3J0RXJyb3I6CiAgICAgICAgaWYgbm90IF9QSUxMT1dfV0FSTkVEOgogICAgICAgICAgICBwcmludCgiXG5b"
    "IV0gJ1BpbGxvdycgbm90IGluc3RhbGxlZCAtIHNraXBwaW5nIGF1dG8tZ2VuZXJhdGVkIGV2aWRlbmNlIHNjcmVlbnNob3Rz"
    "ICIKICAgICAgICAgICAgICAgICAgIih0aGUgcmVzdCBvZiB0aGUgc2NhbiBpcyB1bmFmZmVjdGVkKS4iKQogICAgICAgICAg"
    "ICBwcmludCgiICAgIEluc3RhbGwgd2l0aDogcGlwMyBpbnN0YWxsIFBpbGxvdyAgICIKICAgICAgICAgICAgICAgICAgIihh"
    "ZGQgLS1icmVhay1zeXN0ZW0tcGFja2FnZXMgaWYgeW91ciBQeXRob24gcmVwb3J0cyBhbiBleHRlcm5hbGx5LW1hbmFnZWQt"
    "ZW52aXJvbm1lbnQgZXJyb3IpIikKICAgICAgICAgICAgX1BJTExPV19XQVJORUQgPSBUcnVlCiAgICAgICAgcmV0dXJuIEZh"
    "bHNlCgoKX1JFU1VMVF9DT0xPUlMgPSB7CiAgICAiUEFTUyI6ICgiIzFlN2UzNCIsICIjZWFmYWYxIiksCiAgICAiRkFJTCI6"
    "ICgiI2E0MjYyYyIsICIjZmRlY2VhIiksCiAgICAiTUFOVUFMIjogKCIjOGE2ZDAwIiwgIiNmZmY4ZTEiKSwKICAgICJJTkZP"
    "IjogKCIjMWY0ZTc4IiwgIiNlYWYxZmIiKSwKICAgICJFUlJPUiI6ICgiIzNiM2IzYiIsICIjZWVlZWVlIiksCn0KCgpkZWYg"
    "X3dyYXBfYnlfcGl4ZWwoZHJhdywgdGV4dCwgZm9udCwgbWF4X3dpZHRoX3B4KToKICAgICIiIldvcmQtd3JhcHMgYnkgYWN0"
    "dWFsbHkgTUVBU1VSSU5HIGVhY2ggY2FuZGlkYXRlIGxpbmUncyBwaXhlbAogICAgd2lkdGggYWdhaW5zdCB0aGUgZm9udCBp"
    "biB1c2UsIGluc3RlYWQgb2YgZ3Vlc3NpbmcgYSBmaXhlZAogICAgY2hhcmFjdGVyIGNvdW50IC0gYSBjaGFyLWNvdW50IGd1"
    "ZXNzIChlLmcuIHdpZHRoPTEyOCkgc2lsZW50bHkKICAgIG92ZXJmbG93cyB0aGUgaW1hZ2UgZWRnZSB3aGVuZXZlciB0aGUg"
    "cmVhbCBnbHlwaCB3aWR0aCBkb2Vzbid0CiAgICBtYXRjaCB0aGUgZ3Vlc3MgKGRpZmZlcmVudCBmb250LCBib2xkIHZzIHJl"
    "Z3VsYXIsIG9yIHRoZQogICAgbG9hZF9kZWZhdWx0KCkgZmFsbGJhY2sgd2hlbiBEZWphVnVTYW5zTW9ubyBpc24ndCBpbnN0"
    "YWxsZWQsCiAgICB3aGljaCBpc24ndCBldmVuIG1vbm9zcGFjZSkuIEZhbGxzIGJhY2sgdG8gYSBzaW5nbGUgY2hhcmFjdGVy"
    "LWJ5LQogICAgY2hhcmFjdGVyIGJyZWFrIG9ubHkgZm9yIG9uZSB3b3JkIHRvbyBsb25nIHRvIGZpdCBhdCBhbGwuIFNoYXJl"
    "ZCBieQogICAgcmVuZGVyX2V2aWRlbmNlX2ltYWdlKCkgYW5kIHJlbmRlcl90ZXJtaW5hbF9pbWFnZSgpIHNvIGV2ZXJ5CiAg"
    "ICBzY3JlZW5zaG90IC0gY3VybC9ubWFwLWJhY2tlZCBvciBub3QgLSB3cmFwcyB0ZXh0IGlkZW50aWNhbGx5LiIiIgogICAg"
    "d29yZHMgPSB0ZXh0LnNwbGl0KCIgIikKICAgIGxpbmVzX291dCwgY3VyID0gW10sICIiCiAgICBmb3Igd29yZCBpbiB3b3Jk"
    "czoKICAgICAgICBjYW5kaWRhdGUgPSB3b3JkIGlmIG5vdCBjdXIgZWxzZSBmIntjdXJ9IHt3b3JkfSIKICAgICAgICBpZiBk"
    "cmF3LnRleHRsZW5ndGgoY2FuZGlkYXRlLCBmb250PWZvbnQpIDw9IG1heF93aWR0aF9weDoKICAgICAgICAgICAgY3VyID0g"
    "Y2FuZGlkYXRlCiAgICAgICAgICAgIGNvbnRpbnVlCiAgICAgICAgaWYgY3VyOgogICAgICAgICAgICBsaW5lc19vdXQuYXBw"
    "ZW5kKGN1cikKICAgICAgICBpZiBkcmF3LnRleHRsZW5ndGgod29yZCwgZm9udD1mb250KSA8PSBtYXhfd2lkdGhfcHg6CiAg"
    "ICAgICAgICAgIGN1ciA9IHdvcmQKICAgICAgICBlbHNlOgogICAgICAgICAgICAjIGEgc2luZ2xlICJ3b3JkIiAoZS5nLiBv"
    "bmUgbG9uZyBVUkwvdG9rZW4pIHdpZGVyIHRoYW4gdGhlCiAgICAgICAgICAgICMgbGluZSBpdHNlbGYgLSBoYXJkLWJyZWFr"
    "IGl0IGNoYXJhY3RlciBieSBjaGFyYWN0ZXIKICAgICAgICAgICAgY2h1bmsgPSAiIgogICAgICAgICAgICBmb3IgY2ggaW4g"
    "d29yZDoKICAgICAgICAgICAgICAgIGlmIGRyYXcudGV4dGxlbmd0aChjaHVuayArIGNoLCBmb250PWZvbnQpID4gbWF4X3dp"
    "ZHRoX3B4OgogICAgICAgICAgICAgICAgICAgIGxpbmVzX291dC5hcHBlbmQoY2h1bmspCiAgICAgICAgICAgICAgICAgICAg"
    "Y2h1bmsgPSBjaAogICAgICAgICAgICAgICAgZWxzZToKICAgICAgICAgICAgICAgICAgICBjaHVuayArPSBjaAogICAgICAg"
    "ICAgICBjdXIgPSBjaHVuawogICAgaWYgY3VyOgogICAgICAgIGxpbmVzX291dC5hcHBlbmQoY3VyKQogICAgcmV0dXJuIGxp"
    "bmVzX291dCBvciBbIiJdCgoKZGVmIF9tb25vX2ZvbnRzKCk6CiAgICAiIiJMb2FkcyB0aGUgbW9ub3NwYWNlIGZvbnQgcGFp"
    "ciB1c2VkIGJ5IGV2ZXJ5IHRlcm1pbmFsLXN0eWxlCiAgICBzY3JlZW5zaG90LiBDZW50cmFsaXplZCBzbyByZW5kZXJfZXZp"
    "ZGVuY2VfaW1hZ2UoKSBhbmQKICAgIHJlbmRlcl90ZXJtaW5hbF9pbWFnZSgpIGFsd2F5cyBtYXRjaC4iIiIKICAgIGZyb20g"
    "UElMIGltcG9ydCBJbWFnZUZvbnQKCiAgICBtb25vX2JvbGQgPSBtb25vID0gTm9uZQogICAgZm9yIGNhbmRpZGF0ZSBpbiAo"
    "IkRlamFWdVNhbnNNb25vLUJvbGQudHRmIiwpOgogICAgICAgIHRyeToKICAgICAgICAgICAgbW9ub19ib2xkID0gSW1hZ2VG"
    "b250LnRydWV0eXBlKGNhbmRpZGF0ZSwgMTUpCiAgICAgICAgICAgIGJyZWFrCiAgICAgICAgZXhjZXB0IEV4Y2VwdGlvbjoK"
    "ICAgICAgICAgICAgcGFzcwogICAgZm9yIGNhbmRpZGF0ZSBpbiAoIkRlamFWdVNhbnNNb25vLnR0ZiIsKToKICAgICAgICB0"
    "cnk6CiAgICAgICAgICAgIG1vbm8gPSBJbWFnZUZvbnQudHJ1ZXR5cGUoY2FuZGlkYXRlLCAxMykKICAgICAgICAgICAgYnJl"
    "YWsKICAgICAgICBleGNlcHQgRXhjZXB0aW9uOgogICAgICAgICAgICBwYXNzCiAgICBpZiBtb25vX2JvbGQgaXMgTm9uZToK"
    "ICAgICAgICBtb25vX2JvbGQgPSBJbWFnZUZvbnQubG9hZF9kZWZhdWx0KCkKICAgIGlmIG1vbm8gaXMgTm9uZToKICAgICAg"
    "ICBtb25vID0gSW1hZ2VGb250LmxvYWRfZGVmYXVsdCgpCiAgICByZXR1cm4gbW9ub19ib2xkLCBtb25vCgoKZGVmIHJlbmRl"
    "cl9ldmlkZW5jZV9pbWFnZShyb3cpOgogICAgIiIiUmV0dXJucyAoYmFzZTY0X3BuZ19zdHIsIHJhd19wbmdfYnl0ZXMpIGZv"
    "ciBvbmUgcmVzdWx0IHJvdywgb3IKICAgIChOb25lLCBOb25lKSBpZiBQaWxsb3cgaXNuJ3QgYXZhaWxhYmxlLiBFdmVyeSBz"
    "Y3JlZW5zaG90IG5vdyB1c2VzIHRoZQogICAgc2FtZSBibGFjay90ZXJtaW5hbCBsb29rIC0gcmVxdWVzdGVkIGRpcmVjdGx5"
    "OiAic2NyZWVuc2hvdCBmb3IgYmxhYwogICAgb25lIGF1dGhlbnRpY2EgbG9va3MgbGlrZSBjb21tYW5kIG91dHB1dCBpbnN0"
    "ZWQgb2Ygd2hpdGUgb25lIHlvdQogICAgc2hhcmVkLCBvdXRwdXQgc2hvdWRsIGJlIGNvbW1hbmQgbGluZSBvcHR1dC4iIFJv"
    "d3MgY2FycnlpbmcgcmVhbAogICAgY29tbWFuZC1saW5lIHRvb2wgb3V0cHV0IChjdXJsL25tYXAvc3NseXplLy4uLikgc3Rp"
    "bGwgZ28gdGhyb3VnaAogICAgcmVuZGVyX3Rlcm1pbmFsX2ltYWdlKCkgKHJlYWwgIiQgIiBjb21tYW5kICsgcmVhbCBvdXRw"
    "dXQpOyByb3dzCiAgICB3aXRob3V0IG9uZSAoaGV1cmlzdGljL21hbnVhbC1yZXZpZXcgY2hlY2tzKSBnZXQgYSB0ZXJtaW5h"
    "bC1zdHlsZWQKICAgIGNhcmQgYnVpbHQgZnJvbSB0aGlzIHJvdydzIG93biBmaWVsZHMgaW5zdGVhZCBvZiB0aGUgb2xkIHdo"
    "aXRlCiAgICAibGFiZWw6dmFsdWUiIHN1bW1hcnkgY2FyZC4iIiIKICAgIGlmIG5vdCBfcGlsbG93X2F2YWlsYWJsZSgpOgog"
    "ICAgICAgIHJldHVybiBOb25lLCBOb25lCiAgICBpZiBDTURfQkxPQ0tfTUFSS0VSIGluIChyb3cuZ2V0KCJldmlkZW5jZSIp"
    "IG9yICIiKToKICAgICAgICByZXR1cm4gcmVuZGVyX3Rlcm1pbmFsX2ltYWdlKHJvdykKICAgIGZyb20gUElMIGltcG9ydCBJ"
    "bWFnZSwgSW1hZ2VEcmF3CgogICAgVywgSCA9IDk4MCwgNjQwCiAgICBmZywgX2JnID0gX1JFU1VMVF9DT0xPUlMuZ2V0KHJv"
    "d1sicmVzdWx0Il0sICgiIzMzMzMzMyIsICIjZjVmNWY1IikpCiAgICBpbWcgPSBJbWFnZS5uZXcoIlJHQiIsIChXLCBIKSwg"
    "IiMwYzBjMGMiKQogICAgZHJhdyA9IEltYWdlRHJhdy5EcmF3KGltZykKICAgIG1vbm9fYm9sZCwgbW9ubyA9IF9tb25vX2Zv"
    "bnRzKCkKCiAgICBkcmF3LnJlY3RhbmdsZShbMCwgMCwgVywgNDBdLCBmaWxsPWZnKQogICAgZHJhdy50ZXh0KCgxNiwgMTAp"
    "LCBmIntyb3dbJ3Jlc3VsdCddfSAtIHtyb3dbJ2lkJ119IC0ge3Jvd1sndGVzdCddWzo3MF19IiwgZm9udD1tb25vX2JvbGQs"
    "IGZpbGw9IndoaXRlIikKCiAgICBtYXhfd2lkdGhfcHggPSBXIC0gMzIgICMgMTZweCBtYXJnaW4gZWFjaCBzaWRlCiAgICB5"
    "ID0gNTIKCiAgICBkZWYgZmllbGRfbGluZShsYWJlbCwgdmFsdWUsIHkpOgogICAgICAgIGRyYXcudGV4dCgoMTYsIHkpLCBm"
    "IntsYWJlbH06IiwgZm9udD1tb25vX2JvbGQsIGZpbGw9IiM1N2UzODkiKQogICAgICAgIGRyYXcudGV4dCgoMTUwLCB5KSwg"
    "c3RyKHZhbHVlKVs6MTEwXSwgZm9udD1tb25vLCBmaWxsPSIjZTBlMGUwIikKICAgICAgICByZXR1cm4geSArIDE5CgogICAg"
    "eSA9IGZpZWxkX2xpbmUoIlVSTCIsIHJvd1sidXJsIl0sIHkpCiAgICB5ID0gZmllbGRfbGluZSgiVVJMIFJvbGUiLCByb3db"
    "InVybF9yb2xlIl0sIHkpCiAgICB5ID0gZmllbGRfbGluZSgiQ2F0ZWdvcnkiLCByb3dbImNhdGVnb3J5Il0sIHkpCiAgICB5"
    "ID0gZmllbGRfbGluZSgiU2V2ZXJpdHkiLCBmIntyb3dbJ3NldmVyaXR5J119ICh7cm93Wydwcmlvcml0eSddfSkiLCB5KQog"
    "ICAgeSA9IGZpZWxkX2xpbmUoIkNoZWNrZWQgQXQiLCByb3dbImNoZWNrZWRfYXQiXSwgeSkKICAgIHkgKz0gNgogICAgZHJh"
    "dy5saW5lKFsxNiwgeSwgVyAtIDE2LCB5XSwgZmlsbD0iIzNhM2EzYSIsIHdpZHRoPTEpCiAgICB5ICs9IDEyCiAgICBkcmF3"
    "LnRleHQoKDE2LCB5KSwgIkV2aWRlbmNlOiIsIGZvbnQ9bW9ub19ib2xkLCBmaWxsPSIjNTdlMzg5IikKICAgIHkgKz0gMjAK"
    "CiAgICBtYXhfbGluZXMgPSBtYXgoKEggLSAzMCAtIHkpIC8vIDE3LCAxKQogICAgbGluZXMgPSBbXQogICAgZm9yIHJhd19s"
    "aW5lIGluIChyb3cuZ2V0KCJldmlkZW5jZSIpIG9yICIiKS5zcGxpdGxpbmVzKCk6CiAgICAgICAgbGluZXMuZXh0ZW5kKF93"
    "cmFwX2J5X3BpeGVsKGRyYXcsIHJhd19saW5lLCBtb25vLCBtYXhfd2lkdGhfcHgpIGlmIHJhd19saW5lIGVsc2UgWyIiXSkK"
    "ICAgIGZvciBsaW5lX3R4dCBpbiBsaW5lc1s6bWF4X2xpbmVzXToKICAgICAgICBkcmF3LnRleHQoKDE2LCB5KSwgbGluZV90"
    "eHQsIGZvbnQ9bW9ubywgZmlsbD0iI2QwZDBkMCIpCiAgICAgICAgeSArPSAxNwogICAgaWYgbGVuKGxpbmVzKSA+IG1heF9s"
    "aW5lczoKICAgICAgICBkcmF3LnRleHQoKDE2LCB5KSwgZiIuLi4gKHtsZW4obGluZXMpIC0gbWF4X2xpbmVzfSBtb3JlIGxp"
    "bmUocykgdHJ1bmNhdGVkIC0gc2VlIEpTT04vQ1NWIGZvciBmdWxsIHRleHQpIiwKICAgICAgICAgICAgICAgICAgIGZvbnQ9"
    "bW9ubywgZmlsbD0iIzg4ODg4OCIpCgogICAgZHJhdy50ZXh0KCgxNiwgSCAtIDIwKSwgIkF1dG8tZ2VuZXJhdGVkIGV2aWRl"
    "bmNlIGNhcmQgKGNoZWNrbGlzdF9hdXRvX3NjYW4ucHkpIC0gbm90IGEgbGl2ZSBicm93c2VyIHNjcmVlbnNob3QiLAogICAg"
    "ICAgICAgICAgICBmb250PW1vbm8sIGZpbGw9IiM2NjY2NjYiKQoKICAgIGJ1ZiA9IGlvLkJ5dGVzSU8oKQogICAgaW1nLnNh"
    "dmUoYnVmLCBmb3JtYXQ9IlBORyIpCiAgICByYXcgPSBidWYuZ2V0dmFsdWUoKQogICAgcmV0dXJuIGJhc2U2NC5iNjRlbmNv"
    "ZGUocmF3KS5kZWNvZGUoImFzY2lpIiksIHJhdwoKCmRlZiByZW5kZXJfdGVybWluYWxfaW1hZ2Uocm93KToKICAgICIiIlRl"
    "cm1pbmFsLXN0eWxlIHNjcmVlbnNob3QgZm9yIHJvd3MgY2FycnlpbmcgcmVhbCBjb21tYW5kLWxpbmUgdG9vbAogICAgb3V0"
    "cHV0IChjdXJsL25tYXAvc3NseXplLy4uLikuIFJlcXVlc3RlZCBkaXJlY3RseTogImNoZWNrIHdpdCBoY29tbWFuZAogICAg"
    "bGluZSB0b29scyBJIGhhdmUgbm90IHNlZW4gc3kgc2NyZWVuc2hvdHMgZm9yIGdpdmUgZmluZGluZ3MiIC0gdGhpcyBpcwog"
    "ICAgd2hhdCBtYWtlcyB0aG9zZSBzY3JlZW5zaG90cyBsb29rIGxpa2UgYW4gYWN0dWFsIHRlcm1pbmFsIGNhcHR1cmUgb2YK"
    "ICAgIHRoZSByZWFsIGNvbW1hbmQgKyBvdXRwdXQsIGluc3RlYWQgb2YgdGhlIGdlbmVyaWMgc3VtbWFyeSBjYXJkLiIiIgog"
    "ICAgZnJvbSBQSUwgaW1wb3J0IEltYWdlLCBJbWFnZURyYXcKCiAgICBXLCBIID0gOTgwLCA2NDAKICAgIGZnLCBfYmcgPSBf"
    "UkVTVUxUX0NPTE9SUy5nZXQocm93WyJyZXN1bHQiXSwgKCIjMzMzMzMzIiwgIiNmNWY1ZjUiKSkKICAgIGltZyA9IEltYWdl"
    "Lm5ldygiUkdCIiwgKFcsIEgpLCAiIzBjMGMwYyIpCiAgICBkcmF3ID0gSW1hZ2VEcmF3LkRyYXcoaW1nKQogICAgbW9ub19i"
    "b2xkLCBtb25vID0gX21vbm9fZm9udHMoKQoKICAgIGRyYXcucmVjdGFuZ2xlKFswLCAwLCBXLCA0MF0sIGZpbGw9ZmcpCiAg"
    "ICBkcmF3LnRleHQoKDE2LCAxMCksIGYie3Jvd1sncmVzdWx0J119IC0ge3Jvd1snaWQnXX0gLSB7cm93Wyd0ZXN0J11bOjcw"
    "XX0iLCBmb250PW1vbm9fYm9sZCwgZmlsbD0id2hpdGUiKQoKICAgIGV2aWRlbmNlID0gcm93LmdldCgiZXZpZGVuY2UiKSBv"
    "ciAiIgogICAgbWFya2VyX3BvcyA9IGV2aWRlbmNlLmZpbmQoQ01EX0JMT0NLX01BUktFUikKICAgIHN1bW1hcnkgPSBldmlk"
    "ZW5jZVs6bWFya2VyX3Bvc10uc3RyaXAoKSBpZiBtYXJrZXJfcG9zID49IDAgZWxzZSBldmlkZW5jZS5zdHJpcCgpCiAgICBj"
    "bWRfYmxvY2sgPSBldmlkZW5jZVttYXJrZXJfcG9zICsgMjpdLnN0cmlwKCkgaWYgbWFya2VyX3BvcyA+PSAwIGVsc2UgIiIg"
    "ICMga2VlcCBsZWFkaW5nICIkICIKCiAgICBtYXhfd2lkdGhfcHggPSBXIC0gMzIgICMgMTZweCBtYXJnaW4gZWFjaCBzaWRl"
    "CgogICAgeSA9IDUyCiAgICBkcmF3LnRleHQoKDE2LCB5KSwgZiJVUkw6IHtyb3dbJ3VybCddfSAgfCAgUm9sZToge3Jvd1sn"
    "dXJsX3JvbGUnXX0gIHwgIHtyb3dbJ2NoZWNrZWRfYXQnXX0iLAogICAgICAgICAgICAgIGZvbnQ9bW9ubywgZmlsbD0iIzlh"
    "YTViMSIpCiAgICB5ICs9IDIyCgogICAgaWYgc3VtbWFyeToKICAgICAgICBmb3IgbGluZV90eHQgaW4gX3dyYXBfYnlfcGl4"
    "ZWwoZHJhdywgc3VtbWFyeSwgbW9ubywgbWF4X3dpZHRoX3B4KVs6NF06CiAgICAgICAgICAgIGRyYXcudGV4dCgoMTYsIHkp"
    "LCBsaW5lX3R4dCwgZm9udD1tb25vLCBmaWxsPSIjZDBkMGQwIikKICAgICAgICAgICAgeSArPSAxOAogICAgICAgIHkgKz0g"
    "NgoKICAgIGRyYXcubGluZShbMTYsIHksIFcgLSAxNiwgeV0sIGZpbGw9IiMzYTNhM2EiLCB3aWR0aD0xKQogICAgeSArPSAx"
    "MAoKICAgIG1heF9saW5lcyA9IG1heCgoSCAtIDMwIC0geSkgLy8gMTcsIDEpCiAgICBsaW5lcyA9IFtdCiAgICBmb3IgcmF3"
    "X2xpbmUgaW4gY21kX2Jsb2NrLnNwbGl0bGluZXMoKToKICAgICAgICBsaW5lcy5leHRlbmQoX3dyYXBfYnlfcGl4ZWwoZHJh"
    "dywgcmF3X2xpbmUsIG1vbm8sIG1heF93aWR0aF9weCkgaWYgcmF3X2xpbmUgZWxzZSBbIiJdKQogICAgZm9yIGxpbmVfdHh0"
    "IGluIGxpbmVzWzptYXhfbGluZXNdOgogICAgICAgIGNvbG9yID0gIiM1N2UzODkiIGlmIGxpbmVfdHh0LnN0YXJ0c3dpdGgo"
    "IiQgIikgZWxzZSAiI2UwZTBlMCIKICAgICAgICBkcmF3LnRleHQoKDE2LCB5KSwgbGluZV90eHQsIGZvbnQ9bW9ubywgZmls"
    "bD1jb2xvcikKICAgICAgICB5ICs9IDE3CiAgICBpZiBsZW4obGluZXMpID4gbWF4X2xpbmVzOgogICAgICAgIGRyYXcudGV4"
    "dCgoMTYsIHkpLCBmIi4uLiAoe2xlbihsaW5lcykgLSBtYXhfbGluZXN9IG1vcmUgbGluZShzKSB0cnVuY2F0ZWQgLSBzZWUg"
    "SlNPTi9DU1YgZm9yIGZ1bGwgb3V0cHV0KSIsCiAgICAgICAgICAgICAgICAgIGZvbnQ9bW9ubywgZmlsbD0iIzg4ODg4OCIp"
    "CgogICAgZHJhdy50ZXh0KCgxNiwgSCAtIDIwKSwgIlJlYWwgY29tbWFuZC1saW5lIHRvb2wgb3V0cHV0IChjaGVja2xpc3Rf"
    "YXV0b19zY2FuLnB5KSAtIG5vdCBhIGxpdmUgYnJvd3NlciBzY3JlZW5zaG90IiwKICAgICAgICAgICAgICBmb250PW1vbm8s"
    "IGZpbGw9IiM2NjY2NjYiKQoKICAgIGJ1ZiA9IGlvLkJ5dGVzSU8oKQogICAgaW1nLnNhdmUoYnVmLCBmb3JtYXQ9IlBORyIp"
    "CiAgICByYXcgPSBidWYuZ2V0dmFsdWUoKQogICAgcmV0dXJuIGJhc2U2NC5iNjRlbmNvZGUocmF3KS5kZWNvZGUoImFzY2lp"
    "IiksIHJhdwoKCmRlZiBzaG91bGRfc2NyZWVuc2hvdChyZXN1bHQsIHBvbGljeSk6CiAgICBpZiBwb2xpY3kgPT0gIm5vbmUi"
    "OgogICAgICAgIHJldHVybiBGYWxzZQogICAgaWYgcG9saWN5ID09ICJhbGwiOgogICAgICAgIHJldHVybiByZXN1bHQgaW4g"
    "KCJQQVNTIiwgIkZBSUwiLCAiTUFOVUFMIiwgIklORk8iLCAiRVJST1IiKQogICAgaWYgcG9saWN5ID09ICJmYWlsK3Bhc3Mi"
    "OgogICAgICAgIHJldHVybiByZXN1bHQgaW4gKCJQQVNTIiwgIkZBSUwiKQogICAgcmV0dXJuIHJlc3VsdCA9PSAiRkFJTCIg"
    "ICMgZGVmYXVsdCBwb2xpY3k6ICJmYWlsIgoKCmRlZiBnZW5lcmF0ZV9zY3JlZW5zaG90cyhwb2xpY3kpOgogICAgIiIiUnVu"
    "cyBvbmNlLCBhZnRlciBhbGwgc2Nhbm5pbmcgaXMgZG9uZS4gRmlsbHMgaW4KICAgIHJvd1siZXZpZGVuY2VfaW1hZ2VfYmFz"
    "ZTY0Il0gZm9yIHF1YWxpZnlpbmcgcm93cyBhbmQgcmV0dXJucwogICAge3Jvd19pbmRleDogcmF3X3BuZ19ieXRlc30gZm9y"
    "IHRoZSBvbmVzIHdyaXR0ZW4gdG8gZGlzayAodXNlZCBieQogICAgd3JpdGVfeGxzeCB0byBlbWJlZCByZWFsIGltYWdlcykg"
    "LSBpbWFnZSBnZW5lcmF0aW9uIGhhcHBlbnMgZXhhY3RseQogICAgb25jZSBwZXIgcm93IGVpdGhlciB3YXksIGJhc2U2NCBh"
    "bmQgcmF3IGJ5dGVzIGNvbWUgZnJvbSB0aGUgc2FtZSBjYWxsLiIiIgogICAgaWYgcG9saWN5ID09ICJub25lIjoKICAgICAg"
    "ICByZXR1cm4ge30KICAgIGltYWdlX2J5dGVzID0ge30KICAgIGdlbmVyYXRlZCA9IDAKICAgIGZvciBpZHgsIHJvdyBpbiBl"
    "bnVtZXJhdGUoUkVTVUxUUyk6CiAgICAgICAgaWYgbm90IHNob3VsZF9zY3JlZW5zaG90KHJvd1sicmVzdWx0Il0sIHBvbGlj"
    "eSk6CiAgICAgICAgICAgIGNvbnRpbnVlCiAgICAgICAgYjY0LCByYXcgPSByZW5kZXJfZXZpZGVuY2VfaW1hZ2Uocm93KQog"
    "ICAgICAgIGlmIGI2NCBpcyBOb25lOgogICAgICAgICAgICBicmVhayAgIyBQaWxsb3cgdW5hdmFpbGFibGUgLSBubyBwb2lu"
    "dCByZXRyeWluZyBvbiBldmVyeSByZW1haW5pbmcgcm93CiAgICAgICAgcm93WyJldmlkZW5jZV9pbWFnZV9iYXNlNjQiXSA9"
    "IGI2NAogICAgICAgIGltYWdlX2J5dGVzW2lkeF0gPSByYXcKICAgICAgICBnZW5lcmF0ZWQgKz0gMQogICAgaWYgZ2VuZXJh"
    "dGVkOgogICAgICAgIHByaW50KGYiXG5bKl0gR2VuZXJhdGVkIHtnZW5lcmF0ZWR9IGF1dG8tZXZpZGVuY2Ugc2NyZWVuc2hv"
    "dChzKSAoLS1zY3JlZW5zaG90IHtwb2xpY3l9KS4iKQogICAgcmV0dXJuIGltYWdlX2J5dGVzCgoKIyAtLS0tLS0tLS0tLS0t"
    "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQojIExvdy1sZXZl"
    "bCBIVFRQIGhlbHBlciAoc3RkbGliIG9ubHkgLSBubyAicmVxdWVzdHMiIGRlcGVuZGVuY3ksIHNvIHRoaXMKIyBydW5zIG9u"
    "IGEgYmFyZS1ib25lcyBQeXRob24gaW5zdGFsbCB3aXRoIG5vdGhpbmcgZXh0cmEgcGlwLWluc3RhbGxlZCkKIyAtLS0tLS0t"
    "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQoKY2xh"
    "c3MgSHR0cFJlc3VsdDoKICAgIGRlZiBfX2luaXRfXyhzZWxmLCBzdGF0dXM9Tm9uZSwgaGVhZGVycz1Ob25lLCBib2R5PWIi"
    "IiwgZXJyb3I9Tm9uZSwgZmluYWxfdXJsPU5vbmUpOgogICAgICAgIHNlbGYuc3RhdHVzID0gc3RhdHVzCiAgICAgICAgc2Vs"
    "Zi5oZWFkZXJzID0gaGVhZGVycyBvciB7fQogICAgICAgIHNlbGYuYm9keSA9IGJvZHkKICAgICAgICBzZWxmLmVycm9yID0g"
    "ZXJyb3IKICAgICAgICBzZWxmLmZpbmFsX3VybCA9IGZpbmFsX3VybAoKICAgIGRlZiBoZWFkZXIoc2VsZiwgbmFtZSwgZGVm"
    "YXVsdD0iIik6CiAgICAgICAgZm9yIGssIHYgaW4gc2VsZi5oZWFkZXJzLml0ZW1zKCk6CiAgICAgICAgICAgIGlmIGsubG93"
    "ZXIoKSA9PSBuYW1lLmxvd2VyKCk6CiAgICAgICAgICAgICAgICByZXR1cm4gdgogICAgICAgIHJldHVybiBkZWZhdWx0Cgog"
    "ICAgZGVmIHRleHQoc2VsZiwgbGltaXQ9MjAwMDAwKToKICAgICAgICB0cnk6CiAgICAgICAgICAgIHJldHVybiBzZWxmLmJv"
    "ZHlbOmxpbWl0XS5kZWNvZGUoInV0Zi04IiwgZXJyb3JzPSJyZXBsYWNlIikKICAgICAgICBleGNlcHQgRXhjZXB0aW9uOgog"
    "ICAgICAgICAgICByZXR1cm4gIiIKCgojIFN0YWJsZSBtYXJrZXIgcHJlZml4IHN0YW1wZWQgb250byBldmVyeSBIdHRwUmVz"
    "dWx0LmVycm9yIHByb2R1Y2VkIGJ5IHRoZQojIHNzbC5TU0xDZXJ0VmVyaWZpY2F0aW9uRXJyb3IgaGFuZGxlciBpbiByYXdf"
    "cmVxdWVzdCgpIGJlbG93IC0gdXNlZCBvbmx5IHRvCiMgcmVsaWFibHkgZGV0ZWN0ICJ0aGlzIHJvdyBmYWlsZWQgYmVjYXVz"
    "ZSBvZiBhIFRMUyBjaGFpbi12ZXJpZnkgcHJvYmxlbSIKIyBmcm9tIGV2aWRlbmNlL2Vycm9yIHRleHQgbGF0ZXIgKHByaW50"
    "X3NzbF92ZXJpZnlfc3VtbWFyeV9jYWxsb3V0KCkpLAojIGluZGVwZW5kZW50IG9mIHdoYXRldmVyIGV4YWN0IHdvcmRpbmcg"
    "T3BlblNTTC9QeXRob24gaGFwcGVuIHRvIHVzZSBmb3IKIyB0aGUgdW5kZXJseWluZyBlcnJvciBvbiBhIGdpdmVuIHBsYXRm"
    "b3JtL3ZlcnNpb24uCl9TU0xfVkVSSUZZX0hJTlRfTUFSS0VSID0gIltTU0wtQ0VSVC1WRVJJRlktRkFJTEVEXSIKCgpkZWYg"
    "cmF3X3JlcXVlc3QodXJsLCBtZXRob2Q9IkdFVCIsIGV4dHJhX2hlYWRlcnM9Tm9uZSwgdGltZW91dD0xMCwgaW5zZWN1cmU9"
    "RmFsc2UsCiAgICAgICAgICAgICAgICAgZm9sbG93X3JlZGlyZWN0cz1GYWxzZSwgbWF4X3JlZGlyZWN0cz0zLCBob3N0X292"
    "ZXJyaWRlPU5vbmUsIGJvZHk9Tm9uZSk6CiAgICAiIiJNaW5pbWFsIEhUVFAgY2xpZW50IHVzaW5nIGh0dHAuY2xpZW50IHNv"
    "IHdlIGNvbnRyb2wgcmF3IGhlYWRlcnMKICAgIGV4YWN0bHkgKG5lZWRlZCBmb3IgdGhlIEhvc3QtaGVhZGVyIHByb2JlIGFu"
    "ZCBPUFRJT05TL1RSQUNFIGNoZWNrcykgLQogICAgdXJsbGliIHJld3JpdGVzL25vcm1hbGl6ZXMgc29tZSBoZWFkZXJzIGlu"
    "IHdheXMgdGhhdCBnZXQgaW4gdGhlIHdheSBoZXJlLgogICAgYm9keT0gKGJ5dGVzKSBpcyBvcHRpb25hbCAtIG9ubHkgdGhl"
    "IGluamVjdGlvbiBwaGFzZSdzIFBPU1QtZmllbGQKICAgIHRlc3RpbmcgcGFzc2VzIGl0OyBldmVyeSBleGlzdGluZyBHRVQv"
    "T1BUSU9OUy1vbmx5IGNoZWNrIGlzIHVuYWZmZWN0ZWQKICAgIHNpbmNlIGJvZHkgZGVmYXVsdHMgdG8gTm9uZSwgc2FtZSBh"
    "cyBiZWZvcmUgdGhpcyB3YXMgYWRkZWQuIiIiCiAgICBoZWFkZXJzID0geyJVc2VyLUFnZW50IjogREVGQVVMVF9VQSwgIkFj"
    "Y2VwdCI6ICIqLyoiLCAiQ29ubmVjdGlvbiI6ICJjbG9zZSJ9CiAgICBpZiBFWFRSQV9BVVRIX0hFQURFUlM6CiAgICAgICAg"
    "aGVhZGVycy51cGRhdGUoRVhUUkFfQVVUSF9IRUFERVJTKQogICAgaWYgZXh0cmFfaGVhZGVyczoKICAgICAgICBoZWFkZXJz"
    "LnVwZGF0ZShleHRyYV9oZWFkZXJzKQoKICAgIHBhcnNlZCA9IHVybHBhcnNlKHVybCkKICAgIHNjaGVtZSA9IHBhcnNlZC5z"
    "Y2hlbWUgb3IgImh0dHBzIgogICAgaG9zdCA9IHBhcnNlZC5ob3N0bmFtZQogICAgcG9ydCA9IHBhcnNlZC5wb3J0IG9yICg0"
    "NDMgaWYgc2NoZW1lID09ICJodHRwcyIgZWxzZSA4MCkKICAgIHBhdGggPSBwYXJzZWQucGF0aCBvciAiLyIKICAgIGlmIHBh"
    "cnNlZC5xdWVyeToKICAgICAgICBwYXRoICs9ICI/IiArIHBhcnNlZC5xdWVyeQoKICAgIHRyeToKICAgICAgICBpZiBzY2hl"
    "bWUgPT0gImh0dHBzIjoKICAgICAgICAgICAgY3R4ID0gc3NsLmNyZWF0ZV9kZWZhdWx0X2NvbnRleHQoKQogICAgICAgICAg"
    "ICBpZiBpbnNlY3VyZToKICAgICAgICAgICAgICAgIGN0eC5jaGVja19ob3N0bmFtZSA9IEZhbHNlCiAgICAgICAgICAgICAg"
    "ICBjdHgudmVyaWZ5X21vZGUgPSBzc2wuQ0VSVF9OT05FCiAgICAgICAgICAgIGNvbm4gPSBIVFRQU0Nvbm5lY3Rpb24oaG9z"
    "dCwgcG9ydCwgdGltZW91dD10aW1lb3V0LCBjb250ZXh0PWN0eCkKICAgICAgICBlbHNlOgogICAgICAgICAgICBjb25uID0g"
    "SFRUUENvbm5lY3Rpb24oaG9zdCwgcG9ydCwgdGltZW91dD10aW1lb3V0KQoKICAgICAgICBzZW5kX2hlYWRlcnMgPSBkaWN0"
    "KGhlYWRlcnMpCiAgICAgICAgaWYgIkhvc3QiIG5vdCBpbiBzZW5kX2hlYWRlcnM6CiAgICAgICAgICAgIHNlbmRfaGVhZGVy"
    "c1siSG9zdCJdID0gaG9zdF9vdmVycmlkZSBvciAoaG9zdCBpZiBub3QgcGFyc2VkLnBvcnQgZWxzZSBmIntob3N0fTp7cGFy"
    "c2VkLnBvcnR9IikKICAgICAgICBlbHNlOgogICAgICAgICAgICBwYXNzCgogICAgICAgIGlmIGJvZHkgaXMgbm90IE5vbmU6"
    "CiAgICAgICAgICAgIHNlbmRfaGVhZGVycy5zZXRkZWZhdWx0KCJDb250ZW50LUxlbmd0aCIsIHN0cihsZW4oYm9keSkpKQog"
    "ICAgICAgICAgICBjb25uLnJlcXVlc3QobWV0aG9kLCBwYXRoLCBib2R5PWJvZHksIGhlYWRlcnM9c2VuZF9oZWFkZXJzKQog"
    "ICAgICAgIGVsc2U6CiAgICAgICAgICAgIGNvbm4ucmVxdWVzdChtZXRob2QsIHBhdGgsIGhlYWRlcnM9c2VuZF9oZWFkZXJz"
    "KQogICAgICAgIHJlc3AgPSBjb25uLmdldHJlc3BvbnNlKCkKICAgICAgICBzdGF0dXMgPSByZXNwLnN0YXR1cwogICAgICAg"
    "IHJlc3BfaGVhZGVycyA9IGRpY3QocmVzcC5nZXRoZWFkZXJzKCkpCiAgICAgICAgYm9keSA9IHJlc3AucmVhZCg1MDAwMDAp"
    "CiAgICAgICAgY29ubi5jbG9zZSgpCgogICAgICAgIHJlc3VsdCA9IEh0dHBSZXN1bHQoc3RhdHVzPXN0YXR1cywgaGVhZGVy"
    "cz1yZXNwX2hlYWRlcnMsIGJvZHk9Ym9keSwgZmluYWxfdXJsPXVybCkKCiAgICAgICAgaWYgZm9sbG93X3JlZGlyZWN0cyBh"
    "bmQgc3RhdHVzIGluICgzMDEsIDMwMiwgMzAzLCAzMDcsIDMwOCkgYW5kIG1heF9yZWRpcmVjdHMgPiAwOgogICAgICAgICAg"
    "ICBsb2NhdGlvbiA9IHJlc3BfaGVhZGVycy5nZXQoIkxvY2F0aW9uIikgb3IgcmVzcF9oZWFkZXJzLmdldCgibG9jYXRpb24i"
    "KQogICAgICAgICAgICBpZiBsb2NhdGlvbjoKICAgICAgICAgICAgICAgIG5leHRfdXJsID0gdXJsam9pbih1cmwsIGxvY2F0"
    "aW9uKQogICAgICAgICAgICAgICAgcmV0dXJuIHJhd19yZXF1ZXN0KG5leHRfdXJsLCBtZXRob2QsIGV4dHJhX2hlYWRlcnMs"
    "IHRpbWVvdXQsIGluc2VjdXJlLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBmb2xsb3dfcmVkaXJlY3Rz"
    "LCBtYXhfcmVkaXJlY3RzIC0gMSkKICAgICAgICByZXR1cm4gcmVzdWx0CiAgICBleGNlcHQgc3NsLlNTTENlcnRWZXJpZmlj"
    "YXRpb25FcnJvciBhcyBlOgogICAgICAgICMgaW5zZWN1cmU9VHJ1ZSBzZXRzIHZlcmlmeV9tb2RlPUNFUlRfTk9ORSBhYm92"
    "ZSwgd2hpY2ggbWVhbnMKICAgICAgICAjIE9wZW5TU0wgbmV2ZXIgcmFpc2VzIHRoaXMgaW4gdGhlIGZpcnN0IHBsYWNlIHdo"
    "ZW4gLS1pbnNlY3VyZSB3YXMKICAgICAgICAjIHVzZWQgLSBzbyByZWFjaGluZyB0aGlzIGJyYW5jaCBhbHdheXMgbWVhbnMg"
    "dmVyaWZpY2F0aW9uIHdhcyBPTgogICAgICAgICMgYW5kIGdlbnVpbmVseSBmYWlsZWQuIFRoZSBleGFjdCBlcnJvciB0ZXh0"
    "IFB5dGhvbidzIHNzbCBtb2R1bGUKICAgICAgICAjIHJhaXNlcyBmb3IgYSBicm9rZW4vc2VsZi1zaWduZWQvaW5jb21wbGV0"
    "ZSBjaGFpbiAoImNlcnRpZmljYXRlCiAgICAgICAgIyB2ZXJpZnkgZmFpbGVkOiB1bmFibGUgdG8gZ2V0IGxvY2FsIGlzc3Vl"
    "ciBjZXJ0aWZpY2F0ZSIsIGV0Yy4pIGlzCiAgICAgICAgIyBhY2N1cmF0ZSBidXQgZG9lc24ndCBzYXkgd2hhdCB0byBETyBh"
    "Ym91dCBpdCAtIGV2ZXJ5IG9uZSBvZiB0aGUKICAgICAgICAjIH4zMCBjaGVja18qKCkgZnVuY3Rpb25zIHJvdXRlcyBIVFRQ"
    "UyByZXF1ZXN0cyB0aHJvdWdoIGhlcmUsIHNvCiAgICAgICAgIyBmaXhpbmcgdGhlIG1lc3NhZ2Ugb25jZSBoZXJlIGZpeGVz"
    "IGl0IGV2ZXJ5d2hlcmUgaXQgY2FuIHN1cmZhY2UsCiAgICAgICAgIyBpbnN0ZWFkIG9mIG9ubHkgd2hlcmV2ZXIgYSBjaGVj"
    "ayBoYXBwZW5lZCB0byBwcmludCBpdC4gU2VlIGFsc28KICAgICAgICAjIHRoZSBTU0wgY2VydC12ZXJpZnkgY2FsbG91dCBp"
    "biBwcmludF9zdW1tYXJ5KCksIHdoaWNoIHN1cmZhY2VzCiAgICAgICAgIyB0aGlzIHNhbWUgY2xhc3Mgb2YgZmFpbHVyZSBh"
    "cyBhIHNpbmdsZSB0b3Atb2Ytc3VtbWFyeSBub3RlIHdoZW4KICAgICAgICAjIGl0IGFmZmVjdHMgc2V2ZXJhbCByb3dzLCBp"
    "bnN0ZWFkIG9mIGl0IG9ubHkgYXBwZWFyaW5nIHNjYXR0ZXJlZAogICAgICAgICMgYWNyb3NzIGluZGl2aWR1YWwgZXZpZGVu"
    "Y2UgdGV4dC4KICAgICAgICByZXR1cm4gSHR0cFJlc3VsdChlcnJvcj1mIntfU1NMX1ZFUklGWV9ISU5UX01BUktFUn0ge2V9"
    "IC0gaWYgdGhpcyBpcyBhbiBleHBlY3RlZCBzZWxmLXNpZ25lZC9pbnRlcm5hbC9VQVQgIgogICAgICAgICAgICAgICAgICAg"
    "ICAgICAgICAgICAgICBmImNlcnRpZmljYXRlLCByZS1ydW4gd2l0aCAtLWluc2VjdXJlIHRvIHNraXAgdmVyaWZpY2F0aW9u"
    "IGFuZCB0ZXN0IGFueXdheTsgaWYgIgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBmInlvdSBleHBlY3RlZCB0"
    "aGlzIHRvIGJlIGEgcmVhbCwgdHJ1c3RlZCBjZXJ0aWZpY2F0ZSwgdGhpcyBJUyBhIGxlZ2l0aW1hdGUgIgogICAgICAgICAg"
    "ICAgICAgICAgICAgICAgICAgICAgICBmImZpbmRpbmcgKFdBLVRMUy00MDctc3R5bGUgY2hhaW4gaXNzdWUpIC0gb3IgeW91"
    "ciBtYWNoaW5lJ3Mgb3duIENBIGJ1bmRsZSBtYXkgIgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBmImJlIG91"
    "dCBvZiBkYXRlICh0cnk6IHBpcDMgaW5zdGFsbCAtLXVwZ3JhZGUgY2VydGlmaSkuIikKICAgIGV4Y2VwdCBFeGNlcHRpb24g"
    "YXMgZToKICAgICAgICByZXR1cm4gSHR0cFJlc3VsdChlcnJvcj1zdHIoZSkpCgoKZGVmIGJhc2VfdXJsX29mKHVybCk6CiAg"
    "ICAiIiJzY2hlbWU6Ly9ob3N0Wzpwb3J0XS8gLSBhbHdheXMgdGhlIFNJVEUgUk9PVCwgZHJvcHBpbmcgYW55IHBhdGguCiAg"
    "ICBVc2VkIG9uY2UgcGVyIGlucHV0IFVSTCB0byBjb21wdXRlIHRoZSBhdXRvbWF0aWMgc2Vjb25kICgic2l0ZS1yb290IikK"
    "ICAgIHBhc3M7IHNlZSBkaXJfb2YoKSBiZWxvdyBmb3IgdGhlIHBlci1wYXNzIGRpcmVjdG9yeSB1c2VkIGZvciBwcm9iZXMu"
    "IiIiCiAgICBwID0gdXJscGFyc2UodXJsKQogICAgcG9ydF9wYXJ0ID0gZiI6e3AucG9ydH0iIGlmIHAucG9ydCBhbmQgbm90"
    "ICgocC5zY2hlbWUgPT0gImh0dHBzIiBhbmQgcC5wb3J0ID09IDQ0Mykgb3IKICAgICAgICAgICAgICAgICAgICAgICAgICAg"
    "ICAgICAgICAgICAgICAgICAgICAgICAocC5zY2hlbWUgPT0gImh0dHAiIGFuZCBwLnBvcnQgPT0gODApKSBlbHNlICIiCiAg"
    "ICByZXR1cm4gZiJ7cC5zY2hlbWV9Oi8ve3AuaG9zdG5hbWV9e3BvcnRfcGFydH0vIgoKCmRlZiBkaXJfb2YodXJsKToKICAg"
    "ICIiInNjaGVtZTovL2hvc3RbOnBvcnRdLzxwYXRoPi8gLSB0aGUgVVJMIGN1cnJlbnRseSBiZWluZyB0ZXN0ZWQsCiAgICB0"
    "cmVhdGVkIGFzIGEgZGlyZWN0b3J5ICh0cmFpbGluZyBzbGFzaCBhZGRlZCBpZiBtaXNzaW5nKS4gUGF0aC1iYXNlZAogICAg"
    "cHJvYmVzIGFyZSBqb2luZWQgdW5kZXIgVEhJUywgc28gd2hlbiB0aGUgY3VycmVudCBwYXNzJ3MgdGFyZ2V0IGlzCiAgICBo"
    "dHRwczovL2hvc3Qvc3ViZm9sZGVyLCBwcm9iZXMgbGFuZCBhdCBodHRwczovL2hvc3Qvc3ViZm9sZGVyL3JvYm90cy50eHQK"
    "ICAgIGV0Yy47IHdoZW4gdGhlIGN1cnJlbnQgcGFzcydzIHRhcmdldCBpcyB0aGUgc2l0ZSByb290LCB0aGV5IGxhbmQgYXQK"
    "ICAgIGh0dHBzOi8vaG9zdC9yb2JvdHMudHh0IC0gc2FtZSBoZWxwZXIsIGNvcnJlY3QgZWl0aGVyIHdheS4iIiIKICAgIHAg"
    "PSB1cmxwYXJzZSh1cmwpCiAgICBwb3J0X3BhcnQgPSBmIjp7cC5wb3J0fSIgaWYgcC5wb3J0IGFuZCBub3QgKChwLnNjaGVt"
    "ZSA9PSAiaHR0cHMiIGFuZCBwLnBvcnQgPT0gNDQzKSBvcgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg"
    "ICAgICAgICAgICAgIChwLnNjaGVtZSA9PSAiaHR0cCIgYW5kIHAucG9ydCA9PSA4MCkpIGVsc2UgIiIKICAgIHBhdGggPSBw"
    "LnBhdGggb3IgIi8iCiAgICBpZiBub3QgcGF0aC5lbmRzd2l0aCgiLyIpOgogICAgICAgIHBhdGggKz0gIi8iCiAgICByZXR1"
    "cm4gZiJ7cC5zY2hlbWV9Oi8ve3AuaG9zdG5hbWV9e3BvcnRfcGFydH17cGF0aH0iCgoKZGVmIGpvaW5fdGFyZ2V0KGJhc2Us"
    "IHBhdGgpOgogICAgIyBwYXRoIGNvbnN0YW50cyBiZWxvdyBhcmUgd3JpdHRlbiBhcyAiL3JvYm90cy50eHQiIGV0Yy4gZm9y"
    "CiAgICAjIHJlYWRhYmlsaXR5OyBzdHJpcCB0aGUgbGVhZGluZyAiLyIgYmVmb3JlIGpvaW5pbmcgc28gdXJsam9pbiB0cmVh"
    "dHMKICAgICMgdGhlbSBhcyByZWxhdGl2ZSB0byBgYmFzZWAncyBkaXJlY3RvcnkgaW5zdGVhZCBvZiByZXNldHRpbmcgdG8g"
    "dGhlCiAgICAjIGRvbWFpbiByb290ICh3aGljaCBpcyB3aGF0IGEgbGVhZGluZyAiLyIgbWVhbnMgdG8gdXJsam9pbikuCiAg"
    "ICByZXR1cm4gdXJsam9pbihiYXNlLCBwYXRoLmxzdHJpcCgiLyIpKQoKCiMgLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t"
    "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KIyBDb21tYW5kLWxpbmUgdG9vbCBpbnRl"
    "Z3JhdGlvbiAoY3VybCAvIG5tYXAgLyBzc2x5emUgLyBzc2xzY2FuIC8gdGVzdHNzbC5zaCkKIyAtIHVzZWQgQVVUT01BVElD"
    "QUxMWSB3aGVuZXZlciB0aGUgdG9vbCBpcyBmb3VuZCBvbiBQQVRILCBubyBmbGFnIG5lZWRlZAojICAgKG9wdCBPVVQgd2l0"
    "aCAtLW5vLWNsaS10b29scykuIFJlcXVlc3RlZCBkaXJlY3RseTogIkkgaGF2ZSBjdWxzIGFuZAojICAgbm1hcCBhbmQgc3Ns"
    "YWx5emVyIGluc3RhbGxlZCBpbiB0aGUgcmVtb3RlIHNlcnZlciAuLi4gY2hlY2sgd2l0CiMgICBoY29tbWFuZCBsaW5lIHRv"
    "b2xzIEkgaGF2ZSBub3Qgc2VlbiBzeSBzY3JlZW5zaG90cyBmb3IgZ2l2ZSBmaW5kaW5ncy4iCiMgICBFdmVyeXRoaW5nIGhl"
    "cmUgaXMgUkVBRC1PTkxZIChHRVQgLyBUTFMgaGFuZHNoYWtlIHByb2JlcyBvbmx5KSAtIG5vCiMgICBjcmVkZW50aWFscyBh"
    "cmUgZXZlciB1c2VkLCBzZW50LCBvciByZXF1ZXN0ZWQgYW55d2hlcmUgaW4gdGhpcyBzY3JpcHQsCiMgICBwZXIgIm5ldmVy"
    "IHRha2UgdGhlIGNyZWRldGlscyBhbHNvIHRvIG5hdmlnYXRlIGluc2lkZSIuIFdoZW4gYSB0b29sCiMgICBpc24ndCBpbnN0"
    "YWxsZWQsIGV2ZXJ5IGNhbGxlciBiZWxvdyBmYWxscyBiYWNrIHRvIHRoZSBleGFjdCBzYW1lCiMgICBQeXRob24tb25seS9N"
    "QU5VQUwgYmVoYXZpb3VyIHRoaXMgc2NyaXB0IGFsd2F5cyBoYWQgLSBhIG1pc3NpbmcgdG9vbAojICAgbmV2ZXIgYnJlYWtz"
    "IG9yIGJsb2NrcyB0aGUgc2Nhbi4KIyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t"
    "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQoKQ01EX0JMT0NLX01BUktFUiA9ICJcblxuJCAiICAjIHJlbmRlcl9ldmlkZW5j"
    "ZV9pbWFnZSgpIHN3aXRjaGVzIHRvIHRoZSB0ZXJtaW5hbC1zdHlsZSBjYXJkIG9uIHRoaXMgbWFya2VyCk1BWF9DTURfT1VU"
    "UFVUX0NIQVJTID0gNDAwMAoKCmRlZiBfY2xpX2F2YWlsYWJsZShuYW1lKToKICAgIHJldHVybiBzaHV0aWwud2hpY2gobmFt"
    "ZSkgaXMgbm90IE5vbmUKCgpkZWYgX2Zvcm1hdF9jbWRfYmxvY2soY21kX2xpc3QsIG91dHB1dF90ZXh0LCBtYXhfbGVuPU1B"
    "WF9DTURfT1VUUFVUX0NIQVJTKToKICAgICIiIkFwcGVuZHMgYSByZWFsICIkIDxjb21tYW5kPlxcbjxvdXRwdXQ+IiBibG9j"
    "ayB0byBhbiBldmlkZW5jZSBzdHJpbmcuCiAgICBUaGlzIGlzIHdoYXQgbWFrZXMgcmVuZGVyX2V2aWRlbmNlX2ltYWdlKCkg"
    "c3dpdGNoIHRvIGEgdGVybWluYWwtc3R5bGUKICAgIHNjcmVlbnNob3QgaW5zdGVhZCBvZiB0aGUgZ2VuZXJpYyBzdW1tYXJ5"
    "IGNhcmQsIGFuZCBzaG93cyB1cCB2ZXJiYXRpbQogICAgaW4gdGhlIEpTT04vQ1NWL1hMU1ggZXZpZGVuY2UgY29sdW1uIGFz"
    "IGdlbnVpbmUgY29tbWFuZC1saW5lIHByb29mCiAgICByYXRoZXIgdGhhbiBhIHN5bnRoZXNpemVkIHN1bW1hcnkuIiIiCiAg"
    "ICBjbWRfc3RyID0gIiAiLmpvaW4oY21kX2xpc3QpCiAgICBvdXQgPSAob3V0cHV0X3RleHQgb3IgIiIpLnN0cmlwKCkKICAg"
    "IGlmIGxlbihvdXQpID4gbWF4X2xlbjoKICAgICAgICBvdXQgPSBvdXRbOm1heF9sZW5dICsgZiJcbi4uLiAodHJ1bmNhdGVk"
    "LCB7bGVuKG91dCkgLSBtYXhfbGVufSBtb3JlIGNoYXJzIC0gc2VlIEpTT04gZm9yIGZ1bGwgb3V0cHV0KSIKICAgIHJldHVy"
    "biBmIntDTURfQkxPQ0tfTUFSS0VSfXtjbWRfc3RyfVxue291dH0iCgoKZGVmIHJ1bl9jdXJsX3dpdGhfaG9zdF9oZWFkZXIo"
    "dXJsLCBob3N0X3ZhbHVlLCB0aW1lb3V0PTEwLCBpbnNlY3VyZT1GYWxzZSk6CiAgICAiIiJTYW1lIGlkZWEgYXMgcnVuX2N1"
    "cmxfaGVhZGVycygpIGJ1dCBzZW5kcyBhIGN1c3RvbSBIb3N0OiBoZWFkZXIgdmlhCiAgICBgY3VybCAtSCAiSG9zdDogLi4u"
    "ImAgLSB1c2VkIGJ5IGNoZWNrX2hvc3RfaGVhZGVyKCkgc28gVEhBVCBjaGVjayBhbHNvCiAgICBnZXRzIHJlYWwgY29tbWFu"
    "ZC1saW5lIGV2aWRlbmNlL3Rlcm1pbmFsIHNjcmVlbnNob3QgaW5zdGVhZCBvZiB0aGUKICAgIGdlbmVyaWMgc3VtbWFyeSBj"
    "YXJkLiBSZXF1ZXN0ZWQgZGlyZWN0bHkgYWZ0ZXIgc2VlaW5nIGEgSG9zdCBIZWFkZXIKICAgIGZpbmRpbmcncyBzY3JlZW5z"
    "aG90IHdpdGhvdXQgY29tbWFuZCBvdXRwdXQ6ICJnaXZlIHRoZSBjb21tYWRuIG91dAogICAgcHV0IG9mIHByb3BlciBvdXQg"
    "cHV0Ii4iIiIKICAgIGlmIG5vdCBfY2xpX2F2YWlsYWJsZSgiY3VybCIpOgogICAgICAgIHJldHVybiBOb25lCiAgICBjbWQg"
    "PSBbImN1cmwiLCAiLXNTIiwgIi1EIiwgIi0iLCAiLW8iLCAiL2Rldi9udWxsIiwgIi0tbWF4LXRpbWUiLCBzdHIoaW50KHRp"
    "bWVvdXQpIG9yIDEwKSwKICAgICAgICAgICAiLUEiLCBERUZBVUxUX1VBLCAiLUgiLCBmIkhvc3Q6IHtob3N0X3ZhbHVlfSJd"
    "CiAgICBpZiBpbnNlY3VyZToKICAgICAgICBjbWQuYXBwZW5kKCItayIpCiAgICBjbWQuYXBwZW5kKHVybCkKICAgIHRyeToK"
    "ICAgICAgICBwcm9jID0gc3VicHJvY2Vzcy5ydW4oY21kLCBjYXB0dXJlX291dHB1dD1UcnVlLCB0aW1lb3V0PXRpbWVvdXQg"
    "KyAxMCkKICAgICAgICBvdXQgPSBwcm9jLnN0ZG91dC5kZWNvZGUoInV0Zi04IiwgZXJyb3JzPSJyZXBsYWNlIikKICAgICAg"
    "ICBlcnIgPSBwcm9jLnN0ZGVyci5kZWNvZGUoInV0Zi04IiwgZXJyb3JzPSJyZXBsYWNlIikuc3RyaXAoKQogICAgICAgIGlm"
    "IGVycjoKICAgICAgICAgICAgb3V0ICs9ICgiXG4iIGlmIG91dCBlbHNlICIiKSArIGVycgogICAgICAgIHJldHVybiBjbWQs"
    "IG91dAogICAgZXhjZXB0IEV4Y2VwdGlvbiBhcyBlOgogICAgICAgIHJldHVybiBjbWQsIGYiKGN1cmwgZXhlY3V0aW9uIGZh"
    "aWxlZDoge2V9KSIKCgpkZWYgcnVuX2N1cmxfaGVhZGVycyh1cmwsIHRpbWVvdXQ9MTAsIGluc2VjdXJlPUZhbHNlKToKICAg"
    "ICIiIlJ1bnMgYGN1cmwgLXNTIC1EIC0gLW8gL2Rldi9udWxsIC4uLmAgYWdhaW5zdCBgdXJsYCBhbmQgcmV0dXJucwogICAg"
    "KGNtZF9saXN0LCBvdXRwdXRfdGV4dCksIG9yIE5vbmUgaWYgY3VybCBpc24ndCBvbiBQQVRILiBBIG5vbi0yeHgvM3h4CiAg"
    "ICBIVFRQIHN0YXR1cyBpcyBOT1QgdHJlYXRlZCBhcyBmYWlsdXJlIGhlcmUgLSBjdXJsIHN0aWxsIHByaW50cyB0aGUKICAg"
    "IHJlYWwgcmVzcG9uc2UgaGVhZGVycyBlaXRoZXIgd2F5LCB3aGljaCBpcyB0aGUgcG9pbnQuIiIiCiAgICBpZiBub3QgX2Ns"
    "aV9hdmFpbGFibGUoImN1cmwiKToKICAgICAgICByZXR1cm4gTm9uZQogICAgY21kID0gWyJjdXJsIiwgIi1zUyIsICItRCIs"
    "ICItIiwgIi1vIiwgIi9kZXYvbnVsbCIsICItLW1heC10aW1lIiwgc3RyKGludCh0aW1lb3V0KSBvciAxMCksCiAgICAgICAg"
    "ICAgIi1BIiwgREVGQVVMVF9VQV0KICAgIGlmIGluc2VjdXJlOgogICAgICAgIGNtZC5hcHBlbmQoIi1rIikKICAgIGNtZC5h"
    "cHBlbmQodXJsKQogICAgdHJ5OgogICAgICAgIHByb2MgPSBzdWJwcm9jZXNzLnJ1bihjbWQsIGNhcHR1cmVfb3V0cHV0PVRy"
    "dWUsIHRpbWVvdXQ9dGltZW91dCArIDEwKQogICAgICAgIG91dCA9IHByb2Muc3Rkb3V0LmRlY29kZSgidXRmLTgiLCBlcnJv"
    "cnM9InJlcGxhY2UiKQogICAgICAgIGVyciA9IHByb2Muc3RkZXJyLmRlY29kZSgidXRmLTgiLCBlcnJvcnM9InJlcGxhY2Ui"
    "KS5zdHJpcCgpCiAgICAgICAgaWYgZXJyOgogICAgICAgICAgICBvdXQgKz0gKCJcbiIgaWYgb3V0IGVsc2UgIiIpICsgZXJy"
    "CiAgICAgICAgcmV0dXJuIGNtZCwgb3V0CiAgICBleGNlcHQgRXhjZXB0aW9uIGFzIGU6CiAgICAgICAgcmV0dXJuIGNtZCwg"
    "ZiIoY3VybCBleGVjdXRpb24gZmFpbGVkOiB7ZX0pIgoKCiMgVHJpZWQgaW4gdGhpcyBvcmRlciAtIGZpcnN0IG9uZSBmb3Vu"
    "ZCBvbiBQQVRIIGlzIHVzZWQuIG5tYXAgaXMgdHJpZWQKIyBmaXJzdCBzaW5jZSBzc2wtZW51bS1jaXBoZXJzIG91dHB1dCBp"
    "cyB3aGF0IHRoZSBwYXJzZXIgYmVsb3cgdW5kZXJzdGFuZHMKIyBiZXN0LCBhbmQgdGhlIHVzZXIgY29uZmlybWVkIG5tYXAg"
    "aXMgaW5zdGFsbGVkOyBzc2x5emUvc3Nsc2Nhbi90ZXN0c3NsLnNoCiMgYXJlIHVzZWQgYXMtaXMgaWYgbm1hcCBpc24ndCBw"
    "cmVzZW50LgpfU1NMX0NMSV9UT09MUyA9IFsKICAgICgibm1hcCIsIGxhbWJkYSBoLCBwLCB0OiBbIm5tYXAiLCAiLVBuIiwg"
    "Ii0tc2NyaXB0IiwgInNzbC1lbnVtLWNpcGhlcnMiLCAiLXAiLCBzdHIocCksIGhdKSwKICAgICgic3NseXplIiwgbGFtYmRh"
    "IGgsIHAsIHQ6IFsic3NseXplIiwgZiJ7aH06e3B9Il0pLAogICAgKCJzc2xzY2FuIiwgbGFtYmRhIGgsIHAsIHQ6IFsic3Ns"
    "c2NhbiIsIGYie2h9OntwfSJdKSwKICAgICgidGVzdHNzbC5zaCIsIGxhbWJkYSBoLCBwLCB0OiBbInRlc3Rzc2wuc2giLCAi"
    "LS1mYXN0IiwgZiJ7aH06e3B9Il0pLApdCgoKZGVmIHJ1bl9zc2xfY2xpX3NjYW4oaG9zdCwgcG9ydCwgdGltZW91dD00NSk6"
    "CiAgICAiIiJSdW5zIHRoZSBGSVJTVCBhdmFpbGFibGUgU1NML1RMUyBDTEkgc2Nhbm5lciAoc2VlIF9TU0xfQ0xJX1RPT0xT"
    "KQogICAgYWdhaW5zdCBob3N0OnBvcnQgYW5kIHJldHVybnMgKHRvb2xfbmFtZSwgY21kX2xpc3QsIG91dHB1dF90ZXh0KSwg"
    "b3IKICAgIE5vbmUgaWYgbm9uZSBvZiB0aGVtIGFyZSBpbnN0YWxsZWQuIE9ubHkgb25lIHRvb2wgaXMgcnVuIChub3QgYWxs"
    "CiAgICBmb3VyKSB0byBrZWVwIHNjYW4gdGltZSByZWFzb25hYmxlLiIiIgogICAgZm9yIG5hbWUsIGJ1aWxkX2NtZCBpbiBf"
    "U1NMX0NMSV9UT09MUzoKICAgICAgICBpZiBub3QgX2NsaV9hdmFpbGFibGUobmFtZSk6CiAgICAgICAgICAgIGNvbnRpbnVl"
    "CiAgICAgICAgY21kID0gYnVpbGRfY21kKGhvc3QsIHBvcnQsIHRpbWVvdXQpCiAgICAgICAgdHJ5OgogICAgICAgICAgICBw"
    "cm9jID0gc3VicHJvY2Vzcy5ydW4oY21kLCBjYXB0dXJlX291dHB1dD1UcnVlLCB0aW1lb3V0PXRpbWVvdXQpCiAgICAgICAg"
    "ICAgIG91dCA9IHByb2Muc3Rkb3V0LmRlY29kZSgidXRmLTgiLCBlcnJvcnM9InJlcGxhY2UiKQogICAgICAgICAgICBlcnIg"
    "PSBwcm9jLnN0ZGVyci5kZWNvZGUoInV0Zi04IiwgZXJyb3JzPSJyZXBsYWNlIikuc3RyaXAoKQogICAgICAgICAgICBpZiBl"
    "cnI6CiAgICAgICAgICAgICAgICBvdXQgKz0gKCJcbiIgaWYgb3V0IGVsc2UgIiIpICsgZXJyCiAgICAgICAgICAgIHJldHVy"
    "biBuYW1lLCBjbWQsIG91dAogICAgICAgIGV4Y2VwdCBzdWJwcm9jZXNzLlRpbWVvdXRFeHBpcmVkOgogICAgICAgICAgICBy"
    "ZXR1cm4gbmFtZSwgY21kLCBmIihzY2FuIHRpbWVkIG91dCBhZnRlciB7dGltZW91dH1zIC0gdGFyZ2V0IG1heSBiZSBzbG93"
    "L3VucmVhY2hhYmxlLCB0cnkgYSBsb25nZXIgLS10aW1lb3V0KSIKICAgICAgICBleGNlcHQgRXhjZXB0aW9uIGFzIGU6CiAg"
    "ICAgICAgICAgIHJldHVybiBuYW1lLCBjbWQsIGYiKHtuYW1lfSBleGVjdXRpb24gZmFpbGVkOiB7ZX0pIgogICAgcmV0dXJu"
    "IE5vbmUKCgpfV0VBS19DSVBIRVJfSElOVFMgPSByZS5jb21waWxlKHIiXGIoUkM0fERFU3wzREVTfE5VTEx8RVhQT1JUfE1E"
    "NXxhbm9ufElERUF8U0VFRClcYiIsIHJlLklHTk9SRUNBU0UpCl9XRUFLX1RMU19WRVJTSU9OX0hJTlRTID0gcmUuY29tcGls"
    "ZShyIlxiKFNTTHYyfFNTTHYzfFRMU3YxXC4wfFRMU3YxXC4xfFRMUyAxXC4wfFRMUyAxXC4xKVxiIikKCgpkZWYgX3BhcnNl"
    "X3NzbF9jbGlfb3V0cHV0KG91dHB1dF90ZXh0KToKICAgICIiIkJlc3QtZWZmb3J0IHBhcnNlIG9mIHdoaWNoZXZlciBTU0wg"
    "Q0xJIHRvb2wgcmFuLCB1c2VkIHRvIHR1cm4KICAgIFdBLVRMUy00MDIvNDA0IGludG8gYSByZWFsIFBBU1MvRkFJTCBpbnN0"
    "ZWFkIG9mIGxlYXZpbmcgdGhlbSBNQU5VQUwuCiAgICBEZWxpYmVyYXRlbHkgY29uc2VydmF0aXZlIC0gYW4gaW5jb25jbHVz"
    "aXZlIHBhcnNlIGZhbGxzIGJhY2sgdG8KICAgIElORk8vTUFOVUFMIHJhdGhlciB0aGFuIGd1ZXNzaW5nIGEgUEFTUy4KCiAg"
    "ICBPbmx5IHNjYW5zIGxpbmVzIHRoYXQgYWN0dWFsbHkgbG9vayBsaWtlIGNpcGhlci1zdWl0ZSBvdXRwdXQgKGNvbnRhaW4K"
    "ICAgICJfV0lUSF8iLCBzdGFydCB3aXRoIFRMU18vU1NMXywgb3IgY29tZSBmcm9tIHNzbHNjYW4vdGVzdHNzbC1zdHlsZQog"
    "ICAgIkFjY2VwdGVkIC4uLiIgbGluZXMpIC0gTk9UIHRoZSB3aG9sZSByYXcgYmxvYi4gbm1hcCdzIHNzbC1lbnVtLWNpcGhl"
    "cnMKICAgIGFsc28gcHJpbnRzIGFuIHVucmVsYXRlZCAiY29tcHJlc3NvcnM6IE5VTEwiIGxpbmUgKE5VTEwgPSBubyBUTFMK"
    "ICAgIGNvbXByZXNzaW9uIG5lZ290aWF0ZWQsIGkuZS4gQ1JJTUUtc2FmZSAtIGEgR09PRCB0aGluZyksIGFuZCBtYXRjaGlu"
    "ZwogICAgIk5VTEwiIHRoZXJlIGFzIGEgd2Vhay1jaXBoZXIgaGl0IHdvdWxkIGJlIGEgZmFsc2UgcG9zaXRpdmUuIiIiCiAg"
    "ICBpZiBub3Qgb3V0cHV0X3RleHQ6CiAgICAgICAgcmV0dXJuIHsid2Vha19jaXBoZXJzIjogTm9uZSwgIndlYWtfcHJvdG9j"
    "b2xzIjogTm9uZSwgImxlYXN0X3N0cmVuZ3RoIjogTm9uZX0KCiAgICBjaXBoZXJfbGluZXMgPSAiXG4iLmpvaW4oCiAgICAg"
    "ICAgbGluZSBmb3IgbGluZSBpbiBvdXRwdXRfdGV4dC5zcGxpdGxpbmVzKCkKICAgICAgICBpZiAiY29tcHJlc3MiIG5vdCBp"
    "biBsaW5lLmxvd2VyKCkKICAgICAgICBhbmQgKCJfV0lUSF8iIGluIGxpbmUgb3IgIlRMU18iIGluIGxpbmUgb3IgIlNTTF8i"
    "IGluIGxpbmUKICAgICAgICAgICAgIG9yIHJlLnNlYXJjaChyIlxiKEFjY2VwdGVkfFByZWZlcnJlZHxSZWplY3RlZClcYiIs"
    "IGxpbmUsIHJlLklHTk9SRUNBU0UpKQogICAgKQoKICAgIHdlYWtfY2lwaGVycyA9IHNvcnRlZChzZXQobS5ncm91cCgwKSBm"
    "b3IgbSBpbiBfV0VBS19DSVBIRVJfSElOVFMuZmluZGl0ZXIoY2lwaGVyX2xpbmVzKSkpCiAgICB3ZWFrX3Byb3RvY29scyA9"
    "IHNvcnRlZChzZXQobS5ncm91cCgwKSBmb3IgbSBpbiBfV0VBS19UTFNfVkVSU0lPTl9ISU5UUy5maW5kaXRlcihvdXRwdXRf"
    "dGV4dCkpKQogICAgbSA9IHJlLnNlYXJjaChyImxlYXN0IHN0cmVuZ3RoOlxzKihbQS1aYS16XSspIiwgb3V0cHV0X3RleHQs"
    "IHJlLklHTk9SRUNBU0UpICAjIG5tYXAgc3NsLWVudW0tY2lwaGVycwogICAgbGVhc3Rfc3RyZW5ndGggPSBtLmdyb3VwKDEp"
    "IGlmIG0gZWxzZSBOb25lCiAgICByZXR1cm4geyJ3ZWFrX2NpcGhlcnMiOiB3ZWFrX2NpcGhlcnMgb3IgTm9uZSwgIndlYWtf"
    "cHJvdG9jb2xzIjogd2Vha19wcm90b2NvbHMgb3IgTm9uZSwKICAgICAgICAgICAgImxlYXN0X3N0cmVuZ3RoIjogbGVhc3Rf"
    "c3RyZW5ndGh9CgoKIyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t"
    "LS0tLS0tLS0tLS0tLS0tLQojIDEuIEhUVFAgU2VjdXJpdHkgSGVhZGVycyAtIFdBLUhEUi0zOTIuLjQwMQojIC0tLS0tLS0t"
    "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCgpkZWYg"
    "Y2hlY2tfc2VjdXJpdHlfaGVhZGVycyhmdWxsX3VybCwgYXJncyk6CiAgICByID0gcmF3X3JlcXVlc3QoZnVsbF91cmwsICJH"
    "RVQiLCB0aW1lb3V0PWFyZ3MudGltZW91dCwgaW5zZWN1cmU9YXJncy5pbnNlY3VyZSkKICAgIGlmIHIuZXJyb3I6CiAgICAg"
    "ICAgZm9yIGNpZCwgbmFtZSwgc2V2LCBwcmkgaW4gWwogICAgICAgICAgICAoIldBLUhEUi0zOTIiLCAiQ29udGVudC1TZWN1"
    "cml0eS1Qb2xpY3kgcHJlc2VudCBhbmQgc3RyaWN0IiwgIk1lZGl1bSIsICJQMiIpLAogICAgICAgICAgICAoIldBLUhEUi0z"
    "OTMiLCAiWC1GcmFtZS1PcHRpb25zOiBTQU1FT1JJR0lOIG9yIERFTlkgcHJlc2VudCIsICJNZWRpdW0iLCAiUDIiKSwKICAg"
    "ICAgICAgICAgKCJXQS1IRFItMzk0IiwgIlgtQ29udGVudC1UeXBlLU9wdGlvbnM6IG5vc25pZmYgcHJlc2VudCIsICJMb3ci"
    "LCAiUDMiKSwKICAgICAgICAgICAgKCJXQS1IRFItMzk1IiwgIlN0cmljdC1UcmFuc3BvcnQtU2VjdXJpdHkgKEhTVFMpIHBy"
    "b3Blcmx5IGNvbmZpZ3VyZWQiLCAiTWVkaXVtIiwgIlAyIiksCiAgICAgICAgICAgICgiV0EtSERSLTM5NiIsICJSZWZlcnJl"
    "ci1Qb2xpY3kgaGVhZGVyIHByZXNlbnQiLCAiTG93IiwgIlAzIiksCiAgICAgICAgICAgICgiV0EtSERSLTM5NyIsICJDYWNo"
    "ZS1Db250cm9sOiBuby1zdG9yZSBvbiBhdXRoZW50aWNhdGVkL3NlbnNpdGl2ZSBwYWdlcyIsICJNZWRpdW0iLCAiUDIiKSwK"
    "ICAgICAgICAgICAgKCJXQS1IRFItMzk4IiwgIlBlcm1pc3Npb25zLVBvbGljeSByZXN0cmljdHMgc2Vuc2l0aXZlIGJyb3dz"
    "ZXIgQVBJcyIsICJMb3ciLCAiUDMiKSwKICAgICAgICAgICAgKCJXQS1IRFItMzk5IiwgIkhUVFBTIGVuZm9yY2VkIC0gSFRU"
    "UCByZWRpcmVjdHMgdG8gSFRUUFMiLCAiSGlnaCIsICJQMSIpLAogICAgICAgICAgICAoIldBLUhEUi00MDAiLCAiVmVyYm9z"
    "ZSBlcnJvciBtZXNzYWdlcyAvIHN0YWNrIHRyYWNlcyBvbiA0eHgvNXh4IiwgIk1lZGl1bSIsICJQMiIpLAogICAgICAgICAg"
    "ICAoIldBLUhEUi00MDEiLCAiU2VydmVyIHZlcnNpb24gZGlzY2xvc3VyZSBpbiByZXNwb25zZSBoZWFkZXJzIiwgIkxvdyIs"
    "ICJQMyIpLAogICAgICAgIF06CiAgICAgICAgICAgIGFkZChmdWxsX3VybCwgY2lkLCAiSFRUUCBTZWN1cml0eSBIZWFkZXJz"
    "IiwgbmFtZSwgc2V2LCBwcmksICJFUlJPUiIsCiAgICAgICAgICAgICAgICBmIkNvdWxkIG5vdCBjb25uZWN0OiB7ci5lcnJv"
    "cn0iKQogICAgICAgIHJldHVybiByLCAiIgoKICAgIGN1cmxfcmVzdWx0ID0gTm9uZSBpZiBnZXRhdHRyKGFyZ3MsICJub19j"
    "bGlfdG9vbHMiLCBGYWxzZSkgZWxzZSBydW5fY3VybF9oZWFkZXJzKAogICAgICAgIGZ1bGxfdXJsLCB0aW1lb3V0PWFyZ3Mu"
    "dGltZW91dCwgaW5zZWN1cmU9YXJncy5pbnNlY3VyZSkKICAgIGN1cmxfYmxvY2sgPSBfZm9ybWF0X2NtZF9ibG9jayhjdXJs"
    "X3Jlc3VsdFswXSwgY3VybF9yZXN1bHRbMV0pIGlmIGN1cmxfcmVzdWx0IGVsc2UgIiIKCiAgICBjc3AgPSByLmhlYWRlcigi"
    "Q29udGVudC1TZWN1cml0eS1Qb2xpY3kiKQogICAgaWYgbm90IGNzcDoKICAgICAgICBhZGQoZnVsbF91cmwsICJXQS1IRFIt"
    "MzkyIiwgIkhUVFAgU2VjdXJpdHkgSGVhZGVycyIsICJDb250ZW50LVNlY3VyaXR5LVBvbGljeSBwcmVzZW50IGFuZCBzdHJp"
    "Y3QiLAogICAgICAgICAgICAiTWVkaXVtIiwgIlAyIiwgIkZBSUwiLAogICAgICAgICAgICAiQ09ORklSTUVEIEJZOiB0aGUg"
    "cmVzcG9uc2UgaGVhZGVycyBiZWxvdyBjb250YWluIG5vICdDb250ZW50LVNlY3VyaXR5LVBvbGljeScgZW50cnkgYXQgYWxs"
    "ICIKICAgICAgICAgICAgIihjaGVja2VkIGNhc2UtaW5zZW5zaXRpdmVseSBhY3Jvc3MgZXZlcnkgaGVhZGVyIHJldHVybmVk"
    "KS4iICsgY3VybF9ibG9jaykKICAgIGVsc2U6CiAgICAgICAgbWF0Y2hlZF90b2tlbnMgPSBbdCBmb3IgdCBpbiAoInVuc2Fm"
    "ZS1pbmxpbmUiLCAidW5zYWZlLWV2YWwiLCAiKiAiKSBpZiB0IGluIGNzcF0KICAgICAgICBsb29zZSA9IGJvb2wobWF0Y2hl"
    "ZF90b2tlbnMpIG9yIGNzcC5zdHJpcCgpLmVuZHN3aXRoKCIqIikKICAgICAgICBpZiBsb29zZToKICAgICAgICAgICAgcmVh"
    "c29uID0gKGYiQ1NQIGNvbnRhaW5zIHdlYWsgdG9rZW4ocykge21hdGNoZWRfdG9rZW5zfSIgaWYgbWF0Y2hlZF90b2tlbnMK"
    "ICAgICAgICAgICAgICAgICAgICAgICBlbHNlICJDU1AgdmFsdWUgZW5kcyB3aXRoIGEgYmFyZSB3aWxkY2FyZCAnKiciKQog"
    "ICAgICAgICAgICBldmlkZW5jZSA9IGYiQ09ORklSTUVEIEJZOiB7cmVhc29ufSAtIGZ1bGwgaGVhZGVyIHZhbHVlOiB7Y3Nw"
    "WzozMDBdfSIKICAgICAgICBlbHNlOgogICAgICAgICAgICBldmlkZW5jZSA9IGYiQ1NQOiB7Y3NwWzozMDBdfSIKICAgICAg"
    "ICBhZGQoZnVsbF91cmwsICJXQS1IRFItMzkyIiwgIkhUVFAgU2VjdXJpdHkgSGVhZGVycyIsICJDb250ZW50LVNlY3VyaXR5"
    "LVBvbGljeSBwcmVzZW50IGFuZCBzdHJpY3QiLAogICAgICAgICAgICAiTWVkaXVtIiwgIlAyIiwgIkZBSUwiIGlmIGxvb3Nl"
    "IGVsc2UgIlBBU1MiLCBldmlkZW5jZSArIGN1cmxfYmxvY2spCgogICAgeGZvID0gci5oZWFkZXIoIlgtRnJhbWUtT3B0aW9u"
    "cyIpCiAgICBmcmFtZV9hbmNlc3RvcnMgPSAiZnJhbWUtYW5jZXN0b3JzIiBpbiBjc3AubG93ZXIoKSBpZiBjc3AgZWxzZSBG"
    "YWxzZQogICAgaWYgeGZvIGFuZCB4Zm8uc3RyaXAoKS51cHBlcigpIGluICgiREVOWSIsICJTQU1FT1JJR0lOIik6CiAgICAg"
    "ICAgYWRkKGZ1bGxfdXJsLCAiV0EtSERSLTM5MyIsICJIVFRQIFNlY3VyaXR5IEhlYWRlcnMiLCAiWC1GcmFtZS1PcHRpb25z"
    "OiBTQU1FT1JJR0lOIG9yIERFTlkgcHJlc2VudCIsCiAgICAgICAgICAgICJNZWRpdW0iLCAiUDIiLCAiUEFTUyIsIGYiWC1G"
    "cmFtZS1PcHRpb25zOiB7eGZvfSIgKyBjdXJsX2Jsb2NrKQogICAgZWxpZiBmcmFtZV9hbmNlc3RvcnM6CiAgICAgICAgYWRk"
    "KGZ1bGxfdXJsLCAiV0EtSERSLTM5MyIsICJIVFRQIFNlY3VyaXR5IEhlYWRlcnMiLCAiWC1GcmFtZS1PcHRpb25zOiBTQU1F"
    "T1JJR0lOIG9yIERFTlkgcHJlc2VudCIsCiAgICAgICAgICAgICJNZWRpdW0iLCAiUDIiLCAiUEFTUyIsICJObyBYLUZyYW1l"
    "LU9wdGlvbnMsIGJ1dCBDU1AgZnJhbWUtYW5jZXN0b3JzIGlzIHNldCAoY292ZXJzIG1vZGVybiBicm93c2VycykuIiArIGN1"
    "cmxfYmxvY2spCiAgICBlbHNlOgogICAgICAgIGFkZChmdWxsX3VybCwgIldBLUhEUi0zOTMiLCAiSFRUUCBTZWN1cml0eSBI"
    "ZWFkZXJzIiwgIlgtRnJhbWUtT3B0aW9uczogU0FNRU9SSUdJTiBvciBERU5ZIHByZXNlbnQiLAogICAgICAgICAgICAiTWVk"
    "aXVtIiwgIlAyIiwgIkZBSUwiLAogICAgICAgICAgICBmIkNPTkZJUk1FRCBCWTogWC1GcmFtZS1PcHRpb25zIGhlYWRlciB2"
    "YWx1ZSBpcyAne3hmbyBvciAnKG5vdCBwcmVzZW50IGluIHJlc3BvbnNlIGhlYWRlcnMpJ30nICIKICAgICAgICAgICAgIihl"
    "eHBlY3RlZCBERU5ZIG9yIFNBTUVPUklHSU4pIGFuZCB0aGUgQ1NQIGhhcyBubyBmcmFtZS1hbmNlc3RvcnMgZGlyZWN0aXZl"
    "IGVpdGhlci4iICsgY3VybF9ibG9jaykKCiAgICB4Y3RvID0gci5oZWFkZXIoIlgtQ29udGVudC1UeXBlLU9wdGlvbnMiKQog"
    "ICAgYWRkKGZ1bGxfdXJsLCAiV0EtSERSLTM5NCIsICJIVFRQIFNlY3VyaXR5IEhlYWRlcnMiLCAiWC1Db250ZW50LVR5cGUt"
    "T3B0aW9uczogbm9zbmlmZiBwcmVzZW50IiwKICAgICAgICAiTG93IiwgIlAzIiwgIlBBU1MiIGlmIHhjdG8ubG93ZXIoKSA9"
    "PSAibm9zbmlmZiIgZWxzZSAiRkFJTCIsCiAgICAgICAgKGYiWC1Db250ZW50LVR5cGUtT3B0aW9uczoge3hjdG8gb3IgJ21p"
    "c3NpbmcnfSIgaWYgeGN0by5sb3dlcigpID09ICJub3NuaWZmIiBlbHNlCiAgICAgICAgIGYiQ09ORklSTUVEIEJZOiBYLUNv"
    "bnRlbnQtVHlwZS1PcHRpb25zIGhlYWRlciB2YWx1ZSBpcyAne3hjdG8gb3IgJyhub3QgcHJlc2VudCBpbiByZXNwb25zZSBo"
    "ZWFkZXJzKSd9JyAiCiAgICAgICAgICIoZXhwZWN0ZWQgZXhhY3RseSAnbm9zbmlmZicpLiIpICsgY3VybF9ibG9jaykKCiAg"
    "ICBoc3RzID0gci5oZWFkZXIoIlN0cmljdC1UcmFuc3BvcnQtU2VjdXJpdHkiKQogICAgaWYgZnVsbF91cmwuc3RhcnRzd2l0"
    "aCgiaHR0cHMiKSBhbmQgaHN0czoKICAgICAgICBtID0gcmUuc2VhcmNoKHIibWF4LWFnZT0oXGQrKSIsIGhzdHMpCiAgICAg"
    "ICAgbWF4X2FnZV9vayA9IG0gYW5kIGludChtLmdyb3VwKDEpKSA+PSAxNTU1MjAwMCAgIyAxODAgZGF5cwogICAgICAgIGV2"
    "aWRlbmNlID0gKGYiSFNUUzoge2hzdHN9IiBpZiBtYXhfYWdlX29rIGVsc2UKICAgICAgICAgICAgICAgICAgICBmIkNPTkZJ"
    "Uk1FRCBCWTogU3RyaWN0LVRyYW5zcG9ydC1TZWN1cml0eSBtYXgtYWdlIGlzIHttLmdyb3VwKDEpIGlmIG0gZWxzZSAnbWlz"
    "c2luZy91bnBhcnNlYWJsZSd9ICIKICAgICAgICAgICAgICAgICAgICBmIihyZWNvbW1lbmQgPj0gMTU1NTIwMDApIC0gZnVs"
    "bCBoZWFkZXIgdmFsdWU6IHtoc3RzfSIpCiAgICAgICAgYWRkKGZ1bGxfdXJsLCAiV0EtSERSLTM5NSIsICJIVFRQIFNlY3Vy"
    "aXR5IEhlYWRlcnMiLCAiU3RyaWN0LVRyYW5zcG9ydC1TZWN1cml0eSAoSFNUUykgcHJvcGVybHkgY29uZmlndXJlZCIsCiAg"
    "ICAgICAgICAgICJNZWRpdW0iLCAiUDIiLCAiUEFTUyIgaWYgbWF4X2FnZV9vayBlbHNlICJGQUlMIiwgZXZpZGVuY2UgKyBj"
    "dXJsX2Jsb2NrKQogICAgZWxpZiBmdWxsX3VybC5zdGFydHN3aXRoKCJodHRwcyIpOgogICAgICAgIGFkZChmdWxsX3VybCwg"
    "IldBLUhEUi0zOTUiLCAiSFRUUCBTZWN1cml0eSBIZWFkZXJzIiwgIlN0cmljdC1UcmFuc3BvcnQtU2VjdXJpdHkgKEhTVFMp"
    "IHByb3Blcmx5IGNvbmZpZ3VyZWQiLAogICAgICAgICAgICAiTWVkaXVtIiwgIlAyIiwgIkZBSUwiLAogICAgICAgICAgICAi"
    "Q09ORklSTUVEIEJZOiBubyBTdHJpY3QtVHJhbnNwb3J0LVNlY3VyaXR5IGhlYWRlciBwcmVzZW50IGluIHRoZSByZXNwb25z"
    "ZSBoZWFkZXJzIGJlbG93LCAiCiAgICAgICAgICAgICJvbiBhbiBIVFRQUyByZXNwb25zZS4iICsgY3VybF9ibG9jaykKICAg"
    "IGVsc2U6CiAgICAgICAgYWRkKGZ1bGxfdXJsLCAiV0EtSERSLTM5NSIsICJIVFRQIFNlY3VyaXR5IEhlYWRlcnMiLCAiU3Ry"
    "aWN0LVRyYW5zcG9ydC1TZWN1cml0eSAoSFNUUykgcHJvcGVybHkgY29uZmlndXJlZCIsCiAgICAgICAgICAgICJNZWRpdW0i"
    "LCAiUDIiLCAiSU5GTyIsICJVUkwgaXMgSFRUUCwgbm90IEhUVFBTIC0gSFNUUyBvbmx5IG1lYW5pbmdmdWwgb3ZlciBIVFRQ"
    "Uy4iICsgY3VybF9ibG9jaykKCiAgICByZWZwb2wgPSByLmhlYWRlcigiUmVmZXJyZXItUG9saWN5IikKICAgIGFkZChmdWxs"
    "X3VybCwgIldBLUhEUi0zOTYiLCAiSFRUUCBTZWN1cml0eSBIZWFkZXJzIiwgIlJlZmVycmVyLVBvbGljeSBoZWFkZXIgcHJl"
    "c2VudCIsCiAgICAgICAgIkxvdyIsICJQMyIsICJQQVNTIiBpZiByZWZwb2wgZWxzZSAiRkFJTCIsCiAgICAgICAgKGYiUmVm"
    "ZXJyZXItUG9saWN5OiB7cmVmcG9sfSIgaWYgcmVmcG9sIGVsc2UKICAgICAgICAgIkNPTkZJUk1FRCBCWTogbm8gUmVmZXJy"
    "ZXItUG9saWN5IGhlYWRlciBwcmVzZW50IGluIHRoZSByZXNwb25zZSBoZWFkZXJzIGJlbG93LiIpICsgY3VybF9ibG9jaykK"
    "CiAgICBjYWNoZV9jdHJsID0gci5oZWFkZXIoIkNhY2hlLUNvbnRyb2wiKQogICAgYWRkKGZ1bGxfdXJsLCAiV0EtSERSLTM5"
    "NyIsICJIVFRQIFNlY3VyaXR5IEhlYWRlcnMiLCAiQ2FjaGUtQ29udHJvbDogbm8tc3RvcmUgb24gYXV0aGVudGljYXRlZC9z"
    "ZW5zaXRpdmUgcGFnZXMiLAogICAgICAgICJNZWRpdW0iLCAiUDIiLCAiTUFOVUFMIiwKICAgICAgICBmIkNhY2hlLUNvbnRy"
    "b2wgb24gdGhpcyBwYWdlOiB7Y2FjaGVfY3RybCBvciAnbWlzc2luZyd9LiBBdXRvbWF0ZWQgc2NhbiBjYW4ndCBrbm93IGlm"
    "IHRoaXMgIgogICAgICAgICJzcGVjaWZpYyBwYWdlIGlzIGF1dGhlbnRpY2F0ZWQvc2Vuc2l0aXZlIC0gY29uZmlybSBtYW51"
    "YWxseSBhbmQgY2hlY2sgbm8tc3RvcmUgaXMgc2V0IGlmIHNvLiIgKyBjdXJsX2Jsb2NrKQoKICAgIHBlcm1wb2wgPSByLmhl"
    "YWRlcigiUGVybWlzc2lvbnMtUG9saWN5Iikgb3Igci5oZWFkZXIoIkZlYXR1cmUtUG9saWN5IikKICAgIGFkZChmdWxsX3Vy"
    "bCwgIldBLUhEUi0zOTgiLCAiSFRUUCBTZWN1cml0eSBIZWFkZXJzIiwgIlBlcm1pc3Npb25zLVBvbGljeSByZXN0cmljdHMg"
    "c2Vuc2l0aXZlIGJyb3dzZXIgQVBJcyIsCiAgICAgICAgIkxvdyIsICJQMyIsICJQQVNTIiBpZiBwZXJtcG9sIGVsc2UgIkZB"
    "SUwiLAogICAgICAgIChmIlBlcm1pc3Npb25zLVBvbGljeToge3Blcm1wb2x9IiBpZiBwZXJtcG9sIGVsc2UKICAgICAgICAg"
    "IkNPTkZJUk1FRCBCWTogbm8gUGVybWlzc2lvbnMtUG9saWN5IG9yIEZlYXR1cmUtUG9saWN5IGhlYWRlciBwcmVzZW50IGlu"
    "IHRoZSByZXNwb25zZSBoZWFkZXJzIGJlbG93LiIpICsgY3VybF9ibG9jaykKCiAgICBpZiBmdWxsX3VybC5zdGFydHN3aXRo"
    "KCJodHRwOi8vIik6CiAgICAgICAgcmVkaXJfdGFyZ2V0ID0gZnVsbF91cmwucmVwbGFjZSgiaHR0cDovLyIsICJodHRwczov"
    "LyIsIDEpCiAgICAgICAgcjIgPSByYXdfcmVxdWVzdChmdWxsX3VybCwgIkdFVCIsIHRpbWVvdXQ9YXJncy50aW1lb3V0LCBp"
    "bnNlY3VyZT1hcmdzLmluc2VjdXJlLCBmb2xsb3dfcmVkaXJlY3RzPUZhbHNlKQogICAgICAgIGxvYyA9IHIyLmhlYWRlcigi"
    "TG9jYXRpb24iKQogICAgICAgIHJlZGlyZWN0ZWRfdG9faHR0cHMgPSBib29sKGxvYyBhbmQgbG9jLmxvd2VyKCkuc3RhcnRz"
    "d2l0aCgiaHR0cHMiKSkKICAgICAgICBjdXJsX3Jlc3VsdF8zOTkgPSBOb25lIGlmIGdldGF0dHIoYXJncywgIm5vX2NsaV90"
    "b29scyIsIEZhbHNlKSBlbHNlIHJ1bl9jdXJsX2hlYWRlcnMoCiAgICAgICAgICAgIGZ1bGxfdXJsLCB0aW1lb3V0PWFyZ3Mu"
    "dGltZW91dCwgaW5zZWN1cmU9YXJncy5pbnNlY3VyZSkKICAgICAgICBjdXJsX2Jsb2NrXzM5OSA9IF9mb3JtYXRfY21kX2Js"
    "b2NrKGN1cmxfcmVzdWx0XzM5OVswXSwgY3VybF9yZXN1bHRfMzk5WzFdKSBpZiBjdXJsX3Jlc3VsdF8zOTkgZWxzZSAiIgog"
    "ICAgICAgIGV2aWRlbmNlMzk5ID0gKGYiSFRUUCByZXNwb25zZToge3IyLnN0YXR1c30sIExvY2F0aW9uOiB7bG9jIG9yICdu"
    "b25lJ30uIiBpZiByZWRpcmVjdGVkX3RvX2h0dHBzIGVsc2UKICAgICAgICAgICAgICAgICAgICAgICBmIkNPTkZJUk1FRCBC"
    "WTogcGxhaW4gaHR0cDovLyByZXF1ZXN0IHJldHVybmVkIHN0YXR1cyB7cjIuc3RhdHVzfSB3aXRoICIKICAgICAgICAgICAg"
    "ICAgICAgICAgICBmIkxvY2F0aW9uOiAne2xvYyBvciAnKG5vIExvY2F0aW9uIGhlYWRlciBhdCBhbGwpJ30nIC0gZGlkIG5v"
    "dCByZWRpcmVjdCB0byBhbiBodHRwczovLyBVUkwuIikKICAgICAgICBhZGQoZnVsbF91cmwsICJXQS1IRFItMzk5IiwgIkhU"
    "VFAgU2VjdXJpdHkgSGVhZGVycyIsICJIVFRQUyBlbmZvcmNlZCAtIEhUVFAgcmVkaXJlY3RzIHRvIEhUVFBTIiwKICAgICAg"
    "ICAgICAgIkhpZ2giLCAiUDEiLCAiUEFTUyIgaWYgcmVkaXJlY3RlZF90b19odHRwcyBlbHNlICJGQUlMIiwgZXZpZGVuY2Uz"
    "OTkgKyBjdXJsX2Jsb2NrXzM5OSkKICAgIGVsc2U6CiAgICAgICAgYWRkKGZ1bGxfdXJsLCAiV0EtSERSLTM5OSIsICJIVFRQ"
    "IFNlY3VyaXR5IEhlYWRlcnMiLCAiSFRUUFMgZW5mb3JjZWQgLSBIVFRQIHJlZGlyZWN0cyB0byBIVFRQUyIsCiAgICAgICAg"
    "ICAgICJIaWdoIiwgIlAxIiwgIklORk8iLCAiVVJMIGdpdmVuIHdhcyBhbHJlYWR5IEhUVFBTIC0gcmUtcnVuIHdpdGggdGhl"
    "IGh0dHA6Ly8gdmVyc2lvbiB0byB0ZXN0IHRoZSByZWRpcmVjdC4iKQoKICAgIGJhc2UgPSBkaXJfb2YoZnVsbF91cmwpCiAg"
    "ICBwcm9iZV9wYXRoID0gam9pbl90YXJnZXQoYmFzZSwgIi90aGlzLXBhdGgtc2hvdWxkLW5vdC1leGlzdC0iICsgcmFuZF90"
    "b2tlbigpKQogICAgcjQwNCA9IHJhd19yZXF1ZXN0KHByb2JlX3BhdGgsICJHRVQiLCB0aW1lb3V0PWFyZ3MudGltZW91dCwg"
    "aW5zZWN1cmU9YXJncy5pbnNlY3VyZSkKICAgIHRyYWNlX2ZvdW5kID0gTm9uZQogICAgdHJhY2Vfc25pcHBldCA9ICIiCiAg"
    "ICBpZiBub3QgcjQwNC5lcnJvcjoKICAgICAgICBib2R5X3RleHQgPSByNDA0LnRleHQoKQogICAgICAgIGZvciBwYXQgaW4g"
    "U1RBQ0tfVFJBQ0VfUEFUVEVSTlM6CiAgICAgICAgICAgIG00MDQgPSByZS5zZWFyY2gocGF0LCBib2R5X3RleHQsIHJlLklH"
    "Tk9SRUNBU0UpCiAgICAgICAgICAgIGlmIG00MDQ6CiAgICAgICAgICAgICAgICB0cmFjZV9mb3VuZCA9IHBhdAogICAgICAg"
    "ICAgICAgICAgc3RhcnQgPSBtYXgobTQwNC5zdGFydCgpIC0gNDAsIDApCiAgICAgICAgICAgICAgICB0cmFjZV9zbmlwcGV0"
    "ID0gYm9keV90ZXh0W3N0YXJ0Om00MDQuZW5kKCkgKyA2MF0ucmVwbGFjZSgiXG4iLCAiICIpLnN0cmlwKCkKICAgICAgICAg"
    "ICAgICAgIGJyZWFrCiAgICBhZGQoZnVsbF91cmwsICJXQS1IRFItNDAwIiwgIkhUVFAgU2VjdXJpdHkgSGVhZGVycyIsICJW"
    "ZXJib3NlIGVycm9yIG1lc3NhZ2VzIC8gc3RhY2sgdHJhY2VzIG9uIDR4eC81eHgiLAogICAgICAgICJNZWRpdW0iLCAiUDIi"
    "LCAiRkFJTCIgaWYgdHJhY2VfZm91bmQgZWxzZSAoIkVSUk9SIiBpZiByNDA0LmVycm9yIGVsc2UgIlBBU1MiKSwKICAgICAg"
    "ICAoZiJDT05GSVJNRUQgQlk6IHJlc3BvbnNlIGJvZHkgZm9yIHRoZSA0MDQgcHJvYmUgKHtwcm9iZV9wYXRofSkgbWF0Y2hl"
    "ZCBrbm93biBlcnJvci1kaXNjbG9zdXJlIHBhdHRlcm4gIgogICAgICAgICBmIid7dHJhY2VfZm91bmR9JyAtIGV4Y2VycHQg"
    "YXJvdW5kIHRoZSBtYXRjaDogXCIuLi57dHJhY2Vfc25pcHBldH0uLi5cIiIgaWYgdHJhY2VfZm91bmQgZWxzZQogICAgICAg"
    "ICAocjQwNC5lcnJvciBvciBmIk5vIGtub3duIHN0YWNrLXRyYWNlIHBhdHRlcm4gZm91bmQgb24gNDA0IHByb2JlIChzdGF0"
    "dXMge3I0MDQuc3RhdHVzfSkuIikpKQoKICAgIHNlcnZlcl9oZHIgPSByLmhlYWRlcigiU2VydmVyIikKICAgIHhwYl9oZHIg"
    "PSByLmhlYWRlcigiWC1Qb3dlcmVkLUJ5IikKICAgIHNlcnZlcl9tYXRjaCA9IHJlLnNlYXJjaChyIlxkK1wuXGQrIiwgc2Vy"
    "dmVyX2hkcikgaWYgc2VydmVyX2hkciBlbHNlIE5vbmUKICAgIHhwYl9tYXRjaCA9IHJlLnNlYXJjaChyIlxkK1wuXGQrIiwg"
    "eHBiX2hkcikgaWYgeHBiX2hkciBlbHNlIE5vbmUKICAgIHZlcnNpb25fbGVhayA9IGJvb2woc2VydmVyX21hdGNoIG9yIHhw"
    "Yl9tYXRjaCkKICAgIGlmIHZlcnNpb25fbGVhazoKICAgICAgICB3aGljaCA9IFtdCiAgICAgICAgaWYgc2VydmVyX21hdGNo"
    "OgogICAgICAgICAgICB3aGljaC5hcHBlbmQoZiJTZXJ2ZXI6ICd7c2VydmVyX2hkcn0nICh2ZXJzaW9uLWxvb2tpbmcgc3Vi"
    "c3RyaW5nOiAne3NlcnZlcl9tYXRjaC5ncm91cCgwKX0nKSIpCiAgICAgICAgaWYgeHBiX21hdGNoOgogICAgICAgICAgICB3"
    "aGljaC5hcHBlbmQoZiJYLVBvd2VyZWQtQnk6ICd7eHBiX2hkcn0nICh2ZXJzaW9uLWxvb2tpbmcgc3Vic3RyaW5nOiAne3hw"
    "Yl9tYXRjaC5ncm91cCgwKX0nKSIpCiAgICAgICAgZXZpZGVuY2U0MDEgPSAiQ09ORklSTUVEIEJZOiAiICsgIjsgIi5qb2lu"
    "KHdoaWNoKQogICAgZWxzZToKICAgICAgICBldmlkZW5jZTQwMSA9IGYiU2VydmVyOiB7c2VydmVyX2hkciBvciAnbm9uZSd9"
    "LCBYLVBvd2VyZWQtQnk6IHt4cGJfaGRyIG9yICdub25lJ30iCiAgICBhZGQoZnVsbF91cmwsICJXQS1IRFItNDAxIiwgIkhU"
    "VFAgU2VjdXJpdHkgSGVhZGVycyIsICJTZXJ2ZXIgdmVyc2lvbiBkaXNjbG9zdXJlIGluIHJlc3BvbnNlIGhlYWRlcnMiLAog"
    "ICAgICAgICJMb3ciLCAiUDMiLCAiRkFJTCIgaWYgdmVyc2lvbl9sZWFrIGVsc2UgIlBBU1MiLCBldmlkZW5jZTQwMSArIGN1"
    "cmxfYmxvY2spCgogICAgcmV0dXJuIHIsIGN1cmxfYmxvY2sKCgojIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t"
    "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiMgMi4gU1NMIC8gVExTIC0gV0EtVExTLTQwMi4u"
    "NDA5IChiZXN0LWVmZm9ydDsgc2V2ZXJhbCBhcmUgTUFOVUFMIGJ5IGRlc2lnbiwKIyAgICBzZWUgbW9kdWxlIGRvY3N0cmlu"
    "ZyAtIGEgcmVhbCBncmFkZSBuZWVkcyB0ZXN0c3NsLnNoL3NzbHl6ZS9TU0wgTGFicykKIyAtLS0tLS0tLS0tLS0tLS0tLS0t"
    "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQoKZGVmIF9vcGVuc3NsX2F2"
    "YWlsYWJsZSgpOgogICAgdHJ5OgogICAgICAgIHN1YnByb2Nlc3MucnVuKFsib3BlbnNzbCIsICJ2ZXJzaW9uIl0sIGNhcHR1"
    "cmVfb3V0cHV0PVRydWUsIHRpbWVvdXQ9NSkKICAgICAgICByZXR1cm4gVHJ1ZQogICAgZXhjZXB0IEV4Y2VwdGlvbjoKICAg"
    "ICAgICByZXR1cm4gRmFsc2UKCgpkZWYgY2hlY2tfdGxzKGZ1bGxfdXJsLCBhcmdzKToKICAgIHAgPSB1cmxwYXJzZShmdWxs"
    "X3VybCkKICAgIGlmIHAuc2NoZW1lICE9ICJodHRwcyI6CiAgICAgICAgZm9yIGNpZCwgbmFtZSwgc2V2LCBwcmkgaW4gWwog"
    "ICAgICAgICAgICAoIldBLVRMUy00MDIiLCAiU1NML1RMUyBzY2FuIC0gZ3JhZGUgYW5kIGNpcGhlciBzdHJlbmd0aCIsICJI"
    "aWdoIiwgIlAxIiksCiAgICAgICAgICAgICgiV0EtVExTLTQwMyIsICJTU0x2MiwgU1NMdjMsIFRMU3YxLjAgZGlzYWJsZWQi"
    "LCAiSGlnaCIsICJQMSIpLAogICAgICAgICAgICAoIldBLVRMUy00MDQiLCAiTm8gd2VhayBjaXBoZXIgc3VpdGVzIChSQzQs"
    "IERFUywgTlVMTCwgRVhQT1JUKSIsICJIaWdoIiwgIlAxIiksCiAgICAgICAgICAgICgiV0EtVExTLTQwNSIsICJDZXJ0aWZp"
    "Y2F0ZSBrZXkgc3RyZW5ndGggPj0gMjA0OC1iaXQgUlNBIC8gMjU2LWJpdCBFQ0MiLCAiTWVkaXVtIiwgIlAyIiksCiAgICAg"
    "ICAgICAgICgiV0EtVExTLTQwNiIsICJDZXJ0aWZpY2F0ZSB1c2VzIFNIQS0yNTYrIHNpZ25hdHVyZSBhbGdvcml0aG0iLCAi"
    "TWVkaXVtIiwgIlAyIiksCiAgICAgICAgICAgICgiV0EtVExTLTQwNyIsICJDZXJ0aWZpY2F0ZSBjaGFpbiBjb21wbGV0ZSAt"
    "IG5vIG1pc3NpbmcgaW50ZXJtZWRpYXRlcyIsICJNZWRpdW0iLCAiUDIiKSwKICAgICAgICAgICAgKCJXQS1UTFMtNDA4Iiwg"
    "IkhTVFMgcHJlbG9hZCBsaXN0IGNvbmZpZ3VyZWQiLCAiTWVkaXVtIiwgIlAyIiksCiAgICAgICAgICAgICgiV0EtVExTLTQw"
    "OSIsICJXZWJTb2NrZXQgZW5kcG9pbnRzIHVzZSBXU1Mgbm90IFdTIiwgIkhpZ2giLCAiUDEiKSwKICAgICAgICBdOgogICAg"
    "ICAgICAgICBhZGQoZnVsbF91cmwsIGNpZCwgIlNTTCAvIFRMUyIsIG5hbWUsIHNldiwgcHJpLCAiSU5GTyIsICJVUkwgaXMg"
    "bm90IEhUVFBTIC0gVExTIGNoZWNrcyBza2lwcGVkLiIpCiAgICAgICAgcmV0dXJuCgogICAgaG9zdCA9IHAuaG9zdG5hbWUK"
    "ICAgIHBvcnQgPSBwLnBvcnQgb3IgNDQzCgogICAgc3NsX2NsaSA9IE5vbmUgaWYgZ2V0YXR0cihhcmdzLCAibm9fY2xpX3Rv"
    "b2xzIiwgRmFsc2UpIGVsc2UgcnVuX3NzbF9jbGlfc2NhbigKICAgICAgICBob3N0LCBwb3J0LCB0aW1lb3V0PW1heChhcmdz"
    "LnRpbWVvdXQsIDQ1KSkKICAgIGlmIHNzbF9jbGk6CiAgICAgICAgc3NsX3Rvb2wsIHNzbF9jbWQsIHNzbF9vdXRwdXQgPSBz"
    "c2xfY2xpCiAgICAgICAgc3NsX2Jsb2NrID0gX2Zvcm1hdF9jbWRfYmxvY2soc3NsX2NtZCwgc3NsX291dHB1dCkKICAgICAg"
    "ICBwYXJzZWQgPSBfcGFyc2Vfc3NsX2NsaV9vdXRwdXQoc3NsX291dHB1dCkKICAgICAgICB3ZWFrX2NpcGhlcnMgPSBwYXJz"
    "ZWRbIndlYWtfY2lwaGVycyJdCiAgICAgICAgbGVhc3Rfc3RyZW5ndGggPSBwYXJzZWRbImxlYXN0X3N0cmVuZ3RoIl0KICAg"
    "ICAgICByYW5fYnV0X2VtcHR5ID0gbm90IHNzbF9vdXRwdXQuc3RyaXAoKSBvciBzc2xfb3V0cHV0Lmxvd2VyKCkuc3RhcnRz"
    "d2l0aCgiKCIpCgogICAgICAgIGlmIGxlYXN0X3N0cmVuZ3RoOgogICAgICAgICAgICBncmFkZV9yZXN1bHQgPSAiRkFJTCIg"
    "aWYgbGVhc3Rfc3RyZW5ndGgubG93ZXIoKSBpbiAoIndlYWsiLCAiaW5zZWN1cmUiKSBlbHNlICJQQVNTIgogICAgICAgICAg"
    "ICBncmFkZV9ldmlkZW5jZSA9IGYie3NzbF90b29sfSBsZWFzdCBjaXBoZXIgc3RyZW5ndGg6IHtsZWFzdF9zdHJlbmd0aH0u"
    "IgogICAgICAgIGVsaWYgd2Vha19jaXBoZXJzOgogICAgICAgICAgICBncmFkZV9yZXN1bHQgPSAiRkFJTCIKICAgICAgICAg"
    "ICAgZ3JhZGVfZXZpZGVuY2UgPSBmIntzc2xfdG9vbH0gb3V0cHV0IGZsYWdzIHdlYWsgY2lwaGVyIGluZGljYXRvcihzKTog"
    "eycsICcuam9pbih3ZWFrX2NpcGhlcnMpfS4iCiAgICAgICAgZWxpZiByYW5fYnV0X2VtcHR5OgogICAgICAgICAgICBncmFk"
    "ZV9yZXN1bHQgPSAiSU5GTyIKICAgICAgICAgICAgZ3JhZGVfZXZpZGVuY2UgPSBmIntzc2xfdG9vbH0gcmFuIGJ1dCBwcm9k"
    "dWNlZCBubyBjb25jbHVzaXZlIGNpcGhlci1zdHJlbmd0aCBvdXRwdXQgLSByZXZpZXcgcmF3IG91dHB1dCBiZWxvdy4iCiAg"
    "ICAgICAgZWxzZToKICAgICAgICAgICAgZ3JhZGVfcmVzdWx0ID0gIlBBU1MiCiAgICAgICAgICAgIGdyYWRlX2V2aWRlbmNl"
    "ID0gZiJ7c3NsX3Rvb2x9IHJhbiBhbmQgZm91bmQgbm8gd2Vhay1jaXBoZXIgaW5kaWNhdG9ycyBpbiBpdHMgb3V0cHV0IC0g"
    "cmV2aWV3IHJhdyBvdXRwdXQgYmVsb3cgdG8gY29uZmlybS4iCiAgICAgICAgYWRkKGZ1bGxfdXJsLCAiV0EtVExTLTQwMiIs"
    "ICJTU0wgLyBUTFMiLCAiU1NML1RMUyBzY2FuIC0gZ3JhZGUgYW5kIGNpcGhlciBzdHJlbmd0aCIsCiAgICAgICAgICAgICJI"
    "aWdoIiwgIlAxIiwgZ3JhZGVfcmVzdWx0LCBncmFkZV9ldmlkZW5jZSArIHNzbF9ibG9jaykKCiAgICAgICAgY2lwaGVyX3Jl"
    "c3VsdCA9ICJGQUlMIiBpZiB3ZWFrX2NpcGhlcnMgZWxzZSAoIklORk8iIGlmIHJhbl9idXRfZW1wdHkgZWxzZSAiUEFTUyIp"
    "CiAgICAgICAgY2lwaGVyX2V2aWRlbmNlID0gKGYiV2VhayBjaXBoZXIgaW5kaWNhdG9yKHMpIGZvdW5kIGJ5IHtzc2xfdG9v"
    "bH06IHsnLCAnLmpvaW4od2Vha19jaXBoZXJzKX0uIgogICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgd2Vha19jaXBo"
    "ZXJzIGVsc2UgZiJObyBSQzQvREVTLzNERVMvTlVMTC9FWFBPUlQvTUQ1L2Fub24gaW5kaWNhdG9ycyBmb3VuZCBpbiB7c3Ns"
    "X3Rvb2x9IG91dHB1dC4iKQogICAgICAgIGFkZChmdWxsX3VybCwgIldBLVRMUy00MDQiLCAiU1NMIC8gVExTIiwgIk5vIHdl"
    "YWsgY2lwaGVyIHN1aXRlcyAoUkM0LCBERVMsIE5VTEwsIEVYUE9SVCkiLAogICAgICAgICAgICAiSGlnaCIsICJQMSIsIGNp"
    "cGhlcl9yZXN1bHQsIGNpcGhlcl9ldmlkZW5jZSArIHNzbF9ibG9jaykKICAgIGVsc2U6CiAgICAgICAgYWRkKGZ1bGxfdXJs"
    "LCAiV0EtVExTLTQwMiIsICJTU0wgLyBUTFMiLCAiU1NML1RMUyBzY2FuIC0gZ3JhZGUgYW5kIGNpcGhlciBzdHJlbmd0aCIs"
    "CiAgICAgICAgICAgICJIaWdoIiwgIlAxIiwgIk1BTlVBTCIsCiAgICAgICAgICAgIGYiTm8gU1NMIENMSSBzY2FubmVyIChu"
    "bWFwL3NzbHl6ZS9zc2xzY2FuL3Rlc3Rzc2wuc2gpIGZvdW5kIG9uIFBBVEguIEEgcmVhbCBBLUYgZ3JhZGUgbmVlZHMgb25l"
    "IC0gcnVuOiAiCiAgICAgICAgICAgIGYibm1hcCAtLXNjcmlwdCBzc2wtZW51bS1jaXBoZXJzIC1wIHtwb3J0fSB7aG9zdH0g"
    "IE9SICB0ZXN0c3NsLnNoIHtob3N0fTp7cG9ydH0gIE9SIGNoZWNrICIKICAgICAgICAgICAgZiJodHRwczovL3d3dy5zc2xs"
    "YWJzLmNvbS9zc2x0ZXN0L2FuYWx5emUuaHRtbD9kPXtob3N0fSIpCiAgICAgICAgYWRkKGZ1bGxfdXJsLCAiV0EtVExTLTQw"
    "NCIsICJTU0wgLyBUTFMiLCAiTm8gd2VhayBjaXBoZXIgc3VpdGVzIChSQzQsIERFUywgTlVMTCwgRVhQT1JUKSIsCiAgICAg"
    "ICAgICAgICJIaWdoIiwgIlAxIiwgIk1BTlVBTCIsCiAgICAgICAgICAgIGYiTm8gU1NMIENMSSBzY2FubmVyIGZvdW5kIG9u"
    "IFBBVEguIFJ1bjogbm1hcCAtLXNjcmlwdCBzc2wtZW51bS1jaXBoZXJzIC1wIHtwb3J0fSB7aG9zdH0gIE9SICB0ZXN0c3Ns"
    "LnNoIHtob3N0fTp7cG9ydH0iKQoKICAgIG9sZF9wcm90b2NvbHMgPSB7fQogICAgZm9yIG5hbWUsIHZlciBpbiBbKCJTU0x2"
    "MyIsIGdldGF0dHIoc3NsLlRMU1ZlcnNpb24sICJTU0x2MyIsIE5vbmUpKSwKICAgICAgICAgICAgICAgICAgICAgICAoIlRM"
    "U3YxLjAiLCBzc2wuVExTVmVyc2lvbi5UTFN2MSksCiAgICAgICAgICAgICAgICAgICAgICAgKCJUTFN2MS4xIiwgc3NsLlRM"
    "U1ZlcnNpb24uVExTdjFfMSldOgogICAgICAgIGlmIHZlciBpcyBOb25lOgogICAgICAgICAgICBvbGRfcHJvdG9jb2xzW25h"
    "bWVdID0gIm5vdCBzdXBwb3J0ZWQgYnkgbG9jYWwgT3BlblNTTCBidWlsZCAtIGNhbid0IHRlc3QiCiAgICAgICAgICAgIGNv"
    "bnRpbnVlCiAgICAgICAgdHJ5OgogICAgICAgICAgICBjdHggPSBzc2wuU1NMQ29udGV4dChzc2wuUFJPVE9DT0xfVExTX0NM"
    "SUVOVCkKICAgICAgICAgICAgY3R4LmNoZWNrX2hvc3RuYW1lID0gRmFsc2UKICAgICAgICAgICAgY3R4LnZlcmlmeV9tb2Rl"
    "ID0gc3NsLkNFUlRfTk9ORQogICAgICAgICAgICAjIERlbGliZXJhdGVseSBzZXR0aW5nIG1pbi9tYXggdmVyc2lvbiB0byBT"
    "U0x2My9UTFN2MS4wL1RMU3YxLjEKICAgICAgICAgICAgIyBpcyBleGFjdGx5IHdoYXQgdGhpcyBwcm9iZSBuZWVkcyAod2Ug"
    "V0FOVCB0byB0cnkgY29ubmVjdGluZwogICAgICAgICAgICAjIHdpdGggdGhlIG9sZCwgd2VhayBwcm90b2NvbCB0byBzZWUg"
    "aWYgdGhlIHNlcnZlciBzdGlsbAogICAgICAgICAgICAjIGFjY2VwdHMgaXQpIC0gYnV0IHJlY2VudCBQeXRob24vT3BlblNT"
    "TCBidWlsZHMgcmFpc2UgYQogICAgICAgICAgICAjIERlcHJlY2F0aW9uV2FybmluZyBvbiB0aGUgYXNzaWdubWVudCBpdHNl"
    "bGYganVzdCBmb3IKICAgICAgICAgICAgIyByZWZlcmVuY2luZyBzc2wuVExTVmVyc2lvbi5TU0x2MyBhdCBhbGwuIFRoYXQn"
    "cyBhIHdhcm5pbmcKICAgICAgICAgICAgIyBhYm91dCBPVVIgdXNlIG9mIGEgZGVwcmVjYXRlZCBQeXRob24gQVBJLCBub3Qg"
    "YSBmaW5kaW5nCiAgICAgICAgICAgICMgYWJvdXQgdGhlIHNjYW5uZWQgdGFyZ2V0IC0gc3VwcHJlc3NlZCBoZXJlIHNvIGl0"
    "IGRvZXNuJ3QgZ2V0CiAgICAgICAgICAgICMgbWlzdGFrZW4gZm9yIG9uZSAoYXNrZWQgZGlyZWN0bHk6ICJpbiBweXRob24g"
    "aSBjYW4gc2VlCiAgICAgICAgICAgICMgZGVwcmVjYXRpb24gd2FybmluZyAuLi4gaXMgdGlzIGlzIGZpbmRpbmdzIG9yIHdh"
    "cm5pbmc/IikuCiAgICAgICAgICAgIHdpdGggd2FybmluZ3MuY2F0Y2hfd2FybmluZ3MoKToKICAgICAgICAgICAgICAgIHdh"
    "cm5pbmdzLnNpbXBsZWZpbHRlcigiaWdub3JlIiwgRGVwcmVjYXRpb25XYXJuaW5nKQogICAgICAgICAgICAgICAgY3R4Lm1p"
    "bmltdW1fdmVyc2lvbiA9IHZlcgogICAgICAgICAgICAgICAgY3R4Lm1heGltdW1fdmVyc2lvbiA9IHZlcgogICAgICAgICAg"
    "ICB3aXRoIHNvY2tldC5jcmVhdGVfY29ubmVjdGlvbigoaG9zdCwgcG9ydCksIHRpbWVvdXQ9YXJncy50aW1lb3V0KSBhcyBz"
    "b2NrOgogICAgICAgICAgICAgICAgd2l0aCBjdHgud3JhcF9zb2NrZXQoc29jaywgc2VydmVyX2hvc3RuYW1lPWhvc3QpIGFz"
    "IHNzb2NrOgogICAgICAgICAgICAgICAgICAgIHNzb2NrLnZlcnNpb24oKQogICAgICAgICAgICBvbGRfcHJvdG9jb2xzW25h"
    "bWVdID0gIkFDQ0VQVEVEIGJ5IHNlcnZlciAod2VhaykiCiAgICAgICAgZXhjZXB0IHNzbC5TU0xFcnJvcjoKICAgICAgICAg"
    "ICAgb2xkX3Byb3RvY29sc1tuYW1lXSA9ICJyZWplY3RlZCBieSBzZXJ2ZXIgKGdvb2QpIgogICAgICAgIGV4Y2VwdCBWYWx1"
    "ZUVycm9yOgogICAgICAgICAgICBvbGRfcHJvdG9jb2xzW25hbWVdID0gIm5vdCBzdXBwb3J0ZWQgYnkgbG9jYWwgT3BlblNT"
    "TCBidWlsZCAtIGNhbid0IHRlc3QiCiAgICAgICAgZXhjZXB0IEV4Y2VwdGlvbiBhcyBlOgogICAgICAgICAgICBvbGRfcHJv"
    "dG9jb2xzW25hbWVdID0gZiJjb3VsZCBub3QgdGVzdCAoe2V9KSIKCiAgICBhbnlfYWNjZXB0ZWQgPSBhbnkoIkFDQ0VQVEVE"
    "IiBpbiB2IGZvciB2IGluIG9sZF9wcm90b2NvbHMudmFsdWVzKCkpCiAgICBhbnlfdW50ZXN0YWJsZSA9IGFueSgiY2FuJ3Qg"
    "dGVzdCIgaW4gdiBmb3IgdiBpbiBvbGRfcHJvdG9jb2xzLnZhbHVlcygpKQogICAgcmVzdWx0ID0gIkZBSUwiIGlmIGFueV9h"
    "Y2NlcHRlZCBlbHNlICgiSU5GTyIgaWYgYW55X3VudGVzdGFibGUgYW5kIG5vdCBhbnlfYWNjZXB0ZWQgZWxzZSAiUEFTUyIp"
    "CiAgICBhZGQoZnVsbF91cmwsICJXQS1UTFMtNDAzIiwgIlNTTCAvIFRMUyIsICJTU0x2MiwgU1NMdjMsIFRMU3YxLjAgZGlz"
    "YWJsZWQiLAogICAgICAgICJIaWdoIiwgIlAxIiwgcmVzdWx0LCAiOyAiLmpvaW4oZiJ7a306IHt2fSIgZm9yIGssIHYgaW4g"
    "b2xkX3Byb3RvY29scy5pdGVtcygpKSkKCiAgICAjIE5PVEU6IFdBLVRMUy00MDQgKHdlYWsgY2lwaGVyIHN1aXRlcykgaXMg"
    "YWxyZWFkeSBmdWxseSBoYW5kbGVkIGFib3ZlLAogICAgIyBpbnNpZGUgdGhlIGBpZiBzc2xfY2xpOiAuLi4gZWxzZTogLi4u"
    "YCBibG9jayByaWdodCBhZnRlcgogICAgIyBydW5fc3NsX2NsaV9zY2FuKCkgLSBlaXRoZXIgYSByZWFsIFBBU1MvRkFJTC9J"
    "TkZPIGZyb20gd2hpY2hldmVyIFNTTAogICAgIyBDTEkgdG9vbCByYW4sIG9yIGEgTUFOVUFMIGZhbGxiYWNrIHdpdGggdGhl"
    "IGV4YWN0IGNvbW1hbmQgdG8gcnVuIGlmCiAgICAjIG5vbmUgaXMgaW5zdGFsbGVkLiBBIHNlY29uZCwgdW5jb25kaXRpb25h"
    "bCBhZGQoLi4uLCAiV0EtVExTLTQwNCIsCiAgICAjIC4uLiwgIk1BTlVBTCIsIC4uLikgdXNlZCB0byBzaXQgcmlnaHQgaGVy"
    "ZSBhbmQgc2lsZW50bHkgT1ZFUldSSVRFCiAgICAjIHRoYXQgcmVhbCByZXN1bHQgZXZlcnkgc2luZ2xlIHRpbWUgKFJFU1VM"
    "VFMgaXMgYW4gYXBwZW5kLW9ubHkgbGlzdCAtCiAgICAjIHNlZSBhZGQoKSdzIG93biBkZWZpbml0aW9uIC0gc28gdGhpcyBy"
    "YW4gcmVnYXJkbGVzcyBvZiB3aGV0aGVyIHRoZQogICAgIyBibG9jayBhYm92ZSBhbHJlYWR5IHByb2R1Y2VkIGEgcmVhbCBQ"
    "QVNTL0ZBSUwpLCBtZWFuaW5nIFdBLVRMUy00MDQKICAgICMgY291bGQgbmV2ZXIgc2hvdyBhbnl0aGluZyBidXQgTUFOVUFM"
    "IGV2ZW4gd2hlbiBubWFwL3NzbHl6ZS9zc2xzY2FuLwogICAgIyB0ZXN0c3NsLnNoIHdhcyBpbnN0YWxsZWQgYW5kIHJhbiBz"
    "dWNjZXNzZnVsbHkuIFJlbW92ZWQuCgogICAgY2VydF90ZXh0ID0gTm9uZQogICAgaWYgX29wZW5zc2xfYXZhaWxhYmxlKCk6"
    "CiAgICAgICAgdHJ5OgogICAgICAgICAgICBzX2NsaWVudCA9IHN1YnByb2Nlc3MucnVuKAogICAgICAgICAgICAgICAgWyJv"
    "cGVuc3NsIiwgInNfY2xpZW50IiwgIi1jb25uZWN0IiwgZiJ7aG9zdH06e3BvcnR9IiwgIi1zZXJ2ZXJuYW1lIiwgaG9zdF0s"
    "CiAgICAgICAgICAgICAgICBpbnB1dD1iIiIsIGNhcHR1cmVfb3V0cHV0PVRydWUsIHRpbWVvdXQ9YXJncy50aW1lb3V0KQog"
    "ICAgICAgICAgICBwZW0gPSBzX2NsaWVudC5zdGRvdXQKICAgICAgICAgICAgeDUwOSA9IHN1YnByb2Nlc3MucnVuKFsib3Bl"
    "bnNzbCIsICJ4NTA5IiwgIi1ub291dCIsICItdGV4dCJdLCBpbnB1dD1wZW0sCiAgICAgICAgICAgICAgICAgICAgICAgICAg"
    "ICAgICAgICAgY2FwdHVyZV9vdXRwdXQ9VHJ1ZSwgdGltZW91dD1hcmdzLnRpbWVvdXQpCiAgICAgICAgICAgIGNlcnRfdGV4"
    "dCA9IHg1MDkuc3Rkb3V0LmRlY29kZSgidXRmLTgiLCBlcnJvcnM9InJlcGxhY2UiKQogICAgICAgIGV4Y2VwdCBFeGNlcHRp"
    "b246CiAgICAgICAgICAgIGNlcnRfdGV4dCA9IE5vbmUKCiAgICBpZiBjZXJ0X3RleHQ6CiAgICAgICAga20gPSByZS5zZWFy"
    "Y2gociJQdWJsaWMtS2V5OlxzKlwoKFxkKylccypiaXRcKSIsIGNlcnRfdGV4dCkKICAgICAgICBrZXlfYml0cyA9IGludChr"
    "bS5ncm91cCgxKSkgaWYga20gZWxzZSBOb25lCiAgICAgICAgaXNfZWMgPSAiaWQtZWNQdWJsaWNLZXkiIGluIGNlcnRfdGV4"
    "dCBvciAiRUNEU0EiIGluIGNlcnRfdGV4dAogICAgICAgIG1pbl9vayA9IChrZXlfYml0cyBhbmQgKChpc19lYyBhbmQga2V5"
    "X2JpdHMgPj0gMjU2KSBvciAobm90IGlzX2VjIGFuZCBrZXlfYml0cyA+PSAyMDQ4KSkpCiAgICAgICAgYWRkKGZ1bGxfdXJs"
    "LCAiV0EtVExTLTQwNSIsICJTU0wgLyBUTFMiLCAiQ2VydGlmaWNhdGUga2V5IHN0cmVuZ3RoID49IDIwNDgtYml0IFJTQSAv"
    "IDI1Ni1iaXQgRUNDIiwKICAgICAgICAgICAgIk1lZGl1bSIsICJQMiIsICJQQVNTIiBpZiBtaW5fb2sgZWxzZSAiRkFJTCIs"
    "CiAgICAgICAgICAgIGYiS2V5IHR5cGU6IHsnRUMnIGlmIGlzX2VjIGVsc2UgJ1JTQS9vdGhlcid9LCBzaXplOiB7a2V5X2Jp"
    "dHMgb3IgJ3Vua25vd24nfSBiaXRzIikKCiAgICAgICAgc2lnbSA9IHJlLnNlYXJjaChyIlNpZ25hdHVyZSBBbGdvcml0aG06"
    "XHMqKFxTKykiLCBjZXJ0X3RleHQpCiAgICAgICAgc2lnX2FsZyA9IHNpZ20uZ3JvdXAoMSkgaWYgc2lnbSBlbHNlICJ1bmtu"
    "b3duIgogICAgICAgIHdlYWtfc2lnID0gYW55KHcgaW4gc2lnX2FsZy5sb3dlcigpIGZvciB3IGluIFsibWQ1IiwgInNoYTEi"
    "XSkKICAgICAgICBhZGQoZnVsbF91cmwsICJXQS1UTFMtNDA2IiwgIlNTTCAvIFRMUyIsICJDZXJ0aWZpY2F0ZSB1c2VzIFNI"
    "QS0yNTYrIHNpZ25hdHVyZSBhbGdvcml0aG0iLAogICAgICAgICAgICAiTWVkaXVtIiwgIlAyIiwgIkZBSUwiIGlmIHdlYWtf"
    "c2lnIGVsc2UgIlBBU1MiLCBmIlNpZ25hdHVyZSBBbGdvcml0aG06IHtzaWdfYWxnfSIpCiAgICBlbHNlOgogICAgICAgIGZv"
    "ciBjaWQsIG5hbWUgaW4gWygiV0EtVExTLTQwNSIsICJDZXJ0aWZpY2F0ZSBrZXkgc3RyZW5ndGggPj0gMjA0OC1iaXQgUlNB"
    "IC8gMjU2LWJpdCBFQ0MiKSwKICAgICAgICAgICAgICAgICAgICAgICAgICAgKCJXQS1UTFMtNDA2IiwgIkNlcnRpZmljYXRl"
    "IHVzZXMgU0hBLTI1Nisgc2lnbmF0dXJlIGFsZ29yaXRobSIpXToKICAgICAgICAgICAgYWRkKGZ1bGxfdXJsLCBjaWQsICJT"
    "U0wgLyBUTFMiLCBuYW1lLCAiTWVkaXVtIiwgIlAyIiwgIklORk8iLAogICAgICAgICAgICAgICAgIkxvY2FsICdvcGVuc3Ns"
    "JyBDTEkgbm90IGF2YWlsYWJsZS9mYWlsZWQgLSBjYW4ndCBwYXJzZSBjZXJ0aWZpY2F0ZSBkZXRhaWxzLiAiCiAgICAgICAg"
    "ICAgICAgICBmIlJ1biBtYW51YWxseTogb3BlbnNzbCBzX2NsaWVudCAtY29ubmVjdCB7aG9zdH06e3BvcnR9IC1zZXJ2ZXJu"
    "YW1lIHtob3N0fSB8IG9wZW5zc2wgeDUwOSAtbm9vdXQgLXRleHQiKQoKICAgIHRyeToKICAgICAgICBjdHggPSBzc2wuY3Jl"
    "YXRlX2RlZmF1bHRfY29udGV4dCgpCiAgICAgICAgaWYgYXJncy5pbnNlY3VyZToKICAgICAgICAgICAgY3R4LmNoZWNrX2hv"
    "c3RuYW1lID0gRmFsc2UKICAgICAgICAgICAgY3R4LnZlcmlmeV9tb2RlID0gc3NsLkNFUlRfTk9ORQogICAgICAgIHdpdGgg"
    "c29ja2V0LmNyZWF0ZV9jb25uZWN0aW9uKChob3N0LCBwb3J0KSwgdGltZW91dD1hcmdzLnRpbWVvdXQpIGFzIHNvY2s6CiAg"
    "ICAgICAgICAgIHdpdGggY3R4LndyYXBfc29ja2V0KHNvY2ssIHNlcnZlcl9ob3N0bmFtZT1ob3N0KSBhcyBzc29jazoKICAg"
    "ICAgICAgICAgICAgIGRlcl9jaGFpbiA9IE5vbmUKICAgICAgICAgICAgICAgIHRyeToKICAgICAgICAgICAgICAgICAgICBk"
    "ZXJfY2hhaW4gPSBzc29jay5zZXNzaW9uLmdldCgicGVlcl9jZXJ0aWZpY2F0ZV9jaGFpbiIpCiAgICAgICAgICAgICAgICBl"
    "eGNlcHQgRXhjZXB0aW9uOgogICAgICAgICAgICAgICAgICAgIHBhc3MKICAgICAgICBhZGQoZnVsbF91cmwsICJXQS1UTFMt"
    "NDA3IiwgIlNTTCAvIFRMUyIsICJDZXJ0aWZpY2F0ZSBjaGFpbiBjb21wbGV0ZSAtIG5vIG1pc3NpbmcgaW50ZXJtZWRpYXRl"
    "cyIsCiAgICAgICAgICAgICJNZWRpdW0iLCAiUDIiLCAiUEFTUyIsCiAgICAgICAgICAgICJIYW5kc2hha2UgY29tcGxldGVk"
    "IHdpdGggZGVmYXVsdCB0cnVzdCBzdG9yZSB2YWxpZGF0aW9uIChjaGFpbiByZXNvbHZlcykgLSAiICsKICAgICAgICAgICAg"
    "KCJpbnNlY3VyZSBtb2RlIHdhcyBvbiwgc28gdGhpcyBkb2Vzbid0IGNvbmZpcm0gdHJ1c3QuIiBpZiBhcmdzLmluc2VjdXJl"
    "IGVsc2UKICAgICAgICAgICAgICJjZXJ0aWZpY2F0ZSBjaGFpbiBpcyB0cnVzdGVkIGJ5IHRoaXMgbWFjaGluZSdzIENBIGJ1"
    "bmRsZS4iKSkKICAgIGV4Y2VwdCBzc2wuU1NMQ2VydFZlcmlmaWNhdGlvbkVycm9yIGFzIGU6CiAgICAgICAgYWRkKGZ1bGxf"
    "dXJsLCAiV0EtVExTLTQwNyIsICJTU0wgLyBUTFMiLCAiQ2VydGlmaWNhdGUgY2hhaW4gY29tcGxldGUgLSBubyBtaXNzaW5n"
    "IGludGVybWVkaWF0ZXMiLAogICAgICAgICAgICAiTWVkaXVtIiwgIlAyIiwgIkZBSUwiLCBmIkNlcnRpZmljYXRlIHZlcmlm"
    "aWNhdGlvbiBmYWlsZWQ6IHtlfSIpCiAgICBleGNlcHQgRXhjZXB0aW9uIGFzIGU6CiAgICAgICAgYWRkKGZ1bGxfdXJsLCAi"
    "V0EtVExTLTQwNyIsICJTU0wgLyBUTFMiLCAiQ2VydGlmaWNhdGUgY2hhaW4gY29tcGxldGUgLSBubyBtaXNzaW5nIGludGVy"
    "bWVkaWF0ZXMiLAogICAgICAgICAgICAiTWVkaXVtIiwgIlAyIiwgIkVSUk9SIiwgc3RyKGUpKQoKICAgIGhzdHNfaGVhZGVy"
    "ID0gIiIKICAgIHIgPSByYXdfcmVxdWVzdChmdWxsX3VybCwgIkdFVCIsIHRpbWVvdXQ9YXJncy50aW1lb3V0LCBpbnNlY3Vy"
    "ZT1hcmdzLmluc2VjdXJlKQogICAgaWYgbm90IHIuZXJyb3I6CiAgICAgICAgaHN0c19oZWFkZXIgPSByLmhlYWRlcigiU3Ry"
    "aWN0LVRyYW5zcG9ydC1TZWN1cml0eSIpCiAgICBwcmVsb2FkX2ludGVudCA9ICJwcmVsb2FkIiBpbiBoc3RzX2hlYWRlci5s"
    "b3dlcigpCiAgICBwcmVsb2FkX2xpc3RlZCA9IE5vbmUKICAgIHRyeToKICAgICAgICBhcGkgPSByYXdfcmVxdWVzdChmImh0"
    "dHBzOi8vaHN0c3ByZWxvYWQub3JnL2FwaS92Mi9zdGF0dXM/ZG9tYWluPXtob3N0fSIsICJHRVQiLCB0aW1lb3V0PWFyZ3Mu"
    "dGltZW91dCkKICAgICAgICBpZiBub3QgYXBpLmVycm9yIGFuZCBhcGkuc3RhdHVzID09IDIwMDoKICAgICAgICAgICAgZGF0"
    "YSA9IGpzb24ubG9hZHMoYXBpLnRleHQoKSkKICAgICAgICAgICAgcHJlbG9hZF9saXN0ZWQgPSBkYXRhLmdldCgic3RhdHVz"
    "IikKICAgIGV4Y2VwdCBFeGNlcHRpb246CiAgICAgICAgcHJlbG9hZF9saXN0ZWQgPSBOb25lCiAgICBldmlkZW5jZSA9IGYi"
    "SFNUUyBoZWFkZXIgaW5jbHVkZXMgJ3ByZWxvYWQnOiB7cHJlbG9hZF9pbnRlbnR9LiIKICAgIGlmIHByZWxvYWRfbGlzdGVk"
    "OgogICAgICAgIGV2aWRlbmNlICs9IGYiIGhzdHNwcmVsb2FkLm9yZyBzdGF0dXM6IHtwcmVsb2FkX2xpc3RlZH0uIgogICAg"
    "ICAgIHJlc3VsdCA9ICJQQVNTIiBpZiBwcmVsb2FkX2xpc3RlZCA9PSAicHJlbG9hZGVkIiBlbHNlICJGQUlMIgogICAgZWxz"
    "ZToKICAgICAgICBldmlkZW5jZSArPSAiIENvdWxkIG5vdCByZWFjaCBoc3RzcHJlbG9hZC5vcmcgQVBJIHRvIGNvbmZpcm0g"
    "YWN0dWFsIGxpc3QgbWVtYmVyc2hpcC4iCiAgICAgICAgcmVzdWx0ID0gIklORk8iIGlmIHByZWxvYWRfaW50ZW50IGVsc2Ug"
    "IkZBSUwiCiAgICBhZGQoZnVsbF91cmwsICJXQS1UTFMtNDA4IiwgIlNTTCAvIFRMUyIsICJIU1RTIHByZWxvYWQgbGlzdCBj"
    "b25maWd1cmVkIiwKICAgICAgICAiTWVkaXVtIiwgIlAyIiwgcmVzdWx0LCBldmlkZW5jZSkKCiAgICBhZGQoZnVsbF91cmws"
    "ICJXQS1UTFMtNDA5IiwgIlNTTCAvIFRMUyIsICJXZWJTb2NrZXQgZW5kcG9pbnRzIHVzZSBXU1Mgbm90IFdTIiwKICAgICAg"
    "ICAiSGlnaCIsICJQMSIsICJNQU5VQUwiLAogICAgICAgICJObyB3ZWJzb2NrZXQgZW5kcG9pbnQgaXMga25vd24gZnJvbSBh"
    "IHBsYWluIFVSTCAtIGlkZW50aWZ5IHdzOi8vIHZzIHdzczovLyB1c2FnZSB2aWEgYnJvd3NlciAiCiAgICAgICAgImRldiB0"
    "b29scyAvIEJ1cnAgV2ViU29ja2V0cyBoaXN0b3J5IHdoaWxlIHVzaW5nIHRoZSBhcHAsIHRoZW4gdmVyaWZ5IG1hbnVhbGx5"
    "LiIpCgoKIyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t"
    "LS0tLS0tLS0tLQojIDMuIENsaWNramFja2luZyAtIFdBLUNTLTE2MS4uMTY1CiMgLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t"
    "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KCmRlZiBjaGVja19jbGlja2phY2tp"
    "bmcoZnVsbF91cmwsIGhlYWRlcnNfcmVzdWx0KToKICAgIGlmIGhlYWRlcnNfcmVzdWx0LmVycm9yOgogICAgICAgIGZvciBj"
    "aWQsIG5hbWUgaW4gWwogICAgICAgICAgICAoIldBLUNTLTE2MSIsICJDbGlja2phY2tpbmcgLSBiYXNpYyBVSSByZWRyZXNz"
    "IGF0dGFjayAoaWZyYW1lIG92ZXJsYXkpIiksCiAgICAgICAgICAgICgiV0EtQ1MtMTYyIiwgIkNsaWNramFja2luZyAtIGZv"
    "cm0gcHJlLWZpbGwgYXR0YWNrIiksCiAgICAgICAgICAgICgiV0EtQ1MtMTYzIiwgIkNsaWNramFja2luZyAtIGZyYW1lLWJ1"
    "c3Rpbmcgc2NyaXB0IGJ5cGFzcyIpLAogICAgICAgICAgICAoIldBLUNTLTE2NCIsICJDbGlja2phY2tpbmcgLSBtdWx0aXN0"
    "ZXAgYXR0YWNrIChjb25maXJtICsgY2xpY2spIiksCiAgICAgICAgICAgICgiV0EtQ1MtMTY1IiwgIkNsaWNramFja2luZyAt"
    "IGRyYWctYW5kLWRyb3AgVUkgYXR0YWNrIiksCiAgICAgICAgXToKICAgICAgICAgICAgYWRkKGZ1bGxfdXJsLCBjaWQsICJD"
    "bGlja2phY2tpbmciLCBuYW1lLCAiTWVkaXVtIiwgIlAyIiwgIkVSUk9SIiwgaGVhZGVyc19yZXN1bHQuZXJyb3IpCiAgICAg"
    "ICAgcmV0dXJuCgogICAgeGZvID0gaGVhZGVyc19yZXN1bHQuaGVhZGVyKCJYLUZyYW1lLU9wdGlvbnMiKQogICAgY3NwID0g"
    "aGVhZGVyc19yZXN1bHQuaGVhZGVyKCJDb250ZW50LVNlY3VyaXR5LVBvbGljeSIpCiAgICBwcm90ZWN0ZWQgPSAoeGZvLnN0"
    "cmlwKCkudXBwZXIoKSBpbiAoIkRFTlkiLCAiU0FNRU9SSUdJTiIpKSBvciAoImZyYW1lLWFuY2VzdG9ycyIgaW4gY3NwLmxv"
    "d2VyKCkpCiAgICBhZGQoZnVsbF91cmwsICJXQS1DUy0xNjEiLCAiQ2xpY2tqYWNraW5nIiwgIkNsaWNramFja2luZyAtIGJh"
    "c2ljIFVJIHJlZHJlc3MgYXR0YWNrIChpZnJhbWUgb3ZlcmxheSkiLAogICAgICAgICJNZWRpdW0iLCAiUDIiLCAiUEFTUyIg"
    "aWYgcHJvdGVjdGVkIGVsc2UgIkZBSUwiLAogICAgICAgIGYiWC1GcmFtZS1PcHRpb25zOiB7eGZvIG9yICdtaXNzaW5nJ30s"
    "IENTUCBmcmFtZS1hbmNlc3RvcnMgcHJlc2VudDogeydmcmFtZS1hbmNlc3RvcnMnIGluIGNzcC5sb3dlcigpfS4gIiArCiAg"
    "ICAgICAgKCJQYWdlIGNhbiBsaWtlbHkgYmUgZnJhbWVkIC0gYnVpbGQgYW4gaWZyYW1lIFBvQyB0byBjb25maXJtIGV4cGxv"
    "aXRhYmlsaXR5LiIgaWYgbm90IHByb3RlY3RlZCBlbHNlCiAgICAgICAgICJGcmFtaW5nIGhlYWRlcnMgcHJlc2VudCAtIHBh"
    "Z2UgaXMgbGlrZWx5IHByb3RlY3RlZC4iKSkKCiAgICBmb3IgY2lkLCBuYW1lIGluIFsKICAgICAgICAoIldBLUNTLTE2MiIs"
    "ICJDbGlja2phY2tpbmcgLSBmb3JtIHByZS1maWxsIGF0dGFjayIpLAogICAgICAgICgiV0EtQ1MtMTYzIiwgIkNsaWNramFj"
    "a2luZyAtIGZyYW1lLWJ1c3Rpbmcgc2NyaXB0IGJ5cGFzcyIpLAogICAgICAgICgiV0EtQ1MtMTY0IiwgIkNsaWNramFja2lu"
    "ZyAtIG11bHRpc3RlcCBhdHRhY2sgKGNvbmZpcm0gKyBjbGljaykiKSwKICAgICAgICAoIldBLUNTLTE2NSIsICJDbGlja2ph"
    "Y2tpbmcgLSBkcmFnLWFuZC1kcm9wIFVJIGF0dGFjayIpLAogICAgXToKICAgICAgICBhZGQoZnVsbF91cmwsIGNpZCwgIkNs"
    "aWNramFja2luZyIsIG5hbWUsICJNZWRpdW0iLCAiUDIiLCAiTUFOVUFMIiwKICAgICAgICAgICAgIk5lZWRzIGFuIGFjdHVh"
    "bCBQb0MgSFRNTCBwYWdlICsgYnJvd3NlciBpbnRlcmFjdGlvbiB0byB2ZXJpZnkgLSBub3QgdGVzdGFibGUgZnJvbSBoZWFk"
    "ZXJzIGFsb25lLiIpCgoKIyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t"
    "LS0tLS0tLS0tLS0tLS0tLS0tLQojIDQuIENPUlMgLSBXQS1DUy0xNTguLjE2MAojIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t"
    "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCgpkZWYgY2hlY2tfY29ycyhmdWxs"
    "X3VybCwgYXJncyk6CiAgICBldmlsX29yaWdpbiA9IGYiaHR0cHM6Ly9ldmlsLWNvcnMtdGVzdC17cmFuZF90b2tlbig2KX0u"
    "ZXhhbXBsZSIKICAgIHIxID0gcmF3X3JlcXVlc3QoZnVsbF91cmwsICJHRVQiLCBleHRyYV9oZWFkZXJzPXsiT3JpZ2luIjog"
    "ZXZpbF9vcmlnaW59LAogICAgICAgICAgICAgICAgICAgICAgdGltZW91dD1hcmdzLnRpbWVvdXQsIGluc2VjdXJlPWFyZ3Mu"
    "aW5zZWN1cmUpCiAgICBpZiByMS5lcnJvcjoKICAgICAgICBmb3IgY2lkLCBuYW1lIGluIFsoIldBLUNTLTE1OCIsICJDT1JT"
    "IC0gbWlzY29uZmlnOiB3aWxkY2FyZC9yZWZsZWN0ZWQgb3JpZ2luIHRydXN0cyBhdHRhY2tlciIpLAogICAgICAgICAgICAg"
    "ICAgICAgICAgICAgICAoIldBLUNTLTE1OSIsICJDT1JTIC0gbnVsbCBvcmlnaW4gdHJ1c3RlZCAoc2FuZGJveCBpZnJhbWUg"
    "YnlwYXNzKSIpLAogICAgICAgICAgICAgICAgICAgICAgICAgICAoIldBLUNTLTE2MCIsICJDT1JTIC0gaW50cmFuZXQgcGl2"
    "b3QgdmlhIHRydXN0ZWQgd2hpdGVsaXN0ZWQgb3JpZ2luIildOgogICAgICAgICAgICBhZGQoZnVsbF91cmwsIGNpZCwgIkNP"
    "UlMiLCBuYW1lLCAiSGlnaCIsICJQMSIsICJFUlJPUiIsIHIxLmVycm9yKQogICAgICAgIHJldHVybgoKICAgIGFjYW8gPSBy"
    "MS5oZWFkZXIoIkFjY2Vzcy1Db250cm9sLUFsbG93LU9yaWdpbiIpCiAgICBhY2FjID0gcjEuaGVhZGVyKCJBY2Nlc3MtQ29u"
    "dHJvbC1BbGxvdy1DcmVkZW50aWFscyIpCiAgICByZWZsZWN0ZWQgPSBhY2FvID09IGV2aWxfb3JpZ2luCiAgICB3aWxkY2Fy"
    "ZF93aXRoX2NyZWRzID0gYWNhbyA9PSAiKiIgYW5kIGFjYWMubG93ZXIoKSA9PSAidHJ1ZSIKICAgIGZhaWwxID0gcmVmbGVj"
    "dGVkIG9yIHdpbGRjYXJkX3dpdGhfY3JlZHMKICAgIGFkZChmdWxsX3VybCwgIldBLUNTLTE1OCIsICJDT1JTIiwgIkNPUlMg"
    "LSBtaXNjb25maWc6IHdpbGRjYXJkL3JlZmxlY3RlZCBvcmlnaW4gdHJ1c3RzIGF0dGFja2VyIiwKICAgICAgICAiSGlnaCIs"
    "ICJQMSIsICJGQUlMIiBpZiBmYWlsMSBlbHNlICJQQVNTIiwKICAgICAgICBmIlNlbnQgT3JpZ2luOiB7ZXZpbF9vcmlnaW59"
    "IC0+IEFjY2Vzcy1Db250cm9sLUFsbG93LU9yaWdpbjoge2FjYW8gb3IgJ25vbmUnfSwgIgogICAgICAgIGYiQWNjZXNzLUNv"
    "bnRyb2wtQWxsb3ctQ3JlZGVudGlhbHM6IHthY2FjIG9yICdub25lJ30uIiArCiAgICAgICAgKCIgQXJiaXRyYXJ5IG9yaWdp"
    "biBpcyByZWZsZWN0ZWQvdHJ1c3RlZCAtIGxpa2VseSBleHBsb2l0YWJsZS4iIGlmIGZhaWwxIGVsc2UgIiIpKQoKICAgIHIy"
    "ID0gcmF3X3JlcXVlc3QoZnVsbF91cmwsICJHRVQiLCBleHRyYV9oZWFkZXJzPXsiT3JpZ2luIjogIm51bGwifSwKICAgICAg"
    "ICAgICAgICAgICAgICAgIHRpbWVvdXQ9YXJncy50aW1lb3V0LCBpbnNlY3VyZT1hcmdzLmluc2VjdXJlKQogICAgYWNhb19u"
    "dWxsID0gcjIuaGVhZGVyKCJBY2Nlc3MtQ29udHJvbC1BbGxvdy1PcmlnaW4iKSBpZiBub3QgcjIuZXJyb3IgZWxzZSAiIgog"
    "ICAgbnVsbF90cnVzdGVkID0gYWNhb19udWxsLnN0cmlwKCkgPT0gIm51bGwiCiAgICBhZGQoZnVsbF91cmwsICJXQS1DUy0x"
    "NTkiLCAiQ09SUyIsICJDT1JTIC0gbnVsbCBvcmlnaW4gdHJ1c3RlZCAoc2FuZGJveCBpZnJhbWUgYnlwYXNzKSIsCiAgICAg"
    "ICAgIkhpZ2giLCAiUDEiLCAiRkFJTCIgaWYgbnVsbF90cnVzdGVkIGVsc2UgIlBBU1MiLAogICAgICAgIGYiU2VudCBPcmln"
    "aW46IG51bGwgLT4gQWNjZXNzLUNvbnRyb2wtQWxsb3ctT3JpZ2luOiB7YWNhb19udWxsIG9yICdub25lJ30uIiArCiAgICAg"
    "ICAgKCIgJ251bGwnIG9yaWdpbiBpcyB0cnVzdGVkIC0gZXhwbG9pdGFibGUgdmlhIHNhbmRib3hlZCBpZnJhbWUvZGF0YTog"
    "VVJJLiIgaWYgbnVsbF90cnVzdGVkIGVsc2UgIiIpKQoKICAgIGFkZChmdWxsX3VybCwgIldBLUNTLTE2MCIsICJDT1JTIiwg"
    "IkNPUlMgLSBpbnRyYW5ldCBwaXZvdCB2aWEgdHJ1c3RlZCB3aGl0ZWxpc3RlZCBvcmlnaW4iLAogICAgICAgICJIaWdoIiwg"
    "IlAxIiwgIk1BTlVBTCIsCiAgICAgICAgIk5lZWRzIHRoZSBhcHAncyBhY3R1YWwgd2hpdGVsaXN0ZWQtb3JpZ2luIGxpc3Qg"
    "KGUuZy4gaW50ZXJuYWwgc3ViZG9tYWlucykgdG8gdGVzdCAtICIKICAgICAgICAiY2FuJ3QgYmUgZ3Vlc3NlZCBnZW5lcmlj"
    "YWxseS4gUmV2aWV3IHRoZSBDT1JTIGFsbG93LWxpc3Qgc291cmNlL2NvbmZpZyBtYW51YWxseS4iKQoKCiMgLS0tLS0tLS0t"
    "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KIyA1LiBJ"
    "bmZvcm1hdGlvbiBHYXRoZXJpbmcgLSBXQS1PVEctMjczLi4yODIKIyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t"
    "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQoKZGVmIGNoZWNrX2luZm9ybWF0aW9uX2dhdGhl"
    "cmluZyhmdWxsX3VybCwgaGVhZGVyc19yZXN1bHQsIGFyZ3MpOgogICAgYmFzZSA9IGRpcl9vZihmdWxsX3VybCkKCiAgICBh"
    "ZGQoZnVsbF91cmwsICJXQS1PVEctMjczIiwgIkluZm9ybWF0aW9uIEdhdGhlcmluZyIsICJDb25kdWN0IHNlYXJjaCBlbmdp"
    "bmUgcmVjb24gKEdvb2dsZSBkb3JrcywgU2hvZGFuKSIsCiAgICAgICAgIkluZm8iLCAiUDMiLCAiTUFOVUFMIiwgIk5lZWRz"
    "IGV4dGVybmFsIE9TSU5UL3NlYXJjaC1lbmdpbmUvU2hvZGFuIHF1ZXJpZXMgLSBub3QgdGVzdGFibGUgZnJvbSB0aGUgdGFy"
    "Z2V0IGRpcmVjdGx5LiIpCgogICAgc2VydmVyX2hkciA9IGhlYWRlcnNfcmVzdWx0LmhlYWRlcigiU2VydmVyIikgaWYgbm90"
    "IGhlYWRlcnNfcmVzdWx0LmVycm9yIGVsc2UgIiIKICAgIGFkZChmdWxsX3VybCwgIldBLU9URy0yNzQiLCAiSW5mb3JtYXRp"
    "b24gR2F0aGVyaW5nIiwgIkZpbmdlcnByaW50IHdlYiBzZXJ2ZXIgKFNlcnZlciBoZWFkZXIsIGVycm9yIHBhZ2VzKSIsCiAg"
    "ICAgICAgIkxvdyIsICJQMyIsICJJTkZPIiwgZiJTZXJ2ZXIgaGVhZGVyOiB7c2VydmVyX2hkciBvciAnbm90IGRpc2Nsb3Nl"
    "ZCd9LiIpCgogICAgcm9ib3RzID0gcmF3X3JlcXVlc3Qoam9pbl90YXJnZXQoYmFzZSwgIi9yb2JvdHMudHh0IiksICJHRVQi"
    "LCB0aW1lb3V0PWFyZ3MudGltZW91dCwgaW5zZWN1cmU9YXJncy5pbnNlY3VyZSkKICAgIHNpdGVtYXAgPSByYXdfcmVxdWVz"
    "dChqb2luX3RhcmdldChiYXNlLCAiL3NpdGVtYXAueG1sIiksICJHRVQiLCB0aW1lb3V0PWFyZ3MudGltZW91dCwgaW5zZWN1"
    "cmU9YXJncy5pbnNlY3VyZSkKICAgIGRpc2FsbG93X2xpbmVzID0gW10KICAgIGlmIG5vdCByb2JvdHMuZXJyb3IgYW5kIHJv"
    "Ym90cy5zdGF0dXMgPT0gMjAwOgogICAgICAgIGRpc2FsbG93X2xpbmVzID0gW2wuc3RyaXAoKSBmb3IgbCBpbiByb2JvdHMu"
    "dGV4dCgpLnNwbGl0bGluZXMoKSBpZiBsLnN0cmlwKCkubG93ZXIoKS5zdGFydHN3aXRoKCJkaXNhbGxvdyIpXQogICAgc2Vu"
    "c2l0aXZlX2hpbnQgPSBhbnkocmUuc2VhcmNoKHIiYWRtaW58YmFja3VwfGNvbmZpZ3xwcml2YXRlfGludGVybmFsfFwuZ2l0"
    "fHN0YWdpbmciLCBsLCByZS5JKSBmb3IgbCBpbiBkaXNhbGxvd19saW5lcykKICAgIGFkZChmdWxsX3VybCwgIldBLU9URy0y"
    "NzUiLCAiSW5mb3JtYXRpb24gR2F0aGVyaW5nIiwgIlJldmlldyB3ZWJzZXJ2ZXIgbWV0YWZpbGVzIChyb2JvdHMudHh0LCBz"
    "aXRlbWFwLnhtbCkiLAogICAgICAgICJMb3ciLCAiUDMiLCAiRkFJTCIgaWYgc2Vuc2l0aXZlX2hpbnQgZWxzZSAiSU5GTyIs"
    "CiAgICAgICAgZiJyb2JvdHMudHh0OiB7JzIwMCwgJyArIHN0cihsZW4oZGlzYWxsb3dfbGluZXMpKSArICcgRGlzYWxsb3cg"
    "ZW50cmllcycgaWYgbm90IHJvYm90cy5lcnJvciBhbmQgcm9ib3RzLnN0YXR1cyA9PSAyMDAgZWxzZSAnbm90IGZvdW5kL2Vy"
    "cm9yJ30iCiAgICAgICAgZiJ7JyAoJyArICc7ICcuam9pbihkaXNhbGxvd19saW5lc1s6OF0pICsgJyknIGlmIGRpc2FsbG93"
    "X2xpbmVzIGVsc2UgJyd9LiAiCiAgICAgICAgZiJzaXRlbWFwLnhtbDogeycyMDAnIGlmIG5vdCBzaXRlbWFwLmVycm9yIGFu"
    "ZCBzaXRlbWFwLnN0YXR1cyA9PSAyMDAgZWxzZSAnbm90IGZvdW5kL2Vycm9yJ30uIiArCiAgICAgICAgKCIgcm9ib3RzLnR4"
    "dCBEaXNhbGxvdyBsaXN0IGl0c2VsZiBoaW50cyBhdCBzZW5zaXRpdmUgcGF0aHMgLSByZXZpZXcgdGhlbSBkaXJlY3RseS4i"
    "IGlmIHNlbnNpdGl2ZV9oaW50IGVsc2UgIiIpKQoKICAgIGZvciBjaWQsIG5hbWUgaW4gWygiV0EtT1RHLTI3NiIsICJFbnVt"
    "ZXJhdGUgYXBwbGljYXRpb24gZW50cnkgcG9pbnRzIChhbGwgcGFyYW1zL2Zvcm1zKSIpLAogICAgICAgICAgICAgICAgICAg"
    "ICAgICgiV0EtT1RHLTI3NyIsICJNYXAgZXhlY3V0aW9uIHBhdGhzIHRocm91Z2ggYXBwbGljYXRpb24iKV06CiAgICAgICAg"
    "YWRkKGZ1bGxfdXJsLCBjaWQsICJJbmZvcm1hdGlvbiBHYXRoZXJpbmciLCBuYW1lLCAiSW5mbyIsICJQMyIsICJNQU5VQUwi"
    "LAogICAgICAgICAgICAiTmVlZHMgZnVsbCBjcmF3bGluZy9zcGlkZXJpbmcgKEJ1cnAgU3BpZGVyLCBrYXRhbmEsIGhha3Jh"
    "d2xlcikgYWNyb3NzIHRoZSB3aG9sZSBhcHAgLSBhIHNpbmdsZS1wYWdlIGZldGNoIGlzbid0IHJlcHJlc2VudGF0aXZlLiIp"
    "CgogICAgYm9keV90ZXh0ID0gaGVhZGVyc19yZXN1bHQudGV4dCgpIGlmIG5vdCBoZWFkZXJzX3Jlc3VsdC5lcnJvciBlbHNl"
    "ICIiCiAgICB4cGIgPSBoZWFkZXJzX3Jlc3VsdC5oZWFkZXIoIlgtUG93ZXJlZC1CeSIpIGlmIG5vdCBoZWFkZXJzX3Jlc3Vs"
    "dC5lcnJvciBlbHNlICIiCiAgICBjb29raWVzX3JhdyA9IGhlYWRlcnNfcmVzdWx0LmhlYWRlcnMgaWYgbm90IGhlYWRlcnNf"
    "cmVzdWx0LmVycm9yIGVsc2Uge30KICAgIGNvb2tpZV9uYW1lcyA9IFtdCiAgICBmb3IgaywgdiBpbiBjb29raWVzX3Jhdy5p"
    "dGVtcygpOgogICAgICAgIGlmIGsubG93ZXIoKSA9PSAic2V0LWNvb2tpZSI6CiAgICAgICAgICAgIG0gPSByZS5tYXRjaChy"
    "IihbXj1dKyk9IiwgdikKICAgICAgICAgICAgaWYgbToKICAgICAgICAgICAgICAgIGNvb2tpZV9uYW1lcy5hcHBlbmQobS5n"
    "cm91cCgxKSkKICAgIGZ3X2hpbnRzID0gW10KICAgIGlmIHhwYjoKICAgICAgICBmd19oaW50cy5hcHBlbmQoZiJYLVBvd2Vy"
    "ZWQtQnk6IHt4cGJ9IikKICAgIGZvciBjbiBpbiBjb29raWVfbmFtZXM6CiAgICAgICAgaWYgY24udXBwZXIoKSBpbiAoIlBI"
    "UFNFU1NJRCIsKToKICAgICAgICAgICAgZndfaGludHMuYXBwZW5kKCJQSFAgKFBIUFNFU1NJRCBjb29raWUpIikKICAgICAg"
    "ICBlbGlmIGNuLnVwcGVyKCkgaW4gKCJKU0VTU0lPTklEIiwpOgogICAgICAgICAgICBmd19oaW50cy5hcHBlbmQoIkphdmEv"
    "SlNQIChKU0VTU0lPTklEIGNvb2tpZSkiKQogICAgICAgIGVsaWYgImxhcmF2ZWxfc2Vzc2lvbiIgaW4gY24ubG93ZXIoKToK"
    "ICAgICAgICAgICAgZndfaGludHMuYXBwZW5kKCJMYXJhdmVsIChsYXJhdmVsX3Nlc3Npb24gY29va2llKSIpCiAgICAgICAg"
    "ZWxpZiAiZGphbmdvIiBpbiBjbi5sb3dlcigpIG9yICJjc3JmdG9rZW4iIGluIGNuLmxvd2VyKCk6CiAgICAgICAgICAgIGZ3"
    "X2hpbnRzLmFwcGVuZCgiRGphbmdvIChkamFuZ28vY3NyZnRva2VuIGNvb2tpZSkiKQogICAgZ2VuX21hdGNoID0gcmUuc2Vh"
    "cmNoKHInPG1ldGFbXj5dK25hbWU9WyJcJ11nZW5lcmF0b3JbIlwnXVtePl0rY29udGVudD1bIlwnXShbXiJcJ10rKScsIGJv"
    "ZHlfdGV4dCwgcmUuSSkKICAgIGlmIGdlbl9tYXRjaDoKICAgICAgICBmd19oaW50cy5hcHBlbmQoZiJtZXRhIGdlbmVyYXRv"
    "ciB0YWc6IHtnZW5fbWF0Y2guZ3JvdXAoMSl9IikKICAgIGFkZChmdWxsX3VybCwgIldBLU9URy0yNzgiLCAiSW5mb3JtYXRp"
    "b24gR2F0aGVyaW5nIiwgIkZpbmdlcnByaW50IHdlYiBhcHBsaWNhdGlvbiBmcmFtZXdvcmsiLAogICAgICAgICJMb3ciLCAi"
    "UDMiLCAiSU5GTyIsICI7ICIuam9pbihmd19oaW50cykgaWYgZndfaGludHMgZWxzZSAiTm8gb2J2aW91cyBmcmFtZXdvcmsg"
    "ZmluZ2VycHJpbnQgZm91bmQgaW4gaGVhZGVycy9jb29raWVzL2hvbWVwYWdlLiIpCgogICAgY2RuX2hpbnRzID0gW10KICAg"
    "IGlmIG5vdCBoZWFkZXJzX3Jlc3VsdC5lcnJvcjoKICAgICAgICBmb3IgaGssIGh2IGluIGhlYWRlcnNfcmVzdWx0LmhlYWRl"
    "cnMuaXRlbXMoKToKICAgICAgICAgICAgaGtfbCA9IGhrLmxvd2VyKCkKICAgICAgICAgICAgaWYgaGtfbCBpbiBDRE5fV0FG"
    "X0hFQURFUl9ISU5UUzoKICAgICAgICAgICAgICAgIGZvciBuZWVkbGUsIGxhYmVsIGluIENETl9XQUZfSEVBREVSX0hJTlRT"
    "W2hrX2xdLml0ZW1zKCk6CiAgICAgICAgICAgICAgICAgICAgaWYgbmVlZGxlID09ICIiIG9yIG5lZWRsZSBpbiBodi5sb3dl"
    "cigpOgogICAgICAgICAgICAgICAgICAgICAgICBjZG5faGludHMuYXBwZW5kKGYie2xhYmVsfSAodmlhIHtoa306IHtodls6"
    "NjBdfSkiKQogICAgYWRkKGZ1bGxfdXJsLCAiV0EtT1RHLTI3OSIsICJJbmZvcm1hdGlvbiBHYXRoZXJpbmciLCAiTWFwIGFw"
    "cGxpY2F0aW9uIGFyY2hpdGVjdHVyZSAoQ0ROLCBXQUYsIExCLCBwcm94eSBsYXllcnMpIiwKICAgICAgICAiSW5mbyIsICJQ"
    "MyIsICJJTkZPIiwgIjsgIi5qb2luKGNkbl9oaW50cykgaWYgY2RuX2hpbnRzIGVsc2UgIk5vIENETi9XQUYvcHJveHkgaGVh"
    "ZGVyIGhpbnRzIGRldGVjdGVkIG9uIHRoaXMgcmVzcG9uc2UuIikKCiAgICBkZXBfaGl0cyA9IFtdCiAgICBmb3IgcGF0aCBp"
    "biBERVBFTkRFTkNZX1BST0JFUzoKICAgICAgICByciA9IHJhd19yZXF1ZXN0KGpvaW5fdGFyZ2V0KGJhc2UsIHBhdGgpLCAi"
    "R0VUIiwgdGltZW91dD1hcmdzLnRpbWVvdXQsIGluc2VjdXJlPWFyZ3MuaW5zZWN1cmUpCiAgICAgICAgaWYgbm90IHJyLmVy"
    "cm9yIGFuZCByci5zdGF0dXMgPT0gMjAwOgogICAgICAgICAgICBkZXBfaGl0cy5hcHBlbmQocGF0aCkKICAgIGFkZChmdWxs"
    "X3VybCwgIldBLU9URy0yODAiLCAiSW5mb3JtYXRpb24gR2F0aGVyaW5nIiwgIklkZW50aWZ5IGFwcGxpY2F0aW9uIGRlcGVu"
    "ZGVuY2llcyAocGFja2FnZS5qc29uLCBHZW1maWxlLCBwb20pIiwKICAgICAgICAiTG93IiwgIlAzIiwgIkZBSUwiIGlmIGRl"
    "cF9oaXRzIGVsc2UgIlBBU1MiLAogICAgICAgIGYiUHVibGljbHkgYWNjZXNzaWJsZSBkZXBlbmRlbmN5IG1hbmlmZXN0KHMp"
    "OiB7JywgJy5qb2luKGRlcF9oaXRzKX0iIGlmIGRlcF9oaXRzIGVsc2UKICAgICAgICBmIk5vbmUgb2YgdGhlIHByb2JlZCBt"
    "YW5pZmVzdCBwYXRocyAoeycsICcuam9pbihERVBFTkRFTkNZX1BST0JFUyl9KSBhcmUgcHVibGljbHkgYWNjZXNzaWJsZSBh"
    "dCB0aGUgc2l0ZSByb290LiIpCgogICAgZW1haWxzID0gc29ydGVkKHNldChyZS5maW5kYWxsKHIiW2EtekEtWjAtOS5fJSst"
    "XStAW2EtekEtWjAtOS4tXStcLlthLXpBLVpdezIsfSIsIGJvZHlfdGV4dCkpKVs6MTBdCiAgICBhZGQoZnVsbF91cmwsICJX"
    "QS1PVEctMjgxIiwgIkluZm9ybWF0aW9uIEdhdGhlcmluZyIsICJIYXJ2ZXN0IGVtYWlscywgdXNlcm5hbWVzLCBwaG9uZSBu"
    "dW1iZXJzIGZyb20gYXBwIiwKICAgICAgICAiSW5mbyIsICJQMyIsICJJTkZPIiBpZiBlbWFpbHMgZWxzZSAiTUFOVUFMIiwK"
    "ICAgICAgICAoZiJFbWFpbCBhZGRyZXNzKGVzKSBmb3VuZCBvbiB0aGlzIHNpbmdsZSBwYWdlOiB7JywgJy5qb2luKGVtYWls"
    "cyl9LiAiCiAgICAgICAgICJUaGlzIGlzIG9ubHkgYSBzcG90LWNoZWNrIG9mIG9uZSBwYWdlLCBub3QgYSBmdWxsIGhhcnZl"
    "c3QuIiBpZiBlbWFpbHMgZWxzZQogICAgICAgICAiTm9uZSBmb3VuZCBvbiB0aGlzIHNpbmdsZSBwYWdlIC0gYSBmdWxsIGhh"
    "cnZlc3QgbmVlZHMgY3Jhd2xpbmcgdGhlIHdob2xlIGFwcC4iKSkKCiAgICBidWNrZXRfaGl0cyA9IHNvcnRlZChzZXQobSBm"
    "b3IgcGF0IGluIENMT1VEX0JVQ0tFVF9QQVRURVJOUyBmb3IgbSBpbiByZS5maW5kYWxsKHBhdCwgYm9keV90ZXh0LCByZS5J"
    "KSkpWzoxMF0KICAgIGFkZChmdWxsX3VybCwgIldBLU9URy0yODIiLCAiSW5mb3JtYXRpb24gR2F0aGVyaW5nIiwgIklkZW50"
    "aWZ5IGNsb3VkIHN0b3JhZ2UgYnVja2V0cyAoUzMsIEdDUywgQXp1cmUgQmxvYikiLAogICAgICAgICJIaWdoIiwgIlAxIiwg"
    "IklORk8iIGlmIGJ1Y2tldF9oaXRzIGVsc2UgIlBBU1MiLAogICAgICAgIChmIkNsb3VkIHN0b3JhZ2UgcmVmZXJlbmNlKHMp"
    "IGZvdW5kIG9uIHRoaXMgcGFnZTogeycsICcuam9pbihidWNrZXRfaGl0cyl9IC0gY2hlY2sgZWFjaCBtYW51YWxseSBmb3Ig"
    "IgogICAgICAgICAicHVibGljIHJlYWQvd3JpdGUvbGlzdCBhY2Nlc3MuIiBpZiBidWNrZXRfaGl0cyBlbHNlICJObyBjbG91"
    "ZCBzdG9yYWdlIGJ1Y2tldCBVUkxzIHJlZmVyZW5jZWQgb24gdGhpcyBzaW5nbGUgcGFnZS4iKSkKCgojIC0tLS0tLS0tLS0t"
    "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiMgNi4gQ29u"
    "ZmlndXJhdGlvbiBUZXN0aW5nIC0gV0EtT1RHLTI4My4uMjk0CiMgLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t"
    "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KCmRlZiBfcG9ydF9zY2FuKGhvc3QsIHBvcnRzLCB0"
    "aW1lb3V0PTIuMCk6CiAgICBvcGVuX3BvcnRzID0gW10KICAgIGZvciBwb3J0IGluIHBvcnRzOgogICAgICAgIHRyeToKICAg"
    "ICAgICAgICAgd2l0aCBzb2NrZXQuY3JlYXRlX2Nvbm5lY3Rpb24oKGhvc3QsIHBvcnQpLCB0aW1lb3V0PXRpbWVvdXQpOgog"
    "ICAgICAgICAgICAgICAgb3Blbl9wb3J0cy5hcHBlbmQocG9ydCkKICAgICAgICBleGNlcHQgRXhjZXB0aW9uOgogICAgICAg"
    "ICAgICBwYXNzCiAgICByZXR1cm4gb3Blbl9wb3J0cwoKCmRlZiBjaGVja19jb25maWd1cmF0aW9uKGZ1bGxfdXJsLCBoZWFk"
    "ZXJzX3Jlc3VsdCwgaGRyX2N1cmxfYmxvY2ssIGFyZ3MpOgogICAgYmFzZSA9IGRpcl9vZihmdWxsX3VybCkKICAgIGhvc3Qg"
    "PSB1cmxwYXJzZShmdWxsX3VybCkuaG9zdG5hbWUKCiAgICBpZiBhcmdzLnBvcnRfc2NhbjoKICAgICAgICBvcGVuX3BvcnRz"
    "ID0gX3BvcnRfc2Nhbihob3N0LCBDT01NT05fQURNSU5fUE9SVFMsIHRpbWVvdXQ9bWluKGFyZ3MudGltZW91dCwgMykpCiAg"
    "ICAgICAgYWRkKGZ1bGxfdXJsLCAiV0EtT1RHLTI4MyIsICJDb25maWd1cmF0aW9uIFRlc3RpbmciLCAiVGVzdCBuZXR3b3Jr"
    "L2luZnJhc3RydWN0dXJlIGNvbmZpZyAoZXhwb3NlZCBhZG1pbiBwb3J0cykiLAogICAgICAgICAgICAiSGlnaCIsICJQMSIs"
    "ICJGQUlMIiBpZiBvcGVuX3BvcnRzIGVsc2UgIlBBU1MiLAogICAgICAgICAgICBmIkNvbW1vbiBhZG1pbi9EQiBwb3J0cyBw"
    "cm9iZWQgKHsnLCAnLmpvaW4obWFwKHN0ciwgQ09NTU9OX0FETUlOX1BPUlRTKSl9KS4gIgogICAgICAgICAgICBmIk9wZW46"
    "IHsnLCAnLmpvaW4obWFwKHN0ciwgb3Blbl9wb3J0cykpIGlmIG9wZW5fcG9ydHMgZWxzZSAnbm9uZSd9LiIpCiAgICBlbHNl"
    "OgogICAgICAgIGFkZChmdWxsX3VybCwgIldBLU9URy0yODMiLCAiQ29uZmlndXJhdGlvbiBUZXN0aW5nIiwgIlRlc3QgbmV0"
    "d29yay9pbmZyYXN0cnVjdHVyZSBjb25maWcgKGV4cG9zZWQgYWRtaW4gcG9ydHMpIiwKICAgICAgICAgICAgIkhpZ2giLCAi"
    "UDEiLCAiTUFOVUFMIiwgIlNraXBwZWQgYnkgZGVmYXVsdCAobm9pc2llciBzY2FuKS4gUmUtcnVuIHdpdGggLS1wb3J0LXNj"
    "YW4sIG9yIHVzZSBubWFwIGRpcmVjdGx5LiIpCgogICAgYWRkKGZ1bGxfdXJsLCAiV0EtT1RHLTI4NCIsICJDb25maWd1cmF0"
    "aW9uIFRlc3RpbmciLCAiVGVzdCBhcHBsaWNhdGlvbiBwbGF0Zm9ybSBjb25maWd1cmF0aW9uIChkZWZhdWx0IGNyZWRzKSIs"
    "CiAgICAgICAgIkhpZ2giLCAiUDEiLCAiTUFOVUFMIiwgIk5lZWRzIGEga25vd24gbG9naW4gZW5kcG9pbnQgKyBjcmVkZW50"
    "aWFsIGxpc3QgLSB1c2UgaHlkcmEvbWFudWFsIHRlc3RpbmcgYWdhaW5zdCB0aGUgYWN0dWFsIGxvZ2luIGZvcm0uIikKCiAg"
    "ICBiYWtfaGl0cyA9IFtdCiAgICBmb3IgcGF0aCBpbiBCQUNLVVBfRVhUX1BST0JFUzoKICAgICAgICByciA9IHJhd19yZXF1"
    "ZXN0KGpvaW5fdGFyZ2V0KGJhc2UsIHBhdGgpLCAiR0VUIiwgdGltZW91dD1hcmdzLnRpbWVvdXQsIGluc2VjdXJlPWFyZ3Mu"
    "aW5zZWN1cmUpCiAgICAgICAgaWYgbm90IHJyLmVycm9yIGFuZCByci5zdGF0dXMgPT0gMjAwOgogICAgICAgICAgICBiYWtf"
    "aGl0cy5hcHBlbmQocGF0aCkKICAgIGFkZChmdWxsX3VybCwgIldBLU9URy0yODUiLCAiQ29uZmlndXJhdGlvbiBUZXN0aW5n"
    "IiwgIlRlc3QgZmlsZSBleHRlbnNpb24gaGFuZGxpbmcgKC5iYWsgLm9sZCAub3JpZyAuc3dwKSIsCiAgICAgICAgIkhpZ2gi"
    "LCAiUDEiLCAiRkFJTCIgaWYgYmFrX2hpdHMgZWxzZSAiUEFTUyIsCiAgICAgICAgZiJBY2Nlc3NpYmxlOiB7JywgJy5qb2lu"
    "KGJha19oaXRzKX0iIGlmIGJha19oaXRzIGVsc2UgZiJOb25lIG9mIHsnLCAnLmpvaW4oQkFDS1VQX0VYVF9QUk9CRVMpfSBh"
    "Y2Nlc3NpYmxlIGF0IHNpdGUgcm9vdC4iKQoKICAgIGJhY2t1cF9oaXRzID0gW10KICAgIGZvciBwYXRoIGluIEJBQ0tVUF9G"
    "SUxFX1BST0JFUzoKICAgICAgICByciA9IHJhd19yZXF1ZXN0KGpvaW5fdGFyZ2V0KGJhc2UsIHBhdGgpLCAiR0VUIiwgdGlt"
    "ZW91dD1hcmdzLnRpbWVvdXQsIGluc2VjdXJlPWFyZ3MuaW5zZWN1cmUpCiAgICAgICAgaWYgbm90IHJyLmVycm9yIGFuZCBy"
    "ci5zdGF0dXMgPT0gMjAwOgogICAgICAgICAgICBiYWNrdXBfaGl0cy5hcHBlbmQocGF0aCkKICAgIGFkZChmdWxsX3VybCwg"
    "IldBLU9URy0yODYiLCAiQ29uZmlndXJhdGlvbiBUZXN0aW5nIiwgIlJldmlldyBiYWNrdXAgYW5kIHVucmVmZXJlbmNlZCBm"
    "aWxlcyIsCiAgICAgICAgIkhpZ2giLCAiUDEiLCAiRkFJTCIgaWYgYmFja3VwX2hpdHMgZWxzZSAiUEFTUyIsCiAgICAgICAg"
    "ZiJBY2Nlc3NpYmxlOiB7JywgJy5qb2luKGJhY2t1cF9oaXRzKX0iIGlmIGJhY2t1cF9oaXRzIGVsc2UgZiJOb25lIG9mIHsn"
    "LCAnLmpvaW4oQkFDS1VQX0ZJTEVfUFJPQkVTKX0gYWNjZXNzaWJsZSBhdCBzaXRlIHJvb3QuIikKCiAgICBhZG1pbl9oaXRz"
    "ID0gW10KICAgIGZvciBwYXRoIGluIEFETUlOX1BBVEhfUFJPQkVTOgogICAgICAgIHJyID0gcmF3X3JlcXVlc3Qoam9pbl90"
    "YXJnZXQoYmFzZSwgcGF0aCksICJHRVQiLCB0aW1lb3V0PWFyZ3MudGltZW91dCwgaW5zZWN1cmU9YXJncy5pbnNlY3VyZSkK"
    "ICAgICAgICBpZiBub3QgcnIuZXJyb3IgYW5kIHJyLnN0YXR1cyA9PSAyMDA6CiAgICAgICAgICAgIGFkbWluX2hpdHMuYXBw"
    "ZW5kKGYie3BhdGh9ICgyMDAgLSBwdWJsaWNseSByZWFjaGFibGUpIikKICAgICAgICBlbGlmIG5vdCByci5lcnJvciBhbmQg"
    "cnIuc3RhdHVzIGluICg0MDEsIDQwMyk6CiAgICAgICAgICAgIGFkbWluX2hpdHMuYXBwZW5kKGYie3BhdGh9ICh7cnIuc3Rh"
    "dHVzfSAtIGV4aXN0cywgYXBwZWFycyBwcm90ZWN0ZWQpIikKICAgIGFkZChmdWxsX3VybCwgIldBLU9URy0yODciLCAiQ29u"
    "ZmlndXJhdGlvbiBUZXN0aW5nIiwgIkVudW1lcmF0ZSBpbmZyYXN0cnVjdHVyZSBhbmQgYWRtaW4gaW50ZXJmYWNlcyIsCiAg"
    "ICAgICAgIkNyaXRpY2FsIiwgIlAxIiwgIkZBSUwiIGlmIGFueSgiMjAwIiBpbiBoIGZvciBoIGluIGFkbWluX2hpdHMpIGVs"
    "c2UgKCJJTkZPIiBpZiBhZG1pbl9oaXRzIGVsc2UgIlBBU1MiKSwKICAgICAgICAiOyAiLmpvaW4oYWRtaW5faGl0cykgaWYg"
    "YWRtaW5faGl0cyBlbHNlIGYiTm9uZSBvZiB7JywgJy5qb2luKEFETUlOX1BBVEhfUFJPQkVTKX0gcmVzcG9uZGVkIGF0IHNp"
    "dGUgcm9vdC4iKQoKICAgIHJvcHRzID0gcmF3X3JlcXVlc3QoYmFzZSwgIk9QVElPTlMiLCB0aW1lb3V0PWFyZ3MudGltZW91"
    "dCwgaW5zZWN1cmU9YXJncy5pbnNlY3VyZSkKICAgIGFsbG93ID0gcm9wdHMuaGVhZGVyKCJBbGxvdyIpIGlmIG5vdCByb3B0"
    "cy5lcnJvciBlbHNlICIiCiAgICByaXNreV9tZXRob2RzID0gW20gZm9yIG0gaW4gWyJQVVQiLCAiREVMRVRFIiwgIlRSQUNF"
    "IiwgIkNPTk5FQ1QiXSBpZiBtIGluIGFsbG93LnVwcGVyKCldCiAgICBhZGQoZnVsbF91cmwsICJXQS1PVEctMjg4IiwgIkNv"
    "bmZpZ3VyYXRpb24gVGVzdGluZyIsICJUZXN0IEhUVFAgbWV0aG9kcyAoUFVUL0RFTEVURS9PUFRJT05TL1RSQUNFKSIsCiAg"
    "ICAgICAgIk1lZGl1bSIsICJQMiIsICJGQUlMIiBpZiByaXNreV9tZXRob2RzIGVsc2UgKCJFUlJPUiIgaWYgcm9wdHMuZXJy"
    "b3IgZWxzZSAiUEFTUyIpLAogICAgICAgIChyb3B0cy5lcnJvciBvciBmIk9QVElPTlMge2Jhc2V9IC0+IEFsbG93OiB7YWxs"
    "b3cgb3IgJ25vdCBkaXNjbG9zZWQnfS4iICsKICAgICAgICAgKGYiIFJpc2t5IG1ldGhvZChzKSBhZHZlcnRpc2VkOiB7Jywg"
    "Jy5qb2luKHJpc2t5X21ldGhvZHMpfSAtIHZlcmlmeSBlYWNoIGlzIGFjdHVhbGx5IHVzYWJsZS4iIGlmIHJpc2t5X21ldGhv"
    "ZHMgZWxzZSAiIikpKQoKICAgICMgUmVwb3J0ZWQgZGlyZWN0bHksIHdpdGggYSBzY3JlZW5zaG90OiAib3V0cHV0IGlzIG5v"
    "dCBhIGNvbW1hbmQgbGluZQogICAgIyBvciByZXF1ZXN0IHJlc3BvbnNlIGJhc2VzIGl0IGp1c3QgYSBzdGF0ZW1lbnQgcGxl"
    "YXNlIGZpeCIgLSB0aGlzIGFuZAogICAgIyBXQS1PVEctMjk0IGJlbG93IHJlLXJlYWQgdGhlIFNBTUUgcmVzcG9uc2UgY2hl"
    "Y2tfc2VjdXJpdHlfaGVhZGVycygpCiAgICAjIGFscmVhZHkgZmV0Y2hlZCAoV0EtT1RHLTI4OS8yOTQgYXJlIHRoZSBPV0FT"
    "UCBUZXN0aW5nIEd1aWRlIElEcyBmb3IKICAgICMgdGhlIGlkZW50aWNhbCBIU1RTL0NTUCBoZWFkZXIgY2hlY2tzIFdBLUhE"
    "Ui0zOTUvMzkyIGNvdmVyIHVuZGVyIHRoZQogICAgIyBtYXN0ZXIgY2hlY2tsaXN0J3Mgb3duIElEIHNjaGVtZSAtIG5vIG5l"
    "ZWQgdG8gcmUtcmVxdWVzdCB0aGUgcGFnZSksCiAgICAjIGJ1dCB1c2VkIHRvIG9ubHkgcHJpbnQgYSBiYXJlICIoc2FtZSBj"
    "aGVjayBhcyBXQS1IRFItMzk1KSIgc2VudGVuY2UKICAgICMgaW5zdGVhZCBvZiB0aGUgcmVhbCBjdXJsIGNvbW1hbmQgKyBy"
    "ZXNwb25zZSB0aGF0IGNoZWNrX3NlY3VyaXR5X2hlYWRlcnMoKQogICAgIyBhbHJlYWR5IGNhcHR1cmVkIGZvciB0aGF0IGV4"
    "YWN0IHJlcXVlc3QuIGhkcl9jdXJsX2Jsb2NrICh0aHJlYWRlZCBpbgogICAgIyBmcm9tIHJ1bl9mdWxsX3N1aXRlLCBzb3Vy"
    "Y2VkIGZyb20gY2hlY2tfc2VjdXJpdHlfaGVhZGVycygpJ3MgcmV0dXJuCiAgICAjIHZhbHVlKSBpcyB0aGF0IHNhbWUgcmVh"
    "bCBldmlkZW5jZSBibG9jaywgcmV1c2VkIGhlcmUgYXQgemVybyBleHRyYQogICAgIyByZXF1ZXN0IGNvc3QgaW5zdGVhZCBv"
    "ZiBzaGVsbGluZyBvdXQgdG8gY3VybCBhIHNlY29uZCB0aW1lLgogICAgaHN0c19mb3JfMjg5ID0gaGVhZGVyc19yZXN1bHQu"
    "aGVhZGVyKCJTdHJpY3QtVHJhbnNwb3J0LVNlY3VyaXR5IikgaWYgbm90IGhlYWRlcnNfcmVzdWx0LmVycm9yIGVsc2UgIiIK"
    "ICAgIGFkZChmdWxsX3VybCwgIldBLU9URy0yODkiLCAiQ29uZmlndXJhdGlvbiBUZXN0aW5nIiwgIlRlc3QgSFRUUCBTdHJp"
    "Y3QgVHJhbnNwb3J0IFNlY3VyaXR5IChIU1RTIHByZXNlbnQ/KSIsCiAgICAgICAgIk1lZGl1bSIsICJQMiIsICJQQVNTIiBp"
    "ZiBoc3RzX2Zvcl8yODkgZWxzZSAiRkFJTCIsCiAgICAgICAgKGYiU3RyaWN0LVRyYW5zcG9ydC1TZWN1cml0eToge2hzdHNf"
    "Zm9yXzI4OX0iIGlmIGhzdHNfZm9yXzI4OSBlbHNlCiAgICAgICAgICJDT05GSVJNRUQgQlk6IG5vIFN0cmljdC1UcmFuc3Bv"
    "cnQtU2VjdXJpdHkgaGVhZGVyIHByZXNlbnQgaW4gdGhlIHJlc3BvbnNlIGhlYWRlcnMgYmVsb3cuIikgKyBoZHJfY3VybF9i"
    "bG9jaykKCiAgICBjZHhtbCA9IHJhd19yZXF1ZXN0KGpvaW5fdGFyZ2V0KGJhc2UsICIvY3Jvc3Nkb21haW4ueG1sIiksICJH"
    "RVQiLCB0aW1lb3V0PWFyZ3MudGltZW91dCwgaW5zZWN1cmU9YXJncy5pbnNlY3VyZSkKICAgIGNhcCA9IHJhd19yZXF1ZXN0"
    "KGpvaW5fdGFyZ2V0KGJhc2UsICIvY2xpZW50YWNjZXNzcG9saWN5LnhtbCIpLCAiR0VUIiwgdGltZW91dD1hcmdzLnRpbWVv"
    "dXQsIGluc2VjdXJlPWFyZ3MuaW5zZWN1cmUpCiAgICBmaW5kaW5ncyA9IFtdCiAgICBpZiBub3QgY2R4bWwuZXJyb3IgYW5k"
    "IGNkeG1sLnN0YXR1cyA9PSAyMDA6CiAgICAgICAgd2lkZV9vcGVuID0gImRvbWFpbj1cIipcIiIgaW4gY2R4bWwudGV4dCgp"
    "IG9yICJkb21haW49JyonIiBpbiBjZHhtbC50ZXh0KCkKICAgICAgICBmaW5kaW5ncy5hcHBlbmQoZiJjcm9zc2RvbWFpbi54"
    "bWwgcHJlc2VudHsnIHdpdGggd2lsZGNhcmQgZG9tYWluIChGQUlMKScgaWYgd2lkZV9vcGVuIGVsc2UgJyd9IikKICAgIGlm"
    "IG5vdCBjYXAuZXJyb3IgYW5kIGNhcC5zdGF0dXMgPT0gMjAwOgogICAgICAgIHdpZGVfb3BlbjIgPSAiZG9tYWluPVwiKlwi"
    "IiBpbiBjYXAudGV4dCgpIG9yICJkb21haW49JyonIiBpbiBjYXAudGV4dCgpCiAgICAgICAgZmluZGluZ3MuYXBwZW5kKGYi"
    "Y2xpZW50YWNjZXNzcG9saWN5LnhtbCBwcmVzZW50eycgd2l0aCB3aWxkY2FyZCBkb21haW4gKEZBSUwpJyBpZiB3aWRlX29w"
    "ZW4yIGVsc2UgJyd9IikKICAgIGFueV93aWxkY2FyZCA9IGFueSgid2lsZGNhcmQiIGluIGYgZm9yIGYgaW4gZmluZGluZ3Mp"
    "CiAgICBhZGQoZnVsbF91cmwsICJXQS1PVEctMjkwIiwgIkNvbmZpZ3VyYXRpb24gVGVzdGluZyIsICJUZXN0IFJJQSBjcm9z"
    "cyBkb21haW4gcG9saWN5IChjcm9zc2RvbWFpbi54bWwgLyBjbGllbnRhY2Nlc3Nwb2xpY3kpIiwKICAgICAgICAiTWVkaXVt"
    "IiwgIlAyIiwgIkZBSUwiIGlmIGFueV93aWxkY2FyZCBlbHNlICgiSU5GTyIgaWYgZmluZGluZ3MgZWxzZSAiUEFTUyIpLAog"
    "ICAgICAgICI7ICIuam9pbihmaW5kaW5ncykgaWYgZmluZGluZ3MgZWxzZSAiTmVpdGhlciBjcm9zc2RvbWFpbi54bWwgbm9y"
    "IGNsaWVudGFjY2Vzc3BvbGljeS54bWwgZm91bmQgLSBub3QgYXBwbGljYWJsZS4iKQoKICAgIGFkZChmdWxsX3VybCwgIldB"
    "LU9URy0yOTEiLCAiQ29uZmlndXJhdGlvbiBUZXN0aW5nIiwgIlRlc3QgZmlsZSBwZXJtaXNzaW9ucyBvbiB3ZWIgc2VydmVy"
    "IiwKICAgICAgICAiTWVkaXVtIiwgIlAyIiwgIk1BTlVBTCIsCiAgICAgICAgIk5vdCB0ZXN0YWJsZSByZW1vdGVseSB3aXRo"
    "IGNlcnRhaW50eSAtIHNlZSB0aGUgLmdpdC8uc3ZuLy5EU19TdG9yZSBleHBvc3VyZSBjaGVjayAoV0EtU1MtMDU5KSBmb3Ig"
    "YSByZWxhdGVkICIKICAgICAgICAiYXV0b21hdGVkIHNpZ25hbCwgYnV0IGZ1bGwgZmlsZS1wZXJtaXNzaW9uIHJldmlldyBu"
    "ZWVkcyBzZXJ2ZXIgYWNjZXNzIG9yIGEgZGVkaWNhdGVkIG1pc2NvbmZpZyBzY2FubmVyLiIpCgogICAgY25hbWVfaW5mbyA9"
    "IF9yZXNvbHZlX2NuYW1lKGhvc3QpCiAgICBkYW5nbGluZ19oaW50ID0gTm9uZQogICAgaWYgY25hbWVfaW5mbyBhbmQgY25h"
    "bWVfaW5mb1sxXSBpcyBOb25lOgogICAgICAgIGZvciBzdmMgaW4gWyJnaXRodWIuaW8iLCAiaGVyb2t1YXBwLmNvbSIsICJz"
    "My5hbWF6b25hd3MuY29tIiwgImF6dXJld2Vic2l0ZXMubmV0IiwgImNsb3VkZnJvbnQubmV0IiwKICAgICAgICAgICAgICAg"
    "ICAgICAidHJhZmZpY21hbmFnZXIubmV0IiwgInJlYWR0aGVkb2NzLmlvIiwgInJlYWRtZS5pbyJdOgogICAgICAgICAgICBp"
    "ZiBzdmMgaW4gY25hbWVfaW5mb1swXToKICAgICAgICAgICAgICAgIGRhbmdsaW5nX2hpbnQgPSBzdmMKICAgICAgICAgICAg"
    "ICAgIGJyZWFrCiAgICBhZGQoZnVsbF91cmwsICJXQS1PVEctMjkyIiwgIkNvbmZpZ3VyYXRpb24gVGVzdGluZyIsICJUZXN0"
    "IHN1YmRvbWFpbiB0YWtlb3ZlciIsCiAgICAgICAgIkhpZ2giLCAiUDEiLAogICAgICAgICJGQUlMIiBpZiBkYW5nbGluZ19o"
    "aW50IGVsc2UgKCJNQU5VQUwiIGlmIG5vdCBjbmFtZV9pbmZvIGVsc2UgIlBBU1MiKSwKICAgICAgICAoZiJDTkFNRSAtPiB7"
    "Y25hbWVfaW5mb1swXX0sIHJlc29sdmVzOiB7J25vIChOWERPTUFJTi91bnJlc29sdmFibGUpJyBpZiBjbmFtZV9pbmZvIGFu"
    "ZCBjbmFtZV9pbmZvWzFdIGlzIE5vbmUgZWxzZSAneWVzJ30uIgogICAgICAgICArIChmIiBQb2ludHMgYXQgYSBrbm93biB0"
    "YWtlb3Zlci1wcm9uZSBzZXJ2aWNlICh7ZGFuZ2xpbmdfaGludH0pIGFuZCBkb2Vzbid0IHJlc29sdmUgLSBpbnZlc3RpZ2F0"
    "ZSBtYW51YWxseS4iIGlmIGRhbmdsaW5nX2hpbnQgZWxzZSAiIikpCiAgICAgICAgaWYgY25hbWVfaW5mbyBlbHNlICJObyBD"
    "TkFNRSBmb3VuZCBmb3IgdGhpcyBob3N0IChuc2xvb2t1cCB1bmF2YWlsYWJsZSBvciBob3N0IGhhcyBubyBDTkFNRSkgLSBm"
    "dWxsIHN1YmRvbWFpbiAiCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAiZW51bWVyYXRpb24gYWNyb3NzIHRoZSB3aG9s"
    "ZSBkb21haW4gc3RpbGwgbmVlZHMgYSBkZWRpY2F0ZWQgdG9vbCAoc3ViZmluZGVyL2FtYXNzICsgZG5zeCkuIikKCiAgICBh"
    "ZGQoZnVsbF91cmwsICJXQS1PVEctMjkzIiwgIkNvbmZpZ3VyYXRpb24gVGVzdGluZyIsICJUZXN0IGNsb3VkIHN0b3JhZ2Ug"
    "cGVybWlzc2lvbnMgKHB1YmxpYyBidWNrZXRzL2Jsb2JzKSIsCiAgICAgICAgIkhpZ2giLCAiUDEiLCAiTUFOVUFMIiwKICAg"
    "ICAgICAiU2VlIFdBLU9URy0yODIgZm9yIGJ1Y2tldHMgcmVmZXJlbmNlZCBieSB0aGlzIHBhZ2UgLSBjaGVjayBlYWNoIHdp"
    "dGggYSBIRUFEL0dFVC9saXN0IHJlcXVlc3QgbWFudWFsbHkgb3IgdmlhICIKICAgICAgICAiYSBidWNrZXQtcGVybWlzc2lv"
    "biB0b29sIChzM3NjYW5uZXIpLiBDYW4ndCBiZSB0ZXN0ZWQgZ2VuZXJpY2FsbHkgd2l0aG91dCBhIGJ1Y2tldCBuYW1lLiIp"
    "CgogICAgY3NwX2Zvcl8yOTQgPSBoZWFkZXJzX3Jlc3VsdC5oZWFkZXIoIkNvbnRlbnQtU2VjdXJpdHktUG9saWN5IikgaWYg"
    "bm90IGhlYWRlcnNfcmVzdWx0LmVycm9yIGVsc2UgIiIKICAgIGlmIG5vdCBjc3BfZm9yXzI5NDoKICAgICAgICBjc3AyOTRf"
    "cmVzdWx0LCBjc3AyOTRfZXZpZGVuY2UgPSAiRkFJTCIsICgKICAgICAgICAgICAgIkNPTkZJUk1FRCBCWTogbm8gQ29udGVu"
    "dC1TZWN1cml0eS1Qb2xpY3kgaGVhZGVyIHByZXNlbnQgaW4gdGhlIHJlc3BvbnNlIGhlYWRlcnMgYmVsb3cuIikKICAgIGVs"
    "aWYgInVuc2FmZS1pbmxpbmUiIGluIGNzcF9mb3JfMjk0OgogICAgICAgIGNzcDI5NF9yZXN1bHQsIGNzcDI5NF9ldmlkZW5j"
    "ZSA9ICJGQUlMIiwgKAogICAgICAgICAgICBmIkNPTkZJUk1FRCBCWTogQ1NQIGNvbnRhaW5zICd1bnNhZmUtaW5saW5lJyAt"
    "IGZ1bGwgaGVhZGVyIHZhbHVlOiB7Y3NwX2Zvcl8yOTRbOjMwMF19IikKICAgIGVsc2U6CiAgICAgICAgY3NwMjk0X3Jlc3Vs"
    "dCwgY3NwMjk0X2V2aWRlbmNlID0gIlBBU1MiLCBmIkNTUDoge2NzcF9mb3JfMjk0WzozMDBdfSIKICAgIGFkZChmdWxsX3Vy"
    "bCwgIldBLU9URy0yOTQiLCAiQ29uZmlndXJhdGlvbiBUZXN0aW5nIiwgIlRlc3QgY29udGVudCBzZWN1cml0eSBwb2xpY3kg"
    "KENTUCBoZWFkZXIgYW5hbHlzaXMpIiwKICAgICAgICAiTWVkaXVtIiwgIlAyIiwgY3NwMjk0X3Jlc3VsdCwgY3NwMjk0X2V2"
    "aWRlbmNlICsgaGRyX2N1cmxfYmxvY2spCgoKZGVmIF9yZXNvbHZlX2NuYW1lKGhvc3QpOgogICAgIiIiUmV0dXJucyAoY25h"
    "bWVfdGFyZ2V0LCByZXNvbHZlZF9pcF9vcl9Ob25lKSB1c2luZyBuc2xvb2t1cCwgb3IgTm9uZSBpZiB1bmF2YWlsYWJsZS4i"
    "IiIKICAgIHRyeToKICAgICAgICBvdXQgPSBzdWJwcm9jZXNzLnJ1bihbIm5zbG9va3VwIiwgIi10eXBlPUNOQU1FIiwgaG9z"
    "dF0sIGNhcHR1cmVfb3V0cHV0PVRydWUsIHRpbWVvdXQ9NSwKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdGV4dD1U"
    "cnVlKS5zdGRvdXQKICAgICAgICBtID0gcmUuc2VhcmNoKHIiY2Fub25pY2FsIG5hbWUgPSAoXFMrKVwuPyIsIG91dCkKICAg"
    "ICAgICBpZiBub3QgbToKICAgICAgICAgICAgcmV0dXJuIE5vbmUKICAgICAgICBjbmFtZSA9IG0uZ3JvdXAoMSkucnN0cmlw"
    "KCIuIikKICAgICAgICB0cnk6CiAgICAgICAgICAgIHNvY2tldC5nZXRob3N0YnluYW1lKGNuYW1lKQogICAgICAgICAgICBy"
    "ZXR1cm4gKGNuYW1lLCBUcnVlKQogICAgICAgIGV4Y2VwdCBFeGNlcHRpb246CiAgICAgICAgICAgIHJldHVybiAoY25hbWUs"
    "IE5vbmUpCiAgICBleGNlcHQgRXhjZXB0aW9uOgogICAgICAgIHJldHVybiBOb25lCgoKIyAtLS0tLS0tLS0tLS0tLS0tLS0t"
    "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQojIDcuIFNlc3Npb24gTWFu"
    "YWdlbWVudCBUZXN0aW5nIC0gV0EtT1RHLTMxNS4uMzIzCiMgLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t"
    "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KCmRlZiBjaGVja19zZXNzaW9uX21hbmFnZW1lbnQoZnVs"
    "bF91cmwsIGhlYWRlcnNfcmVzdWx0LCBhcmdzKToKICAgIGlmIGhlYWRlcnNfcmVzdWx0LmVycm9yOgogICAgICAgIGZvciBj"
    "aWQsIG5hbWUgaW4gWwogICAgICAgICAgICAoIldBLU9URy0zMTUiLCAiVGVzdCBzZXNzaW9uIG1hbmFnZW1lbnQgc2NoZW1h"
    "ICh0b2tlbiBhbmFseXNpcykiKSwKICAgICAgICAgICAgKCJXQS1PVEctMzE2IiwgIlRlc3QgY29va2llIGF0dHJpYnV0ZXMg"
    "KFNlY3VyZSwgSHR0cE9ubHksIFNhbWVTaXRlLCBQYXRoKSIpLAogICAgICAgICAgICAoIldBLU9URy0zMTciLCAiVGVzdCBz"
    "ZXNzaW9uIGZpeGF0aW9uICh0b2tlbiByZWN5Y2xlZCBhZnRlciBsb2dpbikiKSwKICAgICAgICAgICAgKCJXQS1PVEctMzE4"
    "IiwgIlRlc3QgZXhwb3NlZCBzZXNzaW9uIHZhcmlhYmxlcyAoaW4gVVJMLCBsb2dzKSIpLAogICAgICAgICAgICAoIldBLU9U"
    "Ry0zMTkiLCAiVGVzdCBDU1JGIHByb3RlY3Rpb24gKHRva2VuIHZhbGlkYXRpb24sIFNhbWVTaXRlKSIpLAogICAgICAgICAg"
    "ICAoIldBLU9URy0zMjAiLCAiVGVzdCBsb2dvdXQgZnVuY3Rpb25hbGl0eSAoc2VydmVyLXNpZGUgc2Vzc2lvbiBpbnZhbGlk"
    "YXRpb24pIiksCiAgICAgICAgICAgICgiV0EtT1RHLTMyMSIsICJUZXN0IHNlc3Npb24gdGltZW91dCAoaWRsZSArIGFic29s"
    "dXRlKSIpLAogICAgICAgICAgICAoIldBLU9URy0zMjIiLCAiVGVzdCBzZXNzaW9uIHB1enpsaW5nIC8gb3ZlcmxvYWRpbmci"
    "KSwKICAgICAgICAgICAgKCJXQS1PVEctMzIzIiwgIlRlc3Qgc2Vzc2lvbiBoaWphY2tpbmcgKHRva2VuIHRoZWZ0IHZpYSBY"
    "U1MvTWl0TSkiKSwKICAgICAgICBdOgogICAgICAgICAgICBhZGQoZnVsbF91cmwsIGNpZCwgIlNlc3Npb24gTWFuYWdlbWVu"
    "dCBUZXN0aW5nIiwgbmFtZSwgIkhpZ2giLCAiUDEiLCAiRVJST1IiLCBoZWFkZXJzX3Jlc3VsdC5lcnJvcikKICAgICAgICBy"
    "ZXR1cm4KCiAgICAjIFJlYWwgIiQgY3VybCAuLi4iIGNvbW1hbmQgKyB0aGUgYWN0dWFsIFNldC1Db29raWUgaGVhZGVyKHMp"
    "IGl0IGdvdAogICAgIyBiYWNrLCBhdHRhY2hlZCBhcyBldmlkZW5jZSBmb3IgdGhlIHR3byBjaGVja3MgYmVsb3cgdGhhdCBh"
    "cmUKICAgICMgREVSSVZFRCBmcm9tIHRob3NlIGhlYWRlcnMgKFdBLU9URy0zMTUvMzE2KSAtIGZpeGVkIGFmdGVyIGJlaW5n"
    "CiAgICAjIHJlcG9ydGVkIGRpcmVjdGx5LCB3aXRoIGEgc2NyZWVuc2hvdCBzaG93aW5nIGEgVnVsbmVyYWJsZSBjb29raWUt"
    "CiAgICAjIGF0dHJpYnV0ZXMgZmluZGluZyB3aXRoIG5vIG91dHB1dCBjYXB0dXJlZDogIm4gbyBvdXQgcHV0IGNhcHR1cmVk"
    "CiAgICAjIHlvdSBjYW4gdXNlIGN1cmwgaGVkZXJzIGNvbW1hbmQgdG8gY29sbGVjdCB0aGUgY29va2llcyBvdXR1dCIuCiAg"
    "ICAjIFByZXZpb3VzbHkgdGhpcyBmdW5jdGlvbiBvbmx5IGV2ZXIgcmV1c2VkIGBoZWFkZXJzX3Jlc3VsdGAgKHRoZQogICAg"
    "IyBQeXRob24taW50ZXJuYWwgSHR0cFJlc3VsdCBvYmplY3QgZnJvbSBjaGVja19zZWN1cml0eV9oZWFkZXJzKCkpIHRvCiAg"
    "ICAjIERFQ0lERSB0aGUgUEFTUy9GQUlMIHZlcmRpY3QsIGJ1dCBuZXZlciByYW4vYXR0YWNoZWQgdGhlIGFjdHVhbCBjdXJs"
    "CiAgICAjIGNvbW1hbmQrb3V0cHV0IHRoZSBvdGhlciBIVFRQLWhlYWRlciBjaGVja3MgKFdBLUhEUi0zOTIgZXRjLikgc2hv"
    "dwogICAgIyBhcyBldmlkZW5jZSAtIHNvIGEgY29va2llLWF0dHJpYnV0ZXMgRkFJTCBoYWQgbm8gcmVwcm9kdWNpYmxlCiAg"
    "ICAjIGNvbW1hbmQgYSByZXZpZXdlciBjb3VsZCByZS1ydW4gdG8gc2VlIHRoZSByZWFsIFNldC1Db29raWUgdmFsdWUocykK"
    "ICAgICMgdGhlbXNlbHZlcywganVzdCB0aGUgZGVyaXZlZCAiWCBtaXNzaW5nIFNlY3VyZS9IdHRwT25seSIgc2VudGVuY2Uu"
    "CiAgICBjdXJsX3Jlc3VsdCA9IE5vbmUgaWYgZ2V0YXR0cihhcmdzLCAibm9fY2xpX3Rvb2xzIiwgRmFsc2UpIGVsc2UgcnVu"
    "X2N1cmxfaGVhZGVycygKICAgICAgICBmdWxsX3VybCwgdGltZW91dD1hcmdzLnRpbWVvdXQsIGluc2VjdXJlPWFyZ3MuaW5z"
    "ZWN1cmUpCiAgICBjdXJsX2Jsb2NrID0gX2Zvcm1hdF9jbWRfYmxvY2soY3VybF9yZXN1bHRbMF0sIGN1cmxfcmVzdWx0WzFd"
    "KSBpZiBjdXJsX3Jlc3VsdCBlbHNlICIiCgogICAgc2V0X2Nvb2tpZXMgPSBbdiBmb3IgaywgdiBpbiBoZWFkZXJzX3Jlc3Vs"
    "dC5oZWFkZXJzLml0ZW1zKCkgaWYgay5sb3dlcigpID09ICJzZXQtY29va2llIl0KICAgIGNvb2tpZV9uYW1lcyA9IFtyZS5t"
    "YXRjaChyIihbXj1dKyk9IiwgYykuZ3JvdXAoMSkgZm9yIGMgaW4gc2V0X2Nvb2tpZXMgaWYgcmUubWF0Y2gociIoW149XSsp"
    "PSIsIGMpXQogICAgYWRkKGZ1bGxfdXJsLCAiV0EtT1RHLTMxNSIsICJTZXNzaW9uIE1hbmFnZW1lbnQgVGVzdGluZyIsICJU"
    "ZXN0IHNlc3Npb24gbWFuYWdlbWVudCBzY2hlbWEgKHRva2VuIGFuYWx5c2lzKSIsCiAgICAgICAgIkhpZ2giLCAiUDEiLCAi"
    "SU5GTyIgaWYgY29va2llX25hbWVzIGVsc2UgIk1BTlVBTCIsCiAgICAgICAgKGYiQ29va2llKHMpIHNlZW4gb24gdGhpcyBy"
    "ZXNwb25zZTogeycsICcuam9pbihjb29raWVfbmFtZXMpfS4gRnVsbCBlbnRyb3B5L3ByZWRpY3RhYmlsaXR5IGFuYWx5c2lz"
    "IG5lZWRzICIKICAgICAgICAgIm11bHRpcGxlIHNhbXBsZXMgYWNyb3NzIHNlc3Npb25zIC0gb3V0IG9mIHNjb3BlIGZvciBh"
    "IHNpbmdsZSByZXF1ZXN0LiIgaWYgY29va2llX25hbWVzIGVsc2UKICAgICAgICAgIk5vIFNldC1Db29raWUgb24gdGhpcyBy"
    "ZXNwb25zZSAtIHNlc3Npb24gbWF5IGJlIGlzc3VlZCBhZnRlciBsb2dpbjsgcmUtcnVuIHRoaXMgY2hlY2sgb24gYW4gYXV0"
    "aGVudGljYXRlZCBwYWdlLiIpCiAgICAgICAgKyBjdXJsX2Jsb2NrKQoKICAgIGlmIHNldF9jb29raWVzOgogICAgICAgIGlz"
    "c3VlcyA9IFtdCiAgICAgICAgaXNfaHR0cHMgPSBmdWxsX3VybC5zdGFydHN3aXRoKCJodHRwcyIpCiAgICAgICAgZm9yIGMg"
    "aW4gc2V0X2Nvb2tpZXM6CiAgICAgICAgICAgIG5hbWUgPSByZS5tYXRjaChyIihbXj1dKyk9IiwgYykuZ3JvdXAoMSkKICAg"
    "ICAgICAgICAgbWlzc2luZyA9IFtdCiAgICAgICAgICAgIGlmIGlzX2h0dHBzIGFuZCAic2VjdXJlIiBub3QgaW4gYy5sb3dl"
    "cigpOgogICAgICAgICAgICAgICAgbWlzc2luZy5hcHBlbmQoIlNlY3VyZSIpCiAgICAgICAgICAgIGlmICJodHRwb25seSIg"
    "bm90IGluIGMubG93ZXIoKToKICAgICAgICAgICAgICAgIG1pc3NpbmcuYXBwZW5kKCJIdHRwT25seSIpCiAgICAgICAgICAg"
    "IGlmICJzYW1lc2l0ZSIgbm90IGluIGMubG93ZXIoKToKICAgICAgICAgICAgICAgIG1pc3NpbmcuYXBwZW5kKCJTYW1lU2l0"
    "ZSIpCiAgICAgICAgICAgIGlmIG1pc3Npbmc6CiAgICAgICAgICAgICAgICBpc3N1ZXMuYXBwZW5kKGYie25hbWV9IG1pc3Np"
    "bmcgeycvJy5qb2luKG1pc3NpbmcpfSIpCiAgICAgICAgYWRkKGZ1bGxfdXJsLCAiV0EtT1RHLTMxNiIsICJTZXNzaW9uIE1h"
    "bmFnZW1lbnQgVGVzdGluZyIsICJUZXN0IGNvb2tpZSBhdHRyaWJ1dGVzIChTZWN1cmUsIEh0dHBPbmx5LCBTYW1lU2l0ZSwg"
    "UGF0aCkiLAogICAgICAgICAgICAiTWVkaXVtIiwgIlAyIiwgIkZBSUwiIGlmIGlzc3VlcyBlbHNlICJQQVNTIiwKICAgICAg"
    "ICAgICAgKCI7ICIuam9pbihpc3N1ZXMpIGlmIGlzc3VlcyBlbHNlIGYiQWxsIGNvb2tpZShzKSAoeycsICcuam9pbihjb29r"
    "aWVfbmFtZXMpfSkgaGF2ZSBTZWN1cmUvSHR0cE9ubHkvU2FtZVNpdGUgc2V0IGFwcHJvcHJpYXRlbHkuIikKICAgICAgICAg"
    "ICAgKyBjdXJsX2Jsb2NrKQogICAgZWxzZToKICAgICAgICBhZGQoZnVsbF91cmwsICJXQS1PVEctMzE2IiwgIlNlc3Npb24g"
    "TWFuYWdlbWVudCBUZXN0aW5nIiwgIlRlc3QgY29va2llIGF0dHJpYnV0ZXMgKFNlY3VyZSwgSHR0cE9ubHksIFNhbWVTaXRl"
    "LCBQYXRoKSIsCiAgICAgICAgICAgICJNZWRpdW0iLCAiUDIiLCAiSU5GTyIsICJObyBjb29raWVzIHNldCBvbiB0aGlzIHJl"
    "c3BvbnNlIHRvIGV2YWx1YXRlLiIgKyBjdXJsX2Jsb2NrKQoKICAgIGFkZChmdWxsX3VybCwgIldBLU9URy0zMTciLCAiU2Vz"
    "c2lvbiBNYW5hZ2VtZW50IFRlc3RpbmciLCAiVGVzdCBzZXNzaW9uIGZpeGF0aW9uICh0b2tlbiByZWN5Y2xlZCBhZnRlciBs"
    "b2dpbikiLAogICAgICAgICJIaWdoIiwgIlAxIiwgIk1BTlVBTCIsICJOZWVkcyBhbiBhdXRoZW50aWNhdGVkIGxvZ2luIGZs"
    "b3cgKGNhcHR1cmUgcHJlLWxvZ2luIHZzIHBvc3QtbG9naW4gc2Vzc2lvbiB0b2tlbikgLSBub3QgdGVzdGFibGUgZnJvbSBh"
    "IHNpbmdsZSB1bmF1dGhlbnRpY2F0ZWQgcmVxdWVzdC4iKQoKICAgIHBhcnNlZCA9IHVybHBhcnNlKGZ1bGxfdXJsKQogICAg"
    "c2Vzc2lvbl9pbl91cmwgPSBib29sKHJlLnNlYXJjaChyIihzaWR8c2Vzc2lvbnx0b2tlbnxwaHBzZXNzaWR8anNlc3Npb25p"
    "ZCk9IiwgcGFyc2VkLnF1ZXJ5LCByZS5JKSkKICAgIGFkZChmdWxsX3VybCwgIldBLU9URy0zMTgiLCAiU2Vzc2lvbiBNYW5h"
    "Z2VtZW50IFRlc3RpbmciLCAiVGVzdCBleHBvc2VkIHNlc3Npb24gdmFyaWFibGVzIChpbiBVUkwsIGxvZ3MpIiwKICAgICAg"
    "ICAiTWVkaXVtIiwgIlAyIiwgIkZBSUwiIGlmIHNlc3Npb25faW5fdXJsIGVsc2UgIlBBU1MiLAogICAgICAgIGYiUXVlcnkg"
    "c3RyaW5nOiB7cGFyc2VkLnF1ZXJ5IG9yICcobm9uZSknfS4iICsKICAgICAgICAoIiBTZXNzaW9uLWxpa2UgcGFyYW1ldGVy"
    "IG5hbWUgZm91bmQgaW4gdGhlIFVSTCAtIHNlc3Npb24gdG9rZW5zIGluIFVSTHMgbGVhayB2aWEgbG9ncy9yZWZlcnJlci9o"
    "aXN0b3J5LiIgaWYgc2Vzc2lvbl9pbl91cmwgZWxzZSAiIikpCgogICAgYm9keV90ZXh0ID0gaGVhZGVyc19yZXN1bHQudGV4"
    "dCgpCiAgICBmb3JtcyA9IHJlLmZpbmRhbGwociI8Zm9ybVxiW14+XSo+KC4qPyk8L2Zvcm0+IiwgYm9keV90ZXh0LCByZS5J"
    "IHwgcmUuUykKICAgIGlmIGZvcm1zOgogICAgICAgIHRva2VuX3BhdHRlcm4gPSByZS5jb21waWxlKHInbmFtZT1bIlwnXVte"
    "IlwnXSooY3NyZnx0b2tlbnxhdXRoZW50aWNpdHkpW14iXCddKlsiXCddJywgcmUuSSkKICAgICAgICBmb3Jtc19taXNzaW5n"
    "X3Rva2VuID0gc3VtKDEgZm9yIGYgaW4gZm9ybXMgaWYgbm90IHRva2VuX3BhdHRlcm4uc2VhcmNoKGYpKQogICAgICAgIGFk"
    "ZChmdWxsX3VybCwgIldBLU9URy0zMTkiLCAiU2Vzc2lvbiBNYW5hZ2VtZW50IFRlc3RpbmciLCAiVGVzdCBDU1JGIHByb3Rl"
    "Y3Rpb24gKHRva2VuIHZhbGlkYXRpb24sIFNhbWVTaXRlKSIsCiAgICAgICAgICAgICJIaWdoIiwgIlAxIiwgIkZBSUwiIGlm"
    "IGZvcm1zX21pc3NpbmdfdG9rZW4gZWxzZSAiUEFTUyIsCiAgICAgICAgICAgIGYie2xlbihmb3Jtcyl9IDxmb3JtPiB0YWco"
    "cykgZm91bmQgb24gdGhpcyBwYWdlLCB7Zm9ybXNfbWlzc2luZ190b2tlbn0gd2l0aCBubyBvYnZpb3VzIENTUkYvdG9rZW4g"
    "aGlkZGVuICIKICAgICAgICAgICAgImZpZWxkIGJ5IG5hbWUuIFRoaXMgaXMgYSBuYW1pbmcgaGV1cmlzdGljIG9ubHkgLSBh"
    "IGZvcm0gY2FuIHN0aWxsIGJlIHByb3RlY3RlZCB2aWEgU2FtZVNpdGUgY29va2llcyBvciBhICIKICAgICAgICAgICAgImN1"
    "c3RvbSBoZWFkZXIgY2hlY2tlZCBzZXJ2ZXItc2lkZTsgdmVyaWZ5IG1hbnVhbGx5IGJlZm9yZSByZXBvcnRpbmcuIikKICAg"
    "IGVsc2U6CiAgICAgICAgYWRkKGZ1bGxfdXJsLCAiV0EtT1RHLTMxOSIsICJTZXNzaW9uIE1hbmFnZW1lbnQgVGVzdGluZyIs"
    "ICJUZXN0IENTUkYgcHJvdGVjdGlvbiAodG9rZW4gdmFsaWRhdGlvbiwgU2FtZVNpdGUpIiwKICAgICAgICAgICAgIkhpZ2gi"
    "LCAiUDEiLCAiSU5GTyIsICJObyA8Zm9ybT4gdGFncyBmb3VuZCBvbiB0aGlzIHBhZ2UgdG8gaW5zcGVjdC4iKQoKICAgIGZv"
    "ciBjaWQsIG5hbWUgaW4gWwogICAgICAgICgiV0EtT1RHLTMyMCIsICJUZXN0IGxvZ291dCBmdW5jdGlvbmFsaXR5IChzZXJ2"
    "ZXItc2lkZSBzZXNzaW9uIGludmFsaWRhdGlvbikiKSwKICAgICAgICAoIldBLU9URy0zMjEiLCAiVGVzdCBzZXNzaW9uIHRp"
    "bWVvdXQgKGlkbGUgKyBhYnNvbHV0ZSkiKSwKICAgICAgICAoIldBLU9URy0zMjIiLCAiVGVzdCBzZXNzaW9uIHB1enpsaW5n"
    "IC8gb3ZlcmxvYWRpbmciKSwKICAgICAgICAoIldBLU9URy0zMjMiLCAiVGVzdCBzZXNzaW9uIGhpamFja2luZyAodG9rZW4g"
    "dGhlZnQgdmlhIFhTUy9NaXRNKSIpLAogICAgXToKICAgICAgICBhZGQoZnVsbF91cmwsIGNpZCwgIlNlc3Npb24gTWFuYWdl"
    "bWVudCBUZXN0aW5nIiwgbmFtZSwgIkhpZ2giLCAiUDEiLCAiTUFOVUFMIiwKICAgICAgICAgICAgIk5lZWRzIGFuIGF1dGhl"
    "bnRpY2F0ZWQgc2Vzc2lvbiBhbmQgYSBtdWx0aS1zdGVwIGludGVyYWN0aW9uIG92ZXIgdGltZSAtIG5vdCB0ZXN0YWJsZSBm"
    "cm9tIGEgc2luZ2xlIHVuYXV0aGVudGljYXRlZCByZXF1ZXN0LiIpCgoKIyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t"
    "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQojIDdiLiBDbGllbnQtU2lkZSBUZXN0aW5n"
    "IC0gV0EtT1RHLTM2NiAoc3RhdGljIGFuYWx5c2lzIG9ubHkgLSBubyBicm93c2VyIEpTCiMgICAgIGV4ZWN1dGlvbiwgc28g"
    "dGhpcyBpcyBhdXRvbWF0YWJsZSB3aXRob3V0IGV2ZXIgbmVlZGluZyBhIGxvZ2luOiAibmV2ZXIKIyAgICAgdGFrZSB0aGUg"
    "Y3JlZGV0aWxzIGFsc28gdG8gbmF2aWdhdGUgaW5zaWRlIikKIyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t"
    "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQoKX1NFTlNJVElWRV9LRVlfUEFUVEVSTiA9IHJlLmNv"
    "bXBpbGUoCiAgICByIih0b2tlbnxqd3R8YXV0aHxzZXNzaW9ufHBhc3N3b3JkfHBhc3N3ZHxzZWNyZXR8YXBpa2V5fGFwaV9r"
    "ZXl8c3NufGNyZWRpdGNhcmR8Y2FyZF8/bnVtYmVyfFxicGluXGIpIiwKICAgIHJlLklHTk9SRUNBU0UpCl9TVE9SQUdFX0NB"
    "TExfUEFUVEVSTiA9IHJlLmNvbXBpbGUoCiAgICByIlxiKD86bG9jYWxTdG9yYWdlfHNlc3Npb25TdG9yYWdlKVxzKlwuXHMq"
    "c2V0SXRlbVxzKlwoXHMqKFsnXCJdKSguKj8pXDEiLCByZS5JR05PUkVDQVNFKQpfU1RPUkFHRV9VU0FHRV9QQVRURVJOID0g"
    "cmUuY29tcGlsZShyIlxiKD86bG9jYWxTdG9yYWdlfHNlc3Npb25TdG9yYWdlKVxiIiwgcmUuSUdOT1JFQ0FTRSkKCgpkZWYg"
    "Y2hlY2tfY2xpZW50X3N0b3JhZ2UoZnVsbF91cmwsIGhlYWRlcnNfcmVzdWx0LCBhcmdzKToKICAgICIiIldBLU9URy0zNjYg"
    "LSBUZXN0IGxvY2FsIHN0b3JhZ2UgLyBzZXNzaW9uU3RvcmFnZSBmb3Igc2Vuc2l0aXZlIGRhdGEuCiAgICBTY2FucyB0aGUg"
    "cGFnZSdzIGlubGluZSA8c2NyaXB0PiBibG9ja3MgYW5kIHNhbWUtb3JpZ2luIGV4dGVybmFsIEpTIGl0CiAgICBsaW5rcyB0"
    "byBmb3IgbG9jYWxTdG9yYWdlL3Nlc3Npb25TdG9yYWdlLnNldEl0ZW0oKSBjYWxscywgZmxhZ2dpbmcKICAgIHNlbnNpdGl2"
    "ZS1sb29raW5nIGtleSBuYW1lcyAodG9rZW4vc2Vzc2lvbi9hdXRoL3Bhc3N3b3JkLy4uLikuIENhbid0CiAgICBzZWUgc3Rv"
    "cmFnZSB3cml0dGVuIG9ubHkgYWZ0ZXIgbG9naW4gb3IgYnkgb2JmdXNjYXRlZC9idW5kbGVkIGNvZGUgLQogICAgdGhvc2Ug"
    "Y2FzZXMgZmFsbCBiYWNrIHRvIE1BTlVBTC9JTkZPIHJhdGhlciB0aGFuIGEgZmFsc2UgUEFTUy4iIiIKICAgIGlmIGhlYWRl"
    "cnNfcmVzdWx0LmVycm9yOgogICAgICAgIGFkZChmdWxsX3VybCwgIldBLU9URy0zNjYiLCAiQ2xpZW50LVNpZGUgVGVzdGlu"
    "ZyIsICJUZXN0IGxvY2FsIHN0b3JhZ2UgLyBzZXNzaW9uU3RvcmFnZSBmb3Igc2Vuc2l0aXZlIGRhdGEiLAogICAgICAgICAg"
    "ICAiTWVkaXVtIiwgIlAyIiwgIkVSUk9SIiwgaGVhZGVyc19yZXN1bHQuZXJyb3IpCiAgICAgICAgcmV0dXJuCgogICAgYm9k"
    "eV90ZXh0ID0gaGVhZGVyc19yZXN1bHQudGV4dCgpCiAgICBjb21iaW5lZF90ZXh0ID0gYm9keV90ZXh0CiAgICBjb21iaW5l"
    "ZF9zb3VyY2VzID0gWyJwYWdlIEhUTUwvaW5saW5lIHNjcmlwdHMiXQoKICAgIHNjcmlwdF9zcmNzID0gcmUuZmluZGFsbChy"
    "JzxzY3JpcHRbXj5dK3NyYz1bIlwnXShbXiJcJ10rKVsiXCddJywgYm9keV90ZXh0LCByZS5JR05PUkVDQVNFKQogICAgcGFn"
    "ZV9ob3N0ID0gdXJscGFyc2UoZnVsbF91cmwpLmhvc3RuYW1lCiAgICBmZXRjaGVkID0gMAogICAgZm9yIHNyYyBpbiBzY3Jp"
    "cHRfc3JjczoKICAgICAgICBpZiBmZXRjaGVkID49IDU6CiAgICAgICAgICAgIGJyZWFrCiAgICAgICAganNfdXJsID0gdXJs"
    "am9pbihmdWxsX3VybCwgc3JjKQogICAgICAgIGlmIHVybHBhcnNlKGpzX3VybCkuaG9zdG5hbWUgIT0gcGFnZV9ob3N0Ogog"
    "ICAgICAgICAgICBjb250aW51ZSAgIyBzYW1lLW9yaWdpbiBvbmx5IC0gbm8gcmVhc29uIHRvIHB1bGwgdGhpcmQtcGFydHkv"
    "Q0ROIEpTIGZvciB0aGlzIGhldXJpc3RpYwogICAgICAgIHJfanMgPSByYXdfcmVxdWVzdChqc191cmwsICJHRVQiLCB0aW1l"
    "b3V0PWFyZ3MudGltZW91dCwgaW5zZWN1cmU9YXJncy5pbnNlY3VyZSkKICAgICAgICBmZXRjaGVkICs9IDEKICAgICAgICBp"
    "ZiBub3Qgcl9qcy5lcnJvciBhbmQgcl9qcy5zdGF0dXMgYW5kIHJfanMuc3RhdHVzIDwgNDAwOgogICAgICAgICAgICBjb21i"
    "aW5lZF90ZXh0ICs9ICJcbiIgKyByX2pzLnRleHQoKQogICAgICAgICAgICBjb21iaW5lZF9zb3VyY2VzLmFwcGVuZChqc191"
    "cmwpCgogICAgbWF0Y2hlcyA9IF9TVE9SQUdFX0NBTExfUEFUVEVSTi5maW5kYWxsKGNvbWJpbmVkX3RleHQpCiAgICBrZXlz"
    "X2ZvdW5kID0gW21bMV0gZm9yIG0gaW4gbWF0Y2hlc10KICAgIHNlbnNpdGl2ZV9rZXlzID0gc29ydGVkKHNldChrIGZvciBr"
    "IGluIGtleXNfZm91bmQgaWYgX1NFTlNJVElWRV9LRVlfUEFUVEVSTi5zZWFyY2goaykpKQogICAgYW55X3VzYWdlID0gYm9v"
    "bChfU1RPUkFHRV9VU0FHRV9QQVRURVJOLnNlYXJjaChjb21iaW5lZF90ZXh0KSkKICAgIHNvdXJjZXNfc3RyID0gIiwgIi5q"
    "b2luKGNvbWJpbmVkX3NvdXJjZXMpCgogICAgaWYgc2Vuc2l0aXZlX2tleXM6CiAgICAgICAgYWRkKGZ1bGxfdXJsLCAiV0Et"
    "T1RHLTM2NiIsICJDbGllbnQtU2lkZSBUZXN0aW5nIiwgIlRlc3QgbG9jYWwgc3RvcmFnZSAvIHNlc3Npb25TdG9yYWdlIGZv"
    "ciBzZW5zaXRpdmUgZGF0YSIsCiAgICAgICAgICAgICJNZWRpdW0iLCAiUDIiLCAiRkFJTCIsCiAgICAgICAgICAgIGYibG9j"
    "YWxTdG9yYWdlL3Nlc3Npb25TdG9yYWdlLnNldEl0ZW0oKSBjYWxsKHMpIHdpdGggc2Vuc2l0aXZlLWxvb2tpbmcga2V5IG5h"
    "bWUocykgZm91bmQ6ICIKICAgICAgICAgICAgZiJ7JywgJy5qb2luKHNlbnNpdGl2ZV9rZXlzKX0uIFNjYW5uZWQ6IHtzb3Vy"
    "Y2VzX3N0cn0uIENvbmZpcm0gaW4gYnJvd3NlciBEZXZUb29scyA+IEFwcGxpY2F0aW9uID4gIgogICAgICAgICAgICAiU3Rv"
    "cmFnZSB0aGF0IHRoZSBWQUxVRSAobm90IGp1c3QgdGhlIGtleSBuYW1lKSBhY3R1YWxseSBob2xkcyBzZW5zaXRpdmUgZGF0"
    "YSBiZWZvcmUgcmVwb3J0aW5nLiIpCiAgICBlbGlmIGtleXNfZm91bmQ6CiAgICAgICAgYWRkKGZ1bGxfdXJsLCAiV0EtT1RH"
    "LTM2NiIsICJDbGllbnQtU2lkZSBUZXN0aW5nIiwgIlRlc3QgbG9jYWwgc3RvcmFnZSAvIHNlc3Npb25TdG9yYWdlIGZvciBz"
    "ZW5zaXRpdmUgZGF0YSIsCiAgICAgICAgICAgICJNZWRpdW0iLCAiUDIiLCAiSU5GTyIsCiAgICAgICAgICAgIGYibG9jYWxT"
    "dG9yYWdlL3Nlc3Npb25TdG9yYWdlLnNldEl0ZW0oKSBjYWxsKHMpIGZvdW5kIGJ1dCBrZXkgbmFtZShzKSBkb24ndCBtYXRj"
    "aCBjb21tb24gc2Vuc2l0aXZlICIKICAgICAgICAgICAgZiJwYXR0ZXJuczogeycsICcuam9pbihzb3J0ZWQoc2V0KGtleXNf"
    "Zm91bmQpKVs6MTVdKX0uIFNjYW5uZWQ6IHtzb3VyY2VzX3N0cn0uIFN0YXRpYyBrZXktbmFtZSAiCiAgICAgICAgICAgICJt"
    "YXRjaGluZyBvbmx5IC0gdmVyaWZ5IGFjdHVhbCBzdG9yZWQgdmFsdWVzIG1hbnVhbGx5LiIpCiAgICBlbGlmIGFueV91c2Fn"
    "ZToKICAgICAgICBhZGQoZnVsbF91cmwsICJXQS1PVEctMzY2IiwgIkNsaWVudC1TaWRlIFRlc3RpbmciLCAiVGVzdCBsb2Nh"
    "bCBzdG9yYWdlIC8gc2Vzc2lvblN0b3JhZ2UgZm9yIHNlbnNpdGl2ZSBkYXRhIiwKICAgICAgICAgICAgIk1lZGl1bSIsICJQ"
    "MiIsICJNQU5VQUwiLAogICAgICAgICAgICBmImxvY2FsU3RvcmFnZS9zZXNzaW9uU3RvcmFnZSBBUEkgaXMgcmVmZXJlbmNl"
    "ZCBpbiBzY2FubmVkIHNvdXJjZSAoe3NvdXJjZXNfc3RyfSkgYnV0IHdpdGggYSBkeW5hbWljLyIKICAgICAgICAgICAgIm5v"
    "bi1saXRlcmFsIGtleSBuYW1lIHRoaXMgc3RhdGljIHNjYW4gY2FuJ3QgcmVhZCAtIGluc3BlY3QgdmlhIGJyb3dzZXIgRGV2"
    "VG9vbHMgPiBBcHBsaWNhdGlvbiA+ICIKICAgICAgICAgICAgIlN0b3JhZ2Ugd2hpbGUgdXNpbmcgdGhlIGFwcCB0byBzZWUg"
    "d2hhdCdzIGFjdHVhbGx5IHN0b3JlZC4iKQogICAgZWxzZToKICAgICAgICBhZGQoZnVsbF91cmwsICJXQS1PVEctMzY2Iiwg"
    "IkNsaWVudC1TaWRlIFRlc3RpbmciLCAiVGVzdCBsb2NhbCBzdG9yYWdlIC8gc2Vzc2lvblN0b3JhZ2UgZm9yIHNlbnNpdGl2"
    "ZSBkYXRhIiwKICAgICAgICAgICAgIk1lZGl1bSIsICJQMiIsICJJTkZPIiwKICAgICAgICAgICAgZiJObyBsb2NhbFN0b3Jh"
    "Z2Uvc2Vzc2lvblN0b3JhZ2UgdXNhZ2UgZm91bmQgaW4gdGhpcyBzaW5nbGUgdW5hdXRoZW50aWNhdGVkIHBhZ2UncyBzdGF0"
    "aWMgSFRNTC9pbmxpbmUgIgogICAgICAgICAgICBmInNjcmlwdHN7Zicgb3Ige2ZldGNoZWR9IHNhbWUtb3JpZ2luIGV4dGVy"
    "bmFsIEpTIGZpbGUocyknIGlmIGZldGNoZWQgZWxzZSAnJ30uIFN0YXRpYyBhbmFseXNpcyBvZiBvbmUgIgogICAgICAgICAg"
    "ICAidW5hdXRoZW50aWNhdGVkIHBhZ2Ugb25seSAtIHVzYWdlIGFkZGVkIGFmdGVyIGxvZ2luLCBpbiBidW5kbGVkL21pbmlm"
    "aWVkL29iZnVzY2F0ZWQgSlMsIG9yIG9uIG90aGVyICIKICAgICAgICAgICAgInBhZ2VzIGNhbid0IGJlIHJ1bGVkIG91dCB0"
    "aGlzIHdheS4gVmVyaWZ5IHZpYSBicm93c2VyIERldlRvb2xzIGR1cmluZyBtYW51YWwgdGVzdGluZyBmb3IgZnVsbCBjb3Zl"
    "cmFnZS4iKQoKCiMgLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t"
    "LS0tLS0tLS0tLS0tLS0KIyA4LiBFbWFpbCBTZWN1cml0eSAtIFdBLU1BSUwtNDEwLi40MTMKIyAtLS0tLS0tLS0tLS0tLS0t"
    "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQoKZGVmIF9uc2xvb2t1"
    "cF90eHQobmFtZSk6CiAgICB0cnk6CiAgICAgICAgb3V0ID0gc3VicHJvY2Vzcy5ydW4oWyJuc2xvb2t1cCIsICItdHlwZT1U"
    "WFQiLCBuYW1lXSwgY2FwdHVyZV9vdXRwdXQ9VHJ1ZSwgdGltZW91dD02LCB0ZXh0PVRydWUpLnN0ZG91dAogICAgICAgIHJl"
    "dHVybiByZS5maW5kYWxsKHInIihbXiJdKikiJywgb3V0KQogICAgZXhjZXB0IEV4Y2VwdGlvbjoKICAgICAgICByZXR1cm4g"
    "Tm9uZQoKCmRlZiBjaGVja19lbWFpbF9zZWN1cml0eShmdWxsX3VybCwgYXJncyk6CiAgICBob3N0ID0gdXJscGFyc2UoZnVs"
    "bF91cmwpLmhvc3RuYW1lCiAgICBpZiBub3QgaG9zdDoKICAgICAgICByZXR1cm4KICAgIHR4dHMgPSBfbnNsb29rdXBfdHh0"
    "KGhvc3QpCiAgICBpZiB0eHRzIGlzIE5vbmU6CiAgICAgICAgZm9yIGNpZCwgbmFtZSBpbiBbKCJXQS1NQUlMLTQxMCIsICJT"
    "UEYgcmVjb3JkIHByZXNlbnQgYW5kIHVzZXMgaGFyZCBmYWlsICgtYWxsKSIpLAogICAgICAgICAgICAgICAgICAgICAgICAg"
    "ICAoIldBLU1BSUwtNDExIiwgIkRNQVJDIHBvbGljeSBjb25maWd1cmVkIChyZWplY3Qgb3IgcXVhcmFudGluZSkiKSwKICAg"
    "ICAgICAgICAgICAgICAgICAgICAgICAgKCJXQS1NQUlMLTQxMiIsICJES0lNIHNpZ25pbmcgY29uZmlndXJlZCBhbmQgdmFs"
    "aWQiKSwKICAgICAgICAgICAgICAgICAgICAgICAgICAgKCJXQS1NQUlMLTQxMyIsICJFbWFpbCBzcG9vZmluZyBwb3NzaWJs"
    "ZSBpZiBTUEYvRE1BUkMgYWJzZW50IG9yIHdlYWsiKV06CiAgICAgICAgICAgIGFkZChmdWxsX3VybCwgY2lkLCAiRW1haWwg"
    "U2VjdXJpdHkiLCBuYW1lLCAiTWVkaXVtIiwgIlAyIiwgIklORk8iLAogICAgICAgICAgICAgICAgIiduc2xvb2t1cCcgbm90"
    "IGF2YWlsYWJsZSBvbiB0aGlzIG1hY2hpbmUgLSBjYW4ndCBxdWVyeSBETlMgVFhUIHJlY29yZHMuIFJ1biBtYW51YWxseTog"
    "IgogICAgICAgICAgICAgICAgZiJuc2xvb2t1cCAtdHlwZT1UWFQge2hvc3R9ICBhbmQgIG5zbG9va3VwIC10eXBlPVRYVCBf"
    "ZG1hcmMue2hvc3R9IikKICAgICAgICByZXR1cm4KCiAgICBzcGYgPSBuZXh0KCh0IGZvciB0IGluIHR4dHMgaWYgdC5sb3dl"
    "cigpLnN0YXJ0c3dpdGgoInY9c3BmMSIpKSwgTm9uZSkKICAgIHNwZl9oYXJkX2ZhaWwgPSBib29sKHNwZiBhbmQgIi1hbGwi"
    "IGluIHNwZikKICAgIGFkZChmdWxsX3VybCwgIldBLU1BSUwtNDEwIiwgIkVtYWlsIFNlY3VyaXR5IiwgIlNQRiByZWNvcmQg"
    "cHJlc2VudCBhbmQgdXNlcyBoYXJkIGZhaWwgKC1hbGwpIiwKICAgICAgICAiTWVkaXVtIiwgIlAyIiwgIlBBU1MiIGlmIHNw"
    "Zl9oYXJkX2ZhaWwgZWxzZSAoIkZBSUwiIGlmIHNwZiBlbHNlICJGQUlMIiksCiAgICAgICAgZiJTUEY6IHtzcGYgb3IgJ25v"
    "IHY9c3BmMSBUWFQgcmVjb3JkIGZvdW5kJ30uIiArCiAgICAgICAgKCIiIGlmIHNwZl9oYXJkX2ZhaWwgZWxzZSAoIiBVc2Vz"
    "IHNvZnQtZmFpbC9uZXV0cmFsL3Bhc3MgaW5zdGVhZCBvZiAtYWxsLiIgaWYgc3BmIGVsc2UgIiBObyBTUEYgcmVjb3JkIGF0"
    "IGFsbC4iKSkpCgogICAgZG1hcmNfdHh0cyA9IF9uc2xvb2t1cF90eHQoZiJfZG1hcmMue2hvc3R9Iikgb3IgW10KICAgIGRt"
    "YXJjID0gbmV4dCgodCBmb3IgdCBpbiBkbWFyY190eHRzIGlmIHQubG93ZXIoKS5zdGFydHN3aXRoKCJ2PWRtYXJjMSIpKSwg"
    "Tm9uZSkKICAgIHBtID0gcmUuc2VhcmNoKHIicD0oXHcrKSIsIGRtYXJjKSBpZiBkbWFyYyBlbHNlIE5vbmUKICAgIHBvbGlj"
    "eSA9IHBtLmdyb3VwKDEpLmxvd2VyKCkgaWYgcG0gZWxzZSBOb25lCiAgICBkbWFyY19vayA9IHBvbGljeSBpbiAoInJlamVj"
    "dCIsICJxdWFyYW50aW5lIikKICAgIGFkZChmdWxsX3VybCwgIldBLU1BSUwtNDExIiwgIkVtYWlsIFNlY3VyaXR5IiwgIkRN"
    "QVJDIHBvbGljeSBjb25maWd1cmVkIChyZWplY3Qgb3IgcXVhcmFudGluZSkiLAogICAgICAgICJNZWRpdW0iLCAiUDIiLCAi"
    "UEFTUyIgaWYgZG1hcmNfb2sgZWxzZSAiRkFJTCIsCiAgICAgICAgZiJETUFSQzoge2RtYXJjIG9yICdubyB2PURNQVJDMSBU"
    "WFQgcmVjb3JkIGZvdW5kIGF0IF9kbWFyYy4nICsgaG9zdH0uIiArCiAgICAgICAgKGYiIFBvbGljeTogcD17cG9saWN5fS4i"
    "IGlmIHBvbGljeSBlbHNlICIiKSkKCiAgICBka2ltX2ZvdW5kID0gTm9uZQogICAgc2VsZWN0b3JzX3RvX3RyeSA9IGxpc3Qo"
    "Q09NTU9OX0RLSU1fU0VMRUNUT1JTKSArIGxpc3QoYXJncy5ka2ltX3NlbGVjdG9yIG9yIFtdKQogICAgZm9yIHNlbCBpbiBz"
    "ZWxlY3RvcnNfdG9fdHJ5OgogICAgICAgIGRraW1fdHh0cyA9IF9uc2xvb2t1cF90eHQoZiJ7c2VsfS5fZG9tYWlua2V5Lnto"
    "b3N0fSIpIG9yIFtdCiAgICAgICAgaWYgYW55KHQubG93ZXIoKS5zdGFydHN3aXRoKCJ2PWRraW0xIikgb3IgInA9IiBpbiB0"
    "Lmxvd2VyKCkgZm9yIHQgaW4gZGtpbV90eHRzKToKICAgICAgICAgICAgZGtpbV9mb3VuZCA9IHNlbAogICAgICAgICAgICBi"
    "cmVhawogICAgYWRkKGZ1bGxfdXJsLCAiV0EtTUFJTC00MTIiLCAiRW1haWwgU2VjdXJpdHkiLCAiREtJTSBzaWduaW5nIGNv"
    "bmZpZ3VyZWQgYW5kIHZhbGlkIiwKICAgICAgICAiTWVkaXVtIiwgIlAyIiwgIlBBU1MiIGlmIGRraW1fZm91bmQgZWxzZSAi"
    "TUFOVUFMIiwKICAgICAgICAoZiJGb3VuZCBhIERLSU0gcmVjb3JkIHVuZGVyIHNlbGVjdG9yICd7ZGtpbV9mb3VuZH0nLiIg"
    "aWYgZGtpbV9mb3VuZCBlbHNlCiAgICAgICAgIGYiTm8gREtJTSByZWNvcmQgZm91bmQgdW5kZXIgY29tbW9uIHNlbGVjdG9y"
    "cyAoeycsICcuam9pbihzZWxlY3RvcnNfdG9fdHJ5KX0pLiBES0lNIHNlbGVjdG9ycyBhcmUgIgogICAgICAgICAicHJvdmlk"
    "ZXItc3BlY2lmaWMgYW5kIG5vdCBndWVzc2FibGUgaW4gZ2VuZXJhbCAtIGNvbmZpcm0gdGhlIHJlYWwgc2VsZWN0b3IgKGNo"
    "ZWNrIGEgcmF3IGVtYWlsJ3MgIgogICAgICAgICAiREtJTS1TaWduYXR1cmUgaGVhZGVyKSBhbmQgcmUtY2hlY2sgd2l0aCAt"
    "LWRraW0tc2VsZWN0b3IgPG5hbWU+LiIpKQoKICAgIHNwb29mX3Jpc2sgPSAobm90IHNwZl9oYXJkX2ZhaWwpIGFuZCAobm90"
    "IGRtYXJjX29rKQogICAgYWRkKGZ1bGxfdXJsLCAiV0EtTUFJTC00MTMiLCAiRW1haWwgU2VjdXJpdHkiLCAiRW1haWwgc3Bv"
    "b2ZpbmcgcG9zc2libGUgaWYgU1BGL0RNQVJDIGFic2VudCBvciB3ZWFrIiwKICAgICAgICAiSGlnaCIsICJQMSIsICJGQUlM"
    "IiBpZiBzcG9vZl9yaXNrIGVsc2UgIlBBU1MiLAogICAgICAgIGYiRGVyaXZlZCBmcm9tIFNQRiAoaGFyZCBmYWlsOiB7c3Bm"
    "X2hhcmRfZmFpbH0pIGFuZCBETUFSQyAocG9saWN5OiB7cG9saWN5IG9yICdub25lJ30pIGFib3ZlLiIgKwogICAgICAgICgi"
    "IEJvdGggYXJlIHdlYWsvYWJzZW50IC0gc3Bvb2ZlZCBtYWlsIGFzIHRoaXMgZG9tYWluIGlzIHBsYXVzaWJsZTsgdmVyaWZ5"
    "IHdpdGggYSB0b29sIGxpa2UgbWFpbHNwb29mL3NwZi1yZWNvcmQuY29tLiIgaWYgc3Bvb2ZfcmlzayBlbHNlICIiKSkKCgoj"
    "IC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t"
    "LS0tCiMgOS4gSW5mb3JtYXRpb24gRGlzY2xvc3VyZSAtIFdBLVNTLTA1NS4uMDU5IChyZXVzZXMgc2V2ZXJhbCBjaGVja3Mg"
    "YWJvdmUpCiMgLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t"
    "LS0tLS0tLS0tLS0KCmRlZiBjaGVja19pbmZvcm1hdGlvbl9kaXNjbG9zdXJlKGZ1bGxfdXJsLCBoZWFkZXJzX3Jlc3VsdCwg"
    "YXJncywgaGRyNDAwX2V2aWRlbmNlLCBoZHI0MDFfZXZpZGVuY2UsIG90ZzI4Nl9ldmlkZW5jZSk6CiAgICBiYXNlID0gZGly"
    "X29mKGZ1bGxfdXJsKQoKICAgIHRyYWNlX2ZhaWwgPSAiRkFJTCIgaW4gW3JbInJlc3VsdCJdIGZvciByIGluIFJFU1VMVFMg"
    "aWYgclsiaWQiXSA9PSAiV0EtSERSLTQwMCIgYW5kIHJbInVybCJdID09IGZ1bGxfdXJsXQogICAgYWRkKGZ1bGxfdXJsLCAi"
    "V0EtU1MtMDU1IiwgIkluZm9ybWF0aW9uIERpc2Nsb3N1cmUiLCAiSW5mb3JtYXRpb24gZGlzY2xvc3VyZSBpbiBlcnJvciBt"
    "ZXNzYWdlcyAoc3RhY2sgdHJhY2UpIiwKICAgICAgICAiTWVkaXVtIiwgIlAyIiwgIkZBSUwiIGlmIHRyYWNlX2ZhaWwgZWxz"
    "ZSAiUEFTUyIsCiAgICAgICAgIihzYW1lIHVuZGVybHlpbmcgY2hlY2sgYXMgV0EtSERSLTQwMCkgIiArIGhkcjQwMF9ldmlk"
    "ZW5jZSkKCiAgICBkYmdfaGl0cyA9IFtdCiAgICBmb3IgcGF0aCBpbiBERUJVR19QQUdFUzoKICAgICAgICByciA9IHJhd19y"
    "ZXF1ZXN0KGpvaW5fdGFyZ2V0KGJhc2UsIHBhdGgpLCAiR0VUIiwgdGltZW91dD1hcmdzLnRpbWVvdXQsIGluc2VjdXJlPWFy"
    "Z3MuaW5zZWN1cmUpCiAgICAgICAgaWYgbm90IHJyLmVycm9yIGFuZCByci5zdGF0dXMgPT0gMjAwOgogICAgICAgICAgICBk"
    "YmdfaGl0cy5hcHBlbmQocGF0aCkKICAgIGFkZChmdWxsX3VybCwgIldBLVNTLTA1NiIsICJJbmZvcm1hdGlvbiBEaXNjbG9z"
    "dXJlIiwgIkluZm8gZGlzY2xvc3VyZSAtIGRlYnVnIHBhZ2UgKHBocGluZm8vcmFpbHMgZGVidWcpIiwKICAgICAgICAiSGln"
    "aCIsICJQMSIsICJGQUlMIiBpZiBkYmdfaGl0cyBlbHNlICJQQVNTIiwKICAgICAgICBmIkFjY2Vzc2libGU6IHsnLCAnLmpv"
    "aW4oZGJnX2hpdHMpfSIgaWYgZGJnX2hpdHMgZWxzZSBmIk5vbmUgb2YgeycsICcuam9pbihERUJVR19QQUdFUyl9IGFjY2Vz"
    "c2libGUgYXQgc2l0ZSByb290LiIpCgogICAgYmFja3VwX2ZhaWwgPSBhbnkoclsicmVzdWx0Il0gPT0gIkZBSUwiIGZvciBy"
    "IGluIFJFU1VMVFMgaWYgclsiaWQiXSBpbiAoIldBLU9URy0yODUiLCAiV0EtT1RHLTI4NiIpIGFuZCByWyJ1cmwiXSA9PSBm"
    "dWxsX3VybCkKICAgIGFkZChmdWxsX3VybCwgIldBLVNTLTA1NyIsICJJbmZvcm1hdGlvbiBEaXNjbG9zdXJlIiwgIkluZm8g"
    "ZGlzY2xvc3VyZSAtIHNvdXJjZSBjb2RlIHZpYSBiYWNrdXAgZmlsZXMiLAogICAgICAgICJIaWdoIiwgIlAxIiwgIkZBSUwi"
    "IGlmIGJhY2t1cF9mYWlsIGVsc2UgIlBBU1MiLAogICAgICAgICIoc2FtZSB1bmRlcmx5aW5nIHByb2JlcyBhcyBXQS1PVEct"
    "Mjg1LzI4NikgIiArIG90ZzI4Nl9ldmlkZW5jZSkKCiAgICBhZGQoZnVsbF91cmwsICJXQS1TUy0wNTgiLCAiSW5mb3JtYXRp"
    "b24gRGlzY2xvc3VyZSIsICJJbmZvIGRpc2Nsb3N1cmUgLSB2ZXJzaW9uIHZpYSByZXNwb25zZSBoZWFkZXJzIiwKICAgICAg"
    "ICAiTG93IiwgIlAzIiwKICAgICAgICBuZXh0KChyWyJyZXN1bHQiXSBmb3IgciBpbiBSRVNVTFRTIGlmIHJbImlkIl0gPT0g"
    "IldBLUhEUi00MDEiIGFuZCByWyJ1cmwiXSA9PSBmdWxsX3VybCksICJJTkZPIiksCiAgICAgICAgIihzYW1lIHVuZGVybHlp"
    "bmcgY2hlY2sgYXMgV0EtSERSLTQwMSkgIiArIGhkcjQwMV9ldmlkZW5jZSkKCiAgICBnaXRfaGl0cyA9IFtdCiAgICBmb3Ig"
    "cGF0aCBpbiBHSVRfU1ZOX1BST0JFUzoKICAgICAgICByciA9IHJhd19yZXF1ZXN0KGpvaW5fdGFyZ2V0KGJhc2UsIHBhdGgp"
    "LCAiR0VUIiwgdGltZW91dD1hcmdzLnRpbWVvdXQsIGluc2VjdXJlPWFyZ3MuaW5zZWN1cmUpCiAgICAgICAgaWYgbm90IHJy"
    "LmVycm9yIGFuZCByci5zdGF0dXMgPT0gMjAwOgogICAgICAgICAgICBnaXRfaGl0cy5hcHBlbmQocGF0aCkKICAgIGFkZChm"
    "dWxsX3VybCwgIldBLVNTLTA1OSIsICJJbmZvcm1hdGlvbiBEaXNjbG9zdXJlIiwgIkluZm8gZGlzY2xvc3VyZSAtIHNlbnNp"
    "dGl2ZSBkYXRhIGluIGdpdC9zdm4vLkRTX1N0b3JlIiwKICAgICAgICAiSGlnaCIsICJQMSIsICJGQUlMIiBpZiBnaXRfaGl0"
    "cyBlbHNlICJQQVNTIiwKICAgICAgICBmIkFjY2Vzc2libGU6IHsnLCAnLmpvaW4oZ2l0X2hpdHMpfSAtIGNsb25lL2V4dHJh"
    "Y3QgdGhlc2UgdG8gcmVjb3ZlciBzb3VyY2UgKGUuZy4gZ2l0LWR1bXBlciBmb3IgLy5naXQvKS4iIGlmIGdpdF9oaXRzCiAg"
    "ICAgICAgZWxzZSBmIk5vbmUgb2YgeycsICcuam9pbihHSVRfU1ZOX1BST0JFUyl9IGFjY2Vzc2libGUgYXQgc2l0ZSByb290"
    "LiIpCgoKIyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t"
    "LS0tLS0tLS0tLQojIDEwLiBIVFRQIEhvc3QgSGVhZGVyIEF0dGFja3MgLSBXQS1BRFYtMjE4Li4yMjQKIyAtLS0tLS0tLS0t"
    "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQoKIyAtLS0t"
    "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQoj"
    "IEFjY2VzcyBDb250cm9sIC8gQXV0aG9yaXphdGlvbiAoMi1hY2NvdW50KSAtIFdBLU9URy0zMTIsIFdBLVNTLTA3MSwKIyBX"
    "QS1PVEctMzE0LiBPcHQtaW4gb25seSwgdmlhIC0tYWNjb3VudDEtY29va2llIC8gLS1hY2NvdW50Mi1jb29raWUgLQojIHRo"
    "aXMgc2NyaXB0IE5FVkVSIGxvZ3MgaW4sIGJydXRlLWZvcmNlcywgb3IgaGFydmVzdHMgY3JlZGVudGlhbHMgaXRzZWxmLgoj"
    "IFJlcXVlc3RlZCBkaXJlY3RseTogIndoZXJlIGV2ZXIgcmVxdWlyZWQgdGhlIHR3byBhY2NvdW50IGFzayBhcyBpbnB1dAoj"
    "IGZvciBjaGVjayAuLi4gbmV2ZXIgdGFrZSB0aGUgY3JlZGV0aWxzIGFsc28gdG8gbmF2aWdhdGUgaW5zaWRlIiAtIHNvCiMg"
    "dGhlc2UgZmxhZ3Mgb25seSBldmVyIGhvbGQgYSBzZXNzaW9uIGNvb2tpZSB0aGUgb3BlcmF0b3IgYWxyZWFkeSBoYXMKIyBm"
    "cm9tIGxvZ2dpbmcgaW4gdGhlbXNlbHZlczsgdGhlIGNvb2tpZSB2YWx1ZSBpdHNlbGYgaXMgbmV2ZXIgd3JpdHRlbiB0bwoj"
    "IGV2aWRlbmNlL0pTT04vQ1NWL3NjcmVlbnNob3RzLCBvbmx5IHBhc3MvZmFpbCBjb21wYXJpc29uIGRhdGEgaXMuCiMgLS0t"
    "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0K"
    "CmRlZiBfZmV0Y2hfd2l0aF9jb29raWUodXJsLCBjb29raWUsIHRpbWVvdXQsIGluc2VjdXJlKToKICAgIGlmIG5vdCBjb29r"
    "aWU6CiAgICAgICAgcmV0dXJuIHJhd19yZXF1ZXN0KHVybCwgIkdFVCIsIHRpbWVvdXQ9dGltZW91dCwgaW5zZWN1cmU9aW5z"
    "ZWN1cmUpCiAgICByZXR1cm4gcmF3X3JlcXVlc3QodXJsLCAiR0VUIiwgZXh0cmFfaGVhZGVycz17IkNvb2tpZSI6IGNvb2tp"
    "ZX0sIHRpbWVvdXQ9dGltZW91dCwgaW5zZWN1cmU9aW5zZWN1cmUpCgoKZGVmIF9yZXNwX3NpZ25hdHVyZShyKToKICAgIGlm"
    "IG5vdCByIG9yIHIuZXJyb3I6CiAgICAgICAgcmV0dXJuIE5vbmUKICAgIHJldHVybiAoci5zdGF0dXMsIGxlbihyLmJvZHkp"
    "LCBoYXNobGliLnNoYTI1NihyLmJvZHkpLmhleGRpZ2VzdCgpWzoxMl0pCgoKZGVmIGNoZWNrX2FjY2Vzc19jb250cm9sXzJm"
    "YShmdWxsX3VybCwgYXJncyk6CiAgICBhY2N0MV9jb29raWUgPSBnZXRhdHRyKGFyZ3MsICJhY2NvdW50MV9jb29raWUiLCBO"
    "b25lKQogICAgYWNjdDJfY29va2llID0gZ2V0YXR0cihhcmdzLCAiYWNjb3VudDJfY29va2llIiwgTm9uZSkKICAgIGFjY3Qx"
    "X2xhYmVsID0gZ2V0YXR0cihhcmdzLCAiYWNjb3VudDFfbGFiZWwiLCBOb25lKSBvciAiQWNjb3VudCAxIgogICAgYWNjdDJf"
    "bGFiZWwgPSBnZXRhdHRyKGFyZ3MsICJhY2NvdW50Ml9sYWJlbCIsIE5vbmUpIG9yICJBY2NvdW50IDIiCgogICAgaWYgbm90"
    "IGFjY3QxX2Nvb2tpZSBhbmQgbm90IGFjY3QyX2Nvb2tpZToKICAgICAgICBmb3IgY2lkLCBjYXQsIG5hbWUgaW4gWwogICAg"
    "ICAgICAgICAoIldBLU9URy0zMTIiLCAiQXV0aG9yaXphdGlvbiBUZXN0aW5nIiwgIlRlc3QgYnlwYXNzaW5nIGF1dGhvcml6"
    "YXRpb24gc2NoZW1hIChmb3JjZSBicm93c2UpIiksCiAgICAgICAgICAgICgiV0EtU1MtMDcxIiwgIkFjY2VzcyBDb250cm9s"
    "IiwgIkhvcml6b250YWwgcHJpdmlsZWdlIGVzY2FsYXRpb24gKGFjY2VzcyBhbm90aGVyIHVzZXIgZGF0YSkiKSwKICAgICAg"
    "ICAgICAgKCJXQS1PVEctMzE0IiwgIkF1dGhvcml6YXRpb24gVGVzdGluZyIsICJUZXN0IGluc2VjdXJlIGRpcmVjdCBvYmpl"
    "Y3QgcmVmZXJlbmNlcyAoSURPUikiKSwKICAgICAgICBdOgogICAgICAgICAgICBhZGQoZnVsbF91cmwsIGNpZCwgY2F0LCBu"
    "YW1lLCAiQ3JpdGljYWwiLCAiUDEiLCAiTUFOVUFMIiwKICAgICAgICAgICAgICAgICJOZWVkcyBhbiBhdXRoZW50aWNhdGVk"
    "IHNlc3Npb24gdG8gdGVzdCAtIHJlLXJ1biB3aXRoIC0tY29va2llIFwic2Vzc2lvbmlkPS4uLlwiICh0aGlzIGFsc28gIgog"
    "ICAgICAgICAgICAgICAgImF1dGhlbnRpY2F0ZXMgZXZlcnkgb3RoZXIgY2hlY2sgaW4gdGhlIHN1aXRlKSBhbmQgYWRkIC0t"
    "Y29va2llMiBcInNlc3Npb25pZD0uLi5cIiAoYSBTRUNPTkQsICIKICAgICAgICAgICAgICAgICJkaWZmZXJlbnQgYWNjb3Vu"
    "dCdzIG93biBzZXNzaW9uKSBmb3IgdGhlIHR3by1hY2NvdW50IElET1IvaG9yaXpvbnRhbC1lc2NhbGF0aW9uIGNoZWNrcy4g"
    "T25seSAiCiAgICAgICAgICAgICAgICAicGFzcyBhIHNlc3Npb24gY29va2llIFlPVSBhbHJlYWR5IG9idGFpbmVkIGJ5IGxv"
    "Z2dpbmcgaW4geW91cnNlbGYgLSB0aGlzIHNjcmlwdCBuZXZlciBhdHRlbXB0cyAiCiAgICAgICAgICAgICAgICAidG8gbG9n"
    "IGluLCBndWVzcywgb3IgaGFydmVzdCBjcmVkZW50aWFscy4iKQogICAgICAgIHJldHVybgoKICAgIHVuYXV0aCA9IHJhd19y"
    "ZXF1ZXN0KGZ1bGxfdXJsLCAiR0VUIiwgdGltZW91dD1hcmdzLnRpbWVvdXQsIGluc2VjdXJlPWFyZ3MuaW5zZWN1cmUpCiAg"
    "ICBhY2N0MSA9IF9mZXRjaF93aXRoX2Nvb2tpZShmdWxsX3VybCwgYWNjdDFfY29va2llLCBhcmdzLnRpbWVvdXQsIGFyZ3Mu"
    "aW5zZWN1cmUpIGlmIGFjY3QxX2Nvb2tpZSBlbHNlIE5vbmUKCiAgICBpZiBhY2N0MV9jb29raWUgYW5kIGFjY3QxIGFuZCBu"
    "b3QgYWNjdDEuZXJyb3IgYW5kIG5vdCB1bmF1dGguZXJyb3I6CiAgICAgICAgc2lnX3VuYXV0aCwgc2lnX2FjY3QxID0gX3Jl"
    "c3Bfc2lnbmF0dXJlKHVuYXV0aCksIF9yZXNwX3NpZ25hdHVyZShhY2N0MSkKICAgICAgICBsb29rc19zYW1lID0gYm9vbChz"
    "aWdfdW5hdXRoIGFuZCBzaWdfYWNjdDEgYW5kIHNpZ191bmF1dGhbMTpdID09IHNpZ19hY2N0MVsxOl0pCiAgICAgICAgYWRk"
    "KGZ1bGxfdXJsLCAiV0EtT1RHLTMxMiIsICJBdXRob3JpemF0aW9uIFRlc3RpbmciLCAiVGVzdCBieXBhc3NpbmcgYXV0aG9y"
    "aXphdGlvbiBzY2hlbWEgKGZvcmNlIGJyb3dzZSkiLAogICAgICAgICAgICAiQ3JpdGljYWwiLCAiUDEiLCAiRkFJTCIgaWYg"
    "bG9va3Nfc2FtZSBlbHNlICJQQVNTIiwKICAgICAgICAgICAgZiJVbmF1dGhlbnRpY2F0ZWQ6IEhUVFAge3VuYXV0aC5zdGF0"
    "dXN9LCB7bGVuKHVuYXV0aC5ib2R5KX0gYnl0ZXMuIFdpdGgge2FjY3QxX2xhYmVsfSBzZXNzaW9uOiAiCiAgICAgICAgICAg"
    "IGYiSFRUUCB7YWNjdDEuc3RhdHVzfSwge2xlbihhY2N0MS5ib2R5KX0gYnl0ZXMuIiArCiAgICAgICAgICAgIChmIiBCb3Ro"
    "IHJlc3BvbnNlcyBhcmUgYnl0ZS1mb3ItYnl0ZSBpZGVudGljYWwgKHNhbWUgbGVuZ3RoK2hhc2gpIC0gaWYgdGhpcyBwYWdl"
    "IGlzIG1lYW50IHRvIHJlcXVpcmUgIgogICAgICAgICAgICAgZiJsb2dpbiwgaXQncyByZWFjaGFibGUgd2l0aG91dCBvbmUu"
    "IiBpZiBsb29rc19zYW1lIGVsc2UKICAgICAgICAgICAgICIgUmVzcG9uc2VzIGRpZmZlciBiZXR3ZWVuIHVuYXV0aGVudGlj"
    "YXRlZCBhbmQgYXV0aGVudGljYXRlZCByZXF1ZXN0cyAtIHRoaXMgcGFnZSBkb2VzIGFwcGVhciB0byAiCiAgICAgICAgICAg"
    "ICAiZ2F0ZSBpdHMgY29udGVudCBvbiB0aGUgc2Vzc2lvbi4iKSkKICAgIGVsc2U6CiAgICAgICAgYWRkKGZ1bGxfdXJsLCAi"
    "V0EtT1RHLTMxMiIsICJBdXRob3JpemF0aW9uIFRlc3RpbmciLCAiVGVzdCBieXBhc3NpbmcgYXV0aG9yaXphdGlvbiBzY2hl"
    "bWEgKGZvcmNlIGJyb3dzZSkiLAogICAgICAgICAgICAiQ3JpdGljYWwiLCAiUDEiLCAiTUFOVUFMIiBpZiBub3QgYWNjdDFf"
    "Y29va2llIGVsc2UgIkVSUk9SIiwKICAgICAgICAgICAgIk5lZWRzIC0tY29va2llIHRvIGNvbXBhcmUgYWdhaW5zdCBhbiB1"
    "bmF1dGhlbnRpY2F0ZWQgcmVxdWVzdC4iIGlmIG5vdCBhY2N0MV9jb29raWUKICAgICAgICAgICAgZWxzZSAoKHVuYXV0aC5l"
    "cnJvciBvciAoYWNjdDEuZXJyb3IgaWYgYWNjdDEgZWxzZSAiIikpIG9yICJDb3VsZCBub3QgY29tcGxldGUgYm90aCByZXF1"
    "ZXN0cy4iKSkKCiAgICBpZiBub3QgYWNjdDJfY29va2llOgogICAgICAgIGZvciBjaWQsIGNhdCwgbmFtZSBpbiBbCiAgICAg"
    "ICAgICAgICgiV0EtU1MtMDcxIiwgIkFjY2VzcyBDb250cm9sIiwgIkhvcml6b250YWwgcHJpdmlsZWdlIGVzY2FsYXRpb24g"
    "KGFjY2VzcyBhbm90aGVyIHVzZXIgZGF0YSkiKSwKICAgICAgICAgICAgKCJXQS1PVEctMzE0IiwgIkF1dGhvcml6YXRpb24g"
    "VGVzdGluZyIsICJUZXN0IGluc2VjdXJlIGRpcmVjdCBvYmplY3QgcmVmZXJlbmNlcyAoSURPUikiKSwKICAgICAgICBdOgog"
    "ICAgICAgICAgICBhZGQoZnVsbF91cmwsIGNpZCwgY2F0LCBuYW1lLCAiQ3JpdGljYWwiLCAiUDEiLCAiTUFOVUFMIiwKICAg"
    "ICAgICAgICAgICAgIGYiTmVlZHMgYSBTRUNPTkQgYWNjb3VudCdzIHNlc3Npb24gdG9vIC0gcmUtcnVuIHdpdGggLS1jb29r"
    "aWUyIFwic2Vzc2lvbmlkPS4uLlwiIHRvIHRlc3QgIgogICAgICAgICAgICAgICAgZiJ3aGV0aGVyIHthY2N0Ml9sYWJlbH0g"
    "Y2FuIHNlZSB7YWNjdDFfbGFiZWx9J3MgY29udGVudCBhdCB0aGlzIHNhbWUgVVJMLiIpCiAgICAgICAgcmV0dXJuCgogICAg"
    "YWNjdDIgPSBfZmV0Y2hfd2l0aF9jb29raWUoZnVsbF91cmwsIGFjY3QyX2Nvb2tpZSwgYXJncy50aW1lb3V0LCBhcmdzLmlu"
    "c2VjdXJlKQogICAgaWYgYWNjdDEgaXMgTm9uZSBhbmQgYWNjdDFfY29va2llOgogICAgICAgIGFjY3QxID0gX2ZldGNoX3dp"
    "dGhfY29va2llKGZ1bGxfdXJsLCBhY2N0MV9jb29raWUsIGFyZ3MudGltZW91dCwgYXJncy5pbnNlY3VyZSkKCiAgICBpZiBh"
    "Y2N0MSBhbmQgYWNjdDIgYW5kIG5vdCBhY2N0MS5lcnJvciBhbmQgbm90IGFjY3QyLmVycm9yOgogICAgICAgIHNpZzEsIHNp"
    "ZzIgPSBfcmVzcF9zaWduYXR1cmUoYWNjdDEpLCBfcmVzcF9zaWduYXR1cmUoYWNjdDIpCiAgICAgICAgaWRlbnRpY2FsID0g"
    "Ym9vbChzaWcxIGFuZCBzaWcyIGFuZCBzaWcxWzE6XSA9PSBzaWcyWzE6XSkKICAgICAgICBldmlkZW5jZSA9IChmInthY2N0"
    "MV9sYWJlbH06IEhUVFAge2FjY3QxLnN0YXR1c30sIHtsZW4oYWNjdDEuYm9keSl9IGJ5dGVzLiAiCiAgICAgICAgICAgICAg"
    "ICAgICAgZiJ7YWNjdDJfbGFiZWx9OiBIVFRQIHthY2N0Mi5zdGF0dXN9LCB7bGVuKGFjY3QyLmJvZHkpfSBieXRlcy4iKQog"
    "ICAgICAgIGlmIGlkZW50aWNhbDoKICAgICAgICAgICAgcmVzdWx0ID0gIk1BTlVBTCIKICAgICAgICAgICAgZXZpZGVuY2Ug"
    "Kz0gKGYiIEJvdGggYWNjb3VudHMgc2VlIGJ5dGUtZm9yLWJ5dGUgaWRlbnRpY2FsIGNvbnRlbnQgKHNhbWUgbGVuZ3RoK2hh"
    "c2gpIGF0IHRoaXMgZXhhY3QgIgogICAgICAgICAgICAgICAgICAgICAgICAgZiJVUkwuIElmIHRoaXMgVVJML3Jlc291cmNl"
    "IGlzIG1lYW50IHRvIGJlIHNwZWNpZmljIHRvIHthY2N0MV9sYWJlbH0gKGNvbnRhaW5zIGFuICIKICAgICAgICAgICAgICAg"
    "ICAgICAgICAgIGYiYWNjb3VudC1zcGVjaWZpYyBJRCwgZmlsZW5hbWUsIG9yIHNpbWlsYXIgaW4gdGhlIHBhdGgvcXVlcnkp"
    "LCB0aGVuIHthY2N0Ml9sYWJlbH0gIgogICAgICAgICAgICAgICAgICAgICAgICAgInN1Y2Nlc3NmdWxseSB2aWV3aW5nIGl0"
    "IGlzIGEgc3Ryb25nIGhvcml6b250YWwtcHJpdmlsZWdlLWVzY2FsYXRpb24gLyBJRE9SIGluZGljYXRvciAtICIKICAgICAg"
    "ICAgICAgICAgICAgICAgICAgICJjb25maXJtIHRoZSByZXNvdXJjZSBJUyBhY2NvdW50LXNwZWNpZmljIChub3QgYSBzaGFy"
    "ZWQvcHVibGljIHBhZ2UpIGJlZm9yZSByZXBvcnRpbmcuIikKICAgICAgICBlbHNlOgogICAgICAgICAgICByZXN1bHQgPSAi"
    "UEFTUyIKICAgICAgICAgICAgZXZpZGVuY2UgKz0gIiBSZXNwb25zZXMgZGlmZmVyIGJldHdlZW4gdGhlIHR3byBhY2NvdW50"
    "cyAtIG5vIGV2aWRlbmNlIG9mIGNyb3NzLWFjY291bnQgYWNjZXNzIGF0IHRoaXMgVVJMLiIKICAgICAgICBhZGQoZnVsbF91"
    "cmwsICJXQS1TUy0wNzEiLCAiQWNjZXNzIENvbnRyb2wiLCAiSG9yaXpvbnRhbCBwcml2aWxlZ2UgZXNjYWxhdGlvbiAoYWNj"
    "ZXNzIGFub3RoZXIgdXNlciBkYXRhKSIsCiAgICAgICAgICAgICJDcml0aWNhbCIsICJQMSIsIHJlc3VsdCwgZXZpZGVuY2Up"
    "CiAgICAgICAgYWRkKGZ1bGxfdXJsLCAiV0EtT1RHLTMxNCIsICJBdXRob3JpemF0aW9uIFRlc3RpbmciLCAiVGVzdCBpbnNl"
    "Y3VyZSBkaXJlY3Qgb2JqZWN0IHJlZmVyZW5jZXMgKElET1IpIiwKICAgICAgICAgICAgIkNyaXRpY2FsIiwgIlAxIiwgcmVz"
    "dWx0LCBldmlkZW5jZSkKICAgIGVsc2U6CiAgICAgICAgZXJyID0gKChhY2N0MS5lcnJvciBpZiBhY2N0MSBhbmQgYWNjdDEu"
    "ZXJyb3IgZWxzZSAiIikgb3IgKGFjY3QyLmVycm9yIGlmIGFjY3QyIGFuZCBhY2N0Mi5lcnJvciBlbHNlICIiKQogICAgICAg"
    "ICAgICAgICBvciAiQ291bGQgbm90IGNvbXBsZXRlIGJvdGggYXV0aGVudGljYXRlZCByZXF1ZXN0cy4iKQogICAgICAgIGZv"
    "ciBjaWQsIGNhdCwgbmFtZSBpbiBbCiAgICAgICAgICAgICgiV0EtU1MtMDcxIiwgIkFjY2VzcyBDb250cm9sIiwgIkhvcml6"
    "b250YWwgcHJpdmlsZWdlIGVzY2FsYXRpb24gKGFjY2VzcyBhbm90aGVyIHVzZXIgZGF0YSkiKSwKICAgICAgICAgICAgKCJX"
    "QS1PVEctMzE0IiwgIkF1dGhvcml6YXRpb24gVGVzdGluZyIsICJUZXN0IGluc2VjdXJlIGRpcmVjdCBvYmplY3QgcmVmZXJl"
    "bmNlcyAoSURPUikiKSwKICAgICAgICBdOgogICAgICAgICAgICBhZGQoZnVsbF91cmwsIGNpZCwgY2F0LCBuYW1lLCAiQ3Jp"
    "dGljYWwiLCAiUDEiLCAiRVJST1IiLCBlcnIpCgoKZGVmIGNoZWNrX2hvc3RfaGVhZGVyKGZ1bGxfdXJsLCBhcmdzKToKICAg"
    "IHRva2VuID0gZiJldmlsLWhvc3QtaGVhZGVyLXRlc3Qte3JhbmRfdG9rZW4oOCl9LmV4YW1wbGUiCiAgICByID0gcmF3X3Jl"
    "cXVlc3QoZnVsbF91cmwsICJHRVQiLCB0aW1lb3V0PWFyZ3MudGltZW91dCwgaW5zZWN1cmU9YXJncy5pbnNlY3VyZSwgaG9z"
    "dF9vdmVycmlkZT10b2tlbikKICAgIGlkc19hbmRfbmFtZXMgPSBbCiAgICAgICAgKCJXQS1BRFYtMjE4IiwgIkhvc3QgaGVh"
    "ZGVyIC0gcGFzc3dvcmQgcmVzZXQgcG9pc29uaW5nIiwKICAgICAgICAgIklmIGEgcGFzc3dvcmQtcmVzZXQgZW1haWwgaXMg"
    "ZXZlciBzZW50LCBjb25maXJtIG1hbnVhbGx5IHdoZXRoZXIgdGhlIHJlc2V0IGxpbmsgdXNlcyB0aGUgSG9zdCBoZWFkZXIg"
    "dmFsdWUuIiksCiAgICAgICAgKCJXQS1BRFYtMjE5IiwgIkhvc3QgaGVhZGVyIC0gd2ViIGNhY2hlIHBvaXNvbmluZyB2aWEg"
    "SG9zdCIsCiAgICAgICAgICJJZiB0aGlzIGFwcCBzaXRzIGJlaGluZCBhIGNhY2hlLCBjb25maXJtIG1hbnVhbGx5IHdoZXRo"
    "ZXIgYSBwb2lzb25lZCByZXNwb25zZSBnZXRzIGNhY2hlZCBhbmQgc2VydmVkIHRvIG90aGVyIHVzZXJzLiIpLAogICAgICAg"
    "ICgiV0EtQURWLTIyMCIsICJIb3N0IGhlYWRlciAtIFNTUkYgdmlhIG1hbGZvcm1lZCBIb3N0IGhlYWRlciIsCiAgICAgICAg"
    "ICJUcnkgYSBtYWxmb3JtZWQvaW50ZXJuYWwgSG9zdCB2YWx1ZSAoZS5nLiAxNjkuMjU0LjE2OS4yNTQpIGFuZCBjaGVjayBm"
    "b3IgYW55IHNlcnZlci1zaWRlIGZldGNoIGJlaGF2aW9yIG1hbnVhbGx5LiIpLAogICAgICAgICgiV0EtQURWLTIyMSIsICJI"
    "b3N0IGhlYWRlciAtIGJ5cGFzcyBpbnRlcm5hbCBhdXRoZW50aWNhdGlvbiAobG9jYWxob3N0KSIsCiAgICAgICAgICJUcnkg"
    "J0hvc3Q6IGxvY2FsaG9zdCcgc3BlY2lmaWNhbGx5IGFuZCBjaGVjayBmb3IgZGlmZmVyZW50IChlLmcuIGFkbWluL2ludGVy"
    "bmFsKSBiZWhhdmlvciBtYW51YWxseS4iKSwKICAgICAgICAoIldBLUFEVi0yMjIiLCAiSG9zdCBoZWFkZXIgLSByb3V0aW5n"
    "LWJhc2VkIFNTUkYgKGFtYmlndW91cyByZXF1ZXN0cykiLAogICAgICAgICAiTmVlZHMgYSBsb2FkLWJhbGFuY2VyL3Byb3h5"
    "LWNoYWluLWF3YXJlIHRlc3QgKGR1cGxpY2F0ZSBIb3N0IGhlYWRlcnMsIG1pc21hdGNoZWQgSG9zdCB2cy4gcmVxdWVzdCBs"
    "aW5lKSAtIG1hbnVhbC9CdXJwLiIpLAogICAgICAgICgiV0EtQURWLTIyMyIsICJIb3N0IGhlYWRlciAtIFNTUkYgdmlhIGNv"
    "bm5lY3Rpb24gaGVhZGVyIiwKICAgICAgICAgIk5lZWRzIGEgQ29ubmVjdGlvbi9YLUZvcndhcmRlZC0qIGhlYWRlciBtYW5p"
    "cHVsYXRpb24gdGVzdCBhZ2FpbnN0IGFuIGludGVybmFsIHRhcmdldCAtIG1hbnVhbC9CdXJwLiIpLAogICAgICAgICgiV0Et"
    "QURWLTIyNCIsICJIb3N0IGhlYWRlciAtIFgtSG9zdCAvIFgtRm9yd2FyZGVkLVNlcnZlciBvdmVycmlkZSIsCiAgICAgICAg"
    "ICJUcnkgWC1Ib3N0IC8gWC1Gb3J3YXJkZWQtSG9zdCAvIFgtRm9yd2FyZGVkLVNlcnZlciBoZWFkZXJzIHNwZWNpZmljYWxs"
    "eSBhbmQgY29tcGFyZSByZXNwb25zZXMgbWFudWFsbHkuIiksCiAgICBdCiAgICBpZiByLmVycm9yOgogICAgICAgIGZvciBj"
    "aWQsIG5hbWUsIF8gaW4gaWRzX2FuZF9uYW1lczoKICAgICAgICAgICAgYWRkKGZ1bGxfdXJsLCBjaWQsICJIVFRQIEhvc3Qg"
    "SGVhZGVyIEF0dGFja3MiLCBuYW1lLCAiSGlnaCIsICJQMSIsICJFUlJPUiIsIHIuZXJyb3IpCiAgICAgICAgcmV0dXJuCgog"
    "ICAgYm9keV90ZXh0ID0gci50ZXh0KCkKICAgIGxvYyA9IHIuaGVhZGVyKCJMb2NhdGlvbiIpCiAgICByZWZsZWN0ZWRfaW5f"
    "Ym9keSA9IHRva2VuIGluIGJvZHlfdGV4dAogICAgcmVmbGVjdGVkX2luX2xvY2F0aW9uID0gYm9vbChsb2MgYW5kIHRva2Vu"
    "IGluIGxvYykKICAgIHJlZmxlY3RlZCA9IHJlZmxlY3RlZF9pbl9ib2R5IG9yIHJlZmxlY3RlZF9pbl9sb2NhdGlvbgogICAg"
    "YmFzZV9ldmlkZW5jZSA9IChmIlNlbnQgSG9zdDoge3Rva2VufSB0byB7ZnVsbF91cmx9IC0+IHN0YXR1cyB7ci5zdGF0dXN9"
    "LCAiCiAgICAgICAgICAgICAgICAgICAgICBmInJlZmxlY3RlZCBpbiBib2R5OiB7cmVmbGVjdGVkX2luX2JvZHl9LCByZWZs"
    "ZWN0ZWQgaW4gTG9jYXRpb24gaGVhZGVyOiB7cmVmbGVjdGVkX2luX2xvY2F0aW9ufS4iKQoKICAgIGN1cmxfcmVzdWx0ID0g"
    "Tm9uZSBpZiBnZXRhdHRyKGFyZ3MsICJub19jbGlfdG9vbHMiLCBGYWxzZSkgZWxzZSBydW5fY3VybF93aXRoX2hvc3RfaGVh"
    "ZGVyKAogICAgICAgIGZ1bGxfdXJsLCB0b2tlbiwgdGltZW91dD1hcmdzLnRpbWVvdXQsIGluc2VjdXJlPWFyZ3MuaW5zZWN1"
    "cmUpCiAgICBjdXJsX2Jsb2NrID0gX2Zvcm1hdF9jbWRfYmxvY2soY3VybF9yZXN1bHRbMF0sIGN1cmxfcmVzdWx0WzFdKSBp"
    "ZiBjdXJsX3Jlc3VsdCBlbHNlICIiCgogICAgZm9yIGNpZCwgbmFtZSwgZXh0cmEgaW4gaWRzX2FuZF9uYW1lczoKICAgICAg"
    "ICBhZGQoZnVsbF91cmwsIGNpZCwgIkhUVFAgSG9zdCBIZWFkZXIgQXR0YWNrcyIsIG5hbWUsICJIaWdoIiBpZiBjaWQgIT0g"
    "IldBLUFEVi0yMjEiIGVsc2UgIkNyaXRpY2FsIiwgIlAxIiwKICAgICAgICAgICAgIkZBSUwiIGlmIHJlZmxlY3RlZCBlbHNl"
    "ICJJTkZPIiwKICAgICAgICAgICAgKGJhc2VfZXZpZGVuY2UgKyAoIiBTZXJ2ZXIgdHJ1c3RzL3JlZmxlY3RzIGFuIGFyYml0"
    "cmFyeSBIb3N0IGhlYWRlciAtICIgKyBleHRyYSBpZiByZWZsZWN0ZWQgZWxzZQogICAgICAgICAgICAgIiBCYXNpYyBzaW5n"
    "bGUtcmVxdWVzdCBwcm9iZSBkaWQgbm90IHNob3cgcmVmbGVjdGlvbiwgYnV0IHRoYXQgYWxvbmUgZG9lc24ndCBydWxlIHRo"
    "aXMgb3V0IC0gIiArIGV4dHJhKSkKICAgICAgICAgICAgKyBjdXJsX2Jsb2NrKQoKCiMgLS0tLS0tLS0tLS0tLS0tLS0tLS0t"
    "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KIyBEcml2ZXIKIyAtLS0tLS0t"
    "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQoKZGVm"
    "IHJlYWRfdXJsX2xpc3QocGF0aCk6CiAgICB1cmxzID0gW10KICAgIHdpdGggb3BlbihwYXRoLCAiciIsIGVuY29kaW5nPSJ1"
    "dGYtOCIpIGFzIGY6CiAgICAgICAgZm9yIGxpbmUgaW4gZjoKICAgICAgICAgICAgbGluZSA9IGxpbmUuc3RyaXAoKQogICAg"
    "ICAgICAgICBpZiBub3QgbGluZSBvciBsaW5lLnN0YXJ0c3dpdGgoIiMiKToKICAgICAgICAgICAgICAgIGNvbnRpbnVlCiAg"
    "ICAgICAgICAgIHVybHMuYXBwZW5kKGxpbmUpCiAgICByZXR1cm4gdXJscwoKCiMgLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t"
    "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KIyAtLWNyZWRzIC8gLS1jcmVkcy1m"
    "aWxlIC0gYSBmcmllbmRsaWVyIHdheSB0byBoYW5kIHRoaXMgc2NyaXB0IGFjY291bnQgMS8yCiMgZm9yIGNoZWNrX2FjY2Vz"
    "c19jb250cm9sXzJmYSgpIHRoYW4gdHlwaW5nIC0tY29va2llLy0tY29va2llMiBieSBoYW5kLgojCiMgU2luY2UgdGhpcyBz"
    "Y3JpcHQgbmV2ZXIgbG9ncyBpbiAoc2VlIGJlbG93KSwgYSBwYXNzd29yZCBpcyBOT1QgbmVlZGVkIGFuZAojIGlzIE5PVCBy"
    "ZWFkIGZyb20gdGhlc2UgZW50cmllcyBhdCBhbGwgLSB0eXBpbmcgb25lIGlzIHdhc3RlZCBlZmZvcnQuCiMgVGhyZWUgZm9y"
    "bXMgYXJlIGFjY2VwdGVkIHBlciBsaW5lL2VudHJ5LCBpbiBvcmRlciBvZiB3aGF0J3MgY2hlY2tlZDoKIwojICAgMS4gImxh"
    "YmVsOjpjb29raWUiICAgICAgICAgICAgPC0gUkVDT01NRU5ERUQgLSBubyBwYXNzd29yZCwganVzdCBhCiMgICAgICAgICAg"
    "ICAgICAgICAgICAgICAgICAgICAgICAgICAgcmVhZGFibGUgbmFtZSBhbmQgdGhlIHNlc3Npb24gY29va2llCiMgICAgICAg"
    "ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgeW91IGFscmVhZHkgb2J0YWluZWQgYnkgbG9nZ2luZyBpbgojICAgICAg"
    "ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHlvdXJzZWxmIGFzIHRoYXQgdXNlci4KIyAgIDIuICJsYWJlbDpwYXNz"
    "d29yZDo6Y29va2llIiAgIDwtIGxlZ2FjeSBmb3JtLCBrZXB0IGZvciBjb21wYXRpYmlsaXR5LgojICAgICAgICAgICAgICAg"
    "ICAgICAgICAgICAgICAgICAgICAgIFdoYXRldmVyIGlzIHR5cGVkIGFzICJwYXNzd29yZCIgaXMKIyAgICAgICAgICAgICAg"
    "ICAgICAgICAgICAgICAgICAgICAgICBwYXJzZWQgb3V0IGFuZCB0aHJvd24gYXdheSB1bnJlYWQgLQojICAgICAgICAgICAg"
    "ICAgICAgICAgICAgICAgICAgICAgICAgIGl0IGlzIG5ldmVyIHN0b3JlZC9sb2dnZWQvdXNlZC4KIyAgIDMuICJjb29raWVf"
    "bmFtZT12YWx1ZSIgICAgICAgIDwtIGJhcmUgY29va2llLCBubyBsYWJlbCBhdCBhbGwgKG5vICI6OiIsCiMgICAgICAgICAg"
    "ICAgICAgICAgICAgICAgICAgICAgICAgICAgYnV0IGNvbnRhaW5zICI9IiBzbyBpdCdzIHJlY29nbmlzZWQKIyAgICAgICAg"
    "ICAgICAgICAgICAgICAgICAgICAgICAgICAgICBhcyBhIHJhdyBDb29raWUgdmFsdWUsIGUuZy4gYSBsaW5lCiMgICAgICAg"
    "ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdGhhdCdzIGp1c3QgIkpTRVNTSU9OSUQ9YWJjMTIzIikuCiMKIyBBIGxp"
    "bmUgd2l0aCBuZWl0aGVyICI6OiIgbm9yICI9IiAoanVzdCAibGFiZWwiIG9yICJsYWJlbDpwYXNzd29yZCIgYW5kCiMgbm90"
    "aGluZyBlbHNlKSBoYXMgbm8gY29va2llIHRvIHRlc3Qgd2l0aCBhbmQgaXMgcmVwb3J0ZWQgYXMgc2tpcHBlZC4KIwojIE11"
    "bHRpcGxlIGNvb2tpZSB2YWx1ZXMgZm9yIE9ORSBhY2NvdW50IChlLmcuIGEgc2Vzc2lvbiBjb29raWUgcGx1cyBhCiMgc2Vw"
    "YXJhdGUgQ1NSRi9YU1JGIGNvb2tpZSkgZ28gb24gdGhlIFNBTUUgbGluZSBhcyBvbmUgQ29va2llLWhlYWRlcgojIHN0cmlu"
    "Zywgc2VtaWNvbG9uLXNlcGFyYXRlZCAtIGUuZy46CiMgICBhbGljZTo6SlNFU1NJT05JRD1hYmMxMjM7IFhTUkYtVE9LRU49"
    "ZGVmNDU2CiMgKElmIHRoZSBzZWNvbmQgdmFsdWUgbXVzdCBiZSBzZW50IGFzIGl0cyBvd24gSFRUUCBoZWFkZXIgcmF0aGVy"
    "IHRoYW4gYQojIGNvb2tpZSAtIGUuZy4gYSBjdXN0b20gIlgtQ1NSRi1Ub2tlbjogLi4uIiBoZWFkZXIgLSB1c2UgLS1oZWFk"
    "ZXIgaW5zdGVhZC8KIyBpbiBhZGRpdGlvbjsgLS1jb29raWUgb25seSBldmVyIGZpbGxzIGluIHRoZSBDb29raWUgaGVhZGVy"
    "LikKIwojIElNUE9SVEFOVCAtIHRoaXMgZG9lcyBOT1QgYWRkIGEgbG9naW4gZmxvdy4gVGhpcyBzY3JpcHQgc3RpbGwgbmV2"
    "ZXIgbG9ncwojIGluLCBicnV0ZS1mb3JjZXMsIG9yIGhhcnZlc3RzIGNyZWRlbnRpYWxzIGFueXdoZXJlIChzZWUgdGhlIG1v"
    "ZHVsZQojIGRvY3N0cmluZykuIFRoZSBsYWJlbCBpcyB1c2VkIE9OTFkgYXMgYSByZWFkYWJsZSBuYW1lIGluIGV2aWRlbmNl"
    "IHRleHQKIyAoZS5nLiAiQWxpY2UiIGluc3RlYWQgb2YgIkFjY291bnQgMSIpLiBUaGUgb25seSB0aGluZyB0aGF0IGFjdHVh"
    "bGx5CiMgYXV0aGVudGljYXRlcyBhbnkgcmVxdWVzdCBpcyB0aGUgY29va2llIC0gaWYgYW4gZW50cnkgaGFzIG5vIGNvb2tp"
    "ZSBhdAojIGFsbCwgdGhlcmUgaXMgbm90aGluZyB0aGlzIHNjcmlwdCBjYW4gdGVzdCB3aXRoIGZvciB0aGF0IGFjY291bnQg"
    "KG5vCiMgdXNlcm5hbWUvcGFzc3dvcmQgYWxvbmUgZXZlciBwcm9kdWNlcyBhIHdvcmtpbmcgc2Vzc2lvbiBoZXJlKSwgYW5k"
    "IGl0J3MKIyByZXBvcnRlZCBhcyBza2lwcGVkIHJhdGhlciB0aGFuIHNpbGVudGx5IGlnbm9yZWQuCiMgLS0tLS0tLS0tLS0t"
    "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KCmRlZiBfcGFy"
    "c2VfY3JlZHNfbGluZShsaW5lKToKICAgICIiIk9uZSBjcmVkZW50aWFsL2Nvb2tpZSBlbnRyeSAtPiAobGFiZWwsIGNvb2tp"
    "ZSkuIGNvb2tpZSBpcyBOb25lIHdoZW4KICAgIHRoZSBlbnRyeSBoYXMgbm8gdXNhYmxlIGNvb2tpZSB2YWx1ZS4gUmV0dXJu"
    "cyBOb25lIGZvciBibGFuay9jb21tZW50CiAgICBsaW5lcy4gU2VlIHRoZSBibG9jayBjb21tZW50IGFib3ZlIGZvciB0aGUg"
    "MyBhY2NlcHRlZCBmb3Jtcy4iIiIKICAgIGxpbmUgPSBsaW5lLnN0cmlwKCkKICAgIGlmIG5vdCBsaW5lIG9yIGxpbmUuc3Rh"
    "cnRzd2l0aCgiIyIpOgogICAgICAgIHJldHVybiBOb25lCiAgICBpZiAiOjoiIGluIGxpbmU6CiAgICAgICAgIyBGb3JtcyAx"
    "IGFuZCAyOiAibGFiZWw6OmNvb2tpZSIgb3IgImxhYmVsOnBhc3N3b3JkOjpjb29raWUiLgogICAgICAgICMgV2hhdGV2ZXIg"
    "aXMgbGVmdCBvZiAiOjoiIGlzIG9ubHkgZXZlciB1c2VkIGFzIGEgZGlzcGxheSBsYWJlbCAtCiAgICAgICAgIyBpZiBpdCBp"
    "dHNlbGYgY29udGFpbnMgYSAiOiIgKHRoZSBsZWdhY3kgImxhYmVsOnBhc3N3b3JkIiBmb3JtKSwKICAgICAgICAjIGV2ZXJ5"
    "dGhpbmcgYWZ0ZXIgdGhhdCBmaXJzdCAiOiIgaXMgYW4gdW5yZWFkLCBkaXNjYXJkZWQgcGFzc3dvcmQuCiAgICAgICAgbGVm"
    "dF9wYXJ0LCBjb29raWVfcGFydCA9IGxpbmUuc3BsaXQoIjo6IiwgMSkKICAgICAgICBsYWJlbCwgXywgX3VudXNlZF9wYXNz"
    "d29yZCA9IGxlZnRfcGFydC5wYXJ0aXRpb24oIjoiKQogICAgICAgICMgX3VudXNlZF9wYXNzd29yZCBpcyBpbnRlbnRpb25h"
    "bGx5IHVucmVhZCBwYXN0IHRoaXMgbGluZSAtIHBhcnNlZAogICAgICAgICMgb3V0IGFuZCBkaXNjYXJkZWQgb24gcHVycG9z"
    "ZSwgbmV2ZXIgc3RvcmVkL2xvZ2dlZC93cml0dGVuCiAgICAgICAgIyBhbnl3aGVyZS4gTm8gcGFzc3dvcmQgaXMgcmVxdWly"
    "ZWQgaGVyZSBhdCBhbGwgKGZvcm0gMSkuCiAgICAgICAgbGFiZWwgPSBsYWJlbC5zdHJpcCgpIG9yIE5vbmUKICAgICAgICBj"
    "b29raWUgPSBjb29raWVfcGFydC5zdHJpcCgpIG9yIE5vbmUKICAgICAgICByZXR1cm4gKGxhYmVsLCBjb29raWUpCiAgICBp"
    "ZiAiPSIgaW4gbGluZToKICAgICAgICAjIEZvcm0gMzogbm8gIjo6IiBtYXJrZXIsIGJ1dCB0aGlzIGxvb2tzIGxpa2UgYSBy"
    "YXcgQ29va2llIGhlYWRlcgogICAgICAgICMgdmFsdWUgKG5hbWU9dmFsdWUpIHJhdGhlciB0aGFuIGEgImxhYmVsWzpwYXNz"
    "d29yZF0iIHBsYWNlaG9sZGVyIC0KICAgICAgICAjIHVzZSB0aGUgd2hvbGUgbGluZSBkaXJlY3RseSBhcyB0aGUgY29va2ll"
    "LCB3aXRoIG5vIGxhYmVsLgogICAgICAgIHJldHVybiAoTm9uZSwgbGluZSkKICAgICMgTm8gIjo6IiBhbmQgbm8gIj0iIC0g"
    "anVzdCBhIGJhcmUgbGFiZWwgb3IgImxhYmVsOnBhc3N3b3JkIiB3aXRoCiAgICAjIG5vdGhpbmcgdXNhYmxlIGFzIGEgY29v"
    "a2llIHlldC4KICAgIHVzZXJpZCwgXywgX3VudXNlZF9wYXNzd29yZCA9IGxpbmUucGFydGl0aW9uKCI6IikKICAgIGxhYmVs"
    "ID0gdXNlcmlkLnN0cmlwKCkgb3IgTm9uZQogICAgcmV0dXJuIChsYWJlbCwgTm9uZSkKCgpkZWYgbG9hZF9jcmVkc19lbnRy"
    "aWVzKGFyZ3MpOgogICAgIiIiQ29sbGVjdHMgdXAgdG8gMiAobGFiZWwsIGNvb2tpZSkgYWNjb3VudCBlbnRyaWVzIGZyb20g"
    "LS1jcmVkcy1maWxlCiAgICAob25lIGVudHJ5IHBlciBub24tY29tbWVudC9ub24tYmxhbmsgbGluZSAtIGxpbmUgMSA9IGFj"
    "Y291bnQgMSwgbGluZSAyCiAgICA9IGFjY291bnQgMiwgYSBmaWxlIHdpdGggb25seSBvbmUgbGluZSBtZWFucyBhIHNpbmds"
    "ZSBhY2NvdW50KSBhbmQvb3IKICAgIC0tY3JlZHMgKHJlcGVhdGFibGUsIHNhbWUgJ3VzZXJJRDpwYXNzd29yZFs6OmNvb2tp"
    "ZV0nIGZvcm1hdCwgYXBwZW5kZWQKICAgIGFmdGVyIGFueSAtLWNyZWRzLWZpbGUgZW50cmllcykuIE1vcmUgdGhhbiAyIGVu"
    "dHJpZXMgdG90YWwgaXMgdHJpbW1lZAogICAgdG8gMiB3aXRoIGEgd2FybmluZyAtIHRoaXMgc2NyaXB0IG9ubHkgZXZlciBj"
    "b21wYXJlcyB0d28gYWNjb3VudHMuIiIiCiAgICBlbnRyaWVzID0gW10KICAgIGlmIGdldGF0dHIoYXJncywgImNyZWRzX2Zp"
    "bGUiLCBOb25lKToKICAgICAgICB3aXRoIG9wZW4oYXJncy5jcmVkc19maWxlLCAiciIsIGVuY29kaW5nPSJ1dGYtOC1zaWci"
    "KSBhcyBmOgogICAgICAgICAgICBmb3IgbGluZSBpbiBmOgogICAgICAgICAgICAgICAgcGFyc2VkID0gX3BhcnNlX2NyZWRz"
    "X2xpbmUobGluZSkKICAgICAgICAgICAgICAgIGlmIHBhcnNlZDoKICAgICAgICAgICAgICAgICAgICBlbnRyaWVzLmFwcGVu"
    "ZChwYXJzZWQpCiAgICBpZiBnZXRhdHRyKGFyZ3MsICJjcmVkcyIsIE5vbmUpOgogICAgICAgIGZvciBjIGluIGFyZ3MuY3Jl"
    "ZHM6CiAgICAgICAgICAgIHBhcnNlZCA9IF9wYXJzZV9jcmVkc19saW5lKGMpCiAgICAgICAgICAgIGlmIHBhcnNlZDoKICAg"
    "ICAgICAgICAgICAgIGVudHJpZXMuYXBwZW5kKHBhcnNlZCkKICAgIGlmIGxlbihlbnRyaWVzKSA+IDI6CiAgICAgICAgcHJp"
    "bnQoZiJbIV0ge2xlbihlbnRyaWVzKX0gY3JlZGVudGlhbCBlbnRyaWVzIGdpdmVuIChmcm9tIC0tY3JlZHMtZmlsZS8tLWNy"
    "ZWRzIGNvbWJpbmVkKSAtIG9ubHkgdXNpbmcgIgogICAgICAgICAgICAgIGYidGhlIGZpcnN0IDI7IHRoaXMgc2NyaXB0IG9u"
    "bHkgZXZlciBjb21wYXJlcyBhIHR3by1hY2NvdW50IHBhaXIuIiwgZmlsZT1zeXMuc3RkZXJyKQogICAgICAgIGVudHJpZXMg"
    "PSBlbnRyaWVzWzoyXQogICAgcmV0dXJuIGVudHJpZXMKCgpkZWYgYXBwbHlfY3JlZHNfZW50cmllcyhhcmdzKToKICAgICIi"
    "IkFwcGxpZXMgbG9hZF9jcmVkc19lbnRyaWVzKCkgcmVzdWx0cyBvbnRvIGFyZ3MuY29va2llL2FyZ3MuY29va2llMi8KICAg"
    "IGFyZ3MuYWNjb3VudDFfbGFiZWwvYXJncy5hY2NvdW50Ml9sYWJlbCwgV0lUSE9VVCBvdmVyd3JpdGluZyBhbnl0aGluZwog"
    "ICAgdGhlIG9wZXJhdG9yIGFscmVhZHkgc2V0IGV4cGxpY2l0bHkgdmlhIC0tY29va2llLy0tY29va2llMi8KICAgIC0tYWNj"
    "b3VudDEtbGFiZWwvLS1hY2NvdW50Mi1sYWJlbCBkaXJlY3RseSAtIGV4cGxpY2l0IGZsYWdzIGFsd2F5cwogICAgd2luLiBD"
    "YWxsIHRoaXMgYmVmb3JlIHRoZSAtLWNvb2tpZS8tLWNvb2tpZTIgLT4gYWNjb3VudDFfY29va2llLwogICAgYWNjb3VudDJf"
    "Y29va2llIGRlcml2YXRpb24gaW4gbWFpbigpIHNvIHRoZSB0d28gZmVhdHVyZXMgY29tcG9zZS4iIiIKICAgIGVudHJpZXMg"
    "PSBsb2FkX2NyZWRzX2VudHJpZXMoYXJncykKICAgIGZvciBpLCAobGFiZWwsIGNvb2tpZSkgaW4gZW51bWVyYXRlKGVudHJp"
    "ZXMpOgogICAgICAgIHNsb3QgPSAxIGlmIGkgPT0gMCBlbHNlIDIKICAgICAgICB3aG8gPSBsYWJlbCBvciAoImFjY291bnQg"
    "MSIgaWYgc2xvdCA9PSAxIGVsc2UgImFjY291bnQgMiIpCiAgICAgICAgaWYgbm90IGNvb2tpZToKICAgICAgICAgICAgcHJp"
    "bnQoZiJbIV0gQ3JlZGVudGlhbCBlbnRyeSB7aSArIDF9ICh7d2hvfSkgaGFzIG5vIGNvb2tpZSB2YWx1ZSAtIHRoaXMgc2Ny"
    "aXB0IG5ldmVyIGxvZ3MgaW4gd2l0aCBhICIKICAgICAgICAgICAgICAgICAgZiJ1c2VybmFtZS9wYXNzd29yZCAobm8gcGFz"
    "c3dvcmQgbmVlZGVkIGF0IGFsbCAtIGRvbid0IGJvdGhlciB0eXBpbmcgb25lKSwgc28gdGhlcmUncyBub3RoaW5nICIKICAg"
    "ICAgICAgICAgICAgICAgZiJ0byB0ZXN0IHdpdGggZm9yIHRoaXMgYWNjb3VudC4gQWRkICc6OnNlc3Npb25pZD0uLi4nIGFm"
    "dGVyIHRoZSBsYWJlbCBvbiB0aGF0IGxpbmUvZW50cnkgKGEgIgogICAgICAgICAgICAgICAgICBmInNlc3Npb24gY29va2ll"
    "IFlPVSBhbHJlYWR5IG9idGFpbmVkIGJ5IGxvZ2dpbmcgaW4geW91cnNlbGYgYXMge3dob30pIHRvIGFjdHVhbGx5IHVzZSBp"
    "dC4iLAogICAgICAgICAgICAgICAgICBmaWxlPXN5cy5zdGRlcnIpCiAgICAgICAgICAgIGNvbnRpbnVlCiAgICAgICAgaWYg"
    "c2xvdCA9PSAxOgogICAgICAgICAgICBpZiBub3QgYXJncy5jb29raWU6CiAgICAgICAgICAgICAgICBhcmdzLmNvb2tpZSA9"
    "IGNvb2tpZQogICAgICAgICAgICBpZiBsYWJlbCBhbmQgbm90IGFyZ3MuYWNjb3VudDFfbGFiZWw6CiAgICAgICAgICAgICAg"
    "ICBhcmdzLmFjY291bnQxX2xhYmVsID0gbGFiZWwKICAgICAgICBlbHNlOgogICAgICAgICAgICBpZiBub3QgYXJncy5jb29r"
    "aWUyOgogICAgICAgICAgICAgICAgYXJncy5jb29raWUyID0gY29va2llCiAgICAgICAgICAgIGlmIGxhYmVsIGFuZCBub3Qg"
    "YXJncy5hY2NvdW50Ml9sYWJlbDoKICAgICAgICAgICAgICAgIGFyZ3MuYWNjb3VudDJfbGFiZWwgPSBsYWJlbAoKCmRlZiBu"
    "b3JtYWxpemVfdXJsKHUpOgogICAgaWYgbm90IHJlLm1hdGNoKHIiXmh0dHBzPzovLyIsIHUsIHJlLkkpOgogICAgICAgIHUg"
    "PSAiaHR0cHM6Ly8iICsgdQogICAgcmV0dXJuIHUKCgojID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
    "PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09CiMgUEhBU0VEIFBJUEVMSU5FIChvcHQtaW4gdmlhIC0tcGhh"
    "c2VzLCBkZWZhdWx0ICJiYXNlbGluZSIgPSB0aGUgfjEwMAojIGNoZWNrcyBhYm92ZSBvbmx5LCB1bmNoYW5nZWQgYmVoYXZp"
    "b3VyKS4gU2l4IHN0YWdlczoKIyAgIHJlY29uIC0+IGRpc2NvdmVyIC0+IGV4dHNjYW4gKG51Y2xlaS9uaWt0bykgLT4gaW5q"
    "ZWN0IC0+IGV4cGxvaXQgLT4gcmVwb3J0CiMgU2VsZWN0aW5nIGEgbGF0ZXIgcGhhc2UgYXV0b21hdGljYWxseSBwdWxscyBp"
    "biB0aGUgcGhhc2VzIGl0IGRlcGVuZHMgb24KIyAoc2VlIGV4cGFuZF9waGFzZV9kZXBlbmRlbmNpZXMoKSkuICJyZXBvcnQi"
    "IGlzbid0IGEgLS1waGFzZXMgdmFsdWUgLSB0aGUKIyBjb21wcmVoZW5zaXZlIHNldmVyaXR5LXdlaWdodGVkIHJlcG9ydCBp"
    "cyBhbHdheXMgd3JpdHRlbiBhdCB0aGUgZW5kIG9mCiMgbWFpbigpIGZyb20gd2hhdGV2ZXIgUkVTVUxUUyBldmVyeSBzZWxl"
    "Y3RlZCBwaGFzZSBwcm9kdWNlZC4KIyA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
    "PT09PT09PT09PT09PT09PT09PT09PT09PQoKIyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t"
    "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQojIFJlY29uIHBoYXNlIC0gc2FtZS1vcmlnaW4gY3Jhd2wsIHR1cm5z"
    "IFdBLU9URy0yNzYvMjc3IChlbnRyeSBwb2ludHMgLwojIGV4ZWN1dGlvbiBwYXRocyAtIE1BTlVBTCBpbiB0aGUgYmFzZWxp"
    "bmUgc3VpdGUsICJuZWVkcyBmdWxsIGNyYXdsaW5nIikKIyBpbnRvIGEgcmVhbCBhdXRvbWF0ZWQgcGFzcy4KIyAtLS0tLS0t"
    "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQoKZGVm"
    "IGNyYXdsX3NpdGUoc3RhcnRfdXJsLCBhcmdzLCBtYXhfcGFnZXMsIG1heF9kZXB0aCk6CiAgICAiIiJTbWFsbCBzYW1lLW9y"
    "aWdpbiBCRlMgY3Jhd2xlciwgc3RkbGliLW9ubHkgLSBzZWVzIG9ubHkgd2hhdCdzIGluIHJhdwogICAgSFRNTCAoQ1JBV0xf"
    "TElOS19SRSksIG5vIEpTLXJlbmRlcmVkIGxpbmtzL3JvdXRlcywgc2FtZSBuby1kZXBlbmRlbmN5CiAgICB0cmFkZW9mZiBh"
    "cyB0aGUgcmVzdCBvZiB0aGlzIHNjcmlwdC4gQm91bmRlZCBieSBtYXhfcGFnZXMvbWF4X2RlcHRoIHNvCiAgICBhIGxhcmdl"
    "IHNpdGUgY2FuJ3QgdHVybiBvbmUgdGFyZ2V0IGludG8gYW4gdW5ib3VuZGVkIGNyYXdsLiIiIgogICAgcGFyc2VkX3N0YXJ0"
    "ID0gdXJscGFyc2Uoc3RhcnRfdXJsKQogICAgb3JpZ2luID0gKHBhcnNlZF9zdGFydC5zY2hlbWUsIHBhcnNlZF9zdGFydC5o"
    "b3N0bmFtZSwgcGFyc2VkX3N0YXJ0LnBvcnQpCiAgICBzZWVuID0gc2V0KCkKICAgIHF1ZXVlID0gWyhzdGFydF91cmwsIDAp"
    "XQogICAgcGFnZXMgPSBbXQogICAgd2hpbGUgcXVldWUgYW5kIGxlbihwYWdlcykgPCBtYXhfcGFnZXM6CiAgICAgICAgdXJs"
    "LCBkZXB0aCA9IHF1ZXVlLnBvcCgwKQogICAgICAgIG5vcm0gPSB1cmwuc3BsaXQoIiMiKVswXQogICAgICAgIGlmIG5vcm0g"
    "aW4gc2VlbjoKICAgICAgICAgICAgY29udGludWUKICAgICAgICBzZWVuLmFkZChub3JtKQogICAgICAgIHIgPSByYXdfcmVx"
    "dWVzdChub3JtLCAiR0VUIiwgdGltZW91dD1hcmdzLnRpbWVvdXQsIGluc2VjdXJlPWFyZ3MuaW5zZWN1cmUpCiAgICAgICAg"
    "aWYgci5lcnJvciBvciBub3Qgci5zdGF0dXMgb3Igci5zdGF0dXMgPj0gNDAwOgogICAgICAgICAgICBjb250aW51ZQogICAg"
    "ICAgIHBhZ2VzLmFwcGVuZCgobm9ybSwgcikpCiAgICAgICAgaWYgZGVwdGggPj0gbWF4X2RlcHRoOgogICAgICAgICAgICBj"
    "b250aW51ZQogICAgICAgIGlmICJodG1sIiBub3QgaW4gKHIuaGVhZGVyKCJDb250ZW50LVR5cGUiKSBvciAiIikubG93ZXIo"
    "KToKICAgICAgICAgICAgY29udGludWUKICAgICAgICBmb3IgbSBpbiBDUkFXTF9MSU5LX1JFLmZpbmRpdGVyKHIudGV4dCgp"
    "KToKICAgICAgICAgICAgbGluayA9IG0uZ3JvdXAoMSkKICAgICAgICAgICAgaWYgbGluay5zdGFydHN3aXRoKCgibWFpbHRv"
    "OiIsICJ0ZWw6IiwgImphdmFzY3JpcHQ6IiwgImRhdGE6IikpOgogICAgICAgICAgICAgICAgY29udGludWUKICAgICAgICAg"
    "ICAgYWJzX2xpbmsgPSB1cmxqb2luKG5vcm0sIGxpbmspLnNwbGl0KCIjIilbMF0KICAgICAgICAgICAgcCA9IHVybHBhcnNl"
    "KGFic19saW5rKQogICAgICAgICAgICBpZiAocC5zY2hlbWUsIHAuaG9zdG5hbWUsIHAucG9ydCkgIT0gb3JpZ2luOgogICAg"
    "ICAgICAgICAgICAgY29udGludWUKICAgICAgICAgICAgaWYgYWJzX2xpbmsgbm90IGluIHNlZW46CiAgICAgICAgICAgICAg"
    "ICBxdWV1ZS5hcHBlbmQoKGFic19saW5rLCBkZXB0aCArIDEpKQogICAgcmV0dXJuIHBhZ2VzCgoKZGVmIHBoYXNlX3JlY29u"
    "KGZ1bGxfdXJsLCBhcmdzKToKICAgIHByaW50KGYiICAgIFtyZWNvbl0gY3Jhd2xpbmcgZnJvbSB7ZnVsbF91cmx9IChtYXgg"
    "e2FyZ3MuY3Jhd2xfbWF4X3BhZ2VzfSBwYWdlcywgZGVwdGgge2FyZ3MuY3Jhd2xfZGVwdGh9KS4uLiIpCiAgICBwYWdlcyA9"
    "IGNyYXdsX3NpdGUoZnVsbF91cmwsIGFyZ3MsIG1heF9wYWdlcz1hcmdzLmNyYXdsX21heF9wYWdlcywgbWF4X2RlcHRoPWFy"
    "Z3MuY3Jhd2xfZGVwdGgpCiAgICB1cmxzX2ZvdW5kID0gW3UgZm9yIHUsIF8gaW4gcGFnZXNdCiAgICBhZGQoZnVsbF91cmws"
    "ICJXQS1PVEctMjc2IiwgIkluZm9ybWF0aW9uIEdhdGhlcmluZyIsICJFbnVtZXJhdGUgYXBwbGljYXRpb24gZW50cnkgcG9p"
    "bnRzIChhbGwgcGFyYW1zL2Zvcm1zKSIsCiAgICAgICAgIkluZm8iLCAiUDMiLCAiSU5GTyIgaWYgdXJsc19mb3VuZCBlbHNl"
    "ICJNQU5VQUwiLAogICAgICAgIChmIlJlY29uIHBoYXNlIGNyYXdsIGZvdW5kIHtsZW4odXJsc19mb3VuZCl9IHNhbWUtb3Jp"
    "Z2luIHBhZ2UocykgKGJvdW5kZWQgYnkgLS1jcmF3bC1tYXgtcGFnZXMgIgogICAgICAgICBmInthcmdzLmNyYXdsX21heF9w"
    "YWdlc30gLyAtLWNyYXdsLWRlcHRoIHthcmdzLmNyYXdsX2RlcHRofSk6ICIgKyAiLCAiLmpvaW4odXJsc19mb3VuZFs6MTVd"
    "KQogICAgICAgICArICgiIC4uLiIgaWYgbGVuKHVybHNfZm91bmQpID4gMTUgZWxzZSAiIikpIGlmIHVybHNfZm91bmQgZWxz"
    "ZQogICAgICAgICJSZWNvbiBwaGFzZSBjcmF3bCBmb3VuZCBubyByZWFjaGFibGUgc2FtZS1vcmlnaW4gcGFnZXMgYmV5b25k"
    "IHRoZSBnaXZlbiBVUkwgLSBKUy1yZW5kZXJlZC9TUEEgcm91dGVzICIKICAgICAgICAiYXJlbid0IHZpc2libGUgdG8gYSBy"
    "YXctSFRNTCBjcmF3bCwgcmV2aWV3IHRob3NlIG1hbnVhbGx5LiIpCiAgICBhZGQoZnVsbF91cmwsICJXQS1PVEctMjc3Iiwg"
    "IkluZm9ybWF0aW9uIEdhdGhlcmluZyIsICJNYXAgZXhlY3V0aW9uIHBhdGhzIHRocm91Z2ggYXBwbGljYXRpb24iLAogICAg"
    "ICAgICJJbmZvIiwgIlAzIiwgIklORk8iIGlmIHVybHNfZm91bmQgZWxzZSAiTUFOVUFMIiwKICAgICAgICAoZiJ7bGVuKHVy"
    "bHNfZm91bmQpfSBwYWdlKHMpIG1hcHBlZCB0aGlzIHBhc3MgLSBzZWUgV0EtT1RHLTI3NiBmb3IgdGhlIGxpc3QuIEpTLXJl"
    "bmRlcmVkL1NQQSByb3V0ZXMgbm90ICIKICAgICAgICAgInJlYWNoYWJsZSBmcm9tIHJhdyBIVE1MIGxpbmtzIGFyZSBOT1Qg"
    "Y292ZXJlZCAtIHRob3NlIHN0aWxsIG5lZWQgbWFudWFsIHJldmlldyBvciBhIGhlYWRsZXNzLWJyb3dzZXIgIgogICAgICAg"
    "ICAiY3Jhd2wuIikgaWYgdXJsc19mb3VuZCBlbHNlICJObyBwYWdlcyB0byBtYXAgLSBzZWUgV0EtT1RHLTI3Ni4iKQogICAg"
    "cmV0dXJuIHBhZ2VzCgoKIyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t"
    "LS0tLS0tLS0tLS0tLS0tLS0tLQojIERpc2NvdmVyIHBoYXNlIC0gImxvb2tpbmcgZm9yIGZpbmRzIjogdHVybnMgdGhlIHJl"
    "Y29uIHBoYXNlJ3MgY3Jhd2xlZAojIHBhZ2VzIGludG8gYSBjb25jcmV0ZSBsaXN0IG9mIGluamVjdGFibGUgKHVybCwgbWV0"
    "aG9kLCBwYXJhbSkgZmllbGRzIGZvcgojIHRoZSBpbmplY3QvZXhwbG9pdCBwaGFzZXMgdG8gYWN0dWFsbHkgdGVzdC4KIyAt"
    "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t"
    "LQoKVFlQRV9BVFRSX1JFID0gcmUuY29tcGlsZShyJ3R5cGVccyo9XHMqWyJcJ10oW14iXCddKylbIlwnXScsIHJlLklHTk9S"
    "RUNBU0UpClNLSVBfRklFTERfVFlQRVMgPSB7InN1Ym1pdCIsICJidXR0b24iLCAiZmlsZSIsICJpbWFnZSIsICJyZXNldCJ9"
    "CgoKZGVmIGV4dHJhY3RfZmllbGRzX2Zyb21fcGFnZSh1cmwsIGh0dHBfcmVzdWx0KToKICAgICIiIk9uZSBwYWdlJ3MgZm9y"
    "bSBmaWVsZHMgKyBpdHMgb3duIFVSTCBxdWVyeS1zdHJpbmcgcGFyYW1zLCB2aWEKICAgIHJlZ2V4IChub3QgYSByZWFsIEhU"
    "TUwgcGFyc2VyIC0gSlMtYWRkZWQgZmllbGRzIGFyZW4ndCBzZWVuKS4gUmV0dXJucwogICAgYSBsaXN0IG9mIHt1cmwsIG1l"
    "dGhvZCwgbG9jYXRpb24sIHBhcmFtLCBzb3VyY2V9IGRpY3RzLiIiIgogICAgZmllbGRzID0gW10KICAgIGJvZHkgPSBodHRw"
    "X3Jlc3VsdC50ZXh0KCkgaWYgbm90IGh0dHBfcmVzdWx0LmVycm9yIGVsc2UgIiIKCiAgICBwYXJzZWQgPSB1cmxwYXJzZSh1"
    "cmwpCiAgICBpZiBwYXJzZWQucXVlcnk6CiAgICAgICAgZm9yIHBhaXIgaW4gcGFyc2VkLnF1ZXJ5LnNwbGl0KCImIik6CiAg"
    "ICAgICAgICAgIG5hbWUgPSBwYWlyLnNwbGl0KCI9IilbMF0KICAgICAgICAgICAgaWYgbmFtZToKICAgICAgICAgICAgICAg"
    "IGZpZWxkcy5hcHBlbmQoeyJ1cmwiOiB1cmwsICJtZXRob2QiOiAiR0VUIiwgImxvY2F0aW9uIjogInF1ZXJ5IiwKICAgICAg"
    "ICAgICAgICAgICAgICAgICAgICAgICAgICAicGFyYW0iOiBuYW1lLCAic291cmNlIjogIlVSTCBxdWVyeSBzdHJpbmcifSkK"
    "CiAgICBmb3IgZm9ybV9tYXRjaCBpbiBGT1JNX0JMT0NLX1JFLmZpbmRpdGVyKGJvZHkpOgogICAgICAgIGZvcm1faHRtbCA9"
    "IGZvcm1fbWF0Y2guZ3JvdXAoMCkKICAgICAgICBhdHRyc19tYXRjaCA9IEZPUk1fQVRUUl9SRS5zZWFyY2goZm9ybV9odG1s"
    "KQogICAgICAgIG1ldGhvZCwgYWN0aW9uID0gIkdFVCIsIHVybAogICAgICAgIGlmIGF0dHJzX21hdGNoOgogICAgICAgICAg"
    "ICBtX21ldGhvZCA9IE1FVEhPRF9BVFRSX1JFLnNlYXJjaChhdHRyc19tYXRjaC5ncm91cCgxKSkKICAgICAgICAgICAgaWYg"
    "bV9tZXRob2Q6CiAgICAgICAgICAgICAgICBtZXRob2QgPSBtX21ldGhvZC5ncm91cCgxKS5zdHJpcCgpLnVwcGVyKCkKICAg"
    "ICAgICAgICAgbV9hY3Rpb24gPSBBQ1RJT05fQVRUUl9SRS5zZWFyY2goYXR0cnNfbWF0Y2guZ3JvdXAoMSkpCiAgICAgICAg"
    "ICAgIGlmIG1fYWN0aW9uIGFuZCBtX2FjdGlvbi5ncm91cCgxKToKICAgICAgICAgICAgICAgIGFjdGlvbiA9IHVybGpvaW4o"
    "dXJsLCBtX2FjdGlvbi5ncm91cCgxKSkKICAgICAgICBmb3IgZmllbGRfbWF0Y2ggaW4gRklFTERfVEFHX1JFLmZpbmRpdGVy"
    "KGZvcm1faHRtbCk6CiAgICAgICAgICAgIGF0dHJzID0gZmllbGRfbWF0Y2guZ3JvdXAoMSkKICAgICAgICAgICAgdHlwZV9t"
    "YXRjaCA9IFRZUEVfQVRUUl9SRS5zZWFyY2goYXR0cnMpCiAgICAgICAgICAgIGlmIHR5cGVfbWF0Y2ggYW5kIHR5cGVfbWF0"
    "Y2guZ3JvdXAoMSkuc3RyaXAoKS5sb3dlcigpIGluIFNLSVBfRklFTERfVFlQRVM6CiAgICAgICAgICAgICAgICBjb250aW51"
    "ZQogICAgICAgICAgICBuYW1lX21hdGNoID0gTkFNRV9BVFRSX1JFLnNlYXJjaChhdHRycykKICAgICAgICAgICAgaWYgbmFt"
    "ZV9tYXRjaDoKICAgICAgICAgICAgICAgIGZpZWxkcy5hcHBlbmQoeyJ1cmwiOiBhY3Rpb24sICJtZXRob2QiOiBtZXRob2Qs"
    "ICJsb2NhdGlvbiI6ICJmb3JtIiwKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAicGFyYW0iOiBuYW1lX21hdGNo"
    "Lmdyb3VwKDEpLCAic291cmNlIjogZiI8Zm9ybT4gb24ge3VybH0ifSkKICAgIHJldHVybiBmaWVsZHMKCgpkZWYgcGhhc2Vf"
    "ZGlzY292ZXIoZnVsbF91cmwsIHBhZ2VzLCBhcmdzKToKICAgIGFsbF9maWVsZHMgPSBbXQogICAgZm9yIHVybCwgciBpbiBw"
    "YWdlczoKICAgICAgICBhbGxfZmllbGRzLmV4dGVuZChleHRyYWN0X2ZpZWxkc19mcm9tX3BhZ2UodXJsLCByKSkKICAgIHNl"
    "ZW4sIGRlZHVwZWQgPSBzZXQoKSwgW10KICAgIGZvciBmIGluIGFsbF9maWVsZHM6CiAgICAgICAga2V5ID0gKGZbInVybCJd"
    "LCBmWyJtZXRob2QiXSwgZlsibG9jYXRpb24iXSwgZlsicGFyYW0iXSkKICAgICAgICBpZiBrZXkgaW4gc2VlbjoKICAgICAg"
    "ICAgICAgY29udGludWUKICAgICAgICBzZWVuLmFkZChrZXkpCiAgICAgICAgZGVkdXBlZC5hcHBlbmQoZikKCiAgICBhZGQo"
    "ZnVsbF91cmwsICJXQS1ESVNDLTAwMSIsICJEaXNjb3ZlcnkiLCAiRW51bWVyYXRlIGluamVjdGFibGUgcGFyYW1ldGVycyAo"
    "Zm9ybSBmaWVsZHMgKyBxdWVyeSBwYXJhbXMpIiwKICAgICAgICAiSW5mbyIsICJQMyIsICJJTkZPIiBpZiBkZWR1cGVkIGVs"
    "c2UgIk1BTlVBTCIsCiAgICAgICAgKGYiRm91bmQge2xlbihkZWR1cGVkKX0gY2FuZGlkYXRlIHBhcmFtZXRlcihzKSBhY3Jv"
    "c3Mge2xlbihwYWdlcyl9IGNyYXdsZWQgcGFnZShzKTogIiArCiAgICAgICAgICI7ICIuam9pbihmIntmWydwYXJhbSddfSAo"
    "e2ZbJ2xvY2F0aW9uJ119LCB7ZlsnbWV0aG9kJ119IG9uIHtmWyd1cmwnXX0pIiBmb3IgZiBpbiBkZWR1cGVkWzoyMF0pICsK"
    "ICAgICAgICAgKGYiIC4uLiBhbmQge2xlbihkZWR1cGVkKSAtIDIwfSBtb3JlIiBpZiBsZW4oZGVkdXBlZCkgPiAyMCBlbHNl"
    "ICIiKSkgaWYgZGVkdXBlZCBlbHNlCiAgICAgICAgIk5vIGZvcm0gZmllbGRzIG9yIFVSTCBxdWVyeS1zdHJpbmcgcGFyYW1l"
    "dGVycyBmb3VuZCBvbiBhbnkgY3Jhd2xlZCBwYWdlIC0gbm90aGluZyBmb3IgdGhlIGluamVjdC9leHBsb2l0ICIKICAgICAg"
    "ICAicGhhc2VzIHRvIHRlc3QgaGVyZS4iKQogICAgcmV0dXJuIGRlZHVwZWQKCgojIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t"
    "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiMgRXh0c2NhbiBwaGFzZSAtIG51"
    "Y2xlaSAvIG5pa3RvLCBhdXRvLWRldGVjdGVkIHZpYSBQQVRIIChzYW1lIHBhdHRlcm4gYXMKIyBjdXJsL25tYXAvc3NseXpl"
    "IGFib3ZlKS4gQSBtaXNzaW5nIHRvb2wgZGVncmFkZXMgdG8gTUFOVUFMLCBzYW1lCiMgZ3JhY2VmdWwtZGVncmFkZSBwaGls"
    "b3NvcGh5IGFzIGV2ZXJ5d2hlcmUgZWxzZSBpbiB0aGlzIHNjcmlwdC4KIyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t"
    "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQoKZGVmIHJ1bl9udWNsZWkodXJsLCBhcmdz"
    "KToKICAgIGlmIG5vdCBfY2xpX2F2YWlsYWJsZSgibnVjbGVpIik6CiAgICAgICAgcmV0dXJuIE5vbmUKICAgIGNtZCA9IFsi"
    "bnVjbGVpIiwgIi11IiwgdXJsLCAiLWpzb25sIiwgIi1zaWxlbnQiLCAiLXRpbWVvdXQiLCBzdHIoaW50KGFyZ3MudGltZW91"
    "dCkgb3IgMTApXQogICAgdHJ5OgogICAgICAgIHByb2MgPSBzdWJwcm9jZXNzLnJ1bihjbWQsIGNhcHR1cmVfb3V0cHV0PVRy"
    "dWUsIHRpbWVvdXQ9YXJncy5udWNsZWlfdGltZW91dCkKICAgICAgICByZXR1cm4gY21kLCBwcm9jLnN0ZG91dC5kZWNvZGUo"
    "InV0Zi04IiwgZXJyb3JzPSJyZXBsYWNlIiksIHByb2Muc3RkZXJyLmRlY29kZSgidXRmLTgiLCBlcnJvcnM9InJlcGxhY2Ui"
    "KS5zdHJpcCgpCiAgICBleGNlcHQgc3VicHJvY2Vzcy5UaW1lb3V0RXhwaXJlZDoKICAgICAgICByZXR1cm4gY21kLCAiIiwg"
    "ZiIobnVjbGVpIHRpbWVkIG91dCBhZnRlciB7YXJncy5udWNsZWlfdGltZW91dH1zIC0gdHJ5IGEgbG9uZ2VyIC0tbnVjbGVp"
    "LXRpbWVvdXQpIgogICAgZXhjZXB0IEV4Y2VwdGlvbiBhcyBlOgogICAgICAgIHJldHVybiBjbWQsICIiLCBmIihudWNsZWkg"
    "ZXhlY3V0aW9uIGZhaWxlZDoge2V9KSIKCgpfTlVDTEVJX1NFVl9UT19XUFQgPSB7ImNyaXRpY2FsIjogKCJDcml0aWNhbCIs"
    "ICJQMSIpLCAiaGlnaCI6ICgiSGlnaCIsICJQMSIpLCAibWVkaXVtIjogKCJNZWRpdW0iLCAiUDIiKSwKICAgICAgICAgICAg"
    "ICAgICAgICAgICAibG93IjogKCJMb3ciLCAiUDMiKSwgImluZm8iOiAoIkluZm8iLCAiUDMiKSwgInVua25vd24iOiAoIklu"
    "Zm8iLCAiUDMiKX0KCgpkZWYgcGhhc2VfZXh0c2Nhbl9udWNsZWkoZnVsbF91cmwsIGFyZ3MpOgogICAgcmVzdWx0ID0gcnVu"
    "X251Y2xlaShmdWxsX3VybCwgYXJncykKICAgIGlmIHJlc3VsdCBpcyBOb25lOgogICAgICAgIGFkZChmdWxsX3VybCwgIldB"
    "LUVYVC1OVUNMRUkiLCAiRXh0ZXJuYWwgU2Nhbm5lciIsICJudWNsZWkgdGVtcGxhdGUgc2NhbiIsICJJbmZvIiwgIlAzIiwg"
    "Ik1BTlVBTCIsCiAgICAgICAgICAgICJudWNsZWkgbm90IGZvdW5kIG9uIFBBVEggLSBpbnN0YWxsIGl0IChodHRwczovL2dp"
    "dGh1Yi5jb20vcHJvamVjdGRpc2NvdmVyeS9udWNsZWkpIHRvIGVuYWJsZSAiCiAgICAgICAgICAgICJhdXRvbWF0ZWQgQ1ZF"
    "L21pc2NvbmZpZ3VyYXRpb24gdGVtcGxhdGUgc2Nhbm5pbmcgZm9yIHRoaXMgcGhhc2UuIikKICAgICAgICByZXR1cm4KICAg"
    "IGNtZCwgb3V0LCBlcnIgPSByZXN1bHQKICAgIGxpbmVzID0gW2wgZm9yIGwgaW4gb3V0LnNwbGl0bGluZXMoKSBpZiBsLnN0"
    "cmlwKCkuc3RhcnRzd2l0aCgieyIpXQogICAgaWYgbm90IGxpbmVzOgogICAgICAgIGFkZChmdWxsX3VybCwgIldBLUVYVC1O"
    "VUNMRUkiLCAiRXh0ZXJuYWwgU2Nhbm5lciIsICJudWNsZWkgdGVtcGxhdGUgc2NhbiIsICJJbmZvIiwgIlAzIiwgIlBBU1Mi"
    "LAogICAgICAgICAgICAibnVjbGVpIHJhbiwgbm8gZmluZGluZ3MuIiArIChmIiBzdGRlcnI6IHtlcnJ9IiBpZiBlcnIgZWxz"
    "ZSAiIikKICAgICAgICAgICAgKyBfZm9ybWF0X2NtZF9ibG9jayhjbWQsIG91dCBvciBlcnIgb3IgIihubyBvdXRwdXQpIikp"
    "CiAgICAgICAgcmV0dXJuCiAgICBmb3IgbGluZSBpbiBsaW5lczoKICAgICAgICB0cnk6CiAgICAgICAgICAgIGZpbmRpbmcg"
    "PSBqc29uLmxvYWRzKGxpbmUpCiAgICAgICAgZXhjZXB0IEV4Y2VwdGlvbjoKICAgICAgICAgICAgY29udGludWUKICAgICAg"
    "ICBpbmZvID0gZmluZGluZy5nZXQoImluZm8iLCB7fSkgb3Ige30KICAgICAgICBzZXYgPSBzdHIoaW5mby5nZXQoInNldmVy"
    "aXR5Iikgb3IgInVua25vd24iKS5sb3dlcigpCiAgICAgICAgd3B0X3Nldiwgd3B0X3ByaSA9IF9OVUNMRUlfU0VWX1RPX1dQ"
    "VC5nZXQoc2V2LCAoIkluZm8iLCAiUDMiKSkKICAgICAgICB0ZW1wbGF0ZV9pZCA9IGZpbmRpbmcuZ2V0KCJ0ZW1wbGF0ZS1p"
    "ZCIsICJ1bmtub3duLXRlbXBsYXRlIikKICAgICAgICBtYXRjaGVkID0gZmluZGluZy5nZXQoIm1hdGNoZWQtYXQiKSBvciBm"
    "aW5kaW5nLmdldCgiaG9zdCIpIG9yIGZ1bGxfdXJsCiAgICAgICAgYWRkKG1hdGNoZWQsIGYiV0EtRVhULU5VQ0xFSS17dGVt"
    "cGxhdGVfaWR9IiwgIkV4dGVybmFsIFNjYW5uZXIiLCBpbmZvLmdldCgibmFtZSIsIHRlbXBsYXRlX2lkKSBvciB0ZW1wbGF0"
    "ZV9pZCwKICAgICAgICAgICAgd3B0X3Nldiwgd3B0X3ByaSwgIkZBSUwiLAogICAgICAgICAgICBmIm51Y2xlaSB0ZW1wbGF0"
    "ZSB7dGVtcGxhdGVfaWQhcn0gbWF0Y2hlZC4ge3N0cihpbmZvLmdldCgnZGVzY3JpcHRpb24nKSBvciAnJylbOjMwMF19Igog"
    "ICAgICAgICAgICArIF9mb3JtYXRfY21kX2Jsb2NrKGNtZCwgbGluZSkpCgoKZGVmIHJ1bl9uaWt0byh1cmwsIGFyZ3MpOgog"
    "ICAgaWYgbm90IF9jbGlfYXZhaWxhYmxlKCJuaWt0byIpOgogICAgICAgIHJldHVybiBOb25lCiAgICBjbWQgPSBbIm5pa3Rv"
    "IiwgIi1oIiwgdXJsLCAiLXRpbWVvdXQiLCBzdHIoaW50KGFyZ3MudGltZW91dCkgb3IgMTApXQogICAgaWYgdXJscGFyc2Uo"
    "dXJsKS5zY2hlbWUgPT0gImh0dHBzIjoKICAgICAgICBjbWQuYXBwZW5kKCItc3NsIikKICAgIHRyeToKICAgICAgICBwcm9j"
    "ID0gc3VicHJvY2Vzcy5ydW4oY21kLCBjYXB0dXJlX291dHB1dD1UcnVlLCB0aW1lb3V0PWFyZ3MubmlrdG9fdGltZW91dCkK"
    "ICAgICAgICByZXR1cm4gY21kLCBwcm9jLnN0ZG91dC5kZWNvZGUoInV0Zi04IiwgZXJyb3JzPSJyZXBsYWNlIiksIHByb2Mu"
    "c3RkZXJyLmRlY29kZSgidXRmLTgiLCBlcnJvcnM9InJlcGxhY2UiKS5zdHJpcCgpCiAgICBleGNlcHQgc3VicHJvY2Vzcy5U"
    "aW1lb3V0RXhwaXJlZDoKICAgICAgICByZXR1cm4gY21kLCAiIiwgZiIobmlrdG8gdGltZWQgb3V0IGFmdGVyIHthcmdzLm5p"
    "a3RvX3RpbWVvdXR9cyAtIHRyeSBhIGxvbmdlciAtLW5pa3RvLXRpbWVvdXQpIgogICAgZXhjZXB0IEV4Y2VwdGlvbiBhcyBl"
    "OgogICAgICAgIHJldHVybiBjbWQsICIiLCBmIihuaWt0byBleGVjdXRpb24gZmFpbGVkOiB7ZX0pIgoKCmRlZiBwaGFzZV9l"
    "eHRzY2FuX25pa3RvKGZ1bGxfdXJsLCBhcmdzKToKICAgIHJlc3VsdCA9IHJ1bl9uaWt0byhmdWxsX3VybCwgYXJncykKICAg"
    "IGlmIHJlc3VsdCBpcyBOb25lOgogICAgICAgIGFkZChmdWxsX3VybCwgIldBLUVYVC1OSUtUTyIsICJFeHRlcm5hbCBTY2Fu"
    "bmVyIiwgIm5pa3RvIHdlYiBzZXJ2ZXIgc2NhbiIsICJJbmZvIiwgIlAzIiwgIk1BTlVBTCIsCiAgICAgICAgICAgICJuaWt0"
    "byBub3QgZm91bmQgb24gUEFUSCAtIGluc3RhbGwgaXQgKGFwdCBpbnN0YWxsIG5pa3RvLCBvciBodHRwczovL2dpdGh1Yi5j"
    "b20vc3VsbG8vbmlrdG8pIHRvIGVuYWJsZSAiCiAgICAgICAgICAgICJhdXRvbWF0ZWQgd2ViIHNlcnZlciBtaXNjb25maWd1"
    "cmF0aW9uIHNjYW5uaW5nIGZvciB0aGlzIHBoYXNlLiIpCiAgICAgICAgcmV0dXJuCiAgICBjbWQsIG91dCwgZXJyID0gcmVz"
    "dWx0CiAgICBmaW5kaW5nX2xpbmVzID0gW2wgZm9yIGwgaW4gb3V0LnNwbGl0bGluZXMoKSBpZiBsLnN0cmlwKCkuc3RhcnRz"
    "d2l0aCgiKyIpCiAgICAgICAgICAgICAgICAgICAgICBhbmQgbm90IGwuc3RhcnRzd2l0aCgoIisgVGFyZ2V0IiwgIisgU3Rh"
    "cnQgVGltZSIsICIrIFNlcnZlcjoiLCAiKyBFbmQgVGltZSIpKV0KICAgIGlmIG5vdCBmaW5kaW5nX2xpbmVzOgogICAgICAg"
    "IGFkZChmdWxsX3VybCwgIldBLUVYVC1OSUtUTyIsICJFeHRlcm5hbCBTY2FubmVyIiwgIm5pa3RvIHdlYiBzZXJ2ZXIgc2Nh"
    "biIsICJJbmZvIiwgIlAzIiwgIlBBU1MiLAogICAgICAgICAgICAibmlrdG8gcmFuLCBubyBmaW5kaW5ncyByZXBvcnRlZC4i"
    "ICsgX2Zvcm1hdF9jbWRfYmxvY2soY21kLCBvdXQgb3IgZXJyIG9yICIobm8gb3V0cHV0KSIpKQogICAgICAgIHJldHVybgog"
    "ICAgYWRkKGZ1bGxfdXJsLCAiV0EtRVhULU5JS1RPIiwgIkV4dGVybmFsIFNjYW5uZXIiLCAibmlrdG8gd2ViIHNlcnZlciBz"
    "Y2FuIiwgIk1lZGl1bSIsICJQMiIsICJGQUlMIiwKICAgICAgICBmIm5pa3RvIHJlcG9ydGVkIHtsZW4oZmluZGluZ19saW5l"
    "cyl9IGZpbmRpbmcocyk6XG4iICsgIlxuIi5qb2luKGZpbmRpbmdfbGluZXNbOjQwXSkgKyBfZm9ybWF0X2NtZF9ibG9jayhj"
    "bWQsIG91dCkpCgoKIyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t"
    "LS0tLS0tLS0tLS0tLS0tLQojIEluamVjdCBwaGFzZSAtIHNlbmRzIHRoZSBidWlsdC1pbiBwYXlsb2FkIGxpc3RzIChzZWUg"
    "dG9wLW9mLWZpbGUKIyBCQVNJQ18qX1BBWUxPQURTKSBpbnRvIGV2ZXJ5IGRpc2NvdmVyZWQgZmllbGQgYW5kIGFwcGxpZXMg"
    "YSBjb25zZXJ2YXRpdmUKIyByZXNwb25zZS1vcmFjbGUgaGV1cmlzdGljIHBlciBjYXRlZ29yeS4gQSBDT05GSVJNRUQgaGl0"
    "IGhlcmUgbWVhbnMgImEKIyByZWFsIHNpZ25hbCBjYW1lIGJhY2siIChlcnJvciBzdHJpbmcgLyByZWZsZWN0ZWQgbWFya2Vy"
    "IC8gdGltaW5nKSAtIGl0CiMgZG9lcyBOT1QgbWVhbiBkYXRhIHdhcyBleHRyYWN0ZWQgb3IgY29kZSBleGVjdXRlZDsgdGhh"
    "dCdzIHRoZSBleHBsb2l0CiMgcGhhc2UncyBqb2IuCiMgLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t"
    "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KCklOSkVDVElPTl9DQVRFR09SSUVTID0gWwogICAgKCJYU1Mi"
    "LCAiQ3Jvc3MtU2l0ZSBTY3JpcHRpbmciLCBCQVNJQ19YU1NfUEFZTE9BRFMpLAogICAgKCJTUUxJIiwgIlNRTCBJbmplY3Rp"
    "b24iLCBCQVNJQ19TUUxJX1BBWUxPQURTKSwKICAgICgiQ01ESSIsICJDb21tYW5kIEluamVjdGlvbiIsIEJBU0lDX0NNRF9J"
    "TkpFQ1RJT05fUEFZTE9BRFMpLAogICAgKCJQQVRIVCIsICJQYXRoIFRyYXZlcnNhbCIsIEJBU0lDX1BBVEhfVFJBVkVSU0FM"
    "X1BBWUxPQURTKSwKICAgICgiU1NUSSIsICJTZXJ2ZXItU2lkZSBUZW1wbGF0ZSBJbmplY3Rpb24iLCBCQVNJQ19TU1RJX1BB"
    "WUxPQURTKSwKXQoKCmRlZiBfaW5qZWN0X2ludG9fdXJsKGJhc2VfdXJsLCBwYXJhbSwgcGF5bG9hZCk6CiAgICBwID0gdXJs"
    "cGFyc2UoYmFzZV91cmwpCiAgICBxID0gZGljdChwYXJzZV9xc2wocC5xdWVyeSwga2VlcF9ibGFua192YWx1ZXM9VHJ1ZSkp"
    "CiAgICBxW3BhcmFtXSA9IHBheWxvYWQKICAgIHJldHVybiBwLl9yZXBsYWNlKHF1ZXJ5PXVybGVuY29kZShxKSkuZ2V0dXJs"
    "KCkKCgpkZWYgX3NlbmRfZmllbGRfcGF5bG9hZChmaWVsZCwgcGF5bG9hZCwgYXJncyk6CiAgICBpZiBmaWVsZFsibWV0aG9k"
    "Il0gPT0gIkdFVCI6CiAgICAgICAgdGFyZ2V0ID0gX2luamVjdF9pbnRvX3VybChmaWVsZFsidXJsIl0sIGZpZWxkWyJwYXJh"
    "bSJdLCBwYXlsb2FkKQogICAgICAgIHJldHVybiByYXdfcmVxdWVzdCh0YXJnZXQsICJHRVQiLCB0aW1lb3V0PWFyZ3MudGlt"
    "ZW91dCwgaW5zZWN1cmU9YXJncy5pbnNlY3VyZSksIHRhcmdldAogICAgYm9keSA9IHVybGVuY29kZSh7ZmllbGRbInBhcmFt"
    "Il06IHBheWxvYWR9KS5lbmNvZGUoKQogICAgaGVhZGVycyA9IHsiQ29udGVudC1UeXBlIjogImFwcGxpY2F0aW9uL3gtd3d3"
    "LWZvcm0tdXJsZW5jb2RlZCJ9CiAgICByZXNwID0gcmF3X3JlcXVlc3QoZmllbGRbInVybCJdLCBmaWVsZFsibWV0aG9kIl0g"
    "b3IgIlBPU1QiLCBleHRyYV9oZWFkZXJzPWhlYWRlcnMsCiAgICAgICAgICAgICAgICAgICAgICAgIHRpbWVvdXQ9YXJncy50"
    "aW1lb3V0LCBpbnNlY3VyZT1hcmdzLmluc2VjdXJlLCBib2R5PWJvZHkpCiAgICByZXR1cm4gcmVzcCwgZmllbGRbInVybCJd"
    "CgoKZGVmIGNsYXNzaWZ5X2luamVjdGlvbihjYXRlZ29yeSwgcGF5bG9hZCwgYmFzZWxpbmVfdGV4dCwgcmVzcCwgZWxhcHNl"
    "ZCwgYmFzZWxpbmVfZWxhcHNlZCk6CiAgICAiIiJEZWxpYmVyYXRlbHkgY29uc2VydmF0aXZlIC0gYW4gaW5jb25jbHVzaXZl"
    "IHJlc3BvbnNlIGZhbGxzIGJhY2sgdG8KICAgICdubyBoaXQnIHJhdGhlciB0aGFuIGd1ZXNzaW5nLCBzYW1lIHBoaWxvc29w"
    "aHkgYXMKICAgIF9wYXJzZV9zc2xfY2xpX291dHB1dCgpIGVsc2V3aGVyZSBpbiB0aGlzIGZpbGUuIiIiCiAgICB0ZXh0ID0g"
    "cmVzcC50ZXh0KCkgaWYgbm90IHJlc3AuZXJyb3IgZWxzZSAiIgogICAgaWYgY2F0ZWdvcnkgPT0gIlhTUyI6CiAgICAgICAg"
    "aWYgcGF5bG9hZCBpbiB0ZXh0OgogICAgICAgICAgICByZXR1cm4gVHJ1ZSwgIlBheWxvYWQgcmVmbGVjdGVkIFVORVNDQVBF"
    "RCB2ZXJiYXRpbSBpbiB0aGUgcmVzcG9uc2UgYm9keS4iCiAgICAgICAgcmV0dXJuIEZhbHNlLCBOb25lCiAgICBpZiBjYXRl"
    "Z29yeSA9PSAiU1FMSSI6CiAgICAgICAgbSA9IFNRTF9FUlJPUl9QQVRURVJOUy5zZWFyY2godGV4dCkKICAgICAgICBpZiBt"
    "OgogICAgICAgICAgICByZXR1cm4gVHJ1ZSwgZiJEYXRhYmFzZSBlcnJvciBzaWduYXR1cmUgaW4gcmVzcG9uc2U6IHttLmdy"
    "b3VwKDApIXJ9LiIKICAgICAgICBpZiAoIlNMRUVQIiBpbiBwYXlsb2FkLnVwcGVyKCkgb3IgIldBSVRGT1IiIGluIHBheWxv"
    "YWQudXBwZXIoKSkgYW5kIGVsYXBzZWQgLSBiYXNlbGluZV9lbGFwc2VkID49IFRJTUVfQkFTRURfREVMVEFfU0VDOgogICAg"
    "ICAgICAgICByZXR1cm4gVHJ1ZSwgZiJUaW1lLWJhc2VkOiByZXNwb25zZSB0b29rIHtlbGFwc2VkOi4xZn1zIHZzIGEge2Jh"
    "c2VsaW5lX2VsYXBzZWQ6LjFmfXMgYmFzZWxpbmUuIgogICAgICAgIHJldHVybiBGYWxzZSwgTm9uZQogICAgaWYgY2F0ZWdv"
    "cnkgPT0gIkNNREkiOgogICAgICAgIG0gPSBDTURfT1VUUFVUX01BUktFUi5zZWFyY2godGV4dCkKICAgICAgICBpZiBtOgog"
    "ICAgICAgICAgICByZXR1cm4gVHJ1ZSwgZiJDb21tYW5kIG91dHB1dCAoJ2lkJykgZm91bmQgaW4gcmVzcG9uc2U6IHttLmdy"
    "b3VwKDApIXJ9LiIKICAgICAgICBpZiAoInNsZWVwIDUiIGluIHBheWxvYWQubG93ZXIoKSBvciAicGluZyAtYyAzIiBpbiBw"
    "YXlsb2FkLmxvd2VyKCkpIGFuZCBlbGFwc2VkIC0gYmFzZWxpbmVfZWxhcHNlZCA+PSBUSU1FX0JBU0VEX0RFTFRBX1NFQzoK"
    "ICAgICAgICAgICAgcmV0dXJuIFRydWUsIGYiVGltZS1iYXNlZDogcmVzcG9uc2UgdG9vayB7ZWxhcHNlZDouMWZ9cyB2cyBh"
    "IHtiYXNlbGluZV9lbGFwc2VkOi4xZn1zIGJhc2VsaW5lLiIKICAgICAgICByZXR1cm4gRmFsc2UsIE5vbmUKICAgIGlmIGNh"
    "dGVnb3J5ID09ICJQQVRIVCI6CiAgICAgICAgaWYgVU5JWF9QQVNTV0RfTUFSS0VSLnNlYXJjaCh0ZXh0KToKICAgICAgICAg"
    "ICAgcmV0dXJuIFRydWUsICJGaWxlLWRpc2Nsb3N1cmUgbWFya2VyICgvZXRjL3Bhc3N3ZCBjb250ZW50cykgZm91bmQgaW4g"
    "cmVzcG9uc2UuIgogICAgICAgIGlmIFdJTl9JTklfTUFSS0VSLnNlYXJjaCh0ZXh0KToKICAgICAgICAgICAgcmV0dXJuIFRy"
    "dWUsICJGaWxlLWRpc2Nsb3N1cmUgbWFya2VyICh3aW4uaW5pIGNvbnRlbnRzKSBmb3VuZCBpbiByZXNwb25zZS4iCiAgICAg"
    "ICAgcmV0dXJuIEZhbHNlLCBOb25lCiAgICBpZiBjYXRlZ29yeSA9PSAiU1NUSSI6CiAgICAgICAgaWYgIjQ5IiBpbiB0ZXh0"
    "IGFuZCAiNDkiIG5vdCBpbiBiYXNlbGluZV90ZXh0OgogICAgICAgICAgICByZXR1cm4gVHJ1ZSwgIlRlbXBsYXRlIGV4cHJl"
    "c3Npb24gYXBwZWFycyBldmFsdWF0ZWQgLSAnNDknICg3KjcpIHByZXNlbnQgaW4gcmVzcG9uc2UsIGFic2VudCBmcm9tIGJh"
    "c2VsaW5lLiIKICAgICAgICByZXR1cm4gRmFsc2UsIE5vbmUKICAgIHJldHVybiBGYWxzZSwgTm9uZQoKCmRlZiBwaGFzZV9p"
    "bmplY3QoZnVsbF91cmwsIGZpZWxkcywgYXJncyk6CiAgICBpZiBub3QgZmllbGRzOgogICAgICAgIGFkZChmdWxsX3VybCwg"
    "IldBLUlOSi0wMDAiLCAiSW5qZWN0aW9uIFRlc3RpbmciLCAiQWN0aXZlIHBheWxvYWQgaW5qZWN0aW9uIiwgIkluZm8iLCAi"
    "UDMiLCAiTUFOVUFMIiwKICAgICAgICAgICAgIk5vIGZpZWxkcyBkaXNjb3ZlcmVkIGJ5IHRoZSBkaXNjb3ZlciBwaGFzZSAt"
    "IG5vdGhpbmcgdG8gaW5qZWN0IGludG8uIikKICAgICAgICByZXR1cm4gW10KICAgIGZpZWxkcyA9IGZpZWxkc1s6IGFyZ3Mu"
    "bWF4X2luamVjdGlvbl9maWVsZHNdCiAgICBjb25maXJtZWQgPSBbXQogICAgZm9yIGZpZWxkIGluIGZpZWxkczoKICAgICAg"
    "ICB0MCA9IHRpbWUudGltZSgpCiAgICAgICAgYmFzZWxpbmVfcmVzcCwgXyA9IF9zZW5kX2ZpZWxkX3BheWxvYWQoZmllbGQs"
    "ICJ3cHRiYXNlIiArIHJhbmRfdG9rZW4oNCksIGFyZ3MpCiAgICAgICAgYmFzZWxpbmVfZWxhcHNlZCA9IHRpbWUudGltZSgp"
    "IC0gdDAKICAgICAgICBiYXNlbGluZV90ZXh0ID0gYmFzZWxpbmVfcmVzcC50ZXh0KCkgaWYgbm90IGJhc2VsaW5lX3Jlc3Au"
    "ZXJyb3IgZWxzZSAiIgoKICAgICAgICBmb3Igc2hvcnRfaWQsIGNhdGVnb3J5X25hbWUsIHBheWxvYWRzIGluIElOSkVDVElP"
    "Tl9DQVRFR09SSUVTOgogICAgICAgICAgICBmb3IgcGF5bG9hZCBpbiBwYXlsb2FkczoKICAgICAgICAgICAgICAgIHQwID0g"
    "dGltZS50aW1lKCkKICAgICAgICAgICAgICAgIHJlc3AsIHRhcmdldCA9IF9zZW5kX2ZpZWxkX3BheWxvYWQoZmllbGQsIHBh"
    "eWxvYWQsIGFyZ3MpCiAgICAgICAgICAgICAgICBlbGFwc2VkID0gdGltZS50aW1lKCkgLSB0MAogICAgICAgICAgICAgICAg"
    "aWYgcmVzcC5lcnJvcjoKICAgICAgICAgICAgICAgICAgICBjb250aW51ZQogICAgICAgICAgICAgICAgaXNfaGl0LCBub3Rl"
    "ID0gY2xhc3NpZnlfaW5qZWN0aW9uKHNob3J0X2lkLCBwYXlsb2FkLCBiYXNlbGluZV90ZXh0LCByZXNwLCBlbGFwc2VkLCBi"
    "YXNlbGluZV9lbGFwc2VkKQogICAgICAgICAgICAgICAgaWYgaXNfaGl0OgogICAgICAgICAgICAgICAgICAgIGFkZChmaWVs"
    "ZFsidXJsIl0sIGYiV0EtSU5KLXtzaG9ydF9pZH0iLCAiSW5qZWN0aW9uIFRlc3RpbmciLAogICAgICAgICAgICAgICAgICAg"
    "ICAgICBmIkFjdGl2ZSBwYXlsb2FkIGluamVjdGlvbiAtIHtjYXRlZ29yeV9uYW1lfSIsICJIaWdoIiwgIlAxIiwgIkZBSUwi"
    "LAogICAgICAgICAgICAgICAgICAgICAgICBmIkZpZWxkICd7ZmllbGRbJ3BhcmFtJ119JyAoe2ZpZWxkWydsb2NhdGlvbidd"
    "fSwge2ZpZWxkWydtZXRob2QnXX0pIC0gc291cmNlOiB7ZmllbGRbJ3NvdXJjZSddfS4gIgogICAgICAgICAgICAgICAgICAg"
    "ICAgICBmIntub3RlfSBQYXlsb2FkIHVzZWQ6IHtwYXlsb2FkIXJ9LiAiCiAgICAgICAgICAgICAgICAgICAgICAgICsgKGYi"
    "UmVxdWVzdCBVUkw6IHt0YXJnZXR9IiBpZiBmaWVsZFsibWV0aG9kIl0gPT0gIkdFVCIgZWxzZQogICAgICAgICAgICAgICAg"
    "ICAgICAgICAgICBmIlBPU1QgYm9keSBwYXJhbToge2ZpZWxkWydwYXJhbSddfT17cGF5bG9hZCFyfSIpKQogICAgICAgICAg"
    "ICAgICAgICAgIGNvbmZpcm1lZC5hcHBlbmQoeyJ1cmwiOiBmaWVsZFsidXJsIl0sICJtZXRob2QiOiBmaWVsZFsibWV0aG9k"
    "Il0sICJsb2NhdGlvbiI6IGZpZWxkWyJsb2NhdGlvbiJdLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg"
    "ICAicGFyYW0iOiBmaWVsZFsicGFyYW0iXSwgImNhdGVnb3J5Ijogc2hvcnRfaWQsICJwYXlsb2FkIjogcGF5bG9hZH0pCiAg"
    "ICAgICAgICAgICAgICAgICAgYnJlYWsgICMgb25lIGNvbmZpcm1lZCBwYXlsb2FkIHBlciBjYXRlZ29yeSBwZXIgZmllbGQg"
    "aXMgZW5vdWdoIHNpZ25hbAogICAgaWYgbm90IGNvbmZpcm1lZDoKICAgICAgICBhZGQoZnVsbF91cmwsICJXQS1JTkotU1VN"
    "TUFSWSIsICJJbmplY3Rpb24gVGVzdGluZyIsICJBY3RpdmUgcGF5bG9hZCBpbmplY3Rpb24gLSBzdW1tYXJ5IiwgIkluZm8i"
    "LCAiUDMiLCAiUEFTUyIsCiAgICAgICAgICAgIGYiVGVzdGVkIHtsZW4oZmllbGRzKX0gZmllbGQocykgeCB7bGVuKElOSkVD"
    "VElPTl9DQVRFR09SSUVTKX0gY2F0ZWdvcmllcyB3aXRoIHRoaXMgc2NyaXB0J3MgYnVpbHQtaW4gIgogICAgICAgICAgICAi"
    "cGF5bG9hZCBsaXN0cyAtIG5vIFhTUy9TUUxpL2NvbW1hbmQtaW5qZWN0aW9uL3BhdGgtdHJhdmVyc2FsL1NTVEkgc2lnbmFs"
    "IGRldGVjdGVkLiBUaGlzIGlzIGEgc21hbGwgIgogICAgICAgICAgICAiY3VyYXRlZCBwYXlsb2FkIHNldCBmb3IgZmFzdCB0"
    "cmlhZ2UsIG5vdCBleGhhdXN0aXZlIGZ1enppbmcgLSBhIE1BTlVBTCByZXZpZXcgd2l0aCBCdXJwIEludHJ1ZGVyLyIKICAg"
    "ICAgICAgICAgInNxbG1hcC9mZnVmIGlzIHN0aWxsIHJlY29tbWVuZGVkIGZvciBoaWdoLXZhbHVlIHRhcmdldHMuIikKICAg"
    "IHJldHVybiBjb25maXJtZWQKCgojIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t"
    "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiMgRXhwbG9pdCBwaGFzZSAtIE9QVC1JTiBPTkxZICgtLWV4cGxvaXQgLyAtLXBo"
    "YXNlcyBleHBsb2l0IEFORAojIC0taS1hbS1hdXRob3JpemVkIGJvdGggcmVxdWlyZWQpLiBGb3IgZWFjaCBjb25maXJtZWQg"
    "aW5qZWN0aW9uIGZpbmRpbmcsCiMgaGFuZHMgb2ZmIHRvIGEgcmVhbCBleHBsb2l0YXRpb24gdG9vbCAoc3FsbWFwIGZvciBT"
    "UUxpLCBkYWxmb3ggZm9yIFhTUykKIyB0byBhdHRlbXB0IGZ1bGwgcHJvb2Ytb2YtaW1wYWN0IC0gZm9yIFNRTGkgdGhpcyBn"
    "ZW51aW5lbHkgZXh0cmFjdHMgcmVhbAojIHJvd3MgZnJvbSB0aGUgdGFyZ2V0J3MgZGF0YWJhc2UgKHNxbG1hcCAtLWR1bXAp"
    "LCBwZXIgdGhlIGV4cGxpY2l0IGNob2ljZQojIHRvIGJ1aWxkIHRoaXMgYXMgZnVsbCBleHBsb2l0YXRpb24gcmF0aGVyIHRo"
    "YW4gY29uZmlybWF0aW9uLW9ubHkuIFRoaXMKIyBpcyB0aGUgaGlnaGVzdC1yaXNrIHBoYXNlIGluIHRoZSBzY3JpcHQgLSBp"
    "dCBXSUxMIHNlbmQgcmVhbCBhdHRhY2sKIyB0cmFmZmljLiBPbmx5IHJ1biBpdCBhZ2FpbnN0IGEgdGFyZ2V0IHlvdSBoYXZl"
    "IEVYUExJQ0lUIFdSSVRURU4KIyBBVVRIT1JJWkFUSU9OIHRvIGFjdGl2ZWx5IGV4cGxvaXQuCiMgLS0tLS0tLS0tLS0tLS0t"
    "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KCmRlZiBwaGFzZV9l"
    "eHBsb2l0KGZ1bGxfdXJsLCBjb25maXJtZWRfZmluZGluZ3MsIGFyZ3MpOgogICAgaWYgbm90IGFyZ3MuaV9hbV9hdXRob3Jp"
    "emVkOgogICAgICAgIHByaW50KCJcblshXSBFeHBsb2l0IHBoYXNlIHJlcXVlc3RlZCBidXQgLS1pLWFtLWF1dGhvcml6ZWQg"
    "d2FzIG5vdCBwYXNzZWQgLSBSRUZVU0lORyB0byBydW4gaXQuIikKICAgICAgICBhZGQoZnVsbF91cmwsICJXQS1FWFAtMDAw"
    "IiwgIkV4cGxvaXRhdGlvbiIsICJBY3RpdmUgZXhwbG9pdGF0aW9uIHBoYXNlIiwgIkluZm8iLCAiUDMiLCAiTUFOVUFMIiwK"
    "ICAgICAgICAgICAgIkV4cGxvaXQgcGhhc2UgcmVxdWVzdGVkICgtLWV4cGxvaXQgLyAtLXBoYXNlcyBleHBsb2l0KSBidXQg"
    "LS1pLWFtLWF1dGhvcml6ZWQgd2FzIG5vdCBwYXNzZWQgLSB0aGlzICIKICAgICAgICAgICAgInBoYXNlIGF0dGVtcHRzIFJF"
    "QUwgZXhwbG9pdGF0aW9uIChlLmcuIHNxbG1hcCAtLWR1bXAgYWdhaW5zdCBjb25maXJtZWQgU1FMaSwgd2hpY2ggcHVsbHMg"
    "cmVhbCByb3dzICIKICAgICAgICAgICAgIm91dCBvZiB0aGUgdGFyZ2V0J3MgZGF0YWJhc2UpIGFuZCBvbmx5IHJ1bnMgYWdh"
    "aW5zdCBhIHRhcmdldCB5b3UgaGF2ZSBFWFBMSUNJVCBXUklUVEVOIEFVVEhPUklaQVRJT04gIgogICAgICAgICAgICAidG8g"
    "YWN0aXZlbHkgZXhwbG9pdC4gUmUtcnVuIHdpdGggLS1leHBsb2l0IC0taS1hbS1hdXRob3JpemVkIG9uY2UgY29uZmlybWVk"
    "LiIpCiAgICAgICAgcmV0dXJuCiAgICBpZiBub3QgY29uZmlybWVkX2ZpbmRpbmdzOgogICAgICAgIGFkZChmdWxsX3VybCwg"
    "IldBLUVYUC0wMDAiLCAiRXhwbG9pdGF0aW9uIiwgIkFjdGl2ZSBleHBsb2l0YXRpb24gcGhhc2UiLCAiSW5mbyIsICJQMyIs"
    "ICJQQVNTIiwKICAgICAgICAgICAgIkV4cGxvaXQgcGhhc2UgcmFuIGJ1dCB0aGUgaW5qZWN0aW9uIHBoYXNlIGhhZCBubyBj"
    "b25maXJtZWQgZmluZGluZ3Mgb24gdGhpcyB0YXJnZXQgdG8gZXhwbG9pdC4iKQogICAgICAgIHJldHVybgogICAgZm9yIGZp"
    "bmRpbmcgaW4gY29uZmlybWVkX2ZpbmRpbmdzOgogICAgICAgIGlmIGZpbmRpbmdbImNhdGVnb3J5Il0gPT0gIlNRTEkiOgog"
    "ICAgICAgICAgICBfZXhwbG9pdF9zcWxpKGZpbmRpbmcsIGFyZ3MpCiAgICAgICAgZWxpZiBmaW5kaW5nWyJjYXRlZ29yeSJd"
    "ID09ICJYU1MiOgogICAgICAgICAgICBfZXhwbG9pdF94c3MoZmluZGluZywgYXJncykKICAgICAgICBlbHNlOgogICAgICAg"
    "ICAgICBhZGQoZmluZGluZ1sidXJsIl0sIGYiV0EtRVhQLXtmaW5kaW5nWydjYXRlZ29yeSddfSIsICJFeHBsb2l0YXRpb24i"
    "LAogICAgICAgICAgICAgICAgZiJBY3RpdmUgZXhwbG9pdGF0aW9uIC0ge2ZpbmRpbmdbJ2NhdGVnb3J5J119IiwgIkhpZ2gi"
    "LCAiUDEiLCAiTUFOVUFMIiwKICAgICAgICAgICAgICAgIGYiSW5qZWN0aW9uIHBoYXNlIGNvbmZpcm1lZCBhIHtmaW5kaW5n"
    "WydjYXRlZ29yeSddfSBzaWduYWwgb24gZmllbGQgJ3tmaW5kaW5nWydwYXJhbSddfScgYnV0IG5vICIKICAgICAgICAgICAg"
    "ICAgICJhdXRvbWF0ZWQgZXhwbG9pdGF0aW9uIHRvb2wgaXMgd2lyZWQgdXAgZm9yIHRoaXMgY2F0ZWdvcnkgeWV0IChvbmx5"
    "IFNRTGkvc3FsbWFwIGFuZCBYU1MvZGFsZm94ICIKICAgICAgICAgICAgICAgICJhcmUpIC0gY29uZmlybS9leHBsb2l0IG1h"
    "bnVhbGx5LiIpCgoKZGVmIF9leHBsb2l0X3NxbGkoZmluZGluZywgYXJncyk6CiAgICBpZiBub3QgX2NsaV9hdmFpbGFibGUo"
    "InNxbG1hcCIpOgogICAgICAgIGFkZChmaW5kaW5nWyJ1cmwiXSwgIldBLUVYUC1TUUxJIiwgIkV4cGxvaXRhdGlvbiIsICJB"
    "Y3RpdmUgZXhwbG9pdGF0aW9uIC0gU1FMIEluamVjdGlvbiIsICJDcml0aWNhbCIsICJQMSIsICJNQU5VQUwiLAogICAgICAg"
    "ICAgICAic3FsbWFwIG5vdCBmb3VuZCBvbiBQQVRIIC0gaW5zdGFsbCBpdCAoaHR0cHM6Ly9naXRodWIuY29tL3NxbG1hcHBy"
    "b2plY3Qvc3FsbWFwKSBmb3IgYXV0b21hdGVkICIKICAgICAgICAgICAgZiJleHBsb2l0YXRpb24uIEluamVjdGlvbiBwaGFz"
    "ZSBhbHJlYWR5IGNvbmZpcm1lZCBhIHNpZ25hbCBvbiBmaWVsZCAne2ZpbmRpbmdbJ3BhcmFtJ119JyAtIGV4cGxvaXQgIgog"
    "ICAgICAgICAgICAibWFudWFsbHkgd2l0aCBzcWxtYXAgb3IgQnVycCBpbiB0aGUgbWVhbnRpbWUuIikKICAgICAgICByZXR1"
    "cm4KICAgIGlmIGZpbmRpbmdbIm1ldGhvZCJdID09ICJHRVQiOgogICAgICAgIGNtZCA9IFsic3FsbWFwIiwgIi11IiwgX2lu"
    "amVjdF9pbnRvX3VybChmaW5kaW5nWyJ1cmwiXSwgZmluZGluZ1sicGFyYW0iXSwgIjEiKV0KICAgIGVsc2U6CiAgICAgICAg"
    "Y21kID0gWyJzcWxtYXAiLCAiLXUiLCBmaW5kaW5nWyJ1cmwiXSwgIi0tZGF0YSIsIHVybGVuY29kZSh7ZmluZGluZ1sicGFy"
    "YW0iXTogIjEifSldCiAgICBjbWQgKz0gWyItLWJhdGNoIiwgIi0tcmFuZG9tLWFnZW50IiwgIi0tbGV2ZWwiLCAiMyIsICIt"
    "LXJpc2siLCAiMiIsICItLWR1bXAiLCAiLS10aHJlYWRzIiwgIjQiXQogICAgaWYgRVhUUkFfQVVUSF9IRUFERVJTLmdldCgi"
    "Q29va2llIik6CiAgICAgICAgY21kICs9IFsiLS1jb29raWUiLCBFWFRSQV9BVVRIX0hFQURFUlNbIkNvb2tpZSJdXQogICAg"
    "cHJpbnQoZiIgICAgW2V4cGxvaXRdIHJ1bm5pbmcgc3FsbWFwIGFnYWluc3Qge2ZpbmRpbmdbJ3VybCddfSAoZmllbGQgJ3tm"
    "aW5kaW5nWydwYXJhbSddfScpIC0gdGhpcyBjYW4gdGFrZSBhIHdoaWxlLi4uIikKICAgIHRyeToKICAgICAgICBwcm9jID0g"
    "c3VicHJvY2Vzcy5ydW4oY21kLCBjYXB0dXJlX291dHB1dD1UcnVlLCB0aW1lb3V0PWFyZ3Muc3FsbWFwX3RpbWVvdXQpCiAg"
    "ICAgICAgb3V0ID0gcHJvYy5zdGRvdXQuZGVjb2RlKCJ1dGYtOCIsIGVycm9ycz0icmVwbGFjZSIpCiAgICBleGNlcHQgc3Vi"
    "cHJvY2Vzcy5UaW1lb3V0RXhwaXJlZDoKICAgICAgICBvdXQgPSBmIihzcWxtYXAgdGltZWQgb3V0IGFmdGVyIHthcmdzLnNx"
    "bG1hcF90aW1lb3V0fXMgLSBpbmNyZWFzZSAtLXNxbG1hcC10aW1lb3V0IGZvciBhIHNsb3dlciB0YXJnZXQpIgogICAgZXhj"
    "ZXB0IEV4Y2VwdGlvbiBhcyBlOgogICAgICAgIG91dCA9IGYiKHNxbG1hcCBleGVjdXRpb24gZmFpbGVkOiB7ZX0pIgogICAg"
    "ZHVtcGVkID0gYm9vbChyZS5zZWFyY2gociJcYlRhYmxlOlxifFxiRGF0YWJhc2U6XGJ8XGQrIGVudHJpZXMiLCBvdXQpKQog"
    "ICAgYWRkKGZpbmRpbmdbInVybCJdLCAiV0EtRVhQLVNRTEkiLCAiRXhwbG9pdGF0aW9uIiwgIkFjdGl2ZSBleHBsb2l0YXRp"
    "b24gLSBTUUwgSW5qZWN0aW9uIiwKICAgICAgICAiQ3JpdGljYWwiLCAiUDEiLCAiRkFJTCIgaWYgZHVtcGVkIGVsc2UgIk1B"
    "TlVBTCIsCiAgICAgICAgKGYic3FsbWFwIENPTkZJUk1FRCBhbmQgZXh0cmFjdGVkIHJlYWwgZGF0YSBmcm9tIGZpZWxkICd7"
    "ZmluZGluZ1sncGFyYW0nXX0nIC0gdGhlIG91dHB1dCBiZWxvdyBtYXkgIgogICAgICAgICAiY29udGFpbiByZWFsIHNlbnNp"
    "dGl2ZSBkYXRhLCBoYW5kbGUgdGhpcyByZXBvcnQgYWNjb3JkaW5nbHkuIiBpZiBkdW1wZWQgZWxzZQogICAgICAgICAic3Fs"
    "bWFwIHJhbiBhZ2FpbnN0IHRoZSBmaWVsZCB0aGUgaW5qZWN0aW9uIHBoYXNlIGZsYWdnZWQgYnV0IGRpZCBub3QgY29uZmly"
    "bS9leHRyYWN0IC0gbWF5IGJlIGEgZmFsc2UgIgogICAgICAgICAicG9zaXRpdmUgZnJvbSB0aGUgaW5qZWN0aW9uIHBoYXNl"
    "J3MgbGlnaHR3ZWlnaHQgaGV1cmlzdGljLCBvciBzcWxtYXAgbmVlZHMgbWFudWFsIHR1bmluZyAiCiAgICAgICAgICIoLS10"
    "ZWNobmlxdWUvLS1kYm1zLy0tdGFtcGVyKS4iKSArIF9mb3JtYXRfY21kX2Jsb2NrKGNtZCwgb3V0KSkKCgpkZWYgX2V4cGxv"
    "aXRfeHNzKGZpbmRpbmcsIGFyZ3MpOgogICAgaWYgbm90IF9jbGlfYXZhaWxhYmxlKCJkYWxmb3giKToKICAgICAgICBhZGQo"
    "ZmluZGluZ1sidXJsIl0sICJXQS1FWFAtWFNTIiwgIkV4cGxvaXRhdGlvbiIsICJBY3RpdmUgZXhwbG9pdGF0aW9uIC0gWFNT"
    "IiwgIkhpZ2giLCAiUDEiLCAiTUFOVUFMIiwKICAgICAgICAgICAgImRhbGZveCBub3QgZm91bmQgb24gUEFUSCAtIGluc3Rh"
    "bGwgaXQgKGh0dHBzOi8vZ2l0aHViLmNvbS9oYWh3dWwvZGFsZm94KSBmb3IgYXV0b21hdGVkIFhTUyBQb0MgIgogICAgICAg"
    "ICAgICBmImNvbmZpcm1hdGlvbi4gSW5qZWN0aW9uIHBoYXNlIGFscmVhZHkgY29uZmlybWVkIGEgcmVmbGVjdGVkIHBheWxv"
    "YWQgb24gZmllbGQgJ3tmaW5kaW5nWydwYXJhbSddfScuIikKICAgICAgICByZXR1cm4KICAgIGNtZCA9IFsiZGFsZm94Iiwg"
    "InVybCIsIGZpbmRpbmdbInVybCJdLCAiLS1zaWxlbmNlIl0KICAgIGlmIEVYVFJBX0FVVEhfSEVBREVSUy5nZXQoIkNvb2tp"
    "ZSIpOgogICAgICAgIGNtZCArPSBbIi1DIiwgRVhUUkFfQVVUSF9IRUFERVJTWyJDb29raWUiXV0KICAgIHByaW50KGYiICAg"
    "IFtleHBsb2l0XSBydW5uaW5nIGRhbGZveCBhZ2FpbnN0IHtmaW5kaW5nWyd1cmwnXX0gKGZpZWxkICd7ZmluZGluZ1sncGFy"
    "YW0nXX0nKS4uLiIpCiAgICB0cnk6CiAgICAgICAgcHJvYyA9IHN1YnByb2Nlc3MucnVuKGNtZCwgY2FwdHVyZV9vdXRwdXQ9"
    "VHJ1ZSwgdGltZW91dD1hcmdzLmRhbGZveF90aW1lb3V0KQogICAgICAgIG91dCA9IHByb2Muc3Rkb3V0LmRlY29kZSgidXRm"
    "LTgiLCBlcnJvcnM9InJlcGxhY2UiKQogICAgZXhjZXB0IHN1YnByb2Nlc3MuVGltZW91dEV4cGlyZWQ6CiAgICAgICAgb3V0"
    "ID0gZiIoZGFsZm94IHRpbWVkIG91dCBhZnRlciB7YXJncy5kYWxmb3hfdGltZW91dH1zKSIKICAgIGV4Y2VwdCBFeGNlcHRp"
    "b24gYXMgZToKICAgICAgICBvdXQgPSBmIihkYWxmb3ggZXhlY3V0aW9uIGZhaWxlZDoge2V9KSIKICAgIHBvY19jb25maXJt"
    "ZWQgPSAiW1BPQ10iIGluIG91dCBvciAidnVsbmVyYWJsZSIgaW4gb3V0Lmxvd2VyKCkKICAgIGFkZChmaW5kaW5nWyJ1cmwi"
    "XSwgIldBLUVYUC1YU1MiLCAiRXhwbG9pdGF0aW9uIiwgIkFjdGl2ZSBleHBsb2l0YXRpb24gLSBYU1MiLAogICAgICAgICJI"
    "aWdoIiwgIlAxIiwgIkZBSUwiIGlmIHBvY19jb25maXJtZWQgZWxzZSAiTUFOVUFMIiwKICAgICAgICAoZiJkYWxmb3ggQ09O"
    "RklSTUVEIGFuIGV4cGxvaXRhYmxlIFhTUyBQb0Mgb24gZmllbGQgJ3tmaW5kaW5nWydwYXJhbSddfScuIiBpZiBwb2NfY29u"
    "ZmlybWVkIGVsc2UKICAgICAgICAgImRhbGZveCByYW4gYnV0IGRpZCBub3QgcmVwb3J0IGEgY29uZmlybWVkIFBvQyAtIHRo"
    "ZSBpbmplY3Rpb24gcGhhc2UncyByZWZsZWN0ZWQtcGF5bG9hZCBzaWduYWwgbWF5ICIKICAgICAgICAgInN0aWxsIG5lZWQg"
    "bWFudWFsIGNvbmZpcm1hdGlvbiBpbiBhIHJlYWwgYnJvd3Nlci4iKSArIF9mb3JtYXRfY21kX2Jsb2NrKGNtZCwgb3V0KSkK"
    "CgojIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t"
    "LS0tLS0tCiMgUGhhc2Ugb3JjaGVzdHJhdGlvbiAtIGRlcGVuZGVuY3kgZXhwYW5zaW9uICsgdGhlIHBlci10YXJnZXQgZHJp"
    "dmVyIGNhbGxlZAojIG9uY2UgZnJvbSBzY2FuX3VybCgpLCBhbmQgdGhlIGZpbmFsIHNldmVyaXR5LXdlaWdodGVkIGNvbXBy"
    "ZWhlbnNpdmUKIyByZXBvcnQgd3JpdHRlbiBvbmNlIGZyb20gbWFpbigpIGFmdGVyIGV2ZXJ5IHRhcmdldCBoYXMgYmVlbiBz"
    "Y2FubmVkLgojIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t"
    "LS0tLS0tLS0tLS0tCgpQSEFTRV9ERVBFTkRFTkNJRVMgPSB7ImV4cGxvaXQiOiAiaW5qZWN0IiwgImluamVjdCI6ICJkaXNj"
    "b3ZlciIsICJkaXNjb3ZlciI6ICJyZWNvbiJ9CgoKZGVmIGV4cGFuZF9waGFzZV9kZXBlbmRlbmNpZXMocGhhc2VzKToKICAg"
    "ICIiIlNlbGVjdGluZyBhIGxhdGVyIHBoYXNlIGltcGxpZXMgZXZlcnkgcGhhc2UgaXQgZGVwZW5kcyBvbiAtIGUuZy4KICAg"
    "IC0tcGhhc2VzIGluamVjdCBhbHNvIG5lZWRzIGRpc2NvdmVyIChmb3IgZmllbGRzKSBhbmQgcmVjb24gKGZvciBwYWdlcwog"
    "ICAgdG8gZGlzY292ZXIgZmllbGRzIG9uKSwgc28gaXQncyBwdWxsZWQgaW4gYXV0b21hdGljYWxseSBpbnN0ZWFkIG9mCiAg"
    "ICBydW5uaW5nIGluamVjdCBhZ2FpbnN0IG5vdGhpbmcuIiIiCiAgICBwaGFzZXMgPSBzZXQocGhhc2VzKQogICAgY2hhbmdl"
    "ZCA9IFRydWUKICAgIHdoaWxlIGNoYW5nZWQ6CiAgICAgICAgY2hhbmdlZCA9IEZhbHNlCiAgICAgICAgZm9yIHBoYXNlLCBk"
    "ZXAgaW4gUEhBU0VfREVQRU5ERU5DSUVTLml0ZW1zKCk6CiAgICAgICAgICAgIGlmIHBoYXNlIGluIHBoYXNlcyBhbmQgZGVw"
    "IG5vdCBpbiBwaGFzZXM6CiAgICAgICAgICAgICAgICBwaGFzZXMuYWRkKGRlcCkKICAgICAgICAgICAgICAgIGNoYW5nZWQg"
    "PSBUcnVlCiAgICByZXR1cm4gcGhhc2VzCgoKZGVmIHJ1bl9leHRlbmRlZF9waGFzZXMoZnVsbF91cmwsIHJhd191cmwsIGFy"
    "Z3MpOgogICAgIiIiUnVucyB3aGljaGV2ZXIgb2YgcmVjb24vZGlzY292ZXIvZXh0c2Nhbi9pbmplY3QvZXhwbG9pdCB3ZXJl"
    "CiAgICBzZWxlY3RlZCB2aWEgLS1waGFzZXMsIG9uY2UgYWdhaW5zdCB0aGUgZ2l2ZW4gVVJMIG9ubHkgLSBOT1QKICAgIGR1"
    "cGxpY2F0ZWQgYWdhaW5zdCB0aGUgYmFzZWxpbmUgc3VpdGUncyBhdXRvbWF0aWMgc2l0ZS1yb290IHBhc3MsCiAgICBzaW5j"
    "ZSB0aGVzZSBwaGFzZXMgZ2VuZXJhdGUgcmVhbCAoYW5kLCBmb3IgZXhwbG9pdCwgcmVhbCBBVFRBQ0spCiAgICB0cmFmZmlj"
    "IGFuZCBzaG91bGRuJ3Qgc2lsZW50bHkgZG91YmxlIGp1c3QgYmVjYXVzZSB0aGUgYmFzZWxpbmUKICAgIGR1YWwtcGFzcyBi"
    "ZWhhdmlvdXIgZG9lcy4iIiIKICAgIHBoYXNlcyA9IGFyZ3MucGhhc2VzCiAgICBpZiBub3QgKHBoYXNlcyAmIHsicmVjb24i"
    "LCAiZGlzY292ZXIiLCAiZXh0c2NhbiIsICJpbmplY3QiLCAiZXhwbG9pdCJ9KToKICAgICAgICByZXR1cm4KCiAgICBDVFhb"
    "InNvdXJjZV9pbnB1dCJdID0gcmF3X3VybAogICAgQ1RYWyJ1cmxfcm9sZSJdID0gImdpdmVuLXVybCIKCiAgICBwYWdlcyA9"
    "IFtdCiAgICBpZiAicmVjb24iIGluIHBoYXNlczoKICAgICAgICBDVFhbInBoYXNlIl0gPSAicmVjb24iCiAgICAgICAgcHJp"
    "bnQoZiJcblsqXSBSZWNvbiBwaGFzZToge2Z1bGxfdXJsfSIpCiAgICAgICAgcGFnZXMgPSBwaGFzZV9yZWNvbihmdWxsX3Vy"
    "bCwgYXJncykKICAgIGlmIG5vdCBwYWdlczoKICAgICAgICBmaXJzdCA9IHJhd19yZXF1ZXN0KGZ1bGxfdXJsLCAiR0VUIiwg"
    "dGltZW91dD1hcmdzLnRpbWVvdXQsIGluc2VjdXJlPWFyZ3MuaW5zZWN1cmUpCiAgICAgICAgaWYgbm90IGZpcnN0LmVycm9y"
    "OgogICAgICAgICAgICBwYWdlcyA9IFsoZnVsbF91cmwsIGZpcnN0KV0KCiAgICBmaWVsZHMgPSBbXQogICAgaWYgImRpc2Nv"
    "dmVyIiBpbiBwaGFzZXM6CiAgICAgICAgQ1RYWyJwaGFzZSJdID0gImRpc2NvdmVyIgogICAgICAgIHByaW50KGYiWypdIERp"
    "c2NvdmVyeSBwaGFzZToge2Z1bGxfdXJsfSIpCiAgICAgICAgZmllbGRzID0gcGhhc2VfZGlzY292ZXIoZnVsbF91cmwsIHBh"
    "Z2VzLCBhcmdzKQoKICAgIGlmICJleHRzY2FuIiBpbiBwaGFzZXM6CiAgICAgICAgQ1RYWyJwaGFzZSJdID0gImV4dHNjYW4i"
    "CiAgICAgICAgcHJpbnQoZiJbKl0gRXh0ZXJuYWwgc2Nhbm5lciBwaGFzZSAobnVjbGVpL25pa3RvKToge2Z1bGxfdXJsfSIp"
    "CiAgICAgICAgcGhhc2VfZXh0c2Nhbl9udWNsZWkoZnVsbF91cmwsIGFyZ3MpCiAgICAgICAgcGhhc2VfZXh0c2Nhbl9uaWt0"
    "byhmdWxsX3VybCwgYXJncykKCiAgICBjb25maXJtZWQgPSBbXQogICAgaWYgImluamVjdCIgaW4gcGhhc2VzOgogICAgICAg"
    "IENUWFsicGhhc2UiXSA9ICJpbmplY3QiCiAgICAgICAgcHJpbnQoZiJbKl0gSW5qZWN0aW9uIHBoYXNlOiB7ZnVsbF91cmx9"
    "IikKICAgICAgICBjb25maXJtZWQgPSBwaGFzZV9pbmplY3QoZnVsbF91cmwsIGZpZWxkcywgYXJncykKCiAgICBpZiAiZXhw"
    "bG9pdCIgaW4gcGhhc2VzOgogICAgICAgIENUWFsicGhhc2UiXSA9ICJleHBsb2l0IgogICAgICAgIHByaW50KGYiWypdIEV4"
    "cGxvaXRhdGlvbiBwaGFzZToge2Z1bGxfdXJsfSIpCiAgICAgICAgcGhhc2VfZXhwbG9pdChmdWxsX3VybCwgY29uZmlybWVk"
    "LCBhcmdzKQoKCmRlZiBjb21wdXRlX2NvbXByZWhlbnNpdmVfcmVwb3J0KCk6CiAgICBmYWlscyA9IFtyIGZvciByIGluIFJF"
    "U1VMVFMgaWYgclsicmVzdWx0Il0gPT0gIkZBSUwiXQogICAgc2NvcmUgPSBzdW0oU0VWRVJJVFlfV0VJR0hULmdldChyWyJz"
    "ZXZlcml0eSJdLCAwKSBmb3IgciBpbiBmYWlscykKICAgIGlmIHNjb3JlID49IDgwOgogICAgICAgIHJhdGluZyA9ICJDcml0"
    "aWNhbCIKICAgIGVsaWYgc2NvcmUgPj0gNDA6CiAgICAgICAgcmF0aW5nID0gIkhpZ2giCiAgICBlbGlmIHNjb3JlID49IDE1"
    "OgogICAgICAgIHJhdGluZyA9ICJNZWRpdW0iCiAgICBlbGlmIHNjb3JlID4gMDoKICAgICAgICByYXRpbmcgPSAiTG93Igog"
    "ICAgZWxzZToKICAgICAgICByYXRpbmcgPSAiSW5mbyIKCiAgICBieV9waGFzZSA9IHt9CiAgICBmb3IgciBpbiBSRVNVTFRT"
    "OgogICAgICAgIHBoYXNlID0gci5nZXQoInBoYXNlIikgb3IgImJhc2VsaW5lIgogICAgICAgIGJ1Y2tldCA9IGJ5X3BoYXNl"
    "LnNldGRlZmF1bHQocGhhc2UsIHsidG90YWwiOiAwLCAicGFzcyI6IDAsICJmYWlsIjogMCwgIm1hbnVhbCI6IDAsICJpbmZv"
    "IjogMCwgImVycm9yIjogMH0pCiAgICAgICAgYnVja2V0WyJ0b3RhbCJdICs9IDEKICAgICAgICBidWNrZXRbclsicmVzdWx0"
    "Il0ubG93ZXIoKV0gPSBidWNrZXQuZ2V0KHJbInJlc3VsdCJdLmxvd2VyKCksIDApICsgMQoKICAgIHRvcF9maW5kaW5ncyA9"
    "IHNvcnRlZChmYWlscywga2V5PWxhbWJkYSByOiAtU0VWRVJJVFlfV0VJR0hULmdldChyWyJzZXZlcml0eSJdLCAwKSlbOjI1"
    "XQoKICAgIHJldHVybiB7CiAgICAgICAgImdlbmVyYXRlZF9hdCI6IG5vd19pc28oKSwKICAgICAgICAib3ZlcmFsbF9yaXNr"
    "X3Njb3JlIjogc2NvcmUsCiAgICAgICAgIm92ZXJhbGxfcmlza19yYXRpbmciOiByYXRpbmcsCiAgICAgICAgInRvdGFsX2No"
    "ZWNrcyI6IGxlbihSRVNVTFRTKSwKICAgICAgICAidG90YWxfZmFpbCI6IGxlbihmYWlscyksCiAgICAgICAgImJ5X3BoYXNl"
    "IjogYnlfcGhhc2UsCiAgICAgICAgInRvcF9maW5kaW5ncyI6IFsKICAgICAgICAgICAgeyJpZCI6IHJbImlkIl0sICJ1cmwi"
    "OiByWyJ1cmwiXSwgImNhdGVnb3J5IjogclsiY2F0ZWdvcnkiXSwgInRlc3QiOiByWyJ0ZXN0Il0sCiAgICAgICAgICAgICAi"
    "c2V2ZXJpdHkiOiByWyJzZXZlcml0eSJdLCAicGhhc2UiOiByLmdldCgicGhhc2UiKSBvciAiYmFzZWxpbmUiLCAiZXZpZGVu"
    "Y2UiOiByWyJldmlkZW5jZSJdWzo1MDBdfQogICAgICAgICAgICBmb3IgciBpbiB0b3BfZmluZGluZ3MKICAgICAgICBdLAog"
    "ICAgfQoKCmRlZiB3cml0ZV9jb21wcmVoZW5zaXZlX3JlcG9ydChwYXRoKToKICAgIHJlcG9ydCA9IGNvbXB1dGVfY29tcHJl"
    "aGVuc2l2ZV9yZXBvcnQoKQogICAgd2l0aCBvcGVuKHBhdGgsICJ3IiwgZW5jb2Rpbmc9InV0Zi04IikgYXMgZjoKICAgICAg"
    "ICBqc29uLmR1bXAocmVwb3J0LCBmLCBpbmRlbnQ9MikKICAgIHJldHVybiByZXBvcnQKCgpkZWYgcHJpbnRfY29tcHJlaGVu"
    "c2l2ZV9yZXBvcnQocmVwb3J0KToKICAgIHByaW50KCJcbiIgKyAiPSIgKiA3OCkKICAgIHByaW50KCJDT01QUkVIRU5TSVZF"
    "IFJFU1VMVCAoYWxsIHBoYXNlcykiKQogICAgcHJpbnQoIj0iICogNzgpCiAgICBwcmludChmIk92ZXJhbGwgcmlzayByYXRp"
    "bmc6IHtyZXBvcnRbJ292ZXJhbGxfcmlza19yYXRpbmcnXX0gICh3ZWlnaHRlZCBzY29yZToge3JlcG9ydFsnb3ZlcmFsbF9y"
    "aXNrX3Njb3JlJ119KSIpCiAgICBwcmludChmIlRvdGFsIGNoZWNrcyBydW46IHtyZXBvcnRbJ3RvdGFsX2NoZWNrcyddfSAg"
    "fCAgVG90YWwgRkFJTDoge3JlcG9ydFsndG90YWxfZmFpbCddfSIpCiAgICBwcmludCgiXG5CeSBwaGFzZToiKQogICAgZm9y"
    "IHBoYXNlLCBzdGF0cyBpbiByZXBvcnRbImJ5X3BoYXNlIl0uaXRlbXMoKToKICAgICAgICBwcmludChmIiAge3BoYXNlOjEw"
    "c30gdG90YWw9e3N0YXRzWyd0b3RhbCddOjw0ZH0gZmFpbD17c3RhdHMuZ2V0KCdmYWlsJywgMCk6PDNkfSAiCiAgICAgICAg"
    "ICAgICAgZiJwYXNzPXtzdGF0cy5nZXQoJ3Bhc3MnLCAwKTo8M2R9IG1hbnVhbD17c3RhdHMuZ2V0KCdtYW51YWwnLCAwKTo8"
    "M2R9ICIKICAgICAgICAgICAgICBmImluZm89e3N0YXRzLmdldCgnaW5mbycsIDApOjwzZH0gZXJyb3I9e3N0YXRzLmdldCgn"
    "ZXJyb3InLCAwKTo8M2R9IikKICAgIGlmIHJlcG9ydFsidG9wX2ZpbmRpbmdzIl06CiAgICAgICAgcHJpbnQoIlxuVG9wIGZp"
    "bmRpbmdzIGJ5IHNldmVyaXR5OiIpCiAgICAgICAgZm9yIGYgaW4gcmVwb3J0WyJ0b3BfZmluZGluZ3MiXVs6MTBdOgogICAg"
    "ICAgICAgICBwcmludChmIiAgW3tmWydzZXZlcml0eSddOjhzfV0ge2ZbJ2lkJ106MjJzfSB7ZlsndGVzdCddWzo1MF06NTBz"
    "fSB7ZlsndXJsJ119IikKICAgIHByaW50KCI9IiAqIDc4KQoKCmRlZiBwcmludF9waGFzZV9wbGFuKGFyZ3MpOgogICAgb3Jk"
    "ZXIgPSBbImJhc2VsaW5lIiwgInJlY29uIiwgImRpc2NvdmVyIiwgImV4dHNjYW4iLCAiaW5qZWN0IiwgImV4cGxvaXQiXQog"
    "ICAgc2VsZWN0ZWQgPSBbcCBmb3IgcCBpbiBvcmRlciBpZiBwIGluIGFyZ3MucGhhc2VzXQogICAgcHJpbnQoZiJbKl0gUGhh"
    "c2VzIHNlbGVjdGVkIGZvciB0aGlzIHJ1bjogeycsICcuam9pbihzZWxlY3RlZCl9IikKICAgIGlmICJleHBsb2l0IiBpbiBh"
    "cmdzLnBoYXNlcyBhbmQgbm90IGFyZ3MuaV9hbV9hdXRob3JpemVkOgogICAgICAgIHByaW50KCJbIV0gJ2V4cGxvaXQnIGlz"
    "IHNlbGVjdGVkIGJ1dCAtLWktYW0tYXV0aG9yaXplZCB3YXMgTk9UIHBhc3NlZCAtIHRoZSBleHBsb2l0IHBoYXNlIHdpbGwg"
    "cmVmdXNlIHRvICIKICAgICAgICAgICAgICAicnVuIChzZWUgV0EtRVhQLTAwMCBpbiB0aGUgb3V0cHV0KSB1bnRpbCB5b3Ug"
    "YWRkIC0taS1hbS1hdXRob3JpemVkLiIpCgoKZGVmIHJ1bl9mdWxsX3N1aXRlKHRhcmdldF91cmwsIGFyZ3MpOgogICAgIiIi"
    "UnVucyBldmVyeSBhdXRvbWF0ZWQgY2hlY2sgYWdhaW5zdCBleGFjdGx5IG9uZSBVUkwgKGVpdGhlciB0aGUKICAgIGdpdmVu"
    "LXVybCBwYXNzIG9yIHRoZSBzaXRlLXJvb3QgcGFzcyAtIHRoZSBjYWxsZXIgaGFzIGFscmVhZHkgc2V0CiAgICBDVFggc28g"
    "ZXZlcnkgYWRkKCkgY2FsbCBiZWxvdyB0YWdzIGl0c2VsZiBjb3JyZWN0bHkpLiIiIgogICAgaGVhZGVyc19yZXN1bHQsIGhk"
    "cl9jdXJsX2Jsb2NrID0gY2hlY2tfc2VjdXJpdHlfaGVhZGVycyh0YXJnZXRfdXJsLCBhcmdzKQogICAgY2hlY2tfdGxzKHRh"
    "cmdldF91cmwsIGFyZ3MpCiAgICBjaGVja19jbGlja2phY2tpbmcodGFyZ2V0X3VybCwgaGVhZGVyc19yZXN1bHQpCiAgICBj"
    "aGVja19jb3JzKHRhcmdldF91cmwsIGFyZ3MpCiAgICBjaGVja19pbmZvcm1hdGlvbl9nYXRoZXJpbmcodGFyZ2V0X3VybCwg"
    "aGVhZGVyc19yZXN1bHQsIGFyZ3MpCiAgICBjaGVja19jb25maWd1cmF0aW9uKHRhcmdldF91cmwsIGhlYWRlcnNfcmVzdWx0"
    "LCBoZHJfY3VybF9ibG9jaywgYXJncykKICAgIGNoZWNrX3Nlc3Npb25fbWFuYWdlbWVudCh0YXJnZXRfdXJsLCBoZWFkZXJz"
    "X3Jlc3VsdCwgYXJncykKICAgIGNoZWNrX2NsaWVudF9zdG9yYWdlKHRhcmdldF91cmwsIGhlYWRlcnNfcmVzdWx0LCBhcmdz"
    "KQogICAgY2hlY2tfZW1haWxfc2VjdXJpdHkodGFyZ2V0X3VybCwgYXJncykKCiAgICBoZHI0MDAgPSBuZXh0KChyWyJldmlk"
    "ZW5jZSJdIGZvciByIGluIFJFU1VMVFMgaWYgclsiaWQiXSA9PSAiV0EtSERSLTQwMCIgYW5kIHJbInVybCJdID09IHRhcmdl"
    "dF91cmwpLCAiIikKICAgIGhkcjQwMSA9IG5leHQoKHJbImV2aWRlbmNlIl0gZm9yIHIgaW4gUkVTVUxUUyBpZiByWyJpZCJd"
    "ID09ICJXQS1IRFItNDAxIiBhbmQgclsidXJsIl0gPT0gdGFyZ2V0X3VybCksICIiKQogICAgb3RnMjg2ID0gbmV4dCgoclsi"
    "ZXZpZGVuY2UiXSBmb3IgciBpbiBSRVNVTFRTIGlmIHJbImlkIl0gPT0gIldBLU9URy0yODYiIGFuZCByWyJ1cmwiXSA9PSB0"
    "YXJnZXRfdXJsKSwgIiIpCiAgICBjaGVja19pbmZvcm1hdGlvbl9kaXNjbG9zdXJlKHRhcmdldF91cmwsIGhlYWRlcnNfcmVz"
    "dWx0LCBhcmdzLCBoZHI0MDAsIGhkcjQwMSwgb3RnMjg2KQogICAgY2hlY2tfaG9zdF9oZWFkZXIodGFyZ2V0X3VybCwgYXJn"
    "cykKICAgIGNoZWNrX2FjY2Vzc19jb250cm9sXzJmYSh0YXJnZXRfdXJsLCBhcmdzKQoKCmRlZiBzY2FuX3VybChyYXdfdXJs"
    "LCBhcmdzKToKICAgICIiIkV2ZXJ5IFVSTCAtIHdoZXRoZXIgZ2l2ZW4gdmlhIC0tdXJsIG9yIHJlYWQgZnJvbSAtLXVybC1m"
    "aWxlIC0gZ29lcwogICAgdGhyb3VnaCBleGFjdGx5IHRoaXMgc2FtZSBwYXRoLCBzbyBhIGJhdGNoIG9mIG1hbnVhbGx5IGN1"
    "cmF0ZWQgVVJMcyBpbgogICAgYSBmaWxlIGlzIGNhcHR1cmVkIGlkZW50aWNhbGx5IHRvIGEgc2luZ2xlIC0tdXJsIHJ1bjog"
    "ZWFjaCBvbmUgZ2V0cwogICAgaXRzIG93biBnaXZlbi11cmwgcGFzcywgYW5kICh1bmxlc3MgLS1za2lwLXJvb3QtcGFzcykg"
    "aXRzIG93bgogICAgYXV0b21hdGljIHNpdGUtcm9vdCBwYXNzIHRvby4iIiIKICAgIGZ1bGxfdXJsID0gbm9ybWFsaXplX3Vy"
    "bChyYXdfdXJsKQogICAgcm9vdF91cmwgPSBiYXNlX3VybF9vZihmdWxsX3VybCkKICAgIHNhbWVfYXNfcm9vdCA9IHJvb3Rf"
    "dXJsLnJzdHJpcCgiLyIpID09IGZ1bGxfdXJsLnJzdHJpcCgiLyIpCgogICAgdGFyZ2V0cyA9IFsoZnVsbF91cmwsICJnaXZl"
    "bi11cmwgKHNpdGUgcm9vdCkiIGlmIHNhbWVfYXNfcm9vdCBlbHNlICJnaXZlbi11cmwiKV0KICAgIGlmIG5vdCBzYW1lX2Fz"
    "X3Jvb3QgYW5kIG5vdCBhcmdzLnNraXBfcm9vdF9wYXNzOgogICAgICAgIHRhcmdldHMuYXBwZW5kKChyb290X3VybCwgInNp"
    "dGUtcm9vdCIpKQoKICAgIGZvciB0YXJnZXRfdXJsLCByb2xlIGluIHRhcmdldHM6CiAgICAgICAgQ1RYWyJzb3VyY2VfaW5w"
    "dXQiXSA9IHJhd191cmwKICAgICAgICBDVFhbInVybF9yb2xlIl0gPSByb2xlCiAgICAgICAgQ1RYWyJwaGFzZSJdID0gImJh"
    "c2VsaW5lIgogICAgICAgIHByaW50KGYiXG5bKl0gVGVzdGluZyB7dGFyZ2V0X3VybH0gICAocm9sZToge3JvbGV9OyBmcm9t"
    "IGlucHV0OiB7cmF3X3VybH0pIikKICAgICAgICBydW5fZnVsbF9zdWl0ZSh0YXJnZXRfdXJsLCBhcmdzKQogICAgICAgIGlm"
    "IGFyZ3MuZGVsYXk6CiAgICAgICAgICAgIHRpbWUuc2xlZXAoYXJncy5kZWxheSkKCiAgICAjIHJlY29uL2Rpc2NvdmVyL2V4"
    "dHNjYW4vaW5qZWN0L2V4cGxvaXQgKHNlZSBydW5fZXh0ZW5kZWRfcGhhc2VzKCkpIC0KICAgICMgcnVuIGF0IG1vc3Qgb25j"
    "ZSBwZXIgaW5wdXQgVVJMLCBhZ2FpbnN0IHRoZSBnaXZlbiBVUkwgb25seSwgbmV2ZXIKICAgICMgZHVwbGljYXRlZCBhZ2Fp"
    "bnN0IHRoZSBhdXRvbWF0aWMgc2l0ZS1yb290IHBhc3MgYWJvdmUuCiAgICBydW5fZXh0ZW5kZWRfcGhhc2VzKGZ1bGxfdXJs"
    "LCByYXdfdXJsLCBhcmdzKQoKCk9VVFBVVF9GSUVMRFMgPSBbInNvdXJjZV9pbnB1dCIsICJ1cmxfcm9sZSIsICJwaGFzZSIs"
    "ICJ1cmwiLCAiaWQiLCAiY2F0ZWdvcnkiLCAidGVzdCIsCiAgICAgICAgICAgICAgICAgICJzZXZlcml0eSIsICJwcmlvcml0"
    "eSIsICJyZXN1bHQiLCAiZXZpZGVuY2UiLCAiY2hlY2tlZF9hdCJdCkNTVl9GSUVMRFMgPSBPVVRQVVRfRklFTERTICsgWyJz"
    "Y3JlZW5zaG90Il0KCiMgV29yc3QtY2FzZSB3aW5zIHdoZW4gdGhlIHNhbWUgY2hlY2tsaXN0IElEIHdhcyB0ZXN0ZWQgYWdh"
    "aW5zdCBtb3JlIHRoYW4KIyBvbmUgVVJML3JvbGUgKHRoZSBkZWZhdWx0IGR1YWwtcGFzcywgb3IgYSAtLXVybC1maWxlIGJh"
    "dGNoKSAtIG1hdGNoZXMKIyB0aGUgc2FtZSByYW5raW5nIHV0aWxzX2F1dG9zY2FuX2ltcG9ydC5weSB1c2VzIG9uIHRoZSBE"
    "amFuZ28gaW1wb3J0IHNpZGUsCiMgc28gIndoYXQgZG9lcyB0aGUgcG9ydGFsIGVuZCB1cCBtYXJraW5nIiBhbmQgIndoYXQg"
    "ZG9lcyB0aGlzIHJlcG9ydCBzaG93CiMgYXMgdGhlIG92ZXJhbGwgcmVzdWx0IiBhbHdheXMgYWdyZWUuClJFU1VMVF9QUklP"
    "UklUWSA9IHsiRkFJTCI6IDUsICJFUlJPUiI6IDQsICJNQU5VQUwiOiAzLCAiSU5GTyI6IDIsICJQQVNTIjogMX0KQ09OU09M"
    "SURBVEVEX0ZJRUxEUyA9IFsiaWQiLCAiY2F0ZWdvcnkiLCAidGVzdCIsICJzZXZlcml0eSIsICJwcmlvcml0eSIsICJyZXN1"
    "bHQiLAogICAgICAgICAgICAgICAgICAgICAgICAiYWZmZWN0ZWRfdXJsX2NvdW50IiwgImFmZmVjdGVkX3VybHMiLCAidG90"
    "YWxfdXJsc190ZXN0ZWQiLCAiZXZpZGVuY2UiLAogICAgICAgICAgICAgICAgICAgICAgICAic2NyZWVuc2hvdF9jb3VudCJd"
    "CgoKZGVmIGNvbnNvbGlkYXRlX2J5X2lkKCk6CiAgICAiIiJHcm91cHMgZXZlcnkgcmVzdWx0IHJvdyBieSBjaGVja2xpc3Qg"
    "SUQgYWNyb3NzIEFMTCBpbnB1dCBVUkxzIGFuZAogICAgQUxMIFVSTCtyb2xlIHBhc3NlcyAoZ2l2ZW4tdXJsICsgc2l0ZS1y"
    "b290LCBhbmQgZXZlcnkgVVJMIGluIGEKICAgIC0tdXJsLWZpbGUgYmF0Y2gpIGludG8gT05FIHJvdyBwZXIgSUQsIHdpdGgg"
    "ZXZlcnkgVVJMIHRoYXQgaGl0IHRoZQogICAgd29yc3QtY2FzZSByZXN1bHQgY29tYmluZWQgaW50byBhIHNpbmdsZSBjZWxs"
    "LiBSZXF1ZXN0ZWQgZGlyZWN0bHk6CiAgICAic2FtZSBmaW5kaWducyBJRCBXQS1IRFItMzkyIHJlcG9ydGVkIG9uIDx1cmwx"
    "PiBhbmQgPHVybDI+IC4uLiByZXBvcnQKICAgIG9uZSBJRCBhdCBvbmNlLCBjbHViIGFsbCB0aGUgdnVsbmVyYWJsZSBVUkxz"
    "IGluIG9uZSBjZWxscyBldmVuIGZvcgogICAgbXVsdGlwbGUgVVJMcyBpIHBhc3RlZCB3aW4gVVJMIHRleHQgZmlsZS4iIERv"
    "ZXMgTk9UIHJlcGxhY2UgdGhlCiAgICBncmFudWxhciBwZXItVVJMIEpTT04gKHN0aWxsIG5lZWRlZCBmb3IgdGhlIERqYW5n"
    "byBpbXBvcnQgZmVhdHVyZSBhbmQKICAgIGV4dHJhY3RfZXZpZGVuY2VfaW1hZ2VzLnB5KSAtIHRoaXMgaXMgYW4gYWRkaXRp"
    "b25hbCByb2xsZWQtdXAgdmlldyBmb3IKICAgIHRoZSBDU1YvWExTWCBzaWRlLiIiIgogICAgYnlfaWQgPSB7fQogICAgZm9y"
    "IHJvdyBpbiBSRVNVTFRTOgogICAgICAgIGJ5X2lkLnNldGRlZmF1bHQocm93WyJpZCJdLCBbXSkuYXBwZW5kKHJvdykKCiAg"
    "ICBjb25zb2xpZGF0ZWQgPSBbXQogICAgZm9yIGNpZCwgcm93cyBpbiBzb3J0ZWQoYnlfaWQuaXRlbXMoKSk6CiAgICAgICAg"
    "d29yc3QgPSBtYXgocm93cywga2V5PWxhbWJkYSByOiBSRVNVTFRfUFJJT1JJVFkuZ2V0KHJbInJlc3VsdCJdLCAwKSkKICAg"
    "ICAgICB3b3JzdF9yZXN1bHQgPSB3b3JzdFsicmVzdWx0Il0KCiAgICAgICAgIyBNdWx0aXBsZSBhZmZlY3RlZCBVUkxzIGNh"
    "biBlYWNoIGNhcnJ5IHRoZWlyIE9XTiBzY3JlZW5zaG90CiAgICAgICAgIyAoLS1zY3JlZW5zaG90IGZhaWwvYWxsIGdlbmVy"
    "YXRlcyBvbmUgcGVyIHF1YWxpZnlpbmcgcm93KSAtCiAgICAgICAgIyByZXF1ZXN0ZWQgZGlyZWN0bHk6ICJzY3JlZW5zaG90"
    "IHNob3VsZCBiZSBtdWx0aXBsZSBvdXRwdXQgd2lsbAogICAgICAgICMgYmUgbXVsdGlwbGUgc28gYWRkIGltYWdlIDEgaW1h"
    "Z2UgZm9yIGltYWdlIGJhc2UgY29kZSIgLSBldmVyeQogICAgICAgICMgVVJMJ3MgaW1hZ2UgKGlmIGl0IGhhcyBvbmUpIGlz"
    "IGtlcHQsIG51bWJlcmVkIGluIHRoZSBzYW1lIG9yZGVyCiAgICAgICAgIyBhcyB1cmxfcmVzdWx0cywgaW5zdGVhZCBvZiBv"
    "bmx5IHRoZSBmaXJzdCBVUkwncy4KICAgICAgICAjCiAgICAgICAgIyBUaGUgU0FNRSBhcHBsaWVzIHRvIGV2aWRlbmNlIHRl"
    "eHQsIGZpeGVkIGFmdGVyIGJlaW5nIHJlcG9ydGVkCiAgICAgICAgIyBkaXJlY3RseTogImZvciBvdXQgcHV0IGluIGVpZGFj"
    "ZSBpIG1hIHNzc2VldGluZyBvbmx5IHRoZQogICAgICAgICMgbWVzc2FnZSBub3QgYWN0dWFsIG91dHB1dCBmb3Igb24gdGFy"
    "Z2V0IHdoZW5pIHBhc3MgbXVsdGlwbGUKICAgICAgICAjIHVybHMgaXQgZ2l2ZSBnZW5yaWMgbWVzc2FnZSBub3Qgc2hvd2lu"
    "ZyB3aGF0IGV4YWN0bHkgaGFwcGVuZAogICAgICAgICMgZm9yIGVhY2ggdXJsLiIgUHJldmlvdXNseSB0aGlzIHJvdydzICJl"
    "dmlkZW5jZSIgZmllbGQgd2FzIGp1c3QKICAgICAgICAjIHdvcnN0WyJldmlkZW5jZSJdIC0gT05FIHJvdydzIHRleHQgKHdo"
    "aWNoZXZlciB0aGUgc2FtZS1wcmlvcml0eQogICAgICAgICMgdGllLWJyZWFrIGhhcHBlbmVkIHRvIGxhbmQgb24pIC0gZXZl"
    "biB0aG91Z2ggc2V2ZXJhbCBkaWZmZXJlbnQKICAgICAgICAjIFVSTHMgY291bGQgYmUgaW52b2x2ZWQsIGVhY2ggb2Ygd2hp"
    "Y2ggcmFuIGl0cyBPV04gcmVxdWVzdCBhbmQKICAgICAgICAjIGdvdCBpdHMgT1dOIHJlYWwgb3V0cHV0IChkaWZmZXJlbnQg"
    "Y3VybC9ubWFwIG91dHB1dCwgc3RhdHVzCiAgICAgICAgIyBjb2RlcywgZXRjLiBwZXIgVVJMKS4gTm93IGV2ZXJ5IFVSTCdz"
    "IG93biBldmlkZW5jZSBpcyBrZXB0IGFuZAogICAgICAgICMgc2hvd24gbGFiZWxsZWQgYnkgVVJMLCBzbyBub3RoaW5nIGlz"
    "IGdlbmVyaWNpemVkIGF3YXkuCiAgICAgICAgIwogICAgICAgICMgQW5kIEVWRVJZIHRlc3RlZCBVUkwgLSBub3QganVzdCB0"
    "aGUgb25lcyBtYXRjaGluZyB0aGUgd29yc3QKICAgICAgICAjIHJlc3VsdCAtIGlzIG5vdyBsaXN0ZWQgd2l0aCBpdHMgT1dO"
    "IHBlci1VUkwgcmVzdWx0LCBmaXhlZCBhZnRlcgogICAgICAgICMgYmVpbmcgcmVwb3J0ZWQgZGlyZWN0bHk6ICJpZiBhbnkg"
    "dXJsIHBhc3NlZCB5b3UgY2FuIG1lbnRpb25lCiAgICAgICAgIyAxMjcuMC4wLjE6UEFTU0VEIGlmIG9uZXNlcnZlciBmYWls"
    "ZWQgdW5kZXIgdGhlIHZ1bG5lcmFiaWxpdHkKICAgICAgICAjIHRpdHRsZSBtYXIgdGhlIHN0YXR1cyBhcyBmYWlsZWQgbmQg"
    "Z2l2ZSB0aGUgb3V0cHV0IGFmZmVjdGVkCiAgICAgICAgIyB1cmxzIHRlbGwgY3JlYWVseSB3aGljaCB1cmwgaXMgcGFzc2Vk"
    "IHdoaWNoIGlzIGZhaWxlZC4iCiAgICAgICAgIyBQcmV2aW91c2x5ICJBZmZlY3RlZCBVUkwocykiIG9ubHkgbGlzdGVkIHRo"
    "ZSBVUkwocykgdGhhdCBoaXQKICAgICAgICAjIHRoZSB3b3JzdC1jYXNlIHJlc3VsdCAtIGlmIFVSTCBBIHBhc3NlZCBhbmQg"
    "VVJMIEIgZmFpbGVkLCBvbmx5CiAgICAgICAgIyBCIGFwcGVhcmVkLCB3aXRoIG5vIHdheSB0byB0ZWxsIEEgd2FzIGV2ZW4g"
    "dGVzdGVkLCBsZXQgYWxvbmUKICAgICAgICAjIHRoYXQgaXQgcGFzc2VkLiBUaGUgb3ZlcmFsbCAicmVzdWx0IiBmb3IgdGhl"
    "IElEIGlzIFVOQ0hBTkdFRCAtCiAgICAgICAgIyBzdGlsbCB3b3JzdC1jYXNlLXdpbnMgKGEgRkFJTCBvbiBhbnkgVVJMIHN0"
    "aWxsIHJlcG9ydHMgdGhlIElECiAgICAgICAgIyBhcyBGQUlMIG92ZXJhbGwpIC0gYnV0IHVybF9yZXN1bHRzL2FmZmVjdGVk"
    "X3VybHMgbm93IHNob3dzCiAgICAgICAgIyBFVkVSWSB0ZXN0ZWQgVVJMIHdpdGggaXRzIG93biBQQVNTL0ZBSUwvZXRjLiBl"
    "eHBsaWNpdGx5LCBzbwogICAgICAgICMgaXQncyBuZXZlciBhbWJpZ3VvdXMgd2hpY2ggVVJMKHMpIGFjdHVhbGx5IGZhaWxl"
    "ZCB2cy4gd2hpY2gKICAgICAgICAjIHBhc3NlZC4KICAgICAgICBzZWVuID0gc2V0KCkKICAgICAgICB1cmxfcmVzdWx0cyA9"
    "IFtdCiAgICAgICAgc2NyZWVuc2hvdHMgPSBbXQogICAgICAgIGZvciByIGluIHJvd3M6CiAgICAgICAgICAgIGtleSA9IChy"
    "WyJ1cmwiXSwgclsidXJsX3JvbGUiXSkKICAgICAgICAgICAgaWYga2V5IGluIHNlZW46CiAgICAgICAgICAgICAgICBjb250"
    "aW51ZQogICAgICAgICAgICBzZWVuLmFkZChrZXkpCiAgICAgICAgICAgIHVybF9yZXN1bHRzLmFwcGVuZCh7CiAgICAgICAg"
    "ICAgICAgICAiaW5kZXgiOiBsZW4odXJsX3Jlc3VsdHMpICsgMSwgICMgbWF0Y2hlcyB0aGlzIFVSTCdzIDEtYmFzZWQgcG9z"
    "aXRpb24gaW4gdXJsX3Jlc3VsdHMKICAgICAgICAgICAgICAgICJ1cmwiOiByWyJ1cmwiXSwgInVybF9yb2xlIjogclsidXJs"
    "X3JvbGUiXSwKICAgICAgICAgICAgICAgICJyZXN1bHQiOiByWyJyZXN1bHQiXSwKICAgICAgICAgICAgICAgICJldmlkZW5j"
    "ZSI6IHJbImV2aWRlbmNlIl0sCiAgICAgICAgICAgIH0pCiAgICAgICAgICAgIGlmIHIuZ2V0KCJldmlkZW5jZV9pbWFnZV9i"
    "YXNlNjQiKToKICAgICAgICAgICAgICAgIHNjcmVlbnNob3RzLmFwcGVuZCh7CiAgICAgICAgICAgICAgICAgICAgImluZGV4"
    "IjogbGVuKHVybF9yZXN1bHRzKSwgICMgbWF0Y2hlcyB0aGlzIFVSTCdzIDEtYmFzZWQgcG9zaXRpb24gaW4gdXJsX3Jlc3Vs"
    "dHMKICAgICAgICAgICAgICAgICAgICAidXJsIjogclsidXJsIl0sICJ1cmxfcm9sZSI6IHJbInVybF9yb2xlIl0sCiAgICAg"
    "ICAgICAgICAgICAgICAgImltYWdlX2Jhc2U2NCI6IHJbImV2aWRlbmNlX2ltYWdlX2Jhc2U2NCJdLAogICAgICAgICAgICAg"
    "ICAgfSkKCiAgICAgICAgdG90YWxfdXJscyA9IGxlbih1cmxfcmVzdWx0cykKICAgICAgICBhZmZlY3RlZF91cmxfY291bnQg"
    "PSBzdW0oMSBmb3IgdSBpbiB1cmxfcmVzdWx0cyBpZiB1WyJyZXN1bHQiXSA9PSB3b3JzdF9yZXN1bHQpCgogICAgICAgICMg"
    "IkFmZmVjdGVkIFVSTChzKSIgdGV4dCBub3cgc2hvd3MgRVZFUlkgdGVzdGVkIFVSTCB3aXRoIGl0cyBvd24KICAgICAgICAj"
    "IHJlc3VsdCBhcHBlbmRlZCAoZS5nLiAiaHR0cHM6Ly9hLmV4YW1wbGUvIChnaXZlbi11cmwpIC0gRkFJTCIpLAogICAgICAg"
    "ICMgbm90IGp1c3QgdGhlIG9uZXMgbWF0Y2hpbmcgdGhlIHdvcnN0LWNhc2UgcmVzdWx0LgogICAgICAgIGFmZmVjdGVkX3Vy"
    "bHNfbGluZXMgPSBbZiJ7dVsndXJsJ119ICh7dVsndXJsX3JvbGUnXX0pIC0ge3VbJ3Jlc3VsdCddfSIgZm9yIHUgaW4gdXJs"
    "X3Jlc3VsdHNdCgogICAgICAgIHdvcnN0X21hdGNoaW5nID0gW3UgZm9yIHUgaW4gdXJsX3Jlc3VsdHMgaWYgdVsicmVzdWx0"
    "Il0gPT0gd29yc3RfcmVzdWx0XQogICAgICAgIGlmIGxlbih3b3JzdF9tYXRjaGluZykgPiAxOgogICAgICAgICAgICAjIE1v"
    "cmUgdGhhbiBvbmUgVVJMIGhpdCB0aGUgd29yc3QtY2FzZSByZXN1bHQgLSBsYWJlbCBlYWNoCiAgICAgICAgICAgICMgb25l"
    "J3Mgb3duIGV2aWRlbmNlIHNvIGl0J3MgY2xlYXIgd2hpY2ggb3V0cHV0IGNhbWUgZnJvbQogICAgICAgICAgICAjIHdoaWNo"
    "IHRhcmdldCwgaW5zdGVhZCBvZiBjb2xsYXBzaW5nIHRvIGEgc2luZ2xlIHJvdydzIHRleHQuCiAgICAgICAgICAgIGNvbWJp"
    "bmVkX2V2aWRlbmNlID0gIlxuXG4iLmpvaW4oCiAgICAgICAgICAgICAgICBmIlt7dVsndXJsX3JvbGUnXX06IHt1Wyd1cmwn"
    "XX1dXG57dVsnZXZpZGVuY2UnXX0iIGZvciB1IGluIHdvcnN0X21hdGNoaW5nKQogICAgICAgIGVsc2U6CiAgICAgICAgICAg"
    "ICMgRXhhY3RseSBvbmUgVVJMIGhpdCB0aGUgd29yc3QtY2FzZSByZXN1bHQgKHRoZSBjb21tb24gY2FzZSkKICAgICAgICAg"
    "ICAgIyAtIG5vIG5lZWQgZm9yIGEgIlt1cmxdIiBsYWJlbCBvbiBhIHNpbmdsZSBibG9jay4KICAgICAgICAgICAgY29tYmlu"
    "ZWRfZXZpZGVuY2UgPSB3b3JzdFsiZXZpZGVuY2UiXQoKICAgICAgICBjb25zb2xpZGF0ZWQuYXBwZW5kKHsKICAgICAgICAg"
    "ICAgImlkIjogY2lkLAogICAgICAgICAgICAiY2F0ZWdvcnkiOiB3b3JzdFsiY2F0ZWdvcnkiXSwKICAgICAgICAgICAgInRl"
    "c3QiOiB3b3JzdFsidGVzdCJdLAogICAgICAgICAgICAic2V2ZXJpdHkiOiB3b3JzdFsic2V2ZXJpdHkiXSwKICAgICAgICAg"
    "ICAgInByaW9yaXR5Ijogd29yc3RbInByaW9yaXR5Il0sCiAgICAgICAgICAgICJyZXN1bHQiOiB3b3JzdF9yZXN1bHQsCiAg"
    "ICAgICAgICAgICJhZmZlY3RlZF91cmxfY291bnQiOiBhZmZlY3RlZF91cmxfY291bnQsCiAgICAgICAgICAgICJhZmZlY3Rl"
    "ZF91cmxzIjogIlxuIi5qb2luKGFmZmVjdGVkX3VybHNfbGluZXMpLAogICAgICAgICAgICAidG90YWxfdXJsc190ZXN0ZWQi"
    "OiB0b3RhbF91cmxzLAogICAgICAgICAgICAiZXZpZGVuY2UiOiBjb21iaW5lZF9ldmlkZW5jZSwKICAgICAgICAgICAgInVy"
    "bF9yZXN1bHRzIjogdXJsX3Jlc3VsdHMsICAjIEpTT04tb25seSAtIGV2ZXJ5IHRlc3RlZCBVUkwgKyBpdHMgb3duIHJlc3Vs"
    "dC9ldmlkZW5jZQogICAgICAgICAgICAic2NyZWVuc2hvdF9jb3VudCI6IGxlbihzY3JlZW5zaG90cyksCiAgICAgICAgICAg"
    "ICJzY3JlZW5zaG90cyI6IHNjcmVlbnNob3RzLCAgIyBKU09OLW9ubHkgLSBzZWUgd3JpdGVfY29uc29saWRhdGVkX2pzb24o"
    "KS93cml0ZV94bHN4KCkKICAgICAgICB9KQogICAgcmV0dXJuIGNvbnNvbGlkYXRlZAoKCmRlZiB3cml0ZV9jb25zb2xpZGF0"
    "ZWRfY3N2KHBhdGgpOgogICAgcm93cyA9IGNvbnNvbGlkYXRlX2J5X2lkKCkKICAgIHdpdGggb3BlbihwYXRoLCAidyIsIG5l"
    "d2xpbmU9IiIsIGVuY29kaW5nPSJ1dGYtOCIpIGFzIGY6CiAgICAgICAgdyA9IGNzdi5EaWN0V3JpdGVyKGYsIGZpZWxkbmFt"
    "ZXM9Q09OU09MSURBVEVEX0ZJRUxEUykKICAgICAgICB3LndyaXRlaGVhZGVyKCkKICAgICAgICBmb3Igcm93IGluIHJvd3M6"
    "CiAgICAgICAgICAgICMgInNjcmVlbnNob3RzIiAodGhlIGxpc3Qgb2YgYmFzZTY0IGltYWdlcykgaXMgSlNPTi1vbmx5IC0g"
    "YQogICAgICAgICAgICAjIGJhc2U2NCBQTkcgZG9lc24ndCBiZWxvbmcgaW4gYSBDU1YgY2VsbDsgc2NyZWVuc2hvdF9jb3Vu"
    "dAogICAgICAgICAgICAjIChhbHJlYWR5IGluIENPTlNPTElEQVRFRF9GSUVMRFMpIHRlbGxzIHlvdSBob3cgbWFueSBleGlz"
    "dC4KICAgICAgICAgICAgdy53cml0ZXJvdyh7azogcm93W2tdIGZvciBrIGluIENPTlNPTElEQVRFRF9GSUVMRFN9KQogICAg"
    "cmV0dXJuIHJvd3MKCgpkZWYgd3JpdGVfY29uc29saWRhdGVkX2pzb24ocGF0aCk6CiAgICByb3dzID0gY29uc29saWRhdGVf"
    "YnlfaWQoKQogICAgIyBhZmZlY3RlZF91cmxzIGlzICJcbiItam9pbmVkIGZvciB0aGUgQ1NWL1hMU1ggc2luZ2xlLWNlbGwg"
    "dmlldyBhYm92ZTsKICAgICMgSlNPTiBjb25zdW1lcnMgZ2VuZXJhbGx5IHdhbnQgYSByZWFsIGxpc3QgaW5zdGVhZCBvZiBv"
    "bmUgbmV3bGluZS0KICAgICMgZGVsaW1pdGVkIHN0cmluZywgc28gaXQncyBleHBhbmRlZCBiYWNrIG91dCBoZXJlLiBFYWNo"
    "IHNjcmVlbnNob3QgaXMKICAgICMgYWxzbyBmbGF0dGVuZWQgb3V0IHRvIGltYWdlXzFfYmFzZTY0L2ltYWdlXzJfYmFzZTY0"
    "Ly4uLiB0b3AtbGV2ZWwKICAgICMga2V5cyAoaW4gYWRkaXRpb24gdG8gdGhlIHN0cnVjdHVyZWQgInNjcmVlbnNob3RzIiBs"
    "aXN0KSBmb3Igc2ltcGxlCiAgICAjIGNvbnN1bWVycyB0aGF0IGp1c3Qgd2FudCAiaW1hZ2UgTiIgYnkgbmFtZSwgcGVyIHRo"
    "ZSBkaXJlY3QgcmVxdWVzdDoKICAgICMgInNjcmVlbnNob3Qgc2hvdWxkIGJlIG11bHRpcGxlIC4uLiBhZGQgaW1hZ2UgMSBp"
    "bWFnZSBmb3IgaW1hZ2UgYmFzZQogICAgIyBjb2RlIiAtIG9uZSByb3cgY2FuIG5vdyBoYXZlIG1vcmUgdGhhbiBvbmUgYWZm"
    "ZWN0ZWQgVVJML3NjcmVlbnNob3QuCiAgICBqc29uX3Jvd3MgPSBbXQogICAgZm9yIHJvdyBpbiByb3dzOgogICAgICAgIGpy"
    "ID0gZGljdChyb3cpCiAgICAgICAganJbImFmZmVjdGVkX3VybHMiXSA9IFt1IGZvciB1IGluIHJvd1siYWZmZWN0ZWRfdXJs"
    "cyJdLnNwbGl0KCJcbiIpIGlmIHVdCiAgICAgICAgZm9yIHNob3QgaW4gcm93WyJzY3JlZW5zaG90cyJdOgogICAgICAgICAg"
    "ICBqcltmImltYWdlX3tzaG90WydpbmRleCddfV9iYXNlNjQiXSA9IHNob3RbImltYWdlX2Jhc2U2NCJdCiAgICAgICAganNv"
    "bl9yb3dzLmFwcGVuZChqcikKICAgIHdpdGggb3BlbihwYXRoLCAidyIsIGVuY29kaW5nPSJ1dGYtOCIpIGFzIGY6CiAgICAg"
    "ICAganNvbi5kdW1wKGpzb25fcm93cywgZiwgaW5kZW50PTIpCiAgICByZXR1cm4gcm93cwoKCmRlZiB3cml0ZV9jc3YocGF0"
    "aCk6CiAgICAjIGV2aWRlbmNlX2ltYWdlX2Jhc2U2NCBpcyBpbnRlbnRpb25hbGx5IGxlZnQgb3V0IG9mIHRoZSBDU1YgKGl0"
    "IHdvdWxkCiAgICAjIG1ha2Ugcm93cyB1bnJlYWRhYmxlKSAtICJzY3JlZW5zaG90OiB5ZXMiIHRlbGxzIHlvdSB0byBjaGVj"
    "ayB0aGUKICAgICMgSlNPTiAob3IgdGhlIC54bHN4IEV2aWRlbmNlIHNoZWV0KSBmb3IgdGhhdCByb3cncyBpbWFnZSBpbnN0"
    "ZWFkLgogICAgd2l0aCBvcGVuKHBhdGgsICJ3IiwgbmV3bGluZT0iIiwgZW5jb2Rpbmc9InV0Zi04IikgYXMgZjoKICAgICAg"
    "ICB3ID0gY3N2LkRpY3RXcml0ZXIoZiwgZmllbGRuYW1lcz1DU1ZfRklFTERTKQogICAgICAgIHcud3JpdGVoZWFkZXIoKQog"
    "ICAgICAgIGZvciByb3cgaW4gUkVTVUxUUzoKICAgICAgICAgICAgb3V0X3JvdyA9IHtrOiByb3dba10gZm9yIGsgaW4gT1VU"
    "UFVUX0ZJRUxEU30KICAgICAgICAgICAgb3V0X3Jvd1sic2NyZWVuc2hvdCJdID0gInllcyIgaWYgcm93LmdldCgiZXZpZGVu"
    "Y2VfaW1hZ2VfYmFzZTY0IikgZWxzZSAibm8iCiAgICAgICAgICAgIHcud3JpdGVyb3cob3V0X3JvdykKCgpkZWYgd3JpdGVf"
    "anNvbihwYXRoKToKICAgIHdpdGggb3BlbihwYXRoLCAidyIsIGVuY29kaW5nPSJ1dGYtOCIpIGFzIGY6CiAgICAgICAganNv"
    "bi5kdW1wKFJFU1VMVFMsIGYsIGluZGVudD0yKQoKCmRlZiB3cml0ZV94bHN4KHBhdGgsIGltYWdlX2J5dGVzKToKICAgICIi"
    "IkNvbG9yLWNvZGVkLCBmaWx0ZXJhYmxlIHdvcmtib29rIC0gdGhlICdlYXN5IHRvIG5hdmlnYXRlIHBvcnRhbAogICAgbGlz"
    "dCB0byB0cmFjaycgb3V0cHV0LiBOZWVkcyBwYW5kYXMgKyB4bHN4d3JpdGVyOyBkZWdyYWRlcyBncmFjZWZ1bGx5CiAgICAo"
    "Q1NWL0pTT04gYXJlIHVuYWZmZWN0ZWQpIGlmIGVpdGhlciBpc24ndCBpbnN0YWxsZWQuIiIiCiAgICB0cnk6CiAgICAgICAg"
    "aW1wb3J0IHBhbmRhcyBhcyBwZAogICAgZXhjZXB0IEltcG9ydEVycm9yOgogICAgICAgIHByaW50KCJcblshXSAncGFuZGFz"
    "JyBub3QgaW5zdGFsbGVkIC0gc2tpcHBpbmcgLnhsc3ggb3V0cHV0IChDU1YvSlNPTiB3ZXJlIHN0aWxsIHdyaXR0ZW4pLiIp"
    "CiAgICAgICAgcHJpbnQoIiAgICBJbnN0YWxsIHdpdGg6IHBpcDMgaW5zdGFsbCBwYW5kYXMgeGxzeHdyaXRlciAgICIKICAg"
    "ICAgICAgICAgICAiKGFkZCAtLWJyZWFrLXN5c3RlbS1wYWNrYWdlcyBpZiB5b3VyIFB5dGhvbiByZXBvcnRzIGFuIGV4dGVy"
    "bmFsbHktbWFuYWdlZC1lbnZpcm9ubWVudCBlcnJvcikiKQogICAgICAgIHJldHVybiBGYWxzZQogICAgdHJ5OgogICAgICAg"
    "IGltcG9ydCB4bHN4d3JpdGVyICAjIG5vcWE6IEY0MDEKICAgIGV4Y2VwdCBJbXBvcnRFcnJvcjoKICAgICAgICBwcmludCgi"
    "XG5bIV0gJ3hsc3h3cml0ZXInIG5vdCBpbnN0YWxsZWQgLSBza2lwcGluZyAueGxzeCBvdXRwdXQgKENTVi9KU09OIHdlcmUg"
    "c3RpbGwgd3JpdHRlbikuIikKICAgICAgICBwcmludCgiICAgIEluc3RhbGwgd2l0aDogcGlwMyBpbnN0YWxsIHhsc3h3cml0"
    "ZXIgICAiCiAgICAgICAgICAgICAgIihhZGQgLS1icmVhay1zeXN0ZW0tcGFja2FnZXMgaWYgeW91ciBQeXRob24gcmVwb3J0"
    "cyBhbiBleHRlcm5hbGx5LW1hbmFnZWQtZW52aXJvbm1lbnQgZXJyb3IpIikKICAgICAgICByZXR1cm4gRmFsc2UKCiAgICBp"
    "ZiBub3QgUkVTVUxUUzoKICAgICAgICByZXR1cm4gRmFsc2UKCiAgICByZW5hbWVfbWFwID0gewogICAgICAgICJzb3VyY2Vf"
    "aW5wdXQiOiAiU291cmNlIElucHV0IiwgInVybF9yb2xlIjogIlVSTCBSb2xlIiwgInBoYXNlIjogIlBoYXNlIiwgInVybCI6"
    "ICJVUkwgVGVzdGVkIiwKICAgICAgICAiaWQiOiAiQ2hlY2tsaXN0IElEIiwgImNhdGVnb3J5IjogIkNhdGVnb3J5IiwgInRl"
    "c3QiOiAiVGVzdCBOYW1lIiwKICAgICAgICAic2V2ZXJpdHkiOiAiU2V2ZXJpdHkiLCAicHJpb3JpdHkiOiAiUHJpb3JpdHki"
    "LCAicmVzdWx0IjogIlJlc3VsdCIsCiAgICAgICAgImV2aWRlbmNlIjogIkV2aWRlbmNlIC8gQ29tbWVudHMiLCAiY2hlY2tl"
    "ZF9hdCI6ICJDaGVja2VkIEF0IChVVEMpIiwKICAgIH0KICAgIGRmID0gcGQuRGF0YUZyYW1lKFJFU1VMVFMpW09VVFBVVF9G"
    "SUVMRFNdLnJlbmFtZShjb2x1bW5zPXJlbmFtZV9tYXApCiAgICBjb2xfb3JkZXIgPSBsaXN0KHJlbmFtZV9tYXAudmFsdWVz"
    "KCkpCiAgICBkZiA9IGRmW2NvbF9vcmRlcl0KCiAgICBjb25zb2xpZGF0ZWRfcm93cyA9IGNvbnNvbGlkYXRlX2J5X2lkKCkK"
    "ICAgIGNvbnNfcmVuYW1lID0gewogICAgICAgICJpZCI6ICJDaGVja2xpc3QgSUQiLCAiY2F0ZWdvcnkiOiAiQ2F0ZWdvcnki"
    "LCAidGVzdCI6ICJUZXN0IE5hbWUiLAogICAgICAgICJzZXZlcml0eSI6ICJTZXZlcml0eSIsICJwcmlvcml0eSI6ICJQcmlv"
    "cml0eSIsICJyZXN1bHQiOiAiT3ZlcmFsbCBSZXN1bHQiLAogICAgICAgICJhZmZlY3RlZF91cmxfY291bnQiOiAiQWZmZWN0"
    "ZWQgVVJMIENvdW50IiwgImFmZmVjdGVkX3VybHMiOiAiQWZmZWN0ZWQgVVJMKHMpIiwKICAgICAgICAidG90YWxfdXJsc190"
    "ZXN0ZWQiOiAiVG90YWwgVVJMcyBUZXN0ZWQiLCAiZXZpZGVuY2UiOiAiRXZpZGVuY2UgKHdvcnN0LWNhc2UgVVJMKSIsCiAg"
    "ICB9CiAgICBjb25zX2RmID0gcGQuRGF0YUZyYW1lKGNvbnNvbGlkYXRlZF9yb3dzKVtDT05TT0xJREFURURfRklFTERTXS5y"
    "ZW5hbWUoY29sdW1ucz1jb25zX3JlbmFtZSkKICAgIGNvbnNfY29sX29yZGVyID0gbGlzdChjb25zX3JlbmFtZS52YWx1ZXMo"
    "KSkKICAgIGNvbnNfZGYgPSBjb25zX2RmW2NvbnNfY29sX29yZGVyXQoKICAgIHdpdGggcGQuRXhjZWxXcml0ZXIocGF0aCwg"
    "ZW5naW5lPSJ4bHN4d3JpdGVyIikgYXMgd3JpdGVyOgogICAgICAgICMgV3JpdHRlbiBGSVJTVCBzbyBpdCdzIHRoZSBzaGVl"
    "dCB2aXNpYmxlIHdoZW4gdGhlIGZpbGUgb3BlbnMgLQogICAgICAgICMgb25lIHJvdyBwZXIgY2hlY2tsaXN0IElELCBldmVy"
    "eSBhZmZlY3RlZCBVUkwgY2x1YmJlZCBpbnRvIGEKICAgICAgICAjIHNpbmdsZSBjZWxsIGluc3RlYWQgb2YgYSBzZXBhcmF0"
    "ZSByb3cgcGVyIFVSTC9yb2xlIHBhc3MuCiAgICAgICAgY29uc19kZi50b19leGNlbCh3cml0ZXIsIHNoZWV0X25hbWU9IkNv"
    "bnNvbGlkYXRlZCIsIGluZGV4PUZhbHNlKQogICAgICAgIHdvcmtib29rID0gd3JpdGVyLmJvb2sKICAgICAgICBjb25zX3No"
    "ZWV0ID0gd3JpdGVyLnNoZWV0c1siQ29uc29saWRhdGVkIl0KICAgICAgICBjb25zX2hlYWRlcl9mbXQgPSB3b3JrYm9vay5h"
    "ZGRfZm9ybWF0KHsiYm9sZCI6IFRydWUsICJiZ19jb2xvciI6ICIjRDdFNEJDIiwgImJvcmRlciI6IDEsICJ0ZXh0X3dyYXAi"
    "OiBUcnVlfSkKICAgICAgICBjb25zX3dyYXBfZm10ID0gd29ya2Jvb2suYWRkX2Zvcm1hdCh7InRleHRfd3JhcCI6IFRydWUs"
    "ICJ2YWxpZ24iOiAidG9wIn0pCiAgICAgICAgZm9yIGksIGNvbCBpbiBlbnVtZXJhdGUoY29uc19jb2xfb3JkZXIpOgogICAg"
    "ICAgICAgICBjb25zX3NoZWV0LndyaXRlKDAsIGksIGNvbCwgY29uc19oZWFkZXJfZm10KQogICAgICAgIGNvbnNfd2lkdGhz"
    "ID0gWzEyLCAyNCwgMzYsIDEwLCAxMCwgMTQsIDEwLCA1MCwgMTIsIDYwXQogICAgICAgIHdyYXBfY29scyA9ICgiQWZmZWN0"
    "ZWQgVVJMKHMpIiwgIkV2aWRlbmNlICh3b3JzdC1jYXNlIFVSTCkiKQogICAgICAgIGZvciBpLCB3IGluIGVudW1lcmF0ZShj"
    "b25zX3dpZHRocyk6CiAgICAgICAgICAgIGNvbnNfc2hlZXQuc2V0X2NvbHVtbihpLCBpLCB3LCBjb25zX3dyYXBfZm10IGlm"
    "IGNvbnNfY29sX29yZGVyW2ldIGluIHdyYXBfY29scyBlbHNlIE5vbmUpCiAgICAgICAgY29uc19zaGVldC5mcmVlemVfcGFu"
    "ZXMoMSwgMCkKICAgICAgICBjb25zX3NoZWV0LmF1dG9maWx0ZXIoMCwgMCwgbGVuKGNvbnNfZGYpLCBsZW4oY29uc19jb2xf"
    "b3JkZXIpIC0gMSkKICAgICAgICBjb25zX3Jlc3VsdF9jb2xfaWR4ID0gY29uc19jb2xfb3JkZXIuaW5kZXgoIk92ZXJhbGwg"
    "UmVzdWx0IikKICAgICAgICBjb25zX2NvbG9yX2ZtdHMgPSB7CiAgICAgICAgICAgICJQQVNTIjogd29ya2Jvb2suYWRkX2Zv"
    "cm1hdCh7ImJnX2NvbG9yIjogIiNDNkVGQ0UiLCAiZm9udF9jb2xvciI6ICIjMDA2MTAwIn0pLAogICAgICAgICAgICAiRkFJ"
    "TCI6IHdvcmtib29rLmFkZF9mb3JtYXQoeyJiZ19jb2xvciI6ICIjRkZDN0NFIiwgImZvbnRfY29sb3IiOiAiIzlDMDAwNiJ9"
    "KSwKICAgICAgICAgICAgIk1BTlVBTCI6IHdvcmtib29rLmFkZF9mb3JtYXQoeyJiZ19jb2xvciI6ICIjRkZFQjlDIiwgImZv"
    "bnRfY29sb3IiOiAiIzlDNjUwMCJ9KSwKICAgICAgICAgICAgIklORk8iOiB3b3JrYm9vay5hZGRfZm9ybWF0KHsiYmdfY29s"
    "b3IiOiAiI0RDRTZGMSIsICJmb250X2NvbG9yIjogIiMxRjRFNzgifSksCiAgICAgICAgICAgICJFUlJPUiI6IHdvcmtib29r"
    "LmFkZF9mb3JtYXQoeyJiZ19jb2xvciI6ICIjRDlEOUQ5IiwgImZvbnRfY29sb3IiOiAiIzNCM0IzQiJ9KSwKICAgICAgICB9"
    "CiAgICAgICAgZm9yIHZhbCwgZm10IGluIGNvbnNfY29sb3JfZm10cy5pdGVtcygpOgogICAgICAgICAgICBjb25zX3NoZWV0"
    "LmNvbmRpdGlvbmFsX2Zvcm1hdCgxLCBjb25zX3Jlc3VsdF9jb2xfaWR4LCBsZW4oY29uc19kZiksIGNvbnNfcmVzdWx0X2Nv"
    "bF9pZHgsCiAgICAgICAgICAgICAgICB7InR5cGUiOiAiY2VsbCIsICJjcml0ZXJpYSI6ICJlcXVhbCB0byIsICJ2YWx1ZSI6"
    "IGYnInt2YWx9IicsICJmb3JtYXQiOiBmbXR9KQoKICAgICAgICBkZi50b19leGNlbCh3cml0ZXIsIHNoZWV0X25hbWU9IlNj"
    "YW4gUmVzdWx0cyAoRGV0YWlsKSIsIGluZGV4PUZhbHNlKQogICAgICAgIHNoZWV0ID0gd3JpdGVyLnNoZWV0c1siU2NhbiBS"
    "ZXN1bHRzIChEZXRhaWwpIl0KCiAgICAgICAgaGVhZGVyX2ZtdCA9IHdvcmtib29rLmFkZF9mb3JtYXQoeyJib2xkIjogVHJ1"
    "ZSwgImJnX2NvbG9yIjogIiNEN0U0QkMiLCAiYm9yZGVyIjogMSwgInRleHRfd3JhcCI6IFRydWV9KQogICAgICAgIHdyYXBf"
    "Zm10ID0gd29ya2Jvb2suYWRkX2Zvcm1hdCh7InRleHRfd3JhcCI6IFRydWUsICJ2YWxpZ24iOiAidG9wIn0pCiAgICAgICAg"
    "Zm9yIGksIGNvbCBpbiBlbnVtZXJhdGUoY29sX29yZGVyKToKICAgICAgICAgICAgc2hlZXQud3JpdGUoMCwgaSwgY29sLCBo"
    "ZWFkZXJfZm10KQoKICAgICAgICB3aWR0aHMgPSBbMjIsIDIwLCAzNCwgMTIsIDI0LCAzNiwgMTAsIDEwLCAxMCwgNzAsIDIw"
    "XQogICAgICAgIGZvciBpLCB3IGluIGVudW1lcmF0ZSh3aWR0aHMpOgogICAgICAgICAgICBzaGVldC5zZXRfY29sdW1uKGks"
    "IGksIHcsIHdyYXBfZm10IGlmIGNvbF9vcmRlcltpXSA9PSAiRXZpZGVuY2UgLyBDb21tZW50cyIgZWxzZSBOb25lKQogICAg"
    "ICAgIHNoZWV0LmZyZWV6ZV9wYW5lcygxLCAwKQogICAgICAgIHNoZWV0LmF1dG9maWx0ZXIoMCwgMCwgbGVuKGRmKSwgbGVu"
    "KGNvbF9vcmRlcikgLSAxKQoKICAgICAgICByZXN1bHRfY29sX2lkeCA9IGNvbF9vcmRlci5pbmRleCgiUmVzdWx0IikKICAg"
    "ICAgICBjb2xvcl9mbXRzID0gewogICAgICAgICAgICAiUEFTUyI6IHdvcmtib29rLmFkZF9mb3JtYXQoeyJiZ19jb2xvciI6"
    "ICIjQzZFRkNFIiwgImZvbnRfY29sb3IiOiAiIzAwNjEwMCJ9KSwKICAgICAgICAgICAgIkZBSUwiOiB3b3JrYm9vay5hZGRf"
    "Zm9ybWF0KHsiYmdfY29sb3IiOiAiI0ZGQzdDRSIsICJmb250X2NvbG9yIjogIiM5QzAwMDYifSksCiAgICAgICAgICAgICJN"
    "QU5VQUwiOiB3b3JrYm9vay5hZGRfZm9ybWF0KHsiYmdfY29sb3IiOiAiI0ZGRUI5QyIsICJmb250X2NvbG9yIjogIiM5QzY1"
    "MDAifSksCiAgICAgICAgICAgICJJTkZPIjogd29ya2Jvb2suYWRkX2Zvcm1hdCh7ImJnX2NvbG9yIjogIiNEQ0U2RjEiLCAi"
    "Zm9udF9jb2xvciI6ICIjMUY0RTc4In0pLAogICAgICAgICAgICAiRVJST1IiOiB3b3JrYm9vay5hZGRfZm9ybWF0KHsiYmdf"
    "Y29sb3IiOiAiI0Q5RDlEOSIsICJmb250X2NvbG9yIjogIiMzQjNCM0IifSksCiAgICAgICAgfQogICAgICAgIGZvciB2YWws"
    "IGZtdCBpbiBjb2xvcl9mbXRzLml0ZW1zKCk6CiAgICAgICAgICAgIHNoZWV0LmNvbmRpdGlvbmFsX2Zvcm1hdCgxLCByZXN1"
    "bHRfY29sX2lkeCwgbGVuKGRmKSwgcmVzdWx0X2NvbF9pZHgsCiAgICAgICAgICAgICAgICB7InR5cGUiOiAiY2VsbCIsICJj"
    "cml0ZXJpYSI6ICJlcXVhbCB0byIsICJ2YWx1ZSI6IGYnInt2YWx9IicsICJmb3JtYXQiOiBmbXR9KQoKICAgICAgICBzdW1t"
    "YXJ5ID0gd29ya2Jvb2suYWRkX3dvcmtzaGVldCgiU3VtbWFyeSIpCiAgICAgICAgc3VtbWFyeS5oaWRlX2dyaWRsaW5lcygy"
    "KQogICAgICAgIHRpdGxlX2ZtdCA9IHdvcmtib29rLmFkZF9mb3JtYXQoeyJib2xkIjogVHJ1ZSwgImZvbnRfc2l6ZSI6IDE0"
    "LCAiZm9udF9jb2xvciI6ICIjMkI1Nzk3In0pCiAgICAgICAgc3VtbWFyeS53cml0ZSgwLCAwLCAiQXV0b21hdGVkIENoZWNr"
    "bGlzdCBTY2FuIC0gU3VtbWFyeSIsIHRpdGxlX2ZtdCkKICAgICAgICBzdW1tYXJ5LndyaXRlKDEsIDAsIGYiR2VuZXJhdGVk"
    "OiB7bm93X2lzbygpfSIpCiAgICAgICAgc3VtbWFyeS53cml0ZSgyLCAwLCBmIlRvdGFsIGNoZWNrbGlzdCByb3dzOiB7bGVu"
    "KGRmKX0iKQogICAgICAgIHN1bW1hcnkud3JpdGUoMywgMCwgZiJVbmlxdWUgc291cmNlIFVSTHMgKGZyb20gLS11cmwgLyAt"
    "LXVybC1maWxlKToge2RmWydTb3VyY2UgSW5wdXQnXS5udW5pcXVlKCl9IikKICAgICAgICBzdW1tYXJ5LndyaXRlKDQsIDAs"
    "IGYiVW5pcXVlIFVSTCtyb2xlIHBhc3NlcyB0ZXN0ZWQ6IHtkZlsnVVJMIFRlc3RlZCddLmFzdHlwZShzdHIpLnN0ci5jYXQo"
    "ZGZbJ1VSTCBSb2xlJ10sIHNlcD0nIHwgJykubnVuaXF1ZSgpfSIpCgogICAgICAgIHJvdyA9IDYKICAgICAgICBzdW1tYXJ5"
    "LndyaXRlKHJvdywgMCwgIlJlc3VsdCIsIGhlYWRlcl9mbXQpCiAgICAgICAgc3VtbWFyeS53cml0ZShyb3csIDEsICJDb3Vu"
    "dCIsIGhlYWRlcl9mbXQpCiAgICAgICAgZm9yIGksICh2YWwsIGNudCkgaW4gZW51bWVyYXRlKGRmWyJSZXN1bHQiXS52YWx1"
    "ZV9jb3VudHMoKS5pdGVtcygpLCBzdGFydD1yb3cgKyAxKToKICAgICAgICAgICAgc3VtbWFyeS53cml0ZShpLCAwLCB2YWwp"
    "CiAgICAgICAgICAgIHN1bW1hcnkud3JpdGUoaSwgMSwgaW50KGNudCkpCgogICAgICAgIHJvdzIgPSByb3cgKyBsZW4oZGZb"
    "IlJlc3VsdCJdLnZhbHVlX2NvdW50cygpKSArIDMKICAgICAgICBzdW1tYXJ5LndyaXRlKHJvdzIsIDAsICJDYXRlZ29yeSIs"
    "IGhlYWRlcl9mbXQpCiAgICAgICAgc3VtbWFyeS53cml0ZShyb3cyLCAxLCAiQ291bnQiLCBoZWFkZXJfZm10KQogICAgICAg"
    "IGZvciBpLCAodmFsLCBjbnQpIGluIGVudW1lcmF0ZShkZlsiQ2F0ZWdvcnkiXS52YWx1ZV9jb3VudHMoKS5pdGVtcygpLCBz"
    "dGFydD1yb3cyICsgMSk6CiAgICAgICAgICAgIHN1bW1hcnkud3JpdGUoaSwgMCwgdmFsKQogICAgICAgICAgICBzdW1tYXJ5"
    "LndyaXRlKGksIDEsIGludChjbnQpKQoKICAgICAgICBzdW1tYXJ5LnNldF9jb2x1bW4oMCwgMCwgNDQpCiAgICAgICAgc3Vt"
    "bWFyeS5zZXRfY29sdW1uKDEsIDEsIDEyKQoKICAgICAgICBpZiBpbWFnZV9ieXRlczoKICAgICAgICAgICAgIyBHcm91cGVk"
    "IGJ5IGNoZWNrbGlzdCBJRCAob25lIGhlYWRpbmcgcGVyIElELCAiSW1hZ2UgMSIsCiAgICAgICAgICAgICMgIkltYWdlIDIi"
    "LCAuLi4gdW5kZXJuZWF0aCkgc28gYW4gSUQgd2l0aCBtb3JlIHRoYW4gb25lCiAgICAgICAgICAgICMgYWZmZWN0ZWQgVVJM"
    "IC0gYW5kIHRoZXJlZm9yZSBtb3JlIHRoYW4gb25lIHNjcmVlbnNob3QgLQogICAgICAgICAgICAjIHJlYWRzIHRoZSBzYW1l"
    "IHdheSB0aGUgQ29uc29saWRhdGVkIHNoZWV0IGdyb3VwcyBpdCwgaW5zdGVhZAogICAgICAgICAgICAjIG9mIGp1c3QgYSBm"
    "bGF0IGxpc3QgaW4gc2NhbiBvcmRlci4KICAgICAgICAgICAgZXZzaGVldCA9IHdvcmtib29rLmFkZF93b3Jrc2hlZXQoIkV2"
    "aWRlbmNlIikKICAgICAgICAgICAgZXZzaGVldC5oaWRlX2dyaWRsaW5lcygyKQogICAgICAgICAgICBldnNoZWV0LndyaXRl"
    "KDAsIDAsIGYiQXV0by1HZW5lcmF0ZWQgRXZpZGVuY2UgU2NyZWVuc2hvdHMgKHtsZW4oaW1hZ2VfYnl0ZXMpfSkiLCB0aXRs"
    "ZV9mbXQpCiAgICAgICAgICAgIGV2c2hlZXQuc2V0X2NvbHVtbigwLCAwLCAxMzApCiAgICAgICAgICAgIGNhcHRpb25fZm10"
    "ID0gd29ya2Jvb2suYWRkX2Zvcm1hdCh7ImJvbGQiOiBUcnVlLCAiYmdfY29sb3IiOiAiI0YyRjJGMiJ9KQogICAgICAgICAg"
    "ICBpZF9oZWFkZXJfZm10ID0gd29ya2Jvb2suYWRkX2Zvcm1hdCh7ImJvbGQiOiBUcnVlLCAiZm9udF9zaXplIjogMTIsICJm"
    "b250X2NvbG9yIjogIiMyQjU3OTciLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg"
    "ICJib3R0b20iOiAyfSkKCiAgICAgICAgICAgIGJ5X2lkX2lkeCA9IHt9CiAgICAgICAgICAgIGZvciBpZHggaW4gc29ydGVk"
    "KGltYWdlX2J5dGVzLmtleXMoKSk6CiAgICAgICAgICAgICAgICBieV9pZF9pZHguc2V0ZGVmYXVsdChSRVNVTFRTW2lkeF1b"
    "ImlkIl0sIFtdKS5hcHBlbmQoaWR4KQoKICAgICAgICAgICAgcm93X2N1cnNvciA9IDIKICAgICAgICAgICAgZm9yIGNpZCBp"
    "biBzb3J0ZWQoYnlfaWRfaWR4LmtleXMoKSk6CiAgICAgICAgICAgICAgICBpZHhzID0gYnlfaWRfaWR4W2NpZF0KICAgICAg"
    "ICAgICAgICAgIHNhbXBsZSA9IFJFU1VMVFNbaWR4c1swXV0KICAgICAgICAgICAgICAgIGV2c2hlZXQud3JpdGUocm93X2N1"
    "cnNvciwgMCwgZiJ7Y2lkfSAtIHtzYW1wbGVbJ3Rlc3QnXX0gICh7bGVuKGlkeHMpfSBpbWFnZXsncycgaWYgbGVuKGlkeHMp"
    "ICE9IDEgZWxzZSAnJ30pIiwgaWRfaGVhZGVyX2ZtdCkKICAgICAgICAgICAgICAgIHJvd19jdXJzb3IgKz0gMQogICAgICAg"
    "ICAgICAgICAgZm9yIG4sIGlkeCBpbiBlbnVtZXJhdGUoaWR4cywgc3RhcnQ9MSk6CiAgICAgICAgICAgICAgICAgICAgciA9"
    "IFJFU1VMVFNbaWR4XQogICAgICAgICAgICAgICAgICAgIGV2c2hlZXQud3JpdGUocm93X2N1cnNvciwgMCwKICAgICAgICAg"
    "ICAgICAgICAgICAgICAgZiJJbWFnZSB7bn06IHtyWydyZXN1bHQnXX0gIHwgIHtyWyd1cmwnXX0gKHtyWyd1cmxfcm9sZSdd"
    "fSkiLCBjYXB0aW9uX2ZtdCkKICAgICAgICAgICAgICAgICAgICByb3dfY3Vyc29yICs9IDEKICAgICAgICAgICAgICAgICAg"
    "ICBpbWdfc3RyZWFtID0gaW8uQnl0ZXNJTyhpbWFnZV9ieXRlc1tpZHhdKQogICAgICAgICAgICAgICAgICAgIGV2c2hlZXQu"
    "aW5zZXJ0X2ltYWdlKHJvd19jdXJzb3IsIDAsIGYie2NpZH1fe259LnBuZyIsCiAgICAgICAgICAgICAgICAgICAgICAgICAg"
    "ICAgICAgICAgICAgICAgIHsiaW1hZ2VfZGF0YSI6IGltZ19zdHJlYW0sICJ4X3NjYWxlIjogMC41NSwgInlfc2NhbGUiOiAw"
    "LjU1fSkKICAgICAgICAgICAgICAgICAgICByb3dfY3Vyc29yICs9IDIwICAjIHJvdWdobHkgdGhlIHNjYWxlZCBpbWFnZSBo"
    "ZWlnaHQgaW4gZGVmYXVsdC1zaXplIHJvd3MKICAgICAgICAgICAgICAgIHJvd19jdXJzb3IgKz0gMQoKICAgIHJldHVybiBU"
    "cnVlCgoKIyBUaGUgMyBjaGVja2xpc3QgaXRlbXMgY2hlY2tfYWNjZXNzX2NvbnRyb2xfMmZhKCkgY2FuIHR1cm4gZnJvbSBN"
    "QU5VQUwKIyBpbnRvIGEgcmVhbCBQQVNTL0ZBSUwgcmVzdWx0LCBhbmQgaG93IG1hbnkgZGlzdGluY3QgYWNjb3VudHMgZWFj"
    "aCBuZWVkcy4KIyBVc2VkIGJ5IGJvdGggY292ZXJhZ2UtcmVwb3J0IGZ1bmN0aW9ucyBiZWxvdyBzbyB0aGUgdHdvIHN0YXkg"
    "aW4gc3luYy4KQVVUSF9HQVRFRF9JRFMgPSBbCiAgICAoIldBLU9URy0zMTIiLCAiQXV0aG9yaXphdGlvbiBUZXN0aW5nIiwg"
    "IlRlc3QgYnlwYXNzaW5nIGF1dGhvcml6YXRpb24gc2NoZW1hIChmb3JjZSBicm93c2UpIiwgMSksCiAgICAoIldBLVNTLTA3"
    "MSIsICJBY2Nlc3MgQ29udHJvbCIsICJIb3Jpem9udGFsIHByaXZpbGVnZSBlc2NhbGF0aW9uIChhY2Nlc3MgYW5vdGhlciB1"
    "c2VyIGRhdGEpIiwgMiksCiAgICAoIldBLU9URy0zMTQiLCAiQXV0aG9yaXphdGlvbiBUZXN0aW5nIiwgIlRlc3QgaW5zZWN1"
    "cmUgZGlyZWN0IG9iamVjdCByZWZlcmVuY2VzIChJRE9SKSIsIDIpLApdCgoKZGVmIHByaW50X2F1dGhfY292ZXJhZ2VfcGxh"
    "bihhcmdzKToKICAgICIiIlByaW50ZWQgb25jZSwgcmlnaHQgYmVmb3JlIHNjYW5uaW5nIHN0YXJ0cyAtIHRlbGxzIHlvdSB1"
    "cGZyb250CiAgICBleGFjdGx5IHdoYXQgLS1jb29raWUvLS1jb29raWUyIHdpbGwgYW5kIHdvbid0IGNvdmVyLCBzbyB5b3Ug"
    "a25vdwogICAgd2hldGhlciB5b3UgbmVlZCBhIHNlY29uZCBzZXNzaW9uIGJlZm9yZSB0aGUgcnVuIGV2ZW4gYmVnaW5zLiBU"
    "aGlzIGlzCiAgICB0aGUgJ2F1dG8gY2hlY2snIGJlaGF2aW9yOiBvbmUgY29va2llIGlzIGVub3VnaCB0byBhdXRoZW50aWNh"
    "dGUgdGhlCiAgICBFTlRJUkUgc3VpdGUgKGV2ZXJ5IGNoZWNrLCBub3QganVzdCB0aGUgMyBiZWxvdykgcGx1cyBXQS1PVEct"
    "MzEyOwogICAgYWRkaW5nIGEgc2Vjb25kIGNvb2tpZSBpcyBvbmx5IG5lZWRlZCBmb3IgdGhlIHR3byBjaGVja3MgdGhhdAog"
    "ICAgc3BlY2lmaWNhbGx5IHJlcXVpcmUgY29tcGFyaW5nIHR3byBkaWZmZXJlbnQgYWNjb3VudHMgYWdhaW5zdCBlYWNoCiAg"
    "ICBvdGhlci4iIiIKICAgIGhhdmUxID0gYm9vbChhcmdzLmNvb2tpZSBvciBhcmdzLmFjY291bnQxX2Nvb2tpZSkKICAgIGhh"
    "dmUyID0gYm9vbChhcmdzLmNvb2tpZTIgb3IgYXJncy5hY2NvdW50Ml9jb29raWUpCiAgICBwcmludCgpCiAgICBpZiBub3Qg"
    "aGF2ZTE6CiAgICAgICAgcHJpbnQoIlsqXSBObyAtLWNvb2tpZSBnaXZlbiAtIGV2ZXJ5IGNoZWNrIHJ1bnMgdW5hdXRoZW50"
    "aWNhdGVkLiBBZGQgLS1jb29raWUgXCJzZXNzaW9uaWQ9Li4uXCIgdG8gdGVzdCAiCiAgICAgICAgICAgICAgImV2ZXJ5dGhp"
    "bmcgYXMgYSBsb2dnZWQtaW4gc2Vzc2lvbiBzZWVzIGl0IChyZWNvbW1lbmRlZCBmb3IgbW9zdCBlbmdhZ2VtZW50cykuIikK"
    "ICAgICAgICByZXR1cm4KICAgIHByaW50KCJbKl0gLS1jb29raWUgZ2l2ZW4gLSBBTEwgfjEwMCBjaGVja3MgaW4gdGhpcyBz"
    "dWl0ZSAoaGVhZGVycywgVExTLCBjb29raWVzLCBDT1JTLCBpbmZvcm1hdGlvbiIpCiAgICBwcmludCgiICAgIGdhdGhlcmlu"
    "ZywgZXRjLikgcnVuIGFzIHRoYXQgYXV0aGVudGljYXRlZCBzZXNzaW9uLCBwbHVzIHJlYWwgKG5vbi1NQU5VQUwpIHRlc3Rp"
    "bmcgZm9yOiIpCiAgICBwcmludCgiICAgICAgV0EtT1RHLTMxMiAgVGVzdCBieXBhc3NpbmcgYXV0aG9yaXphdGlvbiBzY2hl"
    "bWEgKGZvcmNlIGJyb3dzZSkiKQogICAgaWYgaGF2ZTI6CiAgICAgICAgcHJpbnQoIlsqXSAtLWNvb2tpZTIgYWxzbyBnaXZl"
    "biAtIHRoZXNlIEFMU08gZ2V0IHJlYWwgdGVzdGluZywgY29tcGFyaW5nIGFjY291bnQgMSB2cyBhY2NvdW50IDI6IikKICAg"
    "ICAgICBwcmludCgiICAgICAgV0EtU1MtMDcxICAgSG9yaXpvbnRhbCBwcml2aWxlZ2UgZXNjYWxhdGlvbiAoYWNjZXNzIGFu"
    "b3RoZXIgdXNlciBkYXRhKSIpCiAgICAgICAgcHJpbnQoIiAgICAgIFdBLU9URy0zMTQgIFRlc3QgaW5zZWN1cmUgZGlyZWN0"
    "IG9iamVjdCByZWZlcmVuY2VzIChJRE9SKSIpCiAgICBlbHNlOgogICAgICAgIHByaW50KCJbKl0gTm8gLS1jb29raWUyIC0g"
    "dGhlc2Ugc3RheSBNQU5VQUwgKG5lZWQgYSBTRUNPTkQsIGRpZmZlcmVudCBhY2NvdW50J3Mgc2Vzc2lvbiB0byBjb21wYXJl"
    "IikKICAgICAgICBwcmludCgiICAgIGFnYWluc3QgdGhlIGZpcnN0KTogV0EtU1MtMDcxLCBXQS1PVEctMzE0LiBBZGQgLS1j"
    "b29raWUyIFwic2Vzc2lvbmlkPS4uLlwiIHRvIGNvdmVyIHRoZW0gdG9vLiIpCiAgICBwcmludCgpCgoKIyBUaGVzZSBhcmUg"
    "bGl0ZXJhbCBwcmVmaXhlcyBvZiB0aGUgdHdvICJ3ZSBuZXZlciBldmVuIHRyaWVkIiBNQU5VQUwKIyBldmlkZW5jZSBzdHJp"
    "bmdzIGNoZWNrX2FjY2Vzc19jb250cm9sXzJmYSgpIHdyaXRlcyB3aGVuIGEgY29va2llIGlzCiMgbWlzc2luZyAoc2VlIHRo"
    "YXQgZnVuY3Rpb24pLiBNYXRjaGluZyBvbiB0aGVzZSAtIG5vdCBqdXN0IHJlc3VsdCA9PQojICJNQU5VQUwiIC0gaXMgd2hh"
    "dCBsZXRzIHByaW50X2F1dGhfY292ZXJhZ2VfYWN0dWFsKCkgdGVsbCAic2tpcHBlZCwKIyBubyBjb29raWUiIGFwYXJ0IGZy"
    "b20gInJhbiBmb3IgcmVhbCwgYnV0IHRoZSBvdXRjb21lIGl0c2VsZiBuZWVkcyBhCiMgaHVtYW4ganVkZ21lbnQgY2FsbCIg"
    "KGUuZy4gdHdvIGFjY291bnRzIHNhdyBieXRlLWlkZW50aWNhbCBjb250ZW50IC0KIyB0aGF0J3MgTUFOVUFMIGJ5IGRlc2ln"
    "biBldmVuIHdoZW4gYm90aCBjb29raWVzIFdFUkUgcHJvdmlkZWQgYW5kIHRoZQojIGNvbXBhcmlzb24gZ2VudWluZWx5IHJh"
    "bikuIEtlZXAgdGhlc2UgaW4gc3luYyBpZiB0aGF0IGV2aWRlbmNlIHdvcmRpbmcKIyBldmVyIGNoYW5nZXMuCl9BVVRIX1NL"
    "SVBfTk9fU0VTU0lPTiA9ICJNYW51YWwgdGVzdCByZXF1aXJlZC4gTmVlZHMgYW4gYXV0aGVudGljYXRlZCBzZXNzaW9uIHRv"
    "IHRlc3QiCl9BVVRIX1NLSVBfTk9fU0VDT05EX0FDQ09VTlQgPSAiTWFudWFsIHRlc3QgcmVxdWlyZWQuIE5lZWRzIGEgU0VD"
    "T05EIGFjY291bnQncyBzZXNzaW9uIHRvbyIKCgpkZWYgcHJpbnRfYXV0aF9jb3ZlcmFnZV9hY3R1YWwoKToKICAgICIiIlBy"
    "aW50ZWQgYWZ0ZXIgc2Nhbm5pbmcsIGFzIHBhcnQgb2YgcHJpbnRfc3VtbWFyeSgpIC0gZ3JvdW5kLXRydXRoCiAgICBjb25m"
    "aXJtYXRpb24gb2Ygd2hhdCBhY3R1YWxseSBnb3QgcmVjb3JkZWQgYXMgYSByZWFsLCBhdXRvbWF0ZWQKICAgIGNvbXBhcmlz"
    "b24gdnMgd2FzIHNraXBwZWQgb3V0cmlnaHQgZm9yIGxhY2sgb2YgYSBjb29raWUsIHJlYWQgc3RyYWlnaHQKICAgIGZyb20g"
    "UkVTVUxUUyByYXRoZXIgdGhhbiBqdXN0IGludGVudCBmcm9tIHRoZSBmbGFncy4gQSBNQU5VQUwgcmVzdWx0CiAgICBoZXJl"
    "IGNhbiBtZWFuIHR3byBkaWZmZXJlbnQgdGhpbmdzIGFuZCB0aGlzIHJlcG9ydHMgdGhlbSBzZXBhcmF0ZWx5OgogICAgKGEp"
    "IHRoZSBjaGVjayBuZXZlciByYW4gYXQgYWxsIGJlY2F1c2Ugbm8gY29va2llIHdhcyBnaXZlbiwgb3IgKGIpIGl0CiAgICBE"
    "SUQgcnVuIC0gYm90aCBhY2NvdW50cyB3ZXJlIGFjdHVhbGx5IGNvbXBhcmVkIC0gYnV0IHRoZSBvdXRjb21lCiAgICBpdHNl"
    "bGYgbmVlZHMgYSBodW1hbiBqdWRnbWVudCBjYWxsIChlLmcuIGlkZW50aWNhbCBjb250ZW50IGJldHdlZW4KICAgIHR3byBh"
    "Y2NvdW50cywgd2hpY2ggaXMgcmVwb3J0ZWQgTUFOVUFMIGJ5IGRlc2lnbiwgbm90IHNraXBwZWQpLiIiIgogICAgYnlfaWQg"
    "PSB7fQogICAgZm9yIHIgaW4gUkVTVUxUUzoKICAgICAgICBieV9pZC5zZXRkZWZhdWx0KHJbImlkIl0sIFtdKS5hcHBlbmQo"
    "cikKICAgIGlmIG5vdCBhbnkoY2lkIGluIGJ5X2lkIGZvciBjaWQsICpfIGluIEFVVEhfR0FURURfSURTKToKICAgICAgICBy"
    "ZXR1cm4KICAgIHByaW50KCItIiAqIDcwKQogICAgcHJpbnQoIkFDQ0VTUyBDT05UUk9MIC8gQVVUSCBDT1ZFUkFHRSAtIHdo"
    "YXQgYWN0dWFsbHkgcmFuIGF1dGhlbnRpY2F0ZWQ6IikKICAgIGZvciBjaWQsIGNhdCwgbmFtZSwgYWNjb3VudHNfbmVlZGVk"
    "IGluIEFVVEhfR0FURURfSURTOgogICAgICAgIHJvd3MgPSBieV9pZC5nZXQoY2lkKQogICAgICAgIGlmIG5vdCByb3dzOgog"
    "ICAgICAgICAgICBjb250aW51ZQogICAgICAgIHJhbiA9IHNraXBwZWQgPSBlcnJvciA9IDAKICAgICAgICBmb3IgciBpbiBy"
    "b3dzOgogICAgICAgICAgICByZXMsIGV2ID0gclsicmVzdWx0Il0sIHIuZ2V0KCJldmlkZW5jZSIpIG9yICIiCiAgICAgICAg"
    "ICAgIGlmIHJlcyA9PSAiRVJST1IiOgogICAgICAgICAgICAgICAgZXJyb3IgKz0gMQogICAgICAgICAgICBlbGlmIHJlcyA9"
    "PSAiTUFOVUFMIiBhbmQgKGV2LnN0YXJ0c3dpdGgoX0FVVEhfU0tJUF9OT19TRVNTSU9OKSBvciBldi5zdGFydHN3aXRoKF9B"
    "VVRIX1NLSVBfTk9fU0VDT05EX0FDQ09VTlQpKToKICAgICAgICAgICAgICAgIHNraXBwZWQgKz0gMQogICAgICAgICAgICBl"
    "bHNlOgogICAgICAgICAgICAgICAgIyBQQVNTLCBGQUlMLCBvciBhIE1BTlVBTCB0aGF0IHJhbiBmb3IgcmVhbCAoaHVtYW4g"
    "anVkZ21lbnQKICAgICAgICAgICAgICAgICMgbmVlZGVkIG9uIHRoZSBvdXRjb21lLCBub3QgYSBza2lwKS4KICAgICAgICAg"
    "ICAgICAgIHJhbiArPSAxCiAgICAgICAgcGFydHMgPSBbXQogICAgICAgIGlmIHJhbjoKICAgICAgICAgICAgcGFydHMuYXBw"
    "ZW5kKGYie3Jhbn0gdGVzdGVkIGZvciByZWFsIikKICAgICAgICBpZiBza2lwcGVkOgogICAgICAgICAgICBuZWVkID0gImEg"
    "Mm5kIGFjY291bnQncyBjb29raWUgKC0tY29va2llMikiIGlmIGFjY291bnRzX25lZWRlZCA9PSAyIGVsc2UgImEgc2Vzc2lv"
    "biBjb29raWUgKC0tY29va2llKSIKICAgICAgICAgICAgcGFydHMuYXBwZW5kKGYie3NraXBwZWR9IFNLSVBQRUQgLSBuZWVk"
    "cyB7bmVlZH0iKQogICAgICAgIGlmIGVycm9yOgogICAgICAgICAgICBwYXJ0cy5hcHBlbmQoZiJ7ZXJyb3J9IEVSUk9SIChy"
    "ZXF1ZXN0IGZhaWxlZCAtIGNoZWNrIC0taW5zZWN1cmUvdGFyZ2V0IHJlYWNoYWJpbGl0eS9jb29raWUgdmFsaWRpdHkpIikK"
    "ICAgICAgICBwcmludChmIiAge2NpZDoxMnN9IHtuYW1lfTogeycsICcuam9pbihwYXJ0cyl9IikKICAgIHByaW50KCItIiAq"
    "IDcwKQoKCmRlZiBwcmludF9zc2xfdmVyaWZ5X3N1bW1hcnlfY2FsbG91dCgpOgogICAgIiIiT25lIHRvcC1vZi1zdW1tYXJ5"
    "IG5vdGUgd2hlbiBUTFMgY2VydGlmaWNhdGUtY2hhaW4gdmVyaWZpY2F0aW9uCiAgICBmYWlsdXJlcyAocmF3X3JlcXVlc3Qo"
    "KSdzIHNzbC5TU0xDZXJ0VmVyaWZpY2F0aW9uRXJyb3IgaGFuZGxlcikgYWZmZWN0ZWQKICAgIG9uZSBvciBtb3JlIHJvd3Mg"
    "LSBzbyB0aGlzIGRvZXNuJ3Qgb25seSBzaG93IHVwIHNjYXR0ZXJlZCBpbnNpZGUKICAgIGluZGl2aWR1YWwgcm93cycgZXZp"
    "ZGVuY2UgdGV4dCwgd2hpY2ggaXMgZWFzeSB0byBtaXNzIHdoZW4gc2Nhbm5pbmcKICAgIG1hbnkgVVJMcy4gU2VlIF9TU0xf"
    "VkVSSUZZX0hJTlRfTUFSS0VSLiIiIgogICAgYWZmZWN0ZWRfaWRzID0gc2V0KCkKICAgIGFmZmVjdGVkX3Jvd3MgPSAwCiAg"
    "ICBmb3IgciBpbiBSRVNVTFRTOgogICAgICAgIGV2ID0gci5nZXQoImV2aWRlbmNlIikgb3IgIiIKICAgICAgICBpZiBfU1NM"
    "X1ZFUklGWV9ISU5UX01BUktFUiBpbiBldjoKICAgICAgICAgICAgYWZmZWN0ZWRfcm93cyArPSAxCiAgICAgICAgICAgIGFm"
    "ZmVjdGVkX2lkcy5hZGQoclsiaWQiXSkKICAgIGlmIG5vdCBhZmZlY3RlZF9yb3dzOgogICAgICAgIHJldHVybgogICAgcHJp"
    "bnQoIi0iICogNzApCiAgICBwcmludChmIlRMUyBDRVJUSUZJQ0FURSBWRVJJRklDQVRJT04gRkFJTEVEIG9uIHthZmZlY3Rl"
    "ZF9yb3dzfSByb3cocykgYWNyb3NzIHtsZW4oYWZmZWN0ZWRfaWRzKX0gIgogICAgICAgICAgZiJjaGVja2xpc3QgSUQocykg"
    "LSBldmVyeSBjaGVjayB0aGF0IG5lZWRlZCBhbiBIVFRQUyByZXF1ZXN0IHRvIHRoaXMgdGFyZ2V0IGdvdCBhbiBTU0wgY2Vy"
    "dC12ZXJpZnkiKQogICAgcHJpbnQoImVycm9yIGluc3RlYWQgb2YgYSByZWFsIHJlc3VsdCBmb3IgdGhhdCByZXF1ZXN0IChz"
    "ZWUgdGhvc2Ugcm93cycgZXZpZGVuY2UgZm9yIHRoZSBleGFjdCByZWFzb24pLiIpCiAgICBwcmludCgiSWYgdGhpcyBpcyBh"
    "biBleHBlY3RlZCBzZWxmLXNpZ25lZC9pbnRlcm5hbC9VQVQgY2VydGlmaWNhdGUsIHJlLXJ1biB3aXRoIC0taW5zZWN1cmUg"
    "dG8gc2tpcCIpCiAgICBwcmludCgidmVyaWZpY2F0aW9uIGFuZCBnZXQgcmVhbCByZXN1bHRzOyBpZiB5b3UgZXhwZWN0ZWQg"
    "YSB0cnVzdGVkIGNlcnRpZmljYXRlLCB0aGlzIGlzIGl0c2VsZiBhIikKICAgIHByaW50KCJsZWdpdGltYXRlIGZpbmRpbmcg"
    "KFdBLVRMUy00MDctc3R5bGUgY2hhaW4gaXNzdWUpIHdvcnRoIHJlcG9ydGluZyBhcy1pcy4iKQogICAgcHJpbnQoIi0iICog"
    "NzApCgoKZGVmIHByaW50X3N1bW1hcnkoeGxzeF9vayk6CiAgICBjb3VudHMgPSB7fQogICAgZm9yIHIgaW4gUkVTVUxUUzoK"
    "ICAgICAgICBjb3VudHNbclsicmVzdWx0Il1dID0gY291bnRzLmdldChyWyJyZXN1bHQiXSwgMCkgKyAxCiAgICB0b3RhbCA9"
    "IGxlbihSRVNVTFRTKQogICAgcHJpbnQoIlxuIiArICI9IiAqIDcwKQogICAgcHJpbnQoZiJTVU1NQVJZIC0ge3RvdGFsfSBj"
    "aGVja2xpc3Qgcm93cyBwcm9kdWNlZCBhY3Jvc3MgIgogICAgICAgICAgZiJ7bGVuKHNldChyWydzb3VyY2VfaW5wdXQnXSBm"
    "b3IgciBpbiBSRVNVTFRTKSl9IGlucHV0IFVSTChzKSAiCiAgICAgICAgICBmIih7bGVuKHNldCgoclsndXJsJ10sIHJbJ3Vy"
    "bF9yb2xlJ10pIGZvciByIGluIFJFU1VMVFMpKX0gVVJMK3JvbGUgcGFzc2VzKSIpCiAgICBmb3IgayBpbiBbIkZBSUwiLCAi"
    "UEFTUyIsICJNQU5VQUwiLCAiSU5GTyIsICJFUlJPUiJdOgogICAgICAgIGlmIGsgaW4gY291bnRzOgogICAgICAgICAgICBw"
    "cmludChmIiAge2s6OHN9OiB7Y291bnRzW2tdfSIpCiAgICBzY3JlZW5zaG90X2NvdW50ID0gc3VtKDEgZm9yIHIgaW4gUkVT"
    "VUxUUyBpZiByLmdldCgiZXZpZGVuY2VfaW1hZ2VfYmFzZTY0IikpCiAgICBpZiBzY3JlZW5zaG90X2NvdW50OgogICAgICAg"
    "IHByaW50KGYiICBTY3JlZW5zaG90cyBnZW5lcmF0ZWQ6IHtzY3JlZW5zaG90X2NvdW50fSIpCiAgICBwcmludF9hdXRoX2Nv"
    "dmVyYWdlX2FjdHVhbCgpCiAgICBwcmludF9zc2xfdmVyaWZ5X3N1bW1hcnlfY2FsbG91dCgpCiAgICBwcmludCgiLSIgKiA3"
    "MCkKICAgIHByaW50KCJUaGlzIGNvdmVycyAxMyBjaGVja2xpc3QgY2F0ZWdvcmllcyAofjc3IG9mIHRoZSB+NDIxIHRvdGFs"
    "IG1hc3Rlci1jaGVja2xpc3QiKQogICAgcHJpbnQoIml0ZW1zKSB0aGF0IGFyZSBzYWZlbHksIG5vbi1kZXN0cnVjdGl2ZWx5"
    "IHRlc3RhYmxlIGJ5IHNjcmlwdDogSFRUUCBTZWN1cml0eSIpCiAgICBwcmludCgiSGVhZGVycywgU1NML1RMUyAocGFydGlh"
    "bCAtIHJlYWwgZ3JhZGUvY2lwaGVyLWNoZWNrIHZpYSBubWFwL3NzbHl6ZS9zc2xzY2FuLyIpCiAgICBwcmludCgidGVzdHNz"
    "bC5zaCBpZiBpbnN0YWxsZWQpLCBDbGlja2phY2tpbmcgKHBhcnRpYWwpLCBDT1JTLCBJbmZvcm1hdGlvbiBHYXRoZXJpbmci"
    "KQogICAgcHJpbnQoIihwYXJ0aWFsKSwgQ29uZmlndXJhdGlvbiBUZXN0aW5nIChwYXJ0aWFsKSwgU2Vzc2lvbiBNYW5hZ2Vt"
    "ZW50IChwYXJ0aWFsKSwiKQogICAgcHJpbnQoIkNsaWVudC1TaWRlIFRlc3RpbmcgKGxvY2FsL3Nlc3Npb24gc3RvcmFnZSBo"
    "ZXVyaXN0aWMpLCBFbWFpbCBTZWN1cml0eSwiKQogICAgcHJpbnQoIkluZm9ybWF0aW9uIERpc2Nsb3N1cmUsIEhUVFAgSG9z"
    "dCBIZWFkZXIgQXR0YWNrcyAoYmFzaWMgcHJvYmUpLCBhbmQgQWNjZXNzIikKICAgIHByaW50KCJDb250cm9sIC8gQXV0aG9y"
    "aXphdGlvbiBUZXN0aW5nIChmb3JjZS1icm93c2UvSURPUi9ob3Jpem9udGFsLWVzY2FsYXRpb24gLSIpCiAgICBwcmludCgi"
    "b25seSBydW5zIGZvciByZWFsIHdoZW4gLS1jb29raWUvLS1jb29raWUyIChvciAtLWFjY291bnQxLWNvb2tpZS8tLWFjY291"
    "bnQyLSIpCiAgICBwcmludCgiY29va2llKSBhcmUgZ2l2ZW4sIG90aGVyd2lzZSBNQU5VQUwpLiBFdmVyeXRoaW5nIGVsc2Ug"
    "aW4gdGhlIG1hc3RlciBjaGVja2xpc3QgLSBTUUwgSW5qZWN0aW9uLCIpCiAgICBwcmludCgiWFNTLCBCdXNpbmVzcyBMb2dp"
    "YywgUmFjZSBDb25kaXRpb25zLCBldGMuIC0gc3RpbGwgbmVlZHMgdGhlIHRvb2wgbmFtZWQgaW4iKQogICAgcHJpbnQoInRo"
    "YXQgaXRlbSdzICdUb29scycgY29sdW1uIChzcWxtYXAsIEJ1cnAsIG51Y2xlaSwgLi4uKSBvciBtYW51YWwgdGVzdGluZzsi"
    "KQogICAgcHJpbnQoImV2ZXJ5IHJvdyBhYm92ZSB3aXRoIHJlc3VsdD1NQU5VQUwgc3RhcnRzIHdpdGggdGhlIGZpeGVkIHBo"
    "cmFzZSAnTWFudWFsIHRlc3QiKQogICAgcHJpbnQoInJlcXVpcmVkLicgc28geW91IGNhbiBmaWx0ZXIvc2VhcmNoIGZvciBp"
    "dCBkaXJlY3RseS4iKQogICAgaWYgbm90IHhsc3hfb2s6CiAgICAgICAgcHJpbnQoIi0iICogNzApCiAgICAgICAgcHJpbnQo"
    "Ik5PVEU6IC54bHN4IHdhcyBOT1Qgd3JpdHRlbiB0aGlzIHJ1biAoc2VlIG1lc3NhZ2UgYWJvdmUpIC0gLmNzdi8uanNvbiBh"
    "cmUgY29tcGxldGUuIikKICAgIHByaW50KCI9IiAqIDcwKQoKCmRlZiBtYWluKCk6CiAgICBhcCA9IGFyZ3BhcnNlLkFyZ3Vt"
    "ZW50UGFyc2VyKGRlc2NyaXB0aW9uPSJBdXRvbWF0ZWQgcHJlLWNoZWNrIHNjYW5uZXIgZm9yIHRoZSBXUFQgbWFzdGVyIGNo"
    "ZWNrbGlzdCAoc2VlIG1vZHVsZSBkb2NzdHJpbmcpLiIsCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBmb3Jt"
    "YXR0ZXJfY2xhc3M9YXJncGFyc2UuUmF3RGVzY3JpcHRpb25IZWxwRm9ybWF0dGVyLAogICAgICAgICAgICAgICAgICAgICAg"
    "ICAgICAgICAgICAgZXBpbG9nPV9fZG9jX18pCiAgICBzcmMgPSBhcC5hZGRfbXV0dWFsbHlfZXhjbHVzaXZlX2dyb3VwKHJl"
    "cXVpcmVkPVRydWUpCiAgICBzcmMuYWRkX2FyZ3VtZW50KCItLXVybCIsIGhlbHA9IlNpbmdsZSB0YXJnZXQgVVJMIHRvIHRl"
    "c3QiKQogICAgc3JjLmFkZF9hcmd1bWVudCgiLS11cmwtZmlsZSIsIGhlbHA9IlBhdGggdG8gYSB0ZXh0IGZpbGUgd2l0aCBv"
    "bmUgVVJMIHBlciBsaW5lICgjIGNvbW1lbnRzL2JsYW5rIGxpbmVzIGlnbm9yZWQpIC0gZXZlcnkgVVJMIGluIGl0IGlzIHRl"
    "c3RlZCIpCiAgICBhcC5hZGRfYXJndW1lbnQoIi0tb3V0IiwgaGVscD0iT3V0cHV0IGJhc2UgZmlsZW5hbWUsIFdJVEhPVVQg"
    "ZXh0ZW5zaW9uIC0gd3JpdGVzIDxvdXQ+LmNzdiwgPG91dD4uanNvbiBhbmQgPG91dD4ueGxzeC4gRGVmYXVsdDogY2hlY2ts"
    "aXN0X3NjYW5fPHRpbWVzdGFtcD4iKQogICAgYXAuYWRkX2FyZ3VtZW50KCItLXRpbWVvdXQiLCB0eXBlPWZsb2F0LCBkZWZh"
    "dWx0PTEwLCBoZWxwPSJQZXItcmVxdWVzdCB0aW1lb3V0IGluIHNlY29uZHMgKGRlZmF1bHQ6IDEwKSIpCiAgICBhcC5hZGRf"
    "YXJndW1lbnQoIi0taW5zZWN1cmUiLCBhY3Rpb249InN0b3JlX3RydWUiLCBoZWxwPSJEb24ndCB2ZXJpZnkgVExTIGNlcnRp"
    "ZmljYXRlcyAoc2VsZi1zaWduZWQvaW50ZXJuYWwgbGFiIHRhcmdldHMpIikKICAgIGFwLmFkZF9hcmd1bWVudCgiLS1za2lw"
    "LXJvb3QtcGFzcyIsIGFjdGlvbj0ic3RvcmVfdHJ1ZSIsCiAgICAgICAgICAgICAgICAgICAgIGhlbHA9Ik9ubHkgdGVzdCB0"
    "aGUgZXhhY3QgVVJMIGdpdmVuIC0gc2tpcCB0aGUgYXV0b21hdGljIGV4dHJhIHBhc3MgYWdhaW5zdCB0aGF0IGhvc3QncyBz"
    "aXRlIHJvb3QuIERlZmF1bHQ6IE9GRiAoYm90aCBhcmUgdGVzdGVkKSIpCiAgICBhcC5hZGRfYXJndW1lbnQoIi0tcG9ydC1z"
    "Y2FuIiwgYWN0aW9uPSJzdG9yZV90cnVlIiwgaGVscD0iQWxzbyBydW4gdGhlIGxpZ2h0IGNvbW1vbi1hZG1pbi1wb3J0IHNj"
    "YW4gKFdBLU9URy0yODMpLiBPZmYgYnkgZGVmYXVsdCAtIG5vaXNpZXIuIikKICAgIGFwLmFkZF9hcmd1bWVudCgiLS1ka2lt"
    "LXNlbGVjdG9yIiwgYWN0aW9uPSJhcHBlbmQiLCBoZWxwPSJFeHRyYSBES0lNIHNlbGVjdG9yIHRvIHRyeSAocmVwZWF0YWJs"
    "ZSksIGluIGFkZGl0aW9uIHRvIHRoZSBidWlsdC1pbiBjb21tb24gbGlzdCIpCiAgICBhcC5hZGRfYXJndW1lbnQoIi0tZGVs"
    "YXkiLCB0eXBlPWZsb2F0LCBkZWZhdWx0PTAsIGhlbHA9IkRlbGF5IGluIHNlY29uZHMgYmV0d2VlbiBlYWNoIFVSTCtyb2xl"
    "IHBhc3MgKGRlZmF1bHQ6IDApIikKICAgIGFwLmFkZF9hcmd1bWVudCgiLS1zY3JlZW5zaG90IiwgY2hvaWNlcz1bIm5vbmUi"
    "LCAiZmFpbCIsICJmYWlsK3Bhc3MiLCAiYWxsIl0sIGRlZmF1bHQ9ImZhaWwiLAogICAgICAgICAgICAgICAgICAgICBoZWxw"
    "PSJXaGljaCByb3dzIGdldCBhbiBhdXRvLWdlbmVyYXRlZCBldmlkZW5jZSBzY3JlZW5zaG90IChuZWVkcyBQaWxsb3cpLiBE"
    "ZWZhdWx0OiBmYWlsIikKICAgIGFwLmFkZF9hcmd1bWVudCgiLS1uby1jbGktdG9vbHMiLCBhY3Rpb249InN0b3JlX3RydWUi"
    "LAogICAgICAgICAgICAgICAgICAgICBoZWxwPSJEb24ndCBzaGVsbCBvdXQgdG8gY3VybC9ubWFwL3NzbHl6ZS9zc2xzY2Fu"
    "L3Rlc3Rzc2wuc2ggZXZlbiBpZiBpbnN0YWxsZWQgLSAiCiAgICAgICAgICAgICAgICAgICAgICAgICAgInVzZSB0aGUgcHVy"
    "ZS1QeXRob24vTUFOVUFMIGZhbGxiYWNrIGJlaGF2aW91ciBvbmx5IikKICAgIGFwLmFkZF9hcmd1bWVudCgiLS1hY2NvdW50"
    "MS1jb29raWUiLCBoZWxwPSJTZXNzaW9uIENvb2tpZSBoZWFkZXIgdmFsdWUgZm9yIGFjY291bnQgMSwgZS5nLiBcInNlc3Np"
    "b25pZD1hYmMxMjNcIiAtICIKICAgICAgICAgICAgICAgICAgICAgIllPVVIgT1dOIGFscmVhZHktYXV0aGVudGljYXRlZCBz"
    "ZXNzaW9uLCBuZXZlciBoYXJ2ZXN0ZWQvZ3Vlc3NlZCBieSB0aGlzIHNjcmlwdC4gRW5hYmxlcyByZWFsICIKICAgICAgICAg"
    "ICAgICAgICAgICAgImF1dGgtYnlwYXNzIHRlc3RpbmcgKFdBLU9URy0zMTIpOyBhZGQgLS1hY2NvdW50Mi1jb29raWUgdG9v"
    "IGZvciBob3Jpem9udGFsLWVzY2FsYXRpb24vSURPUiAiCiAgICAgICAgICAgICAgICAgICAgICJjaGVja3MuIFVzdWFsbHkg"
    "eW91IHdhbnQgLS1jb29raWUgaW5zdGVhZCAoc2VlIGFib3ZlKSAtIGl0IGRvZXMgZXZlcnl0aGluZyB0aGlzIGRvZXMgUExV"
    "UyAiCiAgICAgICAgICAgICAgICAgICAgICJhdXRoZW50aWNhdGVzIGV2ZXJ5IG90aGVyIGNoZWNrIGluIHRoZSBzdWl0ZTsg"
    "dXNlIC0tYWNjb3VudDEtY29va2llIG9ubHkgaWYgeW91IHNwZWNpZmljYWxseSAiCiAgICAgICAgICAgICAgICAgICAgICJ3"
    "YW50IEpVU1QgdGhlIGFjY2Vzcy1jb250cm9sIGNoZWNrcyBhdXRoZW50aWNhdGVkIGFuZCBldmVyeXRoaW5nIGVsc2UgcnVu"
    "IGFub255bW91c2x5LiIpCiAgICBhcC5hZGRfYXJndW1lbnQoIi0tYWNjb3VudDEtbGFiZWwiLCBoZWxwPSJEaXNwbGF5IGxh"
    "YmVsIGZvciBhY2NvdW50IDEgaW4gZXZpZGVuY2UgdGV4dCAoZGVmYXVsdDogJ0FjY291bnQgMScpIikKICAgIGFwLmFkZF9h"
    "cmd1bWVudCgiLS1hY2NvdW50Mi1jb29raWUiLCBoZWxwPSJTZXNzaW9uIENvb2tpZSBoZWFkZXIgdmFsdWUgZm9yIGFjY291"
    "bnQgMiAtIGEgU0VDT05ELCBESUZGRVJFTlQgIgogICAgICAgICAgICAgICAgICAgICAidXNlcidzIG93biBzZXNzaW9uIC0g"
    "ZW5hYmxlcyB0aGUgdHdvLWFjY291bnQgaG9yaXpvbnRhbC1wcml2aWxlZ2UtZXNjYWxhdGlvbi9JRE9SIGNoZWNrcyAiCiAg"
    "ICAgICAgICAgICAgICAgICAgICIoV0EtU1MtMDcxLCBXQS1PVEctMzE0KS4gVXN1YWxseSB5b3Ugd2FudCAtLWNvb2tpZTIg"
    "aW5zdGVhZCAoc2VlIGFib3ZlKSAtIHNhbWUgZWZmZWN0LCAiCiAgICAgICAgICAgICAgICAgICAgICJuYW1lZCB0byBwYWly"
    "IHdpdGggLS1jb29raWUuIikKICAgIGFwLmFkZF9hcmd1bWVudCgiLS1hY2NvdW50Mi1sYWJlbCIsIGhlbHA9IkRpc3BsYXkg"
    "bGFiZWwgZm9yIGFjY291bnQgMiBpbiBldmlkZW5jZSB0ZXh0IChkZWZhdWx0OiAnQWNjb3VudCAyJykiKQogICAgYXAuYWRk"
    "X2FyZ3VtZW50KCItLWNvb2tpZSIsIGhlbHA9IkNvb2tpZSBoZWFkZXIgdmFsdWUgdG8gc2VuZCB3aXRoIGV2ZXJ5IHJlcXVl"
    "c3QgKHlvdXIgb3duIGFscmVhZHktIgogICAgICAgICAgICAgICAgICAgICAiYXV0aGVudGljYXRlZCBzZXNzaW9uKSwgZS5n"
    "LiBcInNlc3Npb25pZD1hYmMxMjM7IGNzcmZ0b2tlbj14eXpcIi4gQXBwbGllcyB0byBldmVyeSBzaW5nbGUgIgogICAgICAg"
    "ICAgICAgICAgICAgICAiY2hlY2ssIHNvIHJlc3VsdHMgcmVmbGVjdCB3aGF0IGFuIGF1dGhlbnRpY2F0ZWQgdXNlciBzZWVz"
    "IC0gQU5EIGF1dG9tYXRpY2FsbHkgYWxzbyBjb3ZlcnMgIgogICAgICAgICAgICAgICAgICAgICAidGhlIFdBLU9URy0zMTIg"
    "YXV0aC1ieXBhc3MgY2hlY2sgKHNhbWUgYXMgcGFzc2luZyB0aGlzIHNhbWUgdmFsdWUgYXMgLS1hY2NvdW50MS1jb29raWUp"
    "LCBzbyAiCiAgICAgICAgICAgICAgICAgICAgICJ5b3UgZG9uJ3QgbmVlZCB0byBwYXNzIHRoZSBzYW1lIGNvb2tpZSB0d2lj"
    "ZS4gU2VlIHRoZSBjb3ZlcmFnZSByZXBvcnQgcHJpbnRlZCBhdCB0aGUgc3RhcnQgIgogICAgICAgICAgICAgICAgICAgICAi"
    "b2YgZXZlcnkgcnVuIGZvciBleGFjdGx5IHdoYXQgb25lIGNvb2tpZSBkb2VzL2RvZXNuJ3QgY292ZXIuIikKICAgIGFwLmFk"
    "ZF9hcmd1bWVudCgiLS1jb29raWUyIiwgaGVscD0iQSBTRUNPTkQsIERJRkZFUkVOVCBhY2NvdW50J3Mgb3duIENvb2tpZSBo"
    "ZWFkZXIgdmFsdWUsIGUuZy4gIgogICAgICAgICAgICAgICAgICAgICAiXCJzZXNzaW9uaWQ9eHl6Nzg5XCIuIE9ubHkgbWVh"
    "bmluZ2Z1bCB0b2dldGhlciB3aXRoIC0tY29va2llIC0gYXV0b21hdGljYWxseSBleHRlbmRzICIKICAgICAgICAgICAgICAg"
    "ICAgICAgImNvdmVyYWdlIHRvIHRoZSB0d28tYWNjb3VudCBob3Jpem9udGFsLXByaXZpbGVnZS1lc2NhbGF0aW9uL0lET1Ig"
    "Y2hlY2tzIChXQS1TUy0wNzEsICIKICAgICAgICAgICAgICAgICAgICAgIldBLU9URy0zMTQpLCBjb21wYXJpbmcgLS1jb29r"
    "aWUncyBhY2NvdW50IGFnYWluc3QgdGhpcyBvbmUgKHNhbWUgYXMgcGFzc2luZyB0aGlzIHZhbHVlIGFzICIKICAgICAgICAg"
    "ICAgICAgICAgICAgIi0tYWNjb3VudDItY29va2llKS4gTm90IHNlbnQgd2l0aCBldmVyeSByZXF1ZXN0IGxpa2UgLS1jb29r"
    "aWUgaXMgLSBvbmx5IHVzZWQgZm9yIHRoYXQgIgogICAgICAgICAgICAgICAgICAgICAic3BlY2lmaWMgdHdvLWFjY291bnQg"
    "Y29tcGFyaXNvbi4iKQogICAgYXAuYWRkX2FyZ3VtZW50KCItLWhlYWRlciIsIGFjdGlvbj0iYXBwZW5kIiwgbWV0YXZhcj0i"
    "J05hbWU6IFZhbHVlJyIsCiAgICAgICAgICAgICAgICAgICAgIGhlbHA9IkV4dHJhIGhlYWRlciB0byBzZW5kIHdpdGggZXZl"
    "cnkgcmVxdWVzdCAocmVwZWF0YWJsZSksIGUuZy4gLS1oZWFkZXIgXCJBdXRob3JpemF0aW9uOiAiCiAgICAgICAgICAgICAg"
    "ICAgICAgICAgICAgIkJlYXJlciBleUouLi5cIi4gQXBwbGllcyBldmVyeXdoZXJlIC0tY29va2llIGRvZXM7IGEgaGVhZGVy"
    "IG5hbWVkIGhlcmUgYWx3YXlzIHdpbnMgb3ZlciAiCiAgICAgICAgICAgICAgICAgICAgICAgICAgImFuIGlkZW50aWNhbGx5"
    "LW5hbWVkIG9uZSBmcm9tIC0tY29va2llIGlmIHRoZXkgc29tZWhvdyBvdmVybGFwLiIpCiAgICBhcC5hZGRfYXJndW1lbnQo"
    "Ii0tb25seSIsIGFjdGlvbj0iYXBwZW5kIiwgbWV0YXZhcj0iSUQiLAogICAgICAgICAgICAgICAgICAgICBoZWxwPSJSZXN0"
    "cmljdCBvdXRwdXQgdG8ganVzdCB0aGlzIENoZWNrbGlzdCBJRCAocmVwZWF0YWJsZSwgYW5kL29yIGNvbW1hLXNlcGFyYXRl"
    "ZCAtIGUuZy4gIgogICAgICAgICAgICAgICAgICAgICAgICAgICItLW9ubHkgV0EtSERSLTM5MiAtLW9ubHkgV0EtU1MtMDAx"
    "LFdBLVNTLTAwMikuIEV2ZXJ5IGNoZWNrIHN0aWxsIHJ1bnMgKHRoZXkncmUgYWxsIGZhc3QgIgogICAgICAgICAgICAgICAg"
    "ICAgICAgICAgICJIVFRQL1RMUyBwcm9iZXMpLCBidXQgcm93cyBmb3IgYW55IG90aGVyIElEIGFyZSBkcm9wcGVkIGJlZm9y"
    "ZSBiZWluZyB3cml0dGVuIG91dC4gTWVhbnQgIgogICAgICAgICAgICAgICAgICAgICAgICAgICJmb3IgYSAncmVydW4gc2Vs"
    "ZWN0ZWQgcm93cyBvbmx5JyB3b3JrZmxvdyBkcml2ZW4gYnkgYW5vdGhlciB0b29sIChlLmcuIGEgQnVycCBleHRlbnNpb24p"
    "ICIKICAgICAgICAgICAgICAgICAgICAgICAgICAicmF0aGVyIHRoYW4gdHlwaWNhbCBpbnRlcmFjdGl2ZSB1c2UuIikKICAg"
    "IGFwLmFkZF9hcmd1bWVudCgiLS1jcmVkcyIsIGFjdGlvbj0iYXBwZW5kIiwgbWV0YXZhcj0iJ2xhYmVsOjpjb29raWUnIiwK"
    "ICAgICAgICAgICAgICAgICAgICAgaGVscD0iQSBmcmllbmRsaWVyIGFsdGVybmF0aXZlIHRvIC0tY29va2llLy0tY29va2ll"
    "Mi8tLWFjY291bnQxLWxhYmVsLy0tYWNjb3VudDItbGFiZWwsICIKICAgICAgICAgICAgICAgICAgICAgICAgICAicmVwZWF0"
    "YWJsZSB1cCB0byB0d2ljZSAoMXN0ID0gYWNjb3VudCAxLCAybmQgPSBhY2NvdW50IDIpLiBUaGlzIHNjcmlwdCBoYXMgbm8g"
    "bG9naW4gIgogICAgICAgICAgICAgICAgICAgICAgICAgICJmbG93IGF0IGFsbCAoYnkgZGVzaWduKSBhbmQgbmV2ZXIgdXNl"
    "cyBhIHBhc3N3b3JkLCBzbyBSRUNPTU1FTkRFRCBmb3JtYXQgaXMganVzdCAiCiAgICAgICAgICAgICAgICAgICAgICAgICAg"
    "IlwibGFiZWw6OnNlc3Npb25pZD0uLi5cIiAtIG5vIHBhc3N3b3JkIG5lZWRlZCwgZG9uJ3Qgd2FzdGUgdGltZSB0eXBpbmcg"
    "b25lLiBBIGJhcmUgIgogICAgICAgICAgICAgICAgICAgICAgICAgICJjb29raWUgd2l0aCBubyBsYWJlbCBhbHNvIHdvcmtz"
    "OiBcInNlc3Npb25pZD0uLi5cIiBvbiBpdHMgb3duLiAoTGVnYWN5ICIKICAgICAgICAgICAgICAgICAgICAgICAgICAiXCJs"
    "YWJlbDpwYXNzd29yZDo6c2Vzc2lvbmlkPS4uLlwiIGlzIHN0aWxsIGFjY2VwdGVkIGZvciBjb21wYXRpYmlsaXR5IC0gYW55"
    "ICIKICAgICAgICAgICAgICAgICAgICAgICAgICAiXCJwYXNzd29yZFwiIHR5cGVkIHRoZXJlIGlzIHBhcnNlZCBvdXQgYW5k"
    "IGRpc2NhcmRlZCwgTkVWRVIgc3RvcmVkLCBsb2dnZWQsIG9yICIKICAgICAgICAgICAgICAgICAgICAgICAgICAid3JpdHRl"
    "biB0byBldmlkZW5jZS9KU09OL0NTViBhbnl3aGVyZSwgYW5kIG5ldmVyIHVzZWQgdG8gbG9nIGluLikgVGhlIGxhYmVsIGJl"
    "Y29tZXMgIgogICAgICAgICAgICAgICAgICAgICAgICAgICJ0aGF0IGFjY291bnQncyByZWFkYWJsZSBuYW1lIGluIGV2aWRl"
    "bmNlIHRleHQuIE9ubHkgdGhlIHBhcnQgYWZ0ZXIgXCI6OlwiIChvciB0aGUgIgogICAgICAgICAgICAgICAgICAgICAgICAg"
    "ICJ3aG9sZSBlbnRyeSwgZm9yIGEgYmFyZSBjb29raWUpIGlzIHdoYXQgYWN0dWFsbHkgYXV0aGVudGljYXRlcyByZXF1ZXN0"
    "cyAtIGFuIGVudHJ5ICIKICAgICAgICAgICAgICAgICAgICAgICAgICAid2l0aCBubyB1c2FibGUgY29va2llIGlzIHJlcG9y"
    "dGVkIGFzIHNraXBwZWQuIFR3byBjb29raWUgdmFsdWVzIGZvciB0aGUgU0FNRSBhY2NvdW50ICIKICAgICAgICAgICAgICAg"
    "ICAgICAgICAgICAiKGUuZy4gYSBzZXNzaW9uIGNvb2tpZSBwbHVzIGEgc2VwYXJhdGUgQ1NSRi9YU1JGIGNvb2tpZSkgZ28g"
    "b24gb25lIGxpbmUsICIKICAgICAgICAgICAgICAgICAgICAgICAgICAic2VtaWNvbG9uLXNlcGFyYXRlZDogXCJhbGljZTo6"
    "SlNFU1NJT05JRD1hYmMxMjM7IFhTUkYtVE9LRU49ZGVmNDU2XCIuIEV4YW1wbGVzOiAiCiAgICAgICAgICAgICAgICAgICAg"
    "ICAgICAgIi0tY3JlZHMgXCJhbGljZTo6c2Vzc2lvbmlkPWFiYzEyM1wiIC0tY3JlZHMgXCJib2I6OnNlc3Npb25pZD14eXo3"
    "ODlcIiIpCiAgICBhcC5hZGRfYXJndW1lbnQoIi0tY3JlZHMtZmlsZSIsIG1ldGF2YXI9IlBBVEgiLAogICAgICAgICAgICAg"
    "ICAgICAgICBoZWxwPSJTYW1lIGZvcm1hdCBhcyAtLWNyZWRzLCBvbmUgZW50cnkgcGVyIGxpbmUsIHJlYWQgZnJvbSBhIHRl"
    "eHQgZmlsZSBpbnN0ZWFkIG9mIHRoZSAiCiAgICAgICAgICAgICAgICAgICAgICAgICAgImNvbW1hbmQgbGluZSAoIyBjb21t"
    "ZW50cy9ibGFuayBsaW5lcyBpZ25vcmVkKS4gT25lIGxpbmUgPSBvbmUgYWNjb3VudCAoYWNjb3VudCAxICIKICAgICAgICAg"
    "ICAgICAgICAgICAgICAgICAib25seSk7IHR3byBsaW5lcyA9IGFjY291bnQgMSAobGluZSAxKSBhbmQgYWNjb3VudCAyIChs"
    "aW5lIDIpLiBDb21iaW5lIHdpdGggLS1jcmVkcyAiCiAgICAgICAgICAgICAgICAgICAgICAgICAgInRvIGFkZCBtb3JlIGVu"
    "dHJpZXMgb24gdG9wIG9mIHRoZSBmaWxlJ3MgLSBlbnRyaWVzIGJleW9uZCAyIHRvdGFsIGFyZSBkcm9wcGVkIHdpdGggYSAi"
    "CiAgICAgICAgICAgICAgICAgICAgICAgICAgIndhcm5pbmcsIHNpbmNlIHRoaXMgc2NyaXB0IG9ubHkgZXZlciBjb21wYXJl"
    "cyBhIHR3by1hY2NvdW50IHBhaXIuIikKICAgIGFwLmFkZF9hcmd1bWVudCgiLS1waGFzZXMiLCBkZWZhdWx0PSJiYXNlbGlu"
    "ZSIsCiAgICAgICAgICAgICAgICAgICAgIGhlbHA9IkNvbW1hLXNlcGFyYXRlZCBwaXBlbGluZSBwaGFzZXMgdG8gcnVuLCBp"
    "biBhZGRpdGlvbiB0byB0aGUgZGVmYXVsdCB+MTAwLWNoZWNrIHN1aXRlOiAiCiAgICAgICAgICAgICAgICAgICAgICAgICAg"
    "InJlY29uLGRpc2NvdmVyLGV4dHNjYW4saW5qZWN0LGV4cGxvaXQgLSBvciAnYWxsJyBmb3IgZXZlcnkgcGhhc2UuIERlZmF1"
    "bHQ6ICdiYXNlbGluZScgIgogICAgICAgICAgICAgICAgICAgICAgICAgICIodG9kYXkncyBiZWhhdmlvdXIsIHVuY2hhbmdl"
    "ZCkuIFNlbGVjdGluZyBhIGxhdGVyIHBoYXNlIGF1dG8taW5jbHVkZXMgd2hhdCBpdCBkZXBlbmRzICIKICAgICAgICAgICAg"
    "ICAgICAgICAgICAgICAib24gKGUuZy4gLS1waGFzZXMgaW5qZWN0IGFsc28gcnVucyBkaXNjb3ZlciBhbmQgcmVjb24pLiBy"
    "ZWNvbj1zYW1lLW9yaWdpbiBjcmF3bCAiCiAgICAgICAgICAgICAgICAgICAgICAgICAgIihmaWxscyBXQS1PVEctMjc2LzI3"
    "NyBmb3IgcmVhbCk7IGRpc2NvdmVyPWV4dHJhY3QgZm9ybSBmaWVsZHMgKyBxdWVyeSBwYXJhbXMgZnJvbSAiCiAgICAgICAg"
    "ICAgICAgICAgICAgICAgICAgImNyYXdsZWQgcGFnZXM7IGV4dHNjYW49bnVjbGVpK25pa3RvIGlmIGluc3RhbGxlZCAoYXV0"
    "by1kZXRlY3RlZCBvbiBQQVRIKTsgIgogICAgICAgICAgICAgICAgICAgICAgICAgICJpbmplY3Q9c2VuZCBidWlsdC1pbiBY"
    "U1MvU1FMaS9DbWRJbmplY3Rpb24vUGF0aFRyYXZlcnNhbC9TU1RJIHBheWxvYWRzIGludG8gZGlzY292ZXJlZCAiCiAgICAg"
    "ICAgICAgICAgICAgICAgICAgICAgImZpZWxkczsgZXhwbG9pdD1SRUFMIGV4cGxvaXRhdGlvbiB2aWEgc3FsbWFwL2RhbGZv"
    "eCBhZ2FpbnN0IGNvbmZpcm1lZCBpbmplY3QtcGhhc2UgIgogICAgICAgICAgICAgICAgICAgICAgICAgICJmaW5kaW5ncyAt"
    "IHJlcXVpcmVzIC0taS1hbS1hdXRob3JpemVkLCBzZWUgYmVsb3cuIikKICAgIGFwLmFkZF9hcmd1bWVudCgiLS1leHBsb2l0"
    "IiwgYWN0aW9uPSJzdG9yZV90cnVlIiwKICAgICAgICAgICAgICAgICAgICAgaGVscD0iU2hvcnRoYW5kIGZvciBpbmNsdWRp"
    "bmcgJ2V4cGxvaXQnIGluIC0tcGhhc2VzIChhbmQgZXZlcnl0aGluZyBpdCBkZXBlbmRzIG9uKS4gIgogICAgICAgICAgICAg"
    "ICAgICAgICAgICAgICJTdGlsbCByZXF1aXJlcyAtLWktYW0tYXV0aG9yaXplZCBvciB0aGUgZXhwbG9pdCBwaGFzZSByZWZ1"
    "c2VzIHRvIHJ1bi4iKQogICAgYXAuYWRkX2FyZ3VtZW50KCItLWktYW0tYXV0aG9yaXplZCIsIGFjdGlvbj0ic3RvcmVfdHJ1"
    "ZSIsCiAgICAgICAgICAgICAgICAgICAgIGhlbHA9IlJlcXVpcmVkIGFsb25nc2lkZSAtLWV4cGxvaXQgLyAtLXBoYXNlcyBl"
    "eHBsb2l0LiBDb25maXJtcyB5b3UgaGF2ZSBFWFBMSUNJVCBXUklUVEVOICIKICAgICAgICAgICAgICAgICAgICAgICAgICAi"
    "QVVUSE9SSVpBVElPTiB0byBhY3RpdmVseSBleHBsb2l0IHRoZSB0YXJnZXQocykgZ2l2ZW4gLSB0aGUgZXhwbG9pdCBwaGFz"
    "ZSBzZW5kcyByZWFsICIKICAgICAgICAgICAgICAgICAgICAgICAgICAiYXR0YWNrIHRyYWZmaWMgYW5kLCBmb3IgY29uZmly"
    "bWVkIFNRTGksIHJ1bnMgc3FsbWFwIC0tZHVtcCAocHVsbHMgcmVhbCByb3dzIG91dCBvZiB0aGUgIgogICAgICAgICAgICAg"
    "ICAgICAgICAgICAgICJ0YXJnZXQncyBkYXRhYmFzZSkuIFdpdGhvdXQgdGhpcyBmbGFnIHRoZSBleHBsb2l0IHBoYXNlIGxv"
    "Z3MgYSBNQU5VQUwgcm93IGFuZCBkb2VzICIKICAgICAgICAgICAgICAgICAgICAgICAgICAibm90aGluZyBlbHNlLiIpCiAg"
    "ICBhcC5hZGRfYXJndW1lbnQoIi0tY3Jhd2wtbWF4LXBhZ2VzIiwgdHlwZT1pbnQsIGRlZmF1bHQ9MjAsCiAgICAgICAgICAg"
    "ICAgICAgICAgIGhlbHA9IlJlY29uIHBoYXNlOiBtYXggc2FtZS1vcmlnaW4gcGFnZXMgdG8gY3Jhd2wgKGRlZmF1bHQ6IDIw"
    "KSIpCiAgICBhcC5hZGRfYXJndW1lbnQoIi0tY3Jhd2wtZGVwdGgiLCB0eXBlPWludCwgZGVmYXVsdD0yLAogICAgICAgICAg"
    "ICAgICAgICAgICBoZWxwPSJSZWNvbiBwaGFzZTogbWF4IGxpbmstZm9sbG93aW5nIGRlcHRoIGZyb20gdGhlIGdpdmVuIFVS"
    "TCAoZGVmYXVsdDogMikiKQogICAgYXAuYWRkX2FyZ3VtZW50KCItLW1heC1pbmplY3Rpb24tZmllbGRzIiwgdHlwZT1pbnQs"
    "IGRlZmF1bHQ9MjUsCiAgICAgICAgICAgICAgICAgICAgIGhlbHA9IkluamVjdCBwaGFzZTogbWF4IGRpc2NvdmVyZWQgZmll"
    "bGRzIHRvIGFjdHVhbGx5IHRlc3QgKGRlZmF1bHQ6IDI1KSAtIGtlZXBzIHJlcXVlc3QgIgogICAgICAgICAgICAgICAgICAg"
    "ICAgICAgICJ2b2x1bWUvcnVudGltZSBib3VuZGVkIG9uIGZvcm1zL0FQSXMgd2l0aCBhIGxvdCBvZiBmaWVsZHMiKQogICAg"
    "YXAuYWRkX2FyZ3VtZW50KCItLW51Y2xlaS10aW1lb3V0IiwgdHlwZT1pbnQsIGRlZmF1bHQ9MTgwLAogICAgICAgICAgICAg"
    "ICAgICAgICBoZWxwPSJFeHRzY2FuIHBoYXNlOiB0aW1lb3V0IGluIHNlY29uZHMgZm9yIHRoZSBudWNsZWkgc3VicHJvY2Vz"
    "cyAoZGVmYXVsdDogMTgwKSIpCiAgICBhcC5hZGRfYXJndW1lbnQoIi0tbmlrdG8tdGltZW91dCIsIHR5cGU9aW50LCBkZWZh"
    "dWx0PTMwMCwKICAgICAgICAgICAgICAgICAgICAgaGVscD0iRXh0c2NhbiBwaGFzZTogdGltZW91dCBpbiBzZWNvbmRzIGZv"
    "ciB0aGUgbmlrdG8gc3VicHJvY2VzcyAoZGVmYXVsdDogMzAwKSIpCiAgICBhcC5hZGRfYXJndW1lbnQoIi0tc3FsbWFwLXRp"
    "bWVvdXQiLCB0eXBlPWludCwgZGVmYXVsdD0zMDAsCiAgICAgICAgICAgICAgICAgICAgIGhlbHA9IkV4cGxvaXQgcGhhc2U6"
    "IHRpbWVvdXQgaW4gc2Vjb25kcyBmb3IgdGhlIHNxbG1hcCBzdWJwcm9jZXNzIChkZWZhdWx0OiAzMDApIikKICAgIGFwLmFk"
    "ZF9hcmd1bWVudCgiLS1kYWxmb3gtdGltZW91dCIsIHR5cGU9aW50LCBkZWZhdWx0PTEyMCwKICAgICAgICAgICAgICAgICAg"
    "ICAgaGVscD0iRXhwbG9pdCBwaGFzZTogdGltZW91dCBpbiBzZWNvbmRzIGZvciB0aGUgZGFsZm94IHN1YnByb2Nlc3MgKGRl"
    "ZmF1bHQ6IDEyMCkiKQogICAgYXJncyA9IGFwLnBhcnNlX2FyZ3MoKQoKICAgIHBoYXNlX3NldCA9IHt4LnN0cmlwKCkubG93"
    "ZXIoKSBmb3IgeCBpbiBhcmdzLnBoYXNlcy5zcGxpdCgiLCIpIGlmIHguc3RyaXAoKX0KICAgIGlmICJhbGwiIGluIHBoYXNl"
    "X3NldDoKICAgICAgICBwaGFzZV9zZXQgPSB7ImJhc2VsaW5lIiwgInJlY29uIiwgImRpc2NvdmVyIiwgImV4dHNjYW4iLCAi"
    "aW5qZWN0IiwgImV4cGxvaXQifQogICAgaWYgYXJncy5leHBsb2l0OgogICAgICAgIHBoYXNlX3NldC5hZGQoImV4cGxvaXQi"
    "KQogICAgYXJncy5waGFzZXMgPSBleHBhbmRfcGhhc2VfZGVwZW5kZW5jaWVzKHBoYXNlX3NldCkgfCB7ImJhc2VsaW5lIn0K"
    "CiAgICAjIC0tY3JlZHMvLS1jcmVkcy1maWxlIHBvcHVsYXRlIGFyZ3MuY29va2llL2FyZ3MuY29va2llMi9hY2NvdW50MV9s"
    "YWJlbC8KICAgICMgYWNjb3VudDJfbGFiZWwgKHdpdGhvdXQgb3ZlcndyaXRpbmcgYW55dGhpbmcgc2V0IGV4cGxpY2l0bHkg"
    "dmlhIHRob3NlCiAgICAjIGZsYWdzIGRpcmVjdGx5KSBCRUZPUkUgdGhlIC0tY29va2llLy0tY29va2llMiAtPiBhY2NvdW50"
    "MV9jb29raWUvCiAgICAjIGFjY291bnQyX2Nvb2tpZSBkZXJpdmF0aW9uIHJpZ2h0IGJlbG93LCBzbyB0aGUgdHdvIGZlYXR1"
    "cmVzIGNvbXBvc2U6CiAgICAjIGEgLS1jcmVkcy1maWxlIHdpdGggb25lIGxpbmUgYmVoYXZlcyBleGFjdGx5IGxpa2UgLS1j"
    "b29raWUsIHR3byBsaW5lcwogICAgIyBleGFjdGx5IGxpa2UgLS1jb29raWUgKyAtLWNvb2tpZTIsIGp1c3Qgd2l0aCByZWFk"
    "YWJsZSBsYWJlbHMgYXR0YWNoZWQuCiAgICBhcHBseV9jcmVkc19lbnRyaWVzKGFyZ3MpCgogICAgIyAtLWNvb2tpZS8tLWNv"
    "b2tpZTIgZG91YmxlIGFzIC0tYWNjb3VudDEtY29va2llLy0tYWNjb3VudDItY29va2llIGZvcgogICAgIyB0aGUgMi1hY2Nv"
    "dW50IGFjY2Vzcy1jb250cm9sL0lET1IgY2hlY2tzIChjaGVja19hY2Nlc3NfY29udHJvbF8yZmEpCiAgICAjIFVOTEVTUyAt"
    "LWFjY291bnQxLWNvb2tpZS8tLWFjY291bnQyLWNvb2tpZSB3ZXJlIGV4cGxpY2l0bHkgc2V0IHRvCiAgICAjIHNvbWV0aGlu"
    "ZyBkaWZmZXJlbnQuIFRoaXMgaXMgd2hhdCBtYWtlcyBjb3ZlcmFnZSAiYXV0b21hdGljIjogcGFzcwogICAgIyAtLWNvb2tp"
    "ZSBhbG9uZSBhbmQgZXZlcnkgY2hlY2sgaW4gdGhlIHN1aXRlIHJ1bnMgYXV0aGVudGljYXRlZCwKICAgICMgaW5jbHVkaW5n"
    "IFdBLU9URy0zMTIgZm9yIHJlYWw7IGFkZCAtLWNvb2tpZTIgYW5kIFdBLVNTLTA3MS8KICAgICMgV0EtT1RHLTMxNCAod2hp"
    "Y2ggbmVlZCBhIHNlY29uZCwgZGlmZmVyZW50IGFjY291bnQgdG8gY29tcGFyZQogICAgIyBhZ2FpbnN0KSBhdXRvbWF0aWNh"
    "bGx5IGdldCByZWFsIHRlc3RpbmcgdG9vIC0gbm8gbmVlZCB0byBhbHNvIHJlcGVhdAogICAgIyB0aGUgc2FtZSBjb29raWUg"
    "dmFsdWUgb24gLS1hY2NvdW50MS1jb29raWUvLS1hY2NvdW50Mi1jb29raWUuCiAgICBpZiBhcmdzLmNvb2tpZSBhbmQgbm90"
    "IGFyZ3MuYWNjb3VudDFfY29va2llOgogICAgICAgIGFyZ3MuYWNjb3VudDFfY29va2llID0gYXJncy5jb29raWUKICAgIGlm"
    "IGFyZ3MuY29va2llMiBhbmQgbm90IGFyZ3MuYWNjb3VudDJfY29va2llOgogICAgICAgIGFyZ3MuYWNjb3VudDJfY29va2ll"
    "ID0gYXJncy5jb29raWUyCgogICAgZ2xvYmFsIEVYVFJBX0FVVEhfSEVBREVSUywgT05MWV9JRFMKICAgIGlmIGFyZ3MuY29v"
    "a2llOgogICAgICAgIEVYVFJBX0FVVEhfSEVBREVSU1siQ29va2llIl0gPSBhcmdzLmNvb2tpZQogICAgaWYgYXJncy5oZWFk"
    "ZXI6CiAgICAgICAgZm9yIGggaW4gYXJncy5oZWFkZXI6CiAgICAgICAgICAgIGlmICI6IiBub3QgaW4gaDoKICAgICAgICAg"
    "ICAgICAgIHByaW50KGYiWyFdIElnbm9yaW5nIG1hbGZvcm1lZCAtLWhlYWRlciB7aCFyfSAtIGV4cGVjdGVkIFwiTmFtZTog"
    "VmFsdWVcIiIsIGZpbGU9c3lzLnN0ZGVycikKICAgICAgICAgICAgICAgIGNvbnRpbnVlCiAgICAgICAgICAgIG5hbWUsIF8s"
    "IHZhbHVlID0gaC5wYXJ0aXRpb24oIjoiKQogICAgICAgICAgICBFWFRSQV9BVVRIX0hFQURFUlNbbmFtZS5zdHJpcCgpXSA9"
    "IHZhbHVlLnN0cmlwKCkKICAgIGlmIGFyZ3Mub25seToKICAgICAgICBPTkxZX0lEUyA9IHNldCgpCiAgICAgICAgZm9yIHJh"
    "dyBpbiBhcmdzLm9ubHk6CiAgICAgICAgICAgIE9OTFlfSURTLnVwZGF0ZSh4LnN0cmlwKCkgZm9yIHggaW4gcmF3LnNwbGl0"
    "KCIsIikgaWYgeC5zdHJpcCgpKQoKICAgIHVybHMgPSBbYXJncy51cmxdIGlmIGFyZ3MudXJsIGVsc2UgcmVhZF91cmxfbGlz"
    "dChhcmdzLnVybF9maWxlKQogICAgaWYgbm90IHVybHM6CiAgICAgICAgcHJpbnQoIk5vIFVSTHMgdG8gc2Nhbi4iLCBmaWxl"
    "PXN5cy5zdGRlcnIpCiAgICAgICAgc3lzLmV4aXQoMSkKCiAgICBpZiBhcmdzLm5vX2NsaV90b29sczoKICAgICAgICBwcmlu"
    "dCgiWypdIC0tbm8tY2xpLXRvb2xzIHNldCAtIGN1cmwvbm1hcC9zc2x5emUvc3Nsc2Nhbi90ZXN0c3NsLnNoIHdpbGwgTk9U"
    "IGJlIHVzZWQgZXZlbiBpZiBpbnN0YWxsZWQuIikKICAgIGVsc2U6CiAgICAgICAgZm91bmQgPSBbdCBmb3IgdCBpbiAoImN1"
    "cmwiLCAibm1hcCIsICJzc2x5emUiLCAic3Nsc2NhbiIsICJ0ZXN0c3NsLnNoIikgaWYgX2NsaV9hdmFpbGFibGUodCldCiAg"
    "ICAgICAgaWYgZm91bmQ6CiAgICAgICAgICAgIHByaW50KGYiWypdIENvbW1hbmQtbGluZSB0b29scyBkZXRlY3RlZCBvbiBQ"
    "QVRIIGFuZCB3aWxsIGJlIHVzZWQgYXV0b21hdGljYWxseTogeycsICcuam9pbihmb3VuZCl9IikKICAgICAgICBlbHNlOgog"
    "ICAgICAgICAgICBwcmludCgiWypdIE5vIGN1cmwvbm1hcC9zc2x5emUvc3Nsc2Nhbi90ZXN0c3NsLnNoIGZvdW5kIG9uIFBB"
    "VEggLSB0aG9zZSBjaGVja3Mgc3RheSBNQU5VQUwvUHl0aG9uLW9ubHkuIikKICAgIHByaW50X2F1dGhfY292ZXJhZ2VfcGxh"
    "bihhcmdzKQogICAgcHJpbnRfcGhhc2VfcGxhbihhcmdzKQogICAgaWYgImV4cGxvaXQiIGluIGFyZ3MucGhhc2VzIGFuZCBh"
    "cmdzLmlfYW1fYXV0aG9yaXplZDoKICAgICAgICBwcmludCgiXG5bISEhXSBFWFBMT0lUIHBoYXNlIGlzIEVOQUJMRUQgYW5k"
    "IEFVVEhPUklaRUQgZm9yIHRoaXMgcnVuIC0gdGhpcyBXSUxMIHNlbmQgcmVhbCBhdHRhY2sgdHJhZmZpYywgIgogICAgICAg"
    "ICAgICAgICJhbmQgZm9yIGNvbmZpcm1lZCBTUUwgSW5qZWN0aW9uIGZpbmRpbmdzIFdJTEwgcnVuIHNxbG1hcCAtLWR1bXAg"
    "YWdhaW5zdCB0aGUgdGFyZ2V0J3MgZGF0YWJhc2UuICIKICAgICAgICAgICAgICAiTWFrZSBzdXJlIGV2ZXJ5IFVSTCB5b3Un"
    "cmUgYWJvdXQgdG8gc2NhbiBpcyBvbmUgeW91IGhhdmUgZXhwbGljaXQgd3JpdHRlbiBhdXRob3JpemF0aW9uIHRvICIKICAg"
    "ICAgICAgICAgICAiYWN0aXZlbHkgZXhwbG9pdC4iKQoKICAgIGZvciB1IGluIHVybHM6CiAgICAgICAgc2Nhbl91cmwodSwg"
    "YXJncykKCiAgICBpbWFnZV9ieXRlcyA9IGdlbmVyYXRlX3NjcmVlbnNob3RzKGFyZ3Muc2NyZWVuc2hvdCkKCiAgICBzdGFt"
    "cCA9IGRhdGV0aW1lLm5vdygpLnN0cmZ0aW1lKCIlWSVtJWQtJUglTSVTIikKICAgIG91dF9iYXNlID0gYXJncy5vdXQgb3Ig"
    "ZiJjaGVja2xpc3Rfc2Nhbl97c3RhbXB9IgogICAgZm9yIGV4dCBpbiAoIi5jc3YiLCAiLmpzb24iLCAiLnhsc3giKToKICAg"
    "ICAgICBpZiBvdXRfYmFzZS5sb3dlcigpLmVuZHN3aXRoKGV4dCk6CiAgICAgICAgICAgIG91dF9iYXNlID0gb3V0X2Jhc2Vb"
    "OiAtbGVuKGV4dCldCiAgICBjc3ZfcGF0aCwganNvbl9wYXRoLCB4bHN4X3BhdGggPSBvdXRfYmFzZSArICIuY3N2Iiwgb3V0"
    "X2Jhc2UgKyAiLmpzb24iLCBvdXRfYmFzZSArICIueGxzeCIKICAgIGNvbnNvbGlkYXRlZF9jc3ZfcGF0aCA9IG91dF9iYXNl"
    "ICsgIl9jb25zb2xpZGF0ZWQuY3N2IgogICAgY29uc29saWRhdGVkX2pzb25fcGF0aCA9IG91dF9iYXNlICsgIl9jb25zb2xp"
    "ZGF0ZWQuanNvbiIKCiAgICB3cml0ZV9jc3YoY3N2X3BhdGgpCiAgICB3cml0ZV9qc29uKGpzb25fcGF0aCkKICAgIHdyaXRl"
    "X2NvbnNvbGlkYXRlZF9jc3YoY29uc29saWRhdGVkX2Nzdl9wYXRoKQogICAgd3JpdGVfY29uc29saWRhdGVkX2pzb24oY29u"
    "c29saWRhdGVkX2pzb25fcGF0aCkKICAgIHhsc3hfb2sgPSB3cml0ZV94bHN4KHhsc3hfcGF0aCwgaW1hZ2VfYnl0ZXMpCiAg"
    "ICBjb21wcmVoZW5zaXZlX3BhdGggPSBvdXRfYmFzZSArICJfY29tcHJlaGVuc2l2ZS5qc29uIgogICAgcmVwb3J0ID0gd3Jp"
    "dGVfY29tcHJlaGVuc2l2ZV9yZXBvcnQoY29tcHJlaGVuc2l2ZV9wYXRoKQoKICAgIHByaW50X3N1bW1hcnkoeGxzeF9vaykK"
    "ICAgIHByaW50X2NvbXByZWhlbnNpdmVfcmVwb3J0KHJlcG9ydCkKICAgIHByaW50KCJcblJlc3VsdHMgd3JpdHRlbiB0bzoi"
    "KQogICAgcHJpbnQoZiIgIENTViAgKHBlci1VUkwgZGV0YWlsKTogIHtjc3ZfcGF0aH0iKQogICAgcHJpbnQoZiIgIENTViAg"
    "KG9uZSByb3cgcGVyIElEKTogIHtjb25zb2xpZGF0ZWRfY3N2X3BhdGh9IikKICAgIHByaW50KGYiICBKU09OIChwZXItVVJM"
    "IGRldGFpbCwgdXNlIHRoaXMgb25lIGZvciB0aGUgcG9ydGFsIGltcG9ydCAtIHNlZSBSRUFETUUpOiB7anNvbl9wYXRofSIp"
    "CiAgICBwcmludChmIiAgSlNPTiAob25lIHJvdyBwZXIgSUQpOiAge2NvbnNvbGlkYXRlZF9qc29uX3BhdGh9IikKICAgIHBy"
    "aW50KGYiICBKU09OIChzZXZlcml0eS13ZWlnaHRlZCBjb21wcmVoZW5zaXZlIHJlcG9ydCwgYWxsIHBoYXNlcyk6IHtjb21w"
    "cmVoZW5zaXZlX3BhdGh9IikKICAgIGlmIHhsc3hfb2s6CiAgICAgICAgcHJpbnQoZiIgIFhMU1ggKCdDb25zb2xpZGF0ZWQn"
    "IHNoZWV0ICsgJ1NjYW4gUmVzdWx0cyAoRGV0YWlsKScgc2hlZXQpOiB7eGxzeF9wYXRofSIpCgoKaWYgX19uYW1lX18gPT0g"
    "Il9fbWFpbl9fIjoKICAgIG1haW4oKQo="
)


class BurpExtender(IBurpExtender, ITab, IContextMenuFactory):

    # ------------------------------------------------------------------
    # Burp extension entry point
    # ------------------------------------------------------------------
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName(EXT_NAME)

        self._rows = []             # last scan's parsed result rows (list of dict)
        self._burp_issues_raw = []  # full-detail Burp Scanner issue dicts, same order as _burp_issues_model rows
        self._worst_findings_rows = []  # row dicts behind Summary's Failed vulnerabilities table, same order
        self._last_out_base = None  # path prefix of the last scan's output files
        self._last_xlsx_ok = True   # False if the last scan's .xlsx wasn't written (missing pandas/xlsxwriter)
        self._scan_running = False
        self._scan_proc = None      # the live checklist_auto_scan.py subprocess, if a scan is running
        self._scan_timer = None     # watchdog timer that kills a hung subprocess (see _start_scan)
        self._scan_cancelled = False

        # Detailed Results filter state - a category/group AND a result
        # type AND a free-text search can all be active at once (e.g.
        # "SQL Injection" + "FAIL" + "cookie").
        self._filter_categories = None
        self._filter_result = None
        self._filter_search_text = ""

        self._build_ui()
        callbacks.addSuiteTab(self)
        # Reported directly: "when I can confirm the test XSS in repeater
        # or proxy or intruder selected output can be moved to quickchop
        # for a record vulnerability list" - registers this class's
        # createMenuItems() (below) as a right-click context menu source
        # across every Burp tool (Proxy, Repeater, Intruder, Target,
        # Scanner, ...), adding a "Log finding to QuickChop..." item that
        # opens _open_log_finding_dialog() pre-filled with whatever
        # request/response was right-clicked.
        callbacks.registerContextMenuFactory(self)
        callbacks.printOutput("%s loaded. Open the '%s' tab to configure and run." % (EXT_NAME, EXT_NAME))

    def getTabCaption(self):
        return EXT_NAME

    def getUiComponent(self):
        return self._main_panel

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------
    def _build_ui(self):
        self._main_panel = JPanel(BorderLayout())

        # Reported directly: JTabbedPane.LEFT (vertical tabs down the left
        # edge) rendered "tottaly collapsed" in Burp's embedded panel - only
        # the first tab's label was visible and the rest were unreachable,
        # which also meant there was "no option to enter target and cheks"
        # since Configuration lived on one of the unreachable tabs. Switched
        # to JTabbedPane.TOP (Swing's default, most-tested tab placement) to
        # fix that outright, matching the latest request too: "on top tabs,
        # left sected details ... scan status should comes in summary".
        # Tab order: Summary, Configuration, Categories, then the existing
        # Detailed Results / Burp Findings tabs. NOTE: if this order changes,
        # update the index used by _apply_filter()'s
        # self._tabs.setSelectedIndex(...) call.
        self._tabs = JTabbedPane(JTabbedPane.TOP)
        self._tabs.addTab("Summary", self._build_summary_panel())
        self._tabs.addTab("Configuration", self._build_config_panel())
        self._tabs.addTab("Categories", self._build_categories_panel())
        self._tabs.addTab("Detailed Results", self._build_results_panel())
        self._tabs.addTab("Burp Scanner Findings (context only)", self._build_burp_findings_panel())
        # Reported directly: "reference sho all the check list items with
        # name ows id default sevarity etc" - added at the end so the
        # hardcoded self._tabs.setSelectedIndex(3) for Detailed Results
        # above doesn't need to change.
        self._tabs.addTab("Checklist Reference", self._build_checklist_reference_panel())
        # Reported directly: "run and export appearing in two places when i
        # go to config page and moving back to other page config page stays
        # same only top findings are changing" / "something went terribly
        # wrong" (screenshot showed a mostly-blank window with a tab
        # missing from the strip) - forces a full repaint of the tab strip
        # and whichever tab is newly selected every time the selection
        # changes, working around stale/blank Swing rendering after a
        # background-thread-driven UI update. See _TabChangeListener.
        self._tabs.addChangeListener(_TabChangeListener(self))
        self._main_panel.add(self._tabs, BorderLayout.CENTER)

        self._main_panel.add(self._build_status_bar(), BorderLayout.SOUTH)

        # NOTE: a call to self._populate_summary() used to live here, to
        # pre-fill the coverage tables with default 0-value rows before
        # any scan ran. Reverted - it ran extra table/JList-selection
        # logic synchronously during extension load, before the tab was
        # even shown, right when "QuickChop not loading / frozen on
        # load" started. Stability first; the coverage tables just stay
        # empty until the first scan again, like the earliest working
        # builds. Can revisit later once the tab-corruption issue is
        # confirmed fully resolved.

    def _titled_section(self, title):
        """A JPanel with a titled border, laid out top-to-bottom - the
        shared building block for every grouped section in the config
        panel below. Reported directly: "crate same with catagory
        overview, details resutls testing target, and export tabs to
        look neeat" - grouping related fields under labelled sections
        (instead of one long undifferentiated stack of rows) is the
        pure-Swing equivalent of the card-based mockup layout."""
        section = JPanel()
        section.setLayout(BoxLayout(section, BoxLayout.Y_AXIS))
        section.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createTitledBorder(title),
            BorderFactory.createEmptyBorder(2, 4, 6, 4)))
        section.setAlignmentX(JPanel.LEFT_ALIGNMENT)
        return section

    def _build_config_panel(self):
        panel = JPanel()
        panel.setLayout(BoxLayout(panel, BoxLayout.Y_AXIS))
        panel.setBorder(BorderFactory.createTitledBorder("Configuration"))

        # --- Section: scanner setup ---
        setup = self._titled_section("Scanner setup")
        row1 = JPanel(FlowLayout(FlowLayout.LEFT))
        row1.add(JLabel("Python 3 interpreter:"))
        self._python_path_field = JTextField("python3", 12)
        row1.add(self._python_path_field)
        # Reported directly: "make it one file instead of two python
        # files so it is easy to share with burp extension marketplace
        # without the dependency or need to share autoscan script
        # separately" - the "checklist_auto_scan.py path" field/Browse
        # button that used to live here are gone; the scan engine is now
        # embedded in this file (_ENGINE_SOURCE_B64, near the top) and
        # self-extracted to a temp .py at scan time by
        # _materialize_engine_script() - nothing left to point at.
        engine_note = JLabel("Scan engine: bundled with this extension (rev %s) - "
                              "self-extracted automatically, nothing to configure." % ENGINE_SOURCE_REV)
        engine_note.setFont(engine_note.getFont().deriveFont(11.0))
        engine_note.setForeground(Color(0x66, 0x66, 0x66))
        row1.add(engine_note)
        # Reported directly: "configuration tab not aligned properly.
        # targets and run progress bar is right aligned make sure
        # properly left aligned after the text" - root cause (confirmed
        # with a live Swing layout test): a BoxLayout.Y_AXIS container
        # positions each direct child using that child's alignmentX
        # RELATIVE TO ITS SIBLINGS, not independently - if even one
        # sibling in a titled section is left at Swing's default (0.5,
        # CENTER) while another is explicitly 0.0 (LEFT), BoxLayout's
        # cross-axis math splits the difference and renders the LEFT one
        # squeezed to roughly half-width, offset to roughly the
        # horizontal center - exactly the "right aligned" look reported.
        # Every direct child added to a BoxLayout.Y_AXIS section in this
        # file must set the SAME alignmentX as its siblings - LEFT,
        # consistently - or this comes back.
        row1.setAlignmentX(JPanel.LEFT_ALIGNMENT)
        setup.add(row1)

        row2 = JPanel(FlowLayout(FlowLayout.LEFT))
        row2.add(JLabel("Output folder:"))
        self._output_dir_field = JTextField(tempfile.gettempdir(), 34)
        row2.add(self._output_dir_field)
        out_browse_btn = JButton("Browse...")
        out_browse_btn.addActionListener(self._on_browse_output_dir)
        row2.add(out_browse_btn)
        row2.setAlignmentX(JPanel.LEFT_ALIGNMENT)
        setup.add(row2)

        row6b = JPanel(FlowLayout(FlowLayout.LEFT))
        # Real command-line evidence toggle. Earlier builds always passed
        # --no-cli-tools here, which is why runs from inside Burp never
        # showed the real "$ curl ..." command + response that the
        # standalone CLI tool captures - reported directly: "it is not
        # looks like the output you showed... unable to check the request
        # and response". Defaulting this ON matches checklist_auto_scan.py's
        # own CLI default (auto-detect curl/nmap/sslyze/sslscan/testssl.sh
        # on PATH, silently skip whatever isn't installed) - untick it only
        # if you want the old fast/no-subprocess behaviour back.
        self._cli_tools_checkbox = JCheckBox(
            "Use command-line tools (curl/nmap/sslyze/sslscan/testssl.sh) if installed, "
            "for real request/response evidence", True)
        row6b.add(self._cli_tools_checkbox)
        row6b.setAlignmentX(JPanel.LEFT_ALIGNMENT)
        setup.add(row6b)
        panel.add(setup)

        # --- Section: targets & session ---
        targets_section = self._titled_section("Targets & session")
        row3 = JPanel(FlowLayout(FlowLayout.LEFT))
        row3.add(JLabel("Targets (one per line):"))
        row3.setAlignmentX(JPanel.LEFT_ALIGNMENT)
        targets_section.add(row3)
        self._targets_area = JTextArea(4, 60)
        self._targets_area.setLineWrap(True)
        targets_scroll = JScrollPane(self._targets_area)
        targets_scroll.setAlignmentX(JPanel.LEFT_ALIGNMENT)
        targets_section.add(targets_scroll)

        row4 = JPanel(FlowLayout(FlowLayout.LEFT))
        pull_targets_btn = JButton("Pull in-scope targets from Proxy history")
        pull_targets_btn.addActionListener(self._on_pull_targets)
        row4.add(pull_targets_btn)
        # Reported directly: "not all soping urls are pulling only top one
        # it adding as target" - the default (unticked) behaviour collapses
        # Proxy history down to one entry per distinct HOST (scheme+host+
        # port), which is correct for a single-host engagement (most
        # checklist items are host-level: headers/SSL/cookies/etc. don't
        # vary by path, so testing every path would just multiply scan
        # time for no extra coverage) - but if you actually have several
        # distinct in-scope hosts/paths you want tested individually,
        # ticking this pulls full URLs (path included, query stripped)
        # instead of collapsing to one row per host.
        self._pull_full_urls_checkbox = JCheckBox("Pull full URLs (paths too, not just hosts)", False)
        row4.add(self._pull_full_urls_checkbox)
        capture_session_btn = JButton("Capture session (Cookie) from Proxy history")
        capture_session_btn.addActionListener(self._on_capture_session)
        row4.add(capture_session_btn)
        row4.setAlignmentX(JPanel.LEFT_ALIGNMENT)
        targets_section.add(row4)

        row5 = JPanel(FlowLayout(FlowLayout.LEFT))
        row5.add(JLabel("Cookie header (captured or paste your own):"))
        self._cookie_field = JTextField("", 40)
        row5.add(self._cookie_field)
        row5.setAlignmentX(JPanel.LEFT_ALIGNMENT)
        targets_section.add(row5)

        row6 = JPanel(FlowLayout(FlowLayout.LEFT))
        row6.add(JLabel("Extra header (optional, e.g. Authorization: Bearer ...):"))
        self._extra_header_field = JTextField("", 40)
        row6.add(self._extra_header_field)
        row6.setAlignmentX(JPanel.LEFT_ALIGNMENT)
        targets_section.add(row6)
        panel.add(targets_section)

        # --- Section: run / export ---
        actions_section = self._titled_section("Run & export")
        row7 = JPanel(FlowLayout(FlowLayout.LEFT))
        self._run_all_btn = JButton("Run All Tests")
        self._run_all_btn.addActionListener(self._on_run_all)
        row7.add(self._run_all_btn)

        self._rerun_selected_btn = JButton("Re-run Selected")
        self._rerun_selected_btn.addActionListener(self._on_rerun_selected)
        row7.add(self._rerun_selected_btn)

        self._export_btn = JButton("Export -> ReportSystem JSON/CSV/XLSX")
        self._export_btn.addActionListener(self._on_export)
        row7.add(self._export_btn)

        self._pull_burp_issues_btn = JButton("Pull Burp Scanner findings for these targets")
        self._pull_burp_issues_btn.addActionListener(self._on_pull_burp_issues)
        row7.add(self._pull_burp_issues_btn)
        # Reported directly: "burp freezes" - if a scan ever hangs again
        # (SCAN_TIMEOUT_SECONDS is a 20-minute backstop, but no need to
        # wait that long), this lets the user kill it and get the UI back
        # immediately instead of restarting Burp.
        self._cancel_scan_btn = JButton("Cancel Scan")
        self._cancel_scan_btn.addActionListener(self._on_cancel_scan)
        self._cancel_scan_btn.setEnabled(False)
        row7.add(self._cancel_scan_btn)
        row7.setAlignmentX(JPanel.LEFT_ALIGNMENT)
        # Same unbounded FlowLayout-row-under-BoxLayout gap bug as
        # Summary's cards_row/run_export_row/toggle_row (see those for the
        # full explanation) - fixed here too for consistency, since this
        # is the same button row duplicated onto Configuration.
        row7.setMaximumSize(Dimension(4000, 40))
        actions_section.add(row7)

        # Reported directly: "in run all test and re-run selected below
        # add progress bar while test are running and add statement once
        # completed never know if test are performed or idle" - a status
        # bar tucked away at the very bottom of the whole tab (the
        # existing self._status_label) was easy to miss; this progress
        # bar + label live right under the buttons that start a scan, so
        # it's obvious at a glance whether a scan is running, finished,
        # or never started. Kept in sync with the real self._scan_running
        # state from _start_scan()/_on_scan_complete() below - not a
        # decorative/static bar.
        row8 = JPanel(BorderLayout())
        row8.setAlignmentX(JPanel.LEFT_ALIGNMENT)
        row8.setMaximumSize(Dimension(4000, 22))
        row8.setBorder(BorderFactory.createEmptyBorder(8, 0, 0, 0))
        self._config_progress_bar = JProgressBar(0, 100)
        self._config_progress_bar.setStringPainted(True)
        self._config_progress_bar.setString("Idle")
        row8.add(self._config_progress_bar, BorderLayout.CENTER)
        actions_section.add(row8)

        self._config_status_label = JLabel("Idle - no scan has been run yet. Click 'Run All Tests' to start.")
        self._config_status_label.setFont(self._config_status_label.getFont().deriveFont(11.0))
        self._config_status_label.setForeground(Color(0x66, 0x66, 0x66))
        self._config_status_label.setBorder(BorderFactory.createEmptyBorder(4, 2, 0, 0))
        self._config_status_label.setAlignmentX(JPanel.LEFT_ALIGNMENT)
        actions_section.add(self._config_status_label)

        panel.add(actions_section)

        return panel

    def _make_stat_card(self, title, accent, on_click=None):
        """One KPI 'card' (colored accent stripe + big number + small caption)
        - the pure-Swing equivalent of the card-based mockup's stat tiles.
        Plain JLabel text throughout, deliberately no HTML - the old summary
        line used an HTML JLabel and it rendered the literal '<html><b>...'
        tags on screen instead of formatting them (reported directly, with a
        screenshot circling it in red). Cause wasn't chased down since the
        fix is the same either way: don't rely on Swing's HTML label support
        for anything that has to look right.

        on_click, if given, is a zero-arg callable invoked when the card is
        clicked - the Swing equivalent of the mockup's clickable KPI cards
        that jump to Detailed Results filtered to that number. It's read
        lazily at click time (not bound at card-creation time), so a single
        card built once can still reflect whatever category scope is
        currently selected on the Categories tab."""
        card = JPanel(BorderLayout())
        card.setBackground(Color.WHITE)
        card.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createMatteBorder(0, 0, 4, 0, accent),
            BorderFactory.createEmptyBorder(8, 16, 8, 16)))
        # Reported directly: "alignment still missgin layout still not
        # looks like model" - the value/title were left-biased inside
        # each card instead of centered like a real stat tile.
        value_label = JLabel("0", JLabel.CENTER)
        value_label.setHorizontalAlignment(JLabel.CENTER)
        value_label.setFont(Font("SansSerif", Font.BOLD, 28))
        value_label.setForeground(accent)
        title_label = JLabel(title, JLabel.CENTER)
        title_label.setHorizontalAlignment(JLabel.CENTER)
        title_label.setFont(Font("SansSerif", Font.PLAIN, 10))
        title_label.setForeground(Color(0x66, 0x66, 0x66))
        card.add(value_label, BorderLayout.CENTER)
        card.add(title_label, BorderLayout.SOUTH)
        card.setPreferredSize(Dimension(170, 62))
        if on_click is not None:
            card.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR))
            listener = _CallbackMouseListener(on_click)
            card.addMouseListener(listener)
            value_label.addMouseListener(listener)
            title_label.addMouseListener(listener)
        return {"panel": card, "value_label": value_label}

    def _build_summary_panel(self):
        panel = JPanel()
        panel.setLayout(BoxLayout(panel, BoxLayout.Y_AXIS))
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))

        # Reported directly: "Run & export moved to top kepp below KPIs so
        # an every page it will be consistent, KPIs on top, next Run &
        # Export then Categories" - KPI cards come first now (see below),
        # then Run & export, then Coverage.
        cards_row = JPanel(FlowLayout(FlowLayout.LEFT, 12, 6))
        self._card_total = self._make_stat_card("TOTAL CHECKS RUN", Color(0x2C, 0x3E, 0x50),
                                                  lambda: self._apply_filter(None, None, None))
        self._card_pass = self._make_stat_card("PASS", Color(0x1E, 0x7E, 0x34),
                                                 lambda: self._apply_filter(None, "PASS", None))
        self._card_fail = self._make_stat_card("FAIL (VULNERABLE)", Color(0xA4, 0x26, 0x2C),
                                                 lambda: self._apply_filter(None, "FAIL", None))
        self._card_manual = self._make_stat_card("MANUAL / INFO / ERROR", Color(0x8A, 0x6D, 0x00),
                                                   lambda: self._apply_filter(None, "OTHER", None))
        self._card_categories = self._make_stat_card("CATEGORIES COVERED", Color(0x1F, 0x4E, 0x78))
        for card in (self._card_total, self._card_pass, self._card_fail, self._card_manual, self._card_categories):
            cards_row.add(card["panel"])
        cards_row.setAlignmentX(JPanel.LEFT_ALIGNMENT)
        # Reported directly: "auto fit as ther is log of gaps" - a
        # FlowLayout row has an unbounded default max height (FlowLayout
        # doesn't override maximumLayoutSize()), so under a BoxLayout.Y_AXIS
        # parent it's treated as "infinitely stretchable" and soaks up all
        # of the tab's surplus vertical space, showing up as a big empty
        # gap below it. Same fix as the progress-bar rows below
        # (bar_row/row8): pin a bounded max height so this row only ever
        # takes the space its content actually needs.
        cards_row.setMaximumSize(Dimension(4000, 80))
        panel.add(cards_row)

        hint = JLabel("Click a number above (Total / Pass / Fail / Manual) to jump to Detailed Results filtered to it.")
        hint.setFont(hint.getFont().deriveFont(11.0))
        hint.setForeground(Color(0x66, 0x66, 0x66))
        hint.setBorder(BorderFactory.createEmptyBorder(4, 4, 2, 4))
        hint.setAlignmentX(JPanel.LEFT_ALIGNMENT)
        panel.add(hint)

        # Reported directly (this build's freeze/getColumnClass bug is now
        # fixed, so this is safe to bring back): "can we bring run & export
        # to Summary page?" - a second set of buttons, wired to the exact
        # same handlers as the Configuration tab's (_on_run_all/
        # _on_rerun_selected/_on_export/_on_pull_burp_issues/
        # _on_cancel_scan), so clicking either copy does the identical
        # thing and both copies are kept enabled/disabled in lockstep by
        # _start_scan()/_on_scan_complete() below - no separate state to
        # drift out of sync. Targets/cookie/etc. still only live on
        # Configuration (this is just a shortcut to start/export a scan
        # without switching tabs, not a second config surface).
        run_export_section = self._titled_section("Run & export")
        run_export_row = JPanel(FlowLayout(FlowLayout.LEFT))
        self._summary_run_all_btn = JButton("Run All Tests")
        self._summary_run_all_btn.addActionListener(self._on_run_all)
        run_export_row.add(self._summary_run_all_btn)

        self._summary_rerun_selected_btn = JButton("Re-run Selected")
        self._summary_rerun_selected_btn.addActionListener(self._on_rerun_selected)
        run_export_row.add(self._summary_rerun_selected_btn)

        self._summary_export_btn = JButton("Export -> ReportSystem JSON/CSV/XLSX")
        self._summary_export_btn.addActionListener(self._on_export)
        run_export_row.add(self._summary_export_btn)

        self._summary_pull_burp_issues_btn = JButton("Pull Burp Scanner findings for these targets")
        self._summary_pull_burp_issues_btn.addActionListener(self._on_pull_burp_issues)
        run_export_row.add(self._summary_pull_burp_issues_btn)

        self._summary_cancel_scan_btn = JButton("Cancel Scan")
        self._summary_cancel_scan_btn.addActionListener(self._on_cancel_scan)
        self._summary_cancel_scan_btn.setEnabled(False)
        run_export_row.add(self._summary_cancel_scan_btn)
        run_export_row.setAlignmentX(JPanel.LEFT_ALIGNMENT)
        # See cards_row.setMaximumSize() note above - same unbounded
        # FlowLayout-row-under-BoxLayout gap bug, this time on the
        # Run & export button row.
        run_export_row.setMaximumSize(Dimension(4000, 40))
        run_export_section.add(run_export_row)
        run_export_section.setAlignmentX(JPanel.LEFT_ALIGNMENT)
        panel.add(run_export_section)

        self._progress_label = JLabel("No scan run yet - open the Configuration tab, set your targets, and "
                                       "click Run All Tests.")
        self._progress_label.setBorder(BorderFactory.createEmptyBorder(8, 4, 2, 4))
        self._progress_label.setAlignmentX(JPanel.LEFT_ALIGNMENT)
        panel.add(self._progress_label)

        # Reported directly: "alignment still missgin" - the progress bar
        # previously carried its OWN long descriptive sentence as the bar's
        # setString() text, which visually overlapped/garbled against the
        # "NN%" Aqua/macOS auto-draws on top of a JProgressBar's fill -
        # the bar itself now shows only a short "NN%", and the descriptive
        # sentence moved to its own label underneath where it can't clash.
        bar_row = JPanel(BorderLayout())
        bar_row.setAlignmentX(JPanel.LEFT_ALIGNMENT)
        bar_row.setMaximumSize(Dimension(4000, 22))
        self._progress_bar = JProgressBar(0, 100)
        self._progress_bar.setStringPainted(True)
        self._progress_bar.setString("0%")
        bar_row.add(self._progress_bar, BorderLayout.CENTER)
        panel.add(bar_row)

        self._progress_detail_label = JLabel(" ")
        self._progress_detail_label.setFont(self._progress_detail_label.getFont().deriveFont(11.0))
        self._progress_detail_label.setForeground(Color(0x66, 0x66, 0x66))
        self._progress_detail_label.setBorder(BorderFactory.createEmptyBorder(3, 4, 10, 4))
        self._progress_detail_label.setAlignmentX(JPanel.LEFT_ALIGNMENT)
        panel.add(self._progress_detail_label)

        # Reported directly: "bring run & export to Summary page? and
        # worst findings no need can be removed as it is not use for me"
        # - Run & export now lives both here and on Configuration (kept in
        # lockstep, see the button block above). Worst Findings was
        # removed at that point, then reported directly again later: "add
        # bototm fauled vulnerabiitys below the gatagory" - it's back
        # below, now named "Failed vulnerabilities" and placed below the
        # Coverage table specifically (see panel.add(coverage_box) then
        # panel.add(worst_box) below), and reflects the unified
        # automated + manually-logged row set via _refresh_worst_findings().
        #
        # Reported directly (earlier): "when no need to show two different
        # tables you can add the tab above" - one table, a small toggle
        # above it switches between category rows and OWASP Top 10 rows
        # instead of stacking two tables permanently. Same idea as the
        # Categories tab's mode toggle.
        coverage_box = self._titled_section("Coverage")
        coverage_box.setAlignmentX(JPanel.LEFT_ALIGNMENT)

        toggle_row = JPanel(FlowLayout(FlowLayout.LEFT, 6, 0))
        toggle_row.setAlignmentX(JPanel.LEFT_ALIGNMENT)
        self._summary_cat_toggle = JToggleButton("Coverage by category", True)
        self._summary_owasp_toggle = JToggleButton("OWASP Top 10 coverage", False)
        summary_mode_group = ButtonGroup()
        summary_mode_group.add(self._summary_cat_toggle)
        summary_mode_group.add(self._summary_owasp_toggle)
        self._summary_cat_toggle.addActionListener(lambda e: self._on_summary_coverage_mode_changed("cat"))
        self._summary_owasp_toggle.addActionListener(lambda e: self._on_summary_coverage_mode_changed("owasp"))
        toggle_row.add(self._summary_cat_toggle)
        toggle_row.add(self._summary_owasp_toggle)
        # See cards_row.setMaximumSize() note above - same fix, this time
        # on the Coverage mode-toggle row.
        toggle_row.setMaximumSize(Dimension(4000, 36))
        coverage_box.add(toggle_row)

        self._summary_coverage_table_model = ColoredTableModel(
            ["Category", "Total", "Pass", "Fail", "Manual/Other"], 0)
        self._summary_coverage_table = JTable(self._summary_coverage_table_model)
        self._summary_coverage_table.setAutoCreateRowSorter(True)
        summary_coverage_renderer = CategoryFailRenderer(self, None, None)
        self._summary_coverage_table.setDefaultRenderer(JObject, summary_coverage_renderer)
        self._summary_coverage_table.setDefaultRenderer(JInteger, summary_coverage_renderer)
        self._summary_coverage_table.setRowHeight(22)
        self._apply_coverage_table_widths(self._summary_coverage_table)
        self._summary_coverage_table.addMouseListener(_SummaryCoverageDoubleClickListener(self))
        coverage_scroll = JScrollPane(self._summary_coverage_table)
        coverage_scroll.setPreferredSize(Dimension(680, 220))
        coverage_scroll.setAlignmentX(JPanel.LEFT_ALIGNMENT)
        coverage_box.add(coverage_scroll)

        self._summary_coverage_hint = JLabel(
            "Double-click a row to jump to Detailed Results for that category, or use the Categories "
            "tab to browse interactively.")
        self._summary_coverage_hint.setFont(self._summary_coverage_hint.getFont().deriveFont(11.0))
        self._summary_coverage_hint.setForeground(Color(0x66, 0x66, 0x66))
        self._summary_coverage_hint.setAlignmentX(JPanel.LEFT_ALIGNMENT)
        coverage_box.add(self._summary_coverage_hint)
        panel.add(coverage_box)

        # Reported directly: "add bototm fauled vulnerabiitys below the
        # gatagory" - a small ranked list of the current worst (highest
        # severity first) FAIL results, placed below the Coverage table.
        # Populated/refreshed by _refresh_worst_findings(), called from
        # _populate_summary() alongside everything else on this tab.
        # Reported directly again later: "add color codeing for severaity
        # add table form" - rebuilt as a real sortable JTable (was a
        # stack of plain JLabel rows) with its own color-coded Severity
        # column (see _SeverityTextRenderer), same as Detailed Results
        # and Checklist Reference now both have.
        worst_box = self._titled_section("Failed vulnerabilities")
        worst_box.setAlignmentX(JPanel.LEFT_ALIGNMENT)
        self._worst_findings_table_model = ColoredTableModel(["ID", "Category", "Test", "Severity", "Source"], 0)
        self._worst_findings_table = JTable(self._worst_findings_table_model)
        self._worst_findings_table.setAutoCreateRowSorter(True)
        self._worst_findings_table.setRowHeight(22)
        worst_col_model = self._worst_findings_table.getColumnModel()
        for idx, width in ((0, 90), (1, 150), (3, 90), (4, 130)):
            worst_col_model.getColumn(idx).setPreferredWidth(width)
        worst_col_model.getColumn(3).setCellRenderer(_SeverityTextRenderer())
        # Double-click a row for the same full-evidence popup Detailed
        # Results uses (_show_row_detail) - these are real rows out of
        # self._rows, just a filtered/ranked subset (see
        # _worst_findings_rows in _refresh_worst_findings).
        self._worst_findings_table.addMouseListener(_WorstFindingsDoubleClickListener(self))
        # Reported directly: "add slider so i can navigae down" - its own
        # scrollbar (same pattern as coverage_scroll just above), instead
        # of every FAIL row just stretching the whole Summary tab taller
        # and taller.
        worst_scroll = JScrollPane(self._worst_findings_table)
        worst_scroll.setPreferredSize(Dimension(680, 260))
        worst_scroll.setAlignmentX(JPanel.LEFT_ALIGNMENT)
        worst_scroll.getVerticalScrollBar().setUnitIncrement(16)
        worst_box.add(worst_scroll)
        panel.add(worst_box)

        self._summary_coverage_mode = "cat"

        scroll = JScrollPane(panel)
        scroll.setBorder(BorderFactory.createEmptyBorder())
        scroll.getVerticalScrollBar().setUnitIncrement(16)
        return scroll

    def _build_categories_panel(self):
        panel = JPanel(BorderLayout())
        panel.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6))

        top = JPanel()
        top.setLayout(BoxLayout(top, BoxLayout.Y_AXIS))
        top.setBorder(BorderFactory.createEmptyBorder(0, 0, 8, 0))

        # Reported directly: "show the main KPIs in top always like
        # summary static ... when select the specific category change
        # the count in KPI accordingly" - these cards rescope to
        # whichever category/OWASP bucket is selected on the left
        # (All Categories by default = the same global totals Summary
        # shows), instead of staying fixed or duplicating small counts
        # elsewhere ("no need to keep count again in small icons").
        self._cat_scope_label = JLabel("Showing: All Categories")
        self._cat_scope_label.setFont(self._cat_scope_label.getFont().deriveFont(Font.BOLD, 11.5))
        self._cat_scope_label.setForeground(Color(0xB8, 0x56, 0x0F))
        self._cat_scope_label.setBorder(BorderFactory.createEmptyBorder(2, 2, 6, 2))
        self._cat_scope_label.setAlignmentX(JPanel.LEFT_ALIGNMENT)
        top.add(self._cat_scope_label)

        cards_row = JPanel(FlowLayout(FlowLayout.LEFT, 12, 6))
        self._cat_card_total = self._make_stat_card(
            "TOTAL CHECKS RUN", Color(0x2C, 0x3E, 0x50),
            lambda: self._apply_filter(self._cat_selected_categories, None, self._cat_selected_label))
        self._cat_card_pass = self._make_stat_card(
            "PASS", Color(0x1E, 0x7E, 0x34),
            lambda: self._apply_filter(self._cat_selected_categories, "PASS", self._cat_selected_label))
        self._cat_card_fail = self._make_stat_card(
            "FAIL (VULNERABLE)", Color(0xA4, 0x26, 0x2C),
            lambda: self._apply_filter(self._cat_selected_categories, "FAIL", self._cat_selected_label))
        self._cat_card_manual = self._make_stat_card(
            "MANUAL / INFO / ERROR", Color(0x8A, 0x6D, 0x00),
            lambda: self._apply_filter(self._cat_selected_categories, "OTHER", self._cat_selected_label))
        self._cat_card_categories = self._make_stat_card("CATEGORIES COVERED", Color(0x1F, 0x4E, 0x78))
        for card in (self._cat_card_total, self._cat_card_pass, self._cat_card_fail,
                     self._cat_card_manual, self._cat_card_categories):
            cards_row.add(card["panel"])
        cards_row.setAlignmentX(JPanel.LEFT_ALIGNMENT)
        # Same unbounded FlowLayout-row-under-BoxLayout gap bug as
        # Summary's cards_row - fixed here too for consistency.
        cards_row.setMaximumSize(Dimension(4000, 80))
        top.add(cards_row)

        hint = JLabel("Click a category on the left to change these numbers to just that category. Click a "
                       "number above (Total / Pass / Fail / Manual) to jump to Detailed Results filtered to it.")
        hint.setFont(hint.getFont().deriveFont(11.0))
        hint.setForeground(Color(0x66, 0x66, 0x66))
        hint.setBorder(BorderFactory.createEmptyBorder(2, 4, 6, 4))
        hint.setAlignmentX(JPanel.LEFT_ALIGNMENT)
        top.add(hint)

        bar_row = JPanel(BorderLayout())
        bar_row.setAlignmentX(JPanel.LEFT_ALIGNMENT)
        bar_row.setMaximumSize(Dimension(4000, 22))
        self._cat_progress_bar = JProgressBar(0, 100)
        self._cat_progress_bar.setStringPainted(True)
        self._cat_progress_bar.setString("0%")
        bar_row.add(self._cat_progress_bar, BorderLayout.CENTER)
        top.add(bar_row)

        self._cat_progress_detail_label = JLabel(" ")
        self._cat_progress_detail_label.setFont(self._cat_progress_detail_label.getFont().deriveFont(11.0))
        self._cat_progress_detail_label.setForeground(Color(0x66, 0x66, 0x66))
        self._cat_progress_detail_label.setBorder(BorderFactory.createEmptyBorder(3, 4, 0, 4))
        self._cat_progress_detail_label.setAlignmentX(JPanel.LEFT_ALIGNMENT)
        top.add(self._cat_progress_detail_label)

        panel.add(top, BorderLayout.NORTH)

        body = JPanel(BorderLayout())

        # --- Left column: All Categories / OWASP Top 10 mode toggle + list ---
        left = JPanel(BorderLayout())
        left.setPreferredSize(Dimension(270, 100))

        mode_row = JPanel(GridLayout(1, 2))
        # Reported directly: "change name from all categories to
        # vulnerability by categories" - this toggle's "flat list" mode
        # label (left column, top of Categories tab).
        self._cat_all_toggle = JToggleButton("Vulnerability by Categories", True)
        self._cat_owasp_toggle = JToggleButton("OWASP Top 10", False)
        cat_mode_group = ButtonGroup()
        cat_mode_group.add(self._cat_all_toggle)
        cat_mode_group.add(self._cat_owasp_toggle)
        self._cat_all_toggle.addActionListener(lambda e: self._on_cat_mode_changed("all"))
        self._cat_owasp_toggle.addActionListener(lambda e: self._on_cat_mode_changed("owasp"))
        mode_row.add(self._cat_all_toggle)
        mode_row.add(self._cat_owasp_toggle)
        left.add(mode_row, BorderLayout.NORTH)

        # Reported directly: "by default all test should pear if any
        # catarogy select then only those test case shuld be apear".
        # Index 0 is always "All Categories" / clears the scope back to
        # global; self._cat_list_keys/_cats/_labels are parallel arrays
        # (rebuilt by _refresh_categories_tab) so a list row can carry a
        # raw category name (All-Categories mode) or an OWASP bucket key
        # like "A03" (OWASP mode) without parsing it back out of the
        # display text (which also carries a pass/total count).
        self._populating_cat_list = True
        self._cat_list_keys = []
        self._cat_list_cats = []
        self._cat_list_labels = []
        self._cat_list_model = DefaultListModel()
        self._cat_list_model.addElement("All Categories")
        self._cat_list = JList(self._cat_list_model)
        self._cat_list.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        self._cat_list.setSelectedIndex(0)
        self._cat_list.addListSelectionListener(_CategoryListSelectionListener(self))
        self._populating_cat_list = False
        left.add(JScrollPane(self._cat_list), BorderLayout.CENTER)
        body.add(left, BorderLayout.WEST)

        # --- Right column: breakdown table, switches content with the mode ---
        right = JPanel(BorderLayout())
        right.setBorder(BorderFactory.createEmptyBorder(0, 10, 0, 0))
        self._cat_note_label = JLabel("Coverage by category (this scan's targets/session only, not the full "
                                       "ReportSystem master checklist). The selected category is highlighted "
                                       "below - double-click any row to jump straight to Detailed Results for it.")
        self._cat_note_label.setBorder(BorderFactory.createEmptyBorder(4, 4, 8, 4))
        right.add(self._cat_note_label, BorderLayout.NORTH)

        # ColoredTableModel (not a plain DefaultTableModel) specifically so
        # isCellEditable() is False - reported directly: "wehn I click it
        # is renaming it" - a plain DefaultTableModel's cells are editable
        # by default, so clicking a cell opened an in-place text edit box
        # instead of doing anything useful with the click.
        self._cat_table_model = ColoredTableModel(["Category", "Total", "Pass", "Fail", "Manual/Other"], 0)
        self._cat_table = JTable(self._cat_table_model)
        self._cat_table.setAutoCreateRowSorter(True)  # click any column header to sort
        cat_table_renderer = CategoryFailRenderer(self, "_cat_table_keys", "_cat_selected_key")
        self._cat_table.setDefaultRenderer(JObject, cat_table_renderer)
        self._cat_table.setDefaultRenderer(JInteger, cat_table_renderer)
        self._cat_table.setRowHeight(22)
        self._apply_coverage_table_widths(self._cat_table)
        # Reported directly: "it is not taking into the selected catagory
        # findings... not allowing to land the fineld items" - double-
        # click a row (category row, or OWASP bucket row) to jump to
        # Detailed Results filtered down to it.
        self._cat_table.addMouseListener(_CategoryTableDoubleClickListener(self))
        right.add(JScrollPane(self._cat_table), BorderLayout.CENTER)
        body.add(right, BorderLayout.CENTER)

        panel.add(body, BorderLayout.CENTER)

        self._cat_table_keys = []
        self._cat_table_cats = []
        self._cat_table_labels = []
        self._cat_mode = "all"
        self._cat_selected_key = "ALL"
        self._cat_selected_categories = None
        self._cat_selected_label = "All Categories"
        return panel

    def _apply_coverage_table_widths(self, table):
        # Explicit widths so numeric columns stay compact instead of
        # stretching to evenly fill the tab (reported: "alignment still
        # missgin") - Category/OWASP Category gets the room, the four
        # count columns don't need it. Re-applied any time a table's
        # column identifiers are rebuilt (setColumnIdentifiers() resets
        # column objects, which resets their preferred widths too).
        col_widths = {0: 300, 1: 70, 2: 70, 3: 70, 4: 110}
        for idx, width in col_widths.items():
            try:
                table.getColumnModel().getColumn(idx).setPreferredWidth(width)
            except Exception:
                pass

    def _build_results_panel(self):
        panel = JPanel(BorderLayout())
        panel.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6))
        self._results_table_model = ColoredTableModel(RESULT_COLUMNS, 0)
        self._results_table = JTable(self._results_table_model)
        self._results_table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION)
        # Reported directly: "apply sort so i can sor by falied or seqency
        # of id bases" - this turns on Swing's built-in click-a-column-
        # header-to-sort behaviour (toggles ascending/descending, click a
        # second column while holding Shift to sort by that as a tiebreak).
        # Click "Result" to group all FAILs together, or "ID" for checklist
        # sequence order.
        self._results_table.setAutoCreateRowSorter(True)
        # JObject (java.lang.Object, not Python's builtin object) is required
        # here - setDefaultRenderer keys off the column's Java Class, and a
        # plain DefaultTableModel reports every column's class as
        # Object.class, so this one registration colors every column.
        self._results_table.setDefaultRenderer(JObject, ResultRowRenderer())
        self._results_table.setRowHeight(22)
        # Explicit widths so ID/Severity/Priority/Result stay compact and
        # Test/Evidence/URL get the room they actually need, instead of
        # all 9 columns splitting the tab width evenly (reported:
        # "alignment still missgin"). RESULT_COLUMNS order:
        # ID, Category, Test, Severity, Priority, Result, Evidence, URL, Source.
        for idx, width in {0: 90, 1: 140, 2: 230, 3: 80, 4: 60, 5: 70, 6: 320, 7: 220, 8: 140}.items():
            self._results_table.getColumnModel().getColumn(idx).setPreferredWidth(width)
        # Reported directly: "not looks like the output you showed... i am
        # unable to check the request and response, and found what is the
        # messing" - the Evidence column is truncated to 300 chars for the
        # grid, so the real curl/nmap command + full response was never
        # visible in-app. Double-click a row to see it in full.
        self._results_table.addMouseListener(_ResultsTableDoubleClickListener(self))

        # Reported directly: "allow user to add manual search Input box"
        # - matches on ID / Category / Test / Evidence / URL, combines
        # with whatever category/result filter is active (see
        # _apply_row_filter()), and updates live as you type via
        # _SearchDocumentListener below.
        search_row = JPanel(FlowLayout(FlowLayout.LEFT, 6, 4))
        search_row.add(JLabel("Search:"))
        self._results_search_field = JTextField(24)
        self._results_search_field.getDocument().addDocumentListener(_SearchDocumentListener(self))
        search_row.add(self._results_search_field)
        search_hint = JLabel("matches ID / Category / Test / Evidence / URL - or type result=FAIL, "
                              "severity=High, category=..., etc. for an exact field match")
        search_hint.setFont(search_hint.getFont().deriveFont(11.0))
        search_hint.setForeground(Color(0x99, 0x99, 0x99))
        search_row.add(search_hint)

        # Shown/hidden by _apply_filter()/_clear_filter() - double-
        # clicking a category/OWASP row (or clicking a KPI card) on the
        # Summary/Categories tabs lands here with the table filtered;
        # click this banner to go back to showing everything.
        self._filter_label = JLabel(" ")
        self._filter_label.setOpaque(True)
        self._filter_label.setBackground(Color(0xFF, 0xF3, 0xCD))
        self._filter_label.setBorder(BorderFactory.createEmptyBorder(5, 8, 5, 8))
        self._filter_label.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR))
        self._filter_label.setVisible(False)
        self._filter_label.addMouseListener(_ClearFilterMouseListener(self))

        # BorderLayout (NORTH/SOUTH), not BoxLayout - a plain BorderLayout
        # slot always fills the full available width regardless of each
        # child's own alignmentX/maximumSize, sidestepping the BoxLayout
        # cross-axis alignment bug documented at length in
        # _build_config_panel above.
        north_wrap = JPanel(BorderLayout())
        north_wrap.add(search_row, BorderLayout.NORTH)
        north_wrap.add(self._filter_label, BorderLayout.SOUTH)
        panel.add(north_wrap, BorderLayout.NORTH)

        results_scroll = JScrollPane(self._results_table)
        results_scroll.setBorder(BorderFactory.createTitledBorder("Detailed Results (click a column header to "
                                                                    "sort, double-click a row for full evidence)"))
        panel.add(results_scroll, BorderLayout.CENTER)
        hint = JLabel("  Select one or more rows, then click 'Re-run Selected' above to re-test just those "
                       "Checklist IDs (against the same targets/session).")
        hint.setFont(hint.getFont().deriveFont(11.0))
        panel.add(hint, BorderLayout.SOUTH)
        return panel

    def _show_row_detail_from_event(self, event):
        view_row = self._results_table.rowAtPoint(event.getPoint())
        if view_row < 0:
            return
        model_row = self._results_table.convertRowIndexToModel(view_row)
        if model_row < 0 or model_row >= len(self._rows):
            return
        self._show_row_detail(self._rows[model_row])

    # ------------------------------------------------------------------
    # Categories tab: mode toggle, list selection, table double-click
    # ------------------------------------------------------------------
    def _on_cat_mode_changed(self, mode):
        self._cat_mode = mode
        self._refresh_categories_tab()

    def _on_category_list_selection(self):
        if getattr(self, "_populating_cat_list", False):
            return
        index = self._cat_list.getSelectedIndex()
        if index < 0 or index >= len(self._cat_list_keys):
            return
        key = self._cat_list_keys[index]
        cats = self._cat_list_cats[index]
        label = self._cat_list_labels[index]
        self._set_category_scope(cats, label, key)

    def _on_category_table_double_click(self, event):
        view_row = self._cat_table.rowAtPoint(event.getPoint())
        if view_row < 0:
            return
        model_row = self._cat_table.convertRowIndexToModel(view_row)
        if model_row < 0 or model_row >= len(self._cat_table_keys):
            return
        key = self._cat_table_keys[model_row]
        cats = self._cat_table_cats[model_row]
        label = self._cat_table_labels[model_row]
        self._set_category_scope(cats, label, key)
        self._apply_filter(cats, None, label)

    def _on_summary_coverage_table_double_click(self, event):
        view_row = self._summary_coverage_table.rowAtPoint(event.getPoint())
        if view_row < 0:
            return
        model_row = self._summary_coverage_table.convertRowIndexToModel(view_row)
        if model_row < 0 or model_row >= len(self._summary_coverage_table_cats):
            return
        cats = self._summary_coverage_table_cats[model_row]
        label = self._summary_coverage_table_labels[model_row]
        self._apply_filter(cats, None, label)

    def _on_summary_coverage_mode_changed(self, mode):
        self._summary_coverage_mode = mode
        self._refresh_summary_coverage_table()
        # Reported directly: "summary tab not dynamically updating" -
        # the top KPI cards (specifically "Categories Covered") need to
        # re-render scoped to whichever mode is now active too, same as
        # the Categories tab already does for its own toggle.
        self._update_summary_top_cards()

    def _set_category_scope(self, categories, label, key):
        # Reported directly: "by default select All categories" - cats
        # is None for the "All Categories"/"ALL" scope (no restriction);
        # otherwise a list of one or more real category names. Rescopes
        # the top KPI cards in place - does NOT navigate anywhere; that's
        # what clicking one of the KPI numbers or double-clicking a table
        # row is for.
        self._cat_selected_categories = categories
        self._cat_selected_label = label
        self._cat_selected_key = key
        if hasattr(self, "_cat_scope_label"):
            self._cat_scope_label.setText("Showing: %s" % label)
        self._update_categories_top_cards()
        if hasattr(self, "_cat_table"):
            self._cat_table.repaint()
        self._sync_cat_list_selection(key)

    def _sync_cat_list_selection(self, key):
        if not hasattr(self, "_cat_list_keys") or not hasattr(self, "_cat_list"):
            return
        target_index = 0
        for i, k in enumerate(self._cat_list_keys):
            if k == key:
                target_index = i
                break
        if self._cat_list.getSelectedIndex() == target_index:
            return
        self._populating_cat_list = True
        self._cat_list.setSelectedIndex(target_index)
        self._populating_cat_list = False

    # ------------------------------------------------------------------
    # Detailed Results filtering (category/group + result-type, combinable)
    # ------------------------------------------------------------------
    def _apply_filter(self, categories, result, label):
        self._filter_categories = categories
        self._filter_result = result
        self._apply_row_filter()
        self._update_filter_banner(label)
        self._tabs.setSelectedIndex(3)  # Detailed Results (Summary=0, Configuration=1, Categories=2)

    def _apply_row_filter(self):
        # Reported directly: "allow user to add manual search Input
        # box" - the search box is independent of (but combinable with)
        # the category/result quick-filter, so both _apply_filter() and
        # _on_search_text_changed() funnel through this one place to
        # rebuild the actual RowFilter from whatever's currently active.
        sorter = self._results_table.getRowSorter()
        if sorter is None:
            return
        if self._filter_categories or self._filter_result or self._filter_search_text:
            sorter.setRowFilter(_ResultCategoryRowFilter(
                self._filter_categories, self._filter_result, self._filter_search_text))
        else:
            sorter.setRowFilter(None)

    def _on_search_text_changed(self):
        text = self._results_search_field.getText() or ""
        self._filter_search_text = text.strip().lower()
        self._apply_row_filter()

    def _update_filter_banner(self, label):
        if not self._filter_categories and not self._filter_result:
            self._filter_label.setVisible(False)
            return
        parts = []
        if self._filter_categories:
            cat_label = label or ", ".join(self._filter_categories)
            is_group = len(self._filter_categories) > 1
            parts.append(("Category group = %s" if is_group else "Category = %s") % cat_label)
        if self._filter_result:
            result_text = "MANUAL/INFO/ERROR" if self._filter_result == "OTHER" else self._filter_result
            parts.append("Result = %s" % result_text)
        self._filter_label.setText("  Showing: %s  -  click here to clear this filter and see all rows again"
                                    % ", ".join(parts))
        self._filter_label.setVisible(True)

    def _clear_filter(self):
        self._filter_categories = None
        self._filter_result = None
        self._filter_search_text = ""
        if hasattr(self, "_results_search_field") and self._results_search_field.getText():
            self._results_search_field.setText("")  # triggers _on_search_text_changed, harmless/idempotent
        sorter = self._results_table.getRowSorter()
        if sorter is not None:
            sorter.setRowFilter(None)
        self._filter_label.setVisible(False)
        self._set_category_scope(None, "All Categories", "ALL")

    def _show_row_detail(self, row):
        result = row.get("result", "")
        accent = RESULT_ACCENT_COLORS.get(result, Color(0x33, 0x33, 0x33))

        header = JPanel(BorderLayout())
        header.setBackground(accent)
        header_label = JLabel("  %s  -  %s  -  %s" % (result or "?", row.get("id", ""), row.get("test", "")))
        header_label.setForeground(Color.WHITE)
        header_label.setFont(Font("Monospaced", Font.BOLD, 14))
        header_label.setBorder(BorderFactory.createEmptyBorder(8, 4, 8, 4))
        header.add(header_label, BorderLayout.WEST)

        pane = JTextPane()
        pane.setEditable(False)
        pane.setBackground(Color(0x0C, 0x0C, 0x0C))
        pane.setFont(Font("Monospaced", Font.PLAIN, 12))
        doc = pane.getStyledDocument()

        def make_style(color, bold=False):
            attrs = SimpleAttributeSet()
            StyleConstants.setForeground(attrs, color)
            StyleConstants.setBold(attrs, bold)
            return attrs

        label_style = make_style(Color(0x57, 0xE3, 0x89), True)   # field labels + section headers - green, bold
        field_style = make_style(Color(0x9A, 0xA5, 0xB1))         # field values - muted gray-blue
        body_style = make_style(Color(0xE0, 0xE0, 0xE0))          # evidence body text - light gray
        prompt_style = make_style(Color(0x57, 0xE3, 0x89), True)  # "$ curl ..." command lines - green, bold

        def append(text, style):
            try:
                doc.insertString(doc.getLength(), text, style)
            except Exception:
                pass

        for label, value in (
            ("ID", row.get("id", "")), ("Test", row.get("test", "")),
            ("Category", row.get("category", "")),
            ("Severity", "%s (%s)" % (row.get("severity", ""), row.get("priority", ""))),
            ("Result", result), ("URL", row.get("url", "")),
            ("URL Role", row.get("url_role", "")), ("Checked At", row.get("checked_at", "")),
        ):
            append("%-12s" % (label + ":"), label_style)
            append("%s\n" % value, field_style)

        append("\nEvidence (full, untruncated):\n", label_style)
        evidence = row.get("evidence", "") or "(no evidence text)"
        for line in evidence.splitlines() or [""]:
            append(line + "\n", prompt_style if line.startswith("$ ") else body_style)

        pane.setCaretPosition(0)
        scroll = JScrollPane(pane)
        scroll.setPreferredSize(Dimension(900, 560))

        container = JPanel(BorderLayout())
        container.add(header, BorderLayout.NORTH)
        container.add(scroll, BorderLayout.CENTER)

        JOptionPane.showMessageDialog(self._main_panel, container,
                                       "%s - %s" % (row.get("id", ""), row.get("test", "")),
                                       JOptionPane.PLAIN_MESSAGE)

    def _build_burp_findings_panel(self):
        panel = JPanel(BorderLayout())
        panel.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6))
        # Plain text, deliberately no <html> markup - see the note on
        # _make_stat_card() above for why (the old Summary tab's HTML
        # label rendered its raw "<html><b>...</b>" tags on screen
        # instead of formatting them). Reported directly (again, on THIS
        # exact label): "htmls code is not renderd properly" - two plain
        # JLabels instead of one <html>...<br>...</html> label fixes it
        # the same way the rest of the file already does it.
        top = JPanel()
        top.setLayout(BoxLayout(top, BoxLayout.Y_AXIS))
        note1 = JLabel("Burp Scanner's own findings for these targets (requires Burp Pro's Scanner to have "
                        "already run). Shown for cross-reference only - Burp's issue names don't carry a real "
                        "WPT checklist ID, so they aren't auto-counted in the Summary KPIs or ReportSystem export.")
        note1.setBorder(BorderFactory.createEmptyBorder(4, 4, 0, 4))
        note1.setAlignmentX(JPanel.LEFT_ALIGNMENT)
        top.add(note1)
        note2 = JLabel("Double-click a row for the full detail. Select a row and click 'Add selected to "
                        "QuickChop tracked list...' to confirm which checklist ID it maps to - that's what makes "
                        "it count.")
        note2.setBorder(BorderFactory.createEmptyBorder(0, 4, 8, 4))
        note2.setAlignmentX(JPanel.LEFT_ALIGNMENT)
        top.add(note2)
        burp_btn_row = JPanel(FlowLayout(FlowLayout.LEFT))
        self._burp_add_to_tracked_btn = JButton("Add selected to QuickChop tracked list...")
        self._burp_add_to_tracked_btn.addActionListener(self._on_add_burp_finding_to_tracked)
        burp_btn_row.add(self._burp_add_to_tracked_btn)
        burp_btn_row.setAlignmentX(JPanel.LEFT_ALIGNMENT)
        # Same unbounded-FlowLayout-row-under-BoxLayout gap bug as
        # Summary's rows (see _build_summary_panel) - bounded here too.
        burp_btn_row.setMaximumSize(Dimension(4000, 40))
        top.add(burp_btn_row)
        panel.add(top, BorderLayout.NORTH)
        self._burp_issues_model = ColoredTableModel(["Severity", "Confidence", "Issue", "URL", "Detail"], 0)
        self._burp_table = JTable(self._burp_issues_model)
        self._burp_table.setAutoCreateRowSorter(True)
        self._burp_table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        # Reported directly: "when I double click it is not openign
        # related record like scanner page does" - same double-click ->
        # full-detail-popup pattern as Detailed Results (_show_row_detail)
        # and the Summary/Categories coverage tables, now here too.
        self._burp_table.addMouseListener(_BurpFindingsDoubleClickListener(self))
        burp_scroll = JScrollPane(self._burp_table)
        burp_scroll.setBorder(BorderFactory.createTitledBorder("Burp Scanner Findings (context only)"))
        panel.add(burp_scroll, BorderLayout.CENTER)
        return panel

    def _burp_issue_for_view_row(self, view_row):
        if view_row < 0:
            return None
        model_row = self._burp_table.convertRowIndexToModel(view_row)
        if model_row < 0 or model_row >= len(self._burp_issues_raw):
            return None
        return self._burp_issues_raw[model_row]

    def _show_burp_issue_detail(self, issue):
        # Same visual language as _show_row_detail (colored banner +
        # monospace body) so this reads as the same kind of popup, just
        # for a Burp Scanner issue instead of a QuickChop checklist row.
        severity = issue.get("severity", "")
        accent = SEVERITY_ACCENT_COLORS.get(severity, RESULT_ACCENT_COLORS.get("FAIL"))

        header = JPanel(BorderLayout())
        header.setBackground(accent)
        header_label = JLabel("  %s  -  %s" % (severity or "?", issue.get("issue", "")))
        header_label.setForeground(Color.WHITE)
        header_label.setFont(Font("Monospaced", Font.BOLD, 14))
        header_label.setBorder(BorderFactory.createEmptyBorder(8, 4, 8, 4))
        header.add(header_label, BorderLayout.WEST)

        pane = JTextPane()
        pane.setEditable(False)
        pane.setBackground(Color(0x0C, 0x0C, 0x0C))
        pane.setFont(Font("Monospaced", Font.PLAIN, 12))
        doc = pane.getStyledDocument()

        def make_style(color, bold=False):
            attrs = SimpleAttributeSet()
            StyleConstants.setForeground(attrs, color)
            StyleConstants.setBold(attrs, bold)
            return attrs

        label_style = make_style(Color(0x57, 0xE3, 0x89), True)
        field_style = make_style(Color(0x9A, 0xA5, 0xB1))
        body_style = make_style(Color(0xE0, 0xE0, 0xE0))

        def append(text, style):
            try:
                doc.insertString(doc.getLength(), text, style)
            except Exception:
                pass

        for label, value in (
            ("Issue", issue.get("issue", "")), ("Severity", severity),
            ("Confidence", issue.get("confidence", "")), ("URL", issue.get("url", "")),
        ):
            append("%-12s" % (label + ":"), label_style)
            append("%s\n" % value, field_style)

        append("\nDetail (full, untruncated):\n", label_style)
        detail = issue.get("detail_full", "") or "(no detail text)"
        for line in detail.splitlines() or [""]:
            append(line + "\n", body_style)

        # Reported directly: "request and response detals cptured here
        # for burp scaner resutls" - Burp's own IScanIssue carries the
        # real request/response it based the finding on
        # (getHttpMessages(), captured in _on_pull_burp_issues) - shown
        # here the same way Detailed Results shows real curl/captured
        # evidence, instead of just the prose Detail text above.
        req_full = issue.get("req_full", "")
        resp_full = issue.get("resp_full", "")
        if req_full or resp_full:
            if req_full:
                append("\nRequest captured (full, untruncated):\n", label_style)
                for line in req_full.splitlines() or [""]:
                    append(line + "\n", body_style)
            if resp_full:
                append("\nResponse captured (full, untruncated):\n", label_style)
                for line in resp_full.splitlines() or [""]:
                    append(line + "\n", body_style)
        else:
            append("\n(No request/response captured for this issue by Burp Scanner.)\n", field_style)

        pane.setCaretPosition(0)
        scroll = JScrollPane(pane)
        scroll.setPreferredSize(Dimension(900, 560))

        container = JPanel(BorderLayout())
        container.add(header, BorderLayout.NORTH)
        container.add(scroll, BorderLayout.CENTER)

        JOptionPane.showMessageDialog(self._main_panel, container,
                                       "Burp Scanner - %s" % issue.get("issue", ""),
                                       JOptionPane.PLAIN_MESSAGE)

    def _show_burp_issue_detail_from_event(self, event):
        view_row = self._burp_table.rowAtPoint(event.getPoint())
        issue = self._burp_issue_for_view_row(view_row)
        if issue is not None:
            self._show_burp_issue_detail(issue)

    def _on_add_burp_finding_to_tracked(self, event):
        view_row = self._burp_table.getSelectedRow()
        if view_row < 0:
            JOptionPane.showMessageDialog(self._main_panel,
                                           "Select a row in 'Burp Scanner Findings' first.",
                                           EXT_NAME, JOptionPane.WARNING_MESSAGE)
            return
        issue = self._burp_issue_for_view_row(view_row)
        if issue is None:
            return
        severity = issue.get("severity", "")
        # Burp Scanner's own severities (High/Medium/Low/Information) are
        # a different vocabulary than the checklist Result column
        # (PASS/FAIL/MANUAL/INFO) - a reasonable starting guess, always
        # editable in the dialog before saving.
        default_result = "FAIL" if severity in ("High", "Medium") else "INFO"
        context_label_text = "Burp Scanner  -  %s  -  %s  -  %s" % (
            severity or "?", issue.get("issue", ""), issue.get("url", ""))
        evidence_prefill_text = "Confirmed via Burp Scanner (%s confidence, %s severity).\n%s\n\nDetail:\n%s" % (
            issue.get("confidence", "?"), severity or "?", issue.get("url", ""),
            (issue.get("detail_full", "") or "")[:4000])
        # Reported directly: "request and response detals cptured here
        # for burp scaner resutls" - carry the same real request/response
        # (captured in _on_pull_burp_issues via IScanIssue.getHttpMessages())
        # into the tracked-list evidence too, same as the Repeater/Proxy/
        # Intruder "Log finding to QuickChop" flow already does.
        req_full = issue.get("req_full", "")
        resp_full = issue.get("resp_full", "")
        if req_full:
            evidence_prefill_text += "\n\n---- Request captured ----\n" + req_full[:4000]
        if resp_full:
            evidence_prefill_text += "\n\n---- Response captured ----\n" + resp_full[:4000]
        self._show_log_finding_dialog(context_label_text, issue.get("url", ""), evidence_prefill_text,
                                       "Burp Scanner", default_result=default_result)

    def _build_checklist_reference_panel(self):
        # Reported directly: "reference sho all the check list items with
        # name ows id default sevarity etc" - a browsable/searchable list
        # of every one of the 421 Web App Checklist items (not just the
        # ~77 the automated engine covers), independent of any scan
        # having run, plus its own CSV export so the full reference can be
        # handed off on its own (see MASTER_CHECKLIST / AUTOMATED_CHECKLIST_IDS
        # near the top of this file for where this data comes from).
        panel = JPanel(BorderLayout())
        panel.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6))

        top = JPanel()
        top.setLayout(BoxLayout(top, BoxLayout.Y_AXIS))
        note = JLabel("All %d Web App Checklist items - ID, category, OWASP mapping, default severity/priority, "
                       "and whether Run All Tests already automates it. Independent of any scan you've run."
                       % len(MASTER_CHECKLIST))
        note.setBorder(BorderFactory.createEmptyBorder(2, 2, 6, 2))
        note.setAlignmentX(JPanel.LEFT_ALIGNMENT)
        top.add(note)

        search_row = JPanel(FlowLayout(FlowLayout.LEFT, 6, 0))
        search_row.add(JLabel("Search (ID / category / test name):"))
        self._checklist_ref_search_field = JTextField(30)
        search_row.add(self._checklist_ref_search_field)
        self._checklist_ref_export_btn = JButton("Export checklist reference -> CSV")
        self._checklist_ref_export_btn.addActionListener(self._on_export_checklist_reference)
        search_row.add(self._checklist_ref_export_btn)
        search_row.setAlignmentX(JPanel.LEFT_ALIGNMENT)
        # Same unbounded-FlowLayout-row-under-BoxLayout gap bug as Summary's
        # rows (see _build_summary_panel) - bounded here too from the start.
        search_row.setMaximumSize(Dimension(4000, 40))
        top.add(search_row)
        panel.add(top, BorderLayout.NORTH)

        self._checklist_ref_model = ColoredTableModel(
            ["ID", "Category", "OWASP Category", "Test Name", "Default Severity", "Priority", "Automated"], 0)
        ref_table = JTable(self._checklist_ref_model)
        ref_table.setAutoCreateRowSorter(True)
        ref_table.setRowHeight(22)
        col_model = ref_table.getColumnModel()
        for idx, width in ((0, 90), (1, 160), (2, 170), (4, 110), (5, 60), (6, 80)):
            col_model.getColumn(idx).setPreferredWidth(width)
        # Reported directly: "add color codeing for severaity" - Default
        # Severity is column index 4.
        col_model.getColumn(4).setCellRenderer(_SeverityTextRenderer())
        ref_scroll = JScrollPane(ref_table)
        panel.add(ref_scroll, BorderLayout.CENTER)

        def refresh():
            query = (self._checklist_ref_search_field.getText() or "").strip().lower()
            self._checklist_ref_model.setRowCount(0)
            for cid, category, test, severity, priority in MASTER_CHECKLIST:
                haystack = (cid + " " + category + " " + test).lower()
                if query and query not in haystack:
                    continue
                owasp_key = OWASP_CATEGORY_MAP.get(category, OWASP_OTHER_KEY)
                owasp_label = OWASP_GROUPS_BY_KEY.get(owasp_key, owasp_key)
                automated = "Yes" if cid in AUTOMATED_CHECKLIST_IDS else "No"
                self._checklist_ref_model.addRow([cid, category, owasp_label, test, severity, priority, automated])

        self._checklist_ref_search_field.getDocument().addDocumentListener(_CallbackDocumentListener(refresh))
        refresh()
        return panel

    def _on_export_checklist_reference(self, event):
        chooser = JFileChooser()
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY)
        chooser.setDialogTitle("Choose a folder to save the checklist reference CSV into")
        if chooser.showSaveDialog(self._main_panel) != JFileChooser.APPROVE_OPTION:
            return
        dest_dir = chooser.getSelectedFile().getAbsolutePath()
        path = os.path.join(dest_dir, "quickchop_checklist_reference_%s.csv" % str(int(time.time())))
        try:
            with open(path, "wb") as f:
                writer = csv.writer(f)
                writer.writerow(["ID", "Category", "OWASP Category", "Test Name",
                                  "Default Severity", "Priority", "Automated"])
                for cid, category, test, severity, priority in MASTER_CHECKLIST:
                    owasp_key = OWASP_CATEGORY_MAP.get(category, OWASP_OTHER_KEY)
                    owasp_label = OWASP_GROUPS_BY_KEY.get(owasp_key, owasp_key)
                    automated = "Yes" if cid in AUTOMATED_CHECKLIST_IDS else "No"
                    writer.writerow([
                        cid.encode("utf-8", "replace"), category.encode("utf-8", "replace"),
                        owasp_label.encode("utf-8", "replace"), test.encode("utf-8", "replace"),
                        severity.encode("utf-8", "replace"), priority.encode("utf-8", "replace"),
                        automated.encode("utf-8", "replace"),
                    ])
            self._set_status("Exported the full %d-item checklist reference to %s" % (len(MASTER_CHECKLIST), path))
        except Exception as e:
            self._callbacks.printError("Checklist reference export failed: %s" % e)
            JOptionPane.showMessageDialog(self._main_panel, "Export failed: %s" % e,
                                           EXT_NAME, JOptionPane.ERROR_MESSAGE)

    def _build_status_bar(self):
        self._status_label = JLabel("Ready.")
        self._status_label.setBorder(BorderFactory.createEmptyBorder(4, 8, 4, 8))
        return self._status_label

    def _materialize_engine_script(self, out_dir):
        """Decode the embedded _ENGINE_SOURCE_B64 (checklist_auto_scan.py's
        full source - see the constant's definition near the top of this
        file) out to a real .py file on disk, and return its path.

        Reported directly: "make it one file instead of two python files
        so it is easy to share with burp extension marketplace without
        the dependency or need to share autoscan script separately" -
        this is what makes that true: the engine's source now travels
        INSIDE WPTChecklistScanner.py, so there's nothing second to
        install/lose/version-mismatch. It still has to land on disk as a
        real file before this can shell out to it though - Jython can't
        execute embedded CPython-3-only source in-process (see this
        file's module docstring for why the subprocess split exists at
        all: pandas/xlsxwriter/requests aren't importable under Jython).
        Written fresh into the SAME output folder as this run's other
        artifacts every time (cheap, and guarantees it's always exactly
        the version embedded in the extension currently loaded - no
        stale copy from a previous QuickChop version can linger)."""
        import base64
        engine_path = os.path.join(out_dir, "quickchop_engine.py")
        try:
            source_bytes = base64.b64decode(_ENGINE_SOURCE_B64)
            with open(engine_path, "wb") as f:
                f.write(source_bytes)
        except Exception as e:
            raise Exception("Could not write the bundled scan engine to %s: %s" % (engine_path, e))
        return engine_path

    # ------------------------------------------------------------------
    # Config panel button handlers
    # ------------------------------------------------------------------
    def _on_browse_output_dir(self, event):
        chooser = JFileChooser()
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY)
        if chooser.showOpenDialog(self._main_panel) == JFileChooser.APPROVE_OPTION:
            self._output_dir_field.setText(chooser.getSelectedFile().getAbsolutePath())

    def _on_pull_targets(self, event):
        try:
            history = self._callbacks.getProxyHistory()
        except Exception as e:
            self._set_status("Could not read Proxy history: %s" % e)
            return
        full_urls = self._pull_full_urls_checkbox.isSelected()
        cap = 100 if full_urls else 50
        seen = set()
        bases = []
        for item in history:
            try:
                url = self._helpers.analyzeRequest(item).getUrl()
                if not self._callbacks.isInScope(url):
                    continue
                if full_urls:
                    # Full URL, path included, query string stripped (a
                    # query string on its own doesn't change which
                    # checklist items apply, and would otherwise blow up
                    # the distinct-URL count with near-duplicates).
                    entry = "%s://%s%s" % (url.getProtocol(), url.getAuthority(), url.getPath() or "/")
                else:
                    # One entry per distinct HOST only (default) - almost
                    # all checklist items are host-level (headers/SSL/
                    # cookies/etc.), so this is normal/expected to
                    # collapse to a single row for a single-host
                    # engagement, not a bug.
                    entry = "%s://%s" % (url.getProtocol(), url.getAuthority())
                if entry not in seen:
                    seen.add(entry)
                    bases.append(entry)
            except Exception:
                continue
            if len(bases) >= cap:
                break
        if not bases:
            self._set_status("No in-scope requests found in Proxy history yet. Browse the target through Burp's "
                              "Proxy first (Target > Scope must be set), then try again - or just type URLs "
                              "directly into the Targets box.")
            return
        self._targets_area.setText("\n".join(bases))
        self._set_status("Pulled %d in-scope target(s) from Proxy history%s." % (
            len(bases), " (full URLs)" if full_urls else " (one per host - tick 'Pull full URLs' for paths too)"))

    def _on_capture_session(self, event):
        try:
            history = self._callbacks.getProxyHistory()
        except Exception as e:
            self._set_status("Could not read Proxy history: %s" % e)
            return
        captured_cookie = None
        captured_auth = None
        # Walk from most recent backwards so we pick up your latest session.
        for item in reversed(list(history)):
            try:
                req = self._helpers.analyzeRequest(item)
                url = req.getUrl()
                if not self._callbacks.isInScope(url):
                    continue
                for h in req.getHeaders():
                    if h.lower().startswith("cookie:") and not captured_cookie:
                        captured_cookie = h.split(":", 1)[1].strip()
                    if h.lower().startswith("authorization:") and not captured_auth:
                        captured_auth = h.strip()
                if captured_cookie or captured_auth:
                    break
            except Exception:
                continue
        if captured_cookie:
            self._cookie_field.setText(captured_cookie)
        if captured_auth:
            self._extra_header_field.setText(captured_auth)
        if not captured_cookie and not captured_auth:
            self._set_status("No Cookie/Authorization header found on any in-scope request yet - browse an "
                              "authenticated page through Burp's Proxy first, or paste your session Cookie "
                              "manually above.")
        else:
            self._set_status("Session captured from Proxy history (Cookie%s). Values are used locally when "
                              "invoking checklist_auto_scan.py - never sent anywhere else." %
                              (" + Authorization" if captured_auth else ""))

    def _on_pull_burp_issues(self, event):
        targets = self._get_target_list()
        prefix = targets[0] if targets else None
        try:
            issues = self._callbacks.getScanIssues(prefix)
        except Exception as e:
            self._set_status("Could not read Burp Scanner issues: %s" % e)
            return
        self._burp_issues_model.setRowCount(0)
        # Reported directly: "when I double click it is not openign
        # related record like scanner page does" and separately "why burp
        # findigns are not adding a vulnerabilityes and updating the
        # KPIS" - the table only ever held the truncated (400-char)
        # display strings, nothing to show a full-detail popup from or to
        # hand off to the "Log finding to QuickChop" dialog. Keep the
        # untruncated detail text per row here, in the SAME order as
        # addRow() below, so a table row index (even after the user
        # re-sorts the view - see convertRowIndexToModel in the
        # double-click/add-to-tracked handlers) can look its full record
        # back up.
        self._burp_issues_raw = []
        if not issues:
            self._set_status("No Burp Scanner issues found for prefix %r - this needs Burp Pro's Scanner to have "
                              "already run against the target (passive or active)." % prefix)
            return
        for issue in issues:
            try:
                detail_full = re.sub("<[^>]+>", " ", issue.getIssueDetail() or "").strip()
                severity = issue.getSeverity()
                confidence = issue.getConfidence()
                issue_name = issue.getIssueName()
                url = str(issue.getUrl())
                # Reported directly: "request and response detals cptured
                # here for burp scaner resutls" - IScanIssue carries the
                # actual request/response pair(s) Burp Scanner based the
                # finding on (getHttpMessages()), same idea as the real
                # request/response capture already added for the Log
                # finding to QuickChop dialog (see
                # _open_log_finding_dialog) - just from Burp's own Scan
                # Issue object instead of a right-clicked message. Only
                # the FIRST message pair is captured (an issue can carry
                # several near-identical ones; one real example is enough
                # evidence and keeps this from ballooning).
                req_full_text, resp_full_text = "", ""
                try:
                    msgs = issue.getHttpMessages()
                    if msgs:
                        msg = msgs[0]
                        req_bytes = msg.getRequest()
                        if req_bytes is not None:
                            req_full_text = self._helpers.bytesToString(req_bytes)
                        resp_bytes = msg.getResponse()
                        if resp_bytes is not None:
                            resp_full_text = self._helpers.bytesToString(resp_bytes)
                except Exception:
                    pass
                self._burp_issues_model.addRow([severity, confidence, issue_name, url, detail_full[:400]])
                self._burp_issues_raw.append({
                    "severity": severity, "confidence": confidence, "issue": issue_name,
                    "url": url, "detail_full": detail_full,
                    "req_full": req_full_text, "resp_full": resp_full_text,
                })
            except Exception:
                continue
        self._set_status("Pulled %d Burp Scanner issue(s) for cross-reference. Double-click a row for full detail, "
                          "or select one and use 'Add selected to QuickChop tracked list...' to map it to a real "
                          "checklist ID (that's what makes it count toward the KPIs/export - see the tab's note "
                          "above for why they aren't included automatically)." % len(issues))

    # ------------------------------------------------------------------
    # Context menu: "Log finding to QuickChop" (Proxy/Repeater/Intruder/
    # Target/Scanner - anywhere Burp shows a right-click menu on HTTP
    # traffic). Reported directly: "when I can confirm the test XSS in
    # repeater or proxy or intruder selected output can be moved to
    # quickchop for a record vulnerability list so we understand how many
    # findings have been covered."
    # ------------------------------------------------------------------
    def _tool_name_for_flag(self, flag):
        """Maps IBurpExtenderCallbacks.TOOL_* int constants to a readable
        name for the "source" field on a manually-logged row (e.g.
        "Manual (Repeater)") - built once, lazily, off self._callbacks
        rather than hardcoded, so it stays correct across Burp versions
        that might add/renumber tool flags."""
        if not hasattr(self, "_tool_flag_names"):
            names = {}
            for attr in ("TOOL_PROXY", "TOOL_REPEATER", "TOOL_INTRUDER", "TOOL_SCANNER",
                         "TOOL_TARGET", "TOOL_SPIDER", "TOOL_SEQUENCER", "TOOL_DECODER",
                         "TOOL_COMPARER", "TOOL_EXTENDER"):
                try:
                    names[getattr(self._callbacks, attr)] = attr[len("TOOL_"):].title()
                except Exception:
                    pass
            self._tool_flag_names = names
        return self._tool_flag_names.get(flag, "Burp")

    def createMenuItems(self, invocation):
        item = JMenuItem("Log finding to QuickChop...")
        item.addActionListener(lambda event, inv=invocation: self._open_log_finding_dialog(inv))
        return [item]

    def _open_log_finding_dialog(self, invocation):
        # Best-effort context extraction - ANY failure here (unexpected
        # Burp API behaviour for a given tool/context, no response yet,
        # etc.) must still let the dialog open with what it has rather
        # than not open at all, since typing the URL/evidence by hand is
        # a fine fallback and a silent crash here is not.
        tool_name = "Burp"
        url_text, method_text, status_text, selected_text = "", "", "", ""
        req_full_text, resp_full_text = "", ""
        messages = None
        try:
            tool_name = self._tool_name_for_flag(invocation.getToolFlag())
        except Exception:
            pass
        try:
            messages = invocation.getSelectedMessages()
        except Exception:
            messages = None
        if messages:
            try:
                msg = messages[0]
                req_info = self._helpers.analyzeRequest(msg)
                url_text = str(req_info.getUrl())
                method_text = req_info.getMethod()
                resp = msg.getResponse()
                if resp is not None:
                    status_text = str(self._helpers.analyzeResponse(resp).getStatusCode())
                # If the user had actually highlighted text in the request/
                # response editor when they right-clicked (rather than just
                # right-clicking a list row), pull that exact highlighted
                # text in as the starting evidence - it's very likely the
                # payload/response snippet that convinced them this is a
                # real finding.
                bounds = invocation.getSelectionBounds()
                ctx = invocation.getInvocationContext()
                if bounds and bounds[1] > bounds[0]:
                    raw = None
                    if ctx == invocation.CONTEXT_MESSAGE_EDITOR_REQUEST:
                        raw = msg.getRequest()
                    elif ctx == invocation.CONTEXT_MESSAGE_EDITOR_RESPONSE:
                        raw = resp
                    if raw is not None:
                        selected_text = self._helpers.bytesToString(raw[bounds[0]:bounds[1]])
                # Reported directly: "I didn't see the request and response
                # detail of the original, you can add the below box
                # request and response details captured" - a manually
                # logged finding previously only got the generic
                # "Confirmed via <tool>. METHOD url -> HTTP nnn" line, with
                # none of the actual request/response bytes, unlike the
                # automated engine's evidence which always includes a real
                # curl-command/response block. Capture the FULL raw
                # request/response here (not just a user-highlighted
                # snippet, which is the fallback above and stays empty
                # unless the user deliberately drags a selection first) so
                # every manually-logged finding gets real, original
                # request/response detail by default.
                try:
                    req_bytes = msg.getRequest()
                    if req_bytes is not None:
                        req_full_text = self._helpers.bytesToString(req_bytes)
                except Exception:
                    req_full_text = ""
                try:
                    if resp is not None:
                        resp_full_text = self._helpers.bytesToString(resp)
                except Exception:
                    resp_full_text = ""
            except Exception:
                pass

        context_label_text = "%s%s%s" % (
            tool_name, "  -  %s %s" % (method_text, url_text) if url_text else "",
            "  -  HTTP %s" % status_text if status_text else "")

        # Reported directly: "output is not a command line or request
        # response bases it just a stament" (about the automated engine's
        # WA-OTG-289 evidence, fixed earlier) and now the same complaint
        # for manual findings: "I didn't see the request and response
        # detail of the original, you can add the below box request and
        # response details captured" - cap each side at a generous but
        # bounded size so one huge response body can't make the evidence
        # field unusably long or blow up the export file.
        MAX_CAPTURE_CHARS = 4000
        capture_parts = []
        if req_full_text:
            capture_parts.append(
                "---- Request captured ----\n" + req_full_text[:MAX_CAPTURE_CHARS] +
                ("\n... (truncated)" if len(req_full_text) > MAX_CAPTURE_CHARS else ""))
        if resp_full_text:
            capture_parts.append(
                "---- Response captured ----\n" + resp_full_text[:MAX_CAPTURE_CHARS] +
                ("\n... (truncated)" if len(resp_full_text) > MAX_CAPTURE_CHARS else ""))
        captured_block = "\n\n".join(capture_parts)

        prefill_parts = ["Confirmed via %s." % tool_name]
        if url_text:
            prefill_parts.append("%s %s" % (method_text, url_text) + (" -> HTTP %s" % status_text if status_text else ""))
        if selected_text:
            prefill_parts.append("\nHighlighted evidence:\n" + selected_text[:2000])
        if captured_block:
            prefill_parts.append("\n" + captured_block)
        evidence_prefill_text = "\n".join(prefill_parts)

        self._show_log_finding_dialog(context_label_text, url_text, evidence_prefill_text, tool_name)

    def _show_log_finding_dialog(self, context_label_text, url_text, evidence_prefill_text, tool_name,
                                  default_result="FAIL"):
        """The actual checklist-ID-picker dialog (search box + JList of
        all 421 items + Result + Evidence), shared by both call sites:
        _open_log_finding_dialog (Repeater/Proxy/Intruder right-click) and
        _on_add_burp_finding_to_tracked (the Burp Scanner Findings tab's
        "Add selected to QuickChop tracked list..." button) - reported
        directly: "why burp findigns are not adding a vulnerabilityes and
        updating the KPIS" - Burp Scanner's own issues don't carry real
        WPT checklist IDs, so they can't be auto-merged into the tracked
        list/KPIs without guessing a mapping; this dialog is the
        human-in-the-loop way to confirm which checklist ID a given
        finding (from either source) actually corresponds to."""
        context_label = JLabel(context_label_text)
        context_label.setFont(context_label.getFont().deriveFont(Font.BOLD))
        context_label.setAlignmentX(JPanel.LEFT_ALIGNMENT)

        search_field = JTextField(30)
        search_field.setAlignmentX(JPanel.LEFT_ALIGNMENT)
        list_model = DefaultListModel()
        id_list = JList(list_model)
        id_list.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        id_list.setVisibleRowCount(9)
        list_scroll = JScrollPane(id_list)
        list_scroll.setAlignmentX(JPanel.LEFT_ALIGNMENT)

        # Row entries: "ID - Category - Test Name" (+ a marker for the
        # ~77 IDs checklist_auto_scan.py already automates, so logging one
        # of those manually is a deliberate override, not confusion about
        # what's left to cover) - filtered live as you type (matches on
        # ID/Category/Test, same "field:value" idea as Detailed Results'
        # own search box).
        def row_label(entry):
            _id, cat, test, sev, pri = entry
            tag = "  [automated]" if _id in AUTOMATED_CHECKLIST_IDS else ""
            return "%s - %s - %s%s" % (_id, cat, test, tag)

        filtered = list(MASTER_CHECKLIST)

        def refresh_list():
            query = (search_field.getText() or "").strip().lower()
            list_model.clear()
            del filtered[:]
            for entry in MASTER_CHECKLIST:
                haystack = (entry[0] + " " + entry[1] + " " + entry[2]).lower()
                if not query or query in haystack:
                    filtered.append(entry)
            for entry in filtered[:200]:  # cap the visible list - typing narrows it further
                list_model.addElement(row_label(entry))
            if len(filtered) > 200:
                list_model.addElement("... %d more - keep typing to narrow it down ..." % (len(filtered) - 200))

        search_field.getDocument().addDocumentListener(_CallbackDocumentListener(refresh_list))
        refresh_list()

        selected_entry_holder = [None]

        def on_list_selection():
            idx = id_list.getSelectedIndex()
            if 0 <= idx < len(filtered):
                selected_entry_holder[0] = filtered[idx]
            else:
                selected_entry_holder[0] = None

        id_list.addListSelectionListener(_CallbackListSelectionListener(on_list_selection))

        result_combo = JComboBox(["FAIL", "PASS", "MANUAL", "INFO"])
        try:
            result_combo.setSelectedItem(default_result)
        except Exception:
            pass

        evidence_area = JTextArea(8, 40)
        evidence_area.setLineWrap(True)
        evidence_area.setWrapStyleWord(True)
        evidence_area.setText(evidence_prefill_text)
        evidence_scroll = JScrollPane(evidence_area)
        evidence_scroll.setAlignmentX(JPanel.LEFT_ALIGNMENT)

        panel = JPanel()
        panel.setLayout(BoxLayout(panel, BoxLayout.Y_AXIS))
        panel.setPreferredSize(Dimension(680, 560))
        panel.add(context_label)
        spacer1 = JLabel(" ")
        spacer1.setAlignmentX(JPanel.LEFT_ALIGNMENT)
        panel.add(spacer1)
        id_label = JLabel("Checklist ID (type to search %d items, [automated] = already covered by Run All Tests):"
                           % len(MASTER_CHECKLIST))
        id_label.setAlignmentX(JPanel.LEFT_ALIGNMENT)
        panel.add(id_label)
        panel.add(search_field)
        panel.add(list_scroll)
        spacer2 = JLabel(" ")
        spacer2.setAlignmentX(JPanel.LEFT_ALIGNMENT)
        panel.add(spacer2)
        result_row = JPanel(FlowLayout(FlowLayout.LEFT, 6, 0))
        result_row.add(JLabel("Result:"))
        result_row.add(result_combo)
        result_row.setAlignmentX(JPanel.LEFT_ALIGNMENT)
        panel.add(result_row)
        evidence_label = JLabel("Evidence / notes:")
        evidence_label.setAlignmentX(JPanel.LEFT_ALIGNMENT)
        panel.add(evidence_label)
        panel.add(evidence_scroll)

        # Reported directly: "duplicate meant i am submiting a request
        # manetiontng xxs once click out same dialog box opend again to
        # add the details agina" - root cause: clicking OK with no
        # checklist ID selected (easy to do - typing into the search box
        # rebuilds the list and clears any prior selection) used to show
        # a small warning and then just RETURN, discarding everything
        # already typed (evidence text, chosen Result, search text) since
        # the JOptionPane was already closed/disposed by that point. The
        # user then had to right-click all over again and retype from
        # scratch, which looked like "the dialog opened again empty".
        # Looping back on the SAME panel/widgets (nothing recreated, so
        # nothing typed is lost) instead of returning fixes that - the
        # user just needs to click a row in the list and hit OK again.
        while True:
            choice = JOptionPane.showConfirmDialog(self._main_panel, panel, "Log finding to QuickChop",
                                                    JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE)
            if choice != JOptionPane.OK_OPTION:
                return
            entry = selected_entry_holder[0]
            if entry is None:
                JOptionPane.showMessageDialog(
                    self._main_panel,
                    "No checklist ID selected - click a row in the list above, then OK. "
                    "(Your Result/Evidence below are preserved.)",
                    EXT_NAME, JOptionPane.WARNING_MESSAGE)
                continue
            break
        self._save_manual_finding(entry, str(result_combo.getSelectedItem()),
                                   evidence_area.getText(), url_text, tool_name)

    def _save_manual_finding(self, entry, result, evidence, url, tool_name):
        cid, category, test, severity, priority = entry
        row = {
            "source_input": url or "manual", "url_role": "manual", "url": url,
            "id": cid, "category": category, "test": test, "severity": severity, "priority": priority,
            "result": result, "evidence": evidence, "checked_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            "evidence_image_base64": None, "source": "Manual (%s)" % tool_name,
        }
        # Replace any existing row for this same ID (automated OR a
        # previous manual log) - one current verdict per checklist ID,
        # same "re-run replaces" behaviour as _worker_run_scan's merge for
        # automated re-runs, so re-logging a finding updates it in place
        # instead of piling up duplicate rows for the same ID.
        self._rows = [r for r in self._rows if r.get("id") != cid]
        self._rows.append(row)
        self._populate_results_table()
        self._populate_summary()
        self._main_panel.revalidate()
        self._main_panel.repaint()
        self._set_status("Logged %s (%s) as %s - %d finding(s) tracked so far." % (cid, test, result, len(self._rows)))

    # ------------------------------------------------------------------
    # Run / re-run / export
    # ------------------------------------------------------------------
    def _get_target_list(self):
        text = self._targets_area.getText() or ""
        return [line.strip() for line in text.splitlines() if line.strip() and not line.strip().startswith("#")]

    def _on_run_all(self, event):
        self._start_scan(only_ids=None)

    def _on_rerun_selected(self, event):
        rows = self._results_table.getSelectedRows()
        if not rows:
            JOptionPane.showMessageDialog(self._main_panel,
                                           "Select one or more rows in 'Detailed Results' first.",
                                           EXT_NAME, JOptionPane.WARNING_MESSAGE)
            return
        ids = set()
        for r in rows:
            model_row = self._results_table.convertRowIndexToModel(r)
            cid = self._results_table_model.getValueAt(model_row, 0)
            if cid:
                ids.add(str(cid))
        if not ids:
            return
        self._start_scan(only_ids=sorted(ids))

    def _on_export(self, event):
        if not self._rows:
            JOptionPane.showMessageDialog(self._main_panel,
                                           "Nothing to export yet - run a scan and/or log a manual finding first.",
                                           EXT_NAME, JOptionPane.WARNING_MESSAGE)
            return
        chooser = JFileChooser()
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY)
        chooser.setDialogTitle("Choose a folder to copy the JSON/CSV/XLSX into")
        if chooser.showSaveDialog(self._main_panel) != JFileChooser.APPROVE_OPTION:
            return
        dest_dir = chooser.getSelectedFile().getAbsolutePath()
        copied = []

        # Reported directly: "when I confirm a test XSS in Repeater/Proxy/
        # Intruder... record vulnerability list so we understand how many
        # findings have been covered" - manually-logged findings (see
        # _save_manual_finding, wired to the "Log finding to QuickChop"
        # right-click menu) only ever lived in self._rows in memory, never
        # in the .json/.csv/.xlsx files checklist_auto_scan.py itself
        # wrote to disk (those only ever knew about the automated rows) -
        # so Export used to silently drop every manual finding from what
        # actually reaches ReportSystem. This writes a fresh
        # "quickchop_full_<timestamp>.{json,csv}" pair straight from
        # self._rows (automated + manual together, whichever is current
        # right now) so manual findings actually make it into what you
        # hand off, instead of only existing inside QuickChop's own tabs.
        # Pure Jython stdlib (json/csv) - no pandas/xlsxwriter needed, so
        # this part always works regardless of the Python 3 side's
        # package situation.
        stamp = str(int(time.time()))
        full_base = os.path.join(dest_dir, "quickchop_full_%s" % stamp)
        try:
            with open(full_base + ".json", "w") as f:
                json.dump(self._rows, f, indent=2)
            with open(full_base + ".csv", "wb") as f:
                writer = csv.writer(f)
                writer.writerow(["Source", "URL", "ID", "Category", "Test", "Severity", "Priority",
                                  "Result", "Evidence", "Checked At"])
                for r in self._rows:
                    writer.writerow([
                        (r.get("source", "Automated") or "").encode("utf-8", "replace"),
                        (r.get("url", "") or "").encode("utf-8", "replace"),
                        (r.get("id", "") or "").encode("utf-8", "replace"),
                        (r.get("category", "") or "").encode("utf-8", "replace"),
                        (r.get("test", "") or "").encode("utf-8", "replace"),
                        (r.get("severity", "") or "").encode("utf-8", "replace"),
                        (r.get("priority", "") or "").encode("utf-8", "replace"),
                        (r.get("result", "") or "").encode("utf-8", "replace"),
                        (r.get("evidence", "") or "").encode("utf-8", "replace"),
                        (r.get("checked_at", "") or "").encode("utf-8", "replace"),
                    ])
            copied.append(os.path.basename(full_base + ".json"))
            copied.append(os.path.basename(full_base + ".csv"))
        except Exception as e:
            self._callbacks.printError("QuickChop combined export failed: %s" % e)

        if self._last_out_base and os.path.exists(self._last_out_base + ".json"):
            for ext in (".csv", ".json", ".xlsx", "_consolidated.csv", "_consolidated.json"):
                src = self._last_out_base + ext
                if os.path.exists(src):
                    dst = os.path.join(dest_dir, os.path.basename(src))
                    try:
                        with open(src, "rb") as fsrc, open(dst, "wb") as fdst:
                            fdst.write(fsrc.read())
                        copied.append(os.path.basename(dst))
                    except Exception as e:
                        self._callbacks.printError("Export copy failed for %s: %s" % (src, e))

        manual_count = sum(1 for r in self._rows if (r.get("source") or "").startswith("Manual"))
        msg = ("Exported: %s -> %s (upload quickchop_full_*.json here to ReportSystem's 'Import Auto-Scan "
               "Results' page for the combined automated+manual set%s)"
               % (", ".join(copied), dest_dir,
                  " - includes %d manually-logged finding(s)" % manual_count if manual_count else ""))
        if not self._last_xlsx_ok:
            msg += ("  [No .xlsx from the automated engine this run - your Python 3 is missing "
                     "'pandas'/'xlsxwriter'; the quickchop_full_*.json/.csv above are complete either way.]")
        self._set_status(msg)

    def _start_scan(self, only_ids):
        if self._scan_running:
            JOptionPane.showMessageDialog(self._main_panel, "A scan is already running - wait for it to finish.",
                                           EXT_NAME, JOptionPane.WARNING_MESSAGE)
            return
        targets = self._get_target_list()
        if not targets:
            JOptionPane.showMessageDialog(self._main_panel,
                                           "No targets configured. Type one or more URLs into the Targets box, "
                                           "or click 'Pull in-scope targets from Proxy history'.",
                                           EXT_NAME, JOptionPane.WARNING_MESSAGE)
            return
        self._scan_running = True
        running_msg = "Running%s against %d target(s)..." % (
            " (%d selected ID(s))" % len(only_ids) if only_ids else "", len(targets))
        self._set_status(running_msg)
        self._run_all_btn.setEnabled(False)
        self._rerun_selected_btn.setEnabled(False)
        self._cancel_scan_btn.setEnabled(True)
        # Summary tab's own copy of these same buttons (see
        # _build_summary_panel) - kept enabled/disabled in lockstep with
        # the Configuration tab's so neither copy can be clicked twice or
        # left stuck showing "runnable" mid-scan.
        self._summary_run_all_btn.setEnabled(False)
        self._summary_rerun_selected_btn.setEnabled(False)
        self._summary_cancel_scan_btn.setEnabled(True)
        # Reported directly: "in run all test and re-run selected below
        # add progress bar while test are running and add statement once
        # completed never know if test are performed or idle", later
        # "no line by line URL read no 5-10 test perfored and captue
        # progreess eaxly how i it was before" - checklist_auto_scan.py
        # now streams a "QUICKCHOP_ROW|..." line per finished check, and
        # _run_checklist_auto_scan reads that live and pushes batches to
        # _on_scan_progress, so the Summary tab's own progress bar
        # (driven by real pass+fail/total of the rows captured so far -
        # see _update_progress) grows for real as results come in. This
        # Configuration-tab bar has no natural percentage of its own
        # (subprocess start-up, per-target work, etc. aren't weighted),
        # so it stays indeterminate ("still going") but the status label
        # next to it is updated with a live row count each batch so it's
        # never ambiguous whether the scan is stuck or progressing.
        self._config_progress_bar.setIndeterminate(True)
        self._config_progress_bar.setString("Running...")
        self._config_status_label.setText(running_msg)
        self._reset_rows_for_scan(only_ids)
        t = threading.Thread(target=self._worker_run_scan, args=(targets, only_ids))
        t.daemon = True
        t.start()

    def _kill_scan_proc(self, reason):
        """Runs on the watchdog Timer thread (timeout) or the EDT (user
        clicked Cancel Scan) - either way, force-kill whatever
        checklist_auto_scan.py subprocess is currently running. Safe to
        call even if the process already finished on its own (proc.kill()
        on an already-exited Popen is a harmless no-op in both Jython and
        CPython)."""
        self._scan_cancelled = reason
        proc = self._scan_proc
        if proc is not None:
            try:
                proc.kill()
            except Exception:
                pass

    def _on_cancel_scan(self, event):
        if not self._scan_running:
            return
        self._kill_scan_proc("cancelled by user")
        self._config_status_label.setText("Cancelling...")

    def _worker_run_scan(self, targets, only_ids):
        try:
            rows = self._run_checklist_auto_scan(targets, only_ids)
            if only_ids:
                # Merge re-run rows into existing result set (replace matching IDs, keep the rest).
                # self._rows already only holds "kept" + live-streamed-during-this-run rows at this
                # point (see _reset_rows_for_scan/_on_scan_progress) - re-filtering here is cheap and
                # makes the final swap correct/idempotent either way, landing on the authoritative
                # (screenshot-inclusive) rows read back from the JSON file rather than the streamed ones.
                kept = [r for r in self._rows if r.get("id") not in only_ids]
                self._rows = kept + rows
            else:
                self._rows = rows
            SwingUtilities.invokeLater(lambda: self._on_scan_complete(None))
        except Exception as e:
            SwingUtilities.invokeLater(lambda: self._on_scan_complete(e))

    def _reset_rows_for_scan(self, only_ids):
        """Runs on the EDT right before a scan's worker thread starts (see
        _start_scan). Clears out whatever this run is about to replace -
        ALL rows for a fresh Run All, or just the selected IDs' old rows
        for a Re-run Selected - so the incremental updates that follow
        (_on_scan_progress) build up from a clean, correct baseline
        instead of a scan's live partial results getting added on top of
        stale ones."""
        if only_ids:
            self._rows = [r for r in self._rows if r.get("id") not in only_ids]
        else:
            self._rows = []
        self._update_summary_top_cards()
        self._populate_results_table()
        self._progress_label.setText("Scanning... 0 row(s) captured so far")

    def _on_scan_progress(self, rows_batch):
        """Runs on the EDT (invoked via SwingUtilities.invokeLater from the
        scan worker thread as each small batch of QUICKCHOP_ROW lines
        arrives) - merges the batch into self._rows and refreshes just
        the cheap-to-recompute widgets (KPI cards, progress bar/label,
        Detailed Results table) so the scan visibly grows result-by-
        result instead of sitting idle until it's 100% done. The heavier
        per-category breakdowns (_refresh_worst_findings/
        _refresh_summary_coverage_table/_refresh_categories_tab) are left
        for _on_scan_complete at the end, once, on the final authoritative
        (screenshot-inclusive) row set."""
        if not rows_batch:
            return
        self._rows.extend(rows_batch)
        self._update_summary_top_cards()
        total = len(self._rows)
        present_cats = set(r.get("category", "?") for r in self._rows)
        self._progress_label.setText(
            "Scanning... %d row(s) captured so far  |  %d categor%s covered" % (
                total, len(present_cats), "y" if len(present_cats) == 1 else "ies"))
        self._populate_results_table()
        self._config_status_label.setText("Running... %d result(s) captured so far" % total)

    def _run_checklist_auto_scan(self, targets, only_ids):
        python_path = self._python_path_field.getText().strip() or "python3"

        out_dir = self._output_dir_field.getText().strip() or tempfile.gettempdir()
        # Self-extracting engine (see _materialize_engine_script) - no
        # separate checklist_auto_scan.py file to locate/configure any more.
        script_path = self._materialize_engine_script(out_dir)
        stamp = str(int(time.time()))
        out_base = os.path.join(out_dir, "burp_wpt_scan_%s" % stamp)

        url_file = os.path.join(out_dir, "burp_wpt_targets_%s.txt" % stamp)
        with open(url_file, "w") as f:
            f.write("\n".join(targets))

        cmd = [python_path, script_path, "--url-file", url_file, "--out", out_base, "--screenshot", "fail"]
        if not self._cli_tools_checkbox.isSelected():
            cmd.append("--no-cli-tools")

        cookie = self._cookie_field.getText().strip()
        if cookie:
            cmd += ["--cookie", cookie]
        extra_header = self._extra_header_field.getText().strip()
        if extra_header:
            cmd += ["--header", extra_header]
        if only_ids:
            cmd += ["--only", ",".join(only_ids)]

        self._callbacks.printOutput("Running: %s" % " ".join(cmd))
        # stderr is merged into stdout (rather than its own PIPE) because
        # this now reads stdout incrementally line-by-line below instead
        # of via proc.communicate() - communicate() drains both pipes in
        # parallel so it can't deadlock, but a manual read loop watching
        # only one pipe risks exactly that deadlock if the OTHER pipe's
        # OS buffer fills up while nobody's reading it. Merging avoids a
        # second pipe existing at all.
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=1)
        self._scan_proc = proc
        # Reported directly: "after completing the scan it crashed or
        # slow not working properly burp freezes" - proc.communicate()
        # (Jython's subprocess, like Python 2.7's, has no built-in
        # timeout= kwarg) previously blocked FOREVER if
        # checklist_auto_scan.py or a CLI tool it shells out to
        # (nmap/testssl.sh/etc.) hung against an unresponsive target -
        # the Run/Re-run buttons would then stay disabled and the
        # progress bar would spin indefinitely with no way to recover
        # short of restarting Burp. This watchdog force-kills the
        # subprocess (and _on_cancel_scan lets the user do it manually
        # via the Cancel button) instead of hanging indefinitely.
        watchdog = threading.Timer(SCAN_TIMEOUT_SECONDS, self._kill_scan_proc, args=("timed out",))
        watchdog.daemon = True
        watchdog.start()
        # Reported directly: "no line by line URL read no 5-10 test
        # perfored and captue progreess eaxly how i it was before" - read
        # stdout AS THE PROCESS RUNS (instead of blocking on
        # proc.communicate() until it exits) so each "QUICKCHOP_ROW|..."
        # line (emitted by checklist_auto_scan.py's add(), one per
        # finished check - see PROGRESS_FLUSH_EVERY above) can be handed
        # to the UI in small batches as they arrive, not all at once at
        # the very end.
        output_lines = []
        progress_batch = []

        def flush_progress_batch():
            if progress_batch:
                batch_copy = list(progress_batch)
                del progress_batch[:]
                SwingUtilities.invokeLater(lambda: self._on_scan_progress(batch_copy))

        try:
            while True:
                line = proc.stdout.readline()
                if not line:
                    break
                output_lines.append(line)
                stripped = line.strip()
                if stripped.startswith("QUICKCHOP_ROW|"):
                    try:
                        progress_batch.append(json.loads(stripped[len("QUICKCHOP_ROW|"):]))
                    except Exception:
                        pass
                    if len(progress_batch) >= PROGRESS_FLUSH_EVERY:
                        flush_progress_batch()
            flush_progress_batch()
            proc.wait()
        finally:
            watchdog.cancel()
            self._scan_proc = None
        full_output = "".join(output_lines)
        self._callbacks.printOutput(full_output)
        if self._scan_cancelled:
            reason = self._scan_cancelled
            self._scan_cancelled = False
            raise Exception("Scan %s (checklist_auto_scan.py was force-killed)." % reason)
        if proc.returncode != 0:
            # stderr is merged into stdout above, so the tail of the combined
            # output (rather than a separate stderr string) is the best error context available.
            raise Exception("checklist_auto_scan.py exited with code %s:\n%s" % (proc.returncode, full_output[-4000:]))

        json_path = out_base + ".json"
        if not os.path.exists(json_path):
            raise Exception("Scan finished but no output JSON was found at %s" % json_path)

        # checklist_auto_scan.py degrades gracefully (CSV/JSON still get
        # written) when "pandas"/"xlsxwriter" aren't installed on whatever
        # Python 3 the field above points at - it only prints a warning to
        # stdout, which lands in Extensions' Output console, easy to miss.
        # Reported directly: "output doens contan excel" - track it here so
        # the UI itself says something instead of failing silently.
        self._last_xlsx_ok = os.path.exists(out_base + ".xlsx")

        with open(json_path, "r") as f:
            data = json.load(f)
        if isinstance(data, dict) and "results" in data:
            data = data["results"]

        self._last_out_base = out_base
        return data

    def _on_scan_complete(self, error):
        self._scan_running = False
        self._run_all_btn.setEnabled(True)
        self._rerun_selected_btn.setEnabled(True)
        self._cancel_scan_btn.setEnabled(False)
        self._summary_run_all_btn.setEnabled(True)
        self._summary_rerun_selected_btn.setEnabled(True)
        self._summary_cancel_scan_btn.setEnabled(False)
        self._config_progress_bar.setIndeterminate(False)
        if error:
            fail_msg = "Scan failed: %s" % error
            self._config_progress_bar.setValue(0)
            self._config_progress_bar.setString("Failed")
            self._config_status_label.setText(fail_msg)
            self._set_status(fail_msg)
            self._main_panel.revalidate()
            self._main_panel.repaint()
            JOptionPane.showMessageDialog(self._main_panel, str(error), EXT_NAME, JOptionPane.ERROR_MESSAGE)
            return
        self._config_progress_bar.setValue(100)
        self._config_progress_bar.setString("Complete")
        self._clear_filter()  # don't let a stale filter hide rows from a fresh/re-run scan
        self._populate_results_table()
        self._populate_summary()
        if self._last_xlsx_ok:
            done_msg = ("Scan complete - %d row(s). Use 'Export' to write JSON/CSV/XLSX for ReportSystem import."
                         % len(self._rows))
        else:
            done_msg = (
                "Scan complete - %d row(s), but NO .xlsx was written (JSON/CSV are complete and still fine to "
                "import). Your Python 3 is missing 'pandas'/'xlsxwriter' - run: pip3 install pandas xlsxwriter "
                "(add --break-system-packages if that errors) on the SAME machine/interpreter set above, then "
                "re-run." % len(self._rows))
        self._config_status_label.setText(done_msg)
        self._set_status(done_msg)
        # Belt-and-suspenders for the same stale-repaint issue the
        # _TabChangeListener above targets: a scan can finish while the
        # user is looking at a DIFFERENT tab than the ones just repopulated
        # (Summary/Categories), so force the whole window to repaint here
        # too rather than relying only on the next tab switch to do it.
        self._main_panel.revalidate()
        self._main_panel.repaint()

    # ------------------------------------------------------------------
    # Rendering results
    # ------------------------------------------------------------------
    def _populate_results_table(self):
        self._results_table_model.setRowCount(0)
        for r in self._rows:
            self._results_table_model.addRow([
                r.get("id", ""), r.get("category", ""), r.get("test", ""),
                r.get("severity", ""), r.get("priority", ""), r.get("result", ""),
                (r.get("evidence") or "")[:300], r.get("url", ""),
                # Reported directly: "when I confirm a test XSS in Repeater/
                # Proxy/Intruder ... record vulnerability list" - rows from
                # checklist_auto_scan.py never had a "source" key at all
                # (only manually-logged rows do - see _save_manual_finding),
                # so this column reads as "Automated" for every scan-
                # produced row and shows the tool ("Manual (Repeater)" etc.)
                # for a manually-logged one.
                r.get("source", "Automated"),
            ])

    def _stats_for_categories(self, categories):
        """Totals across self._rows, optionally restricted to a list of
        category names (None = every row - the global/'All Categories'
        scope)."""
        total = 0
        passed = 0
        failed = 0
        other = 0
        for r in self._rows:
            cat = r.get("category", "?")
            if categories is not None and cat not in categories:
                continue
            total += 1
            res = r.get("result", "?")
            if res == "PASS":
                passed += 1
            elif res == "FAIL":
                failed += 1
            else:
                other += 1
        return {"total": total, "pass": passed, "fail": failed, "other": other}

    def _set_card_stats(self, total_card, pass_card, fail_card, manual_card, stats):
        total_card["value_label"].setText(str(stats["total"]))
        pass_card["value_label"].setText(str(stats["pass"]))
        fail_card["value_label"].setText(str(stats["fail"]))
        manual_card["value_label"].setText(str(stats["other"]))

    def _update_progress(self, bar, detail_label, stats):
        total = stats["total"]
        determined_pct = int(round(100.0 * (stats["pass"] + stats["fail"]) / total)) if total else 0
        bar.setValue(determined_pct)
        bar.setString("%d%%" % determined_pct)
        detail_label.setText("%d%% automated (PASS/FAIL determined)  -  %d row(s) need manual review"
                              % (determined_pct, stats["other"]))

    def _categories_covered_text(self, mode):
        # Reported directly: "owasp catagories coved is 10 byt KPI shows
        # 8" - the numerator/denominator pair needs to match whichever
        # mode is active: a plain count of distinct real categories seen
        # this scan in "all" mode (the real category set is open-ended -
        # only ~13 of the ~421 master-checklist categories are
        # automatable, so there's no single fixed denominator that's
        # always meaningful here), or "covered OWASP buckets / 10" in
        # "owasp" mode (10 is always a real, meaningful denominator).
        present_cats = set(r.get("category", "?") for r in self._rows)
        if mode == "owasp":
            covered_keys = set()
            for cat in present_cats:
                key = OWASP_CATEGORY_MAP.get(cat, OWASP_OTHER_KEY)
                if key != OWASP_OTHER_KEY:
                    covered_keys.add(key)
            return "%d / %d" % (len(covered_keys), len(OWASP_GROUPS))
        return str(len(present_cats))

    def _update_categories_top_cards(self):
        stats = self._stats_for_categories(self._cat_selected_categories)
        self._set_card_stats(self._cat_card_total, self._cat_card_pass, self._cat_card_fail,
                              self._cat_card_manual, stats)
        self._cat_card_categories["value_label"].setText(self._categories_covered_text(self._cat_mode))
        self._update_progress(self._cat_progress_bar, self._cat_progress_detail_label, stats)

    def _update_summary_top_cards(self):
        stats = self._stats_for_categories(None)
        self._set_card_stats(self._card_total, self._card_pass, self._card_fail, self._card_manual, stats)
        self._card_categories["value_label"].setText(self._categories_covered_text(self._summary_coverage_mode))
        self._update_progress(self._progress_bar, self._progress_detail_label, stats)

    def _refresh_worst_findings(self):
        # Reported directly: "add color codeing for severaity add table
        # form" - rebuilt as a real JTable (see _build_summary_panel);
        # self._worst_findings_rows keeps the exact row dict behind each
        # table row, in the SAME order they're added below, so a
        # double-click (view row -> model row, sorting-safe - see
        # _WorstFindingsDoubleClickListener) can look the full row back
        # up for the shared _show_row_detail popup.
        self._worst_findings_table_model.setRowCount(0)
        self._worst_findings_rows = []
        fails = [r for r in self._rows if r.get("result") == "FAIL"]
        sev_rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}
        fails.sort(key=lambda r: (sev_rank.get(r.get("severity", ""), 5), r.get("id", "")))
        # Reported directly: "add slider so i can navigae down" - this
        # table now sits inside its own JScrollPane (see
        # _build_summary_panel's worst_box), so it no longer needs a tiny
        # hard cap to avoid blowing out the tab's height; 200 is just a
        # sane backstop against a truly pathological scan.
        top = fails[:200]
        for r in top:
            # Now that findings can come from either the automated engine
            # or a manually-logged Repeater/Proxy/Intruder right-click
            # (see _save_manual_finding), tag which one each row came
            # from so this list stays meaningful once both are mixed
            # together.
            self._worst_findings_table_model.addRow([
                r.get("id", ""), r.get("category", ""), r.get("test", ""),
                r.get("severity") or "Informational", r.get("source", "Automated"),
            ])
            self._worst_findings_rows.append(r)
        if len(fails) > len(top):
            self._set_status("Failed vulnerabilities table shows the top %d of %d FAIL result(s) - "
                              "see Detailed Results (filter: result=FAIL) for the rest." % (len(top), len(fails)))

    def _show_worst_finding_detail_from_event(self, event):
        view_row = self._worst_findings_table.rowAtPoint(event.getPoint())
        if view_row < 0:
            return
        model_row = self._worst_findings_table.convertRowIndexToModel(view_row)
        if model_row < 0 or model_row >= len(self._worst_findings_rows):
            return
        self._show_row_detail(self._worst_findings_rows[model_row])

    def _refresh_summary_coverage_table(self):
        present_cats = sorted(set(KNOWN_CATEGORIES) | set(r.get("category", "?") for r in self._rows))
        self._summary_coverage_table_cats = []
        self._summary_coverage_table_labels = []
        if self._summary_coverage_mode == "owasp":
            self._summary_coverage_table_model.setColumnIdentifiers(
                ["OWASP Category", "Total", "Pass", "Fail", "Manual/Other"])
            self._summary_coverage_table_model.setRowCount(0)
            self._summary_coverage_hint.setText(
                "Double-click a row to jump to Detailed Results for every category mapped to that OWASP "
                "bucket, or use the Categories tab's OWASP Top 10 toggle to browse interactively.")
            for key, label in OWASP_GROUPS:
                cats = [c for c in present_cats if OWASP_CATEGORY_MAP.get(c, OWASP_OTHER_KEY) == key]
                stats = self._stats_for_categories(cats) if cats else {"total": 0, "pass": 0, "fail": 0, "other": 0}
                self._summary_coverage_table_model.addRow(
                    [label, stats["total"], stats["pass"], stats["fail"], stats["other"]])
                self._summary_coverage_table_cats.append(cats)
                self._summary_coverage_table_labels.append(label)
            other_cats = [c for c in present_cats if OWASP_CATEGORY_MAP.get(c, OWASP_OTHER_KEY) == OWASP_OTHER_KEY]
            if other_cats:
                stats = self._stats_for_categories(other_cats)
                self._summary_coverage_table_model.addRow(
                    [OWASP_OTHER_LABEL, stats["total"], stats["pass"], stats["fail"], stats["other"]])
                self._summary_coverage_table_cats.append(other_cats)
                self._summary_coverage_table_labels.append(OWASP_OTHER_LABEL)
        else:
            self._summary_coverage_table_model.setColumnIdentifiers(
                ["Category", "Total", "Pass", "Fail", "Manual/Other"])
            self._summary_coverage_table_model.setRowCount(0)
            self._summary_coverage_hint.setText(
                "Double-click a row to jump to Detailed Results for that category, or use the Categories "
                "tab to browse interactively.")
            for cat in present_cats:
                stats = self._stats_for_categories([cat])
                self._summary_coverage_table_model.addRow(
                    [cat, stats["total"], stats["pass"], stats["fail"], stats["other"]])
                self._summary_coverage_table_cats.append([cat])
                self._summary_coverage_table_labels.append(cat)
        self._apply_coverage_table_widths(self._summary_coverage_table)

    def _refresh_categories_tab(self):
        present_cats = sorted(set(KNOWN_CATEGORIES) | set(r.get("category", "?") for r in self._rows))

        # --- left list ---
        self._populating_cat_list = True
        self._cat_list_model.clear()
        self._cat_list_keys = ["ALL"]
        self._cat_list_cats = [None]
        self._cat_list_labels = ["All Categories"]
        self._cat_list_model.addElement("All Categories")
        if self._cat_mode == "owasp":
            for key, label in OWASP_GROUPS:
                cats = [c for c in present_cats if OWASP_CATEGORY_MAP.get(c, OWASP_OTHER_KEY) == key]
                stats = self._stats_for_categories(cats) if cats else {"total": 0, "pass": 0, "fail": 0, "other": 0}
                count_text = "%d/%d" % (stats["pass"], stats["total"]) if cats else "-"
                self._cat_list_model.addElement("%s  (%s)" % (label, count_text))
                self._cat_list_keys.append(key)
                self._cat_list_cats.append(cats)
                self._cat_list_labels.append(label)
            other_cats = [c for c in present_cats if OWASP_CATEGORY_MAP.get(c, OWASP_OTHER_KEY) == OWASP_OTHER_KEY]
            if other_cats:
                stats = self._stats_for_categories(other_cats)
                self._cat_list_model.addElement("%s  (%d/%d)" % (OWASP_OTHER_LABEL, stats["pass"], stats["total"]))
                self._cat_list_keys.append(OWASP_OTHER_KEY)
                self._cat_list_cats.append(other_cats)
                self._cat_list_labels.append(OWASP_OTHER_LABEL)
        else:
            for cat in present_cats:
                stats = self._stats_for_categories([cat])
                self._cat_list_model.addElement("%s  (%d/%d)" % (cat, stats["pass"], stats["total"]))
                self._cat_list_keys.append(cat)
                self._cat_list_cats.append([cat])
                self._cat_list_labels.append(cat)
        self._cat_list.setSelectedIndex(0)
        self._populating_cat_list = False

        # --- right breakdown table (mirrors the same mode) ---
        self._cat_table_keys = []
        self._cat_table_cats = []
        self._cat_table_labels = []
        if self._cat_mode == "owasp":
            self._cat_table_model.setColumnIdentifiers(["OWASP Category", "Total", "Pass", "Fail", "Manual/Other"])
            self._cat_table_model.setRowCount(0)
            self._cat_note_label.setText(
                "Coverage by OWASP Top 10 bucket (categories rolled up per an illustrative mapping - confirm "
                "against ReportSystem's own classification before real engagements). The selected bucket is "
                "highlighted below - double-click any row to jump to Detailed Results for every category in it.")
            for key, label in OWASP_GROUPS:
                cats = [c for c in present_cats if OWASP_CATEGORY_MAP.get(c, OWASP_OTHER_KEY) == key]
                stats = self._stats_for_categories(cats) if cats else {"total": 0, "pass": 0, "fail": 0, "other": 0}
                self._cat_table_model.addRow([label, stats["total"], stats["pass"], stats["fail"], stats["other"]])
                self._cat_table_keys.append(key)
                self._cat_table_cats.append(cats)
                self._cat_table_labels.append(label)
            other_cats = [c for c in present_cats if OWASP_CATEGORY_MAP.get(c, OWASP_OTHER_KEY) == OWASP_OTHER_KEY]
            if other_cats:
                stats = self._stats_for_categories(other_cats)
                self._cat_table_model.addRow(
                    [OWASP_OTHER_LABEL, stats["total"], stats["pass"], stats["fail"], stats["other"]])
                self._cat_table_keys.append(OWASP_OTHER_KEY)
                self._cat_table_cats.append(other_cats)
                self._cat_table_labels.append(OWASP_OTHER_LABEL)
        else:
            self._cat_table_model.setColumnIdentifiers(["Category", "Total", "Pass", "Fail", "Manual/Other"])
            self._cat_table_model.setRowCount(0)
            self._cat_note_label.setText(
                "Coverage by category (this scan's targets/session only, not the full ReportSystem master "
                "checklist). The selected category is highlighted below - double-click any row to jump "
                "straight to Detailed Results for it.")
            for cat in present_cats:
                stats = self._stats_for_categories([cat])
                self._cat_table_model.addRow([cat, stats["total"], stats["pass"], stats["fail"], stats["other"]])
                self._cat_table_keys.append(cat)
                self._cat_table_cats.append([cat])
                self._cat_table_labels.append(cat)
        self._apply_coverage_table_widths(self._cat_table)

        # Reset scope to "All Categories" any time the underlying data (or
        # the mode) changes - keeps the left list, right table, and top
        # cards all unambiguous instead of pointing at a selection that
        # may no longer exist.
        self._set_category_scope(None, "All Categories", "ALL")

    def _populate_summary(self):
        self._update_summary_top_cards()
        total = len(self._rows)
        present_cats = set(r.get("category", "?") for r in self._rows)
        self._progress_label.setText(
            "%d row(s) this scan  |  %d categor%s covered" % (
                total, len(present_cats), "y" if len(present_cats) == 1 else "ies"))

        self._refresh_summary_coverage_table()
        self._refresh_categories_tab()
        # Reported directly: "add bototm fauled vulnerabiitys below the
        # gatagory" - re-added below the Coverage table (see
        # _build_summary_panel); now reflects the unified automated +
        # manually-logged row set, same as everything else on this tab.
        self._refresh_worst_findings()

    def _set_status(self, text):
        self._status_label.setText(text)
        try:
            self._callbacks.printOutput(text)
        except Exception:
            pass


class ColoredTableModel(DefaultTableModel):
    def isCellEditable(self, row, col):
        return False

    def getColumnClass(self, col):
        # Reported directly: "sorting now working properly sort brings
        # fail start with 2 then 13 it should list 13 first" -
        # DefaultTableModel reports every column as plain
        # java.lang.Object by default, so JTable's built-in row sorter
        # falls back to comparing values as TEXT ("2" sorts after "13"
        # lexicographically, since '2' > '1') instead of as numbers.
        # Report the actual runtime type already sitting in the column
        # (java.lang.Integer for the Total/Pass/Fail/Manual-Other count
        # columns, String elsewhere) so the sorter compares numerically
        # where it should. See the matching setDefaultRenderer(JInteger,
        # ...) calls alongside setDefaultRenderer(JObject, ...) at each
        # table using this model - without both registrations, reporting
        # Integer.class here alone would make JTable fall back to its
        # own plain built-in numeric renderer (right-aligned, no colors)
        # instead of our category/result coloring, since
        # getDefaultRenderer() resolves the EXACT class first before
        # climbing to Object.class.
        if self.getRowCount() > 0:
            value = self.getValueAt(0, col)
            if value is not None:
                # Reported directly (traceback from Burp's extension Errors
                # console): "AttributeError: 'unicode' object has no
                # attribute 'getClass'" - every row value that comes from
                # JSON (json.load/json.loads, both the final results file
                # and, since the live-progress streaming feature, every
                # in-progress QUICKCHOP_ROW batch too) is a Python `unicode`
                # object in Jython 2, not a real java.lang.Integer/String,
                # and unicode values don't expose .getClass() the way
                # Jython's `str`/native Java types do. That crashed
                # _clear_filter()'s sorter.setRowFilter(None) call (which
                # triggers this) partway through _on_scan_complete, aborting
                # the rest of it silently - looked like the scan "froze" on
                # "Running..." even though it had actually finished. Only a
                # real java.lang.Integer (the coverage tables' Total/Pass/
                # Fail/Manual-Other columns) should report its own class for
                # numeric sorting; anything else - including this unicode
                # case - safely falls through to the JObject default below.
                try:
                    return value.getClass()
                except AttributeError:
                    pass
        return JObject


class _CallbackMouseListener(MouseAdapter):
    """Wraps a zero-arg Python callable as a Java MouseListener - used by
    the clickable KPI cards (_make_stat_card's on_click) on the Summary
    and Categories tabs. Subclasses MouseAdapter directly rather than
    relying on Jython's automatic callable-to-interface coercion, which
    only applies to single-method interfaces (MouseListener has five
    methods) - same reasoning as every other MouseAdapter subclass in
    this file."""

    def __init__(self, callback):
        self._callback = callback

    def mouseClicked(self, event):
        try:
            self._callback()
        except Exception:
            pass


class _ResultsTableDoubleClickListener(MouseAdapter):
    """Double-click on a Detailed Results row to see its full, untruncated
    evidence (real curl/nmap command + response included) - the grid cell
    itself is hard-capped to 300 chars so it stays readable as a table.
    Subclasses MouseAdapter directly (same reasoning as ResultRowRenderer
    below - real Java subclassing sidesteps Jython's interface-coercion
    ambiguity for a plain object exposing a same-named method)."""

    def __init__(self, extender):
        self._extender = extender

    def mouseClicked(self, event):
        if event.getClickCount() == 2:
            self._extender._show_row_detail_from_event(event)


class _BurpFindingsDoubleClickListener(MouseAdapter):
    """Double-click a Burp Scanner Findings row for its full, untruncated
    detail - reported directly: "when I double click it is not openign
    related record like scanner page does" (i.e. unlike Detailed
    Results' own double-click -> full-evidence popup, see
    _ResultsTableDoubleClickListener above)."""

    def __init__(self, extender):
        self._extender = extender

    def mouseClicked(self, event):
        if event.getClickCount() == 2:
            self._extender._show_burp_issue_detail_from_event(event)


class _WorstFindingsDoubleClickListener(MouseAdapter):
    """Double-click a row on Summary's Failed vulnerabilities table for
    its full-evidence popup - reported directly: "add color codeing for
    severaity add table form" (the table-conversion this listener came
    with). Same shared _show_row_detail popup as Detailed Results, since
    these are real self._rows dicts, just a filtered/ranked subset - see
    _refresh_worst_findings."""

    def __init__(self, extender):
        self._extender = extender

    def mouseClicked(self, event):
        if event.getClickCount() == 2:
            self._extender._show_worst_finding_detail_from_event(event)


class _CategoryTableDoubleClickListener(MouseAdapter):
    """Double-click a category/OWASP-bucket row on the Categories tab to
    jump to Detailed Results filtered down to just it - reported
    directly: "it is not taking into the selected catagory findings...
    not allowing to land the fineld items"."""

    def __init__(self, extender):
        self._extender = extender

    def mouseClicked(self, event):
        if event.getClickCount() == 2:
            self._extender._on_category_table_double_click(event)


class _SummaryCoverageDoubleClickListener(MouseAdapter):
    """Double-click a row on the Summary tab's Coverage table to jump to
    Detailed Results filtered down to it - same idea as
    _CategoryTableDoubleClickListener above, just for the Summary tab's
    own (independent) coverage table."""

    def __init__(self, extender):
        self._extender = extender

    def mouseClicked(self, event):
        if event.getClickCount() == 2:
            self._extender._on_summary_coverage_table_double_click(event)


class _CategoryListSelectionListener(ListSelectionListener):
    """Single-click a category/OWASP-bucket in the left-side list on the
    Categories tab to rescope the top KPI cards to it, or click "All
    Categories" (index 0, the default) to go back to global totals -
    reported directly: "by default all test should pear if any catarogy
    select then only those test case shuld be apear". Subclasses the
    Java interface directly, same Jython pattern as the MouseAdapter
    listeners above."""

    def __init__(self, extender):
        self._extender = extender

    def valueChanged(self, event):
        if event.getValueIsAdjusting():
            return
        self._extender._on_category_list_selection()


class _CallbackListSelectionListener(ListSelectionListener):
    """Generic zero-arg-callback wrapper for ListSelectionListener - same
    idea as _CallbackMouseListener above, for the Log Finding dialog's
    searchable checklist-ID JList (see _open_log_finding_dialog), which
    doesn't need any extra per-listener state beyond "something got
    selected, go re-read it"."""

    def __init__(self, callback):
        self._callback = callback

    def valueChanged(self, event):
        if event.getValueIsAdjusting():
            return
        self._callback()


class _CallbackDocumentListener(DocumentListener):
    """Generic zero-arg-callback wrapper for DocumentListener - same idea
    as _SearchDocumentListener below, but reusable anywhere a text field
    just needs "text changed, go re-filter" (the Log Finding dialog's
    checklist-ID search box)."""

    def __init__(self, callback):
        self._callback = callback

    def insertUpdate(self, event):
        self._callback()

    def removeUpdate(self, event):
        self._callback()

    def changedUpdate(self, event):
        self._callback()


class _TabChangeListener(ChangeListener):
    """Reported directly: 'run and export appearing in two places when i
    go to config page and moving back to other page config page stays
    same only top findings are changing' - a stale-repaint issue where a
    tab's JScrollPane content, redrawn by a background scan thread while
    that tab wasn't the one showing, doesn't get a fresh paint once the
    user switches back to it (only individual labels updated via
    setText() force their own repaint - the surrounding panel doesn't).
    Forcing a full revalidate()+repaint() of whichever tab becomes
    selected (and the tab strip itself) any time selection changes is
    the standard fix for this class of Swing staleness."""

    def __init__(self, extender):
        self._extender = extender

    def stateChanged(self, event):
        tabs = self._extender._tabs
        tabs.revalidate()
        tabs.repaint()
        selected = tabs.getSelectedComponent()
        if selected is not None:
            selected.revalidate()
            selected.repaint()


class _ClearFilterMouseListener(MouseAdapter):
    """Click the yellow filter banner atop Detailed Results to clear an
    active category/result filter and go back to showing every row."""

    def __init__(self, extender):
        self._extender = extender

    def mouseClicked(self, event):
        self._extender._clear_filter()


class _ResultCategoryRowFilter(RowFilter):
    """Detailed Results' combined filter: an optional list of categories
    (a single category, or a whole OWASP-bucket rollup) AND an
    independent result-type ("PASS"/"FAIL"/"OTHER" grouping MANUAL+INFO+
    ERROR) AND an optional free-text search (ID/Category/Test/Evidence/
    URL, case-insensitive substring), all applied together.
    RowFilter.regexFilter() (used by the single-category filter this
    replaced) can't do multi-value-list matching or combine independent
    conditions like this, so this subclasses RowFilter directly instead
    - same Jython pattern as every other custom Swing class in this file
    (subclass the real Java class rather than lean on interface
    auto-coercion, which doesn't apply to abstract classes like
    RowFilter anyway)."""

    # Reported directly, with a screenshot: "search bar not working" -
    # typing "Result = FAIL" into the free-text search box searched for
    # that literal string across ID/Category/Test/Evidence/URL (never
    # Result), matched nothing, and looked broken - the box worked
    # exactly as built, it just didn't understand the "Column = value"
    # syntax typed into it (that syntax is what the yellow filter BANNER
    # displays when you click a KPI card/table row, which is a different,
    # already-working mechanism - see _update_filter_banner). Rather than
    # just explain that away, this teaches the search box to understand
    # it: a leading "field:value" or "field=value" token (field one of
    # id/category/test/severity/priority/result/evidence/url) routes to
    # THAT column only; anything else keeps the original multi-column
    # substring behaviour unchanged.
    _FIELD_COLUMNS = {
        "id": 0, "category": 1, "test": 2, "severity": 3,
        "priority": 4, "result": 5, "evidence": 6, "url": 7, "source": 8,
    }
    _FIELD_TOKEN_RE = re.compile(
        r'^(id|category|test|severity|priority|result|evidence|url|source)\s*[:=]\s*(.+)$')

    def __init__(self, categories, result, search_text=None):
        self._categories = set(categories) if categories else None
        self._result = result
        raw = (search_text or "").strip().lower()
        self._search_field_col = None
        self._search_text = raw
        m = self._FIELD_TOKEN_RE.match(raw)
        if m and m.group(2).strip():
            self._search_field_col = self._FIELD_COLUMNS[m.group(1)]
            self._search_text = m.group(2).strip()

    def include(self, entry):
        try:
            category = entry.getValue(1)  # RESULT_COLUMNS[1] = Category
            result = entry.getValue(5)    # RESULT_COLUMNS[5] = Result
        except Exception:
            return True
        if self._categories is not None and category not in self._categories:
            return False
        if self._result:
            if self._result == "OTHER":
                if result in ("PASS", "FAIL"):
                    return False
            elif result != self._result:
                return False
        if self._search_text:
            if self._search_field_col is not None:
                try:
                    value = entry.getValue(self._search_field_col)
                except Exception:
                    value = None
                haystack = str(value).lower() if value is not None else ""
                if self._search_text not in haystack:
                    return False
            else:
                haystack_parts = []
                for col in (0, 1, 2, 6, 7):  # ID, Category, Test, Evidence, URL
                    try:
                        value = entry.getValue(col)
                    except Exception:
                        value = None
                    if value is not None:
                        haystack_parts.append(str(value))
                haystack = " ".join(haystack_parts).lower()
                if self._search_text not in haystack:
                    return False
        return True


class _SearchDocumentListener(DocumentListener):
    """Live-filters Detailed Results as the search box's text changes -
    reported directly: "allow user to add manual search Input box".
    Subclasses javax.swing.event.DocumentListener directly (three
    methods, not a single-method interface Jython could auto-coerce a
    plain callable into) - same pattern as every other Java-interface
    listener in this file."""

    def __init__(self, extender):
        self._extender = extender

    def insertUpdate(self, event):
        self._extender._on_search_text_changed()

    def removeUpdate(self, event):
        self._extender._on_search_text_changed()

    def changedUpdate(self, event):
        self._extender._on_search_text_changed()


class ResultRowRenderer(DefaultTableCellRenderer):
    """Colors each results-table row's background by its Result column value
    (index 5), matching the PASS=green/FAIL=red/MANUAL=yellow/INFO=blue/
    ERROR=gray scheme already used in the .xlsx output, so the two views
    read the same way. Subclasses DefaultTableCellRenderer directly (the
    standard Jython pattern for a custom Swing renderer) rather than
    composing one, since Jython's automatic Python-callable-to-Java-
    interface coercion isn't guaranteed for a plain object exposing a
    same-named method - subclassing the real Java renderer class sidesteps
    that ambiguity entirely."""

    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, col):
        comp = DefaultTableCellRenderer.getTableCellRendererComponent(
            self, table, value, isSelected, hasFocus, row, col)
        comp.setFont(comp.getFont().deriveFont(Font.PLAIN))
        try:
            model_row = table.convertRowIndexToModel(row)
            result = table.getModel().getValueAt(model_row, 5)
            color = RESULT_COLORS.get(str(result))
            if color and not isSelected:
                comp.setBackground(color)
            elif not isSelected:
                comp.setBackground(Color.WHITE)
            # Reported directly: "add color codeing for severaity" -
            # Severity is column index 3 in RESULT_COLUMNS (see near the
            # top of this file). This keeps the row's existing
            # PASS/FAIL/etc background (set above) and additionally
            # bolds+colors just this column's TEXT by severity tier
            # (Critical -> dark red down to Low -> blue-gray), same
            # SEVERITY_ACCENT_COLORS used by the Summary tab's Failed
            # vulnerabilities table and the Checklist Reference tab, so
            # all three read as one consistent color system.
            if col == 3 and not isSelected:
                severity = table.getModel().getValueAt(model_row, 3)
                sev_color = SEVERITY_ACCENT_COLORS.get(str(severity) if severity is not None else "")
                if sev_color:
                    comp.setForeground(sev_color)
                    comp.setFont(comp.getFont().deriveFont(Font.BOLD))
            elif not isSelected:
                comp.setForeground(Color.BLACK)
        except Exception:
            pass
        return comp


class CategoryFailRenderer(DefaultTableCellRenderer):
    """Category/OWASP breakdown tables (Categories tab + Summary tab's
    Coverage table): bolds+reddens the Fail column (index 3) whenever a
    row has at least one FAIL, and bolds+greens the Pass column (index 2)
    whenever a row is fully clean (no fails, at least one pass) - a quick
    visual scan of what needs attention.

    Optionally also highlights the whole row (orange tint) when it
    matches the extender's currently-selected category/OWASP-bucket key -
    pass extender/keys_attr/selected_attr (attribute names read via
    getattr each render, since the parallel keys list and the selection
    both change after the renderer is installed) to enable this; pass
    None/None/None (as the Summary tab's coverage table does) to disable
    it and get plain color-coded columns only."""

    def __init__(self, extender=None, keys_attr=None, selected_attr=None):
        DefaultTableCellRenderer.__init__(self)
        self._extender = extender
        self._keys_attr = keys_attr
        self._selected_attr = selected_attr

    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, col):
        comp = DefaultTableCellRenderer.getTableCellRendererComponent(
            self, table, value, isSelected, hasFocus, row, col)
        try:
            model_row = table.convertRowIndexToModel(row)
            fail_count = int(table.getModel().getValueAt(model_row, 3) or 0)
            pass_count = int(table.getModel().getValueAt(model_row, 2) or 0)
            comp.setFont(comp.getFont().deriveFont(Font.PLAIN))
            if col == 3 and fail_count > 0:
                comp.setForeground(Color(0xA4, 0x26, 0x2C))
                comp.setFont(comp.getFont().deriveFont(Font.BOLD))
            elif col == 2 and pass_count > 0 and fail_count == 0:
                comp.setForeground(Color(0x1E, 0x7E, 0x34))
                comp.setFont(comp.getFont().deriveFont(Font.BOLD))
            elif not isSelected:
                comp.setForeground(Color.BLACK)

            is_selected_row = False
            if self._extender is not None and self._keys_attr and self._selected_attr:
                keys = getattr(self._extender, self._keys_attr, None)
                selected_key = getattr(self._extender, self._selected_attr, None)
                if keys and selected_key and selected_key != "ALL" and 0 <= model_row < len(keys):
                    is_selected_row = (keys[model_row] == selected_key)
            if not isSelected:
                comp.setBackground(Color(0xFD, 0xF0, 0xE5) if is_selected_row else Color.WHITE)
        except Exception:
            pass
        return comp


class _SeverityTextRenderer(DefaultTableCellRenderer):
    """Bolds+colors a single column's text by severity tier
    (Critical/High/Medium/Low/Informational, via SEVERITY_ACCENT_COLORS -
    see that dict's own comment for why "Information" is also mapped).
    Installed as a per-COLUMN renderer (table.getColumnModel().getColumn
    (idx).setCellRenderer(...)) rather than a table-wide default renderer,
    since the tables that use this (Checklist Reference, Summary's Failed
    vulnerabilities) don't otherwise need row-level coloring the way
    Detailed Results does (see ResultRowRenderer instead for that case).
    Reported directly: "add color codeing for severaity"."""

    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, col):
        comp = DefaultTableCellRenderer.getTableCellRendererComponent(
            self, table, value, isSelected, hasFocus, row, col)
        if not isSelected:
            comp.setBackground(Color.WHITE)
            color = SEVERITY_ACCENT_COLORS.get(str(value) if value is not None else "")
            if color:
                comp.setForeground(color)
                comp.setFont(comp.getFont().deriveFont(Font.BOLD))
            else:
                comp.setForeground(Color.BLACK)
                comp.setFont(comp.getFont().deriveFont(Font.PLAIN))
        return comp
