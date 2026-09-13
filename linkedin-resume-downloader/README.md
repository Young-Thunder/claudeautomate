# Resume Downloader for LinkedIn Jobs

A Chrome extension (Manifest V3) that bulk-downloads applicant resumes from
the **Applicants** page of a LinkedIn job you posted — similar to the
[Resume Downloader for LinkedIn](https://chromewebstore.google.com/detail/resume-downloader-for-lin/ffpmacldiomplbghbhaikflndljlebjl)
Chrome Web Store extension.

It runs entirely in your own browser, using your existing LinkedIn session.
It doesn't scrape other people's private data or bypass any access control —
it just automates clicking the "download resume" links you can already see
and click one by one as the job poster.

## What it does

1. On a job's **Applicants** page, it scans the page for applicant resume
   links/buttons.
2. Optionally auto-scrolls / clicks "Show more" to load every applicant
   before scanning, since LinkedIn paginates long lists.
3. Lets you review the list in the popup and bulk-download the resumes it
   found, named `<Applicant Name>_Resume.<ext>`, saved under
   `Downloads/LinkedIn Resumes/<job title>/`.
4. For any applicant whose resume is only reachable via a button (no direct
   link), it's marked **Manual** with a "Reveal" button that scrolls to and
   clicks that element for you, so you can save it yourself from whatever
   LinkedIn opens.

## Install (unpacked)

1. Open `chrome://extensions`.
2. Enable **Developer mode** (top-right toggle).
3. Click **Load unpacked** and select this `linkedin-resume-downloader`
   folder.
4. Pin the extension for easy access (puzzle-piece icon → pin).

## Usage

1. Go to your job posting's Applicants page on LinkedIn
   (`https://www.linkedin.com/hiring/jobs/<id>/applicants/...`).
2. Click the extension icon.
3. Click **Scan applicants**. Leave "Load all applicants first" checked to
   page through the full list before scanning.
4. Review the list — uncheck anything you don't want.
5. Click **Download selected**.
   - For more than a handful of resumes, click the **⧉** button first to pop
     the popup out into its own window. A regular toolbar popup closes the
     moment it loses focus, which would interrupt a long batch; the popped
     -out window keeps running.
6. For rows tagged **Manual**, click **Reveal** and save that one manually.

## Why "Manual" shows up for some applicants

LinkedIn's markup isn't public/stable API surface, so this extension detects
resume links heuristically — by URL pattern (`resume`, `/dms/.../document`,
`.pdf`, `.docx`) and by visible text/aria-label (`resume`, `cv`, `download
resume`, etc.), anchored to the applicant's profile link
(`linkedin.com/in/...`) to figure out whose row it belongs to. When a
"resume" affordance is a button with no href LinkedIn exposes to the page
(e.g. it only opens an in-page viewer), there's no URL to download
automatically — hence the manual fallback instead of guessing.

## "This resume link opens a LinkedIn viewer page..." errors

Some LinkedIn applicant tables link the resume icon to an internal route
(e.g. `.../resume-view/?applicationId=...`) that's rendered client-side —
fetching it returns LinkedIn's app shell, not the PDF, and the real file is
requested by LinkedIn's own JavaScript after the page loads. This extension
fetches the link directly and can't run that JavaScript, so it can't
resolve these automatically yet. If the same error repeats 3 times in a
row, the batch stops itself instead of failing through everyone selected.

If you hit this: click that resume icon **yourself** (not through the
extension) and note what happens — a new tab opening with the PDF, an
in-page preview panel, an immediate download — and, ideally, the URL of
whatever tab/preview it opens. That tells us which resolution strategy to
add (e.g. opening it in a background tab and reading the rendered result,
rather than a plain fetch).

## If it finds 0 resumes

LinkedIn periodically changes its markup, and some views (e.g. the
icon-only "Hiring Pro" table) show the resume action as a plain icon
button with no text or label the page exposes — the extension has nothing
to match in that case. When a scan finds 0 applicants, the status line
tells you which of two things is going on:

- **"no candidate profile links on this page yet"** — the page (or the
  inner applicant list panel) probably hadn't finished loading yet when it
  scanned. Wait a couple seconds and click **Scan applicants** again.
- **"found N applicant(s) but no resume-like link/button"** — the
  applicant rows are there, but nothing on the page has "resume"/"cv" in
  its text, href, or aria-label. This is the icon-only case:
  1. Right-click the resume/document icon next to an applicant → **Inspect**.
  2. In the popup, open **Advanced** and paste a CSS selector that targets
     that element into **Custom resume link/button selector** (e.g.
     `button[aria-label*="resume" i]`, or something more specific from
     what you inspected).
  3. Re-scan.
     If you're not sure what selector to use, copy the highlighted HTML
     from DevTools and share it — the detection logic in `content.js` can
     be extended to match it directly.

## Permissions

- `downloads` — to save resumes to your Downloads folder.
- `storage` — to remember your settings (delay, custom selector) locally.
- `scripting` + `host_permissions` for `linkedin.com` — to inject the
  scanner into the Applicants tab and to fetch a resume link's final file
  URL when it points at an HTML viewer instead of the raw file, so the
  right file extension gets used.

No data leaves your browser; nothing is sent anywhere except LinkedIn itself
(to fetch/download resumes you already have access to).

## A note on LinkedIn's terms

LinkedIn's User Agreement restricts scraping and automated data collection.
This tool only automates clicks on your own job posting's applicants — data
candidates submitted directly to you — rather than accessing anyone else's
profile or data without authorization. Even so, automation tools like this
one exist outside LinkedIn's official API, so use your own judgment and
check LinkedIn's current terms before relying on it heavily.

## Limitations

- Only works on pages you're already logged into and authorized to view as
  the job poster/hiring manager.
- Built and logic-tested against a synthetic fixture page (no live,
  authenticated LinkedIn session was available while building this), so
  double check the first run and adjust the custom selector if needed — see
  above.
- One job's Applicants page at a time.
- Can't yet resolve resume links that are client-side-rendered viewer
  routes rather than a direct file/redirect — see above.

## Files

| File | Purpose |
|---|---|
| `manifest.json` | Extension configuration (Manifest V3) |
| `content.js` / `content.css` | Injected into LinkedIn Applicants pages: finds applicants + resume links, handles pagination |
| `background.js` | Service worker: resolves resume URLs and performs downloads |
| `popup.html` / `popup.js` / `popup.css` | The UI you interact with |
| `icons/` | Toolbar/store icons |
