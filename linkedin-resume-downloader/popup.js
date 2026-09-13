const params = new URLSearchParams(location.search);
const standalone = params.has("standalone");
const fixedTabId = params.has("tabId") ? Number(params.get("tabId")) : null;

const statusBox = document.getElementById("statusBox");
const mainPanel = document.getElementById("mainPanel");
const popOutBtn = document.getElementById("popOutBtn");
const autoScrollChk = document.getElementById("autoScrollChk");
const scanBtn = document.getElementById("scanBtn");
const scanStatus = document.getElementById("scanStatus");
const customSelectorInput = document.getElementById("customSelector");
const delayMsInput = document.getElementById("delayMs");
const resultsEl = document.getElementById("results");
const footer = document.getElementById("footer");
const selectAllChk = document.getElementById("selectAllChk");
const downloadBtn = document.getElementById("downloadBtn");
const progressEl = document.getElementById("progress");
const allPagesBtn = document.getElementById("allPagesBtn");
const pageSizeInput = document.getElementById("pageSizeInput");
const pageProgressEl = document.getElementById("pageProgress");
const resumePrompt = document.getElementById("resumePrompt");

let targetTabId = fixedTabId;
let applicants = [];
let jobContext = "";

const SUPPORTED_URL = /^https:\/\/www\.linkedin\.com\/(hiring|talent)\//i;

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function sanitize(text) {
  return (text || "")
    .replace(/[\\/:*?"<>|]+/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 80);
}

async function loadSettings() {
  const { lrdSettings } = await chrome.storage.local.get("lrdSettings");
  if (lrdSettings) {
    autoScrollChk.checked = lrdSettings.autoScroll !== false;
    customSelectorInput.value = lrdSettings.customSelector || "";
    delayMsInput.value = lrdSettings.delayMs || 800;
    pageSizeInput.value = lrdSettings.pageSize || 30;
  }
}

function saveSettings() {
  chrome.storage.local.set({
    lrdSettings: {
      autoScroll: autoScrollChk.checked,
      customSelector: customSelectorInput.value.trim(),
      delayMs: Number(delayMsInput.value) || 800,
      pageSize: Number(pageSizeInput.value) || 30,
    },
  });
}

function setStatus(text, showMain) {
  statusBox.textContent = text;
  statusBox.hidden = !text;
  mainPanel.hidden = !showMain;
}

async function resolveTargetTab() {
  if (targetTabId) {
    try {
      return await chrome.tabs.get(targetTabId);
    } catch {
      return null;
    }
  }
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (tab) targetTabId = tab.id;
  return tab || null;
}

async function ensureContentScript(tabId) {
  try {
    const pong = await chrome.tabs.sendMessage(tabId, { type: "LRD_PING" });
    if (pong && pong.ok) return true;
  } catch {
    // not injected yet
  }
  try {
    await chrome.scripting.insertCSS({ target: { tabId }, files: ["content.css"] });
    await chrome.scripting.executeScript({ target: { tabId }, files: ["content.js"] });
    return true;
  } catch (e) {
    console.error("[Resume Downloader] Failed to inject content script:", e);
    return false;
  }
}

function renderResults() {
  resultsEl.innerHTML = "";
  resultsEl.hidden = applicants.length === 0;
  footer.hidden = applicants.length === 0;

  for (const a of applicants) {
    const li = document.createElement("li");

    const checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    checkbox.checked = !a.needsManualClick;
    checkbox.dataset.id = a.id;
    checkbox.disabled = a.needsManualClick;

    const name = document.createElement("span");
    name.className = "applicant-name";
    name.textContent = a.name;
    name.title = a.profileUrl || "";

    const tag = document.createElement("span");
    if (a.status === "done") {
      tag.className = "tag ok";
      tag.textContent = "Downloaded";
    } else if (a.status === "error") {
      tag.className = "tag err";
      tag.textContent = a.statusMessage || "Failed";
    } else if (a.needsManualClick) {
      tag.className = "tag warn";
      tag.textContent = "Manual";
    } else {
      tag.className = "tag ok";
      tag.textContent = "Found";
    }

    li.appendChild(checkbox);
    li.appendChild(name);
    li.appendChild(tag);

    if (a.needsManualClick) {
      const revealBtn = document.createElement("button");
      revealBtn.className = "secondary";
      revealBtn.textContent = "Reveal";
      revealBtn.addEventListener("click", async () => {
        await chrome.tabs.sendMessage(targetTabId, {
          type: "LRD_CLICK_ELEMENT",
          elementId: a.resumeElementId,
        });
      });
      li.appendChild(revealBtn);
    }

    resultsEl.appendChild(li);
  }
}

function explainZeroResults(diag) {
  if (!diag) return "0 applicants found.";
  const counts = `(profile links: ${diag.profileLinksFound}, resume-like elements: ${diag.resumeCandidatesFound}, anchors: ${diag.totalAnchors}, buttons: ${diag.totalButtons})`;

  if (diag.profileLinksFound === 0) {
    return `0 applicants found — no candidate profile links on this page yet. It may still be loading, or this isn't the Applicants list view. Wait a moment and scan again. ${counts}`;
  }
  if (diag.resumeCandidatesFound === 0) {
    return `Found ${diag.profileLinksFound} applicant(s) but no resume-like link/button (nothing with "resume"/"cv" in its text, href, or aria-label). This page's resume icon likely doesn't expose that — right-click it → Inspect, then paste a matching CSS selector into Advanced → Custom selector. ${counts}`;
  }
  return `0 applicants found even though resume-like elements exist — they may not be paired with a profile link nearby. Try Advanced → Custom selector. ${counts}`;
}

async function scan() {
  const tab = await resolveTargetTab();
  if (!tab || !SUPPORTED_URL.test(tab.url || "")) {
    setStatus("Open a LinkedIn job's Applicants page (linkedin.com/hiring/... ) in this tab, then reopen.", false);
    return;
  }

  const injected = await ensureContentScript(tab.id);
  if (!injected) {
    setStatus("Could not access this LinkedIn tab. Reload the page and try again.", false);
    return;
  }

  scanBtn.disabled = true;
  scanStatus.textContent = autoScrollChk.checked ? "Loading all applicants…" : "Scanning…";

  const messageType = autoScrollChk.checked ? "LRD_AUTO_LOAD_AND_SCAN" : "LRD_SCAN";
  const customSelector = customSelectorInput.value.trim();

  try {
    const response = await chrome.tabs.sendMessage(tab.id, { type: messageType, customSelector });
    if (!response || !response.ok) throw new Error("No response from page.");

    applicants = response.applicants;
    jobContext = sanitize(response.pageTitle || "").replace(/\s*\|\s*linkedin.*$/i, "");

    if (applicants.length === 0) {
      scanStatus.textContent = explainZeroResults(response.diagnostics);
    } else {
      const foundCount = applicants.filter((a) => !a.needsManualClick).length;
      scanStatus.textContent = `${applicants.length} applicant(s) found, ${foundCount} resume link(s) resolvable.`;
    }
    renderResults();
  } catch (e) {
    scanStatus.textContent = "";
    setStatus(`Scan failed: ${e.message}. Try reloading the LinkedIn tab.`, true);
  } finally {
    scanBtn.disabled = false;
  }
}

async function downloadOneApplicant(applicant, filename) {
  const direct = await chrome.runtime.sendMessage({
    type: "LRD_DOWNLOAD_ONE",
    payload: { url: applicant.resumeUrl, filename, folder: jobContext },
  });
  if (direct && direct.ok) return direct;
  if (applicant.needsManualClick || !applicant.resumeElementId) return direct;

  // The direct link was a client-rendered LinkedIn viewer route rather than
  // a file: open it for real and capture the document request it makes.
  return chrome.runtime.sendMessage({
    type: "LRD_DOWNLOAD_VIA_VIEWER",
    payload: { tabId: targetTabId, elementId: applicant.resumeElementId, filename, folder: jobContext },
  });
}

// Sequentially downloads one list of applicants, reporting progress via
// onProgress(doneCount, failedCount, total, currentApplicant) after each
// attempt. Stops itself if the same error repeats 3 times in a row (a
// systemic failure, not a per-applicant one) rather than grinding through
// everyone. Shared by the single-page "Download selected" and the
// multi-page "Download all pages" flows below.
async function downloadApplicantList(targets, { delayMs, onProgress }) {
  let done = 0;
  let failed = 0;
  let lastError = null;
  let sameErrorStreak = 0;
  let stoppedEarly = false;

  for (const applicant of targets) {
    if (onProgress) onProgress(done, failed, targets.length, applicant);
    const filename = `${sanitize(applicant.name)}_Resume`;

    const result = await downloadOneApplicant(applicant, filename);

    if (result && result.ok) {
      applicant.status = "done";
      done++;
      sameErrorStreak = 0;
    } else {
      const message = (result && result.error) || "Failed";
      applicant.status = "error";
      applicant.statusMessage = message;
      failed++;
      sameErrorStreak = message === lastError ? sameErrorStreak + 1 : 1;
      lastError = message;
    }
    renderResults();

    if (sameErrorStreak >= 3) {
      stoppedEarly = true;
      break;
    }

    await sleep(delayMs);
  }

  return { done, failed, lastError, sameErrorStreak, stoppedEarly, total: targets.length };
}

function summarizeDownloadResult(result) {
  if (result.stoppedEarly) {
    return (
      `Stopped after ${result.done + result.failed} of ${result.total}: the last ${result.sameErrorStreak} ` +
      `resumes all failed the same way ("${result.lastError}"), so the rest would too. See the README's ` +
      `"If it finds 0 resumes" section, or share what happens when you click the resume icon manually so ` +
      `this can be fixed for your page.`
    );
  }
  return `Done. ${result.done} downloaded, ${result.failed} failed.` +
    (result.failed ? " Check the tags above for details." : "");
}

async function downloadSelected() {
  const checkboxes = [...resultsEl.querySelectorAll('input[type="checkbox"]:checked')];
  const selectedIds = new Set(checkboxes.map((c) => c.dataset.id));
  const targets = applicants.filter((a) => selectedIds.has(a.id) && a.resumeUrl);

  if (targets.length === 0) {
    progressEl.hidden = false;
    progressEl.textContent = "Nothing selected with a resolvable resume link.";
    return;
  }

  downloadBtn.disabled = true;
  scanBtn.disabled = true;
  allPagesBtn.disabled = true;
  progressEl.hidden = false;

  const delayMs = Number(delayMsInput.value) || 800;
  const result = await downloadApplicantList(targets, {
    delayMs,
    onProgress: (done, failed, total, applicant) => {
      progressEl.textContent = `Downloading ${done + failed + 1} / ${total}: ${applicant.name}`;
    },
  });

  progressEl.textContent = summarizeDownloadResult(result);
  downloadBtn.disabled = false;
  scanBtn.disabled = false;
  allPagesBtn.disabled = false;
}

// --- Multi-page: LinkedIn paginates the Applicants table via a `start=`
// URL parameter (confirmed: each page load is a fixed-size slice, not an
// infinite-scroll within one page), so downloading "everything" for a job
// with hundreds/thousands of applicants means navigating through many
// page loads, scanning and downloading each before moving to the next.

function getStartParam(url) {
  try {
    return Number(new URL(url).searchParams.get("start")) || 0;
  } catch {
    return 0;
  }
}

function withStartParam(url, start) {
  const u = new URL(url);
  u.searchParams.set("start", String(start));
  return u.toString();
}

function jobStorageKey(url) {
  try {
    const jobId = new URL(url).searchParams.get("jobId");
    return `lrdProgress_${jobId || new URL(url).pathname}`;
  } catch {
    return "lrdProgress_unknown";
  }
}

async function navigateAndWait(tabId, url, timeoutMs = 15000) {
  try {
    await chrome.tabs.sendMessage(tabId, { type: "LRD_NAVIGATE", url });
  } catch {
    // Message channel closes as the page unloads -- expected, not an error.
  }

  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    await sleep(600);
    try {
      const pong = await chrome.tabs.sendMessage(tabId, { type: "LRD_PING" });
      if (pong && pong.ok && pong.url && pong.url.includes(`start=${getStartParam(url)}`)) {
        return true;
      }
    } catch {
      // content script not ready yet on the new page; keep polling
    }
  }
  return false;
}

// window.confirm()/alert() don't reliably work inside an extension popup
// context, so this asks in-page instead: shows two buttons and resolves
// once one is clicked.
function askResumeOrRestart(savedProgress) {
  return new Promise((resolve) => {
    resumePrompt.innerHTML = "";
    resumePrompt.hidden = false;

    const text = document.createElement("p");
    text.className = "muted";
    text.textContent =
      `Found earlier progress for this job: ${savedProgress.totalDownloaded} resume(s) downloaded, ` +
      `stopped before start=${savedProgress.nextStart}.`;

    const resumeBtn = document.createElement("button");
    resumeBtn.textContent = `Resume from start=${savedProgress.nextStart}`;
    const restartBtn = document.createElement("button");
    restartBtn.className = "secondary";
    restartBtn.textContent = "Start over from page 0";

    resumeBtn.addEventListener("click", () => {
      resumePrompt.hidden = true;
      resolve(savedProgress.nextStart);
    });
    restartBtn.addEventListener("click", () => {
      resumePrompt.hidden = true;
      resolve(0);
    });

    resumePrompt.appendChild(text);
    resumePrompt.appendChild(resumeBtn);
    resumePrompt.appendChild(restartBtn);
  });
}

async function downloadAllPages() {
  const tab = await resolveTargetTab();
  if (!tab || !SUPPORTED_URL.test(tab.url || "")) {
    setStatus("Open a LinkedIn job's Applicants page (linkedin.com/hiring/... ) in this tab, then reopen.", false);
    return;
  }

  const pageSize = Number(pageSizeInput.value) || 30;
  const storageKey = jobStorageKey(tab.url);
  const { [storageKey]: savedProgress } = await chrome.storage.local.get(storageKey);

  let startAt = 0;
  if (savedProgress && savedProgress.nextStart > 0) {
    startAt = await askResumeOrRestart(savedProgress);
  }

  downloadBtn.disabled = true;
  scanBtn.disabled = true;
  allPagesBtn.disabled = true;
  progressEl.hidden = false;
  pageProgressEl.hidden = false;

  const delayMs = Number(delayMsInput.value) || 800;
  const customSelector = customSelectorInput.value.trim();
  const MAX_PAGES = 400; // safety cap: 400 * 30 = 12,000 applicants
  let consecutiveEmptyPages = 0;
  let consecutiveFailedPages = 0;
  let totalDownloaded = 0;
  let totalFailed = 0;
  let pagesProcessed = 0;
  let start = startAt;
  let outcome = "end"; // 'end' | 'load-failed' | 'page-failures' | 'max-pages'

  for (; pagesProcessed < MAX_PAGES; start += pageSize, pagesProcessed++) {
    pageProgressEl.textContent = `Page starting at ${start} (${totalDownloaded} downloaded so far, ${pagesProcessed} page(s) done)…`;

    const pageUrl = withStartParam(tab.url, start);
    const ready = await navigateAndWait(tab.id, pageUrl);
    if (!ready) {
      outcome = "load-failed";
      break;
    }

    const messageType = autoScrollChk.checked ? "LRD_AUTO_LOAD_AND_SCAN" : "LRD_SCAN";
    let response;
    try {
      response = await chrome.tabs.sendMessage(tab.id, { type: messageType, customSelector });
    } catch (e) {
      response = null;
    }

    const pageApplicants = (response && response.ok && response.applicants) || [];
    applicants = pageApplicants;
    renderResults();

    if (pageApplicants.length === 0) {
      consecutiveEmptyPages++;
      if (consecutiveEmptyPages >= 2) {
        outcome = "end";
        break;
      }
      continue;
    }
    consecutiveEmptyPages = 0;

    const targets = pageApplicants.filter((a) => a.resumeUrl);
    const result = await downloadApplicantList(targets, {
      delayMs,
      onProgress: (done, failed, total, applicant) => {
        progressEl.textContent = `Page start=${start}: downloading ${done + failed + 1} / ${total}: ${applicant.name}`;
      },
    });

    totalDownloaded += result.done;
    totalFailed += result.failed;
    consecutiveFailedPages = result.done === 0 && targets.length > 0 ? consecutiveFailedPages + 1 : 0;

    await chrome.storage.local.set({
      [storageKey]: { nextStart: start + pageSize, totalDownloaded, updatedAt: Date.now() },
    });

    if (consecutiveFailedPages >= 3) {
      outcome = "page-failures";
      break;
    }
  }

  if (pagesProcessed >= MAX_PAGES) outcome = "max-pages";

  const messages = {
    end: `Done. ${totalDownloaded} downloaded across ${pagesProcessed} page(s), ${totalFailed} failed. Reached the end of the list.`,
    "load-failed": `Could not load the page at start=${start} in time. Stopped here -- progress is saved; re-run "Download all pages" to resume.`,
    "page-failures": `Stopped: 3 pages in a row downloaded nothing successfully (last page start=${start}). Progress is saved -- re-run to resume from start=${start + pageSize}.`,
    "max-pages": `Stopped at the ${MAX_PAGES}-page safety limit (${totalDownloaded} downloaded). Re-run to continue from where this left off.`,
  };
  pageProgressEl.textContent = messages[outcome];

  if (outcome === "end") {
    await chrome.storage.local.remove(storageKey);
  } else if (outcome !== "page-failures") {
    // page-failures already persisted its own resume point above; the
    // other non-"end" outcomes need it saved now that the loop has exited.
    await chrome.storage.local.set({
      [storageKey]: { nextStart: start, totalDownloaded, updatedAt: Date.now() },
    });
  }

  downloadBtn.disabled = false;
  scanBtn.disabled = false;
  allPagesBtn.disabled = false;
}

popOutBtn.addEventListener("click", async () => {
  const tab = await resolveTargetTab();
  if (!tab) return;
  await chrome.windows.create({
    url: chrome.runtime.getURL(`popup.html?tabId=${tab.id}&standalone=1`),
    type: "popup",
    width: 420,
    height: 640,
  });
  if (!standalone) window.close();
});

scanBtn.addEventListener("click", scan);
downloadBtn.addEventListener("click", downloadSelected);
allPagesBtn.addEventListener("click", downloadAllPages);
selectAllChk.addEventListener("change", () => {
  resultsEl.querySelectorAll('input[type="checkbox"]:not(:disabled)').forEach((c) => {
    c.checked = selectAllChk.checked;
  });
});
[autoScrollChk, customSelectorInput, delayMsInput, pageSizeInput].forEach((el) =>
  el.addEventListener("change", saveSettings)
);

(async function init() {
  await loadSettings();
  const tab = await resolveTargetTab();
  if (!tab) {
    setStatus("No LinkedIn tab found. Open your job's Applicants page first.", false);
    return;
  }
  if (!SUPPORTED_URL.test(tab.url || "")) {
    setStatus("Open a LinkedIn job's Applicants page (linkedin.com/hiring/... ) then reopen this popup.", false);
    return;
  }
  setStatus("", true);
  if (standalone) popOutBtn.hidden = true;
})();
