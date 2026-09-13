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
  }
}

function saveSettings() {
  chrome.storage.local.set({
    lrdSettings: {
      autoScroll: autoScrollChk.checked,
      customSelector: customSelectorInput.value.trim(),
      delayMs: Number(delayMsInput.value) || 800,
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
  progressEl.hidden = false;

  const delayMs = Number(delayMsInput.value) || 800;
  let done = 0;
  let failed = 0;

  for (const applicant of targets) {
    progressEl.textContent = `Downloading ${done + failed + 1} / ${targets.length}: ${applicant.name}`;
    const filename = `${sanitize(applicant.name)}_Resume`;

    const result = await chrome.runtime.sendMessage({
      type: "LRD_DOWNLOAD_ONE",
      payload: { url: applicant.resumeUrl, filename, folder: jobContext },
    });

    if (result && result.ok) {
      applicant.status = "done";
      done++;
    } else {
      applicant.status = "error";
      applicant.statusMessage = (result && result.error) || "Failed";
      failed++;
    }
    renderResults();
    await sleep(delayMs);
  }

  progressEl.textContent = `Done. ${done} downloaded, ${failed} failed.` +
    (failed ? " Check the tags above for details." : "");
  downloadBtn.disabled = false;
  scanBtn.disabled = false;
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
selectAllChk.addEventListener("change", () => {
  resultsEl.querySelectorAll('input[type="checkbox"]:not(:disabled)').forEach((c) => {
    c.checked = selectAllChk.checked;
  });
});
[autoScrollChk, customSelectorInput, delayMsInput].forEach((el) =>
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
