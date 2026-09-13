// Service worker: performs the actual downloads and resolves resume links
// that point at an HTML viewer page rather than the raw file.

const BINARY_CONTENT_TYPES = [
  /application\/pdf/i,
  /application\/octet-stream/i,
  /application\/msword/i,
  /officedocument/i,
];

const EMBEDDED_URL_PATTERN =
  /["'](https:\/\/[^"']*(?:\.pdf|\.docx?|\/dms\/(?:prv|document)\/[^"']+)[^"']*)["']/i;

// LinkedIn's document endpoints don't always serve the file directly -- some
// return a small JSON descriptor about it instead (confirmed shape:
// {"asset": "...", "transcribedDocumentUrl": "<the real file>",
// "scanRequiredForDownload": true, "perResolutions": [...]}). Look for the
// known field first, then fall back to scanning for any string value that
// looks like the actual document URL, in case the field name ever changes.
function extractNestedDocumentUrl(data) {
  if (!data || typeof data !== "object") return null;
  if (typeof data.transcribedDocumentUrl === "string") return data.transcribedDocumentUrl;

  for (const value of Object.values(data)) {
    if (typeof value === "string" && /\/dms\/(prv|document)\//i.test(value) && /pdf|docx?/i.test(value)) {
      return value;
    }
  }
  for (const value of Object.values(data)) {
    if (value && typeof value === "object") {
      const nested = extractNestedDocumentUrl(Array.isArray(value) ? value[0] : value);
      if (nested) return nested;
    }
  }
  return null;
}

async function resolveDownloadable(url, depth = 0) {
  if (depth > 3) return { ok: false, error: "Too many redirects while resolving resume link." };

  let response;
  try {
    response = await fetch(url, { credentials: "include", redirect: "follow" });
  } catch (e) {
    return { ok: false, error: `Could not reach ${url}: ${e.message}` };
  }

  if (!response.ok) {
    return { ok: false, error: `LinkedIn returned HTTP ${response.status} for this resume link.` };
  }

  const contentType = response.headers.get("content-type") || "";

  if (BINARY_CONTENT_TYPES.some((re) => re.test(contentType))) {
    return { ok: true, url: response.url, contentType };
  }

  if (/application\/json/i.test(contentType)) {
    let data;
    try {
      data = await response.json();
    } catch (e) {
      return { ok: false, error: "LinkedIn returned an unreadable JSON response for this resume link." };
    }
    const nestedUrl = extractNestedDocumentUrl(data);
    if (nestedUrl) {
      return resolveDownloadable(nestedUrl, depth + 1);
    }
    return {
      ok: false,
      error: "LinkedIn returned document metadata this extension couldn't find a file URL inside.",
    };
  }

  if (/text\/html/i.test(contentType)) {
    const text = await response.text();
    const match = text.match(EMBEDDED_URL_PATTERN);
    if (match) {
      return resolveDownloadable(match[1], depth + 1);
    }
    return {
      ok: false,
      error: "This resume link opens a LinkedIn viewer page this extension can't parse automatically.",
    };
  }

  // Unknown content-type: try it anyway, most likely a direct file.
  return { ok: true, url: response.url, contentType };
}

function extensionForContentType(contentType) {
  if (/pdf/i.test(contentType)) return "pdf";
  if (/officedocument.wordprocessingml/i.test(contentType)) return "docx";
  if (/msword/i.test(contentType)) return "doc";
  return "pdf";
}

function subfolderFor(folder) {
  return folder ? `LinkedIn Resumes/${folder}` : "LinkedIn Resumes";
}

async function saveDownload(url, filename, folder) {
  try {
    const downloadId = await chrome.downloads.download({
      url,
      filename: `${subfolderFor(folder)}/${filename}`,
      conflictAction: "uniquify",
      saveAs: false,
    });
    return { ok: true, downloadId };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}

async function resolveAndSave(url, filename, folder) {
  const resolved = await resolveDownloadable(url);
  if (!resolved.ok) return resolved;

  let finalName = filename || "resume";
  if (!/\.[a-z0-9]{2,4}$/i.test(finalName)) {
    finalName = `${finalName}.${extensionForContentType(resolved.contentType)}`;
  }

  return saveDownload(resolved.url, finalName, folder);
}

async function downloadResume({ url, filename, folder }) {
  return resolveAndSave(url, filename, folder);
}

// Fallback for resume links that are a client-rendered LinkedIn viewer route
// rather than a direct file (confirmed pattern: opening the viewer makes the
// page itself request the real file from /dms/prv/document/...). We click
// the resume element to open that viewer, catch the matching network
// request as LinkedIn's own JS fires it, download straight from that
// signed URL, then close the viewer so the next applicant's click isn't
// blocked by a modal sitting over the row.
const DOCUMENT_REQUEST_PATTERN = "*://*.linkedin.com/dms/prv/document/*";
let pendingCapture = null;

chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    if (pendingCapture && details.tabId === pendingCapture.tabId) {
      const resolve = pendingCapture.resolve;
      pendingCapture = null;
      resolve(details.url);
    }
  },
  { urls: [DOCUMENT_REQUEST_PATTERN] }
);

function waitForDocumentRequest(tabId, timeoutMs) {
  return new Promise((resolve) => {
    pendingCapture = { tabId, resolve };
    setTimeout(() => {
      if (pendingCapture && pendingCapture.resolve === resolve) {
        pendingCapture = null;
        resolve(null);
      }
    }, timeoutMs);
  });
}

async function downloadViaViewer({ tabId, elementId, filename, folder }) {
  const capturePromise = waitForDocumentRequest(tabId, 8000);

  try {
    await chrome.tabs.sendMessage(tabId, { type: "LRD_CLICK_ELEMENT", elementId });
  } catch (e) {
    pendingCapture = null;
    return { ok: false, error: `Could not open the resume viewer: ${e.message}` };
  }

  const capturedUrl = await capturePromise;
  chrome.tabs.sendMessage(tabId, { type: "LRD_CLOSE_MODAL" }).catch(() => {});

  if (!capturedUrl) {
    return {
      ok: false,
      error: "Clicked the resume icon but no document request appeared within 8s (viewer may be slow, or this applicant has no resume attached).",
    };
  }

  // The captured request is sometimes a JSON descriptor about the document
  // rather than the document itself (see extractNestedDocumentUrl above) --
  // route it through the same resolver as the direct-link path instead of
  // assuming it's already the file.
  return resolveAndSave(capturedUrl, filename, folder);
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || !message.type) return undefined;

  if (message.type === "LRD_DOWNLOAD_ONE") {
    downloadResume(message.payload).then(sendResponse);
    return true;
  }

  if (message.type === "LRD_DOWNLOAD_VIA_VIEWER") {
    const tabId = message.payload.tabId || (sender.tab && sender.tab.id);
    downloadViaViewer({ ...message.payload, tabId }).then(sendResponse);
    return true;
  }

  return undefined;
});
