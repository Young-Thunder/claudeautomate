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

async function resolveDownloadable(url, depth = 0) {
  if (depth > 2) return { ok: false, error: "Too many redirects while resolving resume link." };

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

async function downloadResume({ url, filename, folder }) {
  const resolved = await resolveDownloadable(url);
  if (!resolved.ok) return resolved;

  let finalName = filename || "resume";
  if (!/\.[a-z0-9]{2,4}$/i.test(finalName)) {
    finalName = `${finalName}.${extensionForContentType(resolved.contentType)}`;
  }

  const subfolder = folder ? `LinkedIn Resumes/${folder}` : "LinkedIn Resumes";

  try {
    const downloadId = await chrome.downloads.download({
      url: resolved.url,
      filename: `${subfolder}/${finalName}`,
      conflictAction: "uniquify",
      saveAs: false,
    });
    return { ok: true, downloadId };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (!message || !message.type) return undefined;

  if (message.type === "LRD_DOWNLOAD_ONE") {
    downloadResume(message.payload).then(sendResponse);
    return true;
  }

  return undefined;
});
