// Content script for LinkedIn "Applicants" pages.
//
// LinkedIn does not expose a stable, documented DOM structure for applicant
// resume links, and its class names are largely auto-generated and change
// often. To stay resilient, this scanner deliberately avoids relying on any
// specific class name. Instead it anchors on two things that are part of
// LinkedIn's actual product semantics and therefore far more stable:
//   1. Profile links, which always match the "/in/<slug>" URL pattern.
//   2. Resume affordances, identified by their href or visible text/aria
//      label containing "resume" (or a direct link to a PDF/document).
//
// If LinkedIn changes its markup enough that this stops finding resumes,
// use the "Custom selector" field in the popup to point directly at the
// resume link/button for one applicant card.

(function () {
  const RESUME_HREF_PATTERNS = [
    /resume/i,
    /\/dms\/(prv|document)\//i,
    /\.pdf(\?|#|$)/i,
    /\.docx?(\?|#|$)/i,
  ];

  const RESUME_TEXT_PATTERN = /\b(?:(?:download|view|see|open)\s*)?(?:resume|cv)s?\b/i;
  const PROFILE_HREF_PATTERN = /linkedin\.com\/in\/[^/?#]+/i;

  const MAX_ANCESTOR_WALK = 8;
  const STAMP_ATTR = "data-lrd-id";
  let stampCounter = 0;

  function stamp(el) {
    if (!el.hasAttribute(STAMP_ATTR)) {
      el.setAttribute(STAMP_ATTR, String(++stampCounter));
    }
    return el.getAttribute(STAMP_ATTR);
  }

  function sanitizeFilenamePart(text) {
    return (text || "")
      .replace(/[\\/:*?"<>|]+/g, " ")
      .replace(/\s+/g, " ")
      .trim()
      .slice(0, 80);
  }

  function isVisible(el) {
    if (!(el instanceof Element)) return false;
    const rect = el.getBoundingClientRect();
    if (rect.width === 0 && rect.height === 0) return false;
    const style = window.getComputedStyle(el);
    return style.visibility !== "hidden" && style.display !== "none";
  }

  function findResumeCandidates(root, customSelector) {
    const found = [];
    const seenEls = new Set();

    function add(el, meta) {
      if (!el || seenEls.has(el)) return;
      seenEls.add(el);
      found.push({ el, ...meta });
    }

    if (customSelector) {
      try {
        root.querySelectorAll(customSelector).forEach((el) =>
          add(el, { url: el.href || el.getAttribute("href") || null, source: "custom" })
        );
      } catch (e) {
        console.warn("[Resume Downloader] Invalid custom selector:", customSelector, e);
      }
    }

    root.querySelectorAll("a[href]").forEach((a) => {
      if (RESUME_HREF_PATTERNS.some((re) => re.test(a.href))) {
        add(a, { url: a.href, source: "href" });
      }
    });

    root.querySelectorAll("a, button, [role='button']").forEach((el) => {
      const label = `${el.textContent || ""} ${el.getAttribute("aria-label") || ""}`.trim();
      if (RESUME_TEXT_PATTERN.test(label)) {
        const url = el.tagName === "A" ? el.href : null;
        add(el, { url, source: "text" });
      }
    });

    return found;
  }

  function findProfileLink(container) {
    const anchors = container.querySelectorAll("a[href]");
    for (const a of anchors) {
      if (PROFILE_HREF_PATTERN.test(a.href)) return a;
    }
    return null;
  }

  function extractName(row, profileLink) {
    if (profileLink) {
      const text = sanitizeFilenamePart(profileLink.textContent);
      if (text && text.length <= 100) return text;
      const aria = sanitizeFilenamePart(profileLink.getAttribute("aria-label"));
      if (aria) return aria;
    }
    const heading = row.querySelector("h1, h2, h3, h4, strong");
    if (heading) {
      const text = sanitizeFilenamePart(heading.textContent);
      if (text) return text;
    }
    return "Unknown applicant";
  }

  function findApplicantRow(resumeEl) {
    let node = resumeEl;
    for (let i = 0; i < MAX_ANCESTOR_WALK && node && node !== document.body; i++) {
      const profileLink = findProfileLink(node);
      if (profileLink) return { row: node, profileLink };
      node = node.parentElement;
    }
    return { row: resumeEl.parentElement || resumeEl, profileLink: null };
  }

  function diagnostics(customSelector) {
    let profileLinks = 0;
    document.querySelectorAll("a[href]").forEach((a) => {
      if (PROFILE_HREF_PATTERN.test(a.href)) profileLinks++;
    });
    return {
      totalAnchors: document.querySelectorAll("a").length,
      totalButtons: document.querySelectorAll("button, [role='button']").length,
      profileLinksFound: profileLinks,
      resumeCandidatesFound: findResumeCandidates(document, customSelector).length,
    };
  }

  function scanApplicants(options = {}) {
    const { customSelector = "" } = options;
    const candidates = findResumeCandidates(document, customSelector);
    const rowsById = new Map();

    for (const candidate of candidates) {
      const { row, profileLink } = findApplicantRow(candidate.el);
      const rowId = stamp(row);
      const name = extractName(row, profileLink);
      const profileUrl = profileLink ? profileLink.href.split("?")[0] : null;

      if (!rowsById.has(rowId)) {
        rowsById.set(rowId, {
          id: rowId,
          name,
          profileUrl,
          resumeUrl: candidate.url || null,
          resumeElementId: stamp(candidate.el),
          needsManualClick: !candidate.url,
          visible: isVisible(row),
        });
      } else {
        const existing = rowsById.get(rowId);
        if (!existing.resumeUrl && candidate.url) {
          existing.resumeUrl = candidate.url;
          existing.needsManualClick = false;
          existing.resumeElementId = stamp(candidate.el);
        }
      }
    }

    return Array.from(rowsById.values());
  }

  function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  function findLoadMoreControl() {
    const buttons = document.querySelectorAll("button, a[role='button']");
    const pattern = /^(show more|see more|load more|next)\b/i;
    for (const btn of buttons) {
      const label = (btn.textContent || btn.getAttribute("aria-label") || "").trim();
      if (pattern.test(label) && isVisible(btn) && !btn.disabled) {
        return btn;
      }
    }
    return null;
  }

  async function autoLoadAll({ maxIterations = 40, stepDelayMs = 1000 } = {}) {
    let lastCount = -1;
    let stableRounds = 0;

    for (let i = 0; i < maxIterations && stableRounds < 2; i++) {
      const count = scanApplicants().length;
      if (count === lastCount) {
        stableRounds++;
      } else {
        stableRounds = 0;
      }
      lastCount = count;

      window.scrollTo(0, document.body.scrollHeight);
      const control = findLoadMoreControl();
      if (control) control.click();

      await sleep(stepDelayMs);
    }

    return scanApplicants().length;
  }

  chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
    if (!message || !message.type) return undefined;

    if (message.type === "LRD_PING") {
      sendResponse({ ok: true, url: location.href });
      return undefined;
    }

    if (message.type === "LRD_SCAN") {
      const applicants = scanApplicants({ customSelector: message.customSelector });
      sendResponse({
        ok: true,
        pageTitle: document.title,
        applicants,
        diagnostics: applicants.length === 0 ? diagnostics(message.customSelector) : null,
      });
      return undefined;
    }

    if (message.type === "LRD_AUTO_LOAD_AND_SCAN") {
      autoLoadAll(message.options || {}).then(() => {
        const applicants = scanApplicants({ customSelector: message.customSelector });
        sendResponse({
          ok: true,
          pageTitle: document.title,
          applicants,
          diagnostics: applicants.length === 0 ? diagnostics(message.customSelector) : null,
        });
      });
      return true; // async response
    }

    if (message.type === "LRD_CLICK_ELEMENT") {
      const el = document.querySelector(`[${STAMP_ATTR}="${CSS.escape(message.elementId)}"]`);
      if (el) {
        el.scrollIntoView({ block: "center", behavior: "smooth" });
        el.classList.add("lrd-highlight");
        setTimeout(() => el.classList.remove("lrd-highlight"), 2000);
        el.click();
        sendResponse({ ok: true });
      } else {
        sendResponse({ ok: false, error: "Element no longer on page; re-scan." });
      }
      return undefined;
    }

    return undefined;
  });

  // Exposed only inside this content script's isolated JS world (LinkedIn's
  // own page scripts run in a separate realm and cannot see this), purely so
  // the extension's own devtools console / test harness can call it directly.
  window.__LRD__ = { scanApplicants, autoLoadAll, sanitizeFilenamePart, diagnostics };
})();
