/**
 * Intercepts main-frame navigations before loading. Redirects to interstitial.html
 * to check the URL against the backend before allowing navigation or blocking.
 *
 * IMPORTANT (redirect timing):
 * Manifest V3's chrome.webNavigation.onBeforeNavigate is a notification only -
 * it does NOT pause or block the browser's own navigation while listeners run.
 * The real destination page starts loading in parallel regardless of what this
 * listener does. Previously this listener awaited a network call
 * (wasRecentlyOverridden) BEFORE calling chrome.tabs.update() to redirect to
 * the interstitial - during that wait (up to FETCH_TIMEOUT_MS), the real page
 * could finish loading and briefly render before the redirect kicked in.
 *
 * Fix: chrome.tabs.update() to the interstitial now fires immediately, with
 * no awaited work in front of it. The override check still happens, but only
 * AFTER the redirect, and is used to silently auto-approve the navigation
 * (skip re-showing a warning the user already dismissed) rather than to
 * decide whether to redirect in the first place.
 *
 * IMPORTANT ("Go Back to Safety" fix):
 * The interstitial/overlay "Go Back to Safety" button used to call
 * window.history.back() directly. That triggers a brand-new top-level
 * navigation back to the previous page, which onBeforeNavigate intercepts
 * just like any other navigation - so instead of landing on the previous
 * page, the user got redirected to ANOTHER interstitial to re-check it.
 * Native browser back-button clicks mostly avoided this because Chrome can
 * often restore the previous page from the back/forward cache (bfcache)
 * rather than issuing a fresh navigation the same way a scripted
 * history.back() call does.
 *
 * Fix: track the last known "good" URL per tab (the URL we were on right
 * before redirecting to the interstitial). When the user asks to go back,
 * we pre-approve that URL via pendingApprovals (the same one-shot bypass
 * mechanism used for overrides) and use chrome.tabs.goBack(), so when
 * onBeforeNavigate fires again for it, it passes straight through instead
 * of triggering another check.
 */

// const API_URL = "http://localhost:5000/predict";
// const OVERRIDE_URL = "http://localhost:5000/override";
// const OVERRIDE_CHECK_URL = "http://localhost:5000/override/check";
const API_URL = "https://phishing-guard-csrf.onrender.com/predict";
const OVERRIDE_URL = "https://phishing-guard-csrf.onrender.com/override";
const OVERRIDE_CHECK_URL = "https://phishing-guard-csrf.onrender.com/override/check";
const FETCH_TIMEOUT_MS = 30000;
const INTERSTITIAL_URL = chrome.runtime.getURL("interstitial.html");

// tabId -> URL allowed through without interception.
// One-shot bypass for cleared destinations.
const pendingApprovals = new Map();

// tabId -> URL the tab was on immediately before being redirected to the
// interstitial. Used to power the "Go Back to Safety" action.
const lastKnownGoodUrl = new Map();

// Execute a fetch request with a timeout.
async function fetchWithTimeout(url, options, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

// Check whether a URL can be inspected by the extension.
function isCheckableUrl(url) {
  return typeof url === "string" && /^https?:\/\//i.test(url);
}

function setBadge(tabId, state) {
  const BADGE_STYLES = {
    safe: { text: "OK", color: "#22C55E" },
    danger: { text: "!", color: "#EF4444" },
    offline: { text: "?", color: "#F59E0B" },
    clear: { text: "", color: "#000000" },
  };
  const style = BADGE_STYLES[state] || BADGE_STYLES.clear;
  chrome.action.setBadgeText({ tabId, text: style.text });
  chrome.action.setBadgeBackgroundColor({ tabId, color: style.color });
}

/**
 * Runs backend check and updates storage and badge state.
 * Returns stored result object.
 */
async function runBackendCheck(tabId, url) {
  const storageKey = String(tabId);
  try {
    const response = await fetchWithTimeout(
      API_URL,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      },
      FETCH_TIMEOUT_MS
    );
    if (!response.ok) {
      throw new Error(`Backend returned HTTP ${response.status}`);
    }
    const verdict = await response.json();
    const entry = { flaskOffline: false, checkedUrl: url, verdict };
    await chrome.storage.local.set({ [storageKey]: entry });
    setBadge(tabId, verdict.is_phishing ? "danger" : "safe");
    return entry;
  } catch (err) {
    const entry = { flaskOffline: true, checkedUrl: url, error: err.message };
    await chrome.storage.local.set({ [storageKey]: entry });
    setBadge(tabId, "offline");
    return entry;
  }
}

/**
 * Records that the user chose to proceed through a flagged warning.
 * Best-effort — a logging failure must never block navigation.
 */
async function recordOverride(tabId, url) {
  try {
    await fetchWithTimeout(
      OVERRIDE_URL,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url, tab_id: String(tabId) }),
      },
      FETCH_TIMEOUT_MS
    );
  } catch (err) {
    console.warn("[background] Could not record override:", err.message);
  }
}

/**
 * Checks whether this tab already overrode a warning for this URL
 * recently, so we can skip re-showing the interstitial and nagging
 * the user again this session.
 */
async function wasRecentlyOverridden(tabId, url) {
  try {
    const params = new URLSearchParams({ url, tab_id: String(tabId) });
    const response = await fetchWithTimeout(
      `${OVERRIDE_CHECK_URL}?${params.toString()}`,
      { method: "GET" },
      FETCH_TIMEOUT_MS
    );
    if (!response.ok) return false;
    const data = await response.json();
    return Boolean(data.already_overridden);
  } catch (err) {
    // Backend unreachable — fail safe by still showing the interstitial.
    return false;
  }
}

// Intercepts top-level navigations before loading.
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId !== 0) return;
  if (!isCheckableUrl(details.url)) return;

  // Consume one-shot approval if present
  if (pendingApprovals.get(details.tabId) === details.url) {
    pendingApprovals.delete(details.tabId);
    return;
  }

  // Skip interstitial page navigations
  if (details.url.startsWith(chrome.runtime.getURL(""))) return;

  // Record where this tab was BEFORE we redirect it away, so a later
  // "Go Back to Safety" click has a known-good URL to return to. Read this
  // before chrome.tabs.update() below overwrites the tab's current URL.
  try {
    const tab = await chrome.tabs.get(details.tabId);
    if (tab && isCheckableUrl(tab.url)) {
      lastKnownGoodUrl.set(details.tabId, tab.url);
    }
  } catch (err) {
    // Tab may not exist yet (e.g. first navigation in a new tab) — fine to skip.
  }

  // Redirect immediately, synchronously - no awaited work runs before
  // this call. This is what actually prevents the real page from
  // flashing on screen before the verdict panel appears: the browser
  // is already loading the destination in parallel the moment
  // onBeforeNavigate fires, so every millisecond spent waiting here
  // before redirecting is a millisecond the real page gets to render.
  const interstitialUrl =
    INTERSTITIAL_URL + "?target=" + encodeURIComponent(details.url);
  chrome.tabs.update(details.tabId, { url: interstitialUrl });

  // Override check now runs AFTER the redirect, non-blocking. If this
  // exact URL was already overridden recently in this tab, silently
  // auto-approve it so the user only sees a brief flash of the
  // interstitial rather than being re-shown a warning they already
  // dismissed. This preserves the original "don't nag again" behaviour
  // without delaying the redirect itself.
  wasRecentlyOverridden(details.tabId, details.url).then((overridden) => {
    if (overridden) {
      pendingApprovals.set(details.tabId, details.url);
      chrome.tabs.update(details.tabId, { url: details.url });
    }
  });
});

// Handles messages from interstitial.js, content.js and popup.js.
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message && message.type === "CHECK_FROM_INTERSTITIAL" && message.url) {
    const tabId = sender.tab && sender.tab.id;
    if (tabId == null) {
      sendResponse(null);
      return false;
    }
    runBackendCheck(tabId, message.url).then(sendResponse);
    return true;
  }

  if (message && message.type === "MARK_APPROVED" && message.url) {
    const tabId = sender.tab && sender.tab.id;
    if (tabId != null) {
      pendingApprovals.set(tabId, message.url);
    }
    sendResponse(true);
    return false;
  }

  if (message && message.type === "RECORD_OVERRIDE" && message.url) {
    const tabId = sender.tab && sender.tab.id;
    if (tabId == null) {
      sendResponse(false);
      return false;
    }
    recordOverride(tabId, message.url).then(() => sendResponse(true));
    return true;
  }

  if (message && message.type === "CHECK_NOW" && message.tabId && message.url) {
    runBackendCheck(message.tabId, message.url).then(sendResponse);
    return true;
  }

  if (
    message &&
    message.type === "GET_CURRENT_VERDICT" &&
    sender.tab &&
    sender.tab.id != null
  ) {
    chrome.storage.local.get(String(sender.tab.id)).then((stored) => {
      sendResponse(stored[String(sender.tab.id)] || null);
    });
    return true;
  }

  // "Go Back to Safety" — pre-approve the last known-good URL for this tab
  // (so onBeforeNavigate lets it through without re-checking) and navigate
  // back using the tab history. Falls back to Google if we have no known
  // previous URL or no history to go back to.
  if (message && message.type === "GO_BACK") {
    const tabId = sender.tab && sender.tab.id;
    if (tabId == null) {
      sendResponse(false);
      return false;
    }

    (async () => {
      const prevUrl = lastKnownGoodUrl.get(tabId);
      if (prevUrl) {
        pendingApprovals.set(tabId, prevUrl);
      }

      try {
        await chrome.tabs.goBack(tabId);
      } catch (err) {
        // No back history available in this tab — fall back to a safe default.
        const fallbackUrl = prevUrl || "https://www.google.com";
        pendingApprovals.set(tabId, fallbackUrl);
        await chrome.tabs.update(tabId, { url: fallbackUrl });
      }

      lastKnownGoodUrl.delete(tabId);
      sendResponse(true);
    })();

    return true;
  }
});

// Clean up storage and pending approvals when a tab closes.
chrome.tabs.onRemoved.addListener((tabId) => {
  chrome.storage.local.remove(String(tabId));
  pendingApprovals.delete(tabId);
  lastKnownGoodUrl.delete(tabId);
});