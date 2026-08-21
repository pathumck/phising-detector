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
 */

// const API_URL = "http://localhost:5000/predict";
// const OVERRIDE_URL = "http://localhost:5000/override";
// const OVERRIDE_CHECK_URL = "http://localhost:5000/override/check";
const API_URL = "https://phishing-guard-csrf.onrender.com/predict";
const OVERRIDE_URL = "https://phishing-guard-csrf.onrender.com/override";
const OVERRIDE_CHECK_URL = "https://phishing-guard-csrf.onrender.com/override/check";
const FETCH_TIMEOUT_MS = 4000;
const INTERSTITIAL_URL = chrome.runtime.getURL("interstitial.html");

// tabId -> URL allowed through without interception.
// One-shot bypass for cleared destinations.
const pendingApprovals = new Map();

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
chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  if (details.frameId !== 0) return;
  if (!isCheckableUrl(details.url)) return;

  // Consume one-shot approval if present
  if (pendingApprovals.get(details.tabId) === details.url) {
    pendingApprovals.delete(details.tabId);
    return;
  }

  // Skip interstitial page navigations
  if (details.url.startsWith(chrome.runtime.getURL(""))) return;

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
});

// Clean up storage and pending approvals when a tab closes
chrome.tabs.onRemoved.addListener((tabId) => {
  chrome.storage.local.remove(String(tabId));
  pendingApprovals.delete(tabId);
});