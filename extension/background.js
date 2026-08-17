/**
 * Intercepts main-frame navigations before loading. Redirects to interstitial.html
 * to check the URL against the backend before allowing navigation or blocking.
 */

const API_URL = "http://localhost:5000/predict";
const FETCH_TIMEOUT_MS = 4000;
const INTERSTITIAL_URL = chrome.runtime.getURL("interstitial.html");

// tabId -> URL allowed through without interception.
// One-shot bypass for cleared destinations.
const pendingApprovals = new Map();


//Execute a fetch request with a timeout.
async function fetchWithTimeout(url, options, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}


//Check whether a URL can be inspected by the extension.
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


