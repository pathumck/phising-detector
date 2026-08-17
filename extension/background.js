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