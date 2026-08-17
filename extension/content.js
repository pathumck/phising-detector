/**
 * Listens for the verdict forwarded by background.js. If the verdict
 * is phishing, renders a full-screen block overlay with inline CSS.
 */

const OVERLAY_ID = "phishing-guard-block-overlay";
const TOAST_ID = "phishing-guard-toast";
const TOAST_DURATION_MS = 4000;

const LAYER_LABELS = {
  blacklist: "Known Phishing Domain",
  whitelist: "Trusted Domain",
  lookalike_homograph: "Homograph Character Attack",
  lookalike_exact_lookalike: "Domain Impersonation Attack",
  lookalike_typosquatting: "Typosquatting Attack",
  ml_model: "ML Analysis",
};

function humanLayerName(layer) {
  return LAYER_LABELS[layer] || layer || "Unknown";
}

function formatConfidence(confidence) {
  const pct = Math.round((confidence || 0) * 100);
  return `${pct}%`;
}

// Displays an auto-dismissing corner notification for safe verdicts.
function showSafeToast(verdict) {
  const existing = document.getElementById(TOAST_ID);
  if (existing) {
    existing.remove();
  }

  const toast = document.createElement("div");
  toast.id = TOAST_ID;
  toast.setAttribute(
    "style",
    [
      "position: fixed",
      "top: 16px",
      "right: 16px",
      "z-index: 2147483647",
      "background-color: #1E293B",
      "border: 1px solid #22C55E",
      "border-radius: 8px",
      "padding: 10px 14px",
      "font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Arial, sans-serif",
      "font-size: 13px",
      "color: #F1F5F9",
      "box-shadow: 0 8px 24px rgba(0, 0, 0, 0.35)",
      "display: flex",
      "align-items: center",
      "gap: 8px",
      "opacity: 0",
      "transition: opacity 0.25s ease",
    ].join("; ")
  );

  const dot = document.createElement("span");
  dot.setAttribute(
    "style",
    "width: 8px; height: 8px; border-radius: 50%; background-color: #22C55E; flex-shrink: 0;"
  );

  const text = document.createElement("span");
  text.textContent = `Phishing Guard: page verified safe (${formatConfidence(
    verdict.confidence
  )}, ${humanLayerName(verdict.detection_layer)})`;

  toast.appendChild(dot);
  toast.appendChild(text);
  document.documentElement.appendChild(toast);

  requestAnimationFrame(() => {
    toast.style.opacity = "1";
  });

  setTimeout(() => {
    toast.style.opacity = "0";
    setTimeout(() => toast.remove(), 300);
  }, TOAST_DURATION_MS);
}