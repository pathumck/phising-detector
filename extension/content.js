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