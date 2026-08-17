/**
 * Reads the verdict for the active tab from chrome.storage.local
 * and renders state panel: safe, phishing, or backend offline.
 */

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
  return `${Math.round((confidence || 0) * 100)}%`;
}