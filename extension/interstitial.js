/**
 * Intercepts navigations and checks URLs with the backend before redirecting
 * or displaying a block screen.
 */

const LAYER_LABELS = {
  blacklist: "Known Phishing Domain",
  whitelist: "Trusted Domain",
  lookalike_homograph: "Homograph Character Attack",
  lookalike_exact_lookalike: "Domain Impersonation Attack",
  lookalike_typosquatting: "Typosquatting Attack",
  ml_model: "ML Analysis",
};

const STAGES = ["Blacklist", "Whitelist", "Lookalike", "ML Model"];

function stageIndexForLayer(layer) {
  if (layer === "blacklist") return 0;
  if (layer === "whitelist") return 1;
  if (layer && layer.startsWith("lookalike")) return 2;
  if (layer === "ml_model") return 3;
  return STAGES.length - 1;
}

function humanLayerName(layer) {
  return LAYER_LABELS[layer] || layer || "Unknown";
}

function formatConfidence(confidence) {
  return `${Math.round((confidence || 0) * 100)}%`;
}