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

function renderLoading(app) {
  app.className = "panel panel-loading";
  app.innerHTML = `
    <div class="title">Phishing Guard</div>
    <div class="status-text">No scan data for this tab yet.</div>
  `;
}

function renderOffline(app, entry) {
  app.className = "panel panel-warning";
  app.innerHTML = `
    <div class="title">Phishing Guard</div>
    <span class="badge badge-warning">BACKEND OFFLINE</span>
    <div class="status-text">
      Could not reach the detection server at localhost:5000.
      Make sure Flask (app.py) is running.
    </div>
  `;
}

function renderSafe(app, verdict, checkedUrl) {
  app.className = "panel panel-safe";
  app.innerHTML = `
    <div class="title">Phishing Guard</div>
    <span class="badge badge-safe">SAFE</span>
    <div class="domain">${verdict.domain || checkedUrl}</div>
    <div class="details">
      <div><strong>Confidence:</strong> <span>${formatConfidence(verdict.confidence)}</span></div>
      <div><strong>Checked via:</strong> <span>${humanLayerName(verdict.detection_layer)}</span></div>
    </div>
  `;
}

function renderPhishing(app, verdict) {
  app.className = "panel panel-danger";
  app.innerHTML = `
    <div class="title">Phishing Guard</div>
    <span class="badge badge-danger">DANGEROUS</span>
    <div class="domain">${verdict.domain}</div>
    <div class="details">
      <div><strong>Detection method:</strong> <span>${humanLayerName(verdict.detection_layer)}</span></div>
      <div><strong>Confidence:</strong> <span>${formatConfidence(verdict.confidence)}</span></div>
      <div><strong>Why:</strong> <span>${verdict.explanation || "No further details."}</span></div>
    </div>
  `;
}