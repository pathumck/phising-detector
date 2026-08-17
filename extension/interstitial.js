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

const prefersReducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
const STEP_DELAY_MS = prefersReducedMotion ? 0 : 110;

const params = new URLSearchParams(window.location.search);
const targetUrl = params.get("target");

const card = document.getElementById("card");
const content = document.getElementById("content");

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function buildStepperMarkup(url) {
  content.innerHTML = `
    <div class="domain">${url}</div>
    <div class="stepper" id="stepper">
      ${STAGES.map(
        (_, i) => `<div class="step" id="step-${i}"><div class="step-fill"></div></div>`
      ).join("")}
    </div>
    <div class="step-labels" id="stepLabels">
      ${STAGES.map((label, i) => `<span id="label-${i}">${label}</span>`).join("")}
    </div>
    <div class="status-line" id="statusLine">Contacting detection engine…</div>
  `;
}

function setStatus(text) {
  const el = document.getElementById("statusLine");
  if (el) el.textContent = text;
}

function markStep(i, state) {
  const step = document.getElementById(`step-${i}`);
  const label = document.getElementById(`label-${i}`);
  if (!step || !label) return;
  step.className = `step ${state}`;
  if (state === "cleared") label.className = "done";
  else if (state === "active") label.className = "current";
  else if (state === "match-safe") label.className = "safe-label";
  else if (state === "match-danger") label.className = "danger-label";
}

//Visualizes the cascade execution across detection stages.
async function runStepperSweep(matchIndex, isPhishing) {
  for (let i = 0; i < matchIndex; i++) {
    setStatus(`Checking ${STAGES[i].toLowerCase()}…`);
    markStep(i, "active");
    await sleep(STEP_DELAY_MS);
    markStep(i, "cleared");
  }
  setStatus(`Checking ${STAGES[matchIndex].toLowerCase()}…`);
  markStep(matchIndex, "active");
  await sleep(STEP_DELAY_MS);
  markStep(matchIndex, isPhishing ? "match-danger" : "match-safe");
}