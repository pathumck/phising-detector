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

//Displays an auto-dismissing corner notification for safe verdicts.
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

//Removes the overlay and restores page scrolling.
function removeOverlay() {
  const existing = document.getElementById(OVERLAY_ID);
  if (existing) {
    existing.remove();
  }
  document.documentElement.style.overflow = "";
}

//Builds and injects the block overlay.
function showBlockOverlay(verdict) {
  if (document.getElementById(OVERLAY_ID)) {
    return;
  }

  document.documentElement.style.overflow = "hidden";

  const overlay = document.createElement("div");
  overlay.id = OVERLAY_ID;
  overlay.setAttribute(
    "style",
    [
      "position: fixed",
      "top: 0",
      "left: 0",
      "width: 100vw",
      "height: 100vh",
      "z-index: 2147483647",
      "background-color: #0F172A",
      "display: flex",
      "align-items: center",
      "justify-content: center",
      "font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Arial, sans-serif",
      "color: #F1F5F9",
    ].join("; ")
  );

  const card = document.createElement("div");
  card.setAttribute(
    "style",
    [
      "background-color: #1E293B",
      "border: 2px solid #EF4444",
      "border-radius: 12px",
      "max-width: 480px",
      "width: 90%",
      "padding: 32px",
      "box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5)",
      "box-sizing: border-box",
    ].join("; ")
  );

  const heading = document.createElement("div");
  heading.setAttribute(
    "style",
    "font-size: 22px; font-weight: 700; color: #EF4444; margin-bottom: 8px;"
  );
  heading.textContent = "Dangerous Website Blocked";

  const domainLine = document.createElement("div");
  domainLine.setAttribute(
    "style",
    "font-size: 14px; color: #94A3B8; margin-bottom: 20px; word-break: break-all;"
  );
  domainLine.textContent = verdict.domain || "";

  const detailsBox = document.createElement("div");
  detailsBox.setAttribute(
    "style",
    "background-color: #0F172A; border-radius: 8px; padding: 16px; margin-bottom: 20px; font-size: 14px; line-height: 1.6;"
  );

  const layerRow = document.createElement("div");
  layerRow.innerHTML = `<strong style="color:#F1F5F9;">Detection method:</strong> <span style="color:#CBD5E1;">${humanLayerName(
    verdict.detection_layer
  )}</span>`;

  const confidenceRow = document.createElement("div");
  confidenceRow.setAttribute("style", "margin-top: 6px;");
  confidenceRow.innerHTML = `<strong style="color:#F1F5F9;">Confidence:</strong> <span style="color:#CBD5E1;">${formatConfidence(
    verdict.confidence
  )}</span>`;

  const explanationRow = document.createElement("div");
  explanationRow.setAttribute("style", "margin-top: 6px;");
  explanationRow.innerHTML = `<strong style="color:#F1F5F9;">Why:</strong> <span style="color:#CBD5E1;">${
    verdict.explanation || "No further details available."
  }</span>`;

  detailsBox.appendChild(layerRow);
  detailsBox.appendChild(confidenceRow);
  detailsBox.appendChild(explanationRow);

  const goBackBtn = document.createElement("button");
  goBackBtn.textContent = "Go Back to Safety";
  goBackBtn.setAttribute(
    "style",
    [
      "width: 100%",
      "background-color: #EF4444",
      "color: #FFFFFF",
      "border: none",
      "border-radius: 8px",
      "padding: 12px 16px",
      "font-size: 15px",
      "font-weight: 600",
      "cursor: pointer",
      "margin-bottom: 10px",
    ].join("; ")
  );
  goBackBtn.addEventListener("click", () => {
    if (window.history.length > 1) {
      window.history.back();
    } else {
      window.location.href = "https://www.google.com";
    }
  });

  const continueBtn = document.createElement("button");
  continueBtn.textContent = "I understand the risk, continue anyway";
  continueBtn.setAttribute(
    "style",
    [
      "width: 100%",
      "background-color: transparent",
      "color: #94A3B8",
      "border: 1px solid #475569",
      "border-radius: 8px",
      "padding: 12px 16px",
      "font-size: 13px",
      "cursor: pointer",
    ].join("; ")
  );
  continueBtn.addEventListener("click", () => {
    const confirmed = window.confirm(
      "This site was flagged as dangerous. Continuing may expose you to " +
        "credential theft or malware. Are you sure you want to proceed?"
    );
    if (confirmed) {
      removeOverlay();
    }
  });

  card.appendChild(heading);
  card.appendChild(domainLine);
  card.appendChild(detailsBox);
  card.appendChild(goBackBtn);
  card.appendChild(continueBtn);
  overlay.appendChild(card);

  document.documentElement.appendChild(overlay);
}

chrome.runtime.onMessage.addListener((message) => {
  if (message && message.type === "PHISHING_VERDICT") {
    const verdict = message.verdict;
    if (verdict && verdict.is_phishing) {
      showBlockOverlay(verdict);
    } else if (verdict) {
      showSafeToast(verdict);
    }
  }
});

chrome.runtime
  .sendMessage({ type: "GET_CURRENT_VERDICT" })
  .then((entry) => {
    if (!entry || entry.flaskOffline || !entry.verdict) {
      return;
    }
    if (entry.verdict.is_phishing) {
      showBlockOverlay(entry.verdict);
    } else {
      showSafeToast(entry.verdict);
    }
  })
  .catch(() => {});