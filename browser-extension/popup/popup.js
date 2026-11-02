/**
 * Popup script — handles domain display, investigation trigger,
 * result display, recent list, and settings.
 */

document.addEventListener("DOMContentLoaded", async () => {
  const domainDisplay = document.getElementById("domainDisplay");
  const domainInput = document.getElementById("domainInput");
  const clientDomainInput = document.getElementById("clientDomainInput");
  const investigateBtn = document.getElementById("investigateBtn");
  const statusArea = document.getElementById("statusArea");
  const statusText = document.getElementById("statusText");
  const statusBarFill = document.getElementById("statusBarFill");
  const resultArea = document.getElementById("resultArea");
  const resultClassification = document.getElementById("resultClassification");
  const resultScore = document.getElementById("resultScore");
  const resultAction = document.getElementById("resultAction");
  const resultLink = document.getElementById("resultLink");
  const recentList = document.getElementById("recentList");
  const settingsBtn = document.getElementById("settingsBtn");
  const backBtn = document.getElementById("backBtn");
  const mainView = document.getElementById("mainView");
  const settingsView = document.getElementById("settingsView");
  const backendUrlInput = document.getElementById("backendUrlInput");
  const saveSettingsBtn = document.getElementById("saveSettingsBtn");
  const settingsStatus = document.getElementById("settingsStatus");

  // ── Detect current domain ──
  chrome.runtime.sendMessage({ type: "getDomain" }, (response) => {
    if (response?.domain) {
      domainDisplay.textContent = response.domain;
      domainInput.value = response.domain;
    } else {
      domainDisplay.textContent = "No domain detected";
    }
  });

  // ── Investigate button ──
  investigateBtn.addEventListener("click", async () => {
    const domain = domainInput.value.trim();
    if (!domain) return;

    const clientDomain = clientDomainInput.value.trim() || null;

    investigateBtn.disabled = true;
    investigateBtn.textContent = "Investigating...";
    statusArea.classList.remove("hidden");
    resultArea.classList.add("hidden");
    statusText.textContent = "Starting investigation...";
    statusBarFill.style.width = "10%";

    chrome.runtime.sendMessage(
      { type: "investigate", domain, clientDomain },
      (response) => {
        investigateBtn.disabled = false;
        investigateBtn.textContent = "Investigate";

        if (response?.success) {
          showResult(response.data);
          loadRecent();
        } else {
          statusText.textContent = `Error: ${response?.error || "Unknown error"}`;
          statusBarFill.style.width = "100%";
          statusBarFill.style.background = "#F87171";
        }
      }
    );

    // Poll for progress updates while waiting
    let progress = 10;
    const progressInterval = setInterval(() => {
      if (progress < 90) {
        progress += 5;
        statusBarFill.style.width = `${progress}%`;

        if (progress < 40) {
          statusText.textContent = "Collecting evidence...";
        } else if (progress < 70) {
          statusText.textContent = "Running post-processing...";
        } else {
          statusText.textContent = "AI analyst evaluating...";
        }
      }
    }, 2000);

    // Clear interval when done (give time for response)
    setTimeout(() => clearInterval(progressInterval), 180000);
  });

  // ── Show result ──
  function showResult(data) {
    statusArea.classList.add("hidden");
    resultArea.classList.remove("hidden");

    const classification = data.classification || "inconclusive";
    resultClassification.textContent = classification;
    resultClassification.className = `result-classification ${classification}`;

    resultScore.textContent = data.risk_score != null
      ? `Risk Score: ${data.risk_score}/100`
      : "Risk Score: N/A";

    resultAction.textContent = data.recommended_action
      ? `Action: ${data.recommended_action}`
      : "";

    // Build report URL
    const backendUrl = backendUrlInput.value || "http://localhost:3000";
    const frontendUrl = backendUrl.replace(":8000", ":3000");
    resultLink.href = `${frontendUrl}/investigations/${data.id || data.investigation_id}`;
  }

  // ── Recent investigations ──
  async function loadRecent() {
    const result = await chrome.storage.local.get("recentInvestigations");
    const recent = result.recentInvestigations || [];

    recentList.innerHTML = "";

    if (recent.length === 0) {
      recentList.innerHTML = '<div style="font-size: 11px; color: #64748B; padding: 8px 0;">No recent investigations</div>';
      return;
    }

    for (const item of recent) {
      const el = document.createElement("div");
      el.className = "recent-item";
      el.innerHTML = `
        <span class="recent-domain">${escapeHtml(item.domain)}</span>
        <span class="recent-badge ${item.classification || item.state}">
          ${item.classification
            ? `${item.classification}${item.risk_score != null ? ` ${item.risk_score}` : ""}`
            : item.state}
        </span>
      `;
      el.addEventListener("click", () => {
        domainInput.value = item.domain;
        if (item.id && (item.state === "concluded" || item.state === "failed")) {
          const frontendUrl = (backendUrlInput.value || "http://localhost:3000").replace(":8000", ":3000");
          window.open(`${frontendUrl}/investigations/${item.id}`, "_blank");
        }
      });
      recentList.appendChild(el);
    }
  }

  loadRecent();

  // ── Settings ──
  settingsBtn.addEventListener("click", () => {
    mainView.classList.add("hidden");
    settingsView.classList.remove("hidden");
  });

  backBtn.addEventListener("click", () => {
    settingsView.classList.add("hidden");
    mainView.classList.remove("hidden");
  });

  // Load saved backend URL
  const stored = await chrome.storage.local.get("backendUrl");
  backendUrlInput.value = stored.backendUrl || "http://localhost:8000";

  saveSettingsBtn.addEventListener("click", async () => {
    const url = backendUrlInput.value.trim();
    await chrome.storage.local.set({ backendUrl: url });
    settingsStatus.textContent = "Saved!";
    setTimeout(() => {
      settingsStatus.textContent = "";
    }, 2000);
  });
});

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}
