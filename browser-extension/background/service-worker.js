/**
 * Background service worker — handles context menus, API calls,
 * badge updates, and notifications.
 */

importScripts("../lib/api.js");

// ── Context Menus ──
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: "investigate-page",
    title: "Investigate this domain",
    contexts: ["page"],
  });

  chrome.contextMenus.create({
    id: "investigate-link",
    title: "Investigate linked domain",
    contexts: ["link"],
  });
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
  let url;
  if (info.menuItemId === "investigate-page") {
    url = tab?.url;
  } else if (info.menuItemId === "investigate-link") {
    url = info.linkUrl;
  }

  if (url) {
    const domain = extractDomain(url);
    if (domain) {
      launchInvestigation(domain);
    }
  }
});

// ── Message handling from popup ──
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "investigate") {
    launchInvestigation(message.domain, message.clientDomain)
      .then((result) => sendResponse({ success: true, data: result }))
      .catch((err) => sendResponse({ success: false, error: err.message }));
    return true; // async response
  }

  if (message.type === "getStatus") {
    ThreatAPI.getInvestigation(message.id)
      .then((data) => sendResponse({ success: true, data }))
      .catch((err) => sendResponse({ success: false, error: err.message }));
    return true;
  }

  if (message.type === "getDomain") {
    // Get domain from active tab
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs[0]?.url) {
        sendResponse({ domain: extractDomain(tabs[0].url) });
      } else {
        sendResponse({ domain: null });
      }
    });
    return true;
  }
});

// ── Investigation launcher ──
async function launchInvestigation(domain, clientDomain = null) {
  try {
    // Set badge to "working"
    chrome.action.setBadgeText({ text: "..." });
    chrome.action.setBadgeBackgroundColor({ color: "#60A5FA" });

    // Start investigation
    const result = await ThreatAPI.startInvestigation(domain, clientDomain);
    const investigationId = result.investigation_id;

    // Save to recent investigations
    await saveToRecent(investigationId, domain);

    // Poll for completion
    const finalResult = await ThreatAPI.pollInvestigation(
      investigationId,
      (data) => {
        // Update badge during polling
        if (data.state === "gathering") {
          chrome.action.setBadgeText({ text: "..." });
          chrome.action.setBadgeBackgroundColor({ color: "#60A5FA" });
        } else if (data.state === "evaluating") {
          chrome.action.setBadgeText({ text: "AI" });
          chrome.action.setBadgeBackgroundColor({ color: "#A78BFA" });
        }
      },
      3000
    );

    // Update badge with result
    updateBadge(finalResult);

    // Update recent with final result
    await updateRecent(investigationId, finalResult);

    // Show notification
    showNotification(domain, finalResult);

    return finalResult;
  } catch (err) {
    chrome.action.setBadgeText({ text: "!" });
    chrome.action.setBadgeBackgroundColor({ color: "#F87171" });
    throw err;
  }
}

// ── Badge management ──
function updateBadge(investigation) {
  const score = investigation.risk_score;
  const classification = investigation.classification;

  if (score != null) {
    chrome.action.setBadgeText({ text: String(score) });
  } else {
    chrome.action.setBadgeText({ text: classification?.[0]?.toUpperCase() || "?" });
  }

  const colorMap = {
    malicious: "#F87171",
    suspicious: "#FBBF24",
    benign: "#34D399",
    inconclusive: "#94A3B8",
  };
  chrome.action.setBadgeBackgroundColor({
    color: colorMap[classification] || "#94A3B8",
  });
}

// ── Recent investigations storage ──
async function saveToRecent(id, domain) {
  const result = await chrome.storage.local.get("recentInvestigations");
  const recent = result.recentInvestigations || [];

  recent.unshift({
    id,
    domain,
    state: "gathering",
    timestamp: new Date().toISOString(),
  });

  // Keep last 10
  if (recent.length > 10) recent.length = 10;

  await chrome.storage.local.set({ recentInvestigations: recent });
}

async function updateRecent(id, data) {
  const result = await chrome.storage.local.get("recentInvestigations");
  const recent = result.recentInvestigations || [];

  const index = recent.findIndex((r) => r.id === id);
  if (index !== -1) {
    recent[index] = {
      ...recent[index],
      state: data.state,
      classification: data.classification,
      risk_score: data.risk_score,
    };
    await chrome.storage.local.set({ recentInvestigations: recent });
  }
}

// ── Notifications ──
function showNotification(domain, investigation) {
  const classification = investigation.classification || "unknown";
  const score = investigation.risk_score;

  chrome.notifications.create({
    type: "basic",
    iconUrl: "../icons/icon128.png",
    title: `Investigation Complete: ${domain}`,
    message: `Classification: ${classification.toUpperCase()}${score != null ? ` | Risk: ${score}/100` : ""}`,
    priority: classification === "malicious" ? 2 : 1,
  });
}

// ── Helpers ──
function extractDomain(url) {
  try {
    const parsed = new URL(url);
    return parsed.hostname;
  } catch {
    return null;
  }
}
