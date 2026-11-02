/**
 * Shared API client for the Threat Investigation Platform.
 * Configurable backend URL stored in chrome.storage.local.
 */

const DEFAULT_BACKEND = "http://localhost:8000";

async function getBackendUrl() {
  try {
    const result = await chrome.storage.local.get("backendUrl");
    return result.backendUrl || DEFAULT_BACKEND;
  } catch {
    return DEFAULT_BACKEND;
  }
}

async function apiRequest(path, options = {}) {
  const base = await getBackendUrl();
  const url = `${base}${path}`;

  const response = await fetch(url, {
    headers: {
      "Content-Type": "application/json",
      ...options.headers,
    },
    ...options,
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`API ${response.status}: ${text}`);
  }

  return response.json();
}

/**
 * Start a new investigation.
 * @param {string} domain
 * @param {string|null} clientDomain
 * @returns {Promise<{investigation_id: string, domain: string, state: string}>}
 */
async function startInvestigation(domain, clientDomain = null) {
  const body = { domain };
  if (clientDomain) {
    body.client_domain = clientDomain;
  }
  return apiRequest("/api/investigations", {
    method: "POST",
    body: JSON.stringify(body),
  });
}

/**
 * Get investigation status.
 * @param {string} id
 * @returns {Promise<Object>}
 */
async function getInvestigation(id) {
  return apiRequest(`/api/investigations/${id}`);
}

/**
 * Poll investigation until concluded or failed.
 * @param {string} id
 * @param {function} onUpdate - callback with investigation data
 * @param {number} intervalMs - polling interval
 * @returns {Promise<Object>} - final investigation data
 */
async function pollInvestigation(id, onUpdate = null, intervalMs = 3000) {
  const maxAttempts = 120; // 6 minutes max
  let attempts = 0;

  while (attempts < maxAttempts) {
    const data = await getInvestigation(id);
    if (onUpdate) onUpdate(data);

    if (data.state === "concluded" || data.state === "failed") {
      return data;
    }

    await new Promise((resolve) => setTimeout(resolve, intervalMs));
    attempts++;
  }

  throw new Error("Investigation timed out");
}

// Export for use in other scripts
if (typeof globalThis !== "undefined") {
  globalThis.ThreatAPI = {
    getBackendUrl,
    startInvestigation,
    getInvestigation,
    pollInvestigation,
  };
}
