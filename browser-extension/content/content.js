/**
 * Content script — extracts current page domain for the popup.
 * Minimal footprint: no DOM manipulation, just message handling.
 */

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "getPageDomain") {
    sendResponse({ domain: window.location.hostname });
  }
});
