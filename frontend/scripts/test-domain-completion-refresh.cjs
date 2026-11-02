const assert = require("node:assert/strict");
const {
  shouldTriggerDomainCompletionRefresh,
} = require("../src/app/investigations/[id]/completionRefresh.js");

assert.equal(
  shouldTriggerDomainCompletionRefresh({
    observableType: "domain",
    reportReady: false,
    liveState: "concluded",
    ssePercent: 100,
    sseDone: true,
    refreshInFlight: false,
  }),
  true,
  "domain investigations should trigger a follow-up refresh when completion is reached without a loaded report",
);

assert.equal(
  shouldTriggerDomainCompletionRefresh({
    observableType: "hash",
    reportReady: false,
    liveState: "concluded",
    ssePercent: 100,
    sseDone: true,
    refreshInFlight: false,
  }),
  false,
  "non-domain investigations should not trigger the domain-only completion refresh",
);

assert.equal(
  shouldTriggerDomainCompletionRefresh({
    observableType: "domain",
    reportReady: true,
    liveState: "concluded",
    ssePercent: 100,
    sseDone: true,
    refreshInFlight: false,
  }),
  false,
  "refresh should stop once the report is already loaded",
);

assert.equal(
  shouldTriggerDomainCompletionRefresh({
    observableType: "domain",
    reportReady: false,
    liveState: "evaluating",
    ssePercent: 75,
    sseDone: false,
    refreshInFlight: false,
  }),
  false,
  "refresh should not start before completion",
);

console.log("domain completion refresh logic OK");
