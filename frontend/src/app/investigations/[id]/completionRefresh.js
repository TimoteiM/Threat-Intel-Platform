function shouldTriggerDomainCompletionRefresh({
  observableType,
  reportReady,
  liveState,
  ssePercent,
  sseDone,
  refreshInFlight,
}) {
  if (observableType !== "domain") return false;
  if (reportReady || refreshInFlight) return false;

  const normalizedState = String(liveState || "").toLowerCase();
  return Boolean(
    sseDone ||
      normalizedState === "concluded" ||
      Number(ssePercent || 0) >= 100
  );
}

module.exports = {
  shouldTriggerDomainCompletionRefresh,
};
