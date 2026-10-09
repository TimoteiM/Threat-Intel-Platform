# Bounded case graphs ranked on the wrong field

**Found** 2026-10-09, during the risk-score review.
**Affected** 11 cases — every case holding more than 300 alerts, from the
Phase 2 graph rewire until this fix.
**Impact** Those graphs were drawn from a 93% different set of alerts than a
severity ranking selects.

## What happened

Phase 2 bounded a case graph's read to the "300 most severe" alerts, to keep
assembly inside 400 ms on host-wide buckets. It ranked on
`highest_risk_score`.

`highest_risk_score` is not a severity. It is the maximum, over an alert's
extracted indicators, of a seven-component weighted sum in
`app/services/risk_aggregator.py`. Five of those seven components —
`lexical_score`, `behavior_score`, `content_ml_score`, `attachment_score`,
`sandbox_score` — are URL, email, attachment or sandbox signals. A Sysmon
process-creation event has no URL, no attachment and no email body, so five
components are structurally zero and the score can reach 30 at most unless the
OpenCTI step-floor fires.

Measured by source:

| source | runs | zero | mean |
|---|---|---|---|
| `windows_eventchannel` | 9,062 | 77.7% | 8.8 |
| `fortigate-firewall-v5` | 2,533 | 0.0% | 62.0 |
| `appsec-agent` | 2,685 | 0.4% | 57.5 |
| `macOS_loginwindow` | 10 | 100.0% | 0.0 |

The score tracks whether an alert happens to carry an externally resolvable
indicator — a property of the source, not of the event. So firewall traffic
logs outranked endpoint intrusion chains.

## Measured effect

Overlap between the old selection and a source-severity ranking:

| case | alerts | overlap | score-0 alerts the old ranking chose | mean Wazuh level old → new |
|---|---|---|---|---|
| #61 | 2,818 | **19 of 300 (6.3%)** | 0 | 12.97 → 15.00 |
| #71 | 2,154 | **21 of 300 (7.0%)** | 55 | 12.54 → 15.00 |

Cases at or under 300 alerts were unaffected — the bound never engaged, so
#1440 and #1833 were always drawn in full.

The sharpest illustration is the acceptance case. #1440 has a median
`highest_risk_score` of **0** and a maximum of 90, against Wazuh levels of 6
to 13 (median 12). Six of its eight alerts are unscored. Had it exceeded the
bound, the ranking would have put the alerts the case is about last.

## Fix

- `source_severity` on the run: the alert's own severity, normalised to 0-100
  from Wazuh `rule.level` (1-16), covering 94.2% of alerts. NULL where the
  source states none — never 0.
- The bound ranks on that, and reserves a proportional share of its slots for
  unrated alerts rather than sorting them last. An alert whose source states
  no severity is a gap in coverage, not a quiet alert.
- `alert_graph_entity.rule_level` renamed to `indicator_risk_score`, because
  it never held a rule level.
- `highest_risk_score = 0` converted to NULL, with the migration asserting
  that the smallest real score is 5 before converting.

## What the fix does not do

Within two sources the native severity is a per-decoder constant and cannot
order anything: Fortigate is level 1 on 2,527 of 2,533 alerts, `appsec-agent`
level 2 on all 2,685. The normalisation ranks Windows telemetry against
firewall traffic correctly and gives no ordering inside those two sources.
Inventing one would mean inventing severity.

Severity bands for the risk arc are still open. The distribution of
`highest_risk_score` is about twenty reachable values with four of them
carrying a third of everything scored, so a band edge near 59 would move
1,244 alerts on a one-point change. No bands have been set on it.
