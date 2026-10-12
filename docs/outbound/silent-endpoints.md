# Endpoints that have stopped reporting

**To:** the Wazuh / endpoint-agent owners
**From:** Threat Intel Platform, measured 2026-10-12
**Ask:** tell us which of Tier A are decommissioned and which are broken. We
cannot tell those apart from here, and the difference decides whether this is
an estate-coverage problem or a tidy-up.

## What was measured

Every host that has ever produced an alert, by when it last produced one.
Source table: `alert_body_investigation_runs.entity_host`, which is the only
record of what actually arrived. Hosts classified `test` are excluded. "Days
silent" is calendar days to 2026-10-12.

113 hosts have sent nothing for 14 days or more. That number on its own
overstates the problem: 61 of them produced one or two alerts in their whole
history, which is not an endpoint that stopped so much as one that was barely
there. The tiers below separate those cases.

A silent host is not self-evidently a fault. An agent that was uninstalled
with the machine is correct to be quiet, and no statistic here can tell that
from an agent that died. That judgement is yours, which is why this is a
question rather than a ticket.

## Tier A — had real volume, now silent (17 hosts)

These are the ones worth your time. Each produced ten or more alerts, so the
agent demonstrably worked, and each has now been quiet for at least a
fortnight.

| host | alerts ever | last heard | days silent |
|---|---:|---|---:|
| exprevpxy002 | 2687 | 2026-09-22 | 20 |
| exp-4xhn063 | 34 | 2026-09-25 | 17 |
| expvpnext001 | 21 | 2026-09-06 | 36 |
| exp-gh4w793 | 20 | 2026-09-03 | 39 |
| daniels-macbook-air | 20 | 2026-09-17 | 25 |
| exp-b14zxl3 | 18 | 2026-09-25 | 17 |
| exp-g9hwtg3 | 16 | 2026-09-22 | 20 |
| expsql402 | 15 | 2026-09-24 | 18 |
| expscom002 | 13 | 2026-09-24 | 18 |
| exp-8zly264 | 12 | 2026-09-22 | 20 |
| exp-fl9p954 | 12 | 2026-09-23 | 19 |
| exp-jfw2p34 | 11 | 2026-09-21 | 21 |
| exp-f07dy24 | 10 | 2026-09-17 | 25 |
| exp-8fw2p34 | 10 | 2026-09-18 | 24 |
| exp-6fskjr3 | 10 | 2026-09-21 | 21 |
| exp-97vd864 | 10 | 2026-09-22 | 20 |
| exp-2r52x33 | 10 | 2026-09-22 | 20 |

`exprevpxy002` is the one to look at first: 2,687 alerts in its lifetime and
nothing for 20 days. Whatever it is, it was one of the loudest emitters in the
estate and it stopped.

## Tier B — modest volume, now silent (22 hosts)

Three to nine alerts ever. Worth a glance after Tier A.

| host | alerts ever | last heard | days silent |
|---|---:|---|---:|
| exp-f2hfxl3 | 9 | 2026-09-17 | 25 |
| exp-6chwtg3 | 9 | 2026-09-18 | 24 |
| exp-fin-034 | 8 | 2026-09-03 | 39 |
| exp-7q6f163 | 7 | 2026-09-10 | 32 |
| exp-4lj1p54 | 7 | 2026-09-22 | 20 |
| exp-gchwtg3 | 7 | 2026-09-22 | 20 |
| exp-3lj1p54 | 7 | 2026-09-23 | 19 |
| exp-7m9p954 | 6 | 2026-09-20 | 22 |
| exp-2lwk334 | 6 | 2026-09-21 | 21 |
| siembiot-package-teste-1 | 6 | 2026-09-24 | 18 |
| exp-47vd864 | 6 | 2026-09-25 | 17 |
| exp-9brrpb4 | 5 | 2026-09-09 | 33 |
| exp-hkj1p54 | 5 | 2026-09-22 | 20 |
| mvoraclp01 | 4 | 2026-08-24 | 49 |
| beta-uma | 4 | 2026-09-09 | 33 |
| exp-d20gnx3 | 4 | 2026-09-19 | 23 |
| cpc-alexa-gtfxm | 4 | 2026-09-21 | 21 |
| exp-4chwtg3 | 4 | 2026-09-21 | 21 |
| exp-2j7yz93 | 4 | 2026-09-22 | 20 |
| exp-gzly264 | 4 | 2026-09-23 | 19 |
| expsql401 | 3 | 2026-09-17 | 25 |
| exp-ffbd8s3 | 3 | 2026-09-24 | 18 |

## Tier C — one or two alerts ever (61 hosts)

Listed for completeness. We would not read these as regressions; they look
more like hosts that were never really onboarded, or that produced a single
alert during a one-off event. No action expected unless a name surprises you.

| host | alerts ever | last heard | days silent |
|---|---:|---|---:|
| exp-dfw2p34 | 2 | 2026-08-10 | 63 |
| azizsoez | 2 | 2026-08-24 | 49 |
| zvoracla01 | 2 | 2026-08-24 | 49 |
| elzrkwam | 2 | 2026-08-24 | 49 |
| po00296 | 2 | 2026-08-24 | 49 |
| mvoraclt01 | 2 | 2026-08-24 | 49 |
| dwchtjan | 2 | 2026-08-24 | 49 |
| mvapsupm01 | 2 | 2026-08-24 | 49 |
| exp-jkj1p54 | 2 | 2026-09-04 | 38 |
| exp-hl9p954 | 2 | 2026-09-04 | 38 |
| expvdi022 | 2 | 2026-09-08 | 34 |
| exp-4jhpzy2 | 2 | 2026-09-10 | 32 |
| expgw401 | 2 | 2026-09-17 | 25 |
| exp-6g6xgl3 | 2 | 2026-09-19 | 23 |
| exp-bgbd8s3 | 2 | 2026-09-21 | 21 |
| exp-7lwk334 | 2 | 2026-09-21 | 21 |
| exp-flj1p54 | 2 | 2026-09-22 | 20 |
| exp-77vd864 | 2 | 2026-09-23 | 19 |
| crvladu | 1 | 2026-08-07 | 66 |
| alfresco | 1 | 2026-08-07 | 66 |
| annaleahu | 1 | 2026-08-07 | 66 |
| expdcext002 | 1 | 2026-08-10 | 63 |
| exp-c7vd864 | 1 | 2026-08-10 | 63 |
| exp-4bjx5y2 | 1 | 2026-08-10 | 63 |
| exprdgw001 | 1 | 2026-08-11 | 62 |
| expreu001 | 1 | 2026-08-14 | 59 |
| 5cg3082d03 | 1 | 2026-08-25 | 48 |
| mvctxshp36 | 1 | 2026-08-27 | 46 |
| mvidwkfm02 | 1 | 2026-09-01 | 41 |
| po00502 | 1 | 2026-09-03 | 39 |
| mvctxshp49 | 1 | 2026-09-04 | 38 |
| exp-6xkzz93 | 1 | 2026-09-04 | 38 |
| onvinttlnt01 | 1 | 2026-09-04 | 38 |
| mvctxshp45 | 1 | 2026-09-07 | 35 |
| expsharegate403 | 1 | 2026-09-08 | 34 |
| zvigumsp01 | 1 | 2026-09-08 | 34 |
| exp-3xyzck3 | 1 | 2026-09-10 | 32 |
| mvctxshp56 | 1 | 2026-09-10 | 32 |
| mvctxshp19 | 1 | 2026-09-13 | 29 |
| expm365analytics401 | 1 | 2026-09-15 | 27 |
| expaudi003 | 1 | 2026-09-16 | 26 |
| mvsubcap01 | 1 | 2026-09-16 | 26 |
| xvaadcnp01 | 1 | 2026-09-16 | 26 |
| expaudi006 | 1 | 2026-09-17 | 25 |
| exp-hchwtg3 | 1 | 2026-09-18 | 24 |
| expvdi004 | 1 | 2026-09-18 | 24 |
| expvdi003 | 1 | 2026-09-20 | 22 |
| expvdi012 | 1 | 2026-09-20 | 22 |
| exp-3rx5x33 | 1 | 2026-09-20 | 22 |
| expsql404 | 1 | 2026-09-21 | 21 |
| exp-2k7yz93 | 1 | 2026-09-21 | 21 |
| expvdi017 | 1 | 2026-09-21 | 21 |
| exp-130gnx3 | 1 | 2026-09-21 | 21 |
| expweb003 | 1 | 2026-09-22 | 20 |
| exp-jz6dy24 | 1 | 2026-09-23 | 19 |
| pftest-win11 | 1 | 2026-09-24 | 18 |
| expveeam001 | 1 | 2026-09-24 | 18 |
| expreu002 | 1 | 2026-09-24 | 18 |
| mvctxshp66 | 1 | 2026-09-25 | 17 |
| mvctxshp20 | 1 | 2026-09-28 | 14 |
| mvctxfap01 | 1 | 2026-09-28 | 14 |

## One thing that is ours, not yours

Thirteen "hosts" in this data are bare numbers — 3, 10, 18, 77, 79, 80, 94,
104, 109, 136, 145, 178, 188. Those are almost certainly our own field
extraction splitting something it should not have, not real machines. We are
not asking you about them and we are not counting them above; they are
mentioned so that nobody tries to find a server called 18.

## What we are doing about it at our end

A freshness alarm now measures each source and each host against its own
demonstrated volume rather than against a fixed threshold. It is running in
shadow — computing and logging, alarming on nothing — until it has a week of
its own output to set a threshold from, rather than one we picked. It also
only covers hosts with enough volume to be judged by rate: 181 of 192 hosts
are too sparse for that, and a last-seen instrument for those does not exist
yet. This list was produced by hand for that reason.
