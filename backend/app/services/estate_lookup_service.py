"""Did anything in this customer's estate touch this indicator?

This is the query that turns an intel hit into an incident. An analyst reads
`malicious` on a domain and the next question is always the same: *did it
reach us?* Until now that question had no answer in this platform, so the
reputation verdict stood alone.

Why every absence here is named rather than returned as zero
------------------------------------------------------------
A reader who sees "no host resolved this domain" **de-escalates**. That makes
a false negative here worse than a false positive, and worse than a missing
panel: it closes a ticket. So each way this lookup can fail to answer gets its
own named absence and never a count of 0 —

  * a **URL**, because this estate has no proxy logs at all
  * a window beyond **120-day retention**, which is *unknown*, not no contact
  * the cluster unreachable, or the tenant having no pinned integration
  * a first-seen that is really **when collection began**, not when the estate
    first resolved the name — retention is not the binding limit here and was
    107 days too generous; see `observation_floor`
  * a reference time whose **anchor is not named**, because the two anchors
    nearest to hand are the sender's `Date` header and the analyst's upload
    time, and both are wrong; see `email_anchor`

That is the same rule the ThreatFox and intel-collector failures came down to,
applied before the fact instead of after: `not hits` is true both when nothing
was seen and when nothing was asked.

The two questions this estate can answer, and why they never merge
------------------------------------------------------------------
Measured over the last 7 days, 164.6M documents, 180 agents:

    data.win.eventdata.queryName   2,599,670 docs   175 hosts  (97.2%)
    data.dstip                   126,708,398 docs     1 host

`queryName` is Sysmon event 22 — a host asking DNS for a name. `dstip` is
**one network appliance**, and it is the largest field in the store by two
orders of magnitude. "Did any endpoint resolve this name" and "did the
perimeter carry traffic to this address" are different facts, and the document
count is exactly the gravity well that makes them look like one answer.

**A perimeter hit with no corresponding host query is the more suspicious
shape**, not the same shape — traffic to an address no endpoint resolved. A
union would report one `yes` meaning neither, so this module returns both
separately and has no combined field at all. A test asserts that no key named
`seen`, `any`, `observed_anywhere` or `estate_hit` ever appears in the
payload.

What a negative answer is worth
-------------------------------
"No host resolved it" is a claim about **175 of 180 hosts**, not the estate, so
the DNS answer carries its own coverage. 97.2% is a strong negative and not a
complete one, and the five hosts without Sysmon DNS logging are exactly where
an operator would want to look next.

Cost, measured: 209 ms for a domain with 44,669 documents across 5 hosts;
28 ms for one with none.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timedelta, timezone
from typing import Any

from app.services import absence

#: Sysmon event 22. A host asked DNS for a name — endpoint telemetry, on
#: 175 of 180 agents.
HOST_DNS_FIELD = "data.win.eventdata.queryName"

#: `queryName` is NOT only written by Sysmon's DNS query event. Measured over
#: the full retention on 2026-10-15: of 4,470,660 documents carrying the
#: field, 1,966 come from Windows event **1014** (rule 61109) — "DNS name
#: resolution timed out" — and those are the *only* ones before 2026-10-02.
#: A timeout is a lookup that failed, so counting it as a resolution inverts
#: the meaning of every answer here: a domain nothing could reach would read
#: as a domain a host contacted. Both questions this module asks are about
#: contact, so the event is pinned.
DNS_EVENT_FIELD = "data.win.system.eventID"
DNS_EVENT_QUERY = "22"

#: Applied per field, from module constants only. Nothing a caller supplies
#: reaches a query clause: an estate query whose filters could come from a
#: request is not pinned to a tenant or to a meaning.
_SEMANTIC_FILTERS: dict[str, list[dict[str, Any]]] = {
    HOST_DNS_FIELD: [{"term": {DNS_EVENT_FIELD: DNS_EVENT_QUERY}}],
    # HOST_HASH_FIELD is registered below, where its constants are defined.
}

#: One network appliance. Perimeter traffic to an address, NOT endpoint
#: telemetry, and never to be read as estate-wide.
PERIMETER_FIELD = "data.dstip"

#: Sysmon image hashes. Measured 2026-10-15: 2,626,536 documents across 190
#: hosts, spanning the full 120-day retention from 2026-06-17 — so unlike
#: `queryName` this field has no collection floor inside the window.
#:
#: The value is a COMPOSITE string, `MD5=…,SHA256=…,IMPHASH=…`, and there is
#: no parsed sibling (`.sha256`, `.md5`, `data.hash.sha256` are all empty), so
#: a bare digest matches only through a leading wildcard. That is why the
#: window is bounded — see HASH_WINDOW_DAYS.
HOST_HASH_FIELD = "data.win.eventdata.hashes"

#: Which Sysmon events carry it: 1 (Process Create) 2,614,044, 7 (Image
#: Loaded) 10,364, 29 (File Executable Detected) 2,128.
#:
#: **Pinned to 1 even though all three mean "hashes of an image".** Agreement
#: is not the reason to pin; the reason is that event 1 is the *execution*
#: claim and 7 and 29 are not. A question about what RAN must not silently
#: include what was loaded into another process, or what was merely seen on
#: disk — those are three different findings and the strongest of them would
#: inherit the others' volume.
HASH_EVENT_ID = "1"

#: Default and maximum windows for a hash question, from measured cost rather
#: than from caution. Timed on a quiet cluster, three runs each, median, all
#: complete (360/360 shards, 0 failed, no timeout):
#:
#:     24h       83 ms      455 hits
#:     7d       161 ms    3,024 hits
#:     30d      422 ms   13,442 hits
#:     120d   1,682 ms   27,363 hits   (first, cold run 4,335 ms)
#:
#: 7 days is the default because it matches the DNS lookup's window and costs
#: about what seven concurrent DNS indicators cost (168 ms). 30 days is the
#: measured ceiling. Beyond it the cost is *not established* rather than
#: known-bad, and the lookup says so instead of either refusing or guessing.
HASH_WINDOW_DAYS = 7
HASH_MAX_MEASURED_DAYS = 30

# Registered here rather than in the literal above, because the literal is
# defined before these constants are.
_SEMANTIC_FILTERS[HOST_HASH_FIELD] = [
    {"term": {DNS_EVENT_FIELD: HASH_EVENT_ID}}
]

#: Oldest document 2026-06-16, measured 2026-10-14. Beyond this the store has
#: nothing to say, which is not the same as having nothing to report.
RETENTION_DAYS = 120

#: 175 of 180 agents carry Sysmon DNS query logging.
HOSTS_WITH_DNS_LOGGING = 175
HOSTS_TOTAL = 180

DEFAULT_DAYS = 7

_DOMAIN = re.compile(r"^(?=.{4,253}$)([A-Za-z0-9_-]{1,63}\.)+[A-Za-z]{2,}$")


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False


def _coverage() -> dict[str, Any]:
    return {
        "hosts_with_dns_logging": HOSTS_WITH_DNS_LOGGING,
        "hosts_total": HOSTS_TOTAL,
        "fraction": round(HOSTS_WITH_DNS_LOGGING / HOSTS_TOTAL, 4),
        "note": (
            f"Sysmon DNS query logging is on {HOSTS_WITH_DNS_LOGGING} of "
            f"{HOSTS_TOTAL} agents. A negative answer covers those hosts, not "
            f"the whole estate; the {HOSTS_TOTAL - HOSTS_WITH_DNS_LOGGING} "
            f"without it are where to look next."
        ),
    }


_NO_PROXY_LOGS = (
    "This estate has no proxy logs: `data.proxy.url` and `data.http.url` are "
    "both empty across the full 120-day window, and `data.url` comes from a "
    "single appliance. The estate question cannot be asked at URL grain here, "
    "so this is an absence of capability and not an absence of contact. Ask "
    "the domain instead."
)


#: How a hit's first-seen relates to the moment the email arrived. This is
#: the discriminator an analyst acts on — honest wording stops the panel
#: over-claiming, but it does not sort 46 background hosts from 2 meaningful
#: ones. First-seen against receipt does: a domain first resolved *after* the
#: mail is a finding; one resolved for months is infrastructure.
PRE_EXISTING = "pre_existing"        # resolved before the email arrived
NEW_SINCE = "new_since"              # first resolved after it — the finding
#: first-seen is where *observation* starts, not where the domain's history
#: does. Named for the floor rather than for the retention window because the
#: window is usually not the binding limit — see `observation_floor`.
AT_OBSERVATION_FLOOR = "at_observation_floor"

#: How close to the floor counts AS the floor.
#:
#: Not fitted to the case that prompted it: `aka.ms` was first resolved 22
#: minutes after its 47 hosts began collecting (floor 2026-10-02 11:27:31,
#: first-seen 11:49:42, measured live on 2026-10-15), so even the 2 hours
#: this started with would have caught it *once the floor was the floor*. The
#: defect was never this threshold's size — it was comparing against the
#: retention window, 107 days earlier than the real limit.
#:
#: Sized by which way being wrong hurts instead. Too small and a domain at
#: the floor reads `pre_existing`, which asserts "ordinary infrastructure"
#: about a name we have barely been able to see — the inversion this whole
#: discriminator exists to avoid. Too large and a genuinely new domain reads
#: as a floor artefact: a weaker sentence, not a false one. A day of headroom
#: buys the safe error, and a value's absence during the first hours of a
#: host's collection is poor evidence it was absent before.
FLOOR_GRACE_SECONDS = 86_400


def _human_gap(seconds: float) -> str:
    seconds = abs(seconds)
    for unit, size in (("month", 2_592_000), ("week", 604_800),
                       ("day", 86_400), ("hour", 3_600), ("minute", 60)):
        if seconds >= size:
            n = int(seconds // size)
            return f"{n} {unit}{'s' if n != 1 else ''}"
    return f"{int(seconds)} seconds"


def relative_to(
    first_seen: Any,
    reference: Any,
    *,
    floor: Any,
    anchor_statement: str,
) -> dict[str, Any]:
    """Where a hit's first-seen sits against the email's arrival.

    **Neither limit may read as the answer.** `first_seen` is bounded below by
    two separate things, and the *later* of them binds:

    * retention — the store holds nothing older;
    * **when collection of this telemetry began**, per host.

    The second one is the dangerous one, and it is why this function no longer
    takes a window. On this estate, retention reaches back to 2026-06-17 but
    Sysmon DNS query collection began 2026-10-02: the floor is four months
    inside the window, so nothing was ever *at* the window's edge and the
    edge test could not fire. Every first-seen was biased recent by 107 days
    while reporting itself as a fact. A systematically recent first-seen does
    not merely weaken this discriminator, it inverts it — long-standing
    infrastructure reads as newly contacted, which is the finding.

    `floor` is therefore measured, not assumed, and measured on the same
    predicate the first-seen query uses: see `observation_floor`. `floor` of
    None is not a missing option — the caller must not call this without one,
    because a floorless classification is the bug above.

    `anchor_statement` names which timestamp `reference` is, in the analyst's
    sentence. It is required for the same reason: the first version of this
    took a bare datetime, and what got passed was the investigation's upload
    time, which is not when the mail arrived.
    """
    if first_seen is None or reference is None or floor is None:
        return {}
    since_floor = (first_seen - floor).total_seconds()
    at_floor = since_floor < FLOOR_GRACE_SECONDS
    observable = _human_gap((reference - floor).total_seconds())
    gap = (reference - first_seen).total_seconds()
    before = gap > 0
    if at_floor:
        classification = AT_OBSERVATION_FLOOR
        sentence = (
            f"Resolved at least since {first_seen:%Y-%m-%d}, which is when "
            f"this telemetry began on the hosts that saw it "
            f"({floor:%Y-%m-%d}) — so this is a lower bound and not a "
            f"first-seen. Whether it was resolved before then is not "
            f"recorded either way."
        )
    elif before:
        classification = PRE_EXISTING
        sentence = (
            f"First resolved {_human_gap(gap)} before this email, measured "
            f"against {anchor_statement} — {first_seen:%Y-%m-%d %H:%M} UTC, "
            f"and this telemetry only reaches back {observable} on these "
            f"hosts, so 'before' is bounded by that."
        )
    else:
        classification = NEW_SINCE
        sentence = (
            f"First resolved {_human_gap(gap)} AFTER this email arrived, "
            f"measured against {anchor_statement} — no host had resolved it "
            f"in the {observable} of history before "
            f"{first_seen:%Y-%m-%d %H:%M} UTC."
        )
    return {
        "classification": classification,
        "first_seen_before_reference": bool(before) and not at_floor,
        "first_seen_is_lower_bound": bool(at_floor),
        "reference_time": reference.isoformat(),
        "reference_anchor": anchor_statement,
        "observation_floor": floor.isoformat(),
        "observable_history_seconds": (reference - floor).total_seconds(),
        "sentence": sentence,
    }


def lookup(
    value: str,
    *,
    kind: str,
    tenant_id: str | None,
    days: int = DEFAULT_DAYS,
    client: Any = None,
    now: datetime | None = None,
    #: When the thing under investigation arrived — an email's arrival time.
    #: Supplied, the answer carries the first-seen comparison that an analyst
    #: acts on. Absent, no comparison is claimed.
    reference_time: datetime | None = None,
    #: What `reference_time` *is*, in the words the sentence will use — see
    #: `email_anchor.anchor_statement`. Required whenever a reference time is
    #: given, and not merely for the prose: the first version of this took a
    #: bare datetime, and the value that reached it was the investigation's
    #: upload time rather than the message's arrival. An unnamed anchor is how
    #: that happens quietly, so the pair is unsplittable here.
    reference_anchor: str | None = None,
) -> dict[str, Any]:
    """Both estate facts for one indicator, each with its own absence.

    `client` must already be pinned to this tenant's cluster. It is passed in
    rather than resolved here so a caller cannot accidentally reach another
    tenant's store, and `tenant_id` travels with every query as a second
    guard.
    """
    at = now or datetime.now(timezone.utc)
    observable = str(value or "").strip()
    tenant = str(tenant_id or "").strip()
    queried: list[str] = []

    window = {
        "days": int(days),
        "retention_days": RETENTION_DAYS,
        "within_retention": int(days) <= RETENTION_DAYS,
        "since": (at - timedelta(days=int(days))).isoformat(),
        "until": at.isoformat(),
    }

    def both(reason_absence: absence.Absent) -> dict[str, Any]:
        """One reason that defeats both questions at once."""
        return {
            "observable": observable,
            "kind": kind,
            "tenant_id": tenant or None,
            "window": window,
            "host_dns": reason_absence.as_json(),
            "perimeter": reason_absence.as_json(),
            "queried": queried,
        }

    # ---- the refusals, before any query --------------------------------
    if not tenant:
        return both(absence.absent(
            absence.CHECK_FAILED,
            "No customer was named, so no cluster could be chosen. This "
            "platform never runs an estate query without a pinned tenant: an "
            "unpinned query would answer about somebody else's estate.",
        ))

    if client is None:
        return both(absence.absent(
            absence.CHECK_FAILED,
            f"No log-store integration is configured for {tenant!r}, so the "
            f"estate was not searched. There is deliberately no fallback "
            f"cluster — answering from another customer's logs would be worse "
            f"than not answering.",
            raw=tenant,
        ))

    if int(days) > RETENTION_DAYS:
        return both(absence.absent(
            absence.TOO_LITTLE_HISTORY,
            f"The window asked for is {days} days and the log store's "
            f"retention is {RETENTION_DAYS} days. Outside it the store holds "
            f"nothing, which is unknown and not 'no contact'. Treating an "
            f"aged-out window as clean is how a feed outage reads as safety.",
            raw=str(days),
        ))

    if kind == "url":
        return both(absence.absent(absence.OUT_OF_SCOPE, _NO_PROXY_LOGS,
                                   raw=observable))

    # A reference time with no statement of what it is cannot be used. This is
    # a refusal rather than a default because every default available here is
    # one of the two wrong anchors.
    if reference_time is not None and not str(reference_anchor or "").strip():
        return both(absence.absent(
            absence.CHECK_FAILED,
            "A reference time was supplied without naming which timestamp it "
            "is. 'Before this email' is only meaningful against an anchor our "
            "own infrastructure wrote; an unnamed one is how the upload time "
            "came to be reported as the arrival time. No comparison is made.",
        ))

    # ---- which question can this observable even ask? ------------------
    ask_dns = kind == "domain" and bool(_DOMAIN.match(observable))
    ask_perimeter = kind == "ip" and _is_ip(observable)

    if not ask_dns and not ask_perimeter:
        return both(absence.absent(
            absence.NO_FIELD_MAP,
            f"No estate field answers for an observable of kind {kind!r}. "
            f"The store can be asked about a domain (host DNS queries) and an "
            f"address (perimeter traffic); nothing else is mapped, and a zero "
            f"from an unmapped field would read as 'never seen'.",
            raw=kind,
        ))

    def ask(field: str, basis: str) -> Any:
        queried.append(field)
        try:
            docs, hosts = client.count_and_hosts(
                field=field, value=observable,
                since=window["since"], until=window["until"],
                tenant_id=tenant,
            )
        except Exception as exc:
            return absence.absent(
                absence.CHECK_FAILED,
                f"The log store could not be queried, so whether this was "
                f"seen is unknown rather than no. ({type(exc).__name__})",
                raw=field,
            ).as_json()
        answer: dict[str, Any] = {
            "observed": bool(docs),
            "documents": int(docs),
            "hosts": list(hosts),
            "host_count": len(hosts),
            "field": field,
            "basis": basis,
            "window_days": int(days),
        }
        # Only a HIT pays for the first-seen query, and it runs over the full
        # retention rather than the 7-day window — a 7-day window cannot
        # answer "months", and its edge would read as a first-seen. A miss
        # gets no extra call: there is no first-seen to find.
        if docs and reference_time is not None:
            resolver = getattr(client, "first_last_seen", None)
            if resolver is not None:
                wide_since = at - timedelta(days=RETENTION_DAYS)
                try:
                    first_seen, last_seen = resolver(
                        field=field, value=observable,
                        since=wide_since.isoformat(), until=at.isoformat(),
                        tenant_id=tenant,
                    )
                except Exception as exc:
                    # No comparison is attached: a sentence about "months
                    # before this email" built on an unknown first-seen is
                    # worse than no sentence.
                    answer["first_seen"] = absence.absent(
                        absence.CHECK_FAILED,
                        f"The first-seen query did not complete, so how long "
                        f"this has been resolved is unknown rather than "
                        f"recent. ({type(exc).__name__}: {str(exc)[:120]})",
                    ).as_json()
                    answer["relative_to_reference"] = None
                else:
                    answer["first_seen"] = (
                        None if first_seen is None else first_seen.isoformat()
                    )
                    answer["last_seen"] = (
                        None if last_seen is None else last_seen.isoformat()
                    )
                    answer["relative_to_reference"] = _classify(
                        answer, field=field, first_seen=first_seen,
                        hosts=hosts, wide_since=wide_since, tenant=tenant,
                    )
        return answer

    def _classify(
        answer: dict[str, Any], *, field: str, first_seen: Any,
        hosts: Any, wide_since: datetime, tenant: str,
    ) -> Any:
        """The before/after sentence, or a named absence instead of one.

        The floor is resolved from the hosts that actually hold the hit, and
        every way of not getting one ends here as `check_failed`. None of them
        falls through to a comparison: the whole point of the floor is that a
        classification made without it is confidently wrong rather than
        missing.
        """
        resolver = getattr(client, "observation_floor", None)
        if resolver is None:
            return absence.absent(
                absence.CHECK_FAILED,
                "This log-store client cannot report when collection began, "
                "so how far back 'first resolved' can see is unknown. An "
                "unbounded reading of a bounded first-seen turns ordinary "
                "infrastructure into a new contact.",
                raw=field,
            ).as_json()
        try:
            floors = resolver(field=field, since=wide_since.isoformat(),
                              until=at.isoformat(), tenant_id=tenant)
        except Exception as exc:
            return absence.absent(
                absence.CHECK_FAILED,
                f"The collection-floor query did not complete, so a "
                f"first-seen cannot be told apart from the start of "
                f"collection. ({type(exc).__name__}: {str(exc)[:120]})",
                raw=field,
            ).as_json()

        # Indexed, not `.get()`. A host missing from the floor map is a host
        # whose collection start is unknown — if that read as "no floor" the
        # comparison would silently use somebody else's.
        missing = [h for h in (hosts or []) if h not in floors]
        if missing or not hosts:
            return absence.absent(
                absence.CHECK_FAILED,
                f"{len(missing) or 'All'} of the {len(hosts or [])} hosts "
                f"holding this value report no collection start for "
                f"{field}, so how far back their history reaches is unknown.",
                raw=",".join(sorted(missing)[:5]) or None,
            ).as_json()

        # The earliest floor among the hosts that saw it. Earliest, because a
        # host collecting since the start and still not seeing the value until
        # later is evidence the value is new; the latest floor would throw
        # that evidence away and call everything a floor artefact.
        floor = min(floors[h] for h in hosts)
        answer["observation_floor"] = floor.isoformat()
        answer["observation_floor_basis"] = (
            f"earliest start of {field} collection among the "
            f"{len(hosts)} host(s) that hold this value"
        )
        return relative_to(
            first_seen, reference_time, floor=floor,
            anchor_statement=str(reference_anchor).strip(),
        ) or None

    host_dns: Any = absence.absent(
        absence.OUT_OF_SCOPE,
        "Host DNS telemetry answers for domains. An address is not a name a "
        "host resolves, so this question was not asked of it.",
        raw=observable,
    ).as_json()
    perimeter: Any = absence.absent(
        absence.OUT_OF_SCOPE,
        "Perimeter records answer for addresses. A domain is not an address "
        "the appliance logs, so this question was not asked of it.",
        raw=observable,
    ).as_json()

    if ask_dns:
        host_dns = ask(
            HOST_DNS_FIELD,
            "Sysmon event 22 — an endpoint asked DNS for this name. Endpoint "
            "telemetry across the hosts that report it.",
        )
        if not absence.is_absent(host_dns):
            host_dns["coverage"] = _coverage()

    if ask_perimeter:
        perimeter = ask(
            PERIMETER_FIELD,
            "Perimeter appliance records — traffic to this address as one "
            "network device saw it. NOT endpoint telemetry and not "
            "estate-wide: this field comes from a single agent.",
        )

    return {
        "observable": observable,
        "kind": kind,
        "tenant_id": tenant,
        "window": window,
        # Separate, always. There is deliberately no combined verdict: see the
        # module docstring on why a union would mean neither fact.
        "host_dns": host_dns,
        "perimeter": perimeter,
        "queried": queried,
    }


def hash_lookup(
    digest: str,
    *,
    tenant_id: str | None,
    days: int = HASH_WINDOW_DAYS,
    client: Any = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Did any host in this estate execute an image with this hash.

    Bounded, and the bound is on the card. The window is part of the answer
    because the field needs a leading wildcard, so an unbounded version of
    this question is a different and much more expensive question — and a
    7-day nil is not a 120-day nil.
    """
    at = now or datetime.now(timezone.utc)
    clean = "".join(ch for ch in str(digest or "") if ch.isalnum())
    window = {
        "days": int(days),
        "since": (at - timedelta(days=int(days))).isoformat(),
        "until": at.isoformat(),
        "max_measured_days": HASH_MAX_MEASURED_DAYS,
    }

    def no(reason_absence: absence.Absent) -> dict[str, Any]:
        return {"observable": clean, "kind": "hash", "tenant_id": tenant_id,
                "window": window, "host_hashes": reason_absence.as_json()}

    if not str(tenant_id or "").strip():
        return no(absence.absent(
            absence.CHECK_FAILED,
            "No customer was named, so no cluster could be chosen. An "
            "unpinned query would answer about somebody else's estate."))
    if client is None:
        return no(absence.absent(
            absence.CHECK_FAILED,
            f"No log-store integration is configured for {tenant_id!r}, so "
            f"the estate was not searched. There is deliberately no fallback "
            f"cluster.", raw=str(tenant_id)))
    if len(clean) not in (32, 40, 64):
        return no(absence.absent(
            absence.UNPARSED,
            f"{len(clean)} characters is not a digest length — SHA-256 is 64, "
            f"SHA-1 is 40, MD5 is 32. Not searched: a short needle in a "
            f"leading wildcard scans the field.", raw=str(len(clean))))
    if int(days) > HASH_MAX_MEASURED_DAYS:
        # The kind that exists for exactly this: there IS somewhere to look
        # and this window's cost has not been timed.
        return no(absence.absent(
            absence.COST_NOT_ESTABLISHED,
            f"A {days}-day hash search was asked for and only up to "
            f"{HASH_MAX_MEASURED_DAYS} days has been timed on this cluster "
            f"(24h 83ms, 7d 161ms, 30d 422ms; the full 120 days took 1.7s "
            f"warm and 4.3s cold). The field needs a leading wildcard, so the "
            f"cost grows with the window. Not refused as impossible — "
            f"unmeasured, and worth measuring if this window is wanted.",
            raw=str(days)))

    resolver = getattr(client, "hash_seen", None)
    if resolver is None:
        return no(absence.absent(
            absence.CHECK_FAILED,
            "This log-store client cannot search image hashes."))
    try:
        docs, hosts = resolver(digest=clean, since=window["since"],
                               until=window["until"], tenant_id=tenant_id)
    except Exception as exc:
        return no(absence.absent(
            absence.CHECK_FAILED,
            f"The hash search did not complete, so whether this image ran is "
            f"unknown rather than no. ({type(exc).__name__}: "
            f"{str(exc)[:140]})"))

    return {
        "observable": clean,
        "kind": "hash",
        "tenant_id": tenant_id,
        "window": window,
        "host_hashes": {
            "observed": bool(docs),
            "documents": int(docs),
            "hosts": list(hosts),
            "host_count": len(hosts),
            "field": HOST_HASH_FIELD,
            "basis": (
                f"Sysmon event {HASH_EVENT_ID} (Process Create) only — this "
                f"is what RAN, not what was loaded into another process "
                f"(event 7) or merely seen on disk (event 29). Matched by "
                f"leading wildcard against the composite "
                f"`MD5=…,SHA256=…,IMPHASH=…` value, so any of the three "
                f"digests will match."
            ),
            "window_claim": (
                f"Covers {days} days. A nil result here is not a statement "
                f"about the full {RETENTION_DAYS}-day retention: this field "
                f"spans it (2,626,536 documents from 2026-06-17 across 190 "
                f"hosts), and the window is a cost bound, not a data bound."
            ),
        },
    }


# --- the real client ------------------------------------------------------
#
# Everything above is tested against a fake. That is not evidence the lookup
# works: the fake implements an interface I wrote, and five times this week a
# check verified both halves of a join and not the join itself. So the adapter
# below is the seam, and it is verified against the live cluster with the
# figures from the recon rather than against my expectation of it.
#
# Nothing here is taken from a request. The nodes, index pattern, tenant field
# and credentials all come from the deployment's own per-tenant integration,
# because an estate query whose index or manager filter could be supplied by a
# caller is not pinned to a tenant at all.

#: Which agents reported. `agent.name` is the estate's own host identity and
#: the denominator the coverage figures are measured against.
class PartialResult(RuntimeError):
    """An aggregation that did not see every shard.

    Raised rather than returned, because a partial `min` is a *later*
    timestamp than the truth — it would classify long-standing
    infrastructure as newly resolved, which is the inversion the first-seen
    comparison exists to prevent. Reachable on this cluster: a
    retention-wide min over `data.dstip` (2.07bn docs) timed out during the
    2026-10-15 verification.
    """


AGENT_FIELD = "agent.name"

#: NOT a constant for the timestamp. The per-tenant integration carries
#: `opensearch_timestamp_field` (default `timestamp`), and the first version of
#: this adapter hard-coded `@timestamp`. On a tenant using the configured
#: default, that range filter matches nothing and the lookup returns a
#: confident zero — a silent negative in the one place this module exists to
#: prevent one. There is deliberately no fallback value below.

#: 180 agents in the estate, so a bucket count above that means the terms agg
#: truncated and `hosts` would be a lower bound rather than the set.
_HOST_BUCKETS = 400


class OpenSearchEstateClient:
    """`count_and_hosts` over one tenant's pinned cluster.

    Constructed from `opensearch_tenants.integration_for(tenant_id)`, so a
    tenant with no integration yields no client and the lookup reports
    `check_failed` rather than reaching for a default cluster.
    """

    def __init__(self, client: Any, integration: Any) -> None:
        self._client = client
        self._integration = integration

    def count_and_hosts(
        self, *, field: str, value: str, since: str, until: str, tenant_id: str
    ) -> tuple[int, list[str]]:
        integ = self._integration
        pattern = str(getattr(integ, "opensearch_index_pattern", "") or "")
        tenant_field = str(getattr(integ, "opensearch_tenant_field", "") or "")
        # The real attribute name. The first version read `tenant_values`,
        # which does not exist on TenantIntegration, and
        # `getattr(..., None) or []` turned the missing attribute into "no
        # tenant filter" — so the query ran across every tenant's documents.
        # It was caught by the live host count disagreeing with the recon
        # (109 hosts against 5), not by any test.
        tenant_values = [
            str(v) for v in (getattr(integ, "opensearch_tenant_value_list", None) or [])
            if str(v).strip()
        ]
        timestamp_field = str(getattr(integ, "opensearch_timestamp_field", "") or "")

        # Refusals, not defaults. Each of these would otherwise produce an
        # answer that looks clean: an unpinned query answers about somebody
        # else's estate, and a wrong timestamp field answers zero.
        if not pattern:
            raise RuntimeError("no index pattern configured for this tenant")
        if not timestamp_field:
            raise RuntimeError(
                "no timestamp field configured for this tenant; a guessed "
                "field would silently match nothing"
            )
        if not tenant_field or not tenant_values:
            raise RuntimeError(
                "this tenant has no log-store tenant pin "
                "(opensearch_tenant_field / opensearch_tenant_value_list), so "
                "the query is refused rather than run unpinned"
            )

        filters: list[dict[str, Any]] = [
            # `.keyword` is not appended: these Wazuh fields are mapped as
            # keyword already, and guessing a subfield that does not exist
            # returns zero hits — a silent negative of exactly the kind this
            # module exists to prevent.
            {"term": {field: value}},
            {"range": {timestamp_field: {
                "gte": since, "lte": until,
                "format": "strict_date_optional_time",
            }}},
            # A `filter`, not a `should`, for the same reason the log-context
            # query does it this way: a query that can return another tenant's
            # documents when the value clause happens to match is not pinned.
            # Unconditional, because the refusal above guarantees it is usable.
            {"terms": {tenant_field: tenant_values}},
        ]
        # What the field *means*. Without this the DNS question counts
        # resolution failures (event 1014) as contact — see DNS_EVENT_QUERY.
        filters.extend(_SEMANTIC_FILTERS.get(field, []))

        body = {
            "size": 0,
            "track_total_hits": True,
            "query": {"bool": {"filter": filters}},
            "aggs": {"hosts": {"terms": {
                "field": AGENT_FIELD, "size": _HOST_BUCKETS,
            }}},
        }
        payload, _node, _failures = self._client._request(
            "POST", f"/{pattern}/_search", json_body=body,
        )
        total = (((payload or {}).get("hits") or {}).get("total") or {})
        docs = int(total.get("value") or 0)
        buckets = (((payload or {}).get("aggregations") or {})
                   .get("hosts") or {}).get("buckets") or []
        hosts = [str(b.get("key")) for b in buckets if b.get("key") is not None]
        return docs, hosts


    def first_last_seen(
        self, *, field: str, value: str, since: str, until: str, tenant_id: str
    ) -> tuple[Any, Any]:
        """Earliest and latest time this value appears, over the window given.

        Called only for a HIT, and called over the full retention rather than
        the 7-day window — a 7-day window cannot answer "months", and its edge
        would read as a first-seen. The caller classifies an edge value as a
        lower bound; this method just reports what the store holds.
        """
        from datetime import datetime

        integ = self._integration
        pattern = str(getattr(integ, "opensearch_index_pattern", "") or "")
        tenant_field = str(getattr(integ, "opensearch_tenant_field", "") or "")
        tenant_values = [
            str(v) for v in (getattr(integ, "opensearch_tenant_value_list", None) or [])
            if str(v).strip()
        ]
        timestamp_field = str(getattr(integ, "opensearch_timestamp_field", "") or "")
        if not pattern or not timestamp_field:
            raise RuntimeError("index pattern or timestamp field not configured")
        if not tenant_field or not tenant_values:
            raise RuntimeError(
                "no tenant pin; refusing rather than querying unpinned"
            )

        body = {
            "size": 0,
            "query": {"bool": {"filter": [
                {"term": {field: value}},
                {"range": {timestamp_field: {
                    "gte": since, "lte": until,
                    "format": "strict_date_optional_time",
                }}},
                {"terms": {tenant_field: tenant_values}},
                *_SEMANTIC_FILTERS.get(field, []),
            ]}},
            "aggs": {
                "first": {"min": {"field": timestamp_field}},
                "last": {"max": {"field": timestamp_field}},
            },
        }
        payload, _node, _failures = self._client._request(
            "POST", f"/{pattern}/_search", json_body=body,
        )
        payload = payload or {}
        shards = payload.get("_shards") or {}
        failed = int(shards.get("failed") or 0)
        if payload.get("timed_out") or failed:
            raise PartialResult(
                f"first-seen aggregation incomplete: timed_out="
                f"{payload.get('timed_out')}, shards failed={failed} of "
                f"{shards.get('total')}. A partial min is later than the "
                f"truth, so it is not reported as a first-seen."
            )
        aggs = payload.get("aggregations") or {}

        def _parse(key: str) -> Any:
            node = aggs.get(key) or {}
            # `value_as_string` is the formatted date; `value` is epoch millis.
            raw = node.get("value_as_string")
            if raw:
                try:
                    return datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
                except ValueError:
                    pass
            millis = node.get("value")
            if millis is None:
                return None
            from datetime import timezone as _tz
            return datetime.fromtimestamp(float(millis) / 1000.0, tz=_tz.utc)

        return _parse("first"), _parse("last")

    def hash_seen(
        self, *, digest: str, since: str, until: str, tenant_id: str
    ) -> tuple[int, list[str]]:
        """Did any host execute an image with this hash, and on how many hosts.

        A **leading wildcard**, which is unusual enough to justify: the field
        is a composite `MD5=…,SHA256=…,IMPHASH=…` string with no parsed
        sibling, so a `term` on a bare digest matches nothing (measured: 0
        hits against 18,571 for the wildcard form). The cost is bounded by the
        caller's window rather than by hope — see HASH_WINDOW_DAYS for the
        timings.

        Pinned to Sysmon event 1. Not because the three producing events
        disagree about meaning, but because event 1 is the *execution* claim
        and events 7 and 29 are not — "what ran" must not silently include
        what was loaded or what was seen on disk.
        """
        integ = self._integration
        pattern = str(getattr(integ, "opensearch_index_pattern", "") or "")
        tenant_field = str(getattr(integ, "opensearch_tenant_field", "") or "")
        tenant_values = [
            str(v) for v in (getattr(integ, "opensearch_tenant_value_list", None) or [])
            if str(v).strip()
        ]
        timestamp_field = str(getattr(integ, "opensearch_timestamp_field", "") or "")
        if not pattern or not timestamp_field:
            raise RuntimeError("index pattern or timestamp field not configured")
        if not tenant_field or not tenant_values:
            raise RuntimeError(
                "no tenant pin; refusing rather than querying unpinned")

        clean = "".join(ch for ch in str(digest or "") if ch.isalnum())
        if len(clean) not in (32, 40, 64):
            # Not a digest length. Refused rather than wildcarded, because a
            # short needle in a leading wildcard is a scan of the index.
            raise ValueError(
                f"{len(clean)} characters is not a digest length; a short "
                f"needle in a leading wildcard scans the whole field"
            )

        body = {
            "size": 0,
            "track_total_hits": True,
            "timeout": "120s",
            "query": {"bool": {"filter": [
                # `case_insensitive`, and it is load-bearing rather than
                # tidy. Sysmon stores the digests UPPERCASE; `detect()`
                # lowercases every hash, and lowercase is the form every tool
                # and every analyst pastes (VirusTotal, sha256sum, every
                # report). Measured 2026-10-15 on the same needle and window:
                # uppercase 9,636 hits, lowercase **0**. Without this flag
                # every hash lookup returns a confident nothing.
                {"wildcard": {HOST_HASH_FIELD: {
                    "value": f"*{clean}*", "case_insensitive": True,
                }}},
                {"range": {timestamp_field: {
                    "gte": since, "lte": until,
                    "format": "strict_date_optional_time",
                }}},
                {"terms": {tenant_field: tenant_values}},
                *_SEMANTIC_FILTERS.get(HOST_HASH_FIELD, []),
            ]}},
            "aggs": {"hosts": {"terms": {
                "field": AGENT_FIELD, "size": _HOST_BUCKETS,
            }}},
        }
        payload, _node, _failures = self._client._request(
            "POST", f"/{pattern}/_search", json_body=body,
        )
        payload = payload or {}
        shards = payload.get("_shards") or {}
        if payload.get("timed_out") or int(shards.get("failed") or 0):
            raise PartialResult(
                f"hash search incomplete: timed_out={payload.get('timed_out')}, "
                f"shards failed={shards.get('failed')} of {shards.get('total')}. "
                f"A partial count is a floor, and reporting it as 'not seen' "
                f"would be the false negative this whole module exists to stop."
            )
        total = (((payload.get("hits") or {}).get("total")) or {})
        buckets = (((payload.get("aggregations") or {})
                    .get("hosts") or {}).get("buckets") or [])
        hosts = [str(b.get("key")) for b in buckets if b.get("key") is not None]
        return int(total.get("value") or 0), hosts

    def observation_floor(
        self, *, field: str, since: str, until: str, tenant_id: str
    ) -> dict[str, Any]:
        """When collection of `field` began, per host.

        **The predicate must match the first-seen query exactly, minus the
        value.** Measured on 2026-10-15, dropping just the
        `exists(queryName)` clause and keeping event 22 moved the floor from
        2026-08-22 to 2026-06-20 — four months early, because event-22
        documents exist that do not carry the field. A floor measured on a
        looser predicate is always earlier than the truth, so the grace
        window never fires and the recency bias it exists to catch comes
        straight back in through the floor. The one clause that differs is the
        value itself: this asks when the host could first have reported *any*
        value.

        Per host rather than one number because the floors genuinely differ:
        140 of 175 hosts began on 2026-10-02, and 33 (18.9%) later, the last
        on 2026-10-12. A single global floor is set by whichever host started
        earliest — two outliers here — and is therefore never reached by
        anything, which makes the grace window dead code.
        """
        integ = self._integration
        pattern = str(getattr(integ, "opensearch_index_pattern", "") or "")
        tenant_field = str(getattr(integ, "opensearch_tenant_field", "") or "")
        tenant_values = [
            str(v) for v in (getattr(integ, "opensearch_tenant_value_list", None) or [])
            if str(v).strip()
        ]
        timestamp_field = str(getattr(integ, "opensearch_timestamp_field", "") or "")
        if not pattern or not timestamp_field:
            raise RuntimeError("index pattern or timestamp field not configured")
        if not tenant_field or not tenant_values:
            raise RuntimeError(
                "no tenant pin; refusing rather than querying unpinned"
            )

        body = {
            "size": 0,
            "query": {"bool": {"filter": [
                {"exists": {"field": field}},
                {"range": {timestamp_field: {
                    "gte": since, "lte": until,
                    "format": "strict_date_optional_time",
                }}},
                {"terms": {tenant_field: tenant_values}},
                *_SEMANTIC_FILTERS.get(field, []),
            ]}},
            "aggs": {"hosts": {
                "terms": {"field": AGENT_FIELD, "size": _HOST_BUCKETS},
                "aggs": {"first": {"min": {"field": timestamp_field}}},
            }},
        }
        payload, _node, _failures = self._client._request(
            "POST", f"/{pattern}/_search", json_body=body,
        )
        payload = payload or {}
        shards = payload.get("_shards") or {}
        failed = int(shards.get("failed") or 0)
        if payload.get("timed_out") or failed:
            raise PartialResult(
                f"collection-floor aggregation incomplete: timed_out="
                f"{payload.get('timed_out')}, shards failed={failed} of "
                f"{shards.get('total')}. A partial min is a later floor than "
                f"the truth, which widens the grace window and hides exactly "
                f"the first-seens it exists to flag."
            )
        buckets = (((payload.get("aggregations") or {})
                    .get("hosts") or {}).get("buckets") or [])
        floors: dict[str, Any] = {}
        for bucket in buckets:
            host = bucket.get("key")
            node = bucket.get("first") or {}
            raw = node.get("value_as_string")
            stamp = None
            if raw:
                try:
                    stamp = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
                except ValueError:
                    stamp = None
            if stamp is None and node.get("value") is not None:
                stamp = datetime.fromtimestamp(
                    float(node["value"]) / 1000.0, tz=timezone.utc)
            # A bucket with no parseable min is left out rather than defaulted.
            # The caller treats a host absent from this map as unknown, which
            # is what it is; a default would make it a comparison.
            if host is not None and stamp is not None:
                floors[str(host)] = stamp
        return floors


def estate_client_for(tenant_id: str | None, *, settings: Any = None) -> Any:
    """The pinned client for this tenant, or None.

    None is the honest answer for a tenant with no log-store integration, and
    `lookup()` turns it into `check_failed` — never into a search against
    somebody else's cluster.
    """
    from app.services import opensearch_client as osc
    from app.services import opensearch_tenants

    integration = opensearch_tenants.integration_for(tenant_id, settings=settings)
    if integration is None:
        return None
    client = osc.safe_client(integration)
    if client is None:
        return None
    return OpenSearchEstateClient(client, integration)
