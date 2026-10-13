"""
IP Lookup service — the reputation logic behind the IP Lookup tool.

The API layer (`app.api.ip_lookup`) and any pipeline that needs the same
AbuseIPDB + ThreatFox verdict (e.g. the alert-body investigation) share this
module so the tool and the automated flows always return the same shape.
"""

from __future__ import annotations

import ipaddress
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import requests

from app.services import enrichment_health_service as health
from app.services.absence import CHECK_FAILED, UNRECOGNISED, absent
from sqlalchemy.orm import Session

from app.config import get_settings
from app.services.abuseipdb_client import abuseipdb_get, configured_abuseipdb_api_keys
from app.db.session import sync_engine
from app.models.database import IPLookup

logger = logging.getLogger(__name__)

ABUSEIPDB_CATEGORIES: dict[int, str] = {
    3: "Fraud Orders",
    4: "DDoS Attack",
    5: "FTP Brute-Force",
    6: "Ping of Death",
    7: "Phishing",
    8: "Fraud VoIP",
    9: "Open Proxy",
    10: "Web Spam",
    11: "Email Spam",
    14: "Port Scan",
    15: "Hacking",
    16: "SQL Injection",
    17: "Spoofing",
    18: "Brute-Force",
    19: "Bad Web Bot",
    20: "Exploited Host",
    21: "Web App Attack",
    22: "SSH",
    23: "IoT Targeted",
}


def is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(str(value or "").strip())
    except ValueError:
        return False
    return True


#: The `query_status` values abuse.ch returns that mean "I will not answer
#: this". Measured against the live API on 2026-10-12, because abuse.ch
#: documents none of them — which is exactly why anything NOT in this set is
#: reported as `unrecognised_absence` rather than being folded into one of
#: these. A vocabulary nobody published can grow without telling us.
#:
#: `no_result` is deliberately absent: that one is a real negative.
#: Only the two that were actually observed. Names like `illegal_auth_key`
#: appear in third-party integration guides and were left out on purpose: a
#: set described as measured has to contain only what was measured, and a
#: guessed entry here would silently convert an unrecognised status into a
#: confident claim — the precise failure this split exists to prevent.
THREATFOX_REFUSALS = frozenset({
    "unknown_operation",   # our query verb was wrong (200)
    "unknown_auth_key",    # the key was rejected (403)
})


def perform_ip_lookup(ip: str, *, timeout: int = 15) -> dict[str, Any]:
    """
    Run an IP reputation check (AbuseIPDB verbose + ThreatFox).

    Pure network work — no persistence. Never raises: provider failures are
    reported in the "errors" list so callers always get a usable report.
    """
    settings = get_settings()
    ip = str(ip or "").strip()
    result: dict[str, Any] = {
        "ip": ip,
        "queried_at": datetime.now(timezone.utc).isoformat(),
        "abuseipdb": None,
        "threatfox": [],
        "errors": [],
    }

    # ── AbuseIPDB (verbose) ──
    if not configured_abuseipdb_api_keys(settings):
        result["errors"].append("AbuseIPDB API key not configured")
    else:
        try:
            # Walks every configured key, so a key that has spent its daily
            # 1,000 checks falls through to the spare rather than ending
            # AbuseIPDB coverage until midnight UTC.
            resp = abuseipdb_get(
                "check",
                params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
                timeout=timeout,
                settings=settings,
            )
            resp.raise_for_status()
            data = resp.json().get("data", {})
            if data:
                reports = data.get("reports", [])
                all_cats: list[int] = []
                for report in reports:
                    all_cats.extend(report.get("categories", []))
                unique_cats = list(set(all_cats))

                recent_reports = [
                    {
                        "reported_at": r.get("reportedAt"),
                        "comment": (r.get("comment") or "").strip()[:300],
                        "categories": r.get("categories", []),
                        "category_labels": [
                            ABUSEIPDB_CATEGORIES.get(c, f"Cat {c}")
                            for c in r.get("categories", [])
                        ],
                        "reporter_country": r.get("reporterCountryCode"),
                    }
                    for r in sorted(
                        reports,
                        key=lambda r: r.get("reportedAt", ""),
                        reverse=True,
                    )[:15]
                ]

                result["abuseipdb"] = {
                    "ip": ip,
                    "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                    "total_reports": data.get("totalReports", 0),
                    "num_distinct_users": data.get("numDistinctUsers", 0),
                    "last_reported_at": data.get("lastReportedAt"),
                    "isp": data.get("isp"),
                    "usage_type": data.get("usageType"),
                    "country_code": data.get("countryCode"),
                    "country_name": data.get("countryName"),
                    "domain": data.get("domain"),
                    "hostnames": data.get("hostnames", [])[:10],
                    "is_tor": data.get("isTor", False),
                    "is_public": data.get("isPublic", True),
                    "is_whitelisted": data.get("isWhitelisted", False),
                    "categories": unique_cats,
                    "category_labels": [
                        ABUSEIPDB_CATEGORIES.get(c, f"Category {c}")
                        for c in unique_cats
                    ],
                    "recent_reports": recent_reports,
                }
        except Exception as e:
            logger.warning(f"AbuseIPDB lookup failed for {ip}: {e}")
            result["errors"].append(f"AbuseIPDB: {type(e).__name__}")

    # ── ThreatFox ──
    #
    # Two things were wrong here, and either alone was enough to guarantee the
    # 401 that every one of the 6,376 stored lookups recorded. The header was
    # named `API-KEY`; abuse.ch's documented name is `Auth-Key`. And it was
    # sent empty, from a literal, with no setting anywhere to put a key in.
    auth_key = str(getattr(settings, "abusech_auth_key", "") or "").strip()
    if not auth_key:
        # Do not make the call. A request with no key is a round trip whose
        # only possible outcome is a 401, and dressing that up as a network
        # failure is what made this look like an outage for a month rather
        # than a missing credential. Say which it is.
        health.record("threatfox", ok=False, error="no_auth_key")
        result["errors"].append("ThreatFox: no abuse.ch Auth-Key configured")
        result["threatfox_status"] = absent(
            CHECK_FAILED,
            "ThreatFox was not asked about this address: no abuse.ch Auth-Key "
            "is configured, and abuse.ch has required one since it made "
            "authentication mandatory. This is a missing credential, not a "
            "feed outage, and not a clean result. Set ABUSECH_AUTH_KEY.",
            raw="no_auth_key",
        ).as_json()
        # Fall through to the shared return; the request below is skipped.
    elif not settings.threatfox_enabled:
        # Switched off 2026-10-13. `search_ioc` is a substring search, so a
        # lookup for an observable returns every IOC containing that string —
        # which produced malicious/high on `office.com` from
        # `nlahtc.theluxehomeoffice.com`. Recorded as an absence, never as a
        # clean result: this is "not asked", and the whole point of the
        # convention is that it must not read as "asked and found nothing".
        # `result["threatfox_status"]`, not a bare local. The first version of
        # this branch assigned to a local and the switched-off feed recorded
        # nothing at all — an absence bug inside the fix for an absence bug,
        # and the only reason it was caught is that the test for the
        # dangerous direction was written before the branch.
        health.record("threatfox", ok=False, error="disabled")
        result["errors"].append("ThreatFox: switched off (THREATFOX_ENABLED)")
        result["threatfox_status"] = absent(
            CHECK_FAILED,
            "ThreatFox is switched off (THREATFOX_ENABLED). Its search "
            "endpoint matches substrings, so a lookup returns indicators "
            "belonging to unrelated hosts that merely contain this one's "
            "name. No result here is an absence, not a negative.",
            raw="disabled",
        ).as_json()
    else:
        try:
            resp = requests.post(
                "https://threatfox-api.abuse.ch/api/v1/",
                json={"query": "search_ioc", "search_term": ip},
                # Never interpolated into a log line, an error string or the
                # stored `result_json` — only this header.
                headers={"Auth-Key": auth_key},
                timeout=timeout,
            )
            resp.raise_for_status()
            tf_data = resp.json()
            # `no_result` is the feed working. Counting it as a failure would
            # make the enrichment health monitor read "ThreatFox is broken"
            # from a feed answering correctly about unlisted addresses, which
            # is most of them.
            tf_status = str(tf_data.get("query_status") or "")
            health.record("threatfox", ok=tf_status in ("ok", "no_result"),
                          error=tf_status)
            if tf_data.get("query_status") == "ok":
                for ioc in tf_data.get("data", []) or []:
                    result["threatfox"].append({
                        "ioc_value": ioc.get("ioc", ip),
                        "ioc_type": ioc.get("ioc_type", "ip:port"),
                        "threat_type": ioc.get("threat_type", "unknown"),
                        "malware": ioc.get("malware_printable") or ioc.get("malware"),
                        "confidence_level": ioc.get("confidence_level"),
                        "first_seen": ioc.get("first_seen"),
                        "last_seen": ioc.get("last_seen"),
                        "tags": ioc.get("tags") or [],
                    })
            elif tf_data.get("query_status") == "no_result":
                # A real negative, and the whole point of this module is not to
                # confuse one with a failure. Measured against the live API on
                # 2026-10-12, because abuse.ch does not document the vocabulary:
                #
                #   ok                 200  matches, in `data`
                #   no_result          200  the IOC is not in ThreatFox
                #   unknown_operation  200  our query verb was wrong
                #   unknown_auth_key   403  the key was rejected
                #   (empty key)        401  no JSON at all — this is the
                #                           HTTPError all 6,376 historical
                #                           rows recorded
                #
                # One caveat kept deliberately: a malformed `search_term` also
                # returns `no_result`, so this is only a trustworthy negative
                # because `is_valid_ip` has already run. If this is ever reused
                # for an unvalidated value, that stops being true.
                pass
            elif tf_status in THREATFOX_REFUSALS:
                # abuse.ch answered and would not run the query. Distinct from
                # `no_result`: nothing was checked, so nothing is known.
                result["threatfox_status"] = absent(
                    CHECK_FAILED,
                    f"ThreatFox would not run this query: {tf_status}. "
                    "Nothing was checked against this feed, so this is not a "
                    "'no hits' result.",
                    raw=tf_status,
                ).as_json()
            else:
                # A status this code has not seen. The vocabulary above was
                # measured, not documented, so it can grow without notice —
                # and the honest answer to an unrecognised value is that we do
                # not know what it means. Calling it `check_failed` would
                # assert "the check did not run", which a new status for a
                # rate limit, a partial result or a deprecated endpoint would
                # make false. Same reasoning as `absent()` degrading an
                # unrecognised *kind* rather than filing it under one that
                # means something: do not pick a side, and keep the string.
                result["threatfox_status"] = absent(
                    UNRECOGNISED,
                    "ThreatFox answered with a status this platform does not "
                    f"recognise: {tf_status}. The feed's status vocabulary is "
                    "undocumented, so this is neither a result nor a known "
                    "failure, and nothing should be concluded from it either "
                    "way until somebody looks.",
                    raw=tf_status,
                ).as_json()
        except Exception as e:
            # Measured on `ip_lookups.result_json`, which is where every
            # lookup's outcome is persisted and therefore the right table to
            # ask: all 6,376 rows written before 2026-10-12 record
            # `ThreatFox: HTTPError` and `threatfox_count` 0. Every one of
            # those was the 401 above — wrong header name, no key — so none of
            # them is evidence about this feed's reliability. Reaching here
            # now, with a key configured, is a real failure and new.
            #
            # Logged at warning, not debug. At debug this failed silently for
            # 6,259 lookups and surfaced as a zero that looked like a clean
            # result. The key is never included: `type(e).__name__` only.
            logger.warning(
                "ThreatFox lookup failed for %s: %s. A key is configured, so "
                "this is the feed or the network rather than the credential.",
                ip, type(e).__name__,
            )
            result["errors"].append(f"ThreatFox: {type(e).__name__}")
            health.record("threatfox", ok=False, error=type(e).__name__)
            result["threatfox_status"] = absent(
                CHECK_FAILED,
                "ThreatFox could not be reached, so this address was not "
                "checked against it. This is not a clean result. An Auth-Key "
                "is configured, so this is the feed or the network and not a "
                "missing credential.",
                raw=type(e).__name__,
            ).as_json()

    return result


def build_ip_lookup_record(result: dict[str, Any]) -> IPLookup:
    """Build the history row for a lookup result (shared by API and pipelines)."""
    ab = result.get("abuseipdb") or {}
    return IPLookup(
        id=uuid.uuid4(),
        ip=str(result.get("ip") or ""),
        abuse_score=ab.get("abuse_confidence_score") if ab else None,
        isp=ab.get("isp") if ab else None,
        country_code=ab.get("country_code") if ab else None,
        threatfox_count=len(result.get("threatfox") or []),
        result_json=result,
        queried_at=datetime.now(timezone.utc),
    )


def lookup_ip_with_history(ip: str, *, timeout: int = 15) -> dict[str, Any]:
    """
    Run a lookup and save it to IP Lookup history using a synchronous session.

    Used by Celery tasks (which have no async DB session). History persistence is
    best-effort: a DB failure never loses the lookup result itself.
    """
    result = perform_ip_lookup(ip, timeout=timeout)
    try:
        with Session(sync_engine) as db:
            record = build_ip_lookup_record(result)
            db.add(record)
            db.commit()
            result["id"] = str(record.id)
    except Exception as exc:
        logger.warning("Could not persist IP lookup history for %s: %s", ip, exc)
    return result


# --- reading a stored lookup, and saying how old it is ----------------------

#: When a stored lookup stops being presentable as current.
#:
#: Measured on `ip_lookups.queried_at` — the right table because it is the one
#: holding every lookup this platform has ever performed. Of 6,259 rows: 53
#: under a day, 186 under a week, 2,409 under 30 days, and 15 older than 90
#: days, spanning 2026-03-03 to 2026-10-09. The re-lookup rate is already 4.2
#: per address, so something refreshes them; this threshold decides only what
#: is *labelled* stale, not what is re-fetched.
STALE_AFTER = timedelta(days=30)


def freshness_of(queried_at: datetime | None) -> dict[str, Any]:
    """How old a stored verdict is, in terms a panel can show.

    An IP's reputation changes, so a cached verdict without an age is a claim
    about the present made from the past. The age travels with the verdict.
    """
    if queried_at is None:
        return absent(
            CHECK_FAILED,
            "This lookup has no recorded time, so its age cannot be stated and "
            "it should not be read as current.",
        ).as_json()
    now = datetime.now(timezone.utc)
    stamp = queried_at if queried_at.tzinfo else queried_at.replace(tzinfo=timezone.utc)
    age = now - stamp
    stale = age > STALE_AFTER
    if stale:
        # Logged so "how often is a stale verdict actually read" is answerable
        # from data in a month rather than guessed at now. No refresh path is
        # added until that number exists.
        logger.info(
            "stale_ip_verdict_read ip_lookup_age_days=%d threshold_days=%d",
            age.days, STALE_AFTER.days,
        )
    return {
        "queried_at": stamp.isoformat(),
        "age_days": age.days,
        "stale": stale,
        "threshold_days": STALE_AFTER.days,
    }
