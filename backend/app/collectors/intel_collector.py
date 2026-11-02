"""
Intel Collector — reputation lookups and certificate transparency.

Sources:
- crt.sh (Certificate Transparency logs) — free, no key
- DNS-based blocklists (SURBL, Spamhaus DBL) — free DNS queries
- Abuse contact lookup via abuse.ch / URLhaus — free API

Facts only. No interpretation.

What a DNS blocklist says, and what it does not
-----------------------------------------------
Measured from the api container on 2026-10-13. Each zone publishes a name
that is permanently listed, for exactly this purpose:

    dbltest.com.dbl.spamhaus.org     (listed)  -> 127.255.255.254
    test.surbl.org.multi.surbl.org   (listed)  -> 127.0.0.254
    expertware.net.dbl.spamhaus.org            -> 127.255.255.254
    expertware.net.multi.surbl.org             -> NXDOMAIN
    vshkolu.cz.dbl.spamhaus.org                -> NXDOMAIN

`127.255.255.254` is Spamhaus for "query via a public/open resolver" and
`127.0.0.254` is SURBL's equivalent. Read the five lines together and the
refusal is **per query, not per zone**: both zones refused their own test
point and both answered an ordinary name, in the same minute. So this
deployment is being rate-limited rather than blocked, which means

  * an NXDOMAIN really is "not listed" — the query got through;
  * a refusal really is no answer at all;
  * and the two must not be the same value, which is the whole fix.

It also means listings are being lost. The one name we know for certain is
listed came back as a refusal, so the DNSBL half of this collector is
answering incompletely, and the `sources_skipped` record is what makes that
visible for the first time. Moving these queries to a resolver Spamhaus and
SURBL will serve is the real repair; this code's job is to stop reporting the
gap as a clean result.

Three states, not two. A zone can answer "listed", answer "not listed"
(NXDOMAIN, and only NXDOMAIN), or not answer. `socket.gaierror` covers the
second and the third indistinguishably — EAI_AGAIN is a SERVFAIL or a dead
resolver, not a clean domain — and the original code's comment asserted
"NXDOMAIN = not listed (good)" for all of them. That is the same shape as
seven months of ThreatFox silence, in DNS.

The Spamhaus refusal family was recognised and SURBL's was not, so SURBL's
`127.0.0.254` would have been read as a listing on every domain in the
estate the moment the collector stopped crashing — a mass false positive
created by the fix for a mass false negative.
"""

from __future__ import annotations

import base64
import json
import logging
import socket
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

import requests

from typing import Any

from app.collectors.base import BaseCollector
from app.config import get_settings
from app.services.absence import CHECK_FAILED, UNRECOGNISED, absent
from app.services.threatfox_match_scope import HOST_AGGREGATE
from app.models.schemas import CollectorMeta, IntelEvidence, IntelHit, CertTimelineEntry, CertTimelineEvidence

logger = logging.getLogger(__name__)

# DNS-based blocklists to check
DNSBL_LISTS = [
    ("multi.surbl.org", "SURBL"),
    ("dbl.spamhaus.org", "Spamhaus DBL"),
]

SPAMHAUS_DNSBL_ERROR_CODES = {
    "127.255.255.252": "typing error in DNSBL name",
    "127.255.255.254": "query via public/open resolver",
    "127.255.255.255": "excessive number of queries",
}

#: SURBL answers with a bitmask in the last octet — 8 phishing, 16 malware,
#: 32 abuse, 64 cracked. `254` is every bit set at once, which is not a
#: listing any domain can have; SURBL uses it as the refusal sentinel for an
#: open resolver or an exceeded free-use limit. It is the only thing this
#: deployment has received from the zone, including for SURBL's own test
#: point, so reading it as a reputational response would mark everything.
#: The four sources whose answers land in `blocklist_hits`, named once so the
#: checked/skipped record and the consumers cannot drift apart.
#: One spelling. This feed used to emit two — "URLhaus" from the per-URL path
#: and "URLhaus (abuse.ch)" from the aggregate — so any per-source count of
#: it was wrong in a way nothing could see.
URLHAUS = "URLhaus (abuse.ch)"
SPAMHAUS_SIA = "Spamhaus SIA"
BLOCKLIST_SOURCES = ("SURBL", "Spamhaus DBL", URLHAUS, SPAMHAUS_SIA)

SURBL_DNSBL_ERROR_CODES = {
    "127.0.0.254": "query refused (open resolver or free-use limit exceeded)",
}

#: The one `gaierror` that is an answer. EAI_NONAME is NXDOMAIN: the name is
#: not in the zone, which is exactly what "not listed" means. Everything else
#: — EAI_AGAIN (SERVFAIL, timeout, no resolver), EAI_FAIL — is the query not
#: completing, and must not be recorded as a negative.
_NOT_LISTED_ERRNOS = {
    getattr(socket, name)
    for name in ("EAI_NONAME", "EAI_NODATA")
    if hasattr(socket, name)
}

_SPAMHAUS_SIA_TOKEN_CACHE: dict[str, int | str] = {"token": "", "expires": 0}


class IntelCollector(BaseCollector):
    supported_types = frozenset({"domain", "url"})
    name = "intel"

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        # Per-source, because `blocklist_hits` merges four of them into one
        # list and an empty list says nothing about which ones were asked.
        self.sources_checked: list[str] = []
        self.sources_skipped: dict[str, dict] = {}
        self._dnsbl_notes: list[str] = []

    def _answered(self, source: str) -> None:
        """This source was asked and replied. Recorded even when the reply was
        "not listed", because that is the fact a clean verdict needs."""
        if source not in self.sources_checked:
            self.sources_checked.append(source)
        self.sources_skipped.pop(source, None)

    def _unanswered(self, source: str, kind: str, reason: str, raw: Any = None) -> None:
        """This source did not answer. Never also `_answered`."""
        if source in self.sources_checked:
            self.sources_checked.remove(source)
        self.sources_skipped[source] = absent(kind, reason, raw=raw).as_json()
        self._dnsbl_notes.append(f"{source} did not answer: {reason}")

    def _collect(self) -> IntelEvidence:
        evidence = IntelEvidence()
        # For URL type, all intel queries target the extracted hostname
        target = self.target_domain
        settings = get_settings()
        cached = self._load_cached_intel(target)

        if cached:
            evidence.related_certs = list(cached.get("related_certs") or [])[:50]
            evidence.related_subdomains = list(cached.get("related_subdomains") or [])[:100]
            evidence.cert_entries_raw = list(cached.get("cert_entries_raw") or [])[:200]
            for raw_hit in (cached.get("urlhaus_hits") or []):
                try:
                    evidence.blocklist_hits.append(IntelHit(**raw_hit))
                except Exception:
                    continue
            evidence.notes.append("Reused cached intel (crt.sh + URLhaus)")

        # ── 1. Certificate Transparency via crt.sh ──
        if not cached:
            try:
                certs, subdomains, raw_entries = self._query_crtsh(
                    target,
                    timeout=min(self.timeout, settings.intel_crtsh_timeout_seconds),
                )
                evidence.related_certs = certs[:50]  # Cap at 50
                evidence.related_subdomains = subdomains[:100]
                evidence.cert_entries_raw = raw_entries[:200]  # Store for timeline analysis
            except Exception as e:
                logger.warning(f"crt.sh query failed for {target}: {e}")
                evidence.notes.append(f"crt.sh lookup failed: {e}")

        # ── 2. DNS Blocklist checks ──
        try:
            self._dnsbl_notes = []
            # `extend`, not `=`. The assignment that used to be here replaced
            # the list the cached URLhaus hits had just been appended to, so
            # on the cache path — the common path — a host URLhaus had flagged
            # came back with no hits at all.
            evidence.blocklist_hits.extend(self._check_dns_blocklists(target))
            evidence.notes.extend(self._dnsbl_notes)
        except Exception as e:
            logger.warning(f"DNSBL check failed for {target}: {e}")
            evidence.notes.append(f"DNSBL check failed: {e}")
            for _zone, source_name in DNSBL_LISTS:
                if source_name not in self.sources_checked:
                    self._unanswered(
                        source_name, CHECK_FAILED,
                        f"The DNSBL pass raised {type(e).__name__}: {e}",
                    )

        # ── 3. URLhaus lookup ──
        urlhaus_hits: list[IntelHit] = []
        if not cached:
            try:
                urlhaus_hits = self._check_urlhaus(
                    target,
                    timeout=min(self.timeout, settings.intel_urlhaus_timeout_seconds),
                )
                evidence.blocklist_hits.extend(urlhaus_hits)
            except Exception as e:
                logger.warning(f"URLhaus lookup failed for {target}: {e}")
                evidence.notes.append(f"URLhaus lookup failed: {e}")
                self._unanswered(
                    URLHAUS, CHECK_FAILED,
                    f"The URLhaus lookup raised {type(e).__name__}: {e}",
                )
        else:
            # A cache hit is URLhaus's answer, recorded earlier and reused.
            self._answered(URLHAUS)
            self._save_cached_intel(
                target,
                related_certs=evidence.related_certs,
                related_subdomains=evidence.related_subdomains,
                cert_entries_raw=evidence.cert_entries_raw,
                urlhaus_hits=urlhaus_hits,
                ttl_hours=settings.intel_cache_ttl_hours,
            )

        # ── 4. Spamhaus Intelligence API ──
        #
        # Guarded. This single line, unprotected, is what killed the whole
        # collector: `_get_spamhaus_sia_token` raises `RuntimeError` on a
        # failed login, and from 2026-07-07 to 2026-10-13 it raised on every
        # run — 2,198 of them, every one recorded as
        # `meta.status = "failed"` with crt.sh, both DNSBLs and URLhaus
        # already collected and thrown away with the exception. A fourth
        # source's credential must not be able to discard the other three.
        try:
            spamhaus_token = self._get_spamhaus_sia_token(settings)
        except Exception as e:
            logger.warning(f"Spamhaus SIA login failed for {target}: {e}")
            evidence.notes.append(f"Spamhaus SIA login failed: {e}")
            self._unanswered(
                SPAMHAUS_SIA, CHECK_FAILED,
                f"The Spamhaus SIA login did not succeed ({type(e).__name__}: {e}), "
                "so this source was never asked.",
            )
            spamhaus_token = ""
        if spamhaus_token:
            try:
                evidence.spamhaus_sia = self._query_spamhaus_sia_domain(
                    target,
                    token=spamhaus_token,
                    base_url=settings.spamhaus_sia_base_url,
                    timeout=min(self.timeout, settings.spamhaus_sia_timeout_seconds),
                )
                if evidence.spamhaus_sia.get("status") == "unauthorized" and settings.spamhaus_sia_username:
                    refreshed_token = self._get_spamhaus_sia_token(settings, force_refresh=True)
                    if refreshed_token and refreshed_token != spamhaus_token:
                        evidence.spamhaus_sia = self._query_spamhaus_sia_domain(
                            target,
                            token=refreshed_token,
                            base_url=settings.spamhaus_sia_base_url,
                            timeout=min(self.timeout, settings.spamhaus_sia_timeout_seconds),
                        )
                self._answered(SPAMHAUS_SIA)
            except Exception as e:
                logger.warning(f"Spamhaus SIA lookup failed for {target}: {e}")
                evidence.notes.append(f"Spamhaus SIA lookup failed: {e}")
                self._unanswered(
                    SPAMHAUS_SIA, CHECK_FAILED,
                    f"The Spamhaus SIA lookup raised {type(e).__name__}: {e}",
                )
        elif SPAMHAUS_SIA not in self.sources_skipped:
            evidence.notes.append(
                "Spamhaus SIA lookup skipped: configure SPAMHAUS_SIA_TOKEN or SPAMHAUS_SIA_USERNAME/PASSWORD"
            )
            self._unanswered(
                SPAMHAUS_SIA, CHECK_FAILED,
                "No Spamhaus SIA credential is configured, so this source was "
                "never asked. Set SPAMHAUS_SIA_TOKEN or "
                "SPAMHAUS_SIA_USERNAME/PASSWORD.",
            )

        # ── What was asked, and what was not ──
        #
        # On the evidence rather than only in the log, because the log is not
        # what the decision engine reads. This is the field that makes an
        # empty `blocklist_hits` mean something: four sources agreeing is a
        # clean result, four sources refusing is not, and until now the
        # payload said exactly the same thing in both cases.
        evidence.sources_checked = list(self.sources_checked)
        evidence.sources_skipped = dict(self.sources_skipped)

        # ── Store artifact ──
        self._store_artifact("raw_intel", json.dumps({
            "certs_count": len(evidence.related_certs),
            "subdomains_count": len(evidence.related_subdomains),
            "blocklist_hits": len(evidence.blocklist_hits),
            "sources_checked": list(evidence.sources_checked),
            "sources_skipped": sorted(evidence.sources_skipped),
            "spamhaus_sia_status": evidence.spamhaus_sia.get("status") if evidence.spamhaus_sia else None,
            "subdomains_sample": evidence.related_subdomains[:20],
        }, default=str))

        return evidence

    def _query_crtsh(self, target: str, *, timeout: int) -> tuple[list[str], list[str], list[dict]]:
        """
        Query crt.sh Certificate Transparency logs.
        Returns (cert_identities, unique_subdomains, raw_entries).
        """
        resp = requests.get(
            "https://crt.sh/",
            params={"q": f"%.{target}", "output": "json"},
            timeout=timeout,
            headers={"User-Agent": "ThreatInvestigator/1.0"},
        )

        if resp.status_code != 200:
            return [], [], []

        entries = resp.json()
        if not isinstance(entries, list):
            return [], [], []

        certs = []
        subdomains_set = set()
        raw_entries: list[dict] = []
        seen_serials: set[str] = set()

        for entry in entries:
            name_value = entry.get("name_value", "")
            serial = entry.get("serial_number", "")

            if serial and serial not in seen_serials:
                seen_serials.add(serial)
                certs.append(serial)
                # Store full cert detail for timeline analysis
                raw_entries.append({
                    "serial_number": serial,
                    "issuer_name": entry.get("issuer_name", ""),
                    "common_name": entry.get("common_name", name_value.split("\n")[0].strip()),
                    "not_before": entry.get("not_before", ""),
                    "not_after": entry.get("not_after", ""),
                    "entry_timestamp": entry.get("entry_timestamp", ""),
                    "name_value": name_value,
                })

            # Extract subdomains from SAN name_value
            for name in name_value.split("\n"):
                name = name.strip().lower()
                if name and (name.endswith(f".{target}") or name == target):
                    subdomains_set.add(name)

        subdomains = sorted(subdomains_set)
        return certs, subdomains, raw_entries

    def _check_dns_blocklists(self, target: str) -> list[IntelHit]:
        """
        Check domain against DNS-based blocklists.
        A positive reputation result means the domain is listed. Some providers,
        including Spamhaus, also return DNS A records for query errors; those
        must not be treated as blocklist hits.
        """
        hits = []

        for dnsbl_zone, source_name in DNSBL_LISTS:
            query = f"{target}.{dnsbl_zone}"
            try:
                answers = socket.getaddrinfo(query, None, socket.AF_INET)
                result_ips = sorted({answer[4][0] for answer in answers if answer and answer[4]})
                reputational_ips: list[str] = []
                refusals: list[str] = []
                for result_ip in result_ips:
                    error_reason = self._dnsbl_error_reason(source_name, result_ip)
                    if error_reason:
                        refusals.append(f"{error_reason} (response: {result_ip})")
                        note = f"{source_name} lookup skipped: {error_reason} (response: {result_ip})"
                        self._dnsbl_notes.append(note)
                        logger.info("%s for %s", note, target)
                    else:
                        reputational_ips.append(result_ip)

                if refusals and not reputational_ips:
                    # The zone replied, and what it said was "I am not
                    # answering you". That is an absence, not a negative, and
                    # it is every reply this deployment has had since March.
                    self._unanswered(
                        source_name, CHECK_FAILED,
                        f"{source_name} refused the query: {'; '.join(refusals)}. "
                        "Its answer carries no information about this domain, "
                        "so an empty hit list here is not a clean result.",
                        raw=", ".join(result_ips),
                    )
                    continue

                self._answered(source_name)
                if reputational_ips:
                    result_detail = ", ".join(reputational_ips)
                    hits.append(IntelHit(
                        source=source_name,
                        indicator=target,
                        category="blocklist",
                        severity="high",
                        details=f"Listed in {source_name} (response: {result_detail})",
                    ))
            except socket.gaierror as e:
                if e.errno in _NOT_LISTED_ERRNOS:
                    # NXDOMAIN: the name is not in the zone. A real negative,
                    # and the only gaierror that is one.
                    self._answered(source_name)
                else:
                    self._unanswered(
                        source_name, CHECK_FAILED,
                        f"The {source_name} query did not complete: "
                        f"{e.strerror or e}. A failed resolution is not an "
                        "absent listing.",
                        raw=f"gaierror errno={e.errno}",
                    )
            except Exception as e:
                logger.debug(f"DNSBL {source_name} check error: {e}")
                self._unanswered(
                    source_name, CHECK_FAILED,
                    f"The {source_name} query raised {type(e).__name__}: {e}",
                )

        return hits

    @staticmethod
    def _dnsbl_error_reason(source_name: str, result_ip: str) -> str | None:
        """Why this response is a refusal rather than a listing, or None.

        Per zone, because the codes are per zone and a shared rule would be
        wrong in both directions: `127.0.0.254` is a refusal for SURBL and
        `127.255.255.254` is one for Spamhaus, and neither zone uses the
        other's. Only the Spamhaus half existed, which is why SURBL's refusal
        would have become a hit on every domain.
        """
        if source_name == "Spamhaus DBL":
            if result_ip in SPAMHAUS_DNSBL_ERROR_CODES:
                return SPAMHAUS_DNSBL_ERROR_CODES[result_ip]
            if result_ip.startswith("127.255.255."):
                return "Spamhaus DNSBL query error"
        if source_name == "SURBL":
            if result_ip in SURBL_DNSBL_ERROR_CODES:
                return SURBL_DNSBL_ERROR_CODES[result_ip]
        return None

    def _check_urlhaus(self, target: str, *, timeout: int) -> list[IntelHit]:
        """Ask abuse.ch URLhaus about this host.

        Not a free API any more, and that is why this has never produced a
        stored hit in 400 days. Measured 2026-10-13 from the api container:

            POST /v1/host/ with no Auth-Key   -> HTTP 401
            POST /v1/host/ with the Auth-Key  -> HTTP 200, query_status present

        and the old body was `if resp.status_code != 200: return []`, which
        turned every 401 into "this host is in no blocklist". Third abuse.ch
        caller with the same defect, after `ip_lookup_service` and
        `threat_feeds_collector`.

        What a host-level answer does and does not say
        ---------------------------------------------
        This endpoint is asked about a host and replies with the URLs under
        it. Asked about `github.com` on 2026-10-13 it reported 9,654, and
        `raw.githubusercontent.com` 22,665 — other people's payloads on a
        shared platform. So the aggregate is recorded as context under
        `HOST_AGGREGATE` and is deliberately **not** decision-grade; only a
        URL entry whose path matches the observable is. The re-query of all
        259 hosts that received a benign verdict while this collector was
        dead found four listed, all of them shared platforms, and not one
        with a listing for the path this platform had investigated.
        """
        key = (getattr(get_settings(), "abusech_auth_key", "") or "").strip()
        if not key:
            # No request at all. An unauthenticated call can only return 401,
            # and a 401 is what this defect was made of.
            raise RuntimeError(
                "No abuse.ch Auth-Key configured (ABUSECH_AUTH_KEY), so "
                "URLhaus was not asked. It answers 401 without one."
            )

        resp = requests.post(
            "https://urlhaus-api.abuse.ch/v1/host/",
            data={"host": target},
            timeout=timeout,
            headers={"Auth-Key": key},
        )

        if resp.status_code != 200:
            # Raised, not swallowed: `_collect` records it as an absence
            # against this source. Never the key itself in the message.
            raise RuntimeError(f"URLhaus returned HTTP {resp.status_code}")

        data = resp.json()
        status = str(data.get("query_status") or "").strip().lower()

        if status == "no_results":
            # A real negative: asked, and URLhaus holds nothing for this host.
            self._answered(URLHAUS)
            return []

        if not data.get("urlhaus_reference"):
            # abuse.ch does not document this vocabulary, so the set of values
            # can grow without notice. An unrecognised one is neither a result
            # nor a known failure, and the point of the kind is to refuse to
            # pick between them.
            self._unanswered(
                URLHAUS, UNRECOGNISED,
                f"URLhaus replied with a query_status this code does not "
                f"recognise ({status or 'missing'}), so whether this host is "
                "listed is unknown.",
                raw=status or None,
            )
            return []

        self._answered(URLHAUS)
        hits = []

        # The host-level aggregate. Context, by category: see the docstring.
        url_count = data.get("url_count", 0)
        if url_count and int(url_count) > 0:
            hits.append(IntelHit(
                source=URLHAUS,
                indicator=target,
                category=HOST_AGGREGATE,
                severity="high",
                details=(
                    f"URLhaus holds {url_count} malicious URL(s) under {target}. "
                    "A count against a host is not a statement about the host — "
                    "on a shared platform it is other tenants' payloads — so "
                    "this is recorded as context and does not decide anything."
                ),
                last_seen=self._parse_urlhaus_date(
                    data.get("urls", [{}])[0].get("date_added") if data.get("urls") else None
                ),
            ))

        # Individual URL entries (cap at 10). These carry the path, which is
        # what makes them scopable to the observable.
        for url_entry in (data.get("urls") or [])[:10]:
            threat = url_entry.get("threat", "unknown")
            url = url_entry.get("url", "")
            status_text = url_entry.get("url_status", "")
            hits.append(IntelHit(
                source=URLHAUS,
                indicator=url,
                category=threat,
                severity="high" if status_text == "online" else "medium",
                details=f"Threat: {threat}, Status: {status_text}",
                last_seen=self._parse_urlhaus_date(url_entry.get("date_added")),
            ))

        return hits

    def _query_spamhaus_sia_domain(
        self,
        target: str,
        *,
        token: str,
        base_url: str,
        timeout: int,
    ) -> dict:
        """
        Query Spamhaus Intelligence API domain endpoints.
        """
        base = base_url.rstrip("/")
        domain = quote(target.strip().lower(), safe="")
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "User-Agent": "ThreatInvestigator/1.0",
        }
        endpoint_paths = {
            "general": f"/api/intel/v2/byobject/domain/{domain}",
            "listing": f"/api/intel/v2/byobject/domain/{domain}/listing",
            "dimensions": f"/api/intel/v2/byobject/domain/{domain}/dimensions",
            "contexts": f"/api/intel/v2/byobject/domain/{domain}/contexts",
            "senders": f"/api/intel/v2/byobject/domain/{domain}/senders",
            "nameservers": f"/api/intel/v2/byobject/domain/{domain}/ns",
            "a_records": f"/api/intel/v2/byobject/domain/{domain}/a",
            "hostnames": f"/api/intel/v2/byobject/domain/{domain}/hostnames",
            "malware_hashes": f"/api/intel/v2/byobject/domain/{domain}/malware/hashes",
            "malware_urls": f"/api/intel/v2/byobject/domain/{domain}/malware/urls",
        }
        result: dict = {
            "status": "checked",
            "source": "Spamhaus Intelligence API",
            "domain": target,
            "errors": {},
        }

        for key, path in endpoint_paths.items():
            try:
                response = requests.get(f"{base}{path}", headers=headers, timeout=timeout)
            except requests.RequestException as exc:
                result["errors"][key] = str(exc)
                continue

            if response.status_code == 404:
                result[key] = None if key in {"general", "listing", "dimensions"} else []
                continue
            if response.status_code == 401:
                result["status"] = "unauthorized"
                result["errors"][key] = "token expired or unauthorized"
                break
            if response.status_code == 403:
                result["errors"][key] = "forbidden for token tier"
                continue
            if response.status_code == 429:
                result["status"] = "rate_limited"
                result["errors"][key] = "rate limited"
                break
            if response.status_code != 200:
                result["errors"][key] = f"HTTP {response.status_code}"
                continue

            try:
                result[key] = response.json()
            except ValueError:
                result["errors"][key] = "invalid JSON response"

        if not result["errors"]:
            result.pop("errors", None)
        return result

    def _get_spamhaus_sia_token(self, settings, *, force_refresh: bool = False) -> str:
        now = int(datetime.now(timezone.utc).timestamp())
        cached_token = str(_SPAMHAUS_SIA_TOKEN_CACHE.get("token") or "")
        cached_expires = int(_SPAMHAUS_SIA_TOKEN_CACHE.get("expires") or 0)
        if cached_token and cached_expires > now + 300 and not force_refresh:
            return cached_token

        configured_token = str(settings.spamhaus_sia_token or "").strip()
        configured_expires = self._jwt_exp(configured_token)
        if configured_token and configured_expires > now + 300 and not force_refresh:
            _SPAMHAUS_SIA_TOKEN_CACHE["token"] = configured_token
            _SPAMHAUS_SIA_TOKEN_CACHE["expires"] = configured_expires
            return configured_token

        if not settings.spamhaus_sia_username or not settings.spamhaus_sia_password:
            if configured_token and not force_refresh:
                return configured_token
            return ""

        return self._refresh_spamhaus_sia_token(
            username=settings.spamhaus_sia_username,
            password=settings.spamhaus_sia_password,
            base_url=settings.spamhaus_sia_base_url,
            timeout=min(self.timeout, settings.spamhaus_sia_timeout_seconds),
        )

    def _refresh_spamhaus_sia_token(
        self,
        *,
        username: str,
        password: str,
        base_url: str,
        timeout: int,
    ) -> str:
        response = requests.post(
            f"{base_url.rstrip('/')}/api/v1/login",
            json={"username": username, "password": password, "realm": "intel"},
            timeout=timeout,
            headers={"Accept": "application/json", "User-Agent": "ThreatInvestigator/1.0"},
        )
        if response.status_code != 200:
            raise RuntimeError(f"Spamhaus SIA login failed: HTTP {response.status_code}")
        data = response.json()
        token = str(data.get("token") or "")
        if not token:
            raise RuntimeError("Spamhaus SIA login response did not include a token")
        expires = int(data.get("expires") or self._jwt_exp(token) or 0)
        _SPAMHAUS_SIA_TOKEN_CACHE["token"] = token
        _SPAMHAUS_SIA_TOKEN_CACHE["expires"] = expires
        return token

    @staticmethod
    def _jwt_exp(token: str) -> int:
        if not token or token.count(".") < 2:
            return 0
        try:
            payload = token.split(".", 2)[1]
            payload += "=" * (-len(payload) % 4)
            decoded = base64.urlsafe_b64decode(payload.encode("ascii"))
            return int(json.loads(decoded).get("exp") or 0)
        except Exception:
            return 0

    @staticmethod
    def _parse_urlhaus_date(date_str: str | None) -> datetime | None:
        if not date_str:
            return None
        try:
            return datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S").replace(
                tzinfo=timezone.utc
            )
        except (ValueError, TypeError):
            return None

    def _load_cached_intel(self, target: str) -> dict | None:
        key = f"intel:{target.lower()}"
        try:
            from sqlalchemy import select
            from sqlalchemy.orm import Session
            from app.db.session import sync_engine
            from app.models.database import LookupCache

            with Session(sync_engine) as session:
                row = session.execute(
                    select(LookupCache).where(
                        LookupCache.cache_key == key,
                        LookupCache.expires_at > datetime.now(timezone.utc),
                    )
                ).scalar_one_or_none()
                if row and isinstance(row.cache_value, dict):
                    return row.cache_value
        except Exception as e:
            logger.debug("Intel cache lookup failed for %s: %s", target, e)
        return None

    def _save_cached_intel(
        self,
        target: str,
        *,
        related_certs: list[str],
        related_subdomains: list[str],
        cert_entries_raw: list[dict],
        urlhaus_hits: list[IntelHit],
        ttl_hours: int,
    ) -> None:
        key = f"intel:{target.lower()}"
        payload = {
            "related_certs": list(related_certs or [])[:50],
            "related_subdomains": list(related_subdomains or [])[:100],
            "cert_entries_raw": list(cert_entries_raw or [])[:200],
            "urlhaus_hits": [h.model_dump(mode="json") for h in (urlhaus_hits or [])[:20]],
        }
        expires_at = datetime.now(timezone.utc) + timedelta(hours=max(1, int(ttl_hours or 24)))
        try:
            from sqlalchemy import select
            from sqlalchemy.orm import Session
            from app.db.session import sync_engine
            from app.models.database import LookupCache

            with Session(sync_engine) as session:
                row = session.execute(
                    select(LookupCache).where(LookupCache.cache_key == key)
                ).scalar_one_or_none()
                if row:
                    row.cache_value = payload
                    row.expires_at = expires_at
                    row.source = "intel"
                else:
                    session.add(
                        LookupCache(
                            cache_key=key,
                            cache_value=payload,
                            source="intel",
                            expires_at=expires_at,
                        )
                    )
                session.commit()
        except Exception as e:
            logger.debug("Intel cache save failed for %s: %s", target, e)

    def _empty_evidence(self, meta: CollectorMeta) -> IntelEvidence:
        return IntelEvidence(meta=meta)


def build_cert_timeline(evidence_data: dict, domain: str) -> dict | None:
    """
    Build a certificate transparency timeline from raw crt.sh entries
    stored in the Intel collector's evidence.

    Called from analysis_task.py as a post-processing step.
    Returns a serialized CertTimelineEvidence dict, or None if no data.
    """
    intel = evidence_data.get("intel", {})
    raw_entries = intel.get("cert_entries_raw", [])
    if not raw_entries:
        return None

    SHORT_LIVED_DAYS = 30
    BURST_WINDOW_DAYS = 7
    BURST_THRESHOLD = 5

    entries: list[CertTimelineEntry] = []
    parse_errors = 0

    for raw in raw_entries:
        not_before_str = raw.get("not_before", "")
        not_after_str = raw.get("not_after", "")

        try:
            # crt.sh timestamps can be "2024-01-01T12:00:00" or "2024-01-01 12:00:00"
            not_before_dt = _parse_crtsh_dt(not_before_str)
            not_after_dt = _parse_crtsh_dt(not_after_str)

            if not_before_dt and not_after_dt:
                validity_days = (not_after_dt - not_before_dt).days
            else:
                validity_days = 0

            entries.append(CertTimelineEntry(
                serial_number=raw.get("serial_number", ""),
                issuer_name=_shorten_issuer(raw.get("issuer_name", "")),
                common_name=raw.get("common_name", domain),
                not_before=not_before_str,
                not_after=not_after_str,
                entry_timestamp=raw.get("entry_timestamp", not_before_str),
                validity_days=validity_days,
                is_short_lived=0 < validity_days < SHORT_LIVED_DAYS,
            ))
        except Exception:
            parse_errors += 1
            continue

    if not entries:
        return None

    # Sort by entry_timestamp descending (newest first)
    entries.sort(key=lambda e: e.entry_timestamp, reverse=True)

    unique_issuers = list(dict.fromkeys(e.issuer_name for e in entries if e.issuer_name))
    short_lived_count = sum(1 for e in entries if e.is_short_lived)

    # Detect burst periods: 5+ certs issued within any 7-day window
    burst_periods: list[dict] = []
    cert_burst_detected = False

    timestamps_sorted = sorted(
        [_parse_crtsh_dt(e.entry_timestamp or e.not_before) for e in entries if e.entry_timestamp or e.not_before],
        key=lambda dt: dt or datetime.min.replace(tzinfo=timezone.utc),
    )
    timestamps_sorted = [t for t in timestamps_sorted if t is not None]

    for ts in timestamps_sorted:
        window_end = ts + timedelta(days=BURST_WINDOW_DAYS)
        window_certs = [t for t in timestamps_sorted if ts <= t <= window_end]
        if len(window_certs) >= BURST_THRESHOLD:
            burst_cert_detected_already = any(
                bp["start"] == ts.isoformat() for bp in burst_periods
            )
            if not burst_cert_detected_already:
                burst_periods.append({
                    "start": ts.isoformat(),
                    "end": window_end.isoformat(),
                    "count": len(window_certs),
                })
                cert_burst_detected = True

    notes: list[str] = []
    if parse_errors:
        notes.append(f"{parse_errors} cert entries could not be parsed")
    if short_lived_count > 0:
        notes.append(f"{short_lived_count} certificate(s) had validity < {SHORT_LIVED_DAYS} days (short-lived)")
    if cert_burst_detected:
        notes.append(f"Certificate burst detected: multiple issuances within {BURST_WINDOW_DAYS}-day window(s)")

    earliest = entries[-1].not_before if entries else None
    latest = entries[0].not_before if entries else None

    return CertTimelineEvidence(
        domain=domain,
        total_certs=len(entries),
        entries=entries[:100],  # Cap at 100 for storage
        unique_issuers=unique_issuers,
        cert_burst_detected=cert_burst_detected,
        burst_periods=burst_periods[:10],
        short_lived_count=short_lived_count,
        earliest_cert=earliest,
        latest_cert=latest,
        notes=notes,
    ).model_dump()


def _parse_crtsh_dt(dt_str: str | None) -> datetime | None:
    """Parse crt.sh datetime strings in multiple formats."""
    if not dt_str:
        return None
    formats = [
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%d",
    ]
    for fmt in formats:
        try:
            return datetime.strptime(dt_str[:19], fmt[:len(fmt)]).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _shorten_issuer(issuer_dn: str) -> str:
    """Extract CN or O from issuer Distinguished Name for display."""
    if not issuer_dn:
        return ""
    # Try to extract CN=... first, then O=...
    for prefix in ("CN=", "O="):
        idx = issuer_dn.find(prefix)
        if idx != -1:
            value = issuer_dn[idx + len(prefix):]
            end = value.find(",")
            return value[:end].strip() if end != -1 else value.strip()
    return issuer_dn[:60]
