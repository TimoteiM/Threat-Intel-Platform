"""
VirusTotal Collector — queries VT API v3 for multi-observable reputation.

Supports: domain, IP, URL, file hash, file sample.

Extracts:
- Vendor detections (malicious/suspicious/clean/undetected counts)
- Individual vendor results (who flagged it and as what)
- Last analysis stats
- Domain categories (from multiple categorization services)
- Popularity ranks (Alexa, Cisco Umbrella, etc.)
- DNS records (from VT's passive DNS)
- WHOIS info (from VT's perspective)
- Community reputation score

Requires: VIRUSTOTAL_API_KEY in .env
Free tier: 4 requests/min, 500/day — we use 1 per investigation.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import threading
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

from app.collectors.base import BaseCollector
from app.config import get_settings
from app.models.schemas import (
    CollectorMeta,
    VTBehaviourSummary,
    VTCrowdsourcedRule,
    VTEvidence,
    VTFileDetails,
    VTFileSignature,
    VTSandboxVerdict,
    VTVendorResult,
)
from app.services.provider_usage_metrics import record_provider_request

logger = logging.getLogger(__name__)
_VT_KEY_LOCK = threading.Lock()
_VT_KEY_LIMITED_UNTIL: dict[str, float] = {}
_VT_NEXT_INDEX = 0
_VT_KEY_COOLDOWN_SECONDS = 75.0

# A freshly submitted URL is rarely analysed within a collector's lifetime, and
# every poll costs a request from a 4/min budget. Poll twice, then hand the
# analysis id back for a later run — the host reputation already gave a verdict.
VT_URL_ANALYSIS_POLLS = 2
VT_URL_ANALYSIS_POLL_SECONDS = 5

# One retry rides out a transient DNS/connection blip without masking an outage.
VT_CONNECTION_ATTEMPTS = 2
VT_CONNECTION_RETRY_SECONDS = 2


class VTCollector(BaseCollector):
    name = "vt"
    supported_types = frozenset({"domain", "ip", "url", "hash", "file"})

    def _collect(self) -> VTEvidence:
        settings = get_settings()
        keys = _get_vt_keys(settings.virustotal_api_key)
        if not keys:
            raise ValueError("VIRUSTOTAL_API_KEY(S) not configured")

        last_rate_limit_error = None
        for api_key in _ordered_vt_keys(keys):
            try:
                return self._collect_for_key(api_key)
            except ValueError as exc:
                if _is_rate_limit_error(str(exc)):
                    _mark_vt_key_rate_limited(api_key)
                    last_rate_limit_error = exc
                    continue
                raise

        if last_rate_limit_error is not None:
            raise ValueError(
                "VirusTotal API rate limit exceeded on all configured keys."
            ) from last_rate_limit_error
        raise ValueError("VirusTotal request failed for all configured keys.")

    def _collect_for_key(self, api_key: str) -> VTEvidence:
        """
        Run the lookup for one API key, retrying once on a connection error.

        A DNS hiccup or a dropped TCP connection — the kind a container sees when
        the Docker network is reconfigured under it — used to fail the whole VT
        collector for that investigation and leave the report with no reputation
        at all. One short retry costs nothing and rides out the blip; a genuine
        outage still surfaces as a failure.
        """
        for attempt in range(VT_CONNECTION_ATTEMPTS):
            try:
                if self.observable_type == "ip":
                    return self._collect_ip(api_key)
                if self.observable_type == "url":
                    return self._collect_url(api_key)
                if self.observable_type in ("hash", "file"):
                    return self._collect_hash(api_key)
                return self._collect_domain(api_key)
            except (requests.ConnectionError, requests.Timeout) as exc:
                if attempt + 1 >= VT_CONNECTION_ATTEMPTS:
                    raise
                logger.warning(
                    "VirusTotal connection problem (%s) — retrying in %ss",
                    type(exc).__name__,
                    VT_CONNECTION_RETRY_SECONDS,
                )
                time.sleep(VT_CONNECTION_RETRY_SECONDS)
        raise ValueError("VirusTotal request failed")  # unreachable, keeps type checkers happy

    # ── Domain ────────────────────────────────────────────────────────────────

    def _collect_domain(self, api_key: str) -> VTEvidence:
        """Query VT API v3 for domain report."""
        evidence = VTEvidence()

        record_provider_request("virustotal")
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/domains/{self.domain}",
            headers={"x-apikey": api_key},
            timeout=self.timeout,
        )

        if resp.status_code == 404:
            evidence.found = False
            evidence.notes.append("Domain not found in VirusTotal database")
            return evidence

        if resp.status_code == 429:
            raise ValueError("VirusTotal API rate limit exceeded (4 req/min free tier)")

        if resp.status_code != 200:
            raise ValueError(f"VT API returned {resp.status_code}: {resp.text[:200]}")

        data = resp.json()
        self._store_artifact("raw_vt", json.dumps(data, default=str))
        return self._parse_attributes(evidence, data)

    # ── IP ────────────────────────────────────────────────────────────────────

    def _collect_ip(self, api_key: str) -> VTEvidence:
        """Query VT API v3 for IP address report."""
        evidence = VTEvidence()

        record_provider_request("virustotal")
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{self.domain}",
            headers={"x-apikey": api_key},
            timeout=self.timeout,
        )

        if resp.status_code == 404:
            evidence.found = False
            evidence.notes.append("IP not found in VirusTotal database")
            return evidence

        if resp.status_code == 429:
            raise ValueError("VirusTotal API rate limit exceeded")

        if resp.status_code != 200:
            raise ValueError(f"VT API returned {resp.status_code}: {resp.text[:200]}")

        data = resp.json()
        self._store_artifact("raw_vt", json.dumps(data, default=str))
        return self._parse_attributes(evidence, data)

    # ── URL ───────────────────────────────────────────────────────────────────

    def _collect_url(self, api_key: str) -> VTEvidence:
        """
        Reputation for a URL observable.

        VT only holds a report for a URL somebody already submitted, so an unknown
        URL used to leave us with nothing — while the URL's host often sits in VT
        with dozens of detections. Order of preference:

            1. VT's report for the exact URL
            2. the host's domain report, clearly attributed (scope="domain")
            3. a fresh scan we submit; if it has not finished by the time our
               budget runs out we keep the analysis id so a later run can collect
               it instead of paying for the submission twice

        A known-but-clean URL still gets the domain checked: "the page is clean
        but its domain is flagged 21/91" is exactly the case this collector used
        to hide.
        """
        evidence = VTEvidence()
        headers = {"x-apikey": api_key}
        url_id = base64.urlsafe_b64encode(self.domain.encode()).decode().rstrip("=")

        record_provider_request("virustotal")
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers,
            timeout=self.timeout,
        )

        if resp.status_code == 429:
            raise ValueError("VirusTotal API rate limit exceeded")

        if resp.status_code == 200:
            data = resp.json()
            self._store_artifact("raw_vt", json.dumps(data, default=str))
            evidence = self._parse_attributes(evidence, data)
            evidence.scope = "url"
            evidence.scope_value = self.domain
            if evidence.malicious_count == 0 and evidence.suspicious_count == 0:
                self._attach_host_reputation(evidence, api_key, replace_stats=False)
            return evidence

        if resp.status_code != 404:
            raise ValueError(f"VT API returned {resp.status_code}: {resp.text[:200]}")

        # ── VT has never seen this URL ──
        evidence.notes.append("VirusTotal has no report for this exact URL")
        self._attach_host_reputation(evidence, api_key, replace_stats=True)
        self._submit_url_for_analysis(evidence, api_key, headers)
        return evidence

    def _attach_host_reputation(
        self,
        evidence: VTEvidence,
        api_key: str,
        *,
        replace_stats: bool,
    ) -> None:
        """
        Pull the URL host's domain report.

        `replace_stats=True` promotes the domain's detections into the evidence's
        own counters — the URL itself is unknown to VT, so the host reputation is
        the only reputation there is, and the verdict must be built from it.
        Otherwise the domain result is recorded as context next to a clean URL.
        """
        host = _url_host(self.domain)
        if not host:
            return

        try:
            record_provider_request("virustotal")
            resp = requests.get(
                f"https://www.virustotal.com/api/v3/domains/{host}",
                headers={"x-apikey": api_key},
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            evidence.notes.append(f"Domain reputation lookup for {host} failed: {exc}")
            return

        if resp.status_code == 404:
            evidence.notes.append(f"VirusTotal has no report for the host {host} either")
            return
        if resp.status_code == 429:
            raise ValueError("VirusTotal API rate limit exceeded")
        if resp.status_code != 200:
            evidence.notes.append(f"Domain reputation lookup for {host} returned {resp.status_code}")
            return

        data = resp.json()
        stats = (data.get("data", {}).get("attributes", {}) or {}).get("last_analysis_stats", {}) or {}
        malicious = int(stats.get("malicious") or 0)
        suspicious = int(stats.get("suspicious") or 0)

        if replace_stats:
            self._store_artifact("raw_vt", json.dumps(data, default=str))
            notes = list(evidence.notes)
            parsed = self._parse_attributes(evidence, data)
            parsed.notes = notes
            parsed.scope = "domain"
            parsed.scope_value = host
            parsed.notes.append(
                f"Reputation shown is for the host {host}, not the exact URL "
                f"({malicious} malicious / {suspicious} suspicious)"
            )
            evidence.__dict__.update(parsed.__dict__)
            return

        if malicious or suspicious:
            evidence.notes.append(
                f"VirusTotal flags the host {host}: {malicious} malicious, "
                f"{suspicious} suspicious — the URL itself has no detections"
            )
            evidence.tags = list(dict.fromkeys([*evidence.tags, "host-flagged"]))

    def _submit_url_for_analysis(self, evidence: VTEvidence, api_key: str, headers: dict) -> None:
        """
        Ask VT to scan a URL it does not know, and wait only briefly.

        A fresh URL analysis regularly finishes minutes after submission — longer
        than any collector should block. We keep the analysis id so the result can
        be collected later, rather than discarding a scan we already paid for.
        """
        try:
            record_provider_request("virustotal")
            submit_resp = requests.post(
                "https://www.virustotal.com/api/v3/urls",
                headers={**headers, "Content-Type": "application/x-www-form-urlencoded"},
                data=f"url={self.domain}",
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            evidence.notes.append(f"VT URL submission failed: {exc}")
            return

        if submit_resp.status_code == 429:
            # Not fatal: the host reputation above already carries the verdict.
            evidence.notes.append("VT URL submission skipped — rate limit reached")
            return
        if submit_resp.status_code not in (200, 201):
            evidence.notes.append(f"VT URL submission failed: HTTP {submit_resp.status_code}")
            return

        analysis_id = submit_resp.json().get("data", {}).get("id", "")
        if not analysis_id:
            evidence.notes.append("URL submitted to VT but no analysis ID returned")
            return

        for _ in range(VT_URL_ANALYSIS_POLLS):
            time.sleep(VT_URL_ANALYSIS_POLL_SECONDS)
            record_provider_request("virustotal")
            poll_resp = requests.get(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                headers=headers,
                timeout=self.timeout,
            )
            if poll_resp.status_code != 200:
                continue
            poll_data = poll_resp.json()
            if (poll_data.get("data", {}).get("attributes", {}) or {}).get("status") != "completed":
                continue
            self._store_artifact("raw_vt", json.dumps(poll_data, default=str))
            notes = list(evidence.notes)
            parsed = self._parse_attributes(VTEvidence(), poll_data)
            parsed.notes = [*notes, "Reputation from the fresh VirusTotal scan of this URL"]
            parsed.scope = "url"
            parsed.scope_value = self.domain
            evidence.__dict__.update(parsed.__dict__)
            return

        evidence.pending_analysis_id = analysis_id
        evidence.notes.append(
            f"VirusTotal is still scanning this URL (analysis {analysis_id}) — "
            "re-run the VT collector shortly to collect the result"
        )

    # ── Hash ──────────────────────────────────────────────────────────────────

    def _collect_hash(self, api_key: str) -> VTEvidence:
        """Query VT API v3 for file hash report."""
        import re
        evidence = VTEvidence()

        # Clean hash value: strip known prefixes, then extract from compound identifiers
        # e.g. "sha256.exe.zip::shortid" → extract the 64-char SHA256 embedded in the filename
        hash_value = self.domain
        for prefix in ("md5:", "sha1:", "sha256:", "sha512:"):
            if hash_value.lower().startswith(prefix):
                hash_value = hash_value[len(prefix):]
                break

        # If still not a clean hash, try extracting SHA256 (64 hex) or MD5 (32 hex)
        if not re.fullmatch(r"[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", hash_value):
            sha256_match = re.search(r"\b([0-9a-fA-F]{64})\b", hash_value)
            md5_match = re.search(r"\b([0-9a-fA-F]{32})\b", hash_value)
            if sha256_match:
                hash_value = sha256_match.group(1)
            elif md5_match:
                hash_value = md5_match.group(1)
            else:
                evidence.found = False
                evidence.notes.append(f"Could not extract a valid hash from: {self.domain[:80]}")
                return evidence

        record_provider_request("virustotal")
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/files/{hash_value}",
            headers={"x-apikey": api_key},
            timeout=self.timeout,
        )

        if resp.status_code == 404:
            evidence.found = False
            evidence.notes.append("Hash not found in VirusTotal database")
            return evidence

        if resp.status_code == 429:
            raise ValueError("VirusTotal API rate limit exceeded")

        if resp.status_code != 200:
            raise ValueError(f"VT API returned {resp.status_code}: {resp.text[:200]}")

        data = resp.json()
        self._store_artifact("raw_vt", json.dumps(data, default=str))
        evidence = self._parse_attributes(evidence, data)

        # Extract file-specific metadata
        attrs = data.get("data", {}).get("attributes", {})
        evidence.vt_registrar = attrs.get("type_description", "")  # reuse field for file type
        # File names: meaningful_name is the most common/recognisable name;
        # names contains every name the file has been submitted under.
        evidence.file_name = attrs.get("meaningful_name") or None
        raw_names = attrs.get("names", [])
        if isinstance(raw_names, list):
            evidence.file_names = [n for n in raw_names if n][:20]
        if attrs.get("sha256"):
            evidence.notes.append(f"SHA256: {attrs['sha256']}")
        if attrs.get("md5"):
            evidence.notes.append(f"MD5: {attrs['md5']}")
        if attrs.get("size"):
            evidence.notes.append(f"Size: {attrs['size']} bytes")

        evidence.file_details = _parse_file_details(attrs)
        if get_settings().vt_fetch_file_behaviour:
            evidence.behaviour = self._collect_behaviour(
                api_key, evidence.file_details.sha256 or hash_value
            )

        return evidence

    def _collect_behaviour(self, api_key: str, file_id: str) -> VTBehaviourSummary:
        """
        Fetch VT's aggregated sandbox behaviour for a file.

        One extra request per hash — failures are recorded on the summary rather
        than failing the whole collector, since detections matter more than
        behaviour and the endpoint is not available on every plan.
        """
        summary = VTBehaviourSummary(checked=True)
        try:
            record_provider_request("virustotal")
            resp = requests.get(
                f"https://www.virustotal.com/api/v3/files/{file_id}/behaviour_summary",
                headers={"x-apikey": api_key},
                timeout=self.timeout,
            )
            if resp.status_code == 404:
                summary.error = "No sandbox behaviour reports available"
                return summary
            if resp.status_code == 429:
                summary.error = "Rate limited before behaviour could be fetched"
                return summary
            if resp.status_code != 200:
                summary.error = f"VT behaviour endpoint returned {resp.status_code}"
                return summary
            payload = resp.json()
            self._store_artifact("raw_vt_behaviour", json.dumps(payload, default=str))
            return _parse_behaviour_summary(payload.get("data") or {}, summary)
        except Exception as exc:
            summary.error = f"{type(exc).__name__}: {exc}"
            return summary

    # ── Shared parser ─────────────────────────────────────────────────────────

    def _parse_attributes(self, evidence: VTEvidence, data: dict) -> VTEvidence:
        """Parse common VT response attributes into evidence object."""
        attrs = data.get("data", {}).get("attributes", {})
        evidence.found = True

        # Analysis stats. A domain/URL/IP report carries `last_analysis_*`; the
        # /analyses/{id} object returned for a freshly submitted URL carries
        # `stats`/`results` instead — parse either, or a completed fresh scan
        # reads back as zero detections.
        stats = attrs.get("last_analysis_stats") or attrs.get("stats") or {}
        evidence.malicious_count = stats.get("malicious", 0)
        evidence.suspicious_count = stats.get("suspicious", 0)
        evidence.harmless_count = stats.get("harmless", 0)
        evidence.undetected_count = stats.get("undetected", 0)
        evidence.total_vendors = sum(v for v in stats.values() if isinstance(v, int)) if stats else 0

        # Individual vendor results
        last_analysis = attrs.get("last_analysis_results") or attrs.get("results") or {}
        for vendor_name, result in last_analysis.items():
            category = result.get("category", "undetected")
            vr = VTVendorResult(
                vendor=vendor_name,
                category=category,
                result=result.get("result") or category,
                method=result.get("method", ""),
            )
            evidence.vendor_results.append(vr)
            if category == "malicious":
                evidence.flagged_malicious_by.append(vendor_name)
            elif category == "suspicious":
                evidence.flagged_suspicious_by.append(vendor_name)

        # Categories, popularity, reputation
        evidence.categories = attrs.get("categories", {})
        for service, rank_data in attrs.get("popularity_ranks", {}).items():
            if isinstance(rank_data, dict) and "rank" in rank_data:
                evidence.popularity_ranks[service] = rank_data["rank"]
        evidence.reputation_score = attrs.get("reputation", 0)

        # Dates
        for attr_key, ev_attr in [
            ("creation_date", "vt_creation_date"),
            ("last_modification_date", "vt_last_modified"),
            ("last_analysis_date", "last_analysis_date"),
        ]:
            if attrs.get(attr_key):
                setattr(evidence, ev_attr, datetime.fromtimestamp(
                    attrs[attr_key], tz=timezone.utc
                ).isoformat())

        # Domain-specific extras
        evidence.vt_dns_records = attrs.get("last_dns_records", [])
        cert_info = attrs.get("last_https_certificate", {})
        if cert_info:
            evidence.vt_cert_issuer = cert_info.get("issuer", {}).get("O", "")
            evidence.vt_cert_subject = cert_info.get("subject", {}).get("CN", "")
        if not evidence.vt_registrar:
            evidence.vt_registrar = attrs.get("registrar", "")
        evidence.tags = attrs.get("tags", [])

        return evidence

    def _empty_evidence(self, meta: CollectorMeta) -> VTEvidence:
        return VTEvidence(meta=meta)


def _get_vt_keys(primary_key: str) -> list[str]:
    """
    Build VT key pool from:
    - VIRUSTOTAL_API_KEY (existing)
    - VIRUSTOTAL_API_KEYS (comma-separated, optional)
    """
    extra = os.getenv("VIRUSTOTAL_API_KEYS", "")
    raw = [primary_key] + [k.strip() for k in extra.split(",") if k.strip()]
    keys: list[str] = []
    seen: set[str] = set()
    for key in raw:
        k = (key or "").strip()
        if not k or k in seen:
            continue
        seen.add(k)
        keys.append(k)
    return keys


def _ordered_vt_keys(keys: list[str]) -> list[str]:
    """
    Round-robin across available keys; deprioritize keys in cooldown.
    """
    global _VT_NEXT_INDEX
    if not keys:
        return []
    now = time.time()
    with _VT_KEY_LOCK:
        start = _VT_NEXT_INDEX % len(keys)
        _VT_NEXT_INDEX = (_VT_NEXT_INDEX + 1) % len(keys)
        ordered = keys[start:] + keys[:start]
        ready = [k for k in ordered if _VT_KEY_LIMITED_UNTIL.get(k, 0.0) <= now]
        limited = [k for k in ordered if k not in ready]
    return ready + limited


def _mark_vt_key_rate_limited(key: str) -> None:
    with _VT_KEY_LOCK:
        _VT_KEY_LIMITED_UNTIL[key] = time.time() + _VT_KEY_COOLDOWN_SECONDS


def _url_host(url: str) -> str:
    """The hostname of a URL observable, empty when it has none."""
    try:
        host = urlparse(str(url or "")).hostname
    except ValueError:
        return ""
    return (host or "").strip().strip(".").lower()


def _is_rate_limit_error(message: str) -> bool:
    text = (message or "").lower()
    return "rate limit" in text or "429" in text


# ── File detail parsing ──────────────────────────────────────────────────────


def _parse_file_details(attrs: dict) -> VTFileDetails:
    """Map VT file attributes onto the structured detail block analysts need."""
    details = VTFileDetails(
        sha256=attrs.get("sha256"),
        sha1=attrs.get("sha1"),
        md5=attrs.get("md5"),
        ssdeep=attrs.get("ssdeep"),
        vhash=attrs.get("vhash"),
        size_bytes=attrs.get("size"),
        file_type=attrs.get("type_description"),
        type_tag=attrs.get("type_tag"),
        type_extension=attrs.get("type_extension"),
        magic=attrs.get("magic"),
        meaningful_name=attrs.get("meaningful_name"),
        names=[n for n in (attrs.get("names") or []) if n][:20],
        times_submitted=attrs.get("times_submitted"),
        unique_sources=attrs.get("unique_sources"),
        reputation=attrs.get("reputation"),
        tags=[t for t in (attrs.get("tags") or []) if t][:30],
        capabilities_tags=[t for t in (attrs.get("capabilities_tags") or []) if t][:30],
    )

    for attr_key, field in (
        ("first_submission_date", "first_submission_date"),
        ("last_submission_date", "last_submission_date"),
        ("last_analysis_date", "last_analysis_date"),
    ):
        setattr(details, field, _vt_timestamp(attrs.get(attr_key)))

    votes = attrs.get("total_votes") or {}
    if isinstance(votes, dict):
        details.harmless_votes = votes.get("harmless")
        details.malicious_votes = votes.get("malicious")

    classification = attrs.get("popular_threat_classification") or {}
    if isinstance(classification, dict):
        details.threat_label = classification.get("suggested_threat_label")
        details.threat_categories = [
            str(row.get("value"))
            for row in (classification.get("popular_threat_category") or [])
            if isinstance(row, dict) and row.get("value")
        ][:10]
        details.threat_names = [
            str(row.get("value"))
            for row in (classification.get("popular_threat_name") or [])
            if isinstance(row, dict) and row.get("value")
        ][:10]

    signature_info = attrs.get("signature_info") or {}
    if isinstance(signature_info, dict) and signature_info:
        verified = signature_info.get("verified")
        signers = [
            part.strip()
            for part in str(signature_info.get("signers") or "").split(";")
            if part.strip()
        ]
        counter_signers = [
            part.strip()
            for part in str(signature_info.get("counter signers") or "").split(";")
            if part.strip()
        ]
        details.signature = VTFileSignature(
            verified=verified,
            # VT reports "Signed" / "Invalid signature" / "A certificate was explicitly revoked"
            signed=str(verified or "").strip().lower() == "signed" if verified else bool(signers),
            signers=signers[:10],
            counter_signers=counter_signers[:10],
            product=signature_info.get("product"),
            description=signature_info.get("description"),
            copyright=signature_info.get("copyright"),
            original_name=signature_info.get("original name"),
            internal_name=signature_info.get("internal name"),
            file_version=signature_info.get("file version"),
            signing_date=signature_info.get("signing date"),
        )

    sandbox_verdicts = attrs.get("sandbox_verdicts") or {}
    if isinstance(sandbox_verdicts, dict):
        for sandbox_name, verdict in sandbox_verdicts.items():
            if not isinstance(verdict, dict):
                continue
            details.sandbox_verdicts.append(
                VTSandboxVerdict(
                    sandbox=str(verdict.get("sandbox_name") or sandbox_name),
                    category=verdict.get("category"),
                    confidence=verdict.get("confidence"),
                    malware_names=[n for n in (verdict.get("malware_names") or []) if n][:10],
                    malware_classification=[
                        c for c in (verdict.get("malware_classification") or []) if c
                    ][:10],
                )
            )

    for rule in (attrs.get("crowdsourced_yara_results") or [])[:10]:
        if isinstance(rule, dict):
            details.crowdsourced_rules.append(
                VTCrowdsourcedRule(
                    kind="yara",
                    name=str(rule.get("rule_name") or "unnamed rule"),
                    author=rule.get("author"),
                    source=rule.get("source") or rule.get("ruleset_name"),
                    description=rule.get("description"),
                )
            )
    sigma = attrs.get("crowdsourced_sigma_results") or attrs.get("sigma_analysis_results") or []
    for rule in sigma[:10]:
        if isinstance(rule, dict):
            details.crowdsourced_rules.append(
                VTCrowdsourcedRule(
                    kind="sigma",
                    name=str(rule.get("rule_title") or rule.get("rule_name") or "unnamed rule"),
                    severity=rule.get("rule_level") or rule.get("rule_severity"),
                    author=rule.get("rule_author"),
                    source=rule.get("rule_source"),
                    description=rule.get("rule_description"),
                )
            )
    for rule in (attrs.get("crowdsourced_ids_results") or [])[:10]:
        if isinstance(rule, dict):
            details.crowdsourced_rules.append(
                VTCrowdsourcedRule(
                    kind="ids",
                    name=str(rule.get("rule_msg") or rule.get("alert_context") or "unnamed rule"),
                    severity=rule.get("alert_severity"),
                    source=rule.get("rule_source"),
                )
            )

    pe_info = attrs.get("pe_info") or {}
    if isinstance(pe_info, dict):
        details.imphash = pe_info.get("imphash")
        details.pe_sections = [
            str(section.get("name"))
            for section in (pe_info.get("sections") or [])
            if isinstance(section, dict) and section.get("name")
        ][:20]
        details.pe_imports = [
            str(library.get("library_name"))
            for library in (pe_info.get("import_list") or [])
            if isinstance(library, dict) and library.get("library_name")
        ][:20]

    if details.threat_label:
        details.notes.append(f"VT threat label: {details.threat_label}")
    if details.signature and details.signature.signed is False:
        details.notes.append("File carries a signature block that VT could not verify")
    return details


def _parse_behaviour_summary(data: dict, summary: VTBehaviourSummary) -> VTBehaviourSummary:
    """Flatten the behaviour_summary payload into capped, analyst-readable lists."""
    def take(key: str, limit: int = 25) -> list[str]:
        values = data.get(key) or []
        out: list[str] = []
        for value in values:
            if isinstance(value, str) and value.strip():
                out.append(value.strip())
            elif isinstance(value, dict):
                label = (
                    value.get("process_name")
                    or value.get("destination_ip")
                    or value.get("hostname")
                    or value.get("url")
                    or value.get("key")
                    or value.get("value")
                    or value.get("id")
                )
                if label:
                    extra = value.get("destination_port") or value.get("method")
                    out.append(f"{label}{f' ({extra})' if extra else ''}")
            if len(out) >= limit:
                break
        return out

    summary.sandboxes = sorted({str(name) for name in (data.get("has_html_report") or []) if name}) or take("sandbox_name", 10)
    summary.processes_created = take("processes_created")
    summary.command_executions = take("command_executions")
    summary.files_written = take("files_written")
    summary.files_dropped = take("files_dropped")
    summary.registry_keys_set = take("registry_keys_set")
    summary.mutexes_created = take("mutexes_created")
    summary.services_created = take("services_created")
    summary.dns_lookups = take("dns_lookups")
    summary.ip_traffic = take("ip_traffic")
    summary.http_conversations = take("http_conversations")
    summary.tags = take("tags", 20)
    summary.verdicts = take("verdicts", 20)

    techniques: list[str] = []
    for tactic in (data.get("mitre_attack_techniques") or [])[:40]:
        if isinstance(tactic, dict) and tactic.get("id"):
            label = f"{tactic['id']}"
            if tactic.get("signature_description"):
                label += f" — {str(tactic['signature_description'])[:120]}"
            techniques.append(label)
    summary.attack_techniques = techniques[:25]
    return summary


def _vt_timestamp(value) -> str | None:
    if not value:
        return None
    try:
        return datetime.fromtimestamp(int(value), tz=timezone.utc).isoformat()
    except (TypeError, ValueError, OSError):
        return None
