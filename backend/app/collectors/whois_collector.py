"""
WHOIS Collector — queries registration data via python-whois.

Captures: registrar, creation/expiry dates, domain age,
privacy protection status, registrant details, name servers.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

import whois as python_whois

from app.collectors.base import BaseCollector
from app.models.schemas import CollectorMeta, WHOISEvidence
from app.utils.domain_utils import extract_registered_domain

logger = logging.getLogger(__name__)

PRIVACY_INDICATORS = [
    "privacy", "proxy", "redacted", "whoisguard",
    "domains by proxy", "contact privacy", "withheld",
    "data protected", "not disclosed",
]


class WHOISCollector(BaseCollector):
    supported_types = frozenset({"domain"})
    name = "whois"

    def _collect(self) -> WHOISEvidence:
        evidence = WHOISEvidence()

        # WHOIS only works at the registered domain level (eTLD+1),
        # not on subdomains. e.g. revantage.drojifri.solutions → drojifri.solutions
        query_domain = extract_registered_domain(self.domain)
        if query_domain != self.domain:
            logger.info(f"WHOIS: querying registered domain '{query_domain}' (input was '{self.domain}')")

        w = python_whois.whois(query_domain)

        # ── Registrar ──
        evidence.registrar = w.registrar

        # ── Name servers ──
        if w.name_servers:
            evidence.name_servers = [
                str(ns).lower() for ns in
                (w.name_servers if isinstance(w.name_servers, list) else [w.name_servers])
            ]

        # ── Statuses ──
        if w.status:
            evidence.statuses = (
                w.status if isinstance(w.status, list) else [w.status]
            )

        # ── Dates ──
        evidence.created_date = self._parse_date(w.creation_date)
        evidence.updated_date = self._parse_date(w.updated_date)
        evidence.expiry_date = self._parse_date(w.expiration_date)

        # Domain age
        if evidence.created_date:
            created_utc = evidence.created_date.replace(tzinfo=timezone.utc) \
                if evidence.created_date.tzinfo is None else evidence.created_date
            evidence.domain_age_days = (datetime.now(timezone.utc) - created_utc).days

        # ── Registrant info ──
        evidence.registrant_org = getattr(w, "org", None)
        evidence.registrant_country = getattr(w, "country", None)

        # ── Privacy detection ──
        raw_text = str(w).lower()
        evidence.privacy_protected = any(
            indicator in raw_text for indicator in PRIVACY_INDICATORS
        )

        # ── Store raw artifact ──
        self._store_artifact("raw_whois", str(w))

        return evidence

    def _empty_evidence(self, meta: CollectorMeta) -> WHOISEvidence:
        return WHOISEvidence(meta=meta)

    @staticmethod
    def _parse_date(date_val) -> datetime | None:
        """Handle whois returning a single date or a list of dates."""
        if date_val is None:
            return None
        if isinstance(date_val, list):
            date_val = date_val[0]
        if isinstance(date_val, datetime):
            return date_val
        return None
