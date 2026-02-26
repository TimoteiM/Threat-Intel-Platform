"""
DNS Collector — resolves A/AAAA/CNAME/MX/NS/TXT + DMARC/SPF.

Facts only. No interpretation.
"""

from __future__ import annotations

import json
import logging

import dns.resolver

from app.collectors.base import BaseCollector
from app.models.schemas import CollectorMeta, DNSEvidence, DNSRecord

logger = logging.getLogger(__name__)


class DNSCollector(BaseCollector):
    name = "dns"
    supported_types = frozenset({"domain", "url"})

    def _collect(self) -> DNSEvidence:
        evidence = DNSEvidence()
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
        resolver.timeout = self.timeout
        resolver.lifetime = self.timeout

        # For URL type, resolve the extracted hostname rather than the full URL
        target = self.target_domain

        # ── Standard record types ──
        record_map = {
            "A": "a",
            "AAAA": "aaaa",
            "CNAME": "cname",
            "MX": "mx",
            "NS": "ns",
            "TXT": "txt",
        }

        all_records: list[DNSRecord] = []

        for rtype, field_name in record_map.items():
            try:
                answers = resolver.resolve(target, rtype)
                values = []
                for rdata in answers:
                    val = str(rdata).strip('"')
                    values.append(val)
                    all_records.append(DNSRecord(
                        type=rtype,
                        name=target,
                        value=val,
                        ttl=answers.rrset.ttl if answers.rrset else None,
                    ))
                setattr(evidence, field_name, values)
            except (
                dns.resolver.NoAnswer,
                dns.resolver.NXDOMAIN,
                dns.resolver.NoNameservers,
            ):
                pass
            except Exception as e:
                logger.debug(f"DNS {rtype} lookup failed for {target}: {e}")

        # ── DMARC (TXT record at _dmarc.{domain}) ──
        try:
            dmarc_answers = resolver.resolve(f"_dmarc.{target}", "TXT")
            for rdata in dmarc_answers:
                val = str(rdata).strip('"')
                if val.lower().startswith("v=dmarc"):
                    evidence.dmarc = val
                    all_records.append(DNSRecord(
                        type="TXT",
                        name=f"_dmarc.{target}",
                        value=val,
                    ))
                    break
        except Exception:
            pass

        # ── Extract SPF from TXT records ──
        for txt in evidence.txt:
            if txt.lower().startswith("v=spf1"):
                evidence.spf = txt
                break

        evidence.records = all_records

        # ── Store raw artifact ──
        self._store_artifact(
            "raw_records",
            json.dumps([r.model_dump() for r in all_records], default=str),
        )

        return evidence

    def _empty_evidence(self, meta: CollectorMeta) -> DNSEvidence:
        return DNSEvidence(meta=meta)
