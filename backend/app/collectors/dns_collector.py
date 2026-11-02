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


class DNSLookupError(Exception):
    """Every DNS lookup errored — no answer was obtained at all."""


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
        failures: list[tuple[str, Exception]] = []
        total_lookups = len(record_map) + 1  # + DMARC

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
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                # Genuine answers: the name does not exist, or it has no
                # record of this type. Both are facts about the domain.
                pass
            except Exception as e:
                # Includes NoNameservers, which dnspython raises when EVERY
                # nameserver errored — socket errors during a local outage
                # included. That is a statement about our reachability, not
                # about the domain, so it is a failure and not "no records".
                logger.warning(f"DNS {rtype} lookup failed for {target}: {e}")
                failures.append((rtype, e))

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
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass
        except Exception as e:
            logger.warning(f"DNS DMARC lookup failed for {target}: {e}")
            failures.append(("DMARC", e))

        # ── Every lookup failed: that is a failed run, not "no records" ──
        #
        # The defect this closes: each lookup caught its own exception, logged
        # at debug and moved on, so a DNS outage returned a COMPLETED run with
        # empty evidence — "this domain has no DNS records at all", which is
        # the strongest possible statement, made from having learned nothing.
        if len(failures) == total_lookups:
            raise DNSLookupError(
                f"all {total_lookups} DNS lookups failed for {target}: "
                f"{self._summarize_failures(failures)}"
            )

        # A PARTIAL failure still completes, because the lookups that answered
        # did answer — but each one that could not be checked is named, so an
        # empty `mx` is distinguishable from an mx nobody could ask about.
        for label, e in failures:
            evidence.notes.append(
                f"DNS {label} lookup failed: {type(e).__name__}: {e}"
            )

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

    @staticmethod
    def _summarize_failures(failures: list[tuple[str, Exception]]) -> str:
        """`NoNameservers on A, AAAA, MX (e.g. "All nameservers failed...")`.

        Grouped by exception TYPE rather than by message. Grouping on the
        message was the obvious implementation and it never fires in the real
        case: dnspython embeds the query name in the text, so a total outage
        produces seven "identical" errors that differ — `… example.com. IN A`
        against `… IN AAAA` — and the summary ran to ~630 characters, which is
        what `meta.error` stores and what an analyst is shown.

        Per-lookup detail is not lost; each failure is already logged at
        WARNING as it happens.
        """
        grouped: dict[str, list[str]] = {}
        examples: dict[str, str] = {}
        for label, e in failures:
            kind = type(e).__name__
            grouped.setdefault(kind, []).append(label)
            examples.setdefault(kind, str(e).strip())
        parts = []
        for kind, labels in grouped.items():
            part = f"{kind} on {', '.join(labels)}"
            if examples.get(kind):
                part += f' (e.g. "{examples[kind][:120]}")'
            parts.append(part)
        return "; ".join(parts)
