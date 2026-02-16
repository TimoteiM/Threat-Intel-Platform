#!/usr/bin/env python3
"""
Seed test data — creates sample investigations in the database.

Usage:
    python -m scripts.seed_test_data
    python -m scripts.seed_test_data --count 5

Requires: Postgres running + migrations applied.
"""

from __future__ import annotations

import argparse
import json
import sys
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from sqlalchemy.orm import Session
from app.db.session import sync_engine
from app.models.database import Investigation, Evidence, Report, CollectorResult

SAMPLE_DOMAINS = [
    {
        "domain": "docs.github.com",
        "classification": "benign",
        "confidence": "high",
        "risk_score": 5,
        "action": "monitor",
        "reasoning": "Well-established GitHub documentation subdomain with DigiCert certificate, proper DNS, and strong security headers.",
    },
    {
        "domain": "secure-login-update.net",
        "classification": "suspicious",
        "confidence": "medium",
        "risk_score": 62,
        "action": "investigate",
        "reasoning": "Recently registered domain with login form, privacy-protected WHOIS, and Let's Encrypt certificate. No direct evidence of credential harvesting, but unusual combination of signals.",
    },
    {
        "domain": "totally-legit-banking.xyz",
        "classification": "malicious",
        "confidence": "high",
        "risk_score": 92,
        "action": "block",
        "reasoning": "Domain impersonates banking service, harvests credentials, uses bulletproof hosting, and appears in multiple blocklists.",
    },
    {
        "domain": "mystery-parked.io",
        "classification": "inconclusive",
        "confidence": "low",
        "risk_score": 35,
        "action": "monitor",
        "reasoning": "Parked domain behind Cloudflare. WHOIS data redacted, no web content served. Insufficient evidence to determine intent.",
    },
    {
        "domain": "shop.example-store.com",
        "classification": "benign",
        "confidence": "high",
        "risk_score": 8,
        "action": "monitor",
        "reasoning": "E-commerce subdomain with valid Shopify infrastructure, proper TLS, established domain age of 5 years.",
    },
]


def main():
    parser = argparse.ArgumentParser(description="Seed sample investigation data")
    parser.add_argument("--count", "-n", type=int, default=len(SAMPLE_DOMAINS),
                        help="Number of investigations to create")
    parser.add_argument("--clean", action="store_true",
                        help="Delete existing data first")
    args = parser.parse_args()

    with Session(sync_engine) as session:
        if args.clean:
            print("🗑️  Cleaning existing data...")
            session.query(Report).delete()
            session.query(Evidence).delete()
            session.query(CollectorResult).delete()
            session.query(Investigation).delete()
            session.commit()
            print("   Done.")

        print(f"\n📝 Creating {args.count} sample investigation(s)...\n")

        for i in range(args.count):
            sample = SAMPLE_DOMAINS[i % len(SAMPLE_DOMAINS)]
            inv_id = uuid.uuid4()
            created = datetime.now(timezone.utc) - timedelta(hours=args.count - i)

            # Create investigation
            inv = Investigation(
                id=inv_id,
                domain=sample["domain"],
                state="concluded",
                context=f"Seeded test data #{i + 1}",
                created_at=created,
                concluded_at=created + timedelta(seconds=25),
                classification=sample["classification"],
                confidence=sample["confidence"],
                risk_score=sample["risk_score"],
                recommended_action=sample["action"],
                analyst_iterations=1,
            )
            session.add(inv)

            # Create minimal evidence
            evidence_json = {
                "domain": sample["domain"],
                "investigation_id": str(inv_id),
                "dns": {"meta": {"collector": "dns", "status": "completed", "duration_ms": 150},
                        "a": ["93.184.216.34"], "ns": ["ns1.example.com"], "txt": [], "mx": []},
                "tls": {"meta": {"collector": "tls", "status": "completed", "duration_ms": 200},
                        "present": True, "issuer_org": "DigiCert Inc", "sans": [sample["domain"]]},
                "http": {"meta": {"collector": "http", "status": "completed", "duration_ms": 450},
                         "reachable": True, "final_url": f"https://{sample['domain']}/",
                         "final_status_code": 200, "title": f"{sample['domain']} - Home",
                         "security_headers": {}, "redirect_chain": []},
                "whois": {"meta": {"collector": "whois", "status": "completed", "duration_ms": 800},
                          "registrar": "Example Registrar", "domain_age_days": 365},
                "hosting": {"meta": {"collector": "asn", "status": "completed", "duration_ms": 120},
                            "ip": "93.184.216.34", "asn": 15133, "asn_org": "Example Hosting",
                            "country": "United States"},
                "signals": [],
                "data_gaps": [],
            }
            ev = Evidence(
                investigation_id=inv_id,
                evidence_json=evidence_json,
                signals=[],
                data_gaps=[],
            )
            session.add(ev)

            # Create minimal report
            report_json = {
                "classification": sample["classification"],
                "confidence": sample["confidence"],
                "investigation_state": "concluded",
                "primary_reasoning": sample["reasoning"],
                "legitimate_explanation": "Domain operates as a legitimate service.",
                "malicious_explanation": "No malicious indicators found." if sample["classification"] == "benign"
                    else "Potential threat indicators present.",
                "key_evidence": ["dns.a", "tls.issuer_org", "http.final_url"],
                "contradicting_evidence": [],
                "data_needed": [],
                "findings": [],
                "iocs": [],
                "recommended_action": sample["action"],
                "recommended_steps": ["Continue monitoring"],
                "risk_score": sample["risk_score"],
                "risk_rationale": f"Score based on {sample['classification']} classification.",
            }
            rep = Report(
                investigation_id=inv_id,
                iteration=0,
                report_json=report_json,
                executive_summary=sample["reasoning"],
            )
            session.add(rep)

            print(f"  ✓ {sample['domain']:35s} → {sample['classification'].upper():15s} (risk: {sample['risk_score']})")

        session.commit()
        print(f"\n✅ Seeded {args.count} investigations successfully.\n")


if __name__ == "__main__":
    main()
