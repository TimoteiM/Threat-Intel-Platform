#!/usr/bin/env python3
"""
CLI tool — investigate a single domain from the command line.

Usage:
    python -m scripts.run_single_investigation example.com
    python -m scripts.run_single_investigation suspicious-site.net --collectors dns,tls,http
    python -m scripts.run_single_investigation evil.com --json --output report.json

Requires: pip dependencies installed. Does NOT require Postgres/Redis/Celery.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.collectors.registry import COLLECTOR_REGISTRY, available_collectors
from app.collectors.signals import generate_signals, detect_data_gaps
from app.utils.domain_utils import normalize_domain, validate_domain


def main():
    parser = argparse.ArgumentParser(
        description="Investigate a domain from the command line"
    )
    parser.add_argument("domain", help="Domain to investigate")
    parser.add_argument(
        "--collectors", "-c",
        default=",".join(available_collectors()),
        help=f"Comma-separated collectors (default: all). Available: {', '.join(available_collectors())}",
    )
    parser.add_argument("--timeout", "-t", type=int, default=30, help="Collector timeout in seconds")
    parser.add_argument("--json", "-j", action="store_true", help="Output JSON instead of text")
    parser.add_argument("--output", "-o", help="Save output to file")
    parser.add_argument("--analyst", "-a", action="store_true", help="Run AI analyst (requires OPENAI_API_KEY)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")

    args = parser.parse_args()

    # ── Validate domain ──
    domain = normalize_domain(args.domain)
    if not validate_domain(domain):
        print(f"❌ Invalid domain: {args.domain}", file=sys.stderr)
        sys.exit(1)

    collector_names = [c.strip() for c in args.collectors.split(",")]
    invalid = [c for c in collector_names if c not in COLLECTOR_REGISTRY]
    if invalid:
        print(f"❌ Unknown collector(s): {', '.join(invalid)}", file=sys.stderr)
        print(f"   Available: {', '.join(available_collectors())}", file=sys.stderr)
        sys.exit(1)

    investigation_id = f"cli-{int(time.time())}"

    if not args.json:
        print(f"\n{'═' * 60}")
        print(f"  THREAT INVESTIGATION: {domain}")
        print(f"  Collectors: {', '.join(collector_names)}")
        print(f"{'═' * 60}\n")

    # ── Run collectors ──
    evidence_data = {
        "domain": domain,
        "investigation_id": investigation_id,
        "timestamps": {"started": datetime.now(timezone.utc).isoformat()},
    }
    all_artifacts = {}

    for name in collector_names:
        collector_cls = COLLECTOR_REGISTRY[name]
        collector = collector_cls(
            domain=domain,
            investigation_id=investigation_id,
            timeout=args.timeout,
        )

        if not args.json:
            print(f"  ⏳ Running {name.upper()}...", end=" ", flush=True)

        evidence, meta, artifacts = collector.run()

        # Map collector output to evidence key
        evidence_key = "hosting" if name == "asn" else name
        evidence_data[evidence_key] = evidence.model_dump(mode="json")
        all_artifacts.update(artifacts)

        if not args.json:
            status = "✓" if meta.status.value == "completed" else "✗"
            duration = f"({meta.duration_ms}ms)" if meta.duration_ms else ""
            error = f" — {meta.error}" if meta.error else ""
            print(f"{status} {duration}{error}")

    # ── Generate signals and gaps ──
    signals = generate_signals(evidence_data)
    gaps = detect_data_gaps(evidence_data)
    evidence_data["signals"] = [s.model_dump() for s in signals]
    evidence_data["data_gaps"] = [g.model_dump() for g in gaps]
    evidence_data["timestamps"]["collected"] = datetime.now(timezone.utc).isoformat()

    if not args.json:
        print(f"\n  📊 Signals: {len(signals)}, Data gaps: {len(gaps)}")

    # ── Run analyst (optional) ──
    report_data = None
    if args.analyst:
        if not args.json:
            print(f"\n  Running AI analyst...", flush=True)
        try:
            report_data = asyncio.run(_run_analyst(evidence_data))
            if not args.json:
                print(f"  ✓ Classification: {report_data.get('classification', '?').upper()}")
                print(f"  ✓ Confidence: {report_data.get('confidence', '?')}")
                print(f"  ✓ Risk Score: {report_data.get('risk_score', '?')}/100")
                print(f"  ✓ Action: {report_data.get('recommended_action', '?').upper()}")
        except Exception as e:
            if not args.json:
                print(f"  ✗ Analyst failed: {e}")
            report_data = {"error": str(e)}

    # ── Output ──
    result = {
        "domain": domain,
        "investigation_id": investigation_id,
        "evidence": evidence_data,
    }
    if report_data:
        result["report"] = report_data

    if args.json:
        output = json.dumps(result, indent=2, default=str)
        if args.output:
            Path(args.output).write_text(output)
            print(f"Saved to {args.output}", file=sys.stderr)
        else:
            print(output)
    else:
        # Text summary
        print(f"\n{'─' * 60}")
        _print_text_summary(evidence_data, report_data, signals, gaps)

        if args.output:
            Path(args.output).write_text(json.dumps(result, indent=2, default=str))
            print(f"\n  💾 Full JSON saved to {args.output}")

    print()


async def _run_analyst(evidence_data: dict) -> dict:
    """
    Run the AI analyst on collected evidence.

    Mirrors analysis_task._run_analyst_sync minus the event-loop wrapper (this script is
    already inside asyncio.run) and minus the decision-engine overlay — the CLI shows raw
    analyst output on purpose, which is why the classification it prints can differ from
    what an investigation would persist.
    """
    from app.analyst import evidence_files
    from app.analyst.agent import build_agent, run_analyst
    from app.tasks.analysis_task import _build_analyst_evidence_digest

    investigation_id = str(evidence_data.get("investigation_id") or "cli")
    digest_markdown = evidence_files.render_markdown(
        _build_analyst_evidence_digest(evidence_data, tier="standard")
    )
    files = evidence_files.build(
        evidence_data,
        investigation_id=investigation_id,
        statuses={},
        digest_markdown=digest_markdown,
        signals=evidence_data.get("signals"),
        data_gaps=evidence_data.get("data_gaps"),
    )
    report, source, _state = await run_analyst(
        build_agent(),
        domain=str(evidence_data.get("domain") or ""),
        investigation_id=investigation_id,
        files=files,
        observable_type=str(evidence_data.get("observable_type") or "domain"),
        digest_markdown=digest_markdown,
    )
    print(f"  · analyst report source: {source}")
    return report.model_dump(mode="json")


def _print_text_summary(evidence: dict, report: dict | None, signals: list, gaps: list):
    """Print a human-readable summary."""

    # DNS
    dns = evidence.get("dns", {})
    a_records = dns.get("a", [])
    if a_records:
        print(f"\n  DNS A Records: {', '.join(a_records)}")
    ns = dns.get("ns", [])
    if ns:
        print(f"  Name Servers:  {', '.join(ns[:3])}")

    # WHOIS
    whois = evidence.get("whois", {})
    if whois.get("registrar"):
        print(f"  Registrar:     {whois['registrar']}")
    if whois.get("domain_age_days") is not None:
        print(f"  Domain Age:    {whois['domain_age_days']} days")

    # TLS
    tls = evidence.get("tls", {})
    if tls.get("issuer_org"):
        print(f"  TLS Issuer:    {tls['issuer_org']}")
    if tls.get("sans"):
        print(f"  TLS SANs:      {len(tls['sans'])} entries")

    # HTTP
    http = evidence.get("http", {})
    if http.get("title"):
        print(f"  Page Title:    {http['title']}")
    if http.get("final_url"):
        print(f"  Final URL:     {http['final_url']}")

    # Hosting
    hosting = evidence.get("hosting", {})
    if hosting.get("asn_org"):
        print(f"  Hosting:       {hosting['asn_org']} ({hosting.get('country', '?')})")

    # Intel
    intel = evidence.get("intel", {})
    if intel.get("blocklist_hits"):
        print(f"\n  ⚠️  BLOCKLIST HITS: {len(intel['blocklist_hits'])}")
        for hit in intel["blocklist_hits"][:5]:
            print(f"     → {hit.get('source', '?')}: {hit.get('details', '')}")
    if intel.get("related_subdomains"):
        print(f"  Subdomains (crt.sh): {len(intel['related_subdomains'])}")

    # Signals
    if signals:
        print(f"\n  ⚡ Signals:")
        for sig in signals:
            print(f"     [{sig.severity.upper():>6}] {sig.description}")

    # Gaps
    if gaps:
        print(f"\n  ⚠️  Data Gaps:")
        for gap in gaps:
            print(f"     → {gap.description}")

    # Report
    if report and not report.get("error"):
        print(f"\n{'─' * 60}")
        print(f"  🎯 CLASSIFICATION: {report.get('classification', '?').upper()}")
        print(f"  📊 Confidence:     {report.get('confidence', '?')}")
        print(f"  🔢 Risk Score:     {report.get('risk_score', '?')}/100")
        print(f"  🛡️  Action:         {report.get('recommended_action', '?').upper()}")
        if report.get("primary_reasoning"):
            print(f"\n  Reasoning: {report['primary_reasoning'][:200]}...")


if __name__ == "__main__":
    main()
