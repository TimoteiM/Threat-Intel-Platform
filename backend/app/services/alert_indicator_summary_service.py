"""
What the sources actually found, in one line per indicator.

The alert run's AI narrative is produced from the alert text alone, in parallel
with the collectors — so it can name a hash but never say what VirusTotal thought
of it. The facts are all in the indicator reports' findings; this module turns
them into the sentence an analyst would write:

    SHA256 acf4ecb5… — 21 of 91 engines malicious (Trojan.Win32.Emotet);
    submitted as invoice.exe (PE32 executable, 412 KB); unsigned; AnyRun: malicious

Deterministic on purpose: a summary that drives triage must not be able to
invent a detection count.
"""

from __future__ import annotations

from typing import Any

MAX_HIGHLIGHTS = 12
MAX_VENDORS = 4
MAX_NAMES = 3


def build_indicator_summary(reports: list[dict[str, Any]]) -> dict[str, Any]:
    """
    A factual roll-up of every indicator report.

    Returns `{headline, highlights, indicators}` — a sentence for the top of a
    report, one line per indicator, and the structured facts behind each line.
    """
    entries = [_describe(report) for report in reports or [] if isinstance(report, dict)]
    entries = [entry for entry in entries if entry]

    flagged = [e for e in entries if e["classification"] in ("malicious", "suspicious")]
    flagged.sort(key=lambda e: (-int(e.get("risk_score") or 0), e["value"]))
    quiet = [e for e in entries if e not in flagged]

    return {
        "headline": _headline(entries, flagged),
        "highlights": [entry["line"] for entry in (flagged + quiet)[:MAX_HIGHLIGHTS]],
        "indicators": flagged + quiet,
    }


def _headline(entries: list[dict[str, Any]], flagged: list[dict[str, Any]]) -> str:
    if not entries:
        return "No indicators were extracted from this alert."
    if not flagged:
        # An indicator nobody queried was not "checked", and a headline that
        # says it was reads as a clean bill of health nothing earned.
        checked = [e for e in entries if e.get("status") not in ("excluded", "skipped")]
        if not checked:
            excluded = sum(1 for e in entries if e.get("status") == "excluded")
            detail = f"{excluded} on the exclusion list" if excluded else "none investigable"
            return (
                f"{len(entries)} indicator(s) extracted, none queried "
                f"({detail}) — this alert rests on its own content."
            )
        scope = (
            f"{len(checked)} indicator(s)"
            if len(checked) == len(entries)
            else f"{len(checked)} of {len(entries)} indicator(s)"
        )
        return f"{scope} checked — none was flagged by any source."
    worst = flagged[0]
    others = len(flagged) - 1
    tail = f", and {others} other flagged indicator(s)" if others else ""
    return f"{worst['line']}{tail}."


def _describe(report: dict[str, Any]) -> dict[str, Any] | None:
    indicator = report.get("indicator") or {}
    value = str(indicator.get("value") or "").strip()
    if not value:
        return None

    kind = str(indicator.get("type") or "indicator")
    verdict = report.get("verdict") or {}
    classification = str(verdict.get("classification") or "inconclusive")
    findings = [f for f in (report.get("findings") or []) if isinstance(f, dict)]

    facts: dict[str, Any] = {
        "value": value,
        "type": kind,
        "classification": classification,
        "risk_score": verdict.get("risk_score"),
        "status": report.get("status"),
    }
    parts: list[str] = []

    reputation = _finding(findings, "vt", "reputation")
    if reputation:
        data = reputation.get("data") or {}
        malicious = int(data.get("malicious") or 0)
        total = int(data.get("total_engines") or 0)
        scope = data.get("scope_value") if data.get("scope") == "domain" else None
        if malicious and total:
            vendors = ", ".join(str(v) for v in (data.get("flagged_by") or [])[:MAX_VENDORS])
            detections = ", ".join(str(d) for d in (data.get("detections") or [])[:2])
            line = f"{malicious} of {total} engines malicious"
            if scope:
                line += f" (for the host {scope})"
            if detections:
                line += f" — {detections}"
            elif vendors:
                line += f" — flagged by {vendors}"
            parts.append(line)
            facts.update({"vt_malicious": malicious, "vt_total": total,
                          "vt_detections": data.get("detections") or None,
                          "vt_flagged_by": data.get("flagged_by") or None})
        elif total:
            parts.append(f"no detections across {total} engines")
            facts.update({"vt_malicious": 0, "vt_total": total})

    profile = _finding(findings, "vt", "file_profile")
    if profile:
        data = profile.get("data") or {}
        name = data.get("file_name")
        names = [n for n in (data.get("other_names") or []) if n][:MAX_NAMES]
        descriptor = ", ".join(
            str(part) for part in (data.get("file_type"), _size(data.get("size_bytes"))) if part
        )
        if name:
            parts.append(f"submitted as {name}" + (f" ({descriptor})" if descriptor else ""))
        elif descriptor:
            parts.append(descriptor)
        if names:
            parts.append("also seen as " + ", ".join(names))

        signature = data.get("signature") or {}
        if signature:
            signer = signature.get("signer") or signature.get("signers")
            if signature.get("signed"):
                parts.append("signed" + (f" by {signer}" if signer else ""))
            else:
                parts.append(f"signature {signature.get('verified') or 'not valid'}")
        else:
            parts.append("unsigned")

        if data.get("threat_label"):
            parts.append(f"VT threat label {data['threat_label']}")
        facts.update({
            "file_name": name,
            "other_names": names or None,
            "file_type": data.get("file_type"),
            "size_bytes": data.get("size_bytes"),
            "signed": bool((data.get("signature") or {}).get("signed")),
            "signature": data.get("signature") or None,
            "threat_label": data.get("threat_label"),
            "imphash": data.get("imphash"),
            "times_submitted": data.get("times_submitted"),
        })

    for sandbox in ("hybrid_analysis", "vt"):
        behaviour = _finding(findings, sandbox, "sandbox_behaviour")
        if behaviour:
            parts.append(f"sandbox: {behaviour.get('summary')}")
            facts["sandbox"] = behaviour.get("summary")
            break

    if kind in ("ip", "ipv4", "ipv6", "ip_address"):
        card, identity_facts = _ip_identity(findings)
        if card:
            # First, so the address is introduced by what it is rather than by
            # how many people have reported it.
            parts.insert(0, card)
            facts.update(identity_facts)

    feeds = [f for f in findings if f.get("collector") in ("threat_feeds", "intel", "opencti")]
    for feed in feeds[:2]:
        parts.append(str(feed.get("summary")))
    if feeds:
        facts["feeds"] = [str(f.get("summary")) for f in feeds[:3]]

    investigation = report.get("investigation") or report.get("prior_investigation") or {}
    if investigation.get("investigation_id"):
        facts["investigation_id"] = investigation["investigation_id"]
        if investigation.get("recommended_action"):
            parts.append(f"investigation recommends {investigation['recommended_action']}")

    if report.get("status") == "excluded":
        # "Nothing found" and "we deliberately did not look" are different
        # answers, and the second one has a reason attached. Saying which is
        # what stops a narrative describing our own corporate domain as an
        # indicator no source had heard of.
        exclusion = report.get("exclusion") or {}
        note = str(exclusion.get("reason") or "").strip()
        matched = str(exclusion.get("matched") or "").strip()
        parts.append(
            "on the exclusion list"
            + (f" as {matched}" if matched and matched != value else "")
            + " — treated as benign, no sources queried"
            + (f" ({note})" if note else "")
        )
        facts["excluded"] = True
    elif report.get("status") == "skipped":
        parts.append(f"not investigated ({str(report.get('skip_reason') or '').replace('_', ' ')})")
    elif report.get("status") == "investigating":
        parts.append("investigation still running")
    elif not parts:
        parts.append("nothing found by the sources checked")

    label = _label(kind, value)
    facts["line"] = f"{label} — " + "; ".join(parts)
    return facts


def _label(kind: str, value: str) -> str:
    if kind == "hash":
        return f"{'SHA256' if len(value) == 64 else 'MD5' if len(value) == 32 else 'Hash'} {value[:16]}…"
    return f"{kind.upper()} {value}" if kind in ("ip", "url") else value


def _ip_identity(findings: list[dict[str, Any]]) -> tuple[str | None, dict[str, Any]]:
    """
    The ISP / usage-type identity card for an IP, from AbuseIPDB's enrichment.

    The reports the model writes are meant to introduce a public address by what
    it *is* — "(ISP: ..., Usage Type: ...)", a Tor exit, a CDN endpoint — rather
    than by its abuse statistics. That was impossible to honour: AbuseIPDB
    carries isp, usage_type, country_code and is_tor in the finding's data, but
    only the summary line reached the digest, and that line is nothing but
    "Abuse confidence 100% from 584 report(s)" — precisely the statistic the
    report is supposed to lead away from.
    """
    for finding in findings:
        if str(finding.get("source") or "") != "AbuseIPDB":
            continue
        data = finding.get("data") or {}
        isp = str(data.get("isp") or "").strip()
        usage = str(data.get("usage_type") or "").strip()
        country = str(data.get("country_code") or "").strip()
        if not isp and not usage:
            return None, {}

        card = ", ".join(
            part for part in (
                f"ISP: {isp}" if isp else "",
                f"Usage Type: {usage}" if usage else "",
                f"Country: {country}" if country else "",
            ) if part
        )
        facts = {"isp": isp or None, "usage_type": usage or None,
                 "country_code": country or None, "is_tor": bool(data.get("is_tor")) or None}
        if data.get("is_tor"):
            return f"({card}) — known Tor exit", facts
        return f"({card})", facts
    return None, {}


def _finding(findings: list[dict[str, Any]], collector: str, kind: str) -> dict[str, Any] | None:
    for finding in findings:
        if finding.get("collector") == collector and finding.get("type") == kind:
            return finding
    return None


def _size(value: Any) -> str:
    try:
        size = float(value)
    except (TypeError, ValueError):
        return ""
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return ""


def build_analysis_digest(
    summary: dict[str, Any],
    event_reports: list[dict[str, Any]] | None = None,
    run_summary: dict[str, Any] | None = None,
) -> str:
    """
    The collector results as text for the AI analyst.

    The narrative used to be written from the alert text alone — the model could
    name a hash but had no idea whether anything flagged it. This block is handed
    to it alongside the alert, labelled as verified results so it is never
    mistaken for a claim the alert itself made.
    """
    indicators = (summary or {}).get("indicators") or []
    events = event_reports or []
    if not indicators and not events:
        return ""

    lines = [
        "=== VERIFIED RESULTS FROM OUR OWN SOURCES ===",
        "(Collected by this platform after the alert was received — VirusTotal, threat feeds,",
        "sandbox, WHOIS, URLScan and full investigations. Treat as fact; the alert text above",
        "is only what the sender claimed.)",
        "",
    ]

    if run_summary:
        verdict = run_summary.get("overall_verdict")
        risk = run_summary.get("highest_risk_score")
        if verdict:
            lines.append(f"Overall verdict: {verdict} (highest risk {risk}/100)")
            lines.append("")

    if indicators:
        lines.append("Indicators:")
        lines.extend(f"- {entry['line']}" for entry in indicators)
        lines.append("")

    if events:
        lines.append("Endpoint events (behaviour scored from the process telemetry):")
        for report in events:
            event = report.get("event") or {}
            verdict = report.get("verdict") or {}
            signals = "; ".join(
                str(finding.get("summary")) for finding in (report.get("findings") or [])[:6]
            )
            image = str(event.get("image") or event.get("header") or "event").split("\\")[-1]
            lines.append(
                f"- {event.get('type', 'event')} {image} → {verdict.get('classification')} "
                f"{verdict.get('risk_score')}/100"
                + (f": {signals}" if signals else "")
            )
        lines.append("")

    return "\n".join(lines).strip()
