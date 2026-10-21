"""The WHOLE outgoing payload, per identifier class, per ingest shape.

Probe point is the wire: `(system, user_text)` as handed to
`AssistantService._call_with_fallback`. Everything earlier is an intermediate
— `sanitize_entries`' output is not the payload either, because
`_build_user_payload` wraps it in another `json.dumps`.

Every transform is the real function. The only thing not executed is the
database round trip in `_run_assistant`, which stores `raw_text` in a column
and reads it back unchanged; the assembled text itself is captured from the
real `_analyse` by intercepting `_run_assistant`.

Three states per class:
  BOUNDARY   — `[HOST_<12hex>_n]`, scoped to a tenant and run
  SHIPPED    — `[HOST_n]`, unscoped, from assistant_sanitizer_service
  CLEAR      — present verbatim on the wire
"""
from __future__ import annotations

import json
import pathlib
import re
import sys
from datetime import datetime, timezone

sys.path.insert(
    0, str(pathlib.Path(__file__).resolve().parents[1] / "backend")
)

from app.services import alert_body_ai_service as ai
from app.services import token_boundary as tb
from app.services.alert_payload_service import normalize_alert_payload
from app.services.assistant_prompt_service import build_alert_analysis_prompt
from app.services.assistant_sanitizer_service import sanitize_entries
from app.services.assistant_service import strip_resolved_identifiers

ALERT_TIME = datetime(2026, 10, 20, 12, 0, tzinfo=timezone.utc)

# One sentinel per class. Nothing here appears in any corpus, so finding one
# on the wire means it travelled there.
CLASSES = {
    "gap 1  keyed single-label host": "SENTFILESERVER",
    "gap 2  bare DOMAIN\\user":       "sentuserbeta",
    "gap 3  UNC server name":         "SENTFS01",
    "gap 4  IPv6":                    "2001:db8:dead:beef::1",
    "gap 5  -User switch":            "sentusergamma",
    "gap 6  secret off field list":   "SentinelPassw0rd",
    "NEW    keyed account":           "sentuseralpha",
    "--     keyed multi-label host":  "sentsrv.corp.example.net",
    "--     public IPv4":             "203.0.113.77",
    "--     email":                   "sent.user@example.net",
}

SCOPED = re.compile(r"\[(?:HOST|ACCOUNT|IP|EMAIL|SID)_[0-9a-f]{12}_\d+\]")
UNSCOPED = re.compile(r"\[(?:HOST|ACCOUNT|IP|EMAIL|SID)_\d+\]")


# ── the two ingest shapes, as the two workflows actually deliver them ──────

def sentinelone_structured():
    """A nested JSON document, as the SentinelOne workflow posts it."""
    return {
        "threatInfo": {
            "threatName": "suspicious.ps1",
            "classification": "Malware",
            "identifiedAt": "2026-10-20T12:00:00Z",
        },
        "agentDetectionInfo": {
            "agentDomain": "SENTDOM",
            "agentComputerName": "SENTFILESERVER",
            "agentIpV6": "2001:db8:dead:beef::1",
            "externalIp": "203.0.113.77",
        },
        "agentRealtimeInfo": {"agentComputerName": "SENTFILESERVER"},
        "indicators": [
            {"category": "logon", "description": r"logon by SENTDOM\sentuserbeta"},
        ],
        "sourceProcessInfo": {
            "user": "sentuseralpha",
            "commandline": (
                r"powershell.exe -User sentusergamma -ExecutionPolicy Bypass "
                r"-File \\SENTFS01\finance\q3.xlsx"
            ),
            "integrityLevel": "high",
        },
        "vendorDetail": "password=SentinelPassw0rd",
        "mailbox": "sent.user@example.net",
        "server": "sentsrv.corp.example.net",
    }


def exabeam_flattened():
    """Flattened log lines, as the Exabeam workflow posts them (raw text)."""
    return (
        "rule: Suspicious PowerShell\n"
        'hostname="SENTFILESERVER" user="sentuseralpha" '
        'computer="sentsrv.corp.example.net"\n'
        r"logon by SENTDOM\sentuserbeta from \\SENTFS01\finance\q3.xlsx" "\n"
        "src_ip=203.0.113.77 remote=2001:db8:dead:beef::1\n"
        "powershell.exe -User sentusergamma\n"
        "mail=sent.user@example.net\n"
        'vendor_detail="password=SentinelPassw0rd"'
    )


# ── the log half: events carrying the same classes ────────────────────────

def log_records():
    return [{
        "key": "wazuh-alerts:1", "ref": "wazuh-alerts:1", "index": "wazuh-alerts",
        "id": "1", "event_id": "4624",
        "timestamp": "2026-10-20T12:00:00.000+0000",
        "agent": {"name": "sentsrv.corp.example.net", "id": "1"},
        "rule": {"id": "1", "level": 7, "description": "Logon", "groups": []},
        "users": [], "process": {
            "command_line": (
                r"powershell.exe -User sentusergamma -File \\SENTFS01\finance\q3.xlsx"
            ),
        },
        "full_log": (
            'hostname="SENTFILESERVER" user="sentuseralpha" '
            r"logon by SENTDOM\sentuserbeta "
            "src_ip=203.0.113.77 remote=2001:db8:dead:beef::1 "
            "mail=sent.user@example.net"
        ),
        "vendor_detail": "password=SentinelPassw0rd",
    }]


def build_digest(boundary):
    """The real `_build_log_digest`, with autosend forced on."""
    import app.services.alert_body_investigation_service as svc

    original = svc.get_settings

    class _Autosend:
        alert_log_ai_autosend = True

        def __getattr__(self, name):
            return getattr(original(), name)

    context = {
        "status": "collected", "logs": log_records(),
        "alert_time": ALERT_TIME.isoformat(),
        "entity_host": None, "entity_user": None,
        "extra_fields": ["vendor_detail"],
        "window": {"complete": True},
    }
    svc.get_settings = lambda: _Autosend()
    try:
        return svc._build_log_digest(
            context, "alert body", {"event_id": "4624"},
            indicators=[], boundary=boundary,
        )
    finally:
        svc.get_settings = original


# ── the wire ──────────────────────────────────────────────────────────────

def wire_text(alert_body, digest, title):
    """`(system, user_text)` as `_call_with_fallback` receives it.

    `_analyse` is the real function; `_run_assistant` is intercepted so the
    assembled `entry_text` is the genuine join rather than my restatement of
    it. No database row is written — the interception happens before any
    session is opened.
    """
    captured = {}

    async def _capture(session_factory, *, entry_text, title, model, boundary=None):
        captured["entry_text"] = entry_text
        return {}

    original = ai._run_assistant
    ai._run_assistant = _capture
    try:
        ai.run_alert_body_ai_analysis(
            alert_body=alert_body, title=title, context=None,
            findings_digest=None, log_context_digest=digest,
        )
    finally:
        ai._run_assistant = original

    entry_text = captured["entry_text"]
    # Exactly what add_entry then run_session do with it.
    raw_text = strip_resolved_identifiers(entry_text)
    result = sanitize_entries([raw_text])
    sanitized = result.entries[0].sanitized_text
    system, user_text = build_alert_analysis_prompt(
        title=title,
        sanitized_entries=[{"entry_label": "alert-body", "sanitized_text": sanitized}],
        raw_entries=[raw_text],
        token_map=result.entries[0].token_map,
    )
    return system + "\n" + user_text, entry_text, sanitized


def present(wire, value):
    """Verbatim on the wire, in any encoding it could arrive in.

    `_build_user_payload` runs `json.dumps`, so a backslash on the wire is
    doubled and a quote is escaped. Probing only the plain form would report
    a leak as clean.
    """
    forms = {value, json.dumps(value)[1:-1], value.replace("\\", "\\\\")}
    return any(form in wire for form in forms)


def classify(wire, value, half_text):
    """Which of the three states, and the state is about the WIRE."""
    if present(wire, value):
        return "CLEAR"
    # It is gone from the wire. Which sanitiser took it is decided by the
    # token that replaced it, read at the position it occupied in the text
    # that went in.
    if not present(half_text, value):
        return "BOUNDARY"          # already a token before the shipped layer
    return "SHIPPED"               # still clear going in, tokenised on the wire


def report(label, alert_body, digest):
    wire, entry_text, sanitized = wire_text(alert_body, digest, "Measurement")
    # The halves, so a leak can be attributed. The digest is the tail of
    # entry_text; everything before it is the alert half.
    alert_half = entry_text.split(digest, 1)[0] if digest else entry_text

    print(f"\n{'=' * 78}\n{label}\n{'=' * 78}")
    print(f"  alert body chars: {len(alert_body):6}   digest chars: {len(digest):6}"
          f"   wire chars: {len(wire):6}")
    print(f"  scoped tokens on the wire: {len(set(SCOPED.findall(wire))):3}"
          f"   unscoped: {len(set(UNSCOPED.findall(wire))):3}")
    print()
    print(f"  {'class':34} {'ALERT HALF':>12} {'DIGEST HALF':>12}")
    print(f"  {'-' * 34} {'-' * 12:>12} {'-' * 12:>12}")
    # The digest half must be probed against what went INTO it, not against
    # the digest. Its values were tokenised before the digest existed, so a
    # raw-value search over the digest finds nothing — and reporting that as
    # "absent" renders a success as "never tested". Same absence-as-value
    # mistake this codebase keeps making in its own instruments.
    submitted = repr(log_records())

    leaks = []
    for name, value in CLASSES.items():
        in_alert = present(alert_half, value)
        in_digest = present(submitted, value)
        a = classify(wire, value, alert_half) if in_alert else "not sent"
        # The digest's own contribution, decided ON THE DIGEST and not on the
        # wire: a value the alert half leaks appears on the wire regardless,
        # and crediting that to the digest would mark a working boundary as a
        # leak. If it is absent from the digest before the shipped layer runs,
        # the digest cannot be what put it on the wire.
        if not in_digest:
            d = "not sent"
        elif not present(digest, value):
            d = "BOUNDARY"         # gone before the shipped layer saw it
        elif present(wire, value):
            d = "CLEAR"
        else:
            d = "SHIPPED"          # survived the boundary, caught below it
        # A class present in both halves: the wire verdict is shared, so a
        # CLEAR in either column means it reached the model.
        print(f"  {name:34} {a:>12} {d:>12}")
        if "CLEAR" in (a, d):
            leaks.append((name, a, d))
    return leaks, wire


def main():
    print("PROBE POINT: (system, user_text) at AssistantService._call_with_fallback")
    print("Transforms executed: normalize_alert_payload, _build_log_digest,")
    print("  _analyse's join, strip_resolved_identifiers, sanitize_entries,")
    print("  build_alert_analysis_prompt. All real.")

    all_leaks = {}

    # --- SentinelOne: structured JSON through the real normaliser
    payload = sentinelone_structured()
    normalized = normalize_alert_payload(payload)
    boundary = tb.in_memory(tenant_id="c00", investigation_id="measure-s1")
    digest, summary = build_digest(boundary)
    leaks, wire = report(
        "SentinelOne workflow — structured JSON posted to /api/alert-investigations",
        normalized["alert_body"], digest or "",
    )
    all_leaks["sentinelone"] = leaks
    print(f"  digest status: {summary.get('status')}  "
          f"tokenised: {summary.get('identifiers_tokenised')}")

    # --- Exabeam: flattened lines posted as raw text
    raw = exabeam_flattened()
    normalized = normalize_alert_payload(raw)
    boundary = tb.in_memory(tenant_id="c00", investigation_id="measure-exa")
    digest, summary = build_digest(boundary)
    leaks, wire = report(
        "Exabeam workflow — flattened lines posted to /api/alert-investigations/raw",
        normalized["alert_body"], digest or "",
    )
    all_leaks["exabeam"] = leaks
    print(f"  digest status: {summary.get('status')}  "
          f"tokenised: {summary.get('identifiers_tokenised')}")

    # --- the escaping question, on ingest
    print(f"\n{'=' * 78}\nIS THE ALERT BODY ESCAPED WHEN THE SHIPPED DETECTORS SEE IT?"
          f"\n{'=' * 78}")
    for label, body in (
        ("SentinelOne (structured)", normalize_alert_payload(sentinelone_structured())["alert_body"]),
        ("Exabeam (raw lines)", normalize_alert_payload(exabeam_flattened())["alert_body"]),
    ):
        escaped_quotes = body.count('\\"')
        doubled_slashes = body.count("\\\\")
        print(f"  {label:26} escaped quotes: {escaped_quotes:3}   "
              f"doubled backslashes: {doubled_slashes:3}")
        sample = [ln for ln in body.splitlines() if "SENTFILESERVER" in ln]
        if sample:
            print(f"    host line as the detectors see it: {sample[0][:90]!r}")

    # ── the separator question, which the two shapes above disagreed on ──
    print(f"\n{'=' * 78}\nWHICH SEPARATORS DO THE TWO SANITISERS MATCH?\n{'=' * 78}")
    print("  Ingest flattening emits `key: value`; a raw log line carries")
    print("  `key=\"value\"`; the digest carries `key=\\\"value\\\"` after json.dumps.")
    print()
    print(f"  {'text as the detector sees it':44} {'shipped':>9} {'boundary':>9}")
    print(f"  {'-' * 44} {'-' * 9:>9} {'-' * 9:>9}")
    for shape in (
        'user="sentuseralpha"',
        "user: sentuseralpha",
        "user=sentuseralpha",
        'user=\\"sentuseralpha\\"',
        'hostname="SENTFILESERVER"',
        "hostname: SENTFILESERVER",
        'hostname=\\"SENTFILESERVER\\"',
    ):
        old = sanitize_entries([shape]).entries[0].sanitized_text
        b = tb.in_memory(tenant_id="t", investigation_id="i")
        new = b.tokenize(shape)
        shipped = "tokenised" if old != shape else "CLEAR"
        bound = "tokenised" if new != shape else "CLEAR"
        print(f"  {shape:44} {shipped:>9} {bound:>9}")

    print(f"\n{'=' * 78}\nSUMMARY\n{'=' * 78}")
    for shape, leaks in all_leaks.items():
        if not leaks:
            print(f"  {shape}: nothing in the clear")
        else:
            print(f"  {shape}: {len(leaks)} class(es) reached the model in the clear")
            for name, a, d in leaks:
                print(f"      {name:34} alert={a} digest={d}")


if __name__ == "__main__":
    main()
