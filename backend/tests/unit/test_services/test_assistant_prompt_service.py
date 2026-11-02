import sys
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parents[3]
sys.path = [path for path in sys.path if path != str(BACKEND_ROOT)]
sys.path.insert(0, str(BACKEND_ROOT))
loaded_app = sys.modules.get("app")
if loaded_app and Path(str(getattr(loaded_app, "__file__", ""))).resolve() == BACKEND_ROOT / "__init__.py":
    sys.modules.pop("app", None)

from app.services import assistant_prompt_service as prompt_service


def test_alert_prompt_uses_sanitized_content_and_required_sections() -> None:
    sanitized_entries = [
        {"entry_label": "alert-1", "sanitized_text": "User [ACCOUNT_1] from 10.0.0.1"},
    ]
    raw_entries = ["User admin from 10.0.0.1"]

    system, user = prompt_service.build_alert_analysis_prompt(
        title="Suspicious login",
        sanitized_entries=sanitized_entries,
        raw_entries=raw_entries,
    )

    # Format replaced 2026-11-02: the mode now writes a SOC ticket body
    # ("SOC Resolution:" / "Resolution:") instead of an Event Interpretation
    # section. Asserting the old heading here would defend the format the
    # rewrite removed.
    assert "soc resolution:" in system.lower()
    assert "event interpretation" not in system.lower()
    assert "executive summary" not in system.lower()
    assert "notable entities" not in system.lower()
    # Moved into the shared DROP_LOW_VALUE_DETAIL block by the 2026-11-02
    # rewrite; the rule is still applied, the wording is the shared one.
    assert "leave out detail that does not change the verdict" in system.lower()
    assert "error codes" in system.lower()
    assert "ip address tokens" in system.lower()
    assert "[ACCOUNT_1]" in user
    assert "10.0.0.1" in user
    assert "admin" not in user


def test_alert_prompt_requires_key_indicator_ips_and_tokens_to_be_preserved() -> None:
    system, _ = prompt_service.build_alert_analysis_prompt(
        title="Proxy connection",
        sanitized_entries=[
            {
                "entry_label": "alert-1",
                "sanitized_text": (
                    "srcip=10.0.0.1 dstip=10.0.0.2 user=[ACCOUNT_1] "
                    'policy="SIEMBIOT_REVERSE_PROXY" dstcountry="Romania"'
                ),
            }
        ],
        raw_entries=["srcip=10.0.0.1 dstip=10.0.0.2 user=vhorga"],
    )

    # The IP-token rule survived the rewrite in shorter wording; what it
    # must still say is that IP tokens are indicators to be reproduced.
    lowered = " ".join(system.lower().split())
    assert "ip address tokens such as [ip_1] are first-class indicators" in lowered
    assert "versions, not ip addresses" in lowered


def test_alert_prompt_requires_endpoint_process_hash_and_attack_observables() -> None:
    system, _ = prompt_service.build_alert_analysis_prompt(
        title="Endpoint alert",
        sanitized_entries=[{"entry_label": "alert-1", "sanitized_text": "processFilePath=C:\\\\Temp\\\\sample.exe"}],
    )

    lowered = " ".join(system.lower().split())
    # The SOC format sets its own shape: one to two paragraphs inside
    # "SOC Resolution:", then a single disposition sentence.
    assert "1-2 concise professional paragraphs" in lowered
    assert "one concise final disposition sentence" in lowered
    assert "120-250 words" in lowered
    # The prompt used to require a hash in every report ("when a file hash is
    # available, include it once...") and to name every concrete process. Both
    # were replaced: a hash is now included only where it is the actionable IOC,
    # and only the one or two processes that drive the verdict are named while
    # the rest are summarised by category. Keeping the old assertions would hold
    # the prompt to rules it deliberately no longer follows.
    assert "only where it is the actionable ioc to block" in lowered
    # Likewise: process-naming discipline is PROCESS_SUMMARIZATION now.
    assert "summarise processes; never enumerate them" in lowered
    assert "do not claim that activity is non-recurring" in lowered


def test_incident_prompt_contains_timeline_iocs_root_cause_sections() -> None:
    system, user = prompt_service.build_incident_correlation_prompt(
        title="Multi-stage incident",
        sanitized_entries=[
            {"entry_label": "event-1", "sanitized_text": "Observed 10.0.0.1"},
            {"entry_label": "event-2", "sanitized_text": "Observed [EMAIL_1]"},
        ],
        raw_entries=["Observed 10.0.0.1", "Observed admin@example.com"],
    )

    assert "timeline" in system.lower()
    assert "attack chain" in system.lower()
    assert "root cause" in system.lower()
    assert "remediation" in system.lower()
    assert "10.0.0.1" in user
    assert "admin@example.com" not in user


def test_prompt_forbids_placeholder_tokens_when_no_tokens_present() -> None:
    _system, user = prompt_service.build_alert_analysis_prompt(
        title="Ransomware alert",
        sanitized_entries=[{"entry_label": "alert-1", "sanitized_text": "classification=Ransomware"}],
        token_map={},
    )

    assert "Tokens present in the evidence above: none" in user
    assert "Do not output placeholder tokens" in user


# --- the SOC ticket format (2026-11-02) -------------------------------------
#
# The alert-analysis mode is what analysts paste alerts into all day, so its
# output goes straight into a ticket. The prompt was rewritten to the SOC
# resolution format the team specified, and the rules below are the parts that
# would be expensive to lose silently.

def test_the_alert_prompt_asks_for_the_soc_ticket_format_and_nothing_else():
    from app.services.assistant_prompt_service import ALERT_ANALYSIS_SYSTEM_PROMPT as P

    assert "SOC Resolution:" in P
    assert "Resolution:" in P
    # The headings the format explicitly bans. `Event Interpretation` was the
    # previous format's only section, so its presence would mean the rewrite
    # was partially reverted.
    for banned in ("Event Interpretation", "Executive Summary", "Impact Assessment",
                   "Root Cause Analysis", "MITRE ATT&CK"):
        assert banned not in P or f"such as Executive" in P, (
            f"{banned!r} is still being requested by the prompt"
        )
    assert "Event Interpretation" not in P


def test_administrative_activity_is_not_suspicious_by_default():
    """The specific failure the team is correcting: a 4732 or a SYSTEM account
    being called suspicious because nothing proved it authorised."""
    from app.services.assistant_prompt_service import ALERT_ANALYSIS_SYSTEM_PROMPT as P

    for event_id in ("4732", "4733", "4728", "4729", "4746", "4756"):
        assert event_id in P, f"Event ID {event_id} is not named as non-malicious"
    assert "authorization could not be verified" in P
    assert "INCONCLUSIVE" in P
    # And the preference for INCONCLUSIVE over SUSPICIOUS when evidence is thin.
    assert "Prefer this over" in P


def test_the_sanitisation_rules_survived_the_rewrite():
    """**The security boundary, not a style rule.**

    The token instructions are what stop the model printing a real hostname
    next to its placeholder. A format rewrite is exactly the kind of change
    that drops them by accident, so they are asserted separately from the
    formatting.
    """
    from app.services.assistant_prompt_service import ALERT_ANALYSIS_SYSTEM_PROMPT as P

    flat = " ".join(P.split())
    assert "Tokens present" in flat
    assert "do not invent tokens" in flat
    assert "no parenthetical, no colon, no inline expansion" in flat
    assert "ignore the raw value and use only the token" in flat


def test_the_length_rules_are_not_appended_twice():
    """`WRITING_STYLE` sets "two to four sentences" and asks for a closing
    disposition. The SOC format sets 120-250 words and has its own
    `Resolution:` heading for the disposition, so appending both would give
    the model two different targets."""
    from app.analyst.analysis_guidance import (
        WRITING_STYLE, WRITING_STYLE_SOC_RESOLUTION,
    )
    from app.services.assistant_prompt_service import ALERT_ANALYSIS_SYSTEM_PROMPT as P

    assert "two to four sentences" in WRITING_STYLE
    assert "two to four sentences" not in WRITING_STYLE_SOC_RESOLUTION
    assert "two to four sentences" not in P
    assert "120-250 words" in P
    # What reaches the page is unchanged — only the length rules are dropped.
    from app.analyst import analysis_guidance as g
    assert g.PROCESS_SUMMARIZATION.strip() in WRITING_STYLE_SOC_RESOLUTION
    assert g.DROP_LOW_VALUE_DETAIL.strip() in WRITING_STYLE_SOC_RESOLUTION
