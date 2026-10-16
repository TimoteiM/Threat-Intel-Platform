"""Derive an alert investigation's chain from its completed payload.

Same approach as the email deriver and for the same reason: the stages are
already in the payload, and deriving against a **declared** list of expected
steps records the ones that produced nothing, where instrumenting would only
record the ones that ran.

Every field read here was listed before it was written — `jsonb_object_keys`
over each section, not guessed. Four fields written against an imagined
interface in two days is what that costs otherwise (README rule 19).

**The gate is a step, not a precondition.** The record only exists because the
gate opened, so "why this investigation exists" is the first claim rather than
something implied by the record's existence.

The log-context step is eight kinds, because the data says so. Measured over
2,833 post-cutover runs:

    collected    484   logs read, window complete
    partial    1,654   `window.complete` is False on ALL of them, with
                       truncation layered on: 639 window-only, 433 truncated
                       below the 500 cap, 582 truncated at it
    unavailable  613   372 with a host, 241 without
    empty         75   asked, and the window held nothing
    skipped        7   no host

Before 2026-09-21 the feature did not exist: 10,130 runs have no log context
and never will, which is `out_of_scope` rather than a failure.
"""

from __future__ import annotations

from typing import Any

from app.services import investigation_step_templates as T
from app.services.investigation_recorder import InvestigationRecorder

#: When log-context collection began. Before this a run has none and never
#: will, which is a different claim from one that failed to collect.
LOG_CONTEXT_FROM = "2026-09-21"

_FREE: dict[str, Any] = {}


def _obj(payload: dict[str, Any], key: str) -> dict[str, Any]:
    """A section, or `{}`. A JSON null is not an object — `-> key IS NOT NULL`
    is satisfied by one, which is how a presence check reported 400/400 on
    null values."""
    value = payload.get(key)
    return value if isinstance(value, dict) else {}


def _int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def derive(payload: dict[str, Any], recorder: InvestigationRecorder) -> None:
    """Record the alert investigation's chain. Never raises."""
    entity = _obj(payload, "entity")
    host = str(entity.get("host") or "").strip()
    user = str(entity.get("user") or "").strip()
    exclusions = _obj(payload, "exclusions")
    extraction = _obj(payload, "extraction")
    prior = _obj(payload, "prior_investigations")
    summary = _obj(payload, "summary")
    attack = _obj(payload, "attack_assessment")
    log_context = _obj(payload, "log_context")

    # 1 ── why this investigation exists. The gate, as a claim.
    subject = host or user or "no host or account"
    if host and user:
        subject = f"{host} and the account {user}"
    recorder.step(
        T.ALERT_WHY,
        "Why does this investigation exist?",
        source="local", target="intake",
        verdict="opened", cost=_FREE,
        fields={"source_text": str(payload.get("source") or "an unnamed sender"),
                "subject_text": subject},
        warrant={"exclusions_applied": _int(exclusions.get("applied")),
                 "exclusion_list_size": _int(exclusions.get("list_size")),
                 "suppressed": payload.get("suppressed_by_exclusion")},
    )

    # 2 ── extraction
    investigable = _int(extraction.get("investigable_total"))
    if investigable:
        recorder.step(
            T.ALERT_EXTRACT,
            "What in the alert text can be investigated?",
            source="local", target="indicator extraction",
            verdict="observed", cost=_FREE,
            fields={"investigable": investigable,
                    "characters": _int(extraction.get("characters")),
                    "excluded": _int(extraction.get("excluded_total"))},
        )
    else:
        recorder.step(
            T.ALERT_EXTRACT_NONE,
            "What in the alert text can be investigated?",
            source="local", target="indicator extraction",
            verdict="none", cost=_FREE, fields={},
        )

    # 3 ── what we already knew
    matched = _int(prior.get("matched"))
    if matched:
        recorder.step(
            T.ALERT_PRIOR, "What did this platform already know?",
            source="local", target="prior investigations",
            verdict="observed", cost=_FREE,
            fields={"prior": matched},
            warrant={"checked": _int(prior.get("checked")),
                     "max_age_days": prior.get("max_age_days"),
                     "reuse_enabled": prior.get("reuse_enabled")},
        )
    else:
        recorder.step(
            T.ALERT_PRIOR_NONE, "What did this platform already know?",
            source="local", target="prior investigations",
            verdict="none", cost=_FREE, fields={},
            warrant={"checked": _int(prior.get("checked"))},
        )

    # 4 ── indicator enrichment. The quota spend.
    investigated = _int(summary.get("indicators_investigated"))
    if investigated:
        recorder.step(
            T.ALERT_INDICATORS,
            "What do external sources say about these indicators?",
            source="external", target="indicator pipeline",
            verdict=str(summary.get("overall_verdict") or "unknown"),
            cost={"external_calls": investigated},
            fields={"investigated": investigated,
                    "reused": _int(summary.get("indicators_reused")),
                    "malicious": _int(summary.get("malicious_indicators")),
                    "suspicious": _int(summary.get("suspicious_indicators"))},
        )
    elif investigable:
        # Only when there WAS something to investigate. With nothing
        # extracted, "every one extracted was either excluded or already
        # known" asserts a reason that is false, and step 2 has already made
        # the claim — two steps disagreeing about the same fact.
        recorder.step(
            T.ALERT_INDICATORS_NONE,
            "What do external sources say about these indicators?",
            source="external", target="indicator pipeline",
            verdict="none", cost=_FREE, fields={},
        )

    # 5 ── the host's own logs. Eight kinds, from the measured statuses.
    _log_step(recorder, payload, log_context, host)

    # 6 ── ATT&CK
    # `techniques` is a list of OBJECTS, not strings — element keys listed:
    # id, name, tactic, tactics, status, known, confidence, evidence,
    # evidenceable, explanation, url. `str(t)` rendered the whole dict into
    # the sentence. Listing a section's keys is not enough when a value is a
    # collection: the element shape needs listing too (README rule 19).
    techniques = []
    for item in (attack.get("techniques") or []):
        if isinstance(item, dict):
            label = str(item.get("id") or "").strip()
            name = str(item.get("name") or "").strip()
            if label and name:
                techniques.append(f"{label} {name}")
            elif label or name:
                techniques.append(label or name)
        elif str(item).strip():
            techniques.append(str(item).strip())
    if techniques:
        recorder.step(
            T.ALERT_ATTACK, "Which adversary techniques does this match?",
            source="local", target="attack assessment",
            verdict="observed", cost=_FREE,
            fields={"techniques": techniques},
            warrant={"method": attack.get("method"),
                     "confirmed_count": _int(attack.get("confirmed_count")),
                     "evidence_available": attack.get("evidence_available"),
                     "detection_claimed": attack.get("detection_claimed")},
        )
    else:
        recorder.step(
            T.ALERT_ATTACK_NONE, "Which adversary techniques does this match?",
            source="local", target="attack assessment",
            verdict="none", cost=_FREE, fields={},
            warrant={"method": attack.get("method")},
        )


def _log_step(recorder: InvestigationRecorder, payload: dict[str, Any],
              log_context: dict[str, Any], host: str) -> None:
    """One of eight claims about the host's logs, chosen by measured status."""
    question = "What else was happening on the host around the alert?"
    started = str(payload.get("started_at") or payload.get("created_at") or "")

    if not log_context:
        # Before 2026-09-21 the feature did not exist. That is out_of_scope —
        # none was ever gathered — and NOT check_failed, which would assert a
        # collection that was attempted and failed. 0 post-cutover runs with a
        # host lack the object, so this branch is historical by construction.
        if started and started[:10] < LOG_CONTEXT_FROM:
            recorder.step(
                T.ALERT_LOGS_PREDATES, question,
                source="opensearch", absence_kind="out_of_scope",
                absence_reason=(
                    f"Log-context collection began on {LOG_CONTEXT_FROM}; this "
                    f"investigation ran before it, so none was ever gathered."),
                cost=_FREE, fields={"started_text": LOG_CONTEXT_FROM},
            )
            return
        recorder.step(
            T.STEP_NOT_ASKED, question,
            source="opensearch", absence_kind="check_failed",
            absence_reason=("No log context was recorded for this run, and it "
                            "does not predate collection."),
            cost=_FREE,
            fields={"question_text": question,
                    "reason": "no log context was recorded for this run."},
        )
        return

    status = str(log_context.get("status") or "").strip().lower()
    logs = _int(log_context.get("log_count"))
    window = log_context.get("window") if isinstance(log_context.get("window"), dict) else {}
    truncated = bool(log_context.get("truncated"))
    at_cap = logs >= _int((log_context.get("sources") or {}).get("max_hits"), 500)
    warrant = {
        "status": status, "log_count": logs,
        "window_complete": window.get("complete"),
        "window_start": window.get("start"), "window_end": window.get("end"),
        "covered_until": window.get("covered_until"),
        "truncated": truncated,
        "consistency_absence": (log_context.get("sources") or {}).get("consistency_absence"),
    }
    common = dict(source="opensearch", target="wazuh alert indices",
                  cost={"external_calls": 1}, warrant=warrant)

    if status == "skipped" or (not host and status in ("skipped", "unavailable")):
        recorder.step(T.ALERT_LOGS_NO_HOST, question,
                      absence_kind="out_of_scope",
                      absence_reason=("The alert names no host, so there is no "
                                      "window to read."),
                      source="opensearch", target="wazuh alert indices",
                      cost=_FREE, fields={})
        return
    if status == "unavailable":
        recorder.step(T.ALERT_LOGS_UNAVAILABLE, question,
                      absence_kind="check_failed",
                      absence_reason=str(log_context.get("reason")
                                         or "The log store could not be read."),
                      **common, fields={"host": host or "this host"})
        return
    if status == "empty":
        # Asked, and the window held nothing. `never_observed`, not a failure:
        # calling a real negative an error is false exculpation inverted.
        recorder.step(T.ALERT_LOGS_EMPTY, question,
                      absence_kind="never_observed",
                      absence_reason=("The window was read and held no events. "
                                      "This is a measured negative, not a "
                                      "failure to look."),
                      **common, fields={"host": host or "this host"})
        return

    fields = {"host": host or "this host", "logs": logs}
    if status == "collected" and window.get("complete") is not False:
        recorder.step(T.ALERT_LOGS_COLLECTED, question, verdict="observed",
                      **common, fields=fields)
    elif truncated and at_cap:
        recorder.step(T.ALERT_LOGS_PARTIAL_AT_CAP, question, verdict="observed",
                      absence_kind="lower_bound",
                      absence_reason=(f"{logs:,} events is the row limit, so "
                                      f"there were more than were read."),
                      **common, fields=fields)
    elif truncated:
        recorder.step(T.ALERT_LOGS_PARTIAL_TRUNCATED, question,
                      verdict="observed", **common, fields=fields)
    else:
        recorder.step(T.ALERT_LOGS_PARTIAL_WINDOW, question, verdict="observed",
                      **common, fields=fields)
