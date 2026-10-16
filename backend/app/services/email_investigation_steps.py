"""Derive the email investigation's chain from what the pipeline returned.

**Derived, not instrumented, and that is a choice with a reason.** Every
stage's output is already in the completed payload — `attachment_inspection`,
`file_content`, `url_triage`, `sender_domain`, `sender_ip`, `urls`,
`email_anyrun`, `final_risk`, `resolution`. Threading a recorder through
`run_email_indicator_checks` would mean editing the hottest path in the
product to learn what it already tells us.

The more important consequence is the opposite of a shortcut. Because the
**expected** stages are declared here as a list, a stage that produced nothing
is a step with `check_failed` rather than a gap in the chain. Instrumenting
would only record stages that ran; deriving against a declared set records the
ones that did not. Same reasoning as deriving the expected source set from the
registry instead of from a list of what answered.

What it costs, stated: a derived step has no per-stage duration unless the
payload carries one, so `duration_ms` is null for most of them rather than
invented. The total is on the run.
"""

from __future__ import annotations

from typing import Any

from app.services import investigation_step_templates as T
from app.services.investigation_recorder import InvestigationRecorder

#: Local stages cost nothing external; the rest spend something. Carried so
#: the gate in slice 4 can be evaluated against real numbers rather than
#: guesses about which steps are expensive.
_FREE: dict[str, Any] = {}


def _present(value: Any) -> bool:
    """Whether a stage produced anything. `{}` and `[]` are *not* output."""
    if value is None:
        return False
    if isinstance(value, (dict, list, str)):
        return bool(value)
    return True


def derive(payload: dict[str, Any], recorder: InvestigationRecorder) -> None:
    """Record the eight steps of a completed email investigation.

    Never raises: every stage is recorded through the recorder, which is
    fail-open per step and records its own failures loudly.
    """
    checks = dict(payload.get("indicator_checks") or {})

    # 1 ── parse
    urls = list(payload.get("urls") or [])
    attachments = list(payload.get("attachments") or [])
    sender_domain = payload.get("sender_domain")
    # Through the pluralisation helper, not an f-string. "1 attachments" is
    # the kind of thing a declared helper exists to prevent, and building the
    # phrase by hand routed around it.
    from app.services.investigation_step_templates import plural

    kinds: list[str] = []
    if urls:
        kinds.append(plural(len(urls), "link"))
    if attachments:
        kinds.append(plural(len(attachments), "attachment"))
    if sender_domain:
        kinds.append("a sender domain")
    if payload.get("sender_ip"):
        kinds.append("a sending address")
    found = len(urls) + len(attachments) + (1 if sender_domain else 0)
    if found:
        recorder.step(
            T.EMAIL_PARSE,
            "What indicators does this message carry?",
            source="local", target="email parser",
            observables_found=[*urls, *[a.get("sha256") for a in attachments
                                        if isinstance(a, dict)]],
            verdict="observed", cost=_FREE,
            fields={"found": found, "kinds": kinds},
        )
    else:
        recorder.step(
            T.EMAIL_PARSE_NO_INDICATORS,
            "What indicators does this message carry?",
            source="local", target="email parser", verdict="none",
            cost=_FREE, fields={},
        )

    # 2 ── attachment structure
    inspection = checks.get("attachment_inspection")
    if not attachments:
        recorder.step(T.EMAIL_ATTACHMENT_INSPECT_NONE,
                      "What are the attachments?",
                      source="local", target="attachment inspector",
                      verdict="none", cost=_FREE, fields={})
    elif _present(inspection):
        findings = _inspection_findings(inspection)
        # "found nothing structurally unexpected" is a different claim from
        # "found these things", so it is a different template rather than the
        # same sentence with "no structural findings" interpolated as if it
        # were an item in a list.
        recorder.step(
            T.EMAIL_ATTACHMENT_INSPECT if findings
            else T.EMAIL_ATTACHMENT_INSPECT_CLEAN,
            "What are the attachments?",
            source="local", target="attachment inspector",
            response=inspection, verdict="observed", cost=_FREE,
            fields={"attachments": len(attachments), "findings": findings},
        )
    else:
        _not_asked(recorder, T.EMAIL_ATTACHMENT_INSPECT,
                   "What are the attachments?",
                   "the inspector produced no output for this message.")

    # 3 ── attachment content
    content = checks.get("file_content")
    if not attachments:
        pass  # Covered by step 2's "no attachments" claim; not a second one.
    elif _present(content) and (content or {}).get("files"):
        files = list((content or {}).get("files") or [])
        recorder.step(
            T.EMAIL_ATTACHMENT_CONTENT,
            "What do the attachments say?",
            source="local", target="file content reader",
            response=content, verdict="observed", cost=_FREE,
            fields={"files": len(files),
                    # The real keys, read from a stored payload: `path` and
                    # `kind`. `filename`/`name`/`type` — which this guessed —
                    # do not exist, so every file rendered as "an unnamed
                    # file" while the payload had its path all along.
                    # `path` can carry an internal artefact suffix —
                    # "…CCRM.pdf!stream-22" rendered in production. The part
                    # after "!" is the extractor's own stream id, which is a
                    # fact about our parser rather than about the attachment,
                    # so the reader gets the file and the detail stays in the
                    # payload.
                    "summaries": [
                        str(f.get("path") or f.get("kind")
                            or "an unnamed file").split("!")[0]
                        for f in files if isinstance(f, dict)]},
        )
    else:
        limits = list((content or {}).get("limitations") or [])
        recorder.step(
            T.EMAIL_ATTACHMENT_CONTENT_UNREADABLE,
            "What do the attachments say?",
            source="local", target="file content reader",
            absence_kind="check_failed",
            absence_reason="The attachment contents could not be read.",
            cost=_FREE,
            fields={"reason": (limits[0] if limits else "no reason was recorded.")},
        )

    # 4 ── URL triage
    triage = checks.get("url_triage")
    if not urls:
        recorder.step(T.EMAIL_URL_TRIAGE_NONE,
                      "Which links are worth paying to check?",
                      source="local", target="url triage", verdict="none",
                      cost=_FREE, fields={})
    elif _present(triage):
        # The real key names, read from a stored run. `selected_count` and
        # `seen_count` — which the first version of this guessed at — do not
        # exist, and `.get()` returning None rendered "0 worth checking"
        # beside a step that then asked six sources. A guessed key name is a
        # zero that reads as a measurement.
        selected = (triage or {}).get("looked_up")
        if selected is None:
            selected = len((triage or {}).get("selected") or [])
        seen = (triage or {}).get("urls_in_email") or len(urls)
        recorder.step(
            T.EMAIL_URL_TRIAGE,
            "Which links are worth paying to check?",
            source="local", target="url triage", response=triage,
            observables_found=urls, verdict="observed", cost=_FREE,
            fields={"seen": seen, "selected": selected},
        )
    else:
        _not_asked(recorder, T.EMAIL_URL_TRIAGE,
                   "Which links are worth paying to check?",
                   "the triage stage produced no output.")

    # 5 ── external enrichment. The quota spend.
    sources = [name for name in
               ("sender_domain", "sender_ip", "urls", "attachments",
                "email_security", "content_ml")
               if _present(checks.get(name))]
    if sources:
        recorder.step(
            T.EMAIL_ENRICH,
            "What do external sources say about these indicators?",
            source="external", target=", ".join(sources),
            verdict="observed",
            cost={"external_calls": len(sources)},
            # No `elapsed_ms`. A derived step has no per-stage duration, and
            # the first version of this passed 0, which rendered "in 0 ms" —
            # an invented measurement, which is worse than an absent one.
            fields={"sources": len(sources),
                    "observables": found,
                    "source_names": sources},
        )
    else:
        _not_asked(recorder, T.EMAIL_ENRICH,
                   "What do external sources say about these indicators?",
                   "no external source returned anything for this message.")

    # 6 ── sandbox
    sandbox = checks.get("email_anyrun") or {}
    if sandbox.get("checked"):
        recorder.step(
            T.EMAIL_SANDBOX,
            "What does the message do when it is opened?",
            source="anyrun", target="email sandbox", response=sandbox,
            verdict=str(sandbox.get("verdict") or "unknown"),
            cost={"sandbox_credits": 1},
            fields={"verdict_text": str(sandbox.get("verdict") or "no verdict"),
                    "artifacts": sandbox.get("artifact_count") or 0},
        )
    else:
        recorder.step(
            T.EMAIL_SANDBOX_SKIPPED,
            "What does the message do when it is opened?",
            source="anyrun", target="email sandbox",
            absence_kind="out_of_scope",
            absence_reason=("A sandbox run was not requested for this "
                            "investigation."),
            cost=_FREE, fields={},
        )

    # 7 ── risk aggregation
    risk = checks.get("final_risk") or {}
    drivers = _risk_drivers(risk)
    if _present(risk) and drivers:
        recorder.step(
            T.EMAIL_RISK,
            "Taken together, what do these answers amount to?",
            source="local", target="risk aggregation", response=risk,
            # NOT a verdict. Two stages writing verdicts into their own
            # columns with nothing arbitrating is backlog 25's shape in a
            # third domain, and here the contest is not even close: this
            # column held a constant. The scorer produces evidence; the
            # interpretation stage declares the verdict.
            verdict=None,
            cost=_FREE,
            # Coverage is the score's WARRANT, not part of its ratio. Rule 22:
            # stated beside the claim, with its own boundary.
            warrant={"coverage": _risk_coverage(risk),
                     "observed_range": list(RISK_SCORE_OBSERVED[:2]),
                     "observed_over_runs": RISK_SCORE_OBSERVED[2],
                     "components": (risk or {}).get("components"),
                     "claim_excludes": (
                         "The score is what the seven inputs summed to. It "
                         "says nothing about how many of them were able to "
                         "answer — that is the coverage line — and a low "
                         "score on thin coverage is uncertain rather than "
                         "safe."),
                     },
            fields={"verdict_text": _risk_text(risk), "drivers": drivers},
        )
    elif _present(risk):
        # A score with nothing contributing to it is a different claim from a
        # score with drivers, so it is a different template — not the same
        # sentence with an empty list bolted into it.
        recorder.step(
            T.EMAIL_RISK_NO_DRIVERS,
            "Taken together, what do these answers amount to?",
            source="local", target="risk aggregation", response=risk,
            verdict=None, cost=_FREE,
            warrant={"coverage": _risk_coverage(risk),
                     "observed_range": list(RISK_SCORE_OBSERVED[:2]),
                     "components": (risk or {}).get("components")},
            fields={"verdict_text": _risk_text(risk)},
        )
    else:
        _not_asked(recorder, T.EMAIL_RISK,
                   "Taken together, what do these answers amount to?",
                   "no aggregate risk was produced.")

    # 8 ── the one model call
    resolution = payload.get("resolution") or {}
    if _present(resolution):
        verdict = str(resolution.get("overall_verdict")
                      or resolution.get("classification") or "unknown")
        signals = [s for s in (resolution.get("primary_signals") or [])
                   if str(s).strip()]
        recorder.step(
            T.EMAIL_INTERPRET,
            "What does this evidence mean?",
            source="model", target=str(payload.get("resolution_source") or "model"),
            verdict=verdict,
            cost={"model_calls": 1},
            # The verdict and confidence are structured; `primary_signals` is
            # model prose and is COUNTED, not interpolated. The signals
            # themselves render in the evidence sections, where they are
            # attributed to the model rather than to a template.
            fields={"verdict_text": verdict,
                    "confidence": str(resolution.get("confidence") or "unstated"),
                    "signals": len(signals)},
        )
    else:
        _not_asked(recorder, T.EMAIL_INTERPRET, "What does this evidence mean?",
                   "the interpretation step produced no resolution.")


def _not_asked(recorder: InvestigationRecorder, kind: str, question: str,
               reason: str) -> None:
    """A stage that produced nothing is a step, not a gap.

    Rendered as *No claim* with its reason. Dropping it would silently
    shorten the investigation and nobody could tell — which is the whole
    reason this chain exists.
    """
    recorder.step(
        T.STEP_NOT_ASKED, question,
        source="local", absence_kind="check_failed", absence_reason=reason,
        cost=_FREE, fields={"question_text": question, "reason": reason},
    )


def _inspection_findings(inspection: Any) -> list[str]:
    out: list[str] = []
    data = inspection if isinstance(inspection, dict) else {}
    for item in (data.get("files") or data.get("attachments") or []):
        if not isinstance(item, dict):
            continue
        name = str(item.get("filename") or item.get("name") or "a file")
        note = str(item.get("verdict") or item.get("real_type")
                   or item.get("type") or "inspected")
        out.append(f"{name} ({note})")
    return out


#: What this scorer has actually produced, with its date, because a score
#: without its population is a proportion without its denominator. Declared
#: and `calibrated_on_self`: measured over the 52 scored runs on 2026-10-16,
#: all of them from one small internal estate. Re-measure, do not trust.
RISK_SCORE_OBSERVED = (9, 27, 52, "2026-10-16")


def _risk_text(risk: Any) -> str:
    """The score beside its population. Coverage is a separate claim.

    This sentence has now been wrong three ways, and the third was mine:

    1. `low (score 14, …)` — a band that is a CONSTANT. 52 of 52 runs are
       `low`; the 35/70 thresholds have never been crossed.
    2. `…, confidence low` — the band renamed. Also constant, by a different
       route, so removing one and keeping the other removed nothing.
    3. `14 out of a reachable 32` — **backwards.** It removed a weight from
       the denominator whenever a sub-score was zero, which merges *the check
       ran and found nothing* with *the check could not run* — the two states
       this platform's whole convention exists to separate. The arithmetic
       consequence inverts the meaning:

           lexical 0.70 alone, nothing else run    ->  14 of 32  = 44%
           the same 0.70, with sandbox, infra and
           behaviour all running and finding zero  ->  14 of 100 = 14%

       The second file has strictly MORE exculpating evidence and reads as
       safer, correctly. The first has less information and read as more
       dangerous. Thin coverage means uncertain, not elevated — it is
       `check_failed` being rendered as risk, which is slice 3's
       `unknown`-is-not-`clean` rule inverted.

    So: **an input that ran and returned zero stays in the denominator — the
    file earned that zero** — and coverage comes out of the ratio entirely.
    The score is the claim; what could not contribute is its warrant, stated
    beside it under rule 22 rather than multiplied into it.
    """
    data = risk if isinstance(risk, dict) else {}
    score = data.get("risk_score")
    if score is None:
        return "no score was produced"
    low, high, n, when = RISK_SCORE_OBSERVED
    return (
        f"a composite score of {score} on a nominal 0-100 scale; across the "
        f"{n} runs this scorer has produced, values have ranged {low} to "
        f"{high} (measured {when}, on this estate only)"
    )


def _risk_coverage(risk: Any) -> str | None:
    """Which inputs could not contribute, as the score's warrant.

    Absent from `components` is the only *defensible* reading of "could not
    contribute" available in the record: `opencti_score` is missing entirely
    from 34 of 52 payloads, while `attachment_score` is present-and-zero on
    all 52 with its evidence section non-empty — which is a scorer question
    (backlog 38), not a coverage one, and must not be reported as missing
    coverage on a particular run.
    """
    data = risk if isinstance(risk, dict) else {}
    components = data.get("components") if isinstance(data.get("components"), dict) else {}
    weights = data.get("weights") if isinstance(data.get("weights"), dict) else {}
    if not components or not weights:
        return None
    missing = sorted(k for k in weights if k not in components)
    if not missing:
        return None
    lost = sum(float(weights.get(k) or 0.0) for k in missing)
    names = ", ".join(k.replace("_score", "") for k in missing)
    return (
        f"{len(missing)} of this scorer's {len(weights)} inputs could not "
        f"contribute at all on this run ({names}), carrying "
        f"{int(round(lost * 100))} of the nominal 100 points — so the score "
        f"is bounded below what the scale implies. Inputs that ran and "
        f"returned zero are NOT counted here; that is evidence, not absent "
        f"coverage."
    )


def _risk_drivers(risk: Any) -> list[str]:
    """The largest weighted contributors, named from discrete fields.

    This read `rationale` — which is **prose**: "No strong malicious signal;
    monitor and corroborate with external context". Interpolated into a
    sentence it produced a capital mid-clause and, worse, put a
    *recommendation* where a driver belongs. **A slot that can receive free
    text has the same hazard as a model**, which is the thing templates were
    chosen to avoid.

    `components` and `weights` are seven named scores, so the drivers are
    computed rather than quoted: contribution = score x weight, largest
    first, named by component. Nothing here can carry a sentence.
    """
    data = risk if isinstance(risk, dict) else {}
    components = data.get("components") or {}
    weights = data.get("weights") or {}
    if not isinstance(components, dict) or not components:
        return []

    contributions: list[tuple[float, str]] = []
    for name, score in components.items():
        try:
            value = float(score) * float(weights.get(name, 0) or 0)
        except (TypeError, ValueError):
            continue
        if value <= 0:
            continue
        label = str(name).replace("_score", "").replace("_", " ")
        contributions.append((value, f"{label} {value:.2f}"))
    contributions.sort(reverse=True)
    return [text for _value, text in contributions[:3]]
