"""Whether this observable is worth a sandbox detonation.

ANY.RUN is the most expensive thing this platform does. Measured across stored
investigations it averages 111 seconds and reaches 458, it holds one of three
licence keys that each allow 300 requests a month, and only one submission may
run at a time — so a second alert queues behind the first for the whole
analysis.

The obvious gate is "detonate when something else already called it bad", and
it is wrong. Of the malicious and suspicious investigations that had sandbox
evidence, 16 were flagged by ANY.RUN *alone* — VirusTotal clean, no feed
listing — and they are exactly the shapes reputation misses: a tunnelling
service (photography-buzz.at.ply.gg), dynamic DNS (darkcoder2000.homeip.net),
an abuse-heavy TLD (sofiosu.cfd). A gate keyed on other tools agreeing would
have skipped every one of them, which is to say it would run the sandbox when
it is least needed and skip it when it is most.

So the question is inverted. Detonate when nothing else could settle the
verdict; skip when something already has — in either direction. A host that
five engines call malicious is already blockable, and a decade-old domain that
ninety engines cleared with no login form on it has nothing left to resolve.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from app.services.decision_engine import _is_high_confidence_http_signal
from app.utils.domain_utils import extract_registered_domain

logger = logging.getLogger(__name__)

# Enough engines agreeing that the answer is settled and a detonation would only
# confirm it. Deliberately the same bar the decision engine treats as decisive.
SETTLED_MALICIOUS_ENGINES = 5

# Below this many engines, "no detections" is silence rather than a clearance —
# the same distinction the community-feed rule draws.
AUTHORITATIVE_PANEL = 20

# A domain old enough that its age is evidence. Phishing infrastructure is
# registered days before a campaign; a year of history is not that.
ESTABLISHED_DOMAIN_DAYS = 365

# Under this, age is itself a reason to look — the strongest single predictor
# this platform has, and reputation has not had time to form.
NEWLY_REGISTERED_DAYS = 30


@dataclass(frozen=True)
class SandboxDecision:
    """Whether to detonate, and the one clause that decided it."""

    run: bool
    reason: str

    def as_dict(self) -> dict[str, Any]:
        return {"run": self.run, "reason": self.reason}


def should_detonate(
    evidence: dict[str, Any],
    *,
    observable_type: str,
    excluded: bool = False,
    manual: bool = False,
) -> SandboxDecision:
    """Is a sandbox run worth its cost for this observable?

    `evidence` is what the fast collectors have already produced. The caller
    must not invoke this before they have finished — the whole point is to
    decide with their answers in hand.

    `manual` says an analyst asked for this investigation by hand. The gate
    exists to stop automated volume spending a licence budget on questions
    nothing was asking; a person typing a domain into the box *is* the question,
    and answering it with "we decided not to look" is the wrong answer. Batches
    and alert-spawned investigations are not manual — they are the volume.
    """
    kind = str(observable_type or "").strip().lower()

    if manual:
        # First, ahead of every other clause including the exclusion list: if
        # someone explicitly investigated their own corporate domain, they want
        # the sandbox, not a reminder that it is on the allowlist.
        return SandboxDecision(True, "requested_by_analyst")

    if excluded:
        # The analyst has already said this is theirs and benign. Detonating it
        # spends a licence request to confirm a decision a human made.
        return SandboxDecision(False, "excluded_by_analyst")

    if kind in {"hash", "file"}:
        # A file has to be detonated. Reputation on an unknown hash is silence,
        # and silence about a binary someone was sent is not a clearance.
        return SandboxDecision(True, "file_requires_detonation")

    vt = evidence.get("vt") or {}
    vt_found = bool(vt.get("found"))
    vt_malicious = int(vt.get("malicious_count") or 0)
    vt_suspicious = int(vt.get("suspicious_count") or 0)
    vt_total = int(vt.get("total_vendors") or 0)

    feeds = evidence.get("threat_feeds") or {}
    feed_listed = bool(
        feeds.get("openphish_listed")
        or (feeds.get("threatfox_matches") or [])
        or ((feeds.get("google_safe_browsing") or {}).get("listed"))
    )

    if vt_malicious >= SETTLED_MALICIOUS_ENGINES or feed_listed:
        # Already condemned by sources that agree. The verdict is actionable
        # without a detonation, and a sandbox that returned CLEAN here would not
        # change it — this platform already treats a clean sandbox over a
        # malicious reputation as incomplete coverage, not as an acquittal.
        return SandboxDecision(False, "already_condemned")

    whois = evidence.get("whois") or {}
    age = whois.get("domain_age_days")
    if age is not None and age <= NEWLY_REGISTERED_DAYS:
        # Registered days ago. Reputation cannot have formed yet, so the sandbox
        # is the only source that can say anything at all.
        return SandboxDecision(True, "newly_registered")

    http = evidence.get("http") or {}
    has_login = bool(http.get("has_login_form"))
    # Only the signals the decision engine already treats as high confidence.
    # "Any phishing indicator" is far too loose to gate on: a third-party brand
    # reference is present on ordinary sites, and live testing detonated
    # iana.org on it. Reusing that distinction rather than inventing a second
    # one keeps the gate and the verdict reading the same evidence the same way.
    strong_signals = [
        signal for signal in (http.get("phishing_indicators") or [])
        if _is_high_confidence_http_signal(signal)
    ]
    if has_login or strong_signals:
        # A page asking for credentials, or posting them somewhere, is the case
        # a sandbox exists for: what it does *after* submission is invisible to
        # every static source.
        return SandboxDecision(True, "credential_or_brand_signals")

    if not vt_found or vt_total < AUTHORITATIVE_PANEL:
        # Nobody has looked, or too few did for their silence to mean anything.
        # This is the unresolved case, and it is where the sandbox earned its 16
        # sole detections.
        return SandboxDecision(True, "no_reputation_available")

    # Age belongs to the registration, and a subdomain is not the registration.
    # `photography-buzz.at.ply.gg` was called malicious by the sandbox and by
    # nothing else; `ply.gg` is an old, clean tunnelling service, so judging the
    # child by the parent's history skipped exactly the detonation that found
    # it. The same holds for every shared-hosting and dynamic-DNS provider:
    # their age is real and tells you nothing about what is hosted under them.
    host = str(evidence.get("target_domain") or evidence.get("domain") or "").strip().lower()
    registrable = extract_registered_domain(host) if host else ""
    is_subdomain = bool(host and registrable and host != registrable)

    if (
        vt_found
        and vt_malicious == 0
        and vt_suspicious == 0
        and age is not None
        and age > ESTABLISHED_DOMAIN_DAYS
        and not is_subdomain
    ):
        # An established host that a full panel cleared, with no credential form
        # and nothing else flagging it. There is no question left for a
        # detonation to answer.
        return SandboxDecision(False, "established_and_clean")

    # Anything else is genuinely unresolved: a panel that found it, said
    # nothing, and a domain not old enough for that silence to be reassuring.
    return SandboxDecision(True, "unresolved")
