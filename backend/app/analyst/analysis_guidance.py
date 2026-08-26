"""
Reasoning rules shared by every prompt that judges an alert.

These exist because the same misreadings kept reaching reports from different
prompts: a datacenter IP behind an OAuth token grant read as impossible travel,
a vendor risk score restated as our own verdict, a Group Policy logon script
folded into an attack chain, a "Decoded payload:" sentence that never produced
the payload.

Written once and composed into each prompt rather than pasted into four, because
a rule that is copied is a rule that will diverge — and prompt drift is invisible
until a report is wrong.

The blocks are separate so a prompt takes only what it can act on. Every one of
these costs tokens on every call, and the per-indicator analyst runs far more
often than the alert interpreter does.
"""

from __future__ import annotations

# ── 1. What an IP actually represents ────────────────────────────────────────
IP_ROLE_CLASSIFICATION = """
Classify what every IP represents before weighing it. Machine-generated
addresses look like adversary activity to a pattern matcher and are expected
behaviour of the systems that produced them. Reason about the system, not the
string.

For each IP or [IP_n] token, decide its role, and let the role govern its weight:
- End-user client — the human's actual source. Only these are relevant to
  geolocation or impossible-travel reasoning.
- Service / API backend — the source of a server-to-server call. OAuth access
  token grants, OIDC refresh grants, SAML assertions, MFA push delivery and
  cloud-app-proxied sessions originate from the provider's or application's
  infrastructure, not from the user. That IP is a datacenter by design and is
  NOT evidence of anomalous location or travel.
- Cloud / CDN egress — a well-known provider range (Cloudflare, AWS, Azure,
  Google, Akamai, Fastly and similar). As the source of an identity event this
  is almost always the service, a reverse proxy or a cloud-hosted client — not
  the end user and not an attacker, absent independent malicious corroboration.
- NAT / VPN / proxy egress — a shared corporate or ISP boundary. Many users
  share it, so it is not a per-user location signal.
- External actor — not explained by any of the above AND carrying independent
  malicious signal: a verified threat-feed hit, high abuse confidence, a known
  Tor exit, confirmed C2. Only this role justifies escalation on the IP alone.

Never read different IPs across a single authentication sequence as travel or
velocity anomalies when that sequence spans interactive login, MFA and token
refresh. Several IPs across those stages is the expected topology of modern
federated authentication such as Okta or Entra ID. Impossible-travel reasoning
applies only when two or more interactive human logins are themselves
geographically irreconcilable in the time available.
"""

# ── 2. Someone else's score is an input, not a conclusion ────────────────────
VENDOR_RISK_SCORES = """
Do not launder a vendor's risk score into your own verdict. Okta and Entra risk
levels, Silverfort allow/deny decisions, MFA "high risk" flags and any upstream
platform verdict are inputs to weigh, not conclusions to adopt. When one appears:
- State plainly which factors the vendor's engine fired on — new device, new
  ASN, new IP, velocity, unfamiliar location.
- Assess whether the underlying pattern actually justifies the score, given the
  IP roles above. A risk engine flagging "anomalous ASN/IP/location" on what is
  really a cloud-app or service backend is a known false-positive shape; say so.
- Never write "the verified verdict is malicious", or anything like it, as a
  self-justifying reason. Where an upstream verdict disagrees with the evidence
  in front of you, say so and explain the divergence. Never assert a malicious
  verdict and an absence of malicious evidence in the same breath.
"""

# ── 3. Patterns that are operations, not attacks ─────────────────────────────
KNOWN_BENIGN_PATTERNS = """
The following are operational or managed-environment behaviours. Treat them as
benign unless independent, externally corroborated malicious evidence is
present. Name the pattern and explain why it fits, rather than folding it into
an attack chain:
- Group Policy and logon scripts — gpscript.exe launching powershell.exe or
  cmd.exe to run a script from SYSVOL or a domain share, such as a cache-clear
  or drive-map script, is centrally managed configuration, not adversary
  execution.
- Silverfort / MFA "bad server" or denied Kerberos — a deny or "bad server"
  outcome is usually an operational gap, an unsupported or misconfigured target.
  Repeated denials against the same internal resource read as misconfiguration
  first.
- Windows Update and OS telemetry — traffic to *.windowsupdate.com,
  ctldl.windowsupdate.com, certificate trust list downloads and similar
  signed-OS destinations with no detections is routine.
- Signed system binaries with expected privileges — svchost.exe creating a
  service logon, a token carrying SeLoadDriverPrivilege and the like are normal
  OS behaviour absent a suspicious parent, injected code or an anomalous child.
- Generic or heuristic detection names on legitimate components — a detection
  name containing "Generic", "Heur", "Suspicious" or a vendor catch-all, matched
  against a recognisable OS update, signed system binary or known vendor
  installer, is a classic false-positive shape.

Naming one of these is not a reason to skip the alert. State what triggered it,
what it means, and the benign verdict with its reasoning.
"""

# ── 4. What the evidence shows happening ─────────────────────────────────────
ATTEMPTED_VS_SUCCESSFUL = """
Distinguish attempted from successful, and internal from external:
- Blocked, denied or redirected activity — a DNS block page, a rejected login, a
  policy-blocked request — is an attempt, not a successful connection, session or
  exfiltration. Say which one the evidence actually shows.
- Activity entirely between private or internal addresses materially lowers the
  likelihood of C2 or exfiltration. State the scope. The absence of a public
  destination is a finding, not a reason to escalate.
"""

# ── 5. No dangling promises ──────────────────────────────────────────────────
FINISH_EVERY_DECODE = """
Finish every decode you begin. If you say a payload decodes, or open any
"Decoded payload:" statement, include the actual decoded content in a code block
in the same response. Never end a sentence promising a decode — "...decodes to
the following hostname." — without the value. If a string cannot be decoded from
the evidence available, say that instead. Do not leave a dangling promise.
"""

# ── 6. One verdict, and reasoning that matches it ────────────────────────────
VERDICT_COHERENCE = """
Choose one verdict — benign, suspicious, malicious or inconclusive — and make the
reasoning match it. Do not assert a malicious verdict while stating there is no
malicious payload or confirmed compromise. If the strongest real signal is
"suspicious authentication activity", the verdict is suspicious, and the
reasoning should say what would be needed to confirm or clear it.
"""


def _join(*blocks: str) -> str:
    return "\n".join(block.strip("\n") for block in blocks)


# Everything, for the prompts that interpret a whole alert.
FULL_GUIDANCE = _join(
    IP_ROLE_CLASSIFICATION,
    VENDOR_RISK_SCORES,
    KNOWN_BENIGN_PATTERNS,
    ATTEMPTED_VS_SUCCESSFUL,
    FINISH_EVERY_DECODE,
    VERDICT_COHERENCE,
)

# For the per-indicator analyst: it judges one observable rather than an
# authentication narrative, so it gets the rules about weighing infrastructure
# and about staying coherent, and not the incident-shaped ones.
INDICATOR_GUIDANCE = _join(
    IP_ROLE_CLASSIFICATION,
    VENDOR_RISK_SCORES,
    KNOWN_BENIGN_PATTERNS,
    ATTEMPTED_VS_SUCCESSFUL,
    # It narrates encoded commands found in evidence, so it can promise a decode
    # and then not deliver one.
    FINISH_EVERY_DECODE,
    VERDICT_COHERENCE,
)

# For ATT&CK mapping: the failure there is mapping managed operations onto
# adversary techniques, and calling a blocked attempt a completed one.
TECHNIQUE_MAPPING_GUIDANCE = _join(
    # Included because the roles decide whether a technique is present at all:
    # a service backend or CDN egress address is not command-and-control, and
    # mapping T1071 or an exfiltration technique onto federated-auth traffic
    # invents an attack out of ordinary topology.
    IP_ROLE_CLASSIFICATION,
    KNOWN_BENIGN_PATTERNS,
    ATTEMPTED_VS_SUCCESSFUL,
)
