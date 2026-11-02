"""Telling a hosting platform apart from a site built on one.

github.io scored 90 — malicious, high confidence — on evidence that was never
about github.io. URLScan had returned "malicious, score 100, tags: phishing"
for

    https://hstephan-create.github.io/2-play/

which is somebody's phishing page on GitHub Pages. VirusTotal was 0 malicious
of 91, the page had no login form, no cloaking and no malicious redirect, and
the analyst narrative said in as many words that this "does not establish that
the github.io platform domain itself is malicious". The verdict said it anyway.

The distinction is not a judgement call: the Public Suffix List already records
which names are registries rather than sites. `github.io`, `pages.dev`,
`blogspot.com`, `azurewebsites.net`, `web.app` are suffixes under which anyone
may register — a name with no registrable part of its own. `hstephan-create.github.io`
has one, and is a site.

Two consequences, both of which the github.io report got wrong:

  * Evidence about a *subdomain* is not evidence about the platform. Every
    hosting provider has malicious tenants; that is a property of hosting, not
    of the provider.
  * Signals that mean "crowded infrastructure" — shared hosting, a registrar
    pivot reaching many domains — are the definition of a platform rather than
    a finding about one. MarkMonitor and a /24 full of GitHub Pages addresses
    describe what github.io is.

The list is the bundled Public Suffix snapshot, read offline; nothing here
reaches the network.
"""

from __future__ import annotations

import logging
from functools import lru_cache
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)


@lru_cache(maxsize=1)
def _extractor():
    """The Public Suffix List, private section included, from the bundle.

    `include_psl_private_domains` defaults to False, and the platform suffixes
    are all in the private section — with the default, `github.io` reads as the
    ordinary domain "github" under ".io" and none of this works.

    `suffix_list_urls=()` keeps it offline: this runs inside an estate whose
    egress is deliberately narrow, and a scoring rule must not depend on
    fetching a list at request time.
    """
    import tldextract

    return tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)


def _clean(value: str | None) -> str:
    text = str(value or "").strip().lower()
    if "://" in text:
        text = urlsplit(text).hostname or ""
    return text.strip(".")


def host_of(url: str | None) -> str:
    """The hostname a URL points at, or "" when there isn't one."""
    text = str(url or "").strip()
    if not text:
        return ""
    if "://" not in text:
        text = "//" + text
    try:
        return (urlsplit(text).hostname or "").strip(".").lower()
    except ValueError:
        return ""


def is_platform_apex(domain: str | None) -> bool:
    """True when the whole name is a public suffix — a registry, not a site.

    github.io, pages.dev, blogspot.com, co.uk -> True
    hstephan-create.github.io, google.com     -> False
    """
    name = _clean(domain)
    if not name:
        return False
    try:
        parts = _extractor()(name)
    except Exception as exc:  # noqa: BLE001 — never fail scoring over a lookup
        logger.warning("Public suffix lookup failed for %r: %s", name, exc)
        return False
    return not parts.domain and bool(parts.suffix)


def registrable(domain: str | None) -> str:
    """The registrable name, e.g. hstephan-create.github.io -> the same."""
    name = _clean(domain)
    if not name:
        return ""
    try:
        parts = _extractor()(name)
    except Exception:  # noqa: BLE001
        return name
    return parts.top_domain_under_public_suffix or parts.registered_domain or name


def evidence_is_about(observed_host: str | None, investigated: str | None) -> bool:
    """Whether a finding on `observed_host` is a finding about `investigated`.

    Same host: always. A subdomain of an ordinary domain: yes — evil.corp.com
    is corp.com's problem. A subdomain of a *platform*: no, because that is a
    different customer, and a platform with no malicious tenants has never
    existed.

    An absent host means the evidence did not say what it was about, which is
    treated as being about the investigated domain — the collectors that
    report a bare verdict were asked about it directly.
    """
    target = _clean(investigated)
    observed = _clean(observed_host)
    if not target or not observed or observed == target:
        return True
    if not observed.endswith("." + target):
        return False
    return not is_platform_apex(target)
