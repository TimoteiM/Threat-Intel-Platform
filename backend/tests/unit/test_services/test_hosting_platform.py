"""A platform is not malicious because one of its tenants is."""

from app.services.decision_engine import build_decision_report
from app.services.hosting_platform_service import (
    evidence_is_about,
    host_of,
    is_platform_apex,
)

PHISH_SCAN = {
    "verdict": "malicious",
    "score": 100,
    "tags": ["phishing"],
    "page_url": "https://hstephan-create.github.io/2-play/",
}
CLEAN_VT = {"found": True, "malicious_count": 0, "suspicious_count": 0, "total_vendors": 91}


def _decide(domain, **evidence):
    return build_decision_report({"domain": domain, "vt": CLEAN_VT, **evidence}, "domain")


def test_the_public_suffix_list_tells_a_registry_from_a_site():
    assert is_platform_apex("github.io") is True
    assert is_platform_apex("pages.dev") is True
    assert is_platform_apex("blogspot.com") is True
    assert is_platform_apex("hstephan-create.github.io") is False
    assert is_platform_apex("google.com") is False


def test_a_tenants_phishing_page_does_not_condemn_the_platform():
    """github.io scored 90 — malicious, high confidence — on a URLScan verdict
    for https://hstephan-create.github.io/2-play/, somebody else's phishing
    page, while VirusTotal was 0 of 91 and the narrative said in as many words
    that this does not establish the platform is malicious."""
    decision = _decide("github.io", urlscan=PHISH_SCAN)

    assert decision["classification"] != "malicious"
    assert decision["risk_score"] < 50


def test_the_tenant_is_still_named_in_the_evidence():
    """Not counted is not the same as hidden. An analyst must be able to see
    that a site on this platform is phishing."""
    decision = _decide("github.io", urlscan=PHISH_SCAN)

    joined = " ".join(decision["key_evidence"])
    assert "hstephan-create.github.io" in joined
    assert "not counted" in joined.lower()


def test_the_same_verdict_on_the_domain_itself_still_lands():
    """The guard must not blunt a real detection."""
    own_scan = {**PHISH_SCAN, "page_url": "https://evil-site.com/login"}

    decision = _decide("evil-site.com", urlscan=own_scan)

    assert decision["classification"] in {"malicious", "suspicious"}
    assert decision["risk_score"] >= 50


def test_a_subdomain_of_an_ordinary_domain_still_counts_against_it():
    """evil.corp.com is corp.com's problem; corp.com is not a registry."""
    sub_scan = {**PHISH_SCAN, "page_url": "https://evil.corp.com/login"}

    assert evidence_is_about("evil.corp.com", "corp.com") is True

    decision = _decide("corp.com", urlscan=sub_scan)
    assert decision["classification"] in {"malicious", "suspicious"}


def test_crowded_infrastructure_is_not_a_finding_about_a_platform():
    """github.io resolves to four addresses shared by every Pages site and is
    registered through MarkMonitor with thousands of siblings. Both were being
    scored as weak signals of compromise."""
    decision = _decide(
        "github.io",
        infrastructure_pivot={"shared_hosting_detected": True},
        signals=[{"id": "sig_shared_hosting"}, {"id": "sig_registrant_pivot"}],
    )

    joined = " ".join(decision["key_evidence"] + (decision.get("recommended_steps") or []))
    assert "hosting platform" in joined.lower()
    assert decision["classification"] != "malicious"


def test_host_of_reads_the_hostname_out_of_a_url():
    assert host_of("https://hstephan-create.github.io/2-play/") == "hstephan-create.github.io"
    assert host_of("") == ""
