from app.services.url_lexical_ml_service import (
    assess_url_lexical_risk,
    extract_url_lexical_features,
)


def test_extract_features_flags_ip_and_suspicious_tld() -> None:
    features = extract_url_lexical_features("http://192.168.1.10/login?verify=account")
    assert features["has_ip_host"] == 1.0
    assert features["has_sensitive_keyword"] == 1.0
    assert features["query_param_count"] >= 1.0


def test_assess_url_lexical_risk_high_for_obvious_phishing_pattern() -> None:
    result = assess_url_lexical_risk(
        "http://secure-update-account-login.verify-paypa1-example.top/auth?session=12345"
    )
    assert result["enabled"] is True
    assert result["model_source"] == "built_in"
    assert result["score"] >= 0.75
    assert result["label"] == "high"


def test_assess_url_lexical_risk_low_for_benign_reference() -> None:
    result = assess_url_lexical_risk("https://www.w3.org/1999/xhtml/")
    assert result["enabled"] is True
    assert result["score"] <= 0.45
    assert result["label"] in {"low", "medium"}


def test_assess_url_lexical_risk_fallbacks_to_built_in_when_model_missing() -> None:
    result = assess_url_lexical_risk(
        "https://example.com",
        model_path_override="C:/does-not-exist/url_model.json",
    )
    assert result["enabled"] is True
    assert result["model_source"] == "built_in"
    assert "error" in result
