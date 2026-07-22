"""Normalize legacy internal provider keys for analyst-facing payloads."""


def normalize_anyrun_branding(value):
    """Hide the hybrid_analysis storage name used by the ANY.RUN integration."""
    if isinstance(value, dict):
        return {key: normalize_anyrun_branding(item) for key, item in value.items()}
    if isinstance(value, list):
        return [normalize_anyrun_branding(item) for item in value]
    if isinstance(value, str):
        return (
            value.replace("hybrid_analysis_digest", "anyrun")
            .replace("hybrid_analysis", "anyrun")
            .replace("Hybrid Analysis", "AnyRun")
            .replace("HybridAnalysis", "AnyRun")
            .replace("HYBRID ANALYSIS", "ANY.RUN")
        )
    return value
