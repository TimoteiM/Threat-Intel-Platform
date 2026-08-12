"""The evidence bundle written to the agent's virtual filesystem, and digest.md."""

from __future__ import annotations

import json

from app.analyst.evidence_files import build, build_manifest, render_markdown

EVIDENCE = {
    # Scalars and the sections that get their own top-level file.
    "domain": "evil-phish.tk",
    "investigation_id": "inv-1",
    "observable_type": "domain",
    "target_domain": "paypal.com",
    "timestamps": {"started": "2026-08-01T00:00:00Z"},
    "artifact_hashes": {"screenshot.png": "ab" * 32},
    "signals": [{"id": "young_domain", "severity": "high", "description": "11 days old"}],
    "data_gaps": [{"id": "no_tls", "impact": "medium", "description": "handshake failed"}],
    # Collector sections.
    "vt": {"malicious_count": 9, "meta": {"status": "completed", "duration_ms": 120}},
    "whois": {"registrar": "NameCheap", "meta": {"status": "failed", "error": "timeout"}},
    # Derived: no meta, no recorded status.
    "final_risk": {"score": 82},
}


def _bundle():
    return build(
        EVIDENCE,
        investigation_id="inv-1",
        statuses={"vt": "completed", "whois": "failed"},
        digest_markdown="# Evidence digest\n\n- oriented\n",
        signals=EVIDENCE["signals"],
        data_gaps=EVIDENCE["data_gaps"],
        decision={"classification": "malicious"},
    )


def test_bundle_layout_is_exactly_the_documented_paths():
    assert set(_bundle()) == {
        "/investigations/inv-1/manifest.json",
        "/investigations/inv-1/digest.md",
        "/investigations/inv-1/signals.json",
        "/investigations/inv-1/data_gaps.json",
        "/investigations/inv-1/decision.json",
        "/investigations/inv-1/evidence/vt.json",
        "/investigations/inv-1/evidence/whois.json",
        "/investigations/inv-1/evidence/final_risk.json",
    }


def test_signals_and_data_gaps_are_not_duplicated_under_evidence():
    """
    Two copies would cost context and leave the model guessing which is authoritative.
    """
    files = _bundle()

    assert "/investigations/inv-1/evidence/signals.json" not in files
    assert "/investigations/inv-1/evidence/data_gaps.json" not in files


def test_scalar_and_noise_sections_get_no_file():
    """
    Only dict sections get a file, so `build` and `build_manifest` agree exactly.

    Otherwise `target_domain` becomes evidence/target_domain.json holding a bare JSON
    string — a file the model can `ls` but the manifest never indexes, which breaks the
    "read manifest.json first" contract. artifact_hashes is a {name: sha256} map with no
    analytic content and is skipped outright.
    """
    files = _bundle()

    assert "/investigations/inv-1/evidence/target_domain.json" not in files
    assert "/investigations/inv-1/evidence/timestamps.json" not in files
    assert "/investigations/inv-1/evidence/artifact_hashes.json" not in files
    assert "/investigations/inv-1/evidence/domain.json" not in files


def test_analyst_digest_is_markdown_not_json():
    files = _bundle()

    assert files["/investigations/inv-1/digest.md"].startswith("# Evidence digest")
    assert "/investigations/inv-1/evidence/analyst_digest.json" not in files


def test_manifest_indexes_every_evidence_file_it_claims():
    manifest = json.loads(_bundle()["/investigations/inv-1/manifest.json"])
    files = _bundle()

    for entry in manifest["sources"]:
        assert entry["path"] in files, f"manifest points at a file that was not written: {entry}"
    assert {e["source"] for e in manifest["sources"]} == {"vt", "whois", "final_risk"}


def test_manifest_separates_collected_from_derived_and_flags_failures():
    """
    "derived" keeps the model from reading `completed` as "an external source agreed".
    """
    manifest = json.loads(_bundle()["/investigations/inv-1/manifest.json"])
    by_source = {e["source"]: e for e in manifest["sources"]}

    assert by_source["final_risk"]["derived"] is True
    assert by_source["vt"]["derived"] is False
    assert by_source["whois"]["status"] == "failed"
    assert by_source["whois"]["error"] == "timeout"
    assert manifest["failed_sources"] == ["whois"]
    assert set(manifest["collected_sources"]) == {"vt", "whois"}
    # Scalars with no file of their own are surfaced here instead.
    assert manifest["target_domain"] == "paypal.com"


def test_manifest_reports_byte_sizes_so_the_model_can_choose_grep_over_read():
    manifest = json.loads(_bundle()["/investigations/inv-1/manifest.json"])

    for entry in manifest["sources"]:
        assert entry["bytes"] > 0


def test_build_manifest_skips_non_dict_sections():
    manifest = build_manifest(
        {"domain": "x.com", "whois": {"registrar": "r"}, "target_domain": "y.com"},
        {},
        investigation_id="i",
    )

    assert [e["source"] for e in manifest["sources"]] == ["whois"]


# ── digest.md ────────────────────────────────────────────────────────────────────

def test_digest_prunes_collectors_that_produced_nothing():
    """
    Every `_digest_*` summarizer returns all of its keys even when its collector never
    ran, so without pruning the digest is eleven sections of "None".
    """
    markdown = render_markdown(
        {
            "observable_summary": {"observable": "x.com", "observable_type": "domain"},
            "collector_summaries": {
                "whois": {"registrar": None, "domain_age_days": None},
                "vt": {"malicious_count": None, "tags": [], "categories": {}},
            },
        }
    )

    assert "None" not in markdown
    assert "Collector summaries" not in markdown


def test_digest_keeps_meaningful_zeros_and_falses():
    """
    `reachable: no` and `malicious_count: 0` are findings. Dropping them would make an
    absent collector indistinguishable from a clean one.
    """
    markdown = render_markdown(
        {
            "collector_summaries": {
                "http": {"reachable": False, "title": None},
                "vt": {"malicious_count": 0, "total_vendors": 94},
            }
        }
    )

    assert "reachable: no" in markdown
    assert "malicious count: 0" in markdown
    assert "title" not in markdown


def test_digest_never_exposes_the_hybrid_analysis_storage_name():
    """
    `hybrid_analysis` is the legacy internal key for the ANY.RUN integration and the
    analyst must never see it. This replaces the guarantee the deleted
    `prompt_builder._build_supporting_evidence` used to provide.
    """
    markdown = render_markdown(
        {
            "collector_summaries": {
                "hybrid_analysis": {
                    "items": [{"verdict": "suspicious", "threat_score": 80}],
                }
            }
        }
    )

    assert "hybrid" not in markdown.lower()
    assert "AnyRun sandbox" in markdown
    assert "verdict=suspicious" in markdown


def test_digest_lists_signals_and_gaps_with_counts_and_points_at_the_full_files():
    markdown = render_markdown(
        {
            "top_signals": [{"id": "young_domain", "severity": "high", "description": "11 days"}],
            "top_data_gaps": [{"id": "no_tls", "impact": "medium", "description": "no handshake"}],
        }
    )

    assert "## Top signals (1)" in markdown
    assert "**[HIGH]** `young_domain` — 11 days" in markdown
    assert "`signals.json`" in markdown
    assert "## Data gaps (1)" in markdown
    assert "`no_tls` — no handshake (impact: medium)" in markdown
    assert "`data_gaps.json`" in markdown


def test_digest_of_an_entirely_empty_dict_is_still_valid_markdown():
    assert render_markdown({}).strip() == "# Evidence digest"
