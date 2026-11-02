import json
import os

os.environ.setdefault("OPENAI_API_KEY", "test-key")

from app.services import attack_ai_service as svc

ALERT = (
    "User opened invoice_march.docm from the mail attachment, which then "
    "connected to hxxps://payments-verify[.]net/login and prompted for the "
    "Office 365 password."
)
DIGEST = '{"indicators": [{"value": "payments-verify.net", "verdict": "malicious"}]}'


def _model(payload) -> callable:
    """A stand-in model returning exactly what the test wants it to say."""
    text = payload if isinstance(payload, str) else json.dumps(payload)
    return lambda system, user: text


def _propose(payload, already=()):
    return svc.propose_techniques(
        alert_body=ALERT,
        findings_digest=DIGEST,
        already_evidenced=already,
        call_model=_model(payload),
    )


# ── What it accepts ───────────────────────────────────────────────────────────


def test_a_whitelisted_technique_quoting_real_evidence_is_accepted():
    accepted = _propose(
        {
            "techniques": [
                {
                    "id": "T1566.002",
                    "evidence_quote": "connected to hxxps://payments-verify[.]net/login",
                    "reasoning": "The user followed a link from a mail attachment.",
                }
            ]
        }
    )

    assert len(accepted) == 1
    proposal = accepted[0]
    assert proposal["id"] == "T1566.002"
    assert proposal["name"] == "Phishing: Spearphishing Link"
    assert proposal["source"] == "ai_suggested"
    assert proposal["confidence"] == "low"          # never enough to confirm alone
    assert proposal["status"] == "additional"
    assert "payments-verify" in proposal["evidence"][0]["matched"]
    assert "treat as a lead" in proposal["explanation"]


def test_a_quote_is_matched_despite_reflowed_whitespace_and_case():
    accepted = _propose(
        {
            "techniques": [
                {
                    "id": "T1566.002",
                    "evidence_quote": "PROMPTED FOR   the Office 365\n password",
                }
            ]
        }
    )
    assert len(accepted) == 1


# ── What it refuses ───────────────────────────────────────────────────────────


def test_a_technique_outside_the_whitelist_is_dropped():
    """The whitelist is what makes invention structurally impossible."""
    accepted = _propose(
        {
            "techniques": [
                {"id": "T1055.012", "evidence_quote": "User opened invoice_march.docm"}
            ]
        }
    )
    assert accepted == []


def test_a_fabricated_quote_drops_the_whole_proposal():
    """The model cited text that is nowhere in the evidence — the classic failure."""
    accepted = _propose(
        {
            "techniques": [
                {
                    "id": "T1486",
                    "evidence_quote": "files were encrypted and a ransom note was dropped",
                }
            ]
        }
    )
    assert accepted == []


def test_a_proposal_with_no_quote_is_dropped():
    accepted = _propose({"techniques": [{"id": "T1566.002", "reasoning": "seems likely"}]})
    assert accepted == []


def test_a_trivially_short_quote_is_not_a_citation():
    accepted = _propose({"techniques": [{"id": "T1566.002", "evidence_quote": "the"}]})
    assert accepted == []


def test_the_model_cannot_restate_what_the_deterministic_pass_established():
    accepted = _propose(
        {
            "techniques": [
                {
                    "id": "T1566.002",
                    "evidence_quote": "connected to hxxps://payments-verify[.]net/login",
                }
            ]
        },
        already=["T1566.002"],
    )
    assert accepted == []


def test_malformed_output_yields_nothing_rather_than_a_partial_guess():
    for payload in ["not json at all", "", "{]", '{"techniques": "T1566.002"}', "null"]:
        assert svc.propose_techniques(
            alert_body=ALERT,
            findings_digest=DIGEST,
            already_evidenced=(),
            call_model=_model(payload),
        ) == []


def test_json_fenced_in_markdown_is_still_read():
    fenced = (
        "Here is my answer:\n```json\n"
        + json.dumps(
            {"techniques": [{"id": "T1566.002", "evidence_quote": "prompted for the Office 365 password"}]}
        )
        + "\n```"
    )
    assert len(_propose(fenced)) == 1


def test_a_model_that_raises_costs_nothing():
    def exploding(system, user):
        raise RuntimeError("provider down")

    assert svc.propose_techniques(
        alert_body=ALERT, findings_digest=DIGEST, already_evidenced=(), call_model=exploding
    ) == []


def test_only_the_bad_proposals_are_dropped_from_a_mixed_batch():
    accepted = _propose(
        {
            "techniques": [
                {"id": "T1566.002", "evidence_quote": "prompted for the Office 365 password"},
                {"id": "T1486", "evidence_quote": "ransomware encrypted the share"},   # fabricated
                {"id": "T9999", "evidence_quote": "User opened invoice_march.docm"},   # not whitelisted
            ]
        }
    )
    assert [item["id"] for item in accepted] == ["T1566.002"]


def test_the_proposal_count_is_capped():
    payload = {
        "techniques": [
            {"id": "T1566.002", "evidence_quote": "prompted for the Office 365 password"}
        ]
        * 20
    }
    # Duplicates are rejected after the first, so the cap is visible as one hit.
    assert len(_propose(payload)) == 1
