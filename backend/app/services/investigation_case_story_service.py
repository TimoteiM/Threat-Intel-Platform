"""Evidence-grounded AI case story and investigation Q&A for SOC analysts."""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from typing import Any, Literal

import anthropic
from openai import AsyncOpenAI
from pydantic import BaseModel, Field, ValidationError

from app.config import Settings, get_settings

logger = logging.getLogger(__name__)


class EvidenceClaim(BaseModel):
    title: str = Field(max_length=140)
    explanation: str = Field(max_length=700)
    severity: Literal["critical", "high", "medium", "low", "info"] = "info"
    evidence_refs: list[str] = Field(default_factory=list, max_length=5)
    score_effect: str = Field(default="", max_length=160)


class StoryEvent(BaseModel):
    label: str = Field(max_length=140)
    description: str = Field(max_length=700)
    phase: Literal["observed", "inferred", "recommended"] = "observed"
    evidence_refs: list[str] = Field(default_factory=list, max_length=5)


class ScoreComponent(BaseModel):
    label: str
    effect: str
    explanation: str
    evidence_refs: list[str] = Field(default_factory=list)


class RecommendedAction(BaseModel):
    priority: Literal["P1", "P2", "P3"]
    action: str
    rationale: str
    evidence_refs: list[str] = Field(default_factory=list)


class VisualAssessment(BaseModel):
    performed: bool = False
    summary: str = "No screenshot was available for visual assessment."
    observations: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)


class CaseStory(BaseModel):
    headline: str = Field(max_length=180)
    what_happened: str = Field(max_length=1200)
    why_it_matters: str = Field(max_length=900)
    score_explanation: str = Field(max_length=1200)
    score_components: list[ScoreComponent] = Field(default_factory=list, max_length=6)
    strongest_evidence: list[EvidenceClaim] = Field(default_factory=list, max_length=6)
    contradicting_evidence: list[EvidenceClaim] = Field(default_factory=list, max_length=4)
    timeline: list[StoryEvent] = Field(default_factory=list, max_length=8)
    changes_since_last_run: list[str] = Field(default_factory=list, max_length=6)
    campaign_assessment: str = Field(max_length=800)
    recommended_actions: list[RecommendedAction] = Field(default_factory=list, max_length=6)
    visual_assessment: VisualAssessment = Field(default_factory=VisualAssessment)
    data_gaps: list[str] = Field(default_factory=list, max_length=6)
    soc_handoff_markdown: str = Field(max_length=2500)
    verdict: str = ""
    risk_score: int = 0
    confidence: str = ""
    model: str = ""
    generated_at: str = ""


class CaseQuestionRequest(BaseModel):
    question: str = Field(min_length=2, max_length=2000)


class CaseAnswer(BaseModel):
    answer: str
    evidence_refs: list[str] = Field(default_factory=list)
    confidence: Literal["high", "medium", "low"] = "medium"
    limitations: list[str] = Field(default_factory=list)
    suggested_followups: list[str] = Field(default_factory=list)
    model: str = ""


SYSTEM = """You are a senior SOC investigation analyst. Produce a precise, operational case story from the supplied canonical investigation data.
Hard rules:
- Treat the canonical verdict, risk score and confidence as immutable. Explain them; never recalculate or override them.
- Ground every factual claim in exact evidence paths supplied in the JSON, but put those paths only in the structured evidence_refs field. Never print raw implementation paths such as evidence.*, report.*, or intelligence.* inside analyst-facing prose.
- Clearly separate observations from inference. Never invent malware behavior, attribution, credentials, TDS, or user impact.
- Prefer decisive evidence and contradictions. Exclude repetitive low-value telemetry.
- Timeline events must form a concise attack/investigation story, not a dump of timestamps.
- Recommendations must be concrete SOC actions, prioritized P1-P3, and proportional to the evidence.
- If screenshots are attached, analyze only visible security-relevant details and cite the associated artifact reference.
- The handoff must be concise Markdown suitable for pasting into a SOC ticket, with verdict, score, summary, decisive evidence, gaps, and actions.
"""

CASE_ANSWER_STYLE = """
Answer style for Threat Analyzer - Assistant:
- Lead with a direct answer in the first sentence.
- Then explain the 2-4 most important reasons in plain language, ordered by decision impact.
- Explain model scores as percentages and state what each score does and does not measure.
- Distinguish the final case risk score from component scores and weights.
- End with one practical analyst takeaway when relevant.
- Keep the answer under 260 words unless the analyst explicitly asks for more detail.
- Do not enumerate raw evidence paths, JSON keys, or implementation field names in the answer text. Store grounding paths only in evidence_refs.
"""


def clean_case_answer_text(text: str) -> str:
    """Keep internal grounding references out of analyst-facing chat prose."""
    cleaned = str(text or "").strip()
    cleaned = re.sub(
        r"\[(?=[^\]]*(?:evidence|report|intelligence)\.)[^\]]+\]",
        "",
        cleaned,
        flags=re.IGNORECASE,
    )
    cleaned = re.sub(
        r"\((?=[^)]*(?:evidence|report|intelligence)\.)[^)]+\)",
        "",
        cleaned,
        flags=re.IGNORECASE,
    )
    cleaned = re.sub(
        r"(?<!\w)(?:evidence|report|intelligence)\.[\w.\[\]-]+(?:\s*[;,]\s*)?",
        "",
        cleaned,
        flags=re.IGNORECASE,
    )
    cleaned = re.sub(r"[ \t]+([.,;:])", r"\1", cleaned)
    cleaned = re.sub(r"[ \t]{2,}", " ", cleaned)
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)
    return cleaned.strip()


def compact_case_context(*, detail: dict[str, Any], evidence: dict[str, Any], report: dict[str, Any], intelligence: dict[str, Any]) -> dict[str, Any]:
    """Keep the high-value case corpus while bounding cost and prompt noise."""
    return {
        "canonical": {
            "investigation_id": detail.get("id"), "observable": detail.get("domain"),
            "observable_type": detail.get("observable_type"), "verdict": detail.get("classification") or report.get("classification"),
            "risk_score": detail.get("risk_score") if detail.get("risk_score") is not None else report.get("risk_score"),
            "confidence": detail.get("confidence") or report.get("confidence"), "recommended_action": detail.get("recommended_action"),
            "created_at": detail.get("created_at"), "concluded_at": detail.get("concluded_at"),
        },
        "report": _bounded(report, depth=4, list_limit=12, string_limit=1200),
        "evidence": _bounded({key: evidence.get(key) for key in (
            "signals", "data_gaps", "vt", "threat_feeds", "anyrun", "hybrid_analysis",
            "urlscan", "url_lexical_ml", "ml_url_score", "final_risk", "screenshot", "visual_comparison",
            "opencti", "dns", "http", "tls", "whois", "hosting", "email_security",
        ) if evidence.get(key) is not None}, depth=4, list_limit=10, string_limit=900),
        "derived_intelligence": _bounded({
            "timeline": intelligence.get("timeline"), "summary": intelligence.get("summary"),
            "ioc_quality": intelligence.get("ioc_quality"), "rescan_diff": intelligence.get("rescan_diff"),
            "similar_investigations": intelligence.get("similar_investigations"),
            "confidence": intelligence.get("confidence"), "attack_mapping": intelligence.get("attack_mapping"),
        }, depth=5, list_limit=12, string_limit=1000),
    }


def _bounded(value: Any, *, depth: int, list_limit: int, string_limit: int) -> Any:
    if depth <= 0:
        return "[truncated]"
    if isinstance(value, dict):
        return {str(k): _bounded(v, depth=depth - 1, list_limit=list_limit, string_limit=string_limit) for k, v in list(value.items())[:120]}
    if isinstance(value, list):
        return [_bounded(v, depth=depth - 1, list_limit=list_limit, string_limit=string_limit) for v in value[:list_limit]]
    if isinstance(value, str):
        return value[:string_limit]
    return value


class InvestigationCaseStoryService:
    def __init__(self, settings: Settings | None = None):
        self.settings = settings or get_settings()

    async def generate(self, *, context: dict[str, Any], images: list[tuple[str, str]]) -> CaseStory:
        prompt = "Create the unified SOC Case Story for this investigation.\n\nCASE DATA:\n" + json.dumps(context, default=str, ensure_ascii=False)
        story, model = await self._structured_call(CaseStory, prompt, images)
        canonical = context["canonical"]
        story.verdict = str(canonical.get("verdict") or "UNKNOWN")
        story.risk_score = int(canonical.get("risk_score") or 0)
        story.confidence = str(canonical.get("confidence") or "unknown")
        story.model = model
        story.generated_at = datetime.now(timezone.utc).isoformat()
        return story

    async def answer(self, *, context: dict[str, Any], question: str, images: list[tuple[str, str]]) -> CaseAnswer:
        prompt = f"{CASE_ANSWER_STYLE}\nAnswer this analyst question using only the case data: {question}\n\nCASE DATA:\n{json.dumps(context, default=str, ensure_ascii=False)}"
        answer, model = await self._structured_call(CaseAnswer, prompt, images)
        answer.answer = clean_case_answer_text(answer.answer)
        answer.model = model
        return answer

    async def _structured_call(self, schema: type[BaseModel], prompt: str, images: list[tuple[str, str]]):
        primary = (self.settings.openai_model or "gpt-5.6-luna").strip()
        if self.settings.openai_api_key:
            try:
                content: list[dict[str, Any]] = [{"type": "input_text", "text": prompt}]
                for ref, data_url in images[:3]:
                    content.extend([{"type": "input_text", "text": f"Screenshot evidence reference: {ref}"}, {"type": "input_image", "image_url": data_url, "detail": "high"}])
                response = await AsyncOpenAI(api_key=self.settings.openai_api_key).responses.parse(
                    model=primary, instructions=SYSTEM, input=[{"role": "user", "content": content}],
                    text_format=schema, reasoning={"effort": "low"}, max_output_tokens=4500, store=False,
                )
                parsed = getattr(response, "output_parsed", None)
                if parsed is not None:
                    return parsed, primary
                raise ValueError("OpenAI returned no structured output")
            except ValidationError as exc:
                # A paid response arrived but failed structured parsing (usually
                # truncation). Never trigger another provider charge here.
                logger.warning("Case Story structured output invalid (%s); using local fallback", exc)
                if schema is CaseStory:
                    return _deterministic_story(prompt), f"{primary} (local fallback)"
                return CaseAnswer(answer="The model response could not be parsed. Please ask a narrower question.", confidence="low", limitations=["Malformed structured model response"]), f"{primary} (local fallback)"
            except Exception as exc:
                logger.warning("Case Story primary failed (%s); using Haiku fallback", exc)

        fallback = (self.settings.anthropic_model or "claude-haiku-4-5-20251001").strip()
        if not self.settings.anthropic_api_key:
            raise ValueError("AI Case Story unavailable: both primary and fallback providers are unavailable")
        response = await anthropic.AsyncAnthropic(api_key=self.settings.anthropic_api_key).messages.create(
            model=fallback, max_tokens=4500, system=SYSTEM + "\nReturn only concise JSON matching this schema:\n" + json.dumps(schema.model_json_schema()),
            messages=[{"role": "user", "content": prompt}],
        )
        raw = response.content[0].text if response.content else "{}"
        raw = raw.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip()
        return schema.model_validate_json(raw), fallback


def _deterministic_story(prompt: str) -> CaseStory:
    """Zero-cost last resort after a paid but malformed structured response."""
    marker = "CASE DATA:\n"
    raw = prompt.split(marker, 1)[-1]
    try:
        context = json.loads(raw)
    except Exception:
        context = {}
    return build_saved_case_story(context=context, model="AI report synthesis")


def build_recomputed_case_summary(
    *,
    evidence: dict[str, Any],
    report: dict[str, Any],
    observable: str,
    reason: str,
) -> str:
    """Create analyst-facing prose after asynchronous evidence changes."""
    classification = str(report.get("classification") or "inconclusive").upper()
    confidence = str(report.get("confidence") or "low").lower()
    score = report.get("risk_score")
    sentences: list[str] = []

    if reason == "deferred_anyrun_completed":
        sentences.append(
            f"ANY.RUN completed after the initial analysis for {observable}, and the new sandbox evidence was evaluated."
        )
    elif reason == "anyrun_heuristic_reclassified":
        sentences.append(
            f"The ANY.RUN evidence for {observable} was reevaluated by separating the provider verdict from heuristic observations."
        )
    else:
        sentences.append(
            f"New evidence became available for {observable}, and the investigation was reevaluated."
        )

    form_detection: dict[str, Any] = {}
    form_ref = ""
    js_detection = (evidence.get("js_analysis") or {}).get("sensitive_form_detection") or {}
    if isinstance(js_detection, dict) and js_detection.get("detected"):
        form_detection = js_detection
        form_ref = "rendered browser session"
    if not form_detection:
        for item in (evidence.get("hybrid_analysis") or {}).get("items") or []:
            if not isinstance(item, dict):
                continue
            candidate = (item.get("raw_summary") or {}).get("sensitive_form_detection") or {}
            if isinstance(candidate, dict) and candidate.get("detected"):
                form_detection = candidate
                form_ref = "sandbox screenshots"
                break

    categories = [
        str(value).replace("_", " ")
        for value in form_detection.get("categories") or []
        if value
    ]
    if form_detection:
        category_text = ", ".join(categories) if categories else "user data"
        sentences.append(
            f"The {form_ref} showed a visible form requesting {category_text}, but the form was not submitted, "
            "so behavior triggered after data entry remains untested."
        )

    anyrun_item: dict[str, Any] = {}
    for item in (evidence.get("hybrid_analysis") or {}).get("items") or []:
        if not isinstance(item, dict):
            continue
        raw = item.get("raw_summary") or {}
        if str(raw.get("source") or "").lower() == "anyrun" and str(raw.get("mode") or "").lower() == "sandbox":
            anyrun_item = item
            break
    if not anyrun_item:
        anyrun_item = next(
            (
                item for item in (evidence.get("hybrid_analysis") or {}).get("items") or []
                if isinstance(item, dict)
                and str((item.get("raw_summary") or {}).get("source") or "").lower() == "anyrun"
            ),
            {},
        )

    anyrun_verdict = str(anyrun_item.get("verdict") or "").upper()
    if anyrun_verdict:
        if anyrun_verdict in {"CLEAN", "BENIGN", "SAFE"} and form_detection:
            sentences.append(
                f"ANY.RUN returned {anyrun_verdict}, but that provider verdict is treated as incomplete interaction coverage—not proof that the form is safe."
            )
        else:
            sentences.append(f"ANY.RUN returned {anyrun_verdict} for the investigated observable.")

    if classification == "BENIGN":
        supporting = [
            str(item).rstrip(".")
            for item in report.get("key_evidence") or []
            if item
            and (
                "0 malicious, 0 suspicious" in str(item).lower()
                or str(item).lower().startswith("established domain")
                or "treated as contextual" in str(item).lower()
            )
        ][:3]
    else:
        supporting = [
            str(item).rstrip(".")
            for item in report.get("key_evidence") or []
            if item
            and not str(item).lower().startswith("anyrun")
            and not str(item).lower().startswith("rendered data-entry form")
        ][:3]
    support_text = "; ".join(supporting)
    score_text = f" with a risk score of {score}/100" if score is not None else ""
    conclusion_verb = "is now" if reason == "anyrun_heuristic_reclassified" else "remains"
    conclusion = f"The case {conclusion_verb} {classification}{score_text} at {confidence} confidence"
    if support_text:
        conclusion += f", supported by {support_text}"
    sentences.append(conclusion + ".")

    if form_detection and confidence == "low":
        sentences.append(
            "Confidence remains low because the available run did not establish what happens when the form is submitted."
        )
    return " ".join(sentences)[:1200]


def build_saved_case_story(*, context: dict[str, Any], model: str) -> CaseStory:
    """Build the persisted Case Story from the paid analyst report at zero extra AI cost."""
    canonical = context.get("canonical") or {}
    report = context.get("report") or {}
    intel = context.get("derived_intelligence") or {}
    findings = report.get("findings") if isinstance(report.get("findings"), list) else []
    severity_rank = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    form_finding = next(
        (
            item for item in findings
            if isinstance(item, dict) and item.get("id") == "sensitive_data_entry_form"
        ),
        None,
    )
    benign_findings = [
        item for item in findings
        if isinstance(item, dict)
        and (
            item.get("id") == "anyrun_verdict"
            and "clean" in str(item.get("title") or "").lower()
        )
    ]
    decisive_findings = [
        item for item in findings
        if isinstance(item, dict) and item not in benign_findings
    ]
    decisive_findings.sort(
        key=lambda item: severity_rank.get(str(item.get("severity") or "info").lower(), 1),
        reverse=True,
    )
    claims = []
    for index, item in enumerate(decisive_findings[:5]):
        if not isinstance(item, dict):
            continue
        claims.append(EvidenceClaim(
            title=str(item.get("title") or item.get("name") or f"Finding {index + 1}")[:140],
            explanation=str(item.get("description") or item.get("reasoning") or "Reported analyst finding.")[:700],
            severity=str(item.get("severity") or "info").lower() if str(item.get("severity") or "info").lower() in {"critical","high","medium","low","info"} else "info",
            evidence_refs=(
                list(item.get("evidence_refs") or [])[:5]
                or [f"report.findings[{findings.index(item)}]"]
            ),
        ))
    summary = str(report.get("primary_reasoning") or report.get("executive_summary") or "The collected evidence requires SOC review.")[:1200]
    rescan = intel.get("rescan_diff") or {}
    campaign = intel.get("similar_investigations") or {}
    verdict = str(canonical.get("verdict") or "UNKNOWN")
    score = int(canonical.get("risk_score") or 0)
    recommended = []
    for index, step in enumerate((report.get("recommended_steps") or [])[:6]):
        recommended.append(RecommendedAction(
            priority="P1" if index == 0 and verdict.lower() in {"malicious", "suspicious"} else ("P2" if index < 3 else "P3"),
            action=str(step)[:300], rationale="Recommended by the evidence-grounded analyst assessment.",
        ))
    score_components = [ScoreComponent(
        label=claim.title, effect=claim.score_effect or claim.severity.upper(),
        explanation=claim.explanation, evidence_refs=claim.evidence_refs,
    ) for claim in claims[:6]]
    timeline = []
    timeline_source = intel.get("timeline") or {}
    if isinstance(timeline_source, dict):
        timeline_source = timeline_source.get("items") or timeline_source.get("events") or []
    if isinstance(timeline_source, list):
        for item in timeline_source[:8]:
            if not isinstance(item, dict):
                continue
            timeline.append(StoryEvent(
                label=str(item.get("label") or item.get("title") or item.get("event") or "Observed event")[:140],
                description=str(item.get("description") or item.get("detail") or item.get("summary") or "Evidence observed during investigation.")[:700],
                phase="observed", evidence_refs=[],
            ))
    contradictory = [EvidenceClaim(
        title="Contradicting or benign signal", explanation=str(value)[:700], severity="info",
    ) for value in (report.get("contradicting_evidence") or [])[:4]]
    for item in benign_findings[:max(0, 4 - len(contradictory))]:
        contradictory.append(EvidenceClaim(
            title=str(item.get("title") or "Benign provider signal")[:140],
            explanation=str(item.get("description") or "The provider returned a clean result.")[:700],
            severity="info",
            evidence_refs=list(item.get("evidence_refs") or [])[:5],
        ))
    visual = (context.get("evidence") or {}).get("visual_comparison") or {}
    visual_summary = str(
        visual.get("summary")
        or visual.get("assessment")
        or (
            form_finding.get("description")
            if isinstance(form_finding, dict)
            else "No screenshot-derived conclusion was available."
        )
    )[:800]
    why_it_matters = f"The canonical investigation concluded {verdict} with risk score {score}."
    if form_finding:
        why_it_matters = (
            "A visible data-entry form creates an interaction-dependent blind spot: a clean sandbox result "
            "does not establish what the page does after submission. "
            f"The canonical investigation therefore remains {verdict} with risk score {score}."
        )
    story = CaseStory(
        headline=f"{verdict} assessment for {canonical.get('observable') or 'the observable'}",
        what_happened=summary, why_it_matters=why_it_matters,
        score_explanation=str(report.get("risk_rationale") or f"The score of {score} is the canonical decision-engine result, supported by the strongest findings below.")[:1200],
        score_components=score_components, strongest_evidence=claims, contradicting_evidence=contradictory, timeline=timeline,
        changes_since_last_run=[str(rescan.get("summary"))[:500]] if rescan.get("summary") else [],
        campaign_assessment=str(campaign.get("summary") or "No reliable campaign correlation was available.")[:800],
        recommended_actions=recommended,
        visual_assessment=VisualAssessment(
            performed=bool(visual or form_finding),
            summary=visual_summary,
            evidence_refs=(
                list(form_finding.get("evidence_refs") or [])[:5]
                if isinstance(form_finding, dict)
                else []
            ),
        ),
        data_gaps=[str(x)[:300] for x in (report.get("data_needed") or report.get("data_gaps") or [])[:6]],
        soc_handoff_markdown=f"## SOC handoff\n- Observable: {canonical.get('observable')}\n- Verdict: {verdict}\n- Risk score: {score}\n\n{summary}",
    )
    story.verdict = verdict
    story.risk_score = score
    story.confidence = str(canonical.get("confidence") or "unknown")
    story.model = model
    story.generated_at = datetime.now(timezone.utc).isoformat()
    return story
