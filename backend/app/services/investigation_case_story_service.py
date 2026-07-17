"""Evidence-grounded AI case story and investigation Q&A for SOC analysts."""

from __future__ import annotations

import json
import logging
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
- Every factual claim must cite one or more exact evidence paths supplied in the JSON (for example report.findings[0] or evidence.vt.stats.malicious).
- Clearly separate observations from inference. Never invent malware behavior, attribution, credentials, TDS, or user impact.
- Prefer decisive evidence and contradictions. Exclude repetitive low-value telemetry.
- Timeline events must form a concise attack/investigation story, not a dump of timestamps.
- Recommendations must be concrete SOC actions, prioritized P1-P3, and proportional to the evidence.
- If screenshots are attached, analyze only visible security-relevant details and cite the associated artifact reference.
- The handoff must be concise Markdown suitable for pasting into a SOC ticket, with verdict, score, summary, decisive evidence, gaps, and actions.
"""


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
            "urlscan", "screenshot", "visual_comparison", "opencti", "dns", "http", "tls", "whois", "hosting",
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
        prompt = f"Answer this analyst question using only the case data: {question}\n\nCASE DATA:\n{json.dumps(context, default=str, ensure_ascii=False)}"
        answer, model = await self._structured_call(CaseAnswer, prompt, images)
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


def build_saved_case_story(*, context: dict[str, Any], model: str) -> CaseStory:
    """Build the persisted Case Story from the paid analyst report at zero extra AI cost."""
    canonical = context.get("canonical") or {}
    report = context.get("report") or {}
    intel = context.get("derived_intelligence") or {}
    findings = report.get("findings") if isinstance(report.get("findings"), list) else []
    claims = []
    for index, item in enumerate(findings[:5]):
        if not isinstance(item, dict):
            continue
        claims.append(EvidenceClaim(
            title=str(item.get("title") or item.get("name") or f"Finding {index + 1}")[:140],
            explanation=str(item.get("description") or item.get("reasoning") or "Reported analyst finding.")[:700],
            severity=str(item.get("severity") or "info").lower() if str(item.get("severity") or "info").lower() in {"critical","high","medium","low","info"} else "info",
            evidence_refs=[f"report.findings[{index}]"],
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
    visual = (context.get("evidence") or {}).get("visual_comparison") or {}
    visual_summary = str(visual.get("summary") or visual.get("assessment") or "No screenshot-derived conclusion was available.")[:800]
    story = CaseStory(
        headline=f"{verdict} assessment for {canonical.get('observable') or 'the observable'}",
        what_happened=summary, why_it_matters=f"The canonical investigation concluded {verdict} with risk score {score}.",
        score_explanation=str(report.get("risk_rationale") or f"The score of {score} is the canonical decision-engine result, supported by the strongest findings below.")[:1200],
        score_components=score_components, strongest_evidence=claims, contradicting_evidence=contradictory, timeline=timeline,
        changes_since_last_run=[str(rescan.get("summary"))[:500]] if rescan.get("summary") else [],
        campaign_assessment=str(campaign.get("summary") or "No reliable campaign correlation was available.")[:800],
        recommended_actions=recommended, visual_assessment=VisualAssessment(performed=bool(visual), summary=visual_summary),
        data_gaps=[str(x)[:300] for x in (report.get("data_needed") or report.get("data_gaps") or [])[:6]],
        soc_handoff_markdown=f"## SOC handoff\n- Observable: {canonical.get('observable')}\n- Verdict: {verdict}\n- Risk score: {score}\n\n{summary}",
    )
    story.verdict = verdict
    story.risk_score = score
    story.confidence = str(canonical.get("confidence") or "unknown")
    story.model = model
    story.generated_at = datetime.now(timezone.utc).isoformat()
    return story
