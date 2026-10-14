"""CrowdStrike Falcon — enrichment. Does this tenant's EDR know this host?

The first per-tenant integration. It declares itself with `integration = True`
rather than appearing on a list of tools, so the integrations catalogue and
the per-verdict source coverage both pick it up with nothing to update —
`COLLECTOR_REGISTRY` is already what `source_coverage_service` derives its
expected set from.

Enrichment only, this pass
--------------------------
Ingest — polling Falcon's detections into the alert pipeline — is a separate
pass. It needs `_create_alert_run` extracted out of the API module first, and
it brings a field map (where unmapped Falcon fields are quarantined as
`no_field_map` and never inferred) and the question of Falcon's own MITRE
attributions as a third technique namer that must not quietly join
`rule_only`. `integration_directions` therefore says `enrichment` and not
both: a tool must not report a status for a direction it does not have.

Which tenant's credential
-------------------------
Falcon credentials are per tenant, so this collector needs to know which
tenant it is running for. It reads `external_context["tenant_id"]`, which is
the channel `investigation_task` already passes through to collectors.

**When there is no tenant, it makes no call and records an absence.** It does
not fall back to "any configured credential" — that would be a cross-tenant
read, and the whole reason credentials live on `tenant_id` is that it is the
axis carrying authorisation. An investigation with no tenant is a question
this integration cannot answer, and saying so is the correct answer.

The tenant now reaches both paths. It lives on
`alert_body_investigation_runs.tenant_id`, and `alert_body_task` threads it
into `run_alert_body_investigation` → `_investigate_indicator` → either
`_run_collector` (the inline path, where it becomes this collector's
`external_context`) or `spawn_investigation` (the full-investigation path,
where it joins the pipeline's `external_context`).

Both, deliberately, because a tenant that reached some paths and silently not
others would be indistinguishable from one that worked — the same alert would
enrich or not depending on which branch an indicator took.

An earlier version of this docstring claimed `spawn_investigation` already
accepted the tenant. It did not: `tenant_id` appeared nowhere in that module.
The claim was written as the work was planned and read afterwards as the work
being done, which is why the plumbing is now asserted by
`tests/unit/test_services/test_tenant_plumbing.py` rather than described here.

**Absence stays absence.** A blank or whitespace `tenant_id` is omitted from
`external_context` rather than passed as `""` — a tenant nobody owns would
turn "nobody asked" into "not configured for ''", and a credential lookup
failing for a fabricated tenant is a worse answer than no lookup.
"""

from __future__ import annotations

import logging
from typing import Any

from app.collectors.base import BaseCollector
from app.models.schemas import FalconEvidence
from app.services.absence import CHECK_FAILED, absent

logger = logging.getLogger(__name__)


class FalconCollector(BaseCollector):
    name = "falcon"
    supported_types = frozenset({"domain", "ip", "url", "hash"})

    # ── the integration declaration ──────────────────────────────────────
    integration = True
    integration_label = "CrowdStrike Falcon"
    integration_category = "edr"
    integration_directions = ("enrichment",)
    integration_config_fields = {
        "cloud": "Falcon cloud region — us-1, us-2, eu-1 or us-gov-1",
        "base_url": "Full API base URL, if the region is not one of the above",
    }
    integration_secret_fields = {
        "client_id": "Falcon API client id",
        "client_secret": "Falcon API client secret",
    }

    def _collect(self) -> FalconEvidence:
        evidence = FalconEvidence()
        tenant_id = str(
            (self.external_context or {}).get("tenant_id") or ""
        ).strip()

        if not tenant_id:
            # No tenant, so no per-tenant credential can be selected. Never
            # fall back to another tenant's: that is the cross-tenant read
            # this whole design exists to make impossible.
            evidence.status = absent(
                CHECK_FAILED,
                "This investigation carries no tenant, so no per-tenant "
                "Falcon credential could be selected. No request was made, "
                "and no other tenant's credential was used. An empty result "
                "here is an absence, not a clean answer from the EDR.",
                raw="no_tenant",
            ).as_json()
            evidence.notes.append(
                "Falcon not queried: the investigation has no tenant_id."
            )
            return evidence

        from app.services import integration_credential_service as creds

        try:
            opened = creds.open_for_tenant_sync(tenant_id, self.name)
        except creds.IntegrationNotConfigured:
            evidence.status = absent(
                CHECK_FAILED,
                f"CrowdStrike Falcon is not configured for tenant "
                f"{tenant_id!r}. No request was made. Configure it on the "
                "Integrations page; an unconfigured EDR is an absence, not a "
                "host the EDR has nothing on.",
                raw="not_configured",
            ).as_json()
            return evidence
        except Exception as exc:  # noqa: BLE001
            # A credential that cannot be opened — a rotation left unfinished,
            # or a lost key. Never the exception text verbatim: it is redacted
            # at the source, but this is the belt as well as the braces.
            evidence.status = absent(
                CHECK_FAILED,
                f"The stored Falcon credential for tenant {tenant_id!r} could "
                f"not be opened ({type(exc).__name__}). No request was made.",
                raw="credential_unreadable",
            ).as_json()
            return evidence

        from app.integrations import falcon_client as falcon

        try:
            result = falcon.lookup(
                observable=self.target_domain,
                observable_type=self.observable_type,
                client_id=opened.client_id,
                client_secret=opened.client_secret,
                config=opened.config,
                timeout=self.timeout,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "[falcon] lookup failed for tenant %s: %s",
                tenant_id, falcon._redact(exc),
            )
            evidence.status = absent(
                CHECK_FAILED,
                f"The Falcon query did not complete: "
                f"{falcon._redact(exc)}",
                raw="lookup_failed",
            ).as_json()
            return evidence

        evidence.detections = list(result.get("detections") or [])
        evidence.hosts = list(result.get("hosts") or [])
        evidence.found = bool(evidence.detections or evidence.hosts)
        evidence.queried_at = result.get("queried_at")
        evidence.notes.extend(result.get("notes") or [])
        # Asked and answered — including "answered nothing", which is a real
        # negative and the one state the seven-month ThreatFox silence could
        # never express.
        evidence.status = {"asked": True, "tenant_id": tenant_id}
        return evidence
