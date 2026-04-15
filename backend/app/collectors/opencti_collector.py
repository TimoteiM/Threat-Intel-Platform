"""
OpenCTI Collector — queries an OpenCTI instance for existing threat intelligence.

Supports: domain, ip, url, hash, file observable types.

Search strategy (tried in order until results are found):
  1. stixCyberObservables(search: value)   — ES full-text (fast, but misses cross-type matches)
  2. stixCyberObservables(filters: ...)    — value contains (exact substring, v5/v6 filter syntax)
     For domain type, also tries http://<domain> and https://<domain> variants so that
     URL observables stored in OpenCTI are matched against a domain investigation.

Relationships are fetched in a separate call (best-effort) so that schema differences
in older/newer OpenCTI versions never kill the basic observable lookup.

Requires:
  OPENCTI_API_URL — base URL of your OpenCTI instance (trailing slash optional)
  OPENCTI_API_KEY — OpenCTI user API token (UUID format)
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any
from urllib.parse import urlparse

import requests

from app.collectors.base import BaseCollector
from app.config import get_settings
from app.models.schemas import (
    CollectorMeta,
    OpenCTIEvidence,
    OpenCTIIndicator,
    OpenCTIReport,
    OpenCTIThreatActor,
    OpenCTIMalware,
    OpenCTIAttackPattern,
)

logger = logging.getLogger(__name__)

# ── Shared node fragment — keep minimal to avoid schema-version failures ──
# indicators/reports are fetched separately in best-effort calls below.
_NODE_FIELDS = """
        id
        entity_type
        observable_value
        x_opencti_score
"""

# ── Optional enrichment queries (best-effort, separate calls) ──
_GQL_INDICATORS = """
query GetIndicators($id: String!, $first: Int) {
  stixCyberObservable(id: $id) {
    indicators(first: $first) {
      edges {
        node {
          id
          name
          pattern
          valid_from
          valid_until
          confidence
          revoked
        }
      }
    }
  }
}
"""

_GQL_REPORTS = """
query GetReports($id: String!, $first: Int) {
  stixCyberObservable(id: $id) {
    reports(first: $first) {
      edges {
        node {
          id
          name
          published
          description
          created
          modified
          report_types
          creators {
            id
            name
          }
          createdBy {
            id
            name
          }
          objectLabel {
            value
          }
        }
      }
    }
  }
}
"""

_GQL_OBSERVABLE_METADATA = """
query GetObservableMetadata($id: String!) {
  stixCyberObservable(id: $id) {
    id
    entity_type
    observable_value
    x_opencti_score
    standard_id
    created_at
    updated_at
    creators {
      id
      name
    }
    createdBy {
      id
      name
    }
    objectLabel {
      value
    }
    objectMarking {
      definition_type
      definition
    }
  }
}
"""

# ── Query 1: full-text search (fast path) ──
_GQL_SEARCH = f"""
query SearchObservable($search: String, $first: Int) {{
  stixCyberObservables(search: $search, first: $first) {{
    edges {{
      node {{
        {_NODE_FIELDS}
      }}
    }}
  }}
}}
"""

# ── Query 2a: value-contains filter (OpenCTI v5 list-style) ──
_GQL_FILTER_V5 = f"""
query FilterObservableV5($filters: [StixCyberObservablesFiltering], $first: Int) {{
  stixCyberObservables(filters: $filters, first: $first) {{
    edges {{
      node {{
        {_NODE_FIELDS}
      }}
    }}
  }}
}}
"""

# ── Query 2b: value-contains filter (OpenCTI v6 FilterGroup-style) ──
_GQL_FILTER_V6 = f"""
query FilterObservableV6($filters: FilterGroup, $first: Int) {{
  stixCyberObservables(filters: $filters, first: $first) {{
    edges {{
      node {{
        {_NODE_FIELDS}
      }}
    }}
  }}
}}
"""

# ── Query 3: relationships (best-effort, separate call) ──
_GQL_RELATIONSHIPS = """
query GetRelationships($fromId: [String], $first: Int) {
  stixCoreRelationships(fromId: $fromId, first: $first) {
    edges {
      node {
        relationship_type
        to {
          ... on BasicObject           { entity_type id }
          ... on ThreatActorGroup      { id name sophistication resource_level }
          ... on ThreatActorIndividual { id name sophistication resource_level }
          ... on ThreatActor           { id name sophistication resource_level }
          ... on Malware               { id name malware_types first_seen }
          ... on AttackPattern         { id name x_mitre_id }
          ... on Campaign              { id name }
          ... on IntrusionSet          { id name }
        }
      }
    }
  }
}
"""


class OpenCTICollector(BaseCollector):
    name = "opencti"
    supported_types = frozenset({"domain", "ip", "url", "hash", "file"})

    # ── Public interface ─────────────────────────────────────────────────────

    def _collect(self) -> OpenCTIEvidence:
        settings = get_settings()
        api_url = (settings.opencti_api_url or "").rstrip("/")
        api_key  = (settings.opencti_api_key  or "").strip()

        if not api_url or not api_key:
            ev = OpenCTIEvidence()
            ev.notes.append("OpenCTI not configured: set OPENCTI_API_URL and OPENCTI_API_KEY")
            logger.warning("[opencti] OPENCTI_API_URL or OPENCTI_API_KEY not set — skipping")
            return ev

        # Build the ordered list of search terms to try
        search_terms = self._build_search_terms()
        if not search_terms:
            ev = OpenCTIEvidence()
            ev.notes.append(f"Could not extract a valid search value from: {self.domain[:80]}")
            return ev

        logger.info(
            "[opencti] Searching %s/graphql — terms=%s (type=%s)",
            api_url, search_terms, self.observable_type,
        )

        node: dict | None = None
        used_term: str = search_terms[0]

        for term in search_terms:
            node = self._search_observable(api_url, api_key, term)
            if node:
                used_term = term
                logger.info("[opencti] Found observable for search term '%s'", term)
                break
            logger.debug("[opencti] No result for term '%s'", term)

        if not node:
            ev = OpenCTIEvidence()
            ev.notes.append(
                f"Observable not found in OpenCTI (searched: {', '.join(search_terms)})"
            )
            logger.info("[opencti] Observable not found for any term: %s", search_terms)
            return ev

        ev = self._parse_node(node)
        ev.notes.insert(0, f"Matched via search term: '{used_term}'")

        if ev.observable_id:
            try:
                meta_raw = self._gql(
                    api_url=api_url,
                    api_key=api_key,
                    query=_GQL_OBSERVABLE_METADATA,
                    variables={"id": ev.observable_id},
                )
                self._parse_observable_metadata(ev, meta_raw)
            except Exception as exc:
                logger.warning("[opencti] Observable metadata query failed (non-fatal): %s", exc)
            # ── Indicators (best-effort) ─────────────────────────────────────
            try:
                ind_raw = self._gql(
                    api_url=api_url, api_key=api_key,
                    query=_GQL_INDICATORS,
                    variables={"id": ev.observable_id, "first": 10},
                )
                self._parse_indicators(ev, ind_raw)
            except Exception as exc:
                logger.warning("[opencti] Indicator query failed (non-fatal): %s", exc)

            # ── Reports (best-effort) ────────────────────────────────────────
            try:
                rep_raw = self._gql(
                    api_url=api_url, api_key=api_key,
                    query=_GQL_REPORTS,
                    variables={"id": ev.observable_id, "first": 5},
                )
                self._parse_reports(ev, rep_raw)
            except Exception as exc:
                logger.warning("[opencti] Report query failed (non-fatal): %s", exc)

            # ── Relationships (best-effort) ──────────────────────────────────
            try:
                rel_raw = self._gql(
                    api_url=api_url,
                    api_key=api_key,
                    query=_GQL_RELATIONSHIPS,
                    variables={"fromId": [ev.observable_id], "first": 30},
                )
                self._store_artifact("raw_relationships", json.dumps(rel_raw, default=str))
                self._parse_relationships(ev, rel_raw)
            except Exception as exc:
                logger.warning("[opencti] Relationship query failed (non-fatal): %s", exc)
                ev.notes.append(f"Relationship data unavailable: {type(exc).__name__}")

        return ev

    def _empty_evidence(self, meta: CollectorMeta) -> OpenCTIEvidence:
        return OpenCTIEvidence(meta=meta)

    # ── Search strategies ────────────────────────────────────────────────────

    def _build_search_terms(self) -> list[str]:
        """
        Return an ordered list of search terms to try against OpenCTI.

        Domain investigations may match URL observables stored in OpenCTI, so
        we try the bare domain first, then http/https-prefixed variants.
        URL investigations try the full URL first, then just the hostname.
        Hash investigations extract the clean hex digest.
        """
        if self.observable_type in ("hash", "file"):
            h = _extract_hash(self.domain)
            return [h] if h else []

        if self.observable_type == "url":
            host = (urlparse(self.domain).hostname or "").strip()
            terms = [self.domain]
            if host and host != self.domain:
                terms.append(host)
            return terms

        # domain / ip — also try URL-prefixed variants so URL observables are matched
        base = self.target_domain
        if not base:
            return []
        terms = [base]
        if self.observable_type == "domain":
            terms += [f"http://{base}", f"https://{base}"]
        return terms

    def _search_observable(
        self, api_url: str, api_key: str, term: str
    ) -> dict | None:
        """
        Try to find an OpenCTI StixCyberObservable matching `term`.
        Tries strategies in order: full-text search → v5 filter → v6 filter.
        Returns the best-matching node dict, or None if nothing found.
        """
        # Strategy 1 — full-text search
        try:
            raw = self._gql(
                api_url=api_url, api_key=api_key,
                query=_GQL_SEARCH,
                variables={"search": term, "first": 10},
            )
            self._store_artifact(f"raw_search_{_safe_name(term)}", json.dumps(raw, default=str))
            edges = raw.get("data", {}).get("stixCyberObservables", {}).get("edges", [])
            logger.info("[opencti] search='%s' → %d edge(s)", term, len(edges))
            node = _best_node(raw, "stixCyberObservables", term)
            logger.info("[opencti] search='%s' best_node=%s", term, bool(node))
            if node:
                return node
        except Exception as exc:
            logger.info("[opencti] search query EXCEPTION for '%s': %s", term, exc)

        # Strategy 2 — v5 list-style filter (value contains)
        try:
            raw = self._gql(
                api_url=api_url, api_key=api_key,
                query=_GQL_FILTER_V5,
                variables={
                    "first": 10,
                    "filters": [{"key": "value", "values": [term], "operator": "contains"}],
                },
            )
            node = _best_node(raw, "stixCyberObservables", term)
            logger.info("[opencti] v5 filter='%s' best_node=%s", term, bool(node))
            if node:
                return node
        except Exception as exc:
            logger.info("[opencti] v5 filter EXCEPTION for '%s': %s", term, exc)

        # Strategy 3 — v6 FilterGroup-style filter (value contains)
        try:
            raw = self._gql(
                api_url=api_url, api_key=api_key,
                query=_GQL_FILTER_V6,
                variables={
                    "first": 10,
                    "filters": {
                        "mode": "and",
                        "filters": [
                            {"key": ["value"], "values": [term], "operator": "contains", "mode": "or"}
                        ],
                        "filterGroups": [],
                    },
                },
            )
            edges = raw.get("data", {}).get("stixCyberObservables", {}).get("edges", [])
            logger.info("[opencti] v6 filter='%s' → %d edge(s)", term, len(edges))
            node = _best_node(raw, "stixCyberObservables", term)
            logger.info("[opencti] v6 filter='%s' best_node=%s", term, bool(node))
            if node:
                return node
        except Exception as exc:
            logger.info("[opencti] v6 filter EXCEPTION for '%s': %s", term, exc)

        return None

    # ── GraphQL helper ───────────────────────────────────────────────────────

    def _gql(
        self,
        *,
        api_url: str,
        api_key: str,
        query: str,
        variables: dict[str, Any],
    ) -> dict[str, Any]:
        settings  = get_settings()
        verify_ssl = settings.opencti_verify_ssl
        endpoint  = f"{api_url}/graphql"
        headers   = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}

        if not verify_ssl:
            # Suppress urllib3 InsecureRequestWarning for self-signed certs
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        resp = requests.post(
            endpoint, headers=headers,
            json={"query": query, "variables": variables},
            timeout=self.timeout,
            verify=verify_ssl,
        )

        if resp.status_code == 401:
            raise ValueError("OpenCTI: authentication failed — check OPENCTI_API_KEY")
        if resp.status_code == 403:
            raise ValueError("OpenCTI: 403 Forbidden — check API token permissions")
        if resp.status_code != 200:
            raise ValueError(f"OpenCTI: HTTP {resp.status_code}: {resp.text[:300]}")

        data = resp.json()
        errors = data.get("errors")
        if errors:
            msgs = "; ".join(e.get("message", str(e)) for e in errors)
            if data.get("data"):
                # Non-fatal: partial data returned alongside errors (schema warnings etc.)
                logger.warning("[opencti] GraphQL non-fatal errors (data still present): %s", msgs)
            else:
                raise ValueError(f"OpenCTI GraphQL errors: {msgs}")

        return data

    # ── Evidence parsing ─────────────────────────────────────────────────────

    def _parse_node(self, node: dict) -> OpenCTIEvidence:
        ev = OpenCTIEvidence()
        ev.found = True
        ev.observable_id          = node.get("id")
        ev.observable_entity_type = node.get("entity_type")
        ev.observable_value       = node.get("observable_value")
        ev.score                  = int(node.get("x_opencti_score") or 0)

        if ev.score:
            ev.notes.append(f"OpenCTI threat score: {ev.score}/100")

        return ev

    def _parse_observable_metadata(self, ev: OpenCTIEvidence, raw: dict) -> None:
        node = raw.get("data", {}).get("stixCyberObservable") or {}
        if not node:
            return

        ev.standard_id = _str_or_none(node.get("standard_id")) or ev.standard_id
        ev.created_at = _str_or_none(node.get("created_at")) or ev.created_at
        ev.updated_at = _str_or_none(node.get("updated_at")) or ev.updated_at
        ev.author = _extract_name(node.get("createdBy")) or ev.author
        ev.creators = _dedupe_strings([*ev.creators, *_extract_names(node.get("creators"))])
        ev.labels = _dedupe_strings([*ev.labels, *_extract_values(node, "objectLabel", "value")])
        ev.markings = _dedupe_strings([*ev.markings, *_extract_markings(node)])

        if ev.author:
            ev.notes.append(f"Author: {ev.author}")
        if ev.creators:
            ev.notes.append(f"Creators: {', '.join(ev.creators)}")
        if ev.markings:
            ev.notes.append(f"Markings: {', '.join(ev.markings)}")
        if ev.labels:
            ev.notes.append(f"Labels: {', '.join(ev.labels)}")

    def _parse_indicators(self, ev: OpenCTIEvidence, raw: dict) -> None:
        nodes = (
            raw.get("data", {})
               .get("stixCyberObservable", {})
               .get("indicators", {})
               .get("edges", [])
        )
        for edge in nodes:
            ind = edge.get("node") or {}
            if not ind:
                continue
            ev.indicators.append(OpenCTIIndicator(
                id=ind.get("id", ""),
                name=ind.get("name", ""),
                pattern=ind.get("pattern") or "",
                valid_from=_str_or_none(ind.get("valid_from")),
                valid_until=_str_or_none(ind.get("valid_until")),
                confidence=int(ind.get("confidence") or 0),
                revoked=bool(ind.get("revoked")),
            ))

    def _parse_reports(self, ev: OpenCTIEvidence, raw: dict) -> None:
        nodes = (
            raw.get("data", {})
               .get("stixCyberObservable", {})
               .get("reports", {})
               .get("edges", [])
        )
        for edge in nodes:
            rep = edge.get("node") or {}
            if not rep:
                continue
            ev.reports.append(OpenCTIReport(
                id=rep.get("id", ""),
                name=rep.get("name", ""),
                description=rep.get("description") or "",
                published=_str_or_none(rep.get("published")),
                author=_extract_name(rep.get("createdBy")),
                creators=_extract_names(rep.get("creators")),
                labels=_extract_values(rep, "objectLabel", "value"),
                report_types=_dedupe_strings(rep.get("report_types") or []),
                created=_str_or_none(rep.get("created")),
                modified=_str_or_none(rep.get("modified")),
            ))

    def _parse_relationships(self, ev: OpenCTIEvidence, raw: dict) -> None:
        rel_edges = (
            raw.get("data", {})
               .get("stixCoreRelationships", {})
               .get("edges", [])
        )
        for rel_node in _iter_edges_list(rel_edges):
            to    = rel_node.get("to") or {}
            etype = str(to.get("entity_type") or "").lower().replace("-", "")

            if "threatactor" in etype:
                actor = OpenCTIThreatActor(
                    id=to.get("id", ""), name=to.get("name", ""),
                    entity_type=to.get("entity_type", "Threat-Actor"),
                    sophistication=_str_or_none(to.get("sophistication")),
                    resource_level=_str_or_none(to.get("resource_level")),
                )
                if not any(a.id == actor.id for a in ev.threat_actors):
                    ev.threat_actors.append(actor)

            elif etype == "malware":
                m = OpenCTIMalware(
                    id=to.get("id", ""), name=to.get("name", ""),
                    malware_types=to.get("malware_types") or [],
                    first_seen=_str_or_none(to.get("first_seen")),
                )
                if not any(x.id == m.id for x in ev.malware_families):
                    ev.malware_families.append(m)

            elif etype == "attackpattern":
                ap = OpenCTIAttackPattern(
                    id=to.get("id", ""), name=to.get("name", ""),
                    mitre_id=_str_or_none(to.get("x_mitre_id")),
                )
                if not any(x.id == ap.id for x in ev.attack_patterns):
                    ev.attack_patterns.append(ap)

            elif etype == "campaign":
                name = to.get("name") or ""
                if name and name not in ev.campaigns:
                    ev.campaigns.append(name)

            elif etype == "intrusionset":
                name = to.get("name") or ""
                if name and name not in ev.intrusion_sets:
                    ev.intrusion_sets.append(name)

        if ev.threat_actors:
            ev.notes.append(f"Linked threat actors: {', '.join(a.name for a in ev.threat_actors)}")
        if ev.malware_families:
            ev.notes.append(f"Associated malware: {', '.join(m.name for m in ev.malware_families)}")
        if ev.campaigns:
            ev.notes.append(f"Campaigns: {', '.join(ev.campaigns)}")
        if ev.intrusion_sets:
            ev.notes.append(f"Intrusion sets: {', '.join(ev.intrusion_sets)}")


# ── Module-level helpers ─────────────────────────────────────────────────────

def _best_node(raw: dict, query_field: str, term: str) -> dict | None:
    """Return the node whose observable_value actually matches the searched term."""
    edges = raw.get("data", {}).get(query_field, {}).get("edges", [])
    if not edges:
        return None
    sv = term.strip().lower()
    for edge in edges:
        node = edge.get("node") or {}
        val = str(node.get("observable_value") or "").strip()
        if _observable_matches_term(val, sv):
            return node
    return None


def _observable_matches_term(observable_value: str, searched_term: str) -> bool:
    value = (observable_value or "").strip().lower()
    term = (searched_term or "").strip().lower()
    if not value or not term:
        return False

    if value == term:
        return True

    parsed_value = _parse_url_like(value)
    parsed_term = _parse_url_like(term)

    # Domain searches may legitimately match URL observables hosted on that domain.
    if parsed_term["host"]:
        if value == parsed_term["host"]:
            return True
        if parsed_value["host"] == parsed_term["host"]:
            return True

    # URL searches may also match a bare host-only observable for the same hostname.
    if parsed_value["host"] and term == parsed_value["host"]:
        return True

    return False


def _parse_url_like(value: str) -> dict[str, str]:
    try:
        parsed = urlparse(value if "://" in value else f"//{value}", scheme="")
    except Exception:
        return {"host": "", "path": ""}
    return {
        "host": (parsed.hostname or "").strip().lower(),
        "path": (parsed.path or "").strip(),
    }


def _iter_nodes(node: dict, field: str):
    container = node.get(field)
    if not container:
        return
    if isinstance(container, list):
        for item in container:
            if item:
                yield item
        return
    if isinstance(container, dict):
        edges = container.get("edges")
        if isinstance(edges, list):
            for edge in edges:
                inner = edge.get("node") if isinstance(edge, dict) else edge
                if inner:
                    yield inner
            return
        yield container


def _iter_edges_list(edges: list):
    for edge in edges:
        inner = edge.get("node") or edge
        if inner:
            yield inner


def _str_or_none(val: Any) -> str | None:
    if val is None:
        return None
    s = str(val).strip()
    return s if s else None


def _extract_name(node: Any) -> str | None:
    if isinstance(node, dict):
        return _str_or_none(node.get("name"))
    return None


def _extract_values(node: dict[str, Any], field: str, key: str) -> list[str]:
    values: list[str] = []
    for item in _iter_nodes(node, field):
        value = _str_or_none(item.get(key))
        if value:
            values.append(value)
    return _dedupe_strings(values)


def _extract_names(values: Any) -> list[str]:
    if not isinstance(values, list):
        return []
    out: list[str] = []
    for item in values:
        if isinstance(item, dict):
            name = _str_or_none(item.get("name"))
            if name:
                out.append(name)
        else:
            text = _str_or_none(item)
            if text:
                out.append(text)
    return _dedupe_strings(out)


def _extract_markings(node: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for item in _iter_nodes(node, "objectMarking"):
        definition = _str_or_none(item.get("definition"))
        if definition:
            values.append(definition)
            continue
        definition_type = _str_or_none(item.get("definition_type"))
        if definition_type:
            values.append(definition_type)
    return _dedupe_strings(values)


def _dedupe_strings(values: list[Any]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = _str_or_none(value)
        if not text:
            continue
        key = text.casefold()
        if key in seen:
            continue
        seen.add(key)
        out.append(text)
    return out


def _safe_name(term: str) -> str:
    """Sanitise a search term for use as an artifact filename fragment."""
    return re.sub(r"[^a-zA-Z0-9_.-]", "_", term)[:40]


def _extract_hash(raw: str) -> str:
    value = raw or ""
    for prefix in ("md5:", "sha1:", "sha256:", "sha512:"):
        if value.lower().startswith(prefix):
            value = value[len(prefix):]
            break
    for pattern in (r"[0-9a-fA-F]{64}", r"[0-9a-fA-F]{40}", r"[0-9a-fA-F]{32}"):
        m = re.search(pattern, value)
        if m:
            return m.group(0)
    return ""
