from __future__ import annotations

import uuid

from app.collectors import opencti_collector as svc


def test_opencti_collect_finds_observable_when_label_field_is_unavailable(monkeypatch):
    class _Settings:
        opencti_api_url = "https://opencti.example.test"
        opencti_api_key = "token"
        opencti_verify_ssl = False

    class _Response:
        def __init__(self, payload, status_code=200):
            self._payload = payload
            self.status_code = status_code
            self.text = str(payload)

        def json(self):
            return self._payload

    def fake_post(url, headers=None, json=None, timeout=None, verify=None):
        query = (json or {}).get("query") or ""
        variables = (json or {}).get("variables") or {}

        if "GetIndicators" in query:
            return _Response({"data": {"stixCyberObservable": {"indicators": {"edges": []}}}})
        if "GetReports" in query:
            return _Response({"data": {"stixCyberObservable": {"reports": {"edges": []}}}})
        if "GetRelationships" in query:
            return _Response({"data": {"stixCoreRelationships": {"edges": []}}})

        search = variables.get("search")
        if search == "cmmxhurildiigqghlryq.com":
            return _Response(
                {
                    "data": {
                        "stixCyberObservables": {
                            "edges": [
                                {
                                    "node": {
                                        "id": "obs-1",
                                        "entity_type": "Url",
                                        "observable_value": "http://cmmxhurildiigqghlryq.com/post.php",
                                        "x_opencti_score": 42,
                                    }
                                }
                            ]
                        }
                    }
                }
            )

        return _Response({"data": {"stixCyberObservables": {"edges": []}}})

    monkeypatch.setattr(svc, "get_settings", lambda: _Settings())
    monkeypatch.setattr(svc.requests, "post", fake_post)

    collector = svc.OpenCTICollector(
        domain="http://cmmxhurildiigqghlryq.com/post.php",
        observable_type="url",
        investigation_id=uuid.uuid4(),
    )

    ev = collector._collect()

    assert ev.found is True
    assert ev.observable_value == "http://cmmxhurildiigqghlryq.com/post.php"
    assert ev.observable_entity_type == "Url"
    assert ev.score == 42


def test_opencti_collect_includes_observable_and_report_metadata(monkeypatch):
    class _Settings:
        opencti_api_url = "https://opencti.example.test"
        opencti_api_key = "token"
        opencti_verify_ssl = False

    class _Response:
        def __init__(self, payload, status_code=200):
            self._payload = payload
            self.status_code = status_code
            self.text = str(payload)

        def json(self):
            return self._payload

    def fake_post(url, headers=None, json=None, timeout=None, verify=None):
        query = (json or {}).get("query") or ""
        variables = (json or {}).get("variables") or {}

        if "GetObservableMetadata" in query:
            return _Response(
                {
                    "data": {
                        "stixCyberObservable": {
                            "id": "obs-2",
                            "entity_type": "Domain-Name",
                            "observable_value": "thetollroads-paytollth.xin",
                            "x_opencti_score": 50,
                            "standard_id": "domain-name--0000243e-c38a-5799-b01b-eb7e6b9da54c",
                            "created_at": "2025-03-10T15:48:30.000Z",
                            "updated_at": "2025-03-10T15:48:31.000Z",
                            "createdBy": {"id": "org-1", "name": "ALIENVAULT"},
                            "creators": ["ADMIN"],
                            "objectLabel": {
                                "edges": [
                                    {"node": {"value": "chinese asns"}},
                                    {"node": {"value": "domain spoofing"}},
                                ]
                            },
                            "objectMarking": {
                                "edges": [
                                    {"node": {"definition_type": "TLP", "definition": "TLP:CLEAR"}}
                                ]
                            },
                        }
                    }
                }
            )
        if "GetIndicators" in query:
            return _Response({"data": {"stixCyberObservable": {"indicators": {"edges": []}}}})
        if "GetReports" in query:
            return _Response(
                {
                    "data": {
                        "stixCyberObservable": {
                            "reports": {
                                "edges": [
                                    {
                                        "node": {
                                            "id": "rep-1",
                                            "name": "Silent Night report",
                                            "published": "2025-03-10T12:00:00.000Z",
                                            "description": "Domain flagged in infrastructure analysis.",
                                            "createdBy": {"id": "org-2", "name": "OpenCTI Curator"},
                                            "objectLabel": {
                                                "edges": [{"node": {"value": "infrastructure analysis"}}]
                                            },
                                            "report_types": ["threat-report"],
                                            "created": "2025-03-10T10:00:00.000Z",
                                            "modified": "2025-03-10T11:00:00.000Z",
                                            "creators": ["ANALYST"],
                                        }
                                    }
                                ]
                            }
                        }
                    }
                }
            )
        if "GetRelationships" in query:
            return _Response({"data": {"stixCoreRelationships": {"edges": []}}})

        search = variables.get("search")
        if search == "thetollroads-paytollth.xin":
            return _Response(
                {
                    "data": {
                        "stixCyberObservables": {
                            "edges": [
                                {
                                    "node": {
                                        "id": "obs-2",
                                        "entity_type": "Domain-Name",
                                        "observable_value": "thetollroads-paytollth.xin",
                                        "x_opencti_score": 50,
                                    }
                                }
                            ]
                        }
                    }
                }
            )

        return _Response({"data": {"stixCyberObservables": {"edges": []}}})

    monkeypatch.setattr(svc, "get_settings", lambda: _Settings())
    monkeypatch.setattr(svc.requests, "post", fake_post)

    collector = svc.OpenCTICollector(
        domain="thetollroads-paytollth.xin",
        observable_type="domain",
        investigation_id=uuid.uuid4(),
    )

    ev = collector._collect()

    assert ev.found is True
    assert ev.standard_id == "domain-name--0000243e-c38a-5799-b01b-eb7e6b9da54c"
    assert ev.author == "ALIENVAULT"
    assert ev.creators == ["ADMIN"]
    assert ev.markings == ["TLP:CLEAR"]
    assert ev.labels == ["chinese asns", "domain spoofing"]
    assert ev.created_at == "2025-03-10T15:48:30.000Z"
    assert ev.updated_at == "2025-03-10T15:48:31.000Z"
    assert len(ev.reports) == 1
    assert ev.reports[0].author == "OpenCTI Curator"
    assert ev.reports[0].creators == ["ANALYST"]
    assert ev.reports[0].labels == ["infrastructure analysis"]
    assert ev.reports[0].report_types == ["threat-report"]
    assert ev.reports[0].created == "2025-03-10T10:00:00.000Z"
    assert ev.reports[0].modified == "2025-03-10T11:00:00.000Z"


def test_opencti_collect_does_not_accept_unrelated_first_search_result(monkeypatch):
    class _Settings:
        opencti_api_url = "https://opencti.example.test"
        opencti_api_key = "token"
        opencti_verify_ssl = False

    class _Response:
        def __init__(self, payload, status_code=200):
            self._payload = payload
            self.status_code = status_code
            self.text = str(payload)

        def json(self):
            return self._payload

    def fake_post(url, headers=None, json=None, timeout=None, verify=None):
        query = (json or {}).get("query") or ""
        variables = (json or {}).get("variables") or {}

        if "SearchObservable" in query and variables.get("search") == "topfacedating.xyz":
            return _Response(
                {
                    "data": {
                        "stixCyberObservables": {
                            "edges": [
                                {
                                    "node": {
                                        "id": "obs-wrong",
                                        "entity_type": "StixFile",
                                        "observable_value": "HTTP Spy.EXE",
                                        "x_opencti_score": 60,
                                    }
                                }
                            ]
                        }
                    }
                }
            )

        return _Response({"data": {"stixCyberObservables": {"edges": []}}})

    monkeypatch.setattr(svc, "get_settings", lambda: _Settings())
    monkeypatch.setattr(svc.requests, "post", fake_post)

    collector = svc.OpenCTICollector(
        domain="topfacedating.xyz",
        observable_type="domain",
        investigation_id=uuid.uuid4(),
    )

    ev = collector._collect()

    assert ev.found is False
    assert any("Observable not found in OpenCTI" in note for note in ev.notes)


def test_opencti_collect_does_not_match_https_token_for_https_prefixed_domain_search(monkeypatch):
    class _Settings:
        opencti_api_url = "https://opencti.example.test"
        opencti_api_key = "token"
        opencti_verify_ssl = False

    class _Response:
        def __init__(self, payload, status_code=200):
            self._payload = payload
            self.status_code = status_code
            self.text = str(payload)

        def json(self):
            return self._payload

    def fake_post(url, headers=None, json=None, timeout=None, verify=None):
        query = (json or {}).get("query") or ""
        variables = (json or {}).get("variables") or {}

        if "SearchObservable" in query and variables.get("search") == "https://topfacedating.xyz":
            return _Response(
                {
                    "data": {
                        "stixCyberObservables": {
                            "edges": [
                                {
                                    "node": {
                                        "id": "obs-wrong-https",
                                        "entity_type": "StixFile",
                                        "observable_value": "Https",
                                        "x_opencti_score": 60,
                                    }
                                }
                            ]
                        }
                    }
                }
            )

        return _Response({"data": {"stixCyberObservables": {"edges": []}}})

    monkeypatch.setattr(svc, "get_settings", lambda: _Settings())
    monkeypatch.setattr(svc.requests, "post", fake_post)

    collector = svc.OpenCTICollector(
        domain="topfacedating.xyz",
        observable_type="domain",
        investigation_id=uuid.uuid4(),
    )

    ev = collector._collect()

    assert ev.found is False
    assert any("Observable not found in OpenCTI" in note for note in ev.notes)
