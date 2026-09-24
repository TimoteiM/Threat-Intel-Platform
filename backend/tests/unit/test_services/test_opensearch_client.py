"""The OpenSearch client: failover, paging, and never printing the password.

No cluster. httpx is replaced at the transport level so the failure modes that
matter — a node refusing connections, a node returning 500, a wrong password —
are exercised as they actually arrive rather than as mocks of what they might be.
"""

from __future__ import annotations

import httpx
import pytest

from app.services import opensearch_client as osc


NODES = ("https://os-1:9200", "https://os-2:9200", "https://os-3:9200")


class Settings:
    opensearch_node1, opensearch_node2, opensearch_node3 = NODES
    opensearch_username = "admin"
    opensearch_password = "hunter2-the-real-one"
    opensearch_verify_tls = False
    opensearch_ca_bundle = ""
    opensearch_connect_timeout_seconds = 1
    opensearch_request_timeout_seconds = 2


@pytest.fixture(autouse=True)
def _clean_health():
    osc.reset_node_health()
    yield
    osc.reset_node_health()


def _client(handler, settings=None):
    client = osc.OpenSearchClient(settings=settings or Settings())
    client._client = httpx.Client(
        transport=httpx.MockTransport(handler),
        auth=(client._username, client._password),
    )
    return client


# --- credentials -------------------------------------------------------------

def test_the_password_is_unwrapped_from_a_secret():
    """pydantic renders a SecretStr as `**********`, which reaches the cluster
    as a wrong password and comes back 401 — a bug that looks like a
    misconfiguration rather than like a bug."""
    from pydantic import SecretStr

    class Secret(Settings):
        opensearch_password = SecretStr("hunter2-the-real-one")

    client = osc.OpenSearchClient(settings=Secret())
    try:
        assert client._password == "hunter2-the-real-one"
    finally:
        client.close()


def test_redaction_removes_the_password_from_anything_logged():
    text = "GET https://admin:hunter2-the-real-one@os-1:9200/ failed; Authorization: Basic abc123"
    out = osc.redact(text, username="admin", password="hunter2-the-real-one")
    assert "hunter2-the-real-one" not in out
    assert "abc123" not in out
    assert "***" in out


def test_a_connection_error_never_carries_the_password_into_the_log(caplog):
    """httpx puts the URL in its exception text, and a URL can carry basic auth."""
    def handler(request):
        raise httpx.ConnectError(
            "failed connecting to https://admin:hunter2-the-real-one@os-1:9200"
        )

    client = _client(handler)
    with caplog.at_level("INFO"):
        with pytest.raises(osc.OpenSearchUnavailable) as caught:
            client.ping()
    client.close()

    assert "hunter2-the-real-one" not in caplog.text
    assert "hunter2-the-real-one" not in str(caught.value)


# --- failover ----------------------------------------------------------------

def test_a_dead_node_is_skipped_and_another_answers():
    """An unavailable node is not an unavailable cluster, and alert processing
    must not stop because one box is down."""
    seen: list[str] = []

    def handler(request):
        seen.append(request.url.host)
        if request.url.host == "os-1":
            raise httpx.ConnectError("refused")
        return httpx.Response(200, json={"cluster_name": "C00", "version": {"number": "2.19.4"}})

    # Only two nodes, so the rotation cannot accidentally avoid os-1.
    class TwoNodes(Settings):
        opensearch_node1, opensearch_node2, opensearch_node3 = ("https://os-1:9200", "https://os-2:9200", "")

    client = _client(handler, TwoNodes())
    for _ in range(6):
        osc.reset_node_health()
        client.ping()
    client.close()
    assert "os-2" in seen


def test_every_node_failing_is_reported_not_swallowed():
    def handler(request):
        raise httpx.ConnectError("refused")

    client = _client(handler)
    with pytest.raises(osc.OpenSearchUnavailable):
        client.ping()
    client.close()


def test_a_five_hundred_moves_to_the_next_node():
    def handler(request):
        if request.url.host == "os-1":
            return httpx.Response(503, text="node overloaded")
        return httpx.Response(200, json={"cluster_name": "C00", "version": {"number": "2.19.4"}})

    class TwoNodes(Settings):
        opensearch_node1, opensearch_node2, opensearch_node3 = ("https://os-1:9200", "https://os-2:9200", "")

    client = _client(handler, TwoNodes())
    assert client.ping()["cluster"] == "C00"
    client.close()


def test_a_rejected_password_is_not_retried_against_every_node():
    """Three nodes times a wrong password is how an account gets locked out."""
    attempts: list[str] = []

    def handler(request):
        attempts.append(str(request.url))
        return httpx.Response(401, json={"error": "unauthorised"})

    client = _client(handler)
    with pytest.raises(osc.OpenSearchError, match="rejected the credentials"):
        client.ping()
    client.close()
    assert len(attempts) == 1


def test_a_failed_node_is_put_in_cooldown(monkeypatch):
    # The rotation is random on purpose, so concurrent alerts do not all land on
    # node 1. Pinned here, or this test passes or fails on a coin toss.
    monkeypatch.setattr(osc.random, "randrange", lambda _n: 0)

    def handler(request):
        if request.url.host == "os-1":
            raise httpx.ConnectError("refused")
        return httpx.Response(200, json={"cluster_name": "C00", "version": {}})

    class TwoNodes(Settings):
        opensearch_node1, opensearch_node2, opensearch_node3 = ("https://os-1:9200", "https://os-2:9200", "")

    client = _client(handler, TwoNodes())
    client.ping()
    assert not osc._node_is_cool("https://os-1:9200")
    assert osc._node_is_cool("https://os-2:9200")
    client.close()


# --- paging and bounds -------------------------------------------------------

def _paging_handler(total: int, page_size: int):
    def handler(request):
        body = request.read().decode() or "{}"
        import json as _json

        parsed = _json.loads(body)
        after = parsed.get("search_after")
        start = int(after[0]) if after else 0
        size = int(parsed.get("size") or page_size)
        hits = [
            {"_index": "wazuh-alerts-4.x-2026.09.23", "_id": f"doc{i}",
             "_source": {"timestamp": f"t{i}"}, "sort": [i + 1, f"doc{i}"]}
            for i in range(start, min(start + size, total))
        ]
        return httpx.Response(200, json={"hits": {"hits": hits}})

    return handler


def test_paging_walks_the_whole_result_with_search_after():
    client = _client(_paging_handler(total=250, page_size=100))
    result = client.search_all(
        indices=["wazuh-alerts-4.x-2026.09.23"], query={"match_all": {}},
        sort=[{"timestamp": "asc"}, {"_id": "asc"}], page_size=100, max_hits=500,
    )
    client.close()
    assert len(result.hits) == 250
    assert result.pages == 3
    assert result.truncated is False


def test_the_cap_is_enforced_and_declared():
    """23 million documents a day means an uncapped read is how a report takes
    the search cluster down. Hitting the cap is reported, not hidden."""
    client = _client(_paging_handler(total=5000, page_size=100))
    result = client.search_all(
        indices=["i"], query={"match_all": {}},
        sort=[{"timestamp": "asc"}, {"_id": "asc"}], page_size=100, max_hits=250,
    )
    client.close()
    assert len(result.hits) == 250
    assert result.truncated is True


def test_a_repeated_document_is_not_returned_twice():
    """A cluster mid-refresh can hand back an overlapping page."""
    pages = iter([
        [{"_index": "i", "_id": "a", "_source": {}, "sort": [1, "a"]},
         {"_index": "i", "_id": "b", "_source": {}, "sort": [2, "b"]}],
        [{"_index": "i", "_id": "b", "_source": {}, "sort": [2, "b"]},
         {"_index": "i", "_id": "c", "_source": {}, "sort": [3, "c"]}],
        [],
    ])

    def handler(request):
        return httpx.Response(200, json={"hits": {"hits": next(pages, [])}})

    client = _client(handler)
    result = client.search_all(
        indices=["i"], query={"match_all": {}},
        sort=[{"timestamp": "asc"}, {"_id": "asc"}], page_size=2, max_hits=50,
    )
    client.close()
    assert [h["_id"] for h in result.hits] == ["a", "b", "c"]


def test_no_nodes_or_no_credentials_is_a_configuration_error():
    class NoNodes(Settings):
        opensearch_node1 = opensearch_node2 = opensearch_node3 = ""

    with pytest.raises(osc.OpenSearchNotConfigured):
        osc.OpenSearchClient(settings=NoNodes())

    class NoAuth(Settings):
        opensearch_password = ""

    with pytest.raises(osc.OpenSearchNotConfigured):
        osc.OpenSearchClient(settings=NoAuth())


def test_a_missing_ca_bundle_says_so(tmp_path):
    """Otherwise httpx raises a bare FileNotFoundError and a reachable,
    correctly configured cluster is reported as 'not configured'."""
    class WithCa(Settings):
        opensearch_verify_tls = True
        opensearch_ca_bundle = str(tmp_path / "nope.crt")

    with pytest.raises(osc.OpenSearchNotConfigured, match="CA bundle"):
        osc.OpenSearchClient(settings=WithCa())
