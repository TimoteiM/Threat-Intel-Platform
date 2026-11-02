"""OpenCTI GraphQL responses may null out a field whose resolver errored.

Before the safe traversal helpers, `data.stixCyberObservables = null` crashed the
collector with AttributeError — every indicator was reported as "failed" instead
of "not found in OpenCTI".
"""

from app.collectors.opencti_collector import _best_node, _gql_edges, _gql_path


def test_edges_of_nulled_field_is_empty():
    raw = {"data": {"stixCyberObservables": None}, "errors": [{"message": "bad filter key"}]}
    assert _gql_edges(raw, "stixCyberObservables") == []


def test_edges_of_null_data_is_empty():
    assert _gql_edges({"data": None}, "stixCyberObservables") == []
    assert _gql_edges({}, "stixCyberObservables") == []
    assert _gql_edges(None, "stixCyberObservables") == []


def test_edges_of_nested_nulled_field_is_empty():
    raw = {"data": {"stixCyberObservable": {"indicators": None}}}
    assert _gql_edges(raw, "stixCyberObservable", "indicators") == []


def test_edges_drops_non_dict_entries():
    raw = {"data": {"stixCyberObservables": {"edges": [None, {"node": {"id": "a"}}, "junk"]}}}
    assert _gql_edges(raw, "stixCyberObservables") == [{"node": {"id": "a"}}]


def test_gql_path_walks_and_stops_at_null():
    raw = {"data": {"stixCyberObservable": {"standard_id": "observable--1"}}}
    assert _gql_path(raw, "data", "stixCyberObservable", "standard_id") == "observable--1"
    assert _gql_path({"data": None}, "data", "stixCyberObservable") is None


def test_best_node_returns_none_for_nulled_field():
    raw = {"data": {"stixCyberObservables": None}}
    assert _best_node(raw, "stixCyberObservables", "evil.com") is None


def test_best_node_matches_the_searched_value():
    raw = {
        "data": {
            "stixCyberObservables": {
                "edges": [
                    {"node": {"entity_type": "Domain-Name", "observable_value": "other.com"}},
                    {"node": {"entity_type": "Domain-Name", "observable_value": "evil.com"}},
                ]
            }
        }
    }
    node = _best_node(raw, "stixCyberObservables", "evil.com", allowed_types=["Domain-Name"])
    assert node is not None
    assert node["observable_value"] == "evil.com"
