"""
Unit tests for the attack-path analysis engine (Prompt 6).

The engine is exercised entirely in-memory (NetworkX) using the demo dataset —
no Neo4j and no database required. Neo4j integration is covered by guarded
no-op assertions.
"""
from __future__ import annotations

import uuid
from decimal import Decimal

import pytest

from app.graph.analyzer import (
    CYPHER_BLAST_RADIUS,
    CYPHER_CHOKEPOINTS,
    CYPHER_SHORTEST_PATH,
    PathAnalyzer,
)
from app.graph.builder import (
    GraphBuilder,
    asset_node_id,
    exploit_complexity,
    finding_node_id,
    is_internet_exposed,
)
from app.graph.demo import DemoAsset, DemoFinding, generate_demo_dataset
from app.graph.neo4j_client import Neo4jClient
from app.graph.visualizer import GraphVisualizer


@pytest.fixture
def demo():
    return generate_demo_dataset()


@pytest.fixture
def built_graph(demo):
    gb = GraphBuilder()
    g = gb.build_asset_graph(
        demo["engagement_id"], demo["assets"], demo["services"],
        demo["findings"], demo["credentials"], demo["network_topology"],
    )
    return g


# ═══════════════════════════════════════════════════════════════════════════════
# GraphBuilder
# ═══════════════════════════════════════════════════════════════════════════════

class TestGraphBuilder:

    def test_nodes_and_edges_created(self, built_graph, demo):
        # 4 assets + 4 services + 4 findings + 3 segments + 1 credential = 16
        assert built_graph.number_of_nodes() == 16
        assert built_graph.number_of_edges() > 0

    def test_asset_node_attributes(self, built_graph, demo):
        web = built_graph.nodes[asset_node_id(demo["assets"][0].id)]
        assert web["type"] == "Asset"
        assert web["internet_exposed"] is True
        assert web["criticality"] == "high"

    def test_has_service_and_has_finding_edges(self, built_graph, demo):
        types = {d["type"] for _, _, d in built_graph.edges(data=True)}
        assert "HAS_SERVICE" in types
        assert "HAS_FINDING" in types

    def test_exploit_edges_only_for_exploitable(self, demo):
        gb = GraphBuilder()
        gb.build_asset_graph(demo["engagement_id"], demo["assets"], [], demo["findings"])
        exploits = [(u, v) for u, v, d in gb.graph.edges(data=True) if d["type"] == "EXPLOITS"]
        # 3 of the 4 demo findings are exploitable.
        assert len(exploits) == 3

    def test_connects_to_and_same_segment_edges(self, built_graph):
        types = {d["type"] for _, _, d in built_graph.edges(data=True)}
        assert "CONNECTS_TO" in types
        assert "SAME_SEGMENT" in types

    def test_credential_reuse_edges(self, built_graph):
        cred_edges = [(u, v) for u, v, d in built_graph.edges(data=True)
                      if d["type"] == "CREDENTIAL_REUSE"]
        assert len(cred_edges) == 2  # bidirectional between the 2 reused hosts

    def test_is_internet_exposed(self):
        exposed = DemoAsset(uuid.uuid4(), "h", "1.1.1.1", environment="dmz")
        internal = DemoAsset(uuid.uuid4(), "h2", "10.0.0.1", environment="internal")
        tagged = DemoAsset(uuid.uuid4(), "h3", "10.0.0.2", tags={"internet_exposed": True})
        assert is_internet_exposed(exposed) is True
        assert is_internet_exposed(internal) is False
        assert is_internet_exposed(tagged) is True

    def test_exploit_complexity_from_vector(self):
        easy = DemoFinding(uuid.uuid4(), uuid.uuid4(), "t", "high", Decimal("8"),
                           cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N")
        hard = DemoFinding(uuid.uuid4(), uuid.uuid4(), "t", "high", Decimal("8"),
                           cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N")
        assert exploit_complexity(easy) < exploit_complexity(hard)

    def test_exploit_complexity_falls_back_to_severity(self):
        crit = DemoFinding(uuid.uuid4(), uuid.uuid4(), "t", "critical", Decimal("9"))
        low = DemoFinding(uuid.uuid4(), uuid.uuid4(), "t", "low", Decimal("3"))
        assert exploit_complexity(crit) < exploit_complexity(low)


# ═══════════════════════════════════════════════════════════════════════════════
# PathAnalyzer
# ═══════════════════════════════════════════════════════════════════════════════

class TestPathAnalyzer:

    def test_find_paths_to_target(self, built_graph, demo):
        pa = PathAnalyzer(built_graph)
        paths = pa.find_paths_to_target(demo["critical_asset_id"])
        assert len(paths) >= 1
        # every path starts at an internet-exposed source and ends at the target
        for p in paths:
            assert p["target"] == demo["critical_asset_id"]
            assert p["source"] == demo["exposed_asset_id"]

    def test_paths_sorted_by_risk_desc(self, built_graph, demo):
        pa = PathAnalyzer(built_graph)
        paths = pa.find_paths_to_target(demo["critical_asset_id"])
        scores = [p["risk_score"] for p in paths]
        assert scores == sorted(scores, reverse=True)

    def test_no_paths_for_unknown_target(self, built_graph):
        pa = PathAnalyzer(built_graph)
        assert pa.find_paths_to_target(str(uuid.uuid4())) == []

    def test_score_path_rewards_cvss_penalises_hops(self, built_graph):
        pa = PathAnalyzer(built_graph)
        short = {"hops": 1, "edges": [{"cvss": 9.0, "technique": "CONNECTS_TO"}]}
        long = {"hops": 5, "edges": [{"cvss": 9.0, "technique": "CONNECTS_TO"}]}
        assert pa.score_path(short) > pa.score_path(long)

    def test_score_path_credential_reuse_bonus(self, built_graph):
        pa = PathAnalyzer(built_graph)
        without = {"hops": 2, "edges": [{"cvss": 5.0, "technique": "CONNECTS_TO"}]}
        with_cred = {"hops": 2, "edges": [{"cvss": 5.0, "technique": "CREDENTIAL_REUSE"}]}
        assert pa.score_path(with_cred) > pa.score_path(without)

    def test_score_path_clamped_0_100(self, built_graph):
        pa = PathAnalyzer(built_graph)
        huge = {"hops": 1, "edges": [{"cvss": 10.0, "technique": "X"} for _ in range(20)]}
        assert 0.0 <= pa.score_path(huge) <= 100.0

    def test_identify_chokepoints(self, built_graph, demo):
        pa = PathAnalyzer(built_graph)
        paths = pa.find_paths_to_target(demo["critical_asset_id"])
        chokepoints = pa.identify_chokepoints(paths)
        # app01 sits on every demo path to db01.
        assert any(c["path_fraction"] >= 0.5 for c in chokepoints)
        for c in chokepoints:
            assert c["remediation_priority"] in ("medium", "high", "critical")

    def test_chokepoints_empty_without_paths(self, built_graph):
        pa = PathAnalyzer(built_graph)
        assert pa.identify_chokepoints([]) == []

    def test_find_blast_radius(self, built_graph, demo):
        pa = PathAnalyzer(built_graph)
        result = pa.find_blast_radius(demo["exposed_asset_id"])
        assert result["count"] >= 1
        assert demo["critical_asset_id"] in result["reachable"]
        assert "by_distance" in result

    def test_blast_radius_unknown_asset(self, built_graph):
        pa = PathAnalyzer(built_graph)
        result = pa.find_blast_radius(str(uuid.uuid4()))
        assert result["count"] == 0

    def test_cypher_constants_present(self):
        assert "shortestPath" in CYPHER_SHORTEST_PATH
        assert "$asset_id" in CYPHER_BLAST_RADIUS
        assert "critical" in CYPHER_CHOKEPOINTS


# ═══════════════════════════════════════════════════════════════════════════════
# GraphVisualizer
# ═══════════════════════════════════════════════════════════════════════════════

class TestGraphVisualizer:

    def test_d3_shape(self, built_graph, demo):
        pa = PathAnalyzer(built_graph)
        paths = pa.find_paths_to_target(demo["critical_asset_id"])
        d3 = GraphVisualizer(built_graph).to_d3(paths)
        assert set(d3.keys()) == {"nodes", "edges", "paths"}
        node = d3["nodes"][0]
        assert {"id", "label", "type", "criticality", "compromised", "x", "y"} <= set(node)
        edge = d3["edges"][0]
        assert {"source", "target", "technique", "weight", "exploited"} <= set(edge)

    def test_d3_marks_compromised(self, built_graph, demo):
        d3 = GraphVisualizer(built_graph).to_d3(compromised={demo["exposed_asset_id"]})
        flagged = [n for n in d3["nodes"] if n["compromised"]]
        assert any(n["id"] == demo["exposed_asset_id"] for n in flagged)

    def test_d3_highlights_top_path(self, built_graph, demo):
        pa = PathAnalyzer(built_graph)
        paths = pa.find_paths_to_target(demo["critical_asset_id"])
        for i, p in enumerate(paths):
            p["id"] = f"path-{i}"
        d3 = GraphVisualizer(built_graph).to_d3(paths)
        assert d3["paths"][0]["highlighted"] is True

    def test_layout_is_deterministic(self, built_graph):
        a = GraphVisualizer(built_graph).to_d3()
        b = GraphVisualizer(built_graph).to_d3()
        assert [(n["x"], n["y"]) for n in a["nodes"]] == [(n["x"], n["y"]) for n in b["nodes"]]


# ═══════════════════════════════════════════════════════════════════════════════
# Neo4jClient (guarded, no live DB)
# ═══════════════════════════════════════════════════════════════════════════════

class TestNeo4jClient:

    def test_run_without_connection_returns_empty(self):
        client = Neo4jClient("bolt://localhost:7687", "neo4j", "x")
        assert client.run("MATCH (n) RETURN n") == []

    def test_run_write_noop_without_connection(self):
        client = Neo4jClient("bolt://localhost:7687", "neo4j", "x")
        client.run_write("UNWIND $batch AS n RETURN n", [{"a": 1}])  # no raise

    def test_sync_to_neo4j_noop_without_client(self, built_graph, demo):
        gb = GraphBuilder(neo4j=None)
        gb.graph = built_graph
        assert gb.sync_to_neo4j(demo["engagement_id"]) == {"nodes": 0, "edges": 0}
