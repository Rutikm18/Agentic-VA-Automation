"""
Neo4jClient — thin, optional wrapper around the neo4j Python driver.

Neo4j is *optional*: the attack-path engine builds and analyses an in-memory
NetworkX graph regardless, and mirrors it into Neo4j only when a client is
provided and connected. This keeps the engine fully testable without a running
database while still supporting Cypher shortest-path queries at scale.

Indexing strategy for large graphs (>10k nodes):
  * UNIQUE constraint on :Asset(id) — also creates a backing index, makes node
    MERGE O(log n) instead of a label scan.
  * Range indexes on :Asset(engagement_id), :Asset(criticality), and
    :Asset(internet_exposed) so source/target selection and per-engagement
    sub-graph extraction don't scan every node.
  * Index on :Finding(cvss) to let path scoring pull exploit weights via index.
  * shortestPath/allShortestPaths with a bounded variable-length pattern
    (`[*..10]`) so traversal cost stays bounded on dense graphs.
"""
from __future__ import annotations

from typing import Any

import structlog

logger = structlog.get_logger()

try:
    from neo4j import GraphDatabase

    _HAS_NEO4J = True
except ImportError:  # pragma: no cover
    GraphDatabase = None  # type: ignore
    _HAS_NEO4J = False


# Constraints + indexes applied once per database (idempotent).
SCHEMA_STATEMENTS: list[str] = [
    "CREATE CONSTRAINT asset_id IF NOT EXISTS FOR (a:Asset) REQUIRE a.id IS UNIQUE",
    "CREATE CONSTRAINT finding_id IF NOT EXISTS FOR (f:Finding) REQUIRE f.id IS UNIQUE",
    "CREATE CONSTRAINT service_id IF NOT EXISTS FOR (s:Service) REQUIRE s.id IS UNIQUE",
    "CREATE INDEX asset_engagement IF NOT EXISTS FOR (a:Asset) ON (a.engagement_id)",
    "CREATE INDEX asset_criticality IF NOT EXISTS FOR (a:Asset) ON (a.criticality)",
    "CREATE INDEX asset_exposed IF NOT EXISTS FOR (a:Asset) ON (a.internet_exposed)",
    "CREATE INDEX finding_cvss IF NOT EXISTS FOR (f:Finding) ON (f.cvss)",
]


class Neo4jClient:
    """Connection holder + query helper. No-ops cleanly when the driver is absent."""

    def __init__(self, uri: str, user: str, password: str):
        self._uri = uri
        self._user = user
        self._password = password
        self._driver: Any = None

    @property
    def available(self) -> bool:
        return _HAS_NEO4J

    def connect(self) -> bool:
        """Open the driver and verify connectivity. Returns False on any failure."""
        if not _HAS_NEO4J:
            logger.warning("graph.neo4j.driver_missing", hint="pip install neo4j")
            return False
        try:
            self._driver = GraphDatabase.driver(self._uri, auth=(self._user, self._password))
            self._driver.verify_connectivity()
            logger.info("graph.neo4j.connected", uri=self._uri)
            return True
        except Exception as exc:
            logger.warning("graph.neo4j.connect_failed", uri=self._uri, error=str(exc))
            self._driver = None
            return False

    def ensure_schema(self) -> None:
        """Apply constraints + indexes (idempotent)."""
        if self._driver is None:
            return
        with self._driver.session() as session:
            for stmt in SCHEMA_STATEMENTS:
                try:
                    session.run(stmt)
                except Exception as exc:
                    logger.debug("graph.neo4j.schema_stmt_failed", stmt=stmt, error=str(exc))

    def run(self, cypher: str, **params: Any) -> list[dict[str, Any]]:
        """Run a Cypher statement and return records as dicts. [] if not connected."""
        if self._driver is None:
            return []
        with self._driver.session() as session:
            result = session.run(cypher, **params)
            return [dict(record) for record in result]

    def run_write(self, cypher: str, batch: list[dict[str, Any]]) -> None:
        """Run a parametrised write with UNWIND batching for bulk node/edge loads."""
        if self._driver is None or not batch:
            return
        with self._driver.session() as session:
            session.run(cypher, batch=batch)

    def close(self) -> None:
        if self._driver is not None:
            try:
                self._driver.close()
            finally:
                self._driver = None
