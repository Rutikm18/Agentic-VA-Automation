"""
BloodHoundCollector — wrapper around the BloodHound.py collector + a Neo4j
ingestion/query layer for shortest-path-to-Domain-Admins analysis.

Three stages:
  1. run_collection  — shell out to ``bloodhound-python`` to produce the JSON
                       collector output (users/computers/groups/etc.).
  2. import_to_neo4j — load the collected nodes and membership edges into Neo4j.
  3. query_da_paths  — run a Cypher shortestPath query to Domain Admins and
                       return each path as Finding evidence.

``bloodhound-python`` and the ``neo4j`` driver are optional; methods degrade
gracefully (empty result + warning) when they are absent.
"""
from __future__ import annotations

import asyncio
import glob
import json
import os
import shutil
import tempfile
from typing import Any

import structlog

from app.ad.findings import build_ad_finding
from app.models.enums import FindingSeverity

logger = structlog.get_logger()

try:
    from neo4j import GraphDatabase  # type: ignore

    _HAS_NEO4J = True
except ImportError:  # pragma: no cover
    GraphDatabase = None  # type: ignore
    _HAS_NEO4J = False


class BloodHoundCollector:
    COLLECTOR_BIN = "bloodhound-python"
    MITRE = ["T1482"]  # Domain Trust Discovery / attack path mapping
    CWE = "CWE-269"    # Improper Privilege Management

    def __init__(self) -> None:
        self._driver: Any = None
        self._output_dir: str | None = None

    # ── run_collection ────────────────────────────────────────────────────────────

    async def run_collection(
        self,
        dc_ip: str,
        domain: str,
        credentials: dict[str, str],
        collection_methods: list[str] | None = None,
        output_dir: str | None = None,
        timeout_sec: int = 600,
    ) -> list[str]:
        """
        Run bloodhound-python and return the list of produced JSON file paths.
        Returns [] if the collector binary is not installed.
        """
        collection_methods = collection_methods or ["All"]
        if not shutil.which(self.COLLECTOR_BIN):
            logger.warning(
                "ad.bloodhound.collector_missing",
                hint="pip install bloodhound (provides bloodhound-python)",
            )
            return []

        self._output_dir = output_dir or tempfile.mkdtemp(prefix="bloodhound_")
        username = credentials.get("username", "")
        password = credentials.get("password", "")

        cmd = [
            self.COLLECTOR_BIN,
            "-u", username,
            "-p", password,
            "-d", domain,
            "-dc", dc_ip,
            "-ns", dc_ip,
            "-c", ",".join(collection_methods),
            # No --zip: bloodhound-python writes individual JSON files we ingest directly.
        ]
        # bloodhound-python writes output to CWD; run inside output_dir.
        logger.info("ad.bloodhound.collect.start", domain=domain, methods=collection_methods)

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                cwd=self._output_dir,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                _stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=float(timeout_sec))
            except asyncio.TimeoutError:
                proc.kill()
                logger.error("ad.bloodhound.collect.timeout")
                return []
        except Exception as exc:
            logger.error("ad.bloodhound.collect.failed", error=str(exc))
            return []

        if proc.returncode != 0:
            logger.warning("ad.bloodhound.collect.nonzero", rc=proc.returncode,
                           stderr=stderr.decode("utf-8", "replace")[:500])

        json_files = sorted(glob.glob(os.path.join(self._output_dir, "*.json")))
        logger.info("ad.bloodhound.collect.done", files=len(json_files))
        return json_files

    # ── import_to_neo4j ───────────────────────────────────────────────────────────

    def import_to_neo4j(
        self,
        json_files: list[str],
        neo4j_uri: str,
        neo4j_user: str,
        neo4j_password: str,
    ) -> dict[str, int]:
        """
        Load nodes (users/computers/groups) and MemberOf edges into Neo4j.

        Returns {nodes, relationships}. Returns zeros if the neo4j driver is
        missing or no files were collected.
        """
        if not _HAS_NEO4J:
            logger.warning("ad.bloodhound.no_neo4j", hint="pip install neo4j")
            return {"nodes": 0, "relationships": 0}
        if not json_files:
            return {"nodes": 0, "relationships": 0}

        self._driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))
        nodes = rels = 0

        with self._driver.session() as session:
            # Constraints make repeated imports idempotent.
            session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (n:Base) REQUIRE n.objectid IS UNIQUE")
            for path in json_files:
                try:
                    with open(path, "r", encoding="utf-8") as fh:
                        data = json.load(fh)
                except (OSError, json.JSONDecodeError) as exc:
                    logger.warning("ad.bloodhound.import.bad_file", path=path, error=str(exc))
                    continue
                n, r = self._ingest_collection(session, data)
                nodes += n
                rels += r

        logger.info("ad.bloodhound.import.done", nodes=nodes, relationships=rels)
        return {"nodes": nodes, "relationships": rels}

    def _ingest_collection(self, session: Any, data: dict[str, Any]) -> tuple[int, int]:
        """Ingest one BloodHound collector file. Returns (#nodes, #rels)."""
        nodes = rels = 0
        label_map = {
            "users": "User",
            "computers": "Computer",
            "groups": "Group",
            "domains": "Domain",
            "ous": "OU",
            "gpos": "GPO",
        }
        for key, label in label_map.items():
            for obj in data.get(key, []):
                props = obj.get("Properties", {}) or {}
                objectid = obj.get("ObjectIdentifier") or props.get("objectid")
                name = props.get("name") or props.get("samaccountname")
                if not objectid:
                    continue
                session.run(
                    f"MERGE (n:Base {{objectid: $oid}}) SET n:{label}, n.name = $name",
                    oid=objectid, name=name,
                )
                nodes += 1

                # MemberOf edges from group membership ("Members" or "Aces").
                for member in (obj.get("Members") or []):
                    member_id = member.get("ObjectIdentifier") if isinstance(member, dict) else member
                    if not member_id:
                        continue
                    session.run(
                        "MATCH (m:Base {objectid: $mid}) MATCH (g:Base {objectid: $gid}) "
                        "MERGE (m)-[:MemberOf]->(g)",
                        mid=member_id, gid=objectid,
                    )
                    rels += 1
        return nodes, rels

    # ── query_da_paths ────────────────────────────────────────────────────────────

    def query_da_paths(self, max_paths: int = 25) -> list[dict[str, Any]]:
        """
        Return shortest attack paths from any non-DA principal to a Domain Admins
        group as path dicts {start, end, length, nodes}. Empty list if no driver.
        """
        if self._driver is None:
            logger.warning("ad.bloodhound.no_driver", hint="call import_to_neo4j first")
            return []

        cypher = (
            "MATCH (da:Group) WHERE toLower(da.name) CONTAINS 'domain admins' "
            "MATCH p = shortestPath((s:Base)-[*1..6]->(da)) "
            "WHERE s <> da AND NONE(n IN nodes(p)[1..] WHERE n = s) "
            "RETURN [n IN nodes(p) | n.name] AS names, length(p) AS len "
            "ORDER BY len ASC LIMIT $limit"
        )
        paths: list[dict[str, Any]] = []
        try:
            with self._driver.session() as session:
                for record in session.run(cypher, limit=max_paths):
                    names = record["names"]
                    paths.append({
                        "start": names[0] if names else None,
                        "end": names[-1] if names else None,
                        "length": record["len"],
                        "nodes": names,
                    })
        except Exception as exc:
            logger.warning("ad.bloodhound.query_failed", error=str(exc))
            return []

        logger.info("ad.bloodhound.da_paths", count=len(paths))
        return paths

    def generate_finding(self, da_paths: list[dict[str, Any]]) -> dict[str, Any] | None:
        """Build a Finding summarising the shortest paths to Domain Admins."""
        if not da_paths:
            return None

        shortest = min(p["length"] for p in da_paths)
        sample = " -> ".join(da_paths[0]["nodes"]) if da_paths[0].get("nodes") else ""
        return build_ad_finding(
            title=f"Attack paths to Domain Admins ({len(da_paths)}; shortest = {shortest} hops)",
            severity=FindingSeverity.critical if shortest <= 2 else FindingSeverity.high,
            description=(
                "BloodHound graph analysis identified privilege-escalation paths "
                "from low-privileged principals to the Domain Admins group via "
                f"group memberships and ACL/control edges. Shortest path: {shortest} "
                f"hop(s). Example: {sample}"
            ),
            mitre_techniques=self.MITRE + ["T1078.002"],
            cwe=self.CWE,
            reproduction=[
                "Collect graph data: bloodhound-python -u user -p pass -d domain -c All",
                "Import into BloodHound and run the 'Shortest Paths to Domain Admins' query.",
                "Follow each edge (group membership, ACL right, session) to escalate.",
            ],
            detection_opportunity=(
                "Review and prune the identified edges (excessive group nesting, "
                "ACL grants, and privileged sessions on non-tiered hosts). Monitor "
                "additions to privileged groups (Event ID 4728/4732/4756)."
            ),
            remediation=(
                "Implement tiered administration, remove unnecessary group "
                "memberships and ACL grants along the paths, and ensure privileged "
                "accounts do not log on to lower-tier hosts. Re-run analysis after "
                "remediation to confirm the paths are broken."
            ),
            exploitable=True,
            evidence_extra={"paths": da_paths, "shortest_hops": shortest},
        )

    def close(self) -> None:
        if self._driver is not None:
            try:
                self._driver.close()
            except Exception:
                pass
            self._driver = None
