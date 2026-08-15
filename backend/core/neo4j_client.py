"""Neo4j async driver wrapper.

Provides a thin async wrapper around the official Neo4j Python driver
for managing entity-relationship graphs (OSINT / dark web investigations).
"""

from __future__ import annotations

import logging
from typing import Any

from neo4j import AsyncGraphDatabase, AsyncDriver

from backend.core.config import settings

logger = logging.getLogger(__name__)


class Neo4jClient:
    """Async Neo4j client for graph operations."""

    def __init__(self) -> None:
        self._driver: AsyncDriver | None = None

    async def connect(self) -> None:
        """Initialize the Neo4j async driver."""
        driver = AsyncGraphDatabase.driver(
            settings.neo4j_uri,
            auth=(settings.neo4j_user, settings.neo4j_password),
        )
        try:
            await driver.verify_connectivity()
        except Exception:
            await driver.close()
            raise
        self._driver = driver
        logger.info("Neo4j connected: %s", settings.neo4j_uri)

    async def verify_connectivity(self) -> bool:
        """Verify a live authenticated connection, not only driver presence."""
        if self._driver is None:
            return False
        try:
            await self._driver.verify_connectivity()
            return True
        except Exception:
            return False

    async def disconnect(self) -> None:
        """Close the driver."""
        if self._driver is not None:
            await self._driver.close()
            self._driver = None
            logger.info("Neo4j disconnected")

    @property
    def is_connected(self) -> bool:
        return self._driver is not None

    async def run_query(
        self,
        query: str,
        parameters: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """Execute a Cypher query and return records as dicts."""
        if self._driver is None:
            return []

        async with self._driver.session(database=settings.neo4j_database) as session:
            result = await session.run(query, parameters or {})
            records = await result.data()
            return records

    async def create_constraints(self) -> None:
        """Create uniqueness constraints and indexes for the graph schema."""
        constraints = [
            # Entity uniqueness constraints
            "CREATE CONSTRAINT investigation_id IF NOT EXISTS FOR (i:Investigation) REQUIRE i.id IS UNIQUE",
            "CREATE CONSTRAINT entity_value IF NOT EXISTS FOR (e:Entity) REQUIRE e.value IS UNIQUE",
            "CREATE CONSTRAINT ioc_value IF NOT EXISTS FOR (i:IOC) REQUIRE i.value IS UNIQUE",
            "CREATE CONSTRAINT threat_id IF NOT EXISTS FOR (t:Threat) REQUIRE t.id IS UNIQUE",
            # Indexes for common lookups
            "CREATE INDEX entity_type IF NOT EXISTS FOR (e:Entity) ON (e.type)",
            "CREATE INDEX ioc_type IF NOT EXISTS FOR (i:IOC) ON (i.type)",
            "CREATE INDEX investigation_status IF NOT EXISTS FOR (i:Investigation) ON (i.status)",
        ]
        for cypher in constraints:
            try:
                await self.run_query(cypher)
            except Exception:
                # Constraint may already exist — safe to ignore
                pass
        logger.info("Neo4j constraints and indexes ensured")

    # -- Graph schema helpers --------------------------------------------------

    async def merge_entity(
        self,
        entity_type: str,
        value: str,
        properties: dict[str, Any] | None = None,
    ) -> None:
        """Merge an entity node (creates if absent, matches if present)."""
        props = properties or {}
        props.setdefault("type", entity_type)
        props.setdefault("value", value)

        cypher = (
            "MERGE (e:Entity {value: $value}) "
            "SET e.type = $type, e += $props"
        )
        await self.run_query(cypher, {
            "value": value,
            "type": entity_type,
            "props": props,
        })

    async def merge_relationship(
        self,
        source_value: str,
        target_value: str,
        rel_type: str,
        properties: dict[str, Any] | None = None,
    ) -> None:
        """Merge a directed relationship between two entities."""
        cypher = (
            "MATCH (a:Entity {value: $source}), (b:Entity {value: $target}) "
            f"MERGE (a)-[r:{rel_type}]->(b) "
            "SET r += $props"
        )
        await self.run_query(cypher, {
            "source": source_value,
            "target": target_value,
            "props": properties or {},
        })


# Singleton instance
neo4j_client = Neo4jClient()
