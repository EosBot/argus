"""Neo4j repository for entity-relationship graph operations.

Provides typed CRUD for OSINT entities (Victim, Perpetrator, OnionURL,
WalletAddr, Domain, Email, Phone, CryptoCluster, ImageHash) and their
relationships. Falls back to in-memory storage when Neo4j is unavailable.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from backend.core.neo4j_client import neo4j_client

logger = logging.getLogger(__name__)

# -- Entity type constants -----------------------------------------------------
ENTITY_VICTIM = "Victim"
ENTITY_PERPETRATOR = "Perpetrator"
ENTITY_ONION_URL = "OnionURL"
ENTITY_WALLET_ADDR = "WalletAddr"
ENTITY_DOMAIN = "Domain"
ENTITY_EMAIL = "Email"
ENTITY_PHONE = "Phone"
ENTITY_CRYPTO_CLUSTER = "CryptoCluster"
ENTITY_IMAGE_HASH = "ImageHash"

ENTITY_TYPES: frozenset[str] = frozenset({
    ENTITY_VICTIM,
    ENTITY_PERPETRATOR,
    ENTITY_ONION_URL,
    ENTITY_WALLET_ADDR,
    ENTITY_DOMAIN,
    ENTITY_EMAIL,
    ENTITY_PHONE,
    ENTITY_CRYPTO_CLUSTER,
    ENTITY_IMAGE_HASH,
})

# -- Relationship type constants -----------------------------------------------
REL_VICTIM_OF = "VICTIM_OF"
REL_PERPETRATOR_OF = "PERPETRATOR_OF"
REL_OPERATES = "OPERATES"
REL_USES = "USES"
REL_TRANSACTS = "TRANSACES"
REL_SHARES_HASH = "SHARES_HASH"
REL_LINKED_TO = "LINKED_TO"

RELATIONSHIP_TYPES: frozenset[str] = frozenset({
    REL_VICTIM_OF,
    REL_PERPETRATOR_OF,
    REL_OPERATES,
    REL_USES,
    REL_TRANSACTS,
    REL_SHARES_HASH,
    REL_LINKED_TO,
})


@dataclass(frozen=True, slots=True)
class Entity:
    """A typed graph entity (node).

    Attributes:
        id: Unique identifier (UUID hex).
        type: Entity type constant (e.g. ENTITY_VICTIM).
        value: Canonical value (address, hash, URL, ...).
        properties: Arbitrary metadata.
        created_at: ISO 8601 creation timestamp.
    """

    id: str
    type: str
    value: str
    properties: dict[str, Any] = field(default_factory=dict)
    created_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "value": self.value,
            "properties": self.properties,
            "created_at": self.created_at,
        }


@dataclass(frozen=True, slots=True)
class Relationship:
    """A typed directed relationship (edge) between two entities.

    Attributes:
        id: Unique identifier (UUID hex).
        source_id: Source entity ID.
        target_id: Target entity ID.
        type: Relationship type constant (e.g. REL_OPERATES).
        properties: Arbitrary metadata (confidence, timestamp, ...).
        created_at: ISO 8601 creation timestamp.
    """

    id: str
    source_id: str
    target_id: str
    type: str
    properties: dict[str, Any] = field(default_factory=dict)
    created_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "source_id": self.source_id,
            "target_id": self.target_id,
            "type": self.type,
            "properties": self.properties,
            "created_at": self.created_at,
        }


class _InMemoryGraph:
    """In-memory fallback when Neo4j is unavailable.

    Stores entities and relationships in dicts keyed by ID.
    Mirrors the async interface of Neo4jRepository.
    """

    def __init__(self) -> None:
        self._entities: dict[str, Entity] = {}
        self._relationships: dict[str, Relationship] = {}

    @property
    def is_connected(self) -> bool:
        return True  # Always "connected" — it's in-memory

    async def create_entity(
        self,
        entity_type: str,
        value: str,
        properties: dict[str, Any] | None = None,
    ) -> Entity:
        import uuid

        entity = Entity(
            id=uuid.uuid4().hex,
            type=entity_type,
            value=value,
            properties=properties or {},
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        self._entities[entity.id] = entity
        return entity

    async def get_entity(self, entity_id: str) -> Entity | None:
        return self._entities.get(entity_id)

    async def find_entities(
        self,
        entity_type: str | None = None,
        value: str | None = None,
    ) -> list[Entity]:
        results: list[Entity] = []
        for entity in self._entities.values():
            if entity_type and entity.type != entity_type:
                continue
            if value and entity.value != value:
                continue
            results.append(entity)
        return results

    async def update_entity(
        self,
        entity_id: str,
        properties: dict[str, Any],
    ) -> Entity | None:
        entity = self._entities.get(entity_id)
        if entity is None:
            return None
        merged = {**entity.properties, **properties}
        updated = Entity(
            id=entity.id,
            type=entity.type,
            value=entity.value,
            properties=merged,
            created_at=entity.created_at,
        )
        self._entities[entity_id] = updated
        return updated

    async def delete_entity(self, entity_id: str) -> bool:
        if entity_id not in self._entities:
            return False
        del self._entities[entity_id]
        # Cascade-delete relationships referencing this entity
        to_delete = [
            rel_id
            for rel_id, rel in self._relationships.items()
            if rel.source_id == entity_id or rel.target_id == entity_id
        ]
        for rel_id in to_delete:
            del self._relationships[rel_id]
        return True

    async def create_relationship(
        self,
        source_id: str,
        target_id: str,
        rel_type: str,
        properties: dict[str, Any] | None = None,
    ) -> Relationship | None:
        import uuid

        if source_id not in self._entities or target_id not in self._entities:
            return None
        rel = Relationship(
            id=uuid.uuid4().hex,
            source_id=source_id,
            target_id=target_id,
            type=rel_type,
            properties=properties or {},
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        self._relationships[rel.id] = rel
        return rel

    async def get_relationships(
        self,
        entity_id: str | None = None,
        rel_type: str | None = None,
    ) -> list[Relationship]:
        results: list[Relationship] = []
        for rel in self._relationships.values():
            if entity_id and rel.source_id != entity_id and rel.target_id != entity_id:
                continue
            if rel_type and rel.type != rel_type:
                continue
            results.append(rel)
        return results

    async def delete_relationship(self, rel_id: str) -> bool:
        if rel_id not in self._relationships:
            return False
        del self._relationships[rel_id]
        return True

    async def get_all(self) -> tuple[list[Entity], list[Relationship]]:
        return list(self._entities.values()), list(self._relationships.values())


class Neo4jRepository:
    """Typed repository for entity-relationship graph operations.

    Uses Neo4j when available; transparently falls back to in-memory
    storage otherwise. All methods are async and return typed dataclasses.

    Usage::

        repo = Neo4jRepository()
        entity = await repo.create_entity(ENTITY_VICTIM, "alice@example.com")
        rel = await repo.create_relationship(entity.id, other.id, REL_LINKED_TO)
    """

    def __init__(self) -> None:
        self._fallback: _InMemoryGraph | None = None

    @property
    def is_connected(self) -> bool:
        return neo4j_client.is_connected or self._fallback is not None

    def _use_fallback(self) -> _InMemoryGraph:
        if self._fallback is None:
            self._fallback = _InMemoryGraph()
            logger.info("Neo4jRepository using in-memory fallback")
        return self._fallback

    # -- Entity CRUD ------------------------------------------------------------

    async def create_entity(
        self,
        entity_type: str,
        value: str,
        properties: dict[str, Any] | None = None,
    ) -> Entity:
        """Create a typed entity node.

        Args:
            entity_type: One of the ENTITY_* constants.
            value: Canonical value (address, hash, URL, ...).
            properties: Optional metadata dict.

        Returns:
            The created Entity.
        """
        if entity_type not in ENTITY_TYPES:
            raise ValueError(
                f"unknown entity type {entity_type!r}; "
                f"expected one of {sorted(ENTITY_TYPES)}"
            )

        if neo4j_client.is_connected:
            try:
                props = dict(properties or {})
                props["type"] = entity_type
                props["value"] = value
                await neo4j_client.merge_entity(entity_type, value, props)
                # Retrieve the created/merged entity
                records = await neo4j_client.run_query(
                    "MATCH (e:Entity {value: $value, type: $type}) RETURN e",
                    {"value": value, "type": entity_type},
                )
                if records:
                    node = records[0]["e"]
                    return Entity(
                        id=node.get("id", ""),
                        type=node.get("type", entity_type),
                        value=node.get("value", value),
                        properties={
                            k: v
                            for k, v in node.items()
                            if k not in ("id", "type", "value")
                        },
                    )
            except Exception as exc:
                logger.warning("Neo4j create_entity failed, using fallback: %s", exc)

        return await self._use_fallback().create_entity(
            entity_type, value, properties
        )

    async def get_entity(self, entity_id: str) -> Entity | None:
        """Retrieve an entity by ID."""
        if neo4j_client.is_connected:
            try:
                records = await neo4j_client.run_query(
                    "MATCH (e:Entity) WHERE e.id = $id RETURN e",
                    {"id": entity_id},
                )
                if records:
                    node = records[0]["e"]
                    return Entity(
                        id=node.get("id", ""),
                        type=node.get("type", ""),
                        value=node.get("value", ""),
                        properties={
                            k: v
                            for k, v in node.items()
                            if k not in ("id", "type", "value")
                        },
                    )
            except Exception as exc:
                logger.warning("Neo4j get_entity failed, using fallback: %s", exc)

        return await self._use_fallback().get_entity(entity_id)

    async def find_entities(
        self,
        entity_type: str | None = None,
        value: str | None = None,
    ) -> list[Entity]:
        """Find entities by type and/or value."""
        if neo4j_client.is_connected:
            try:
                clauses: list[str] = []
                params: dict[str, Any] = {}
                if entity_type:
                    clauses.append("e.type = $type")
                    params["type"] = entity_type
                if value:
                    clauses.append("e.value = $value")
                    params["value"] = value
                where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
                records = await neo4j_client.run_query(
                    f"MATCH (e:Entity) {where} RETURN e",
                    params,
                )
                return [
                    Entity(
                        id=r["e"].get("id", ""),
                        type=r["e"].get("type", ""),
                        value=r["e"].get("value", ""),
                        properties={
                            k: v
                            for k, v in r["e"].items()
                            if k not in ("id", "type", "value")
                        },
                    )
                    for r in records
                ]
            except Exception as exc:
                logger.warning("Neo4j find_entities failed, using fallback: %s", exc)

        return await self._use_fallback().find_entities(entity_type, value)

    async def update_entity(
        self,
        entity_id: str,
        properties: dict[str, Any],
    ) -> Entity | None:
        """Merge properties into an existing entity."""
        if neo4j_client.is_connected:
            try:
                await neo4j_client.run_query(
                    "MATCH (e:Entity) WHERE e.id = $id SET e += $props",
                    {"id": entity_id, "props": properties},
                )
                return await self.get_entity(entity_id)
            except Exception as exc:
                logger.warning("Neo4j update_entity failed, using fallback: %s", exc)

        return await self._use_fallback().update_entity(entity_id, properties)

    async def delete_entity(self, entity_id: str) -> bool:
        """Delete an entity and all its relationships."""
        if neo4j_client.is_connected:
            try:
                await neo4j_client.run_query(
                    "MATCH (e:Entity) WHERE e.id = $id DETACH DELETE e",
                    {"id": entity_id},
                )
                return True
            except Exception as exc:
                logger.warning("Neo4j delete_entity failed, using fallback: %s", exc)

        return await self._use_fallback().delete_entity(entity_id)

    # -- Relationship CRUD ------------------------------------------------------

    async def create_relationship(
        self,
        source_id: str,
        target_id: str,
        rel_type: str,
        properties: dict[str, Any] | None = None,
    ) -> Relationship | None:
        """Create a directed relationship between two entities.

        Args:
            source_id: Source entity ID.
            target_id: Target entity ID.
            rel_type: One of the REL_* constants.
            properties: Optional metadata (confidence, timestamp, ...).

        Returns:
            The created Relationship, or None if entities not found.
        """
        if rel_type not in RELATIONSHIP_TYPES:
            raise ValueError(
                f"unknown relationship type {rel_type!r}; "
                f"expected one of {sorted(RELATIONSHIP_TYPES)}"
            )

        if neo4j_client.is_connected:
            try:
                await neo4j_client.merge_relationship(
                    source_id,
                    target_id,
                    rel_type,
                    properties,
                )
                return Relationship(
                    id="",
                    source_id=source_id,
                    target_id=target_id,
                    type=rel_type,
                    properties=properties or {},
                )
            except Exception as exc:
                logger.warning(
                    "Neo4j create_relationship failed, using fallback: %s", exc
                )

        return await self._use_fallback().create_relationship(
            source_id, target_id, rel_type, properties
        )

    async def get_relationships(
        self,
        entity_id: str | None = None,
        rel_type: str | None = None,
    ) -> list[Relationship]:
        """Find relationships by entity and/or type."""
        if neo4j_client.is_connected:
            try:
                clauses: list[str] = []
                params: dict[str, Any] = {}
                if entity_id:
                    clauses.append(
                        "(a.id = $eid OR b.id = $eid)"
                    )
                    params["eid"] = entity_id
                if rel_type:
                    clauses.append(f"type(r) = $rtype")
                    params["rtype"] = rel_type
                where = f"AND {' AND '.join(clauses)}" if clauses else ""
                records = await neo4j_client.run_query(
                    f"MATCH (a:Entity)-[r]->(b:Entity) WHERE true {where} "
                    f"RETURN a.id, b.id, type(r), r",
                    params,
                )
                return [
                    Relationship(
                        id="",
                        source_id=r["a.id"],
                        target_id=r["b.id"],
                        type=r["type(r)"],
                        properties={
                            k: v
                            for k, v in r["r"].items()
                            if k not in ("id", "type")
                        },
                    )
                    for r in records
                ]
            except Exception as exc:
                logger.warning(
                    "Neo4j get_relationships failed, using fallback: %s", exc
                )

        return await self._use_fallback().get_relationships(entity_id, rel_type)

    async def delete_relationship(self, rel_id: str) -> bool:
        """Delete a relationship by ID."""
        if neo4j_client.is_connected:
            try:
                await neo4j_client.run_query(
                    "MATCH ()-[r]->() WHERE r.id = $id DELETE r",
                    {"id": rel_id},
                )
                return True
            except Exception as exc:
                logger.warning(
                    "Neo4j delete_relationship failed, using fallback: %s", exc
                )

        return await self._use_fallback().delete_relationship(rel_id)

    # -- Bulk operations --------------------------------------------------------

    async def get_all(self) -> tuple[list[Entity], list[Relationship]]:
        """Return all entities and relationships in the graph."""
        if neo4j_client.is_connected:
            try:
                records = await neo4j_client.run_query(
                    "MATCH (e:Entity) RETURN e"
                )
                entities = [
                    Entity(
                        id=r["e"].get("id", ""),
                        type=r["e"].get("type", ""),
                        value=r["e"].get("value", ""),
                        properties={
                            k: v
                            for k, v in r["e"].items()
                            if k not in ("id", "type", "value")
                        },
                    )
                    for r in records
                ]
                rel_records = await neo4j_client.run_query(
                    "MATCH (a:Entity)-[r]->(b:Entity) RETURN a.id, b.id, type(r), r"
                )
                relationships = [
                    Relationship(
                        id="",
                        source_id=r["a.id"],
                        target_id=r["b.id"],
                        type=r["type(r)"],
                        properties={
                            k: v
                            for k, v in r["r"].items()
                            if k not in ("id", "type")
                        },
                    )
                    for r in rel_records
                ]
                return entities, relationships
            except Exception as exc:
                logger.warning("Neo4j get_all failed, using fallback: %s", exc)

        return await self._use_fallback().get_all()


# Singleton instance
neo4j_repository = Neo4jRepository()
