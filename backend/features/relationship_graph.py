"""Relationship graph — prepare Neo4j data for React Flow visualization.

Transforms entity-relationship data from Neo4j into the node/edge
format expected by React Flow, with layout hints and styling.
"""

from __future__ import annotations

import logging
from typing import Any

from backend.context.neo4j_repo import Neo4jRepository, neo4j_repository

logger = logging.getLogger(__name__)

# React Flow node color scheme by entity type
_NODE_COLORS: dict[str, str] = {
    "Victim": "#FF6B6B",
    "Perpetrator": "#4ECDC4",
    "OnionURL": "#FFE66D",
    "WalletAddr": "#A8E6CF",
    "Domain": "#FFD93D",
    "Email": "#6BCB77",
    "Phone": "#4D96FF",
    "CryptoCluster": "#9B59B6",
    "ImageHash": "#E17055",
}

# Relationship style by type
_EDGE_STYLES: dict[str, dict[str, Any]] = {
    "VICTIM_OF": {"stroke": "#FF6B6B", "strokeWidth": 2},
    "PERPETRATOR_OF": {"stroke": "#4ECDC4", "strokeWidth": 2},
    "OPERATES": {"stroke": "#FFD93D", "strokeWidth": 1.5},
    "USES": {"stroke": "#A8E6CF", "strokeWidth": 1},
    "TRANSACES": {"stroke": "#9B59B6", "strokeWidth": 1.5},
    "SHARES_HASH": {"stroke": "#E17055", "strokeWidth": 1},
    "LINKED_TO": {"stroke": "#95A5A6", "strokeWidth": 1},
}


class RelationshipGraphBuilder:
    """Build React Flow graph data from Neo4j entities and relationships.

    Converts the Neo4j graph into React Flow compatible format
    with styled nodes and edges, plus layout metadata.

    Usage::

        builder = RelationshipGraphBuilder(neo4j_repository)
        graph = await builder.build_graph()
        subgraph = await builder.build_subgraph(entity_id="abc123", depth=2)
    """

    def __init__(self, repository: Neo4jRepository | None = None) -> None:
        """Initialize with a Neo4j repository (defaults to singleton)."""
        self._repo = repository or neo4j_repository

    async def build_graph(self) -> dict[str, Any]:
        """Build the full graph in React Flow format.

        Returns:
            Dict with 'nodes' and 'edges' lists ready for React Flow.
        """
        entities, relationships = await self._repo.get_all()

        nodes = [self._entity_to_node(e) for e in entities]
        edges = [self._relationship_to_edge(r) for r in relationships]

        return {
            "nodes": nodes,
            "edges": edges,
            "metadata": {
                "node_count": len(nodes),
                "edge_count": len(edges),
                "entity_types": sorted({e.type for e in entities}),
                "relationship_types": sorted({r.type for r in relationships}),
            },
        }

    async def build_subgraph(
        self,
        entity_id: str,
        depth: int = 2,
    ) -> dict[str, Any]:
        """Build a subgraph centered on an entity.

        Traverses relationships up to `depth` hops from the center entity.

        Args:
            entity_id: Center entity ID.
            depth: Number of relationship hops to include.

        Returns:
            Dict with 'nodes' and 'edges' lists for the subgraph.
        """
        all_entities, all_relationships = await self._repo.get_all()

        # BFS to find connected entities within depth
        included_ids: set[str] = {entity_id}
        frontier: set[str] = {entity_id}

        for _ in range(depth):
            new_frontier: set[str] = set()
            for rel in all_relationships:
                if rel.source_id in frontier and rel.target_id not in included_ids:
                    new_frontier.add(rel.target_id)
                if rel.target_id in frontier and rel.source_id not in included_ids:
                    new_frontier.add(rel.source_id)
            included_ids.update(new_frontier)
            frontier = new_frontier

        # Filter entities and relationships
        nodes = [
            self._entity_to_node(e)
            for e in all_entities
            if e.id in included_ids
        ]
        edges = [
            self._relationship_to_edge(r)
            for r in all_relationships
            if r.source_id in included_ids and r.target_id in included_ids
        ]

        return {
            "nodes": nodes,
            "edges": edges,
            "metadata": {
                "node_count": len(nodes),
                "edge_count": len(edges),
                "center_entity": entity_id,
                "depth": depth,
            },
        }

    async def get_entity_details(self, entity_id: str) -> dict[str, Any] | None:
        """Get detailed information about an entity and its connections.

        Args:
            entity_id: Entity UUID.

        Returns:
            Dict with entity info and connected relationships, or None.
        """
        entity = await self._repo.get_entity(entity_id)
        if entity is None:
            return None

        relationships = await self._repo.get_relationships(entity_id=entity_id)

        return {
            "entity": entity.to_dict(),
            "relationships": [r.to_dict() for r in relationships],
            "connected_entities": list({
                r.source_id if r.target_id == entity_id else r.target_id
                for r in relationships
            }),
        }

    def _entity_to_node(self, entity: Any) -> dict[str, Any]:
        """Convert a Neo4j Entity to a React Flow node."""
        color = _NODE_COLORS.get(entity.type, "#95A5A6")
        return {
            "id": entity.id,
            "type": "default",
            "data": {
                "label": entity.value,
                "entity_type": entity.type,
                "properties": entity.properties,
                "color": color,
            },
            "position": {"x": 0, "y": 0},  # Layout algorithm will adjust
            "style": {
                "background": color,
                "color": "#1A1A2E",
                "border": f"2px solid {color}",
                "borderRadius": 8,
                "padding": "8px 12px",
                "fontSize": 12,
                "fontWeight": 600,
            },
        }

    def _relationship_to_edge(self, rel: Any) -> dict[str, Any]:
        """Convert a Neo4j Relationship to a React Flow edge."""
        style = _EDGE_STYLES.get(rel.type, {"stroke": "#95A5A6", "strokeWidth": 1})
        return {
            "id": rel.id or f"{rel.source_id}-{rel.type}-{rel.target_id}",
            "source": rel.source_id,
            "target": rel.target_id,
            "label": rel.type,
            "type": "default",
            "animated": rel.type in ("PERPETRATOR_OF", "VICTIM_OF"),
            "data": {
                "relationship_type": rel.type,
                "properties": rel.properties,
            },
            "style": style,
        }
