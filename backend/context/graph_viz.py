"""Graph visualization data preparation.

Prepares entity-relationship graph data for frontend rendering:
- React Flow compatible nodes + edges JSON
- D3 force-directed layout data
- NetworkX-based analysis (when available) with graceful fallback
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass, field
from typing import Any

from backend.context.neo4j_repo import (
    Entity,
    Relationship,
    ENTITY_TYPES,
    neo4j_repository,
)

logger = logging.getLogger(__name__)

# -- Color palette per entity type --------------------------------------------
ENTITY_COLORS: dict[str, str] = {
    "Victim": "#ef4444",          # red-500
    "Perpetrator": "#f97316",     # orange-500
    "OnionURL": "#a855f7",        # purple-500
    "WalletAddr": "#eab308",      # yellow-500
    "Domain": "#3b82f6",          # blue-500
    "Email": "#06b6d4",           # cyan-500
    "Phone": "#10b981",           # emerald-500
    "CryptoCluster": "#f59e0b",   # amber-500
    "ImageHash": "#6366f1",       # indigo-500
}

DEFAULT_NODE_COLOR = "#6b7280"    # gray-500
DEFAULT_EDGE_COLOR = "#94a3b8"    # slate-400


@dataclass(frozen=True, slots=True)
class GraphNode:
    """A node in the visualization graph (React Flow format).

    Attributes:
        id: Unique node identifier.
        label: Display label.
        type: Entity type.
        color: Hex color string.
        x: X position (for layouts).
        y: Y position (for layouts).
        metadata: Additional display data.
    """

    id: str
    label: str
    type: str
    color: str = DEFAULT_NODE_COLOR
    x: float = 0.0
    y: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_react_flow(self) -> dict[str, Any]:
        """Convert to React Flow node format."""
        return {
            "id": self.id,
            "type": "default",
            "position": {"x": self.x, "y": self.y},
            "data": {
                "label": self.label,
                "entityType": self.type,
                **self.metadata,
            },
            "style": {
                "background": self.color,
                "color": "#ffffff",
                "border": "1px solid rgba(0,0,0,0.2)",
                "borderRadius": 8,
                "padding": 10,
                "fontSize": 12,
                "fontWeight": 600,
            },
        }

    def to_d3(self) -> dict[str, Any]:
        """Convert to D3 force-directed node format."""
        return {
            "id": self.id,
            "label": self.label,
            "group": self.type,
            "color": self.color,
            **self.metadata,
        }


@dataclass(frozen=True, slots=True)
class GraphEdge:
    """An edge in the visualization graph (React Flow format).

    Attributes:
        id: Unique edge identifier.
        source: Source node ID.
        target: Target node ID.
        label: Edge label (relationship type).
        color: Hex color string.
        animated: Whether to animate the edge (highlights active paths).
        metadata: Additional display data.
    """

    id: str
    source: str
    target: str
    label: str = ""
    color: str = DEFAULT_EDGE_COLOR
    animated: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_react_flow(self) -> dict[str, Any]:
        """Convert to React Flow edge format."""
        return {
            "id": self.id,
            "source": self.source,
            "target": self.target,
            "label": self.label,
            "animated": self.animated,
            "style": {"stroke": self.color, "strokeWidth": 1.5},
            "labelStyle": {"fontSize": 10, "fill": "#64748b"},
            "data": self.metadata,
        }

    def to_d3(self) -> dict[str, Any]:
        """Convert to D3 force-directed edge format."""
        return {
            "source": self.source,
            "target": self.target,
            "label": self.label,
            "color": self.color,
            **self.metadata,
        }


class GraphViz:
    """Prepares graph data for visualization.

    Converts entity-relationship data from the Neo4j repository
    into formats suitable for React Flow and D3 force-directed layouts.

    Usage::

        viz = GraphViz()
        nodes, edges = await viz.build_from_repo()
        react_flow_data = viz.to_react_flow_json(nodes, edges)
        d3_data = viz.to_d3_json(nodes, edges)
    """

    def __init__(self) -> None:
        self._layout_cache: dict[str, tuple[float, float]] = {}

    async def build_from_repo(
        self,
        entity_type: str | None = None,
    ) -> tuple[list[GraphNode], list[GraphEdge]]:
        """Build graph data from the Neo4j repository.

        Args:
            entity_type: Optional filter by entity type.

        Returns:
            Tuple of (nodes, edges).
        """
        entities, relationships = await neo4j_repository.get_all()

        if entity_type:
            entities = [e for e in entities if e.type == entity_type]
            entity_ids = {e.id for e in entities}
            relationships = [
                r
                for r in relationships
                if r.source_id in entity_ids or r.target_id in entity_ids
            ]

        nodes = self._build_nodes(entities)
        edges = self._build_edges(relationships)

        return nodes, edges

    async def build_from_data(
        self,
        entities: list[Entity],
        relationships: list[Relationship],
    ) -> tuple[list[GraphNode], list[GraphEdge]]:
        """Build graph data from explicit entity/relationship lists.

        Args:
            entities: List of entities.
            relationships: List of relationships.

        Returns:
            Tuple of (nodes, edges).
        """
        nodes = self._build_nodes(entities)
        edges = self._build_edges(relationships)
        return nodes, edges

    def _build_nodes(self, entities: list[Entity]) -> list[GraphNode]:
        """Convert entities to visualization nodes."""
        nodes: list[GraphNode] = []
        for entity in entities:
            color = ENTITY_COLORS.get(entity.type, DEFAULT_NODE_COLOR)
            nodes.append(
                GraphNode(
                    id=entity.id,
                    label=entity.value,
                    type=entity.type,
                    color=color,
                    metadata={
                        "value": entity.value,
                        "properties": entity.properties,
                        "created_at": entity.created_at,
                    },
                )
            )
        return nodes

    def _build_edges(self, relationships: list[Relationship]) -> list[GraphEdge]:
        """Convert relationships to visualization edges."""
        edges: list[GraphEdge] = []
        for rel in relationships:
            edges.append(
                GraphEdge(
                    id=rel.id or f"{rel.source_id}->{rel.target_id}",
                    source=rel.source_id,
                    target=rel.target_id,
                    label=rel.type,
                    metadata={
                        "properties": rel.properties,
                        "created_at": rel.created_at,
                    },
                )
            )
        return edges

    def apply_circular_layout(
        self,
        nodes: list[GraphNode],
        center_x: float = 400.0,
        center_y: float = 300.0,
        radius: float = 200.0,
    ) -> list[GraphNode]:
        """Apply a circular layout to nodes.

        Simple deterministic layout that doesn't require networkx.

        Args:
            nodes: Nodes to position.
            center_x: Center X coordinate.
            center_y: Center Y coordinate.
            radius: Circle radius.

        Returns:
            New list of nodes with updated positions.
        """
        if not nodes:
            return nodes

        count = len(nodes)
        angle_step = 2 * math.pi / count

        positioned: list[GraphNode] = []
        for i, node in enumerate(nodes):
            angle = i * angle_step
            x = center_x + radius * math.cos(angle)
            y = center_y + radius * math.sin(angle)
            positioned.append(
                GraphNode(
                    id=node.id,
                    label=node.label,
                    type=node.type,
                    color=node.color,
                    x=x,
                    y=y,
                    metadata=node.metadata,
                )
            )

        return positioned

    def apply_force_layout(
        self,
        nodes: list[GraphNode],
        edges: list[GraphEdge],
        iterations: int = 50,
    ) -> list[GraphNode]:
        """Apply a force-directed layout.

        Uses NetworkX if available for Fruchterman-Reingold layout;
        falls back to a simple spring-electrical simulation otherwise.

        Args:
            nodes: Nodes to position.
            edges: Edges connecting nodes.
            iterations: Number of simulation iterations (fallback only).

        Returns:
            New list of nodes with updated positions.
        """
        try:
            return self._apply_nx_layout(nodes, edges)
        except ImportError:
            return self._apply_fallback_layout(nodes, edges, iterations)

    def _apply_nx_layout(
        self,
        nodes: list[GraphNode],
        edges: list[GraphEdge],
    ) -> list[GraphNode]:
        """Apply NetworkX Fruchterman-Reingold layout."""
        import networkx as nx

        G = nx.Graph()
        for node in nodes:
            G.add_node(node.id)
        for edge in edges:
            G.add_edge(edge.source, edge.target)

        positions = nx.spring_layout(G, seed=42, k=1.5)

        positioned: list[GraphNode] = []
        for node in nodes:
            pos = positions.get(node.id, (0.0, 0.0))
            positioned.append(
                GraphNode(
                    id=node.id,
                    label=node.label,
                    type=node.type,
                    color=node.color,
                    x=float(pos[0]) * 400 + 400,
                    y=float(pos[1]) * 300 + 300,
                    metadata=node.metadata,
                )
            )

        return positioned

    def _apply_fallback_layout(
        self,
        nodes: list[GraphNode],
        edges: list[GraphEdge],
        iterations: int,
    ) -> list[GraphNode]:
        """Simple spring-electrical layout (no networkx required).

        Implements a basic force-directed placement:
        - Repulsive force between all node pairs.
        - Attractive force along edges.
        """
        if not nodes:
            return nodes

        # Initialize positions randomly around center
        import random

        random.seed(42)
        positions: dict[str, list[float]] = {}
        for node in nodes:
            positions[node.id] = [
                random.uniform(-100, 100),
                random.uniform(-100, 100),
            ]

        # Build adjacency
        adjacency: dict[str, list[str]] = {n.id: [] for n in nodes}
        for edge in edges:
            adjacency[edge.source].append(edge.target)
            adjacency[edge.target].append(edge.source)

        k = 100.0  # Ideal spring length
        temperature = 0.1

        for _ in range(iterations):
            # Compute forces
            forces: dict[str, list[float]] = {
                n.id: [0.0, 0.0] for n in nodes
            }

            # Repulsive forces (all pairs)
            for i, n1 in enumerate(nodes):
                for n2 in nodes[i + 1 :]:
                    dx = positions[n1.id][0] - positions[n2.id][0]
                    dy = positions[n1.id][1] - positions[n2.id][1]
                    dist = max(math.sqrt(dx * dx + dy * dy), 0.01)
                    force = (k * k) / dist
                    fx = (dx / dist) * force
                    fy = (dy / dist) * force
                    forces[n1.id][0] += fx
                    forces[n1.id][1] += fy
                    forces[n2.id][0] -= fx
                    forces[n2.id][1] -= fy

            # Attractive forces (edges)
            for edge in edges:
                n1_pos = positions[edge.source]
                n2_pos = positions[edge.target]
                dx = n1_pos[0] - n2_pos[0]
                dy = n1_pos[1] - n2_pos[1]
                dist = max(math.sqrt(dx * dx + dy * dy), 0.01)
                force = (dist * dist) / k
                fx = (dx / dist) * force
                fy = (dy / dist) * force
                forces[edge.source][0] -= fx
                forces[edge.source][1] -= fy
                forces[edge.target][0] += fx
                forces[edge.target][1] += fy

            # Apply forces with cooling
            for node in nodes:
                fx, fy = forces[node.id]
                positions[node.id][0] += fx * temperature
                positions[node.id][1] += fy * temperature

            temperature *= 0.95

        # Build result
        positioned: list[GraphNode] = []
        for node in nodes:
            pos = positions[node.id]
            positioned.append(
                GraphNode(
                    id=node.id,
                    label=node.label,
                    type=node.type,
                    color=node.color,
                    x=pos[0] + 400,
                    y=pos[1] + 300,
                    metadata=node.metadata,
                )
            )

        return positioned

    def compute_centrality(
        self,
        nodes: list[GraphNode],
        edges: list[GraphEdge],
    ) -> dict[str, float]:
        """Compute degree centrality for each node.

        Uses NetworkX if available; falls back to simple degree count.

        Returns:
            Dict mapping node ID to centrality score (0.0 - 1.0).
        """
        if not nodes:
            return {}

        try:
            import networkx as nx

            G = nx.Graph()
            for node in nodes:
                G.add_node(node.id)
            for edge in edges:
                G.add_edge(edge.source, edge.target)

            centrality = nx.degree_centrality(G)
            return centrality

        except ImportError:
            # Simple degree centrality fallback
            degree: dict[str, int] = {n.id: 0 for n in nodes}
            for edge in edges:
                degree[edge.source] = degree.get(edge.source, 0) + 1
                degree[edge.target] = degree.get(edge.target, 0) + 1

            max_degree = max(degree.values()) if degree else 1
            if max_degree == 0:
                return {n.id: 0.0 for n in nodes}

            return {nid: d / max_degree for nid, d in degree.items()}

    def find_communities(
        self,
        nodes: list[GraphNode],
        edges: list[GraphEdge],
    ) -> dict[str, int]:
        """Detect communities in the graph.

        Uses NetworkX's greedy modularity if available;
        falls back to connected components.

        Returns:
            Dict mapping node ID to community ID (integer).
        """
        if not nodes:
            return {}

        try:
            import networkx as nx

            G = nx.Graph()
            for node in nodes:
                G.add_node(node.id)
            for edge in edges:
                G.add_edge(edge.source, edge.target)

            from networkx.algorithms.community import greedy_modularity_communities

            communities = list(greedy_modularity_communities(G))
            result: dict[str, int] = {}
            for cid, comm in enumerate(communities):
                for node_id in comm:
                    result[node_id] = cid
            return result

        except ImportError:
            # Connected components fallback
            parent: dict[str, str] = {n.id: n.id for n in nodes}

            def find(x: str) -> str:
                while parent[x] != x:
                    parent[x] = parent[parent[x]]
                    x = parent[x]
                return x

            def union(a: str, b: str) -> None:
                ra, rb = find(a), find(b)
                if ra != rb:
                    parent[ra] = rb

            for edge in edges:
                union(edge.source, edge.target)

            # Assign community IDs
            roots: dict[str, int] = {}
            result: dict[str, int] = {}
            next_id = 0
            for node in nodes:
                root = find(node.id)
                if root not in roots:
                    roots[root] = next_id
                    next_id += 1
                result[node.id] = roots[root]

            return result

    # -- JSON export ------------------------------------------------------------

    def to_react_flow_json(
        self,
        nodes: list[GraphNode],
        edges: list[GraphEdge],
    ) -> dict[str, list[dict[str, Any]]]:
        """Export graph data in React Flow format.

        Returns:
            Dict with ``nodes`` and ``edges`` lists.
        """
        return {
            "nodes": [n.to_react_flow() for n in nodes],
            "edges": [e.to_react_flow() for e in edges],
        }

    def to_d3_json(
        self,
        nodes: list[GraphNode],
        edges: list[GraphEdge],
    ) -> dict[str, list[dict[str, Any]]]:
        """Export graph data in D3 force-directed format.

        Returns:
            Dict with ``nodes`` and ``links`` lists.
        """
        return {
            "nodes": [n.to_d3() for n in nodes],
            "links": [e.to_d3() for e in edges],
        }

    def to_cytoscape_json(
        self,
        nodes: list[GraphNode],
        edges: list[GraphEdge],
    ) -> list[dict[str, Any]]:
        """Export graph data in Cytoscape.js format.

        Returns:
            List of element dicts (nodes and edges interleaved).
        """
        elements: list[dict[str, Any]] = []
        for node in nodes:
            elements.append({
                "data": {
                    "id": node.id,
                    "label": node.label,
                    "type": node.type,
                    "color": node.color,
                    **node.metadata,
                }
            })
        for edge in edges:
            elements.append({
                "data": {
                    "id": edge.id,
                    "source": edge.source,
                    "target": edge.target,
                    "label": edge.label,
                    **edge.metadata,
                }
            })
        return elements
