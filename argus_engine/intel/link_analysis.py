"""Link Analysis module for ARGUS.

Builds entity relationship graphs and runs network analysis algorithms
(PageRank, betweenness centrality, Louvain community detection) to
identify influential actors, brokers, and operational cells.

NetworkX is optional — all methods return empty results when it is
not installed.

Example::

    analyzer = LinkAnalyzer()
    analyzer.build_graph(entities, relationships)
    top_actors = analyzer.pagerank(top_n=10)
    brokers = analyzer.betweenness(top_n=5)
    cells = analyzer.communities()
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Optional dependencies — graceful fallback
# ---------------------------------------------------------------------------
try:
    import networkx as nx  # type: ignore[import-untyped]

    _HAS_NETWORKX = True
except ImportError:
    _HAS_NETWORKX = False
    _logger.debug("networkx not installed — link analysis disabled")

try:
    from networkx.algorithms import community as nx_community  # type: ignore[import-untyped]

    _HAS_NX_COMMUNITY = True
except ImportError:
    _HAS_NX_COMMUNITY = False

try:
    import plotly.graph_objects as go  # type: ignore[import-untyped]

    _HAS_PLOTLY = True
except ImportError:
    _HAS_PLOTLY = False
    _logger.debug("plotly not installed — visualization disabled")


class LinkAnalyzer:
    """Analyze entity relationships using graph algorithms.

    Identifies influential actors (PageRank), intermediaries
    (betweenness centrality), and operational cells (Louvain communities).

    All methods gracefully return empty results when NetworkX is unavailable.
    """

    def __init__(self) -> None:
        """Initialize the link analyzer."""
        self._graph: Any = None
        self._pagerank_cache: dict[str, float] | None = None
        self._betweenness_cache: dict[str, float] | None = None
        self._communities_cache: dict[str, list[str]] | None = None

    @property
    def has_networkx(self) -> bool:
        """Check if NetworkX is available."""
        return _HAS_NETWORKX

    @property
    def graph(self) -> Any | None:
        """Return the underlying NetworkX graph, if built."""
        return self._graph

    @property
    def node_count(self) -> int:
        """Number of nodes in the graph."""
        if self._graph is None:
            return 0
        return self._graph.number_of_nodes()

    @property
    def edge_count(self) -> int:
        """Number of edges in the graph."""
        if self._graph is None:
            return 0
        return self._graph.number_of_edges()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def build_graph(
        self,
        entities: list[dict[str, Any]],
        relationships: list[tuple[str, str, dict[str, Any] | None]],
    ) -> Any:
        """Build a graph from entities and their relationships.

        Args:
            entities: List of entity dicts with at least an ``id`` key.
                Example: ``[{"id": "alice", "type": "person", "label": "Alice"}]``
            relationships: List of ``(source_id, target_id, attrs)`` tuples.
                ``attrs`` is an optional dict with edge attributes like
                ``weight``, ``type``, ``confidence``.

        Returns:
            The constructed NetworkX Graph, or ``None`` if NetworkX
            is not available.

        Example::

            entities = [
                {"id": "alice", "type": "person"},
                {"id": "bob", "type": "person"},
            ]
            relationships = [("alice", "bob", {"weight": 0.8})]
            G = analyzer.build_graph(entities, relationships)
        """
        if not _HAS_NETWORKX:
            _logger.debug("Cannot build graph — networkx not installed")
            return None

        G = nx.Graph()

        # Add nodes with attributes
        for entity in entities:
            node_id = entity.get("id")
            if node_id is None:
                continue
            attrs = {k: v for k, v in entity.items() if k != "id"}
            G.add_node(node_id, **attrs)

        # Add edges with attributes
        for rel in relationships:
            if len(rel) < 2:
                continue
            source, target = rel[0], rel[1]
            attrs = rel[2] if len(rel) > 2 and isinstance(rel[2], dict) else {}
            if G.has_node(source) and G.has_node(target):
                G.add_edge(source, target, **attrs)

        self._graph = G
        self._clear_caches()
        _logger.debug(
            "Built graph: %d nodes, %d edges", G.number_of_nodes(), G.number_of_edges()
        )
        return G

    def pagerank(
        self,
        top_n: int | None = None,
        weight: str | None = "weight",
        alpha: float = 0.85,
    ) -> dict[str, float]:
        """Compute PageRank for all nodes.

        Identifies the most influential actors in the network based on
        their connectivity patterns.

        Args:
            top_n: If set, return only the top N nodes by score.
            weight: Edge attribute to use as weight. ``None`` for unweighted.
            alpha: Damping parameter (default 0.85).

        Returns:
            Dictionary mapping node IDs to PageRank scores, sorted by
            score descending. Empty dict if NetworkX is unavailable or
            no graph has been built.

        Example::

            scores = analyzer.pagerank(top_n=5)
            # {"alice": 0.42, "bob": 0.31, ...}
        """
        if not _HAS_NETWORKX or self._graph is None:
            return {}

        if self._pagerank_cache is None:
            try:
                self._pagerank_cache = nx.pagerank(
                    self._graph, alpha=alpha, weight=weight
                )
            except Exception as exc:
                _logger.warning("PageRank computation failed: %s", exc)
                return {}

        sorted_scores = dict(
            sorted(self._pagerank_cache.items(), key=lambda x: x[1], reverse=True)
        )

        if top_n is not None:
            sorted_scores = dict(list(sorted_scores.items())[:top_n])

        return sorted_scores

    def betweenness(
        self,
        top_n: int | None = None,
        weight: str | None = "weight",
        normalized: bool = True,
    ) -> dict[str, float]:
        """Compute betweenness centrality for all nodes.

        Identifies intermediaries/brokers — nodes that act as bridges
        between different parts of the network.

        Args:
            top_n: If set, return only the top N nodes by score.
            weight: Edge attribute to use as weight. ``None`` for unweighted.
            normalized: Whether to normalize scores (default True).

        Returns:
            Dictionary mapping node IDs to betweenness scores, sorted by
            score descending. Empty dict if NetworkX is unavailable or
            no graph has been built.

        Example::

            brokers = analyzer.betweenness(top_n=3)
            # {"carol": 0.95, "dave": 0.67, ...}
        """
        if not _HAS_NETWORKX or self._graph is None:
            return {}

        if self._betweenness_cache is None:
            try:
                self._betweenness_cache = nx.betweenness_centrality(
                    self._graph, weight=weight, normalized=normalized
                )
            except Exception as exc:
                _logger.warning("Betweenness computation failed: %s", exc)
                return {}

        sorted_scores = dict(
            sorted(self._betweenness_cache.items(), key=lambda x: x[1], reverse=True)
        )

        if top_n is not None:
            sorted_scores = dict(list(sorted_scores.items())[:top_n])

        return sorted_scores

    def communities(
        self,
        resolution: float = 1.0,
        weight: str | None = "weight",
    ) -> dict[str, list[str]]:
        """Detect communities using Louvain algorithm.

        Groups nodes into densely-connected clusters representing
        operational cells or sub-organizations.

        Args:
            resolution: Louvain resolution parameter. Higher values
                produce smaller, more granular communities.
            weight: Edge attribute to use as weight.

        Returns:
            Dictionary mapping community labels to lists of node IDs.
            Empty dict if NetworkX/community detection is unavailable.

        Example::

            cells = analyzer.communities()
            # {"community_0": ["alice", "bob"], "community_1": ["carol"]}
        """
        if not _HAS_NETWORKX or not _HAS_NX_COMMUNITY or self._graph is None:
            return {}

        if self._communities_cache is None:
            try:
                raw_communities = nx_community.louvain_communities(
                    self._graph, weight=weight, resolution=resolution
                )
                self._communities_cache = {
                    f"community_{i}": sorted(list(members))
                    for i, members in enumerate(raw_communities)
                }
            except Exception as exc:
                _logger.warning("Community detection failed: %s", exc)
                return {}

        return self._communities_cache

    def to_plotly(
        self,
        layout: str = "spring",
        dimension: int = 2,
    ) -> dict[str, Any]:
        """Generate Plotly-compatible data for interactive visualization.

        Produces node positions, sizes (by PageRank), colors (by community),
        and edge coordinates for rendering with plotly.graph_objects.

        Args:
            layout: Layout algorithm — ``"spring"``, ``"kamada_kawai"``,
                ``"circular"``, or ``"spectral"``.
            dimension: 2 or 3 for the layout.

        Returns:
            Dictionary with ``"nodes"`` and ``"edges"`` keys containing
            Plotly trace data. Empty dict if NetworkX or Plotly is unavailable.

        Example::

            fig_data = analyzer.to_plotly()
            fig = go.Figure(data=fig_data["edges"] + fig_data["nodes"])
            fig.show()
        """
        if not _HAS_NETWORKX or not _HAS_PLOTLY or self._graph is None:
            return {}

        try:
            pos = self._compute_layout(layout, dimension)
            pagerank_scores = self.pagerank()
            community_map = self._get_community_map()

            # Node trace
            node_x: list[float] = []
            node_y: list[float] = []
            node_z: list[float] = []
            node_text: list[str] = []
            node_size: list[float] = []
            node_color: list[int] = []

            max_pr = max(pagerank_scores.values()) if pagerank_scores else 1.0

            for node in self._graph.nodes():
                coords = pos.get(node, (0, 0, 0) if dimension == 3 else (0, 0))
                node_x.append(coords[0])
                node_y.append(coords[1])
                if dimension == 3 and len(coords) > 2:
                    node_z.append(coords[2])

                # Size proportional to PageRank (min 10, max 50)
                pr = pagerank_scores.get(node, 0)
                size = 10 + (pr / max_pr * 40) if max_pr > 0 else 10
                node_size.append(size)

                # Color by community
                node_color.append(community_map.get(node, 0))

                # Hover text
                label = self._graph.nodes[node].get("label", node)
                node_type = self._graph.nodes[node].get("type", "unknown")
                node_text.append(
                    f"{label}<br>Type: {node_type}<br>PageRank: {pr:.4f}"
                )

            if dimension == 3:
                node_trace = go.Scatter3d(
                    x=node_x,
                    y=node_y,
                    z=node_z,
                    mode="markers+text",
                    marker=dict(
                        size=node_size,
                        color=node_color,
                        colorscale="Viridis",
                        showscale=True,
                        colorbar=dict(title="Community"),
                    ),
                    text=[self._graph.nodes[n].get("label", n) for n in self._graph.nodes()],
                    textposition="top center",
                    hovertext=node_text,
                    hoverinfo="text",
                    name="Entities",
                )
            else:
                node_trace = go.Scatter(
                    x=node_x,
                    y=node_y,
                    mode="markers+text",
                    marker=dict(
                        size=node_size,
                        color=node_color,
                        colorscale="Viridis",
                        showscale=True,
                        colorbar=dict(title="Community"),
                    ),
                    text=[self._graph.nodes[n].get("label", n) for n in self._graph.nodes()],
                    textposition="top center",
                    hovertext=node_text,
                    hoverinfo="text",
                    name="Entities",
                )

            # Edge traces
            edge_traces = []
            for source, target in self._graph.edges():
                s_coords = pos.get(source, (0, 0, 0) if dimension == 3 else (0, 0))
                t_coords = pos.get(target, (0, 0, 0) if dimension == 3 else (0, 0))

                if dimension == 3:
                    edge_trace = go.Scatter3d(
                        x=[s_coords[0], t_coords[0]],
                        y=[s_coords[1], t_coords[1]],
                        z=[s_coords[2], t_coords[2]],
                        mode="lines",
                        line=dict(color="rgba(100,100,100,0.4)", width=1),
                        hoverinfo="none",
                        showlegend=False,
                    )
                else:
                    edge_trace = go.Scatter(
                        x=[s_coords[0], t_coords[0]],
                        y=[s_coords[1], t_coords[1]],
                        mode="lines",
                        line=dict(color="rgba(100,100,100,0.4)", width=1),
                        hoverinfo="none",
                        showlegend=False,
                    )
                edge_traces.append(edge_trace)

            return {"nodes": [node_trace], "edges": edge_traces}

        except Exception as exc:
            _logger.warning("Plotly data generation failed: %s", exc)
            return {}

    def export_stix(self) -> dict[str, Any]:
        """Export the graph as a STIX 2.1 bundle.

        Converts entities to STIX ``identity`` objects and relationships
        to STIX ``relationship`` objects for ingestion into TIP/MISP platforms.

        Returns:
            STIX 2.1 bundle dictionary. Empty dict if NetworkX is
            unavailable or no graph has been built.

        Example::

            bundle = analyzer.export_stix()
            # {"type": "bundle", "id": "bundle--<uuid>", "objects": [...]}
        """
        if not _HAS_NETWORKX or self._graph is None:
            return {}

        try:
            bundle_id = f"bundle--{uuid.uuid4()}"
            timestamp = datetime.now(timezone.utc).isoformat()
            objects: list[dict[str, Any]] = []

            # Map entity types to STIX identity classes
            type_mapping = {
                "person": "individual",
                "organization": "organization",
                "group": "threat-actor",
                "location": "location",
                "infrastructure": "infrastructure",
                "domain": "domain-name",
                "ip": "ipv4-addr",
                "email": "email-addr",
                "wallet": "cryptocurrency-wallet",
            }

            for node_id in self._graph.nodes():
                attrs = self._graph.nodes[node_id]
                entity_type = attrs.get("type", "unknown")
                stix_type = type_mapping.get(entity_type, "unknown")

                stix_obj: dict[str, Any] = {
                    "type": stix_type,
                    "id": f"{stix_type}--{uuid.uuid4()}",
                    "created": timestamp,
                    "modified": timestamp,
                    "name": attrs.get("label", node_id),
                    "description": attrs.get("description", ""),
                }

                if stix_type == "domain-name":
                    stix_obj["value"] = attrs.get("value", node_id)
                elif stix_type == "ipv4-addr":
                    stix_obj["value"] = attrs.get("value", node_id)
                elif stix_type == "email-addr":
                    stix_obj["value"] = attrs.get("value", node_id)
                elif stix_type == "cryptocurrency-wallet":
                    stix_obj["value"] = attrs.get("value", node_id)

                # Store original node ID for relationship mapping
                stix_obj["external_references"] = [
                    {
                        "source_name": "argus_engine-link-analysis",
                        "external_id": node_id,
                    }
                ]

                objects.append(stix_obj)

            # Build node_id -> stix_id mapping
            node_to_stix: dict[str, str] = {}
            for obj in objects:
                for ref in obj.get("external_references", []):
                    if ref.get("source_name") == "argus_engine-link-analysis":
                        node_to_stix[ref["external_id"]] = obj["id"]

            # Create relationship objects
            rel_type_mapping = {
                "communicates-with": "communicates-with",
                "uses": "uses",
                "targets": "targets",
                "located-at": "located-at",
                "owns": "owns",
                "related-to": "related-to",
                "part-of": "part-of",
                "associated-with": "related-to",
            }

            for source, target, attrs in self._graph.edges(data=True):
                source_stix = node_to_stix.get(source)
                target_stix = node_to_stix.get(target)
                if not source_stix or not target_stix:
                    continue

                rel_type = attrs.get("type", "related-to")
                stix_rel_type = rel_type_mapping.get(rel_type, "related-to")

                rel_obj = {
                    "type": "relationship",
                    "id": f"relationship--{uuid.uuid4()}",
                    "created": timestamp,
                    "modified": timestamp,
                    "relationship_type": stix_rel_type,
                    "source_ref": source_stix,
                    "target_ref": target_stix,
                    "description": attrs.get("description", ""),
                }
                objects.append(rel_obj)

            return {
                "type": "bundle",
                "id": bundle_id,
                "spec_version": "2.1",
                "objects": objects,
            }

        except Exception as exc:
            _logger.warning("STIX export failed: %s", exc)
            return {}

    def export_misp(self) -> dict[str, Any]:
        """Export the graph as a MISP Event dictionary.

        Formats the graph data for direct ingestion into a MISP instance
        via the MISP REST API.

        Returns:
            MISP Event dictionary with Attribute and Object entries.
            Empty dict if NetworkX is unavailable or no graph has been built.

        Example::

            event = analyzer.export_misp()
            # {"Event": {"info": "...", "Attribute": [...], ...}}
        """
        if not _HAS_NETWORKX or self._graph is None:
            return {}

        try:
            timestamp = datetime.now(timezone.utc).isoformat()
            attributes: list[dict[str, Any]] = []

            for node_id in self._graph.nodes():
                attrs = self._graph.nodes[node_id]
                entity_type = attrs.get("type", "unknown")

                misp_type = self._entity_to_misp_type(entity_type)
                value = attrs.get("value", attrs.get("label", node_id))

                attribute = {
                    "type": misp_type,
                    "value": value,
                    "comment": attrs.get("description", ""),
                    "timestamp": timestamp,
                    "to_ids": entity_type in ("domain", "ip", "email", "hash"),
                }
                attributes.append(attribute)

            # Add relationship links as references
            for source, target, attrs in self._graph.edges(data=True):
                source_label = self._graph.nodes[source].get("label", source)
                target_label = self._graph.nodes[target].get("label", target)
                rel_type = attrs.get("type", "related-to")

                attributes.append(
                    {
                        "type": "text",
                        "value": f"{source_label} --[{rel_type}]--> {target_label}",
                        "comment": f"Relationship: {rel_type}",
                        "timestamp": timestamp,
                        "to_ids": False,
                    }
                )

            return {
                "Event": {
                    "info": "ARGUS Link Analysis Export",
                    "threat_level_id": "3",
                    "analysis": "1",
                    "timestamp": timestamp,
                    "Attribute": attributes,
                }
            }

        except Exception as exc:
            _logger.warning("MISP export failed: %s", exc)
            return {}

    def summary(self) -> dict[str, Any]:
        """Return a summary of the graph analysis.

        Returns:
            Dictionary with node/edge counts, top PageRank nodes,
            top betweenness nodes, and community count.
        """
        if not _HAS_NETWORKX or self._graph is None:
            return {
                "available": False,
                "node_count": 0,
                "edge_count": 0,
            }

        top_pagerank = self.pagerank(top_n=5)
        top_betweenness = self.betweenness(top_n=5)
        communities = self.communities()

        return {
            "available": True,
            "node_count": self.node_count,
            "edge_count": self.edge_count,
            "density": nx.density(self._graph) if _HAS_NETWORKX else 0,
            "is_connected": (
                nx.is_connected(self._graph) if _HAS_NETWORKX else False
            ),
            "top_pagerank": top_pagerank,
            "top_betweenness": top_betweenness,
            "community_count": len(communities),
            "communities": communities,
        }

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _clear_caches(self) -> None:
        """Invalidate cached computation results."""
        self._pagerank_cache = None
        self._betweenness_cache = None
        self._communities_cache = None

    def _compute_layout(
        self,
        layout: str,
        dimension: int,
    ) -> dict[str, tuple]:
        """Compute node positions for visualization."""
        if not _HAS_NETWORKX or self._graph is None:
            return {}

        layout_funcs = {
            "spring": lambda: nx.spring_layout(self._graph, dim=dimension),
            "kamada_kawai": lambda: nx.kamada_kawai_layout(self._graph, dim=dimension),
            "circular": lambda: nx.circular_layout(self._graph),
            "spectral": lambda: nx.spectral_layout(self._graph, dim=dimension),
        }

        func = layout_funcs.get(layout, layout_funcs["spring"])
        try:
            return func()
        except Exception:
            # Fallback to spring layout if chosen layout fails
            return nx.spring_layout(self._graph, dim=dimension)

    def _get_community_map(self) -> dict[str, int]:
        """Get a mapping of node -> community index."""
        communities = self.communities()
        mapping: dict[str, int] = {}
        for idx, members in enumerate(communities.values()):
            for node in members:
                mapping[node] = idx
        return mapping

    @staticmethod
    def _entity_to_misp_type(entity_type: str) -> str:
        """Map internal entity types to MISP attribute types."""
        mapping = {
            "person": "text",
            "organization": "text",
            "group": "text",
            "domain": "domain",
            "ip": "ip-dst",
            "email": "email",
            "hash": "sha256",
            "wallet": "btc",
            "url": "url",
        }
        return mapping.get(entity_type, "text")
