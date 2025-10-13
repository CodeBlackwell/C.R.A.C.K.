"""
Graph data models for attack chain visualization

Provides node/edge abstraction for visualizing chains as graphs.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any


@dataclass
class GraphNode:
    """
    Represents a node in the attack chain graph

    Can represent:
    - Individual step (command/research/manual)
    - Entire chain (in ecosystem view)
    - Decision point (conditional branching)
    """
    id: str
    label: str
    node_type: str  # step|chain|command|decision
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        """Validate node_type"""
        valid_types = ['step', 'chain', 'command', 'decision']
        if self.node_type not in valid_types:
            raise ValueError(f"node_type must be one of {valid_types}, got '{self.node_type}'")

    @property
    def tags(self) -> List[str]:
        """Extract tags from metadata"""
        return self.metadata.get('tags', [])

    @property
    def is_oscp_relevant(self) -> bool:
        """Check if node is OSCP-relevant"""
        return self.metadata.get('oscp_relevant', False)

    @property
    def difficulty(self) -> Optional[str]:
        """Get difficulty level"""
        return self.metadata.get('difficulty')

    def __repr__(self) -> str:
        return f"GraphNode(id={self.id!r}, type={self.node_type!r}, label={self.label!r})"


@dataclass
class GraphEdge:
    """
    Represents a directed edge between nodes

    Edge types:
    - dependency: Step A must complete before Step B
    - activation: Chain A activates Chain B (parser detected)
    - success: Conditional branch on success
    - failure: Conditional branch on failure
    - triggers: Finding triggers another action
    """
    source: str  # Source node ID
    target: str  # Target node ID
    edge_type: str  # dependency|activation|success|failure|triggers
    label: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        """Validate edge_type"""
        valid_types = ['dependency', 'activation', 'success', 'failure', 'triggers']
        if self.edge_type not in valid_types:
            raise ValueError(f"edge_type must be one of {valid_types}, got '{self.edge_type}'")

    @property
    def is_activation(self) -> bool:
        """Check if this is a chain activation edge"""
        return self.edge_type == 'activation'

    @property
    def is_conditional(self) -> bool:
        """Check if this is a conditional branch"""
        return self.edge_type in ['success', 'failure']

    @property
    def confidence(self) -> Optional[str]:
        """Get activation confidence level"""
        return self.metadata.get('confidence')

    def __repr__(self) -> str:
        label_part = f", label={self.label!r}" if self.label else ""
        return f"GraphEdge({self.source!r} -> {self.target!r}, type={self.edge_type!r}{label_part})"


@dataclass
class Graph:
    """
    Represents a complete attack chain graph

    Can represent:
    - Single chain (steps as nodes, dependencies as edges)
    - Multiple chains (chains as nodes, activations as edges)
    - Entire ecosystem (chains grouped by category)
    """
    nodes: Dict[str, GraphNode] = field(default_factory=dict)
    edges: List[GraphEdge] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def add_node(self, node: GraphNode) -> None:
        """Add a node to the graph"""
        if node.id in self.nodes:
            raise ValueError(f"Node with ID '{node.id}' already exists")
        self.nodes[node.id] = node

    def add_edge(self, edge: GraphEdge) -> None:
        """Add an edge to the graph"""
        # Validate source and target exist
        if edge.source not in self.nodes:
            raise ValueError(f"Source node '{edge.source}' does not exist")
        if edge.target not in self.nodes:
            raise ValueError(f"Target node '{edge.target}' does not exist")
        self.edges.append(edge)

    def get_node(self, node_id: str) -> Optional[GraphNode]:
        """Get node by ID"""
        return self.nodes.get(node_id)

    def get_outgoing_edges(self, node_id: str) -> List[GraphEdge]:
        """Get all edges originating from node"""
        return [e for e in self.edges if e.source == node_id]

    def get_incoming_edges(self, node_id: str) -> List[GraphEdge]:
        """Get all edges pointing to node"""
        return [e for e in self.edges if e.target == node_id]

    def get_root_nodes(self) -> List[GraphNode]:
        """Get nodes with no incoming edges (entry points)"""
        nodes_with_incoming = {e.target for e in self.edges}
        return [node for node_id, node in self.nodes.items()
                if node_id not in nodes_with_incoming]

    def get_leaf_nodes(self) -> List[GraphNode]:
        """Get nodes with no outgoing edges (terminal nodes)"""
        nodes_with_outgoing = {e.source for e in self.edges}
        return [node for node_id, node in self.nodes.items()
                if node_id not in nodes_with_outgoing]

    @property
    def node_count(self) -> int:
        """Number of nodes in graph"""
        return len(self.nodes)

    @property
    def edge_count(self) -> int:
        """Number of edges in graph"""
        return len(self.edges)

    @property
    def title(self) -> str:
        """Get graph title from metadata"""
        return self.metadata.get('title', 'Attack Chain Graph')

    @property
    def description(self) -> Optional[str]:
        """Get graph description from metadata"""
        return self.metadata.get('description')

    @property
    def mode(self) -> str:
        """Get visualization mode (detail|relationships|overview)"""
        return self.metadata.get('mode', 'detail')

    def __repr__(self) -> str:
        return f"Graph(nodes={self.node_count}, edges={self.edge_count}, mode={self.mode!r})"
