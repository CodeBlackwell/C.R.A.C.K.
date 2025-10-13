"""
DOT (GraphViz) renderer for attack chain graphs

Exports graphs to DOT format for:
- PNG/SVG generation via graphviz
- Documentation integration
- External graph tools
"""

from typing import List, Dict, Set
from collections import defaultdict

from ..models import Graph, GraphNode, GraphEdge


class DotRenderer:
    """Render graphs as GraphViz DOT format"""

    def __init__(self):
        """Initialize DOT renderer"""
        pass

    def render(self, graph: Graph) -> str:
        """
        Render graph to DOT format based on mode

        Args:
            graph: Graph to render

        Returns:
            DOT format string
        """
        mode = graph.mode

        if mode == 'detail':
            return self._render_detail(graph)
        elif mode == 'relationships':
            return self._render_relationships(graph)
        elif mode == 'overview':
            return self._render_overview(graph)
        else:
            raise ValueError(f"Unknown render mode: {mode}")

    def _render_detail(self, graph: Graph) -> str:
        """
        Render single chain as detailed flowchart

        Attributes:
        - Rounded boxes for steps
        - Color by status/tags
        - Solid edges for dependencies
        - Dashed edges for activations
        """
        lines = []

        # Graph header
        lines.append("digraph attack_chain {")
        lines.append("  rankdir=TB;")  # Top to bottom
        lines.append("  node [shape=box, style=\"rounded,filled\", fontname=\"Arial\"];")
        lines.append("  edge [fontname=\"Arial\", fontsize=10];")
        lines.append("")

        # Graph title
        title = self._escape_dot(graph.title)
        lines.append(f"  labelloc=\"t\";")
        lines.append(f"  label=\"{title}\";")
        lines.append(f"  fontsize=16;")
        lines.append("")

        # Render nodes
        for node in graph.nodes.values():
            node_id = self._sanitize_id(node.id)
            label = self._escape_dot(node.label)

            # Build label with metadata
            label_parts = [label]

            # Add command reference if present
            command_ref = node.metadata.get('command_ref')
            if command_ref:
                label_parts.append(f"\\n{self._escape_dot(command_ref)}")

            # Add tags
            tags = node.tags
            oscp_tags = [t for t in tags if 'OSCP' in t or t == 'QUICK_WIN']
            if oscp_tags:
                label_parts.append(f"\\n[{', '.join(oscp_tags[:2])}]")

            full_label = ''.join(label_parts)

            # Color by tags/status
            fill_color = self._get_node_color(node)

            lines.append(f'  {node_id} [label="{full_label}", fillcolor="{fill_color}"];')

        lines.append("")

        # Render edges
        for edge in graph.edges:
            source_id = self._sanitize_id(edge.source)
            target_id = self._sanitize_id(edge.target)

            # Edge attributes
            attrs = []

            if edge.is_activation:
                attrs.append('style=dashed')
                attrs.append('color=orange')
            elif edge.is_conditional:
                attrs.append('color=blue')
            else:
                attrs.append('color=black')

            if edge.label:
                label = self._escape_dot(edge.label)
                attrs.append(f'label="{label}"')

            attr_str = ', '.join(attrs)
            lines.append(f"  {source_id} -> {target_id} [{attr_str}];")

        lines.append("}")

        return '\n'.join(lines)

    def _render_relationships(self, graph: Graph) -> str:
        """
        Render multiple chains with subgraph clustering

        Features:
        - Subgraph for each category
        - Chain nodes within subgraphs
        - Activation edges between chains
        """
        lines = []

        # Graph header
        lines.append("digraph chain_relationships {")
        lines.append("  rankdir=LR;")  # Left to right
        lines.append("  node [shape=box, style=\"rounded,filled\", fontname=\"Arial\"];")
        lines.append("  edge [fontname=\"Arial\", fontsize=10];")
        lines.append("  compound=true;")  # Allow edges between clusters
        lines.append("")

        # Title
        title = self._escape_dot(graph.title)
        lines.append(f"  labelloc=\"t\";")
        lines.append(f"  label=\"{title}\";")
        lines.append(f"  fontsize=16;")
        lines.append("")

        # Group chains by category
        by_category = defaultdict(list)
        for node in graph.nodes.values():
            category = node.metadata.get('category', 'uncategorized')
            by_category[category].append(node)

        # Render subgraphs for categories
        for i, (category, nodes) in enumerate(sorted(by_category.items())):
            cluster_id = f"cluster_{i}"
            cat_label = category.replace('_', ' ').title()

            lines.append(f"  subgraph {cluster_id} {{")
            lines.append(f"    label=\"{cat_label}\";")
            lines.append(f"    style=filled;")
            lines.append(f"    color=lightgrey;")
            lines.append("")

            # Nodes in this category
            for node in nodes:
                node_id = self._sanitize_id(node.id)
                label = self._escape_dot(node.label)
                fill_color = self._get_node_color(node)

                # Add difficulty if present
                if node.difficulty:
                    label += f"\\n[{node.difficulty}]"

                lines.append(f"    {node_id} [label=\"{label}\", fillcolor=\"{fill_color}\"];")

            lines.append("  }")
            lines.append("")

        # Render edges
        for edge in graph.edges:
            source_id = self._sanitize_id(edge.source)
            target_id = self._sanitize_id(edge.target)

            attrs = []

            if edge.is_activation:
                attrs.append('style=dashed')
                attrs.append('color=orange')
                confidence = edge.confidence or 'medium'
                attrs.append(f'label="activates ({confidence})"')
            else:
                attrs.append('color=blue')
                if edge.label:
                    label = self._escape_dot(edge.label)
                    attrs.append(f'label="{label}"')

            attr_str = ', '.join(attrs)
            lines.append(f"  {source_id} -> {target_id} [{attr_str}];")

        lines.append("}")

        return '\n'.join(lines)

    def _render_overview(self, graph: Graph) -> str:
        """
        Render ecosystem overview with hierarchical layout

        Features:
        - Category nodes as parent containers
        - Chain nodes as children
        - Hierarchical layout
        """
        lines = []

        # Graph header
        lines.append("digraph ecosystem {")
        lines.append("  rankdir=TB;")
        lines.append("  node [fontname=\"Arial\"];")
        lines.append("  edge [fontname=\"Arial\", fontsize=10];")
        lines.append("")

        # Title
        title = self._escape_dot(graph.title)
        lines.append(f"  labelloc=\"t\";")
        lines.append(f"  label=\"{title}\";")
        lines.append(f"  fontsize=16;")
        lines.append("")

        # Render category nodes
        category_nodes = []
        chain_nodes = []

        for node in graph.nodes.values():
            if node.metadata.get('is_category'):
                category_nodes.append(node)
            else:
                chain_nodes.append(node)

        # Category nodes (larger, distinct)
        for node in category_nodes:
            node_id = self._sanitize_id(node.id)
            label = self._escape_dot(node.label)
            chain_count = node.metadata.get('chain_count', 0)

            lines.append(f'  {node_id} [label="{label}\\n({chain_count} chains)", ' +
                        'shape=folder, style=filled, fillcolor=lightblue];')

        lines.append("")

        # Chain nodes (smaller)
        for node in chain_nodes:
            node_id = self._sanitize_id(node.id)
            label = self._escape_dot(node.label)
            fill_color = self._get_node_color(node)

            # Abbreviated label for overview
            if len(label) > 30:
                label = label[:27] + "..."

            lines.append(f'  {node_id} [label="{label}", ' +
                        f'shape=box, style=\"rounded,filled\", fillcolor=\"{fill_color}\"];')

        lines.append("")

        # Render edges (category to chains)
        for edge in graph.edges:
            source_id = self._sanitize_id(edge.source)
            target_id = self._sanitize_id(edge.target)
            lines.append(f"  {source_id} -> {target_id} [color=grey, arrowhead=none];")

        lines.append("}")

        return '\n'.join(lines)

    def _sanitize_id(self, node_id: str) -> str:
        """
        Sanitize node ID for DOT format

        Args:
            node_id: Original node ID

        Returns:
            DOT-safe identifier
        """
        # Replace invalid characters with underscores
        sanitized = node_id.replace('-', '_').replace(':', '_').replace('.', '_')
        return f"node_{sanitized}"

    def _escape_dot(self, text: str) -> str:
        """
        Escape special characters for DOT format

        Args:
            text: Original text

        Returns:
            Escaped text
        """
        # Escape double quotes and backslashes
        return text.replace('\\', '\\\\').replace('"', '\\"')

    def _get_node_color(self, node: GraphNode) -> str:
        """
        Determine fill color for node based on tags/metadata

        Args:
            node: Graph node

        Returns:
            Color name or hex code
        """
        # OSCP-relevant: light green
        if node.is_oscp_relevant:
            return "lightgreen"

        # QUICK_WIN: yellow
        if 'QUICK_WIN' in node.tags:
            return "lightyellow"

        # High confidence: green
        if 'OSCP:HIGH' in node.tags:
            return "palegreen"

        # Default: light blue
        return "lightblue"
