"""
ASCII renderer for attack chain graphs

Provides terminal-native tree/graph visualization with three modes:
- detail: Single chain step-by-step graph
- relationships: Multi-chain relationship diagram
- overview: Ecosystem category tree
"""

from typing import List, Dict, Set, Optional
from collections import defaultdict

from ..models import Graph, GraphNode, GraphEdge


class AsciiRenderer:
    """Render graphs as ASCII art for terminal display"""

    def __init__(self, use_colors: bool = True):
        """
        Initialize ASCII renderer

        Args:
            use_colors: Enable ANSI color codes
        """
        self.use_colors = use_colors

        # ANSI color codes (from crack.utils.colors)
        self.CYAN = '\033[36m' if use_colors else ''
        self.YELLOW = '\033[33m' if use_colors else ''
        self.GREEN = '\033[32m' if use_colors else ''
        self.RED = '\033[31m' if use_colors else ''
        self.DIM = '\033[2m' if use_colors else ''
        self.BOLD = '\033[1m' if use_colors else ''
        self.RESET = '\033[0m' if use_colors else ''

    def render(self, graph: Graph) -> str:
        """
        Render graph based on mode

        Args:
            graph: Graph to render

        Returns:
            ASCII art string
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
        Render single chain with step-by-step detail

        Layout:
        ┌────────────┐
        │ Step 1     │
        │ command    │
        │ [tags]     │
        └──────┬─────┘
               │
               ▼
        ┌────────────┐
        │ Step 2     │
        └────────────┘
        """
        lines = []

        # Header
        lines.append("=" * 70)
        lines.append(f"{self.BOLD}{graph.title}{self.RESET}".center(70 + len(self.BOLD) + len(self.RESET)))
        lines.append("=" * 70)

        # Metadata
        metadata_parts = []
        if graph.metadata.get('category'):
            metadata_parts.append(f"Category: {self.CYAN}{graph.metadata['category']}{self.RESET}")
        if graph.metadata.get('difficulty'):
            metadata_parts.append(f"Difficulty: {self.YELLOW}{graph.metadata['difficulty']}{self.RESET}")
        if graph.metadata.get('oscp_relevant'):
            metadata_parts.append(f"{self.GREEN}OSCP Relevant{self.RESET}")
        if metadata_parts:
            lines.append(" | ".join(metadata_parts))
        lines.append("")

        if graph.description:
            lines.append(graph.description)
            lines.append("")

        # Get root nodes (entry points)
        roots = graph.get_root_nodes()
        if not roots:
            # Fallback: use first node
            roots = [list(graph.nodes.values())[0]] if graph.nodes else []

        # Render tree starting from roots
        visited = set()
        for root in roots:
            self._render_node_tree(root, graph, lines, visited, indent=0)

        # Legend
        lines.append("")
        lines.append(f"{self.DIM}Legend:{self.RESET}")
        lines.append(f"{self.DIM}  ──► Dependency edge{self.RESET}")
        lines.append(f"{self.DIM}  ··► Activation edge (chain switching){self.RESET}")
        lines.append(f"{self.DIM}  [condition] Edge label{self.RESET}")

        return '\n'.join(lines)

    def _render_node_tree(self,
                         node: GraphNode,
                         graph: Graph,
                         lines: List[str],
                         visited: Set[str],
                         indent: int = 0):
        """
        Recursively render node and children as tree

        Args:
            node: Current node
            graph: Full graph
            lines: Output lines list
            visited: Set of visited node IDs
            indent: Current indentation level
        """
        if node.id in visited:
            # Already rendered (avoid cycles)
            return

        visited.add(node.id)

        prefix = "  " * indent

        # Node box
        box_width = 50
        label = node.label[:box_width-4]  # Truncate if too long

        # Top border
        lines.append(f"{prefix}┌{'─' * (box_width-2)}┐")

        # Node label (with step number if available)
        step_index = node.metadata.get('step_index')
        if step_index is not None:
            label_line = f"{step_index + 1}. {label}"
        else:
            label_line = label

        lines.append(f"{prefix}│ {self.BOLD}{label_line}{self.RESET}{' ' * (box_width - len(label_line) - 3)}│")

        # Command reference (if present)
        command_ref = node.metadata.get('command_ref')
        if command_ref:
            cmd_line = f"  {self.DIM}{command_ref}{self.RESET}"
            lines.append(f"{prefix}│{cmd_line}{' ' * (box_width - len(command_ref) - 4)}│")

        # Tags (if present)
        tags = node.tags
        if tags:
            oscp_tags = [t for t in tags if 'OSCP' in t]
            quick_wins = [t for t in tags if t == 'QUICK_WIN']
            display_tags = oscp_tags[:2] + quick_wins[:1]

            if display_tags:
                tag_str = ', '.join(display_tags)
                tag_line = f"  [{self.GREEN}{tag_str}{self.RESET}]"
                lines.append(f"{prefix}│{tag_line}{' ' * (box_width - len(tag_str) - 6)}│")

        # Bottom border
        lines.append(f"{prefix}└{'─' * (box_width-2)}┘")

        # Get outgoing edges
        outgoing = graph.get_outgoing_edges(node.id)

        if not outgoing:
            # Leaf node
            return

        # Render edges and child nodes
        for i, edge in enumerate(outgoing):
            is_last = i == len(outgoing) - 1

            # Edge line
            if edge.edge_type == 'activation':
                connector = "··►"  # Dashed for activation
                color = self.YELLOW
            else:
                connector = "──►"
                color = self.CYAN

            label_text = f"[{edge.label}]" if edge.label else ""

            if len(outgoing) == 1:
                lines.append(f"{prefix}     │")
                lines.append(f"{prefix}     {color}{connector}{self.RESET} {label_text}")
            else:
                # Branching
                if i == 0:
                    lines.append(f"{prefix}     │")
                    lines.append(f"{prefix}  ┌──┴──┐")

                branch_prefix = "├" if not is_last else "└"
                lines.append(f"{prefix}  {branch_prefix}{color}{connector}{self.RESET} {label_text}")

            # Recursively render target node
            target_node = graph.get_node(edge.target)
            if target_node:
                lines.append("")
                self._render_node_tree(target_node, graph, lines, visited, indent)

    def _render_relationships(self, graph: Graph) -> str:
        """
        Render multiple chains showing relationships

        Layout:
        ┌──────────────┐
        │ Chain A      │
        │ [category]   │
        └───────┬──────┘
                │
           ┌────┴───┐
           │        │
           ▼        ▼
        ┌────┐   ┌────┐
        │ B  │   │ C  │
        └────┘   └────┘
        """
        lines = []

        # Header
        lines.append("=" * 70)
        lines.append(f"{self.BOLD}{graph.title}{self.RESET}".center(70 + len(self.BOLD) + len(self.RESET)))
        lines.append("=" * 70)
        lines.append("")

        # Get root chains (no incoming edges)
        roots = graph.get_root_nodes()

        if not roots:
            # No clear root - show all nodes
            lines.append("Chains (no clear entry point):")
            for node in graph.nodes.values():
                lines.append(f"  • {self.CYAN}{node.label}{self.RESET}")
            return '\n'.join(lines)

        # Render relationship tree
        visited = set()
        for root in roots:
            self._render_chain_tree(root, graph, lines, visited, indent=0)

        # Show activation counts
        lines.append("")
        lines.append(f"{self.DIM}Activation Summary:{self.RESET}")
        activation_counts = defaultdict(int)
        for edge in graph.edges:
            if edge.is_activation:
                activation_counts[edge.target] += 1

        for chain_id, count in sorted(activation_counts.items(), key=lambda x: x[1], reverse=True):
            node = graph.get_node(chain_id)
            if node:
                lines.append(f"  {self.CYAN}{node.label}{self.RESET}: {count} activation(s)")

        return '\n'.join(lines)

    def _render_chain_tree(self,
                          node: GraphNode,
                          graph: Graph,
                          lines: List[str],
                          visited: Set[str],
                          indent: int = 0):
        """Render chain node with children in tree structure"""
        if node.id in visited:
            return

        visited.add(node.id)
        prefix = "  " * indent

        # Chain box
        box_width = 40
        label = node.label[:box_width-4]

        lines.append(f"{prefix}┌{'─' * (box_width-2)}┐")
        lines.append(f"{prefix}│ {self.BOLD}{label}{self.RESET}{' ' * (box_width - len(label) - 3)}│")

        # Category tag
        category = node.metadata.get('category')
        if category:
            cat_display = category.replace('_', ' ').title()
            lines.append(f"{prefix}│ {self.DIM}[{cat_display}]{self.RESET}{' ' * (box_width - len(cat_display) - 5)}│")

        # OSCP tag
        if node.is_oscp_relevant:
            lines.append(f"{prefix}│ {self.GREEN}[OSCP]{self.RESET}{' ' * (box_width - 9)}│")

        lines.append(f"{prefix}└{'─' * (box_width-2)}┘")

        # Outgoing edges
        outgoing = graph.get_outgoing_edges(node.id)
        if outgoing:
            lines.append(f"{prefix}     │")

            for i, edge in enumerate(outgoing):
                is_last = i == len(outgoing) - 1
                target_node = graph.get_node(edge.target)

                if not target_node:
                    continue

                # Edge representation
                if edge.is_activation:
                    edge_sym = "··►"
                    confidence = edge.confidence or "medium"
                    conf_color = self.GREEN if confidence == "high" else self.YELLOW
                    label_text = f"{conf_color}activates ({confidence}){self.RESET}"
                else:
                    edge_sym = "──►"
                    label_text = edge.label or "triggers"

                if len(outgoing) == 1:
                    lines.append(f"{prefix}  {edge_sym} {label_text}")
                    lines.append(f"{prefix}     ▼")
                else:
                    if i == 0:
                        lines.append(f"{prefix}  ┌──┴{'─' * 10}┐")
                    connector = "├" if not is_last else "└"
                    lines.append(f"{prefix}  {connector}{edge_sym} {label_text}")

                # Render target
                lines.append("")
                self._render_chain_tree(target_node, graph, lines, visited, indent + 1)

    def _render_overview(self, graph: Graph) -> str:
        """
        Render ecosystem overview with category grouping

        Layout:
        [Category A]
          ├─ chain-1 (OSCP)
          ├─ chain-2
          └─ chain-3 (QUICK_WIN)

        [Category B]
          ├─ chain-4
          └─ chain-5
        """
        lines = []

        # Header
        lines.append("=" * 70)
        lines.append(f"{self.BOLD}{graph.title}{self.RESET}".center(70 + len(self.BOLD) + len(self.RESET)))
        lines.append("=" * 70)
        lines.append("")

        # Group nodes by category
        category_nodes = {}
        chain_nodes = defaultdict(list)

        for node in graph.nodes.values():
            if node.metadata.get('is_category'):
                category_nodes[node.id] = node
            else:
                parent_cat = node.metadata.get('parent_category', 'uncategorized')
                chain_nodes[parent_cat].append(node)

        # Render each category
        for cat_id in sorted(category_nodes.keys()):
            cat_node = category_nodes[cat_id]
            chains = chain_nodes.get(cat_id, [])

            # Category header
            lines.append(f"{self.YELLOW}[{cat_node.label}]{self.RESET} ({len(chains)} chains)")

            # Sort chains: OSCP first, then by name
            chains.sort(key=lambda n: (not n.is_oscp_relevant, n.label))

            for i, chain in enumerate(chains):
                is_last = i == len(chains) - 1
                connector = "└─" if is_last else "├─"

                # Chain name
                name = chain.label

                # Tags
                tags = []
                if chain.is_oscp_relevant:
                    tags.append(f"{self.GREEN}OSCP{self.RESET}")
                if 'QUICK_WIN' in chain.tags:
                    tags.append(f"{self.GREEN}QUICK_WIN{self.RESET}")
                if chain.difficulty:
                    tags.append(f"{self.DIM}{chain.difficulty}{self.RESET}")

                tag_str = f" ({', '.join(tags)})" if tags else ""

                lines.append(f"  {connector} {self.CYAN}{name}{self.RESET}{tag_str}")

            lines.append("")

        # Summary stats
        total_chains = sum(len(chains) for chains in chain_nodes.values())
        oscp_chains = sum(1 for node in graph.nodes.values()
                         if node.node_type == 'chain' and node.is_oscp_relevant)

        lines.append(f"{self.DIM}Total: {total_chains} chains | OSCP-Relevant: {oscp_chains}{self.RESET}")

        return '\n'.join(lines)
