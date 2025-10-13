"""
Chain graph builder - converts attack chains to graph structures

Supports three visualization modes:
- detail: Single chain with step-by-step graph
- relationships: Multiple chains showing activations
- overview: Ecosystem view with category grouping
"""

from typing import List, Dict, Optional, Set, Any
from collections import defaultdict

from .models import Graph, GraphNode, GraphEdge


class ChainGraphBuilder:
    """Build graph structures from attack chain data"""

    def __init__(self):
        """Initialize graph builder"""
        pass

    def build_single_chain(self, chain: Dict[str, Any]) -> Graph:
        """
        Convert one chain to detailed step-by-step graph

        Mode: detail
        - Each step becomes a node
        - Dependencies become edges
        - Conditional branches shown

        Args:
            chain: Chain dict from ChainRegistry

        Returns:
            Graph with steps as nodes
        """
        graph = Graph()
        graph.metadata = {
            'mode': 'detail',
            'title': chain.get('name', chain['id']),
            'description': chain.get('description'),
            'chain_id': chain['id'],
            'category': chain.get('metadata', {}).get('category'),
            'difficulty': chain.get('difficulty'),
            'oscp_relevant': chain.get('oscp_relevant', False)
        }

        # Create nodes for each step
        for step in chain.get('steps', []):
            node = GraphNode(
                id=step['id'],
                label=step.get('name', step['id']),
                node_type='step',
                metadata={
                    'objective': step.get('objective'),
                    'command_ref': step.get('command_ref'),
                    'description': step.get('description'),
                    'evidence': step.get('evidence', []),
                    'tags': step.get('metadata', {}).get('tags', []),
                    'step_index': chain['steps'].index(step)
                }
            )
            graph.add_node(node)

        # Create edges from dependencies
        for step in chain.get('steps', []):
            step_id = step['id']

            # Dependencies (prerequisite steps)
            for dep_id in step.get('dependencies', []):
                if dep_id in graph.nodes:
                    edge = GraphEdge(
                        source=dep_id,
                        target=step_id,
                        edge_type='dependency',
                        label='requires'
                    )
                    graph.add_edge(edge)

            # Next steps (success paths)
            for next_id in step.get('next_steps', []):
                # Only add if next_id is in same chain
                if next_id in graph.nodes:
                    edge = GraphEdge(
                        source=step_id,
                        target=next_id,
                        edge_type='success',
                        label='on success'
                    )
                    graph.add_edge(edge)

            # Failure conditions (alternative paths)
            failure_conditions = step.get('failure_conditions', [])
            if failure_conditions:
                # Create a decision/branch representation
                # (This is a simplified approach - could be enhanced)
                pass

        # If no explicit edges, create sequential flow
        if not graph.edges and len(graph.nodes) > 1:
            step_ids = [s['id'] for s in chain.get('steps', [])]
            for i in range(len(step_ids) - 1):
                edge = GraphEdge(
                    source=step_ids[i],
                    target=step_ids[i + 1],
                    edge_type='dependency',
                    label='sequential'
                )
                graph.add_edge(edge)

        return graph

    def build_multi_chain(self, chains: List[Dict[str, Any]]) -> Graph:
        """
        Multiple chains showing relationships and activations

        Mode: relationships
        - Each chain becomes a node
        - Activation edges between chains
        - Color by confidence/category

        Args:
            chains: List of chain dicts

        Returns:
            Graph with chains as nodes
        """
        graph = Graph()
        graph.metadata = {
            'mode': 'relationships',
            'title': f'Attack Chain Relationships ({len(chains)} chains)',
            'description': 'Chain-to-chain activation and triggering relationships',
            'chain_count': len(chains)
        }

        # Create nodes for each chain
        for chain in chains:
            node = GraphNode(
                id=chain['id'],
                label=chain.get('name', chain['id']),
                node_type='chain',
                metadata={
                    'description': chain.get('description'),
                    'category': chain.get('metadata', {}).get('category'),
                    'tags': chain.get('metadata', {}).get('tags', []),
                    'difficulty': chain.get('difficulty'),
                    'oscp_relevant': chain.get('oscp_relevant', False),
                    'step_count': len(chain.get('steps', []))
                }
            )
            graph.add_node(node)

        # Detect activation edges between chains
        # This requires parsing step metadata for activations
        for chain in chains:
            chain_id = chain['id']

            for step in chain.get('steps', []):
                # Check for activation metadata (from parsers)
                activations = step.get('activates_chains', [])
                for activation in activations:
                    target_chain_id = activation.get('chain_id')
                    if target_chain_id in graph.nodes:
                        edge = GraphEdge(
                            source=chain_id,
                            target=target_chain_id,
                            edge_type='activation',
                            label=activation.get('reason', 'activates'),
                            metadata={
                                'confidence': activation.get('confidence', 'medium'),
                                'variables': activation.get('variables', {})
                            }
                        )
                        graph.add_edge(edge)

                # Check next_steps for cross-chain references
                for next_step_ref in step.get('next_steps', []):
                    # If it looks like a chain ID (not a step in same chain)
                    if '-' in next_step_ref and not next_step_ref.startswith(chain_id):
                        # Extract potential chain ID
                        potential_chain_id = next_step_ref.split(':')[0] if ':' in next_step_ref else next_step_ref
                        if potential_chain_id in graph.nodes:
                            edge = GraphEdge(
                                source=chain_id,
                                target=potential_chain_id,
                                edge_type='triggers',
                                label='next'
                            )
                            graph.add_edge(edge)

        return graph

    def build_ecosystem(self, chains: List[Dict[str, Any]]) -> Graph:
        """
        High-level ecosystem overview with category grouping

        Mode: overview
        - Chains grouped by category
        - Shows entry points and high-level flow
        - Highlights OSCP-relevant chains

        Args:
            chains: List of all chain dicts

        Returns:
            Graph with category hierarchy
        """
        graph = Graph()
        graph.metadata = {
            'mode': 'overview',
            'title': f'CRACK Attack Chain Ecosystem ({len(chains)} chains)',
            'description': 'Complete overview organized by category',
            'chain_count': len(chains)
        }

        # Group chains by category
        by_category = defaultdict(list)
        for chain in chains:
            category = chain.get('metadata', {}).get('category', 'uncategorized')
            by_category[category].append(chain)

        # Create category nodes
        for category, category_chains in by_category.items():
            # Category parent node
            cat_node = GraphNode(
                id=f'category-{category}',
                label=category.replace('_', ' ').title(),
                node_type='chain',
                metadata={
                    'is_category': True,
                    'chain_count': len(category_chains),
                    'chains': [c['id'] for c in category_chains]
                }
            )
            graph.add_node(cat_node)

            # Individual chain nodes within category
            for chain in category_chains:
                node = GraphNode(
                    id=chain['id'],
                    label=chain.get('name', chain['id']),
                    node_type='chain',
                    metadata={
                        'category': category,
                        'tags': chain.get('metadata', {}).get('tags', []),
                        'difficulty': chain.get('difficulty'),
                        'oscp_relevant': chain.get('oscp_relevant', False),
                        'parent_category': f'category-{category}'
                    }
                )
                graph.add_node(node)

                # Edge from category to chain (grouping)
                edge = GraphEdge(
                    source=f'category-{category}',
                    target=chain['id'],
                    edge_type='dependency',
                    label='contains'
                )
                graph.add_edge(edge)

        return graph

    def add_activation_edges(self, graph: Graph, chains: List[Dict[str, Any]]) -> None:
        """
        Add cross-chain activation edges to existing graph

        Useful for enhancing detail/overview graphs with activation info

        Args:
            graph: Existing graph to enhance
            chains: List of chain dicts for context
        """
        for chain in chains:
            chain_id = chain['id']
            if chain_id not in graph.nodes:
                continue

            for step in chain.get('steps', []):
                activations = step.get('activates_chains', [])
                for activation in activations:
                    target_chain_id = activation.get('chain_id')
                    if target_chain_id in graph.nodes:
                        edge = GraphEdge(
                            source=chain_id,
                            target=target_chain_id,
                            edge_type='activation',
                            label=activation.get('reason', 'activates'),
                            metadata={
                                'confidence': activation.get('confidence', 'medium')
                            }
                        )
                        # Check if edge already exists
                        existing = [e for e in graph.edges
                                  if e.source == chain_id and e.target == target_chain_id]
                        if not existing:
                            graph.add_edge(edge)

    def build_from_filter(self,
                         chains: List[Dict[str, Any]],
                         mode: Optional[str] = None) -> Graph:
        """
        Auto-select appropriate graph mode based on chain count

        Args:
            chains: Filtered chain list
            mode: Force specific mode (detail|relationships|overview)

        Returns:
            Graph with appropriate mode
        """
        if mode == 'detail' or len(chains) == 1:
            return self.build_single_chain(chains[0])
        elif mode == 'relationships' or len(chains) <= 10:
            return self.build_multi_chain(chains)
        else:
            return self.build_ecosystem(chains)
