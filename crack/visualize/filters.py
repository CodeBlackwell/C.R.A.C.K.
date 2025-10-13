"""
Chain filtering with search integration

Integrates with reference/chains filtering system for dynamic chain discovery.
"""

from typing import List, Dict, Optional, Any
from pathlib import Path
import difflib


class ChainFilter:
    """
    Dynamic chain filtering with search/tag/category integration

    Integrates with:
    - reference/chains/registry.py (ChainRegistry)
    - reference/chains/filtering/ (TagFilter, MetadataFilter)
    """

    def __init__(self, registry):
        """
        Initialize filter with chain registry

        Args:
            registry: ChainRegistry instance from reference.chains
        """
        self.registry = registry

        # Import filtering components if available
        try:
            from crack.reference.chains.filtering import TagFilter, MetadataFilter
            self.tag_filter = TagFilter()
            self.metadata_filter = MetadataFilter()
        except ImportError:
            self.tag_filter = None
            self.metadata_filter = None

    def filter_chains(self,
                     chain_ids: Optional[List[str]] = None,
                     search_term: Optional[str] = None,
                     category: Optional[str] = None,
                     tags: Optional[List[str]] = None,
                     difficulty: Optional[str] = None,
                     oscp_relevant: Optional[bool] = None) -> List[Dict[str, Any]]:
        """
        Multi-criteria filtering with existing filter system

        Returns list of chain dicts matching ALL criteria (AND logic)

        Args:
            chain_ids: Specific chain IDs to include
            search_term: Search in name/description (fuzzy)
            category: Filter by category (enumeration, privilege_escalation, etc.)
            tags: Filter by tags (all must match)
            difficulty: Filter by difficulty level
            oscp_relevant: Filter OSCP-relevant chains only

        Returns:
            List of chain dicts matching criteria
        """
        # Start with all chains or specific IDs
        if chain_ids:
            chains = []
            for chain_id in chain_ids:
                chain = self.registry.get_chain(chain_id)
                if chain:
                    chains.append(chain)
        else:
            chains = list(self.registry.filter_chains())

        # Apply search term (fuzzy match on name/description)
        if search_term:
            chains = self.search_by_name(search_term, chains=chains)

        # Apply category filter
        if category:
            chains = [c for c in chains
                     if c.get('metadata', {}).get('category') == category]

        # Apply tag filters (all tags must match)
        if tags and self.tag_filter:
            chains = self.tag_filter.filter_by_tags(tags, chains)
        elif tags:
            # Fallback if TagFilter not available
            chains = [c for c in chains
                     if all(tag in c.get('metadata', {}).get('tags', []) for tag in tags)]

        # Apply difficulty filter
        if difficulty:
            chains = [c for c in chains
                     if c.get('difficulty') == difficulty]

        # Apply OSCP relevance filter
        if oscp_relevant is not None:
            chains = [c for c in chains
                     if c.get('oscp_relevant') == oscp_relevant]

        return chains

    def search_by_name(self,
                      query: str,
                      chains: Optional[List[Dict]] = None,
                      fuzzy: bool = True,
                      threshold: float = 0.6) -> List[Dict]:
        """
        Fuzzy search chain names and descriptions

        Args:
            query: Search query
            chains: Chain list to search (if None, searches all)
            fuzzy: Enable fuzzy matching
            threshold: Minimum similarity ratio (0.0-1.0)

        Returns:
            List of matching chains, sorted by relevance
        """
        if chains is None:
            chains = list(self.registry.filter_chains())

        query_lower = query.lower()
        matches = []

        for chain in chains:
            # Exact match in ID
            if query_lower == chain['id'].lower():
                matches.append((chain, 1.0))
                continue

            # Search in name
            name = chain.get('name', '').lower()
            if query_lower in name:
                matches.append((chain, 0.9))
                continue

            # Search in description
            description = chain.get('description', '').lower()
            if query_lower in description:
                matches.append((chain, 0.8))
                continue

            # Fuzzy matching on name
            if fuzzy:
                ratio = difflib.SequenceMatcher(None, query_lower, name).ratio()
                if ratio >= threshold:
                    matches.append((chain, ratio * 0.7))  # Lower score for fuzzy
                    continue

        # Sort by relevance score (descending)
        matches.sort(key=lambda x: x[1], reverse=True)

        return [chain for chain, score in matches]

    def get_related_chains(self, chain_id: str) -> List[Dict]:
        """
        Find chains that can activate from this chain

        Looks for:
        - Chains referenced in step.next_steps
        - Chains that parsers might activate
        - Chains in same category

        Args:
            chain_id: Chain ID to find relations for

        Returns:
            List of related chain dicts
        """
        chain = self.registry.get_chain(chain_id)
        if not chain:
            return []

        related = []
        related_ids = set()

        # 1. Check steps for next_steps references
        for step in chain.get('steps', []):
            for next_step_ref in step.get('next_steps', []):
                # If next_step is a chain ID (not a step ID)
                if '-' in next_step_ref and not next_step_ref.startswith(chain_id):
                    related_chain = self.registry.get_chain(next_step_ref)
                    if related_chain and next_step_ref not in related_ids:
                        related.append(related_chain)
                        related_ids.add(next_step_ref)

        # 2. Find chains in same category (potential alternatives)
        category = chain.get('metadata', {}).get('category')
        if category:
            category_chains = [c for c in self.registry.filter_chains()
                             if c.get('metadata', {}).get('category') == category
                             and c['id'] != chain_id
                             and c['id'] not in related_ids]
            related.extend(category_chains[:5])  # Limit to 5 alternatives

        return related

    def get_all_chains(self) -> List[Dict]:
        """Return all available chains"""
        return list(self.registry.filter_chains())

    def get_chains_by_category(self, category: str) -> List[Dict]:
        """Get all chains in a category"""
        return self.filter_chains(category=category)

    def get_chains_by_tag(self, tag: str) -> List[Dict]:
        """Get all chains with a specific tag"""
        return self.filter_chains(tags=[tag])

    def get_categories(self) -> List[str]:
        """Get list of all available categories"""
        chains = self.registry.get_all_chains()
        categories = set()
        for chain in chains:
            cat = chain.get('metadata', {}).get('category')
            if cat:
                categories.add(cat)
        return sorted(categories)

    def get_all_tags(self) -> List[str]:
        """Get list of all unique tags across chains"""
        chains = self.registry.get_all_chains()
        tags = set()
        for chain in chains:
            chain_tags = chain.get('metadata', {}).get('tags', [])
            tags.update(chain_tags)
        return sorted(tags)

    def suggest_chains(self, query: str, limit: int = 5) -> List[tuple[Dict, str]]:
        """
        Suggest chains based on partial query with reason

        Args:
            query: Partial search query
            limit: Maximum suggestions to return

        Returns:
            List of (chain, reason) tuples
        """
        suggestions = []

        # Try exact ID match first
        chain = self.registry.get_chain(query)
        if chain:
            return [(chain, "Exact ID match")]

        # Fuzzy search with low threshold
        matches = self.search_by_name(query, fuzzy=True, threshold=0.4)

        for chain in matches[:limit]:
            # Determine reason
            if query.lower() in chain['id'].lower():
                reason = "ID contains query"
            elif query.lower() in chain.get('name', '').lower():
                reason = "Name contains query"
            elif query.lower() in chain.get('description', '').lower():
                reason = "Description contains query"
            else:
                reason = "Similar name"

            suggestions.append((chain, reason))

        return suggestions
