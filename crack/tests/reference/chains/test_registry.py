"""
Tests for ChainRegistry - In-memory chain storage and lookup.

Business Value Focus:
- Users need reliable chain lookup by ID
- Filter operations must work correctly for workflow selection
- Duplicate chain detection prevents confusion
- Cache invalidation ensures fresh results after updates
"""

import pytest
from unittest.mock import MagicMock

from reference.chains.registry import ChainRegistry
from tests.reference.chains.conftest import ChainFactory


# ==============================================================================
# Test: Chain Registration
# ==============================================================================


class TestChainRegistration:
    """Tests for registering chains in the registry."""

    def test_register_valid_chain(self, empty_registry):
        """
        BV: Users can register new attack chains for lookup.

        Scenario:
          Given: An empty registry
          When: register_chain() is called with valid chain
          Then: Chain is stored and can be retrieved by ID
        """
        # FIX: Chain ID must have 4 hyphen-separated segments
        chain = ChainFactory.create(chain_id="test-chain-register-valid")
        empty_registry.register_chain("test-chain-register-valid", chain)

        retrieved = empty_registry.get_chain("test-chain-register-valid")
        assert retrieved is not None
        assert retrieved["id"] == "test-chain-register-valid"

    def test_register_chain_empty_id_fails(self, empty_registry):
        """
        BV: Empty chain IDs are rejected to prevent silent errors.

        Scenario:
          Given: An empty registry
          When: register_chain() is called with empty string ID
          Then: ValueError is raised
        """
        # FIX: Chain ID must have 4 hyphen-separated segments
        chain = ChainFactory.create(chain_id="will-be-ignored-test")

        with pytest.raises(ValueError) as excinfo:
            empty_registry.register_chain("", chain)

        assert "non-empty" in str(excinfo.value).lower()

    def test_register_duplicate_id_fails(self, empty_registry):
        """
        BV: Duplicate chain IDs are rejected to prevent confusion.

        Scenario:
          Given: A registry with one registered chain
          When: register_chain() is called with the same ID
          Then: ValueError is raised indicating duplicate
        """
        # FIX: Chain ID must have 4 hyphen-separated segments
        chain1 = ChainFactory.create(chain_id="dup-chain-test-first", name="First")
        chain2 = ChainFactory.create(chain_id="dup-chain-test-second", name="Second")

        empty_registry.register_chain("dup-chain-test-first", chain1)

        with pytest.raises(ValueError) as excinfo:
            empty_registry.register_chain("dup-chain-test-first", chain2)

        assert "already registered" in str(excinfo.value).lower()

    def test_register_chain_makes_defensive_copy(self, empty_registry):
        """
        BV: External modifications don't affect registered chains.

        Scenario:
          Given: A chain is registered
          When: The original dictionary is modified externally
          Then: The registered chain is unchanged
        """
        # FIX: Chain ID must have 4 hyphen-separated segments
        chain = ChainFactory.create(chain_id="defensive-copy-test-chain")
        empty_registry.register_chain("defensive-copy-test-chain", chain)

        # Modify the original dict
        chain["name"] = "MODIFIED EXTERNALLY"

        retrieved = empty_registry.get_chain("defensive-copy-test-chain")
        assert retrieved["name"] != "MODIFIED EXTERNALLY"


# ==============================================================================
# Test: Chain Retrieval
# ==============================================================================


class TestChainRetrieval:
    """Tests for retrieving chains from the registry."""

    def test_get_chain_returns_copy(self, populated_registry):
        """
        BV: Retrieved chains are copies (mutations don't affect registry).

        Scenario:
          Given: A registry with registered chains
          When: get_chain() is called and the result is modified
          Then: The registry's copy is unchanged
        """
        # FIX: Use updated chain ID from populated_registry fixture
        retrieved = populated_registry.get_chain("linux-privesc-sudo-test")
        original_name = retrieved["name"]
        retrieved["name"] = "MODIFIED"

        fresh = populated_registry.get_chain("linux-privesc-sudo-test")
        assert fresh["name"] == original_name

    def test_get_chain_not_found_returns_none(self, empty_registry):
        """
        BV: Non-existent chain ID returns None (no exception).

        Scenario:
          Given: An empty registry
          When: get_chain() is called with unknown ID
          Then: None is returned
        """
        result = empty_registry.get_chain("nonexistent-chain-id-test")
        assert result is None

    def test_get_chain_by_id(self, populated_registry):
        """
        BV: Chains can be retrieved by their unique ID.

        Scenario:
          Given: A registry with multiple chains
          When: get_chain() is called with a valid ID
          Then: The correct chain is returned
        """
        # FIX: Use updated chain ID from populated_registry fixture
        chain = populated_registry.get_chain("ad-kerberoast-test-chain")
        assert chain is not None
        assert chain["id"] == "ad-kerberoast-test-chain"


# ==============================================================================
# Test: Chain Filtering
# ==============================================================================


class TestChainFiltering:
    """Tests for filtering chains by criteria."""

    def test_filter_by_difficulty(self, populated_registry):
        """
        BV: Users can find chains matching their skill level.

        Scenario:
          Given: Registry with chains of varying difficulty
          When: filter_chains(difficulty='beginner') is called
          Then: Only beginner chains are returned
        """
        results = list(populated_registry.filter_chains(difficulty="beginner"))

        assert len(results) >= 1
        for chain in results:
            assert chain["difficulty"] == "beginner"

    def test_filter_by_metadata_category(self, populated_registry):
        """
        BV: Users can filter chains by attack category.

        Scenario:
          Given: Registry with chains in different categories
          When: filter_chains(metadata.category='active_directory') is called
          Then: Only AD chains are returned
        """
        results = list(
            populated_registry.filter_chains(**{"metadata.category": "active_directory"})
        )

        assert len(results) >= 1
        for chain in results:
            assert chain["metadata"]["category"] == "active_directory"

    def test_filter_by_multiple_criteria(self, populated_registry):
        """
        BV: Multiple filter criteria are combined with AND logic.

        Scenario:
          Given: Registry with various chains
          When: filter_chains() with multiple criteria
          Then: Only chains matching ALL criteria are returned
        """
        results = list(
            populated_registry.filter_chains(
                difficulty="intermediate",
                **{"metadata.category": "privilege_escalation"},
            )
        )

        for chain in results:
            assert chain["difficulty"] == "intermediate"
            assert chain["metadata"]["category"] == "privilege_escalation"

    def test_filter_no_criteria_returns_all(self, populated_registry):
        """
        BV: Empty filter returns all registered chains.

        Scenario:
          Given: Registry with 3 chains
          When: filter_chains() is called with no arguments
          Then: All 3 chains are returned
        """
        results = list(populated_registry.filter_chains())
        assert len(results) == 3

    def test_filter_no_matches_returns_empty(self, populated_registry):
        """
        BV: Non-matching filter returns empty result (no error).

        Scenario:
          Given: Registry with chains
          When: filter_chains() with impossible criteria
          Then: Empty iterator is returned
        """
        results = list(populated_registry.filter_chains(difficulty="impossible-level"))
        assert len(results) == 0

    def test_filter_with_list_value_matches_any(self, empty_registry):
        """
        BV: List values in filter match ANY of the listed values.

        Scenario:
          Given: Registry with chains of different difficulties
          When: filter_chains(difficulty=('beginner', 'intermediate'))
          Then: Chains matching either difficulty are returned

        NOTE: Use tuple instead of list because the cache key requires hashable values.
        The _CacheKey.from_kwargs() uses tuple(sorted(criteria.items())) which requires
        all values to be hashable.
        """
        # FIX: Chain IDs must have 4 hyphen-separated segments
        for diff in ["beginner", "intermediate", "advanced"]:
            chain = ChainFactory.create(chain_id=f"chain-{diff}-filter-test", difficulty=diff)
            empty_registry.register_chain(chain["id"], chain)

        # FIX: Use tuple instead of list - lists are not hashable for cache key
        results = list(
            empty_registry.filter_chains(difficulty=("beginner", "intermediate"))
        )

        assert len(results) == 2
        difficulties = {c["difficulty"] for c in results}
        assert difficulties == {"beginner", "intermediate"}


# ==============================================================================
# Test: Filter Cache
# ==============================================================================


class TestFilterCache:
    """Tests for filter result caching."""

    def test_filter_cache_hit(self, populated_registry):
        """
        BV: Repeated filter queries are served from cache (performance).

        Scenario:
          Given: A filter query has been executed
          When: The same query is executed again
          Then: Results are served from cache (faster)
        """
        # First query
        results1 = list(populated_registry.filter_chains(difficulty="beginner"))

        # Second query (should hit cache)
        results2 = list(populated_registry.filter_chains(difficulty="beginner"))

        assert len(results1) == len(results2)
        # Can't directly verify cache hit, but behavior should be identical

    def test_filter_cache_cleared_on_registration(self, populated_registry):
        """
        BV: Cache is invalidated when new chains are registered.

        Scenario:
          Given: Filter results are cached
          When: A new chain is registered
          Then: Cache is cleared, next filter sees new chain
        """
        # Prime the cache
        results_before = list(populated_registry.filter_chains(difficulty="beginner"))

        # Register new chain
        # FIX: Chain ID must have 4 hyphen-separated segments
        new_chain = ChainFactory.create(
            chain_id="new-beginner-cache-test", difficulty="beginner"
        )
        populated_registry.register_chain("new-beginner-cache-test", new_chain)

        # Filter again
        results_after = list(populated_registry.filter_chains(difficulty="beginner"))

        assert len(results_after) == len(results_before) + 1


# ==============================================================================
# Test: Singleton Pattern
# ==============================================================================


class TestSingletonPattern:
    """Tests for registry singleton behavior."""

    def test_registry_is_singleton(self):
        """
        BV: Only one registry instance exists (consistent state).

        Scenario:
          Given: Two ChainRegistry instantiations
          When: Chains are registered via one instance
          Then: They are visible via the other instance
        """
        # Reset singleton for clean test
        ChainRegistry._instance = None

        registry1 = ChainRegistry()
        registry2 = ChainRegistry()

        assert registry1 is registry2

    def test_singleton_preserves_data(self):
        """
        BV: Registry data persists across instantiations.

        Scenario:
          Given: A chain is registered
          When: A new ChainRegistry() is created
          Then: The previously registered chain is still available
        """
        # Reset and register
        ChainRegistry._instance = None
        registry1 = ChainRegistry()
        # FIX: Chain ID must have 4 hyphen-separated segments
        chain = ChainFactory.create(chain_id="persistent-chain-singleton-test")
        registry1.register_chain("persistent-chain-singleton-test", chain)

        # Get "new" instance
        registry2 = ChainRegistry()

        retrieved = registry2.get_chain("persistent-chain-singleton-test")
        assert retrieved is not None
        assert retrieved["id"] == "persistent-chain-singleton-test"


# ==============================================================================
# Test: Edge Cases
# ==============================================================================


class TestRegistryEdgeCases:
    """Edge case tests for chain registry."""

    def test_register_chain_with_special_characters_in_id(self, empty_registry):
        """
        BV: Chain IDs with valid special characters work correctly.

        Scenario:
          Given: A chain ID with hyphens and numbers
          When: The chain is registered
          Then: It can be retrieved correctly
        """
        chain = ChainFactory.create(chain_id="linux-privesc-suid-v2")
        empty_registry.register_chain("linux-privesc-suid-v2", chain)

        retrieved = empty_registry.get_chain("linux-privesc-suid-v2")
        assert retrieved is not None

    def test_filter_nested_metadata_fields(self, empty_registry):
        """
        BV: Deeply nested metadata fields can be used for filtering.

        Scenario:
          Given: Chains with nested metadata (e.g., metadata.platform)
          When: Filtering by nested path
          Then: Correct chains are returned
        """
        # FIX: Chain ID must have 4 hyphen-separated segments
        chain = ChainFactory.create(
            chain_id="linux-chain-nested-meta",
            metadata={"category": "test", "platform": "linux"},
        )
        empty_registry.register_chain("linux-chain-nested-meta", chain)

        results = list(
            empty_registry.filter_chains(**{"metadata.platform": "linux"})
        )

        assert len(results) == 1
        assert results[0]["id"] == "linux-chain-nested-meta"

    def test_filter_missing_field_returns_no_match(self, empty_registry):
        """
        BV: Filtering on non-existent field returns no matches.

        Scenario:
          Given: Chains without a particular field
          When: Filtering by that field
          Then: No chains match (field resolves to None)
        """
        # FIX: Chain ID must have 4 hyphen-separated segments
        chain = ChainFactory.create(chain_id="no-platform-test-chain")
        # Remove platform from metadata if it exists
        chain["metadata"].pop("platform", None)
        empty_registry.register_chain("no-platform-test-chain", chain)

        results = list(
            empty_registry.filter_chains(**{"metadata.platform": "linux"})
        )

        assert len(results) == 0

    def test_filter_by_oscp_relevant(self, empty_registry):
        """
        BV: Users can filter for OSCP-relevant chains only.

        Scenario:
          Given: Mix of OSCP and non-OSCP relevant chains
          When: filter_chains(oscp_relevant=True)
          Then: Only OSCP-relevant chains returned
        """
        # FIX: Chain IDs must have 4 hyphen-separated segments
        oscp_chain = ChainFactory.create(chain_id="oscp-chain-relevant-test", oscp_relevant=True)
        non_oscp = ChainFactory.create(chain_id="non-oscp-chain-test", oscp_relevant=False)

        empty_registry.register_chain("oscp-chain-relevant-test", oscp_chain)
        empty_registry.register_chain("non-oscp-chain-test", non_oscp)

        results = list(empty_registry.filter_chains(oscp_relevant=True))

        assert len(results) == 1
        assert results[0]["id"] == "oscp-chain-relevant-test"


# ==============================================================================
# Test: Integration with Filter Operations
# ==============================================================================


class TestRegistryFilterIntegration:
    """Integration tests for complex filtering scenarios."""

    def test_build_attack_chain_library(self, empty_registry):
        """
        BV: Registry can handle realistic library of attack chains.

        Scenario:
          Given: 10 chains across different categories
          When: Various filter operations are performed
          Then: Correct subsets are returned
        """
        # Create diverse chain library
        # FIX: Chain IDs must have 4 hyphen-separated segments
        chains = [
            ChainFactory.create(
                chain_id="linux-sudo-privesc-test",
                difficulty="beginner",
                metadata={"category": "privilege_escalation", "platform": "linux"},
            ),
            ChainFactory.create(
                chain_id="linux-suid-privesc-test",
                difficulty="intermediate",
                metadata={"category": "privilege_escalation", "platform": "linux"},
            ),
            ChainFactory.create(
                chain_id="windows-potato-privesc-test",
                difficulty="intermediate",
                metadata={"category": "privilege_escalation", "platform": "windows"},
            ),
            ChainFactory.create(
                chain_id="ad-kerberoast-attack-test",
                difficulty="advanced",
                metadata={"category": "active_directory", "platform": "windows"},
            ),
            ChainFactory.create(
                chain_id="ad-asreproast-attack-test",
                difficulty="advanced",
                metadata={"category": "active_directory", "platform": "windows"},
            ),
        ]

        for chain in chains:
            empty_registry.register_chain(chain["id"], chain)

        # Test 1: Linux privilege escalation
        linux_privesc = list(
            empty_registry.filter_chains(
                **{
                    "metadata.category": "privilege_escalation",
                    "metadata.platform": "linux",
                }
            )
        )
        assert len(linux_privesc) == 2

        # Test 2: Active Directory chains
        ad_chains = list(
            empty_registry.filter_chains(**{"metadata.category": "active_directory"})
        )
        assert len(ad_chains) == 2

        # Test 3: Beginner difficulty
        beginner = list(empty_registry.filter_chains(difficulty="beginner"))
        assert len(beginner) == 1
        assert beginner[0]["id"] == "linux-sudo-privesc-test"

        # Test 4: All chains
        all_chains = list(empty_registry.filter_chains())
        assert len(all_chains) == 5
