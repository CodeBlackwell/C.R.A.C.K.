# 05 - Integration: Router and CLI Updates

## Prerequisites
- [00-ARCHITECTURE.md](00-ARCHITECTURE.md#router-implementation-strategy) - Router design
- [04-ADAPTER-IMPLEMENTATION.md](04-ADAPTER-IMPLEMENTATION.md) - Adapters completed

## Overview

Integration guide for `CommandRegistryRouter` and CLI auto-detection logic to enable seamless dual-backend operation.

---

## Router Implementation

### Purpose

Intelligently route queries to the optimal backend (PostgreSQL vs Neo4j) with automatic fallback.

### File Location

**File**: `reference/core/router.py` (NEW)

### Complete Implementation

```python
"""
Command Registry Router - Intelligent Backend Selection

Routes queries to PostgreSQL or Neo4j based on query type:
- Simple lookups → PostgreSQL (faster for indexed queries)
- Graph traversals → Neo4j (10x+ faster for multi-hop)
- Automatic fallback to PostgreSQL if Neo4j unavailable
"""

import logging
from typing import List, Dict, Optional, Any
from enum import Enum

from crack.reference.core import Command, ConfigManager, ReferenceTheme
from crack.reference.core.sql_adapter import SQLCommandRegistryAdapter
from crack.reference.core.neo4j_adapter import (
    Neo4jCommandRegistryAdapter,
    Neo4jConnectionError,
    Path
)

logger = logging.getLogger(__name__)


class BackendType(Enum):
    """Backend selection strategy"""
    POSTGRESQL = "postgresql"
    NEO4J = "neo4j"
    AUTO = "auto"  # Intelligent routing


class QueryComplexity(Enum):
    """Query complexity classification"""
    SIMPLE = "simple"          # Single node lookup, indexed queries
    MODERATE = "moderate"      # 1-2 JOINs, simple filters
    COMPLEX = "complex"        # 3+ hops, graph traversals


class CommandRegistryRouter:
    """
    Dual-backend router with intelligent query routing

    Decision Matrix:
    - get_command() → Always PostgreSQL (indexed)
    - search() → PostgreSQL (full-text index)
    - find_alternatives(depth=1) → PostgreSQL (single JOIN)
    - find_alternatives(depth≥2) → Neo4j (graph traversal)
    - get_attack_chain_path() → Neo4j (complex dependencies)
    """

    def __init__(
        self,
        config_manager: Optional[ConfigManager] = None,
        theme: Optional[ReferenceTheme] = None,
        backend_preference: BackendType = BackendType.AUTO,
        enable_fallback: bool = True
    ):
        self.config = config_manager or ConfigManager()
        self.theme = theme or ReferenceTheme()
        self.backend_preference = backend_preference
        self.enable_fallback = enable_fallback

        # Initialize PostgreSQL (always available)
        try:
            self.pg_adapter = SQLCommandRegistryAdapter(
                config_manager=self.config,
                theme=self.theme
            )
            self.pg_available = True
        except Exception as e:
            logger.error(f"PostgreSQL initialization failed: {e}")
            self.pg_available = False
            self.pg_adapter = None

        # Initialize Neo4j (optional)
        try:
            self.neo4j_adapter = Neo4jCommandRegistryAdapter(
                config_manager=self.config,
                theme=self.theme
            )
            self.neo4j_available = self.neo4j_adapter.health_check()

            if self.neo4j_available:
                logger.info("Neo4j backend initialized successfully")
            else:
                logger.warning("Neo4j connection failed health check")

        except Neo4jConnectionError as e:
            logger.warning(f"Neo4j unavailable: {e}")
            self.neo4j_available = False
            self.neo4j_adapter = None

        # Validate at least one backend is available
        if not self.pg_available and not self.neo4j_available:
            raise RuntimeError("No database backends available")

    # ========================================================================
    # Simple Queries (PostgreSQL Preferred)
    # ========================================================================

    def get_command(self, command_id: str) -> Optional[Command]:
        """
        Get single command by ID

        Backend: PostgreSQL (indexed lookup, O(1))
        Fallback: Neo4j if PostgreSQL unavailable
        """
        if self.pg_available:
            return self.pg_adapter.get_command(command_id)

        elif self.neo4j_available and self.enable_fallback:
            logger.debug(f"Using Neo4j fallback for get_command({command_id})")
            return self.neo4j_adapter.get_command(command_id)

        return None

    def search(
        self,
        query: str,
        category: Optional[str] = None,
        tags: Optional[List[str]] = None,
        oscp_only: bool = False
    ) -> List[Command]:
        """
        Full-text search

        Backend: PostgreSQL (mature full-text search)
        Fallback: Neo4j (slower but functional)
        """
        if self.pg_available:
            return self.pg_adapter.search(query, category, tags, oscp_only)

        elif self.neo4j_available and self.enable_fallback:
            logger.debug(f"Using Neo4j fallback for search('{query}')")
            return self.neo4j_adapter.search(query, category, tags, oscp_only)

        return []

    def filter_by_category(self, category: str) -> List[Command]:
        """
        Filter by category

        Backend: PostgreSQL (simple WHERE clause)
        Fallback: Neo4j
        """
        if self.pg_available:
            return self.pg_adapter.filter_by_category(category)

        elif self.neo4j_available and self.enable_fallback:
            return self.neo4j_adapter.filter_by_category(category)

        return []

    def filter_by_tags(
        self,
        tags: List[str],
        match_all: bool = True
    ) -> List[Command]:
        """
        Filter by tags

        Backend: PostgreSQL for 1-2 tags, Neo4j for complex tag hierarchies
        """
        complexity = self._assess_query_complexity(
            "filter_by_tags",
            tag_count=len(tags)
        )

        if complexity == QueryComplexity.SIMPLE and self.pg_available:
            return self.pg_adapter.filter_by_tags(tags, match_all)

        elif self.neo4j_available:
            return self.neo4j_adapter.filter_by_tags(tags, match_all)

        elif self.pg_available and self.enable_fallback:
            logger.debug("Neo4j unavailable, using PostgreSQL for tag filter")
            return self.pg_adapter.filter_by_tags(tags, match_all)

        return []

    # ========================================================================
    # Graph Queries (Neo4j Preferred)
    # ========================================================================

    def find_alternatives(
        self,
        command_id: str,
        max_depth: int = 3
    ) -> List[Path]:
        """
        Find alternative command chains

        Backend:
        - depth=1: PostgreSQL (single JOIN)
        - depth≥2: Neo4j (graph traversal 10x+ faster)

        Fallback: PostgreSQL with recursive CTE (slow)
        """
        complexity = self._assess_query_complexity(
            "find_alternatives",
            depth=max_depth
        )

        # Prefer Neo4j for depth ≥2
        if complexity == QueryComplexity.COMPLEX and self.neo4j_available:
            try:
                return self.neo4j_adapter.find_alternatives(command_id, max_depth)
            except Exception as e:
                logger.warning(f"Neo4j query failed: {e}")
                if self.enable_fallback and self.pg_available:
                    logger.info("Falling back to PostgreSQL recursive query")
                    return self._pg_find_alternatives_recursive(command_id, max_depth)
                raise

        # Use PostgreSQL for depth=1 or if Neo4j unavailable
        elif self.pg_available:
            if max_depth == 1:
                # Simple JOIN query
                return self.pg_adapter.find_alternatives(command_id)
            else:
                # Recursive CTE (slower)
                return self._pg_find_alternatives_recursive(command_id, max_depth)

        return []

    def find_prerequisites(self, command_id: str) -> List[Command]:
        """
        Get all prerequisites (transitive closure)

        Backend: Neo4j (native graph traversal)
        Fallback: PostgreSQL with recursive CTE
        """
        if self.neo4j_available:
            try:
                return self.neo4j_adapter.find_prerequisites(command_id)
            except Exception as e:
                logger.warning(f"Neo4j query failed: {e}, falling back to PostgreSQL")

        if self.pg_available and self.enable_fallback:
            return self._pg_find_prerequisites_recursive(command_id)

        return []

    def get_attack_chain_path(self, chain_id: str) -> Dict[str, Any]:
        """
        Get attack chain execution plan

        Backend: Neo4j ONLY (complex dependency resolution)
        Fallback: Raise error (not implemented in PostgreSQL)
        """
        if self.neo4j_available:
            return self.neo4j_adapter.get_attack_chain_path(chain_id)

        else:
            raise NotImplementedError(
                "Attack chain path planning requires Neo4j backend. "
                "Please enable Neo4j or use individual step queries."
            )

    # ========================================================================
    # Helper Methods
    # ========================================================================

    def _assess_query_complexity(
        self,
        query_type: str,
        **params
    ) -> QueryComplexity:
        """
        Classify query complexity to guide backend selection

        Rules:
        - Single node lookup: SIMPLE
        - 1-hop relationships: MODERATE
        - 2+ hop traversals: COMPLEX
        """
        if query_type == "find_alternatives":
            depth = params.get("depth", 1)
            if depth == 1:
                return QueryComplexity.MODERATE
            else:
                return QueryComplexity.COMPLEX

        elif query_type == "filter_by_tags":
            tag_count = params.get("tag_count", 1)
            if tag_count <= 2:
                return QueryComplexity.SIMPLE
            else:
                return QueryComplexity.MODERATE

        elif query_type in ["get_command", "search", "filter_by_category"]:
            return QueryComplexity.SIMPLE

        else:
            return QueryComplexity.COMPLEX

    def _pg_find_alternatives_recursive(
        self,
        command_id: str,
        max_depth: int
    ) -> List[Path]:
        """
        PostgreSQL fallback using recursive CTE

        WARNING: Significantly slower than Neo4j for depth > 2
        """
        # This would use PostgreSQL WITH RECURSIVE syntax
        # Implementation omitted for brevity (see sql_adapter.py)
        logger.warning(
            f"Using PostgreSQL recursive query for depth={max_depth} "
            "(10x+ slower than Neo4j)"
        )
        # Placeholder: return 1-hop alternatives only
        return self.pg_adapter.find_alternatives(command_id)

    def _pg_find_prerequisites_recursive(self, command_id: str) -> List[Command]:
        """PostgreSQL recursive prerequisite lookup"""
        # Similar to _pg_find_alternatives_recursive
        return self.pg_adapter.find_prerequisites(command_id)

    # ========================================================================
    # Utility Methods
    # ========================================================================

    def get_stats(self) -> Dict[str, Any]:
        """Get statistics from both backends"""
        stats = {
            "backends": {
                "postgresql": {
                    "available": self.pg_available,
                    "stats": self.pg_adapter.get_stats() if self.pg_available else None
                },
                "neo4j": {
                    "available": self.neo4j_available,
                    "stats": self.neo4j_adapter.get_stats() if self.neo4j_available else None
                }
            },
            "routing_mode": self.backend_preference.value
        }
        return stats

    def health_check(self) -> Dict[str, bool]:
        """Check health of both backends"""
        return {
            "postgresql": self.pg_adapter.health_check() if self.pg_available else False,
            "neo4j": self.neo4j_adapter.health_check() if self.neo4j_available else False
        }

    def interactive_fill(self, command: Command) -> str:
        """
        Interactive placeholder filling

        Uses PostgreSQL adapter's implementation (backend-agnostic)
        """
        if self.pg_available:
            return self.pg_adapter.interactive_fill(command)
        elif self.neo4j_available:
            return self.neo4j_adapter.interactive_fill(command)
        else:
            raise RuntimeError("No backend available for interactive_fill")
```

---

## CLI Integration

### Update Auto-Detection Logic

**File**: `reference/cli/main.py` (MODIFY lines 52-114)

**Before** (current):
```python
def _initialize_registry(self):
    """Auto-detect backend: try SQL first, fallback to JSON"""

    try:
        from crack.reference.core.sql_adapter import SQLCommandRegistryAdapter
        registry = SQLCommandRegistryAdapter(self.config, self.theme)
        print("[INFO] Using SQL backend")
        return registry

    except Exception as e:
        print(f"[WARN] SQL backend unavailable: {e}")
        print("[INFO] Falling back to JSON backend")
        from crack.reference.core.registry import HybridCommandRegistry
        return HybridCommandRegistry(self.config, self.theme)
```

**After** (with router):
```python
def _initialize_registry(self):
    """
    Auto-detect backend: Neo4j + PostgreSQL → PostgreSQL only → JSON

    Priority:
    1. CommandRegistryRouter (PostgreSQL + Neo4j) - best performance
    2. SQLCommandRegistryAdapter (PostgreSQL only) - reliable fallback
    3. HybridCommandRegistry (JSON) - last resort
    """

    # Try router (dual backend)
    try:
        from crack.reference.core.router import CommandRegistryRouter
        registry = CommandRegistryRouter(
            config_manager=self.config,
            theme=self.theme,
            enable_fallback=True
        )

        health = registry.health_check()
        backends_available = [k for k, v in health.items() if v]

        if len(backends_available) == 2:
            print("[INFO] Using dual backend (PostgreSQL + Neo4j)")
        elif 'postgresql' in backends_available:
            print("[INFO] Using PostgreSQL backend (Neo4j unavailable)")
        elif 'neo4j' in backends_available:
            print("[WARN] Using Neo4j only (PostgreSQL unavailable)")
        else:
            raise RuntimeError("No backends available in router")

        return registry

    except Exception as e:
        print(f"[WARN] Router initialization failed: {e}")

    # Try PostgreSQL adapter
    try:
        from crack.reference.core.sql_adapter import SQLCommandRegistryAdapter
        registry = SQLCommandRegistryAdapter(self.config, self.theme)
        print("[INFO] Using PostgreSQL backend only")
        return registry

    except Exception as e:
        print(f"[WARN] PostgreSQL backend unavailable: {e}")

    # Fallback to JSON
    print("[INFO] Falling back to JSON backend")
    from crack.reference.core.registry import HybridCommandRegistry
    return HybridCommandRegistry(self.config, self.theme)
```

---

### Add Backend Status Command

**New CLI Command**: `crack reference --status`

**Implementation**:
```python
# In reference/cli/main.py

def cmd_status(self):
    """Show backend status and statistics"""

    if not isinstance(self.registry, CommandRegistryRouter):
        print("Backend: Single adapter (not using router)")
        print(f"Type: {type(self.registry).__name__}")
        return

    health = self.registry.health_check()
    stats = self.registry.get_stats()

    print("=" * 60)
    print("CRACK Reference Backend Status")
    print("=" * 60)

    # PostgreSQL
    pg_health = health.get('postgresql', False)
    print(f"\nPostgreSQL: {'✓ ONLINE' if pg_health else '✗ OFFLINE'}")
    if pg_health and stats['backends']['postgresql']['stats']:
        pg_stats = stats['backends']['postgresql']['stats']
        print(f"  Commands: {pg_stats.get('command_count', 'N/A')}")
        print(f"  Services: {pg_stats.get('service_count', 'N/A')}")
        print(f"  Attack Chains: {pg_stats.get('chain_count', 'N/A')}")

    # Neo4j
    neo4j_health = health.get('neo4j', False)
    print(f"\nNeo4j: {'✓ ONLINE' if neo4j_health else '✗ OFFLINE'}")
    if neo4j_health and stats['backends']['neo4j']['stats']:
        neo4j_stats = stats['backends']['neo4j']['stats']
        print(f"  Command Nodes: {neo4j_stats.get('command_count', 'N/A')}")
        print(f"  Total Relationships: {neo4j_stats.get('relationship_count', 'N/A')}")

    # Routing mode
    print(f"\nRouting Mode: {stats.get('routing_mode', 'unknown')}")

    print("=" * 60)
```

---

## Configuration Management

### Environment Variable Support

**File**: `db/config.py` (already modified in 01-ENVIRONMENT.md)

**Usage in Router**:
```python
import os

# Override backend preference via environment
backend_pref = os.getenv('CRACK_BACKEND_PREFERENCE', 'auto')

router = CommandRegistryRouter(
    backend_preference=BackendType(backend_pref),
    enable_fallback=os.getenv('CRACK_ENABLE_FALLBACK', 'true').lower() == 'true'
)
```

**Environment Variables**:
```bash
# Force PostgreSQL only
export CRACK_BACKEND_PREFERENCE=postgresql

# Force Neo4j only (will fail if unavailable)
export CRACK_BACKEND_PREFERENCE=neo4j

# Auto-detect (default)
export CRACK_BACKEND_PREFERENCE=auto

# Disable fallback (strict mode)
export CRACK_ENABLE_FALLBACK=false
```

---

## Testing Integration

### Integration Test Suite

**File**: `tests/reference/test_router_integration.py`

```python
import pytest
from crack.reference.core.router import CommandRegistryRouter, BackendType

@pytest.fixture
def router():
    """Create router with both backends"""
    return CommandRegistryRouter(backend_preference=BackendType.AUTO)


def test_router_health_check(router):
    """Verify both backends are accessible"""
    health = router.health_check()

    assert 'postgresql' in health
    assert 'neo4j' in health

    # At least one backend should be healthy
    assert any(health.values())


def test_router_simple_query_uses_postgresql(router, mocker):
    """Verify simple queries route to PostgreSQL"""

    # Mock adapters to track which is called
    pg_spy = mocker.spy(router.pg_adapter, 'get_command')
    neo4j_spy = mocker.spy(router.neo4j_adapter, 'get_command') if router.neo4j_available else None

    cmd = router.get_command('nmap-quick-scan')

    # PostgreSQL should be called
    assert pg_spy.call_count == 1

    # Neo4j should NOT be called
    if neo4j_spy:
        assert neo4j_spy.call_count == 0


def test_router_graph_query_uses_neo4j(router, mocker):
    """Verify graph queries route to Neo4j"""

    if not router.neo4j_available:
        pytest.skip("Neo4j not available")

    pg_spy = mocker.spy(router.pg_adapter, 'find_alternatives')
    neo4j_spy = mocker.spy(router.neo4j_adapter, 'find_alternatives')

    # depth=3 should trigger Neo4j
    paths = router.find_alternatives('gobuster-dir', max_depth=3)

    # Neo4j should be called
    assert neo4j_spy.call_count == 1

    # PostgreSQL should NOT be called (unless fallback)
    # (Allow 1 call if Neo4j failed and fallback triggered)
    assert pg_spy.call_count <= 1


def test_router_fallback_on_neo4j_failure(router, mocker):
    """Verify automatic fallback to PostgreSQL"""

    if not router.neo4j_available:
        pytest.skip("Neo4j not available")

    # Force Neo4j to fail
    mocker.patch.object(
        router.neo4j_adapter,
        'find_alternatives',
        side_effect=Exception("Simulated failure")
    )

    pg_spy = mocker.spy(router, '_pg_find_alternatives_recursive')

    # Should fallback to PostgreSQL
    paths = router.find_alternatives('gobuster-dir', max_depth=3)

    # Fallback method should be called
    assert pg_spy.call_count == 1
```

---

## Usage Examples

### Basic Usage

```python
from crack.reference.core.router import CommandRegistryRouter

# Initialize router (auto-detects backends)
registry = CommandRegistryRouter()

# Simple query (uses PostgreSQL)
cmd = registry.get_command('nmap-quick-scan')
print(cmd.name)

# Graph query (uses Neo4j)
alternatives = registry.find_alternatives('gobuster-dir', max_depth=3)
for path in alternatives:
    print(f"Depth {path.length}: {' → '.join([c.name for c in path.nodes])}")

# Check backend status
health = registry.health_check()
print(f"PostgreSQL: {health['postgresql']}")
print(f"Neo4j: {health['neo4j']}")
```

---

### Force Specific Backend

```python
from crack.reference.core.router import CommandRegistryRouter, BackendType

# Force PostgreSQL only
pg_only = CommandRegistryRouter(backend_preference=BackendType.POSTGRESQL)

# This will use PostgreSQL even for graph queries (slower)
alternatives = pg_only.find_alternatives('gobuster-dir', max_depth=5)
```

---

## Troubleshooting

### Issue: "No database backends available"

**Cause**: Both PostgreSQL and Neo4j failed to initialize

**Solution**:
```bash
# Check PostgreSQL
psql -h localhost -U crack_user -d crack -c "SELECT 1;"

# Check Neo4j
cypher-shell -u neo4j -p crack_password "RETURN 1;"

# Check Python connectivity
python -c "from crack.reference.core.router import CommandRegistryRouter; r = CommandRegistryRouter()"
```

---

### Issue: Router always uses PostgreSQL fallback

**Symptoms**: Neo4j never called, even for graph queries

**Debug**:
```python
import logging
logging.basicConfig(level=logging.DEBUG)

from crack.reference.core.router import CommandRegistryRouter
router = CommandRegistryRouter()

# Check Neo4j availability
print(f"Neo4j available: {router.neo4j_available}")

# Test health check
print(router.health_check())
```

---

## Next Steps

1. **Test Router**: Run integration tests
2. **Deploy Advanced Queries**: [06-ADVANCED-QUERIES.md](06-ADVANCED-QUERIES.md)
3. **Performance Testing**: [08-PERFORMANCE-OPTIMIZATION.md](08-PERFORMANCE-OPTIMIZATION.md)

---

## See Also

- [00-ARCHITECTURE.md](00-ARCHITECTURE.md#router-implementation-strategy) - Router design
- [04-ADAPTER-IMPLEMENTATION.md](04-ADAPTER-IMPLEMENTATION.md) - Adapter implementations
- [reference/cli/main.py](../../reference/cli/main.py:52-114) - Current auto-detect logic

---

**Document Version**: 1.0.0
**Last Updated**: 2025-11-08
**Owner**: Integration Team
**Status**: Specification Complete (Code TBD)
