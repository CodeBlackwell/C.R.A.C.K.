"""
Tests for SID Resolver

Business Value Focus:
- Resolve Security Identifiers to human-readable names
- Handle well-known SIDs across domains
- Support domain-relative RID resolution

Test Priority: TIER 2 - HIGH (AD Security)
"""

import pytest
from unittest.mock import MagicMock, patch
from tools.post.bloodtrail.sid_resolver import (
    SIDResolver,
    ResolverStats,
)
from tools.post.bloodtrail.config import WELL_KNOWN_SIDS, DOMAIN_RIDS


# =============================================================================
# ResolverStats Tests
# =============================================================================

class TestResolverStats:
    """Tests for ResolverStats dataclass"""

    def test_default_values(self):
        """
        BV: Stats start at zero

        Scenario:
          Given: New ResolverStats
          When: Checking values
          Then: All counters at 0
        """
        stats = ResolverStats()

        assert stats.total_resolved == 0
        assert stats.from_cache == 0
        assert stats.from_wellknown == 0
        assert stats.from_domain_rid == 0
        assert stats.unresolved == 0
        assert stats.unresolved_sids == []

    def test_stats_tracking(self):
        """
        BV: Stats can be incremented

        Scenario:
          Given: ResolverStats
          When: Incrementing counters
          Then: Values update
        """
        stats = ResolverStats()

        stats.total_resolved += 5
        stats.from_cache += 3
        stats.unresolved += 2
        stats.unresolved_sids.append("S-1-5-test")

        assert stats.total_resolved == 5
        assert stats.from_cache == 3
        assert stats.unresolved == 2
        assert len(stats.unresolved_sids) == 1


# =============================================================================
# SIDResolver Initialization Tests
# =============================================================================

class TestSIDResolverInit:
    """Tests for SIDResolver initialization"""

    def test_init_without_datasource(self):
        """
        BV: Initialize without BloodHound data

        Scenario:
          Given: No data source
          When: Creating SIDResolver
          Then: Has well-known SIDs loaded
        """
        resolver = SIDResolver()

        # Should have well-known SIDs
        assert len(resolver) > 0
        assert "S-1-5-32-544" in resolver  # Administrators

    def test_wellknown_sids_loaded(self):
        """
        BV: Well-known SIDs are preloaded

        Scenario:
          Given: New resolver
          When: Checking cache
          Then: Contains BUILTIN groups
        """
        resolver = SIDResolver()

        # Check specific well-known SIDs
        assert "S-1-5-32-544" in resolver  # Administrators
        assert "S-1-5-32-555" in resolver  # Remote Desktop Users
        assert "S-1-1-0" in resolver  # Everyone


# =============================================================================
# Direct Cache Resolution Tests
# =============================================================================

class TestDirectResolution:
    """Tests for direct cache resolution"""

    def test_resolve_wellknown_administrators(self):
        """
        BV: Resolve Administrators group

        Scenario:
          Given: Resolver with well-known SIDs
          When: Resolving S-1-5-32-544
          Then: Returns 'BUILTIN\\Administrators'
        """
        resolver = SIDResolver()

        name, obj_type = resolver.resolve("S-1-5-32-544")

        assert "Administrators" in name
        assert obj_type == "Group"

    def test_resolve_wellknown_everyone(self):
        """
        BV: Resolve Everyone group

        Scenario:
          Given: Resolver
          When: Resolving S-1-1-0
          Then: Returns 'Everyone'
        """
        resolver = SIDResolver()

        name, obj_type = resolver.resolve("S-1-1-0")

        assert name == "Everyone"
        assert obj_type == "Group"

    def test_resolve_wellknown_authenticated_users(self):
        """
        BV: Resolve Authenticated Users

        Scenario:
          Given: Resolver
          When: Resolving S-1-5-11
          Then: Returns 'Authenticated Users'
        """
        resolver = SIDResolver()

        name, obj_type = resolver.resolve("S-1-5-11")

        assert "Authenticated Users" in name
        assert obj_type == "Group"

    def test_resolve_updates_stats(self):
        """
        BV: Resolution updates statistics

        Scenario:
          Given: Resolver
          When: Resolving a SID
          Then: Stats updated
        """
        resolver = SIDResolver()

        resolver.resolve("S-1-5-32-544")

        assert resolver.stats.total_resolved == 1
        assert resolver.stats.from_cache == 1


# =============================================================================
# Domain RID Resolution Tests
# =============================================================================

class TestDomainRIDResolution:
    """Tests for domain-relative RID resolution"""

    def test_resolve_domain_admins_rid(self):
        """
        BV: Resolve Domain Admins via RID

        Scenario:
          Given: Resolver with domain SID tracked
          When: Resolving S-1-5-21-xxx-512
          Then: Returns 'DOMAIN ADMINS@domain'
        """
        resolver = SIDResolver()
        resolver._domain_sids["S-1-5-21-1234-5678-9012"] = "CORP.COM"

        name, obj_type = resolver.resolve("S-1-5-21-1234-5678-9012-512")

        assert "DOMAIN ADMINS" in name
        assert "CORP.COM" in name
        assert obj_type == "Group"

    def test_resolve_administrator_rid(self):
        """
        BV: Resolve Administrator via RID 500

        Scenario:
          Given: Resolver with domain SID
          When: Resolving S-1-5-21-xxx-500
          Then: Returns 'ADMINISTRATOR@domain'
        """
        resolver = SIDResolver()
        resolver._domain_sids["S-1-5-21-1234-5678-9012"] = "CORP.COM"

        name, obj_type = resolver.resolve("S-1-5-21-1234-5678-9012-500")

        assert "ADMINISTRATOR" in name
        assert "CORP.COM" in name
        assert obj_type == "User"

    def test_resolve_krbtgt_rid(self):
        """
        BV: Resolve krbtgt via RID 502

        Scenario:
          Given: Resolver with domain SID
          When: Resolving S-1-5-21-xxx-502
          Then: Returns 'KRBTGT@domain'
        """
        resolver = SIDResolver()
        resolver._domain_sids["S-1-5-21-1234-5678-9012"] = "CORP.COM"

        name, obj_type = resolver.resolve("S-1-5-21-1234-5678-9012-502")

        assert "KRBTGT" in name
        assert obj_type == "User"

    def test_resolve_enterprise_admins_rid(self):
        """
        BV: Resolve Enterprise Admins via RID 519

        Scenario:
          Given: Resolver
          When: Resolving S-1-5-21-xxx-519
          Then: Returns 'ENTERPRISE ADMINS@domain'
        """
        resolver = SIDResolver()
        resolver._domain_sids["S-1-5-21-1234-5678-9012"] = "CORP.COM"

        name, obj_type = resolver.resolve("S-1-5-21-1234-5678-9012-519")

        assert "ENTERPRISE ADMINS" in name
        assert obj_type == "Group"

    def test_resolve_unknown_domain_uses_unknown(self):
        """
        BV: Unknown domain shows UNKNOWN

        Scenario:
          Given: Resolver without domain registered
          When: Resolving domain RID
          Then: Returns 'UNKNOWN' domain
        """
        resolver = SIDResolver()

        name, obj_type = resolver.resolve("S-1-5-21-9999-8888-7777-512")

        assert "DOMAIN ADMINS" in name
        assert "UNKNOWN" in name


# =============================================================================
# Domain-Prefixed SID Resolution Tests
# =============================================================================

class TestDomainPrefixedSIDs:
    """Tests for domain-prefixed SID format"""

    def test_resolve_domain_prefixed_wellknown(self):
        """
        BV: Resolve DOMAIN.COM-S-1-5-32-544 format

        Scenario:
          Given: Domain-prefixed SID
          When: Resolving
          Then: Returns name with domain
        """
        resolver = SIDResolver()

        name, obj_type = resolver.resolve("CORP.COM-S-1-5-32-544")

        assert "Administrators" in name
        assert "CORP.COM" in name


# =============================================================================
# Unresolved SID Tests
# =============================================================================

class TestUnresolvedSIDs:
    """Tests for unresolved SID handling"""

    def test_unresolved_returns_sid(self):
        """
        BV: Unresolved SID returns itself

        Scenario:
          Given: Unknown SID
          When: Resolving
          Then: Returns the SID as name
        """
        resolver = SIDResolver()

        name, obj_type = resolver.resolve("S-1-99-999")

        assert name == "S-1-99-999"
        assert obj_type == "Unknown"

    def test_unresolved_updates_stats(self):
        """
        BV: Unresolved SIDs tracked in stats

        Scenario:
          Given: Resolver
          When: Resolving unknown SID
          Then: Stats show unresolved
        """
        resolver = SIDResolver()

        resolver.resolve("S-1-99-999")

        assert resolver.stats.unresolved == 1
        assert "S-1-99-999" in resolver.stats.unresolved_sids

    def test_unresolved_deduplicated_in_stats(self):
        """
        BV: Duplicate unresolved SIDs not repeated

        Scenario:
          Given: Resolver
          When: Resolving same unknown SID twice
          Then: Only one entry in unresolved list
        """
        resolver = SIDResolver()

        resolver.resolve("S-1-99-999")
        resolver.resolve("S-1-99-999")

        assert resolver.stats.unresolved == 2  # Count increments
        assert len(resolver.stats.unresolved_sids) == 1  # But list dedupes


# =============================================================================
# Statistics Tests
# =============================================================================

class TestGetStats:
    """Tests for get_stats method"""

    def test_get_stats_returns_dict(self):
        """
        BV: get_stats returns summary dict

        Scenario:
          Given: Resolver with resolutions
          When: Calling get_stats()
          Then: Returns dict with all metrics
        """
        resolver = SIDResolver()
        resolver.resolve("S-1-5-32-544")
        resolver.resolve("S-1-99-999")

        stats = resolver.get_stats()

        assert "total_resolved" in stats
        assert "from_cache" in stats
        assert "unresolved" in stats
        assert "cache_size" in stats
        assert stats["total_resolved"] == 2

    def test_get_stats_limits_unresolved_list(self):
        """
        BV: Unresolved list limited to 10

        Scenario:
          Given: Many unresolved SIDs
          When: Calling get_stats()
          Then: Only first 10 shown
        """
        resolver = SIDResolver()

        # Resolve 15 unknown SIDs
        for i in range(15):
            resolver.resolve(f"S-1-99-{i}")

        stats = resolver.get_stats()

        assert len(stats["unresolved_sids"]) == 10


# =============================================================================
# Container Protocol Tests
# =============================================================================

class TestContainerProtocol:
    """Tests for __len__ and __contains__"""

    def test_len_returns_cache_size(self):
        """
        BV: len() returns cache size

        Scenario:
          Given: Resolver
          When: Calling len()
          Then: Returns number of cached SIDs
        """
        resolver = SIDResolver()

        assert len(resolver) == len(WELL_KNOWN_SIDS)

    def test_contains_for_cached_sid(self):
        """
        BV: 'in' operator works for cached SIDs

        Scenario:
          Given: Resolver
          When: Checking if SID in resolver
          Then: Returns True for cached SIDs
        """
        resolver = SIDResolver()

        assert "S-1-5-32-544" in resolver
        assert "S-1-99-999" not in resolver


# =============================================================================
# Edge Cases
# =============================================================================

class TestEdgeCases:
    """Edge case handling tests"""

    def test_empty_sid(self):
        """
        BV: Handle empty SID string

        Scenario:
          Given: Empty string
          When: Resolving
          Then: Returns unresolved
        """
        resolver = SIDResolver()

        name, obj_type = resolver.resolve("")

        assert name == ""
        assert obj_type == "Unknown"

    def test_malformed_sid(self):
        """
        BV: Handle malformed SID

        Scenario:
          Given: Invalid SID format
          When: Resolving
          Then: Returns unresolved
        """
        resolver = SIDResolver()

        name, obj_type = resolver.resolve("not-a-sid")

        assert name == "not-a-sid"
        assert obj_type == "Unknown"

    def test_partial_domain_sid(self):
        """
        BV: Handle incomplete domain SID

        Scenario:
          Given: SID missing RID
          When: Resolving
          Then: Returns unresolved
        """
        resolver = SIDResolver()

        name, obj_type = resolver.resolve("S-1-5-21-1234-5678")

        assert "S-1-5-21-1234-5678" in name
        assert obj_type == "Unknown"


# =============================================================================
# Config Constants Tests
# =============================================================================

class TestConfigConstants:
    """Tests for config constants used by resolver"""

    def test_wellknown_sids_has_administrators(self):
        """
        BV: WELL_KNOWN_SIDS contains Administrators

        Scenario:
          Given: WELL_KNOWN_SIDS constant
          When: Checking contents
          Then: Contains S-1-5-32-544
        """
        assert "S-1-5-32-544" in WELL_KNOWN_SIDS
        name, obj_type = WELL_KNOWN_SIDS["S-1-5-32-544"]
        assert "Administrators" in name

    def test_domain_rids_has_admin(self):
        """
        BV: DOMAIN_RIDS contains Administrator

        Scenario:
          Given: DOMAIN_RIDS constant
          When: Checking contents
          Then: Contains RID 500
        """
        assert 500 in DOMAIN_RIDS
        name, obj_type = DOMAIN_RIDS[500]
        assert "Administrator" in name

    def test_domain_rids_has_domain_admins(self):
        """
        BV: DOMAIN_RIDS contains Domain Admins

        Scenario:
          Given: DOMAIN_RIDS constant
          When: Checking contents
          Then: Contains RID 512
        """
        assert 512 in DOMAIN_RIDS
        name, obj_type = DOMAIN_RIDS[512]
        assert "Domain Admins" in name

    def test_wellknown_sids_tuple_format(self):
        """
        BV: SID values are (name, type) tuples

        Scenario:
          Given: WELL_KNOWN_SIDS entry
          When: Checking format
          Then: Is tuple with 2 elements
        """
        for sid, value in WELL_KNOWN_SIDS.items():
            assert isinstance(value, tuple)
            assert len(value) == 2
            name, obj_type = value
            assert isinstance(name, str)
            assert isinstance(obj_type, str)
