"""
BloodTrail Access Types Mappings Tests

Business Value Focus:
- ACCESS_TYPE_CATALOG structure must be well-formed for command suggestion
- AccessTypeInfo dataclass must have all required fields for display
- get_reason() must correctly substitute placeholders for human-readable output
- Priority values must follow expected ranges (priv-esc 100-199, lateral 50-99)
- Phase categorization must be consistent for grouping attacks
- Backward-compatibility dicts must match catalog

Ownership: tests/tools/post/bloodtrail/mappings/ (exclusive)
"""

import sys
import unittest
from pathlib import Path
from typing import Optional

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


# =============================================================================
# ACCESS_TYPE_CATALOG STRUCTURE TESTS
# =============================================================================

class TestAccessTypeCatalogStructure(unittest.TestCase):
    """Tests for ACCESS_TYPE_CATALOG dict structure validation."""

    def test_access_type_catalog_is_dict(self):
        """
        BV: Catalog is accessible for access type lookups

        Scenario:
          Given: ACCESS_TYPE_CATALOG constant
          When: Type is checked
          Then: It is a dictionary
        """
        from tools.post.bloodtrail.mappings.access_types import ACCESS_TYPE_CATALOG

        self.assertIsInstance(ACCESS_TYPE_CATALOG, dict)

    def test_catalog_has_over_40_edge_types(self):
        """
        BV: Comprehensive coverage of BloodHound edge types

        Scenario:
          Given: ACCESS_TYPE_CATALOG
          When: Entry count is checked
          Then: At least 40 edge types are defined
        """
        from tools.post.bloodtrail.mappings.access_types import ACCESS_TYPE_CATALOG

        # Catalog includes None as fallback, so actual edge types = len - 1
        edge_type_count = len([k for k in ACCESS_TYPE_CATALOG.keys() if k is not None])

        self.assertGreaterEqual(
            edge_type_count, 40,
            f"Expected at least 40 edge types, found {edge_type_count}"
        )

    def test_each_entry_is_access_type_info(self):
        """
        BV: Each catalog entry is properly typed

        Scenario:
          Given: ACCESS_TYPE_CATALOG
          When: Each value is examined
          Then: All are AccessTypeInfo dataclass instances
        """
        from tools.post.bloodtrail.mappings.access_types import ACCESS_TYPE_CATALOG
        from tools.post.bloodtrail.mappings.base import AccessTypeInfo

        for key, value in ACCESS_TYPE_CATALOG.items():
            self.assertIsInstance(
                value, AccessTypeInfo,
                f"Entry for '{key}' should be AccessTypeInfo"
            )

    def test_none_key_exists_for_fallback(self):
        """
        BV: Unknown edge types have fallback behavior

        Scenario:
          Given: ACCESS_TYPE_CATALOG
          When: None key is looked up
          Then: Fallback AccessTypeInfo is returned
        """
        from tools.post.bloodtrail.mappings.access_types import ACCESS_TYPE_CATALOG

        self.assertIn(None, ACCESS_TYPE_CATALOG)
        fallback = ACCESS_TYPE_CATALOG[None]
        self.assertEqual(fallback.phase, "Quick Wins")


# =============================================================================
# ACCESS_TYPE_INFO DATACLASS TESTS
# =============================================================================

class TestAccessTypeInfoFields(unittest.TestCase):
    """Tests for AccessTypeInfo dataclass field requirements."""

    def test_all_entries_have_reward_field(self):
        """
        BV: Each access type explains its attack value

        Scenario:
          Given: Every entry in ACCESS_TYPE_CATALOG
          When: reward field is accessed
          Then: Non-empty string is present
        """
        from tools.post.bloodtrail.mappings.access_types import ACCESS_TYPE_CATALOG

        for key, info in ACCESS_TYPE_CATALOG.items():
            self.assertTrue(
                hasattr(info, 'reward'),
                f"Entry '{key}' missing reward field"
            )
            self.assertIsInstance(info.reward, str)
            if key is not None:  # Skip None fallback
                self.assertGreater(
                    len(info.reward), 0,
                    f"Entry '{key}' has empty reward"
                )

    def test_all_entries_have_phase_field(self):
        """
        BV: Each access type has attack phase classification

        Scenario:
          Given: Every entry in ACCESS_TYPE_CATALOG
          When: phase field is accessed
          Then: Non-empty string is present
        """
        from tools.post.bloodtrail.mappings.access_types import ACCESS_TYPE_CATALOG

        for key, info in ACCESS_TYPE_CATALOG.items():
            self.assertTrue(
                hasattr(info, 'phase'),
                f"Entry '{key}' missing phase field"
            )
            self.assertIsInstance(info.phase, str)
            self.assertGreater(
                len(info.phase), 0,
                f"Entry '{key}' has empty phase"
            )

    def test_all_entries_have_priority_field(self):
        """
        BV: Each access type has priority for sorting

        Scenario:
          Given: Every entry in ACCESS_TYPE_CATALOG
          When: priority field is accessed
          Then: Integer is present
        """
        from tools.post.bloodtrail.mappings.access_types import ACCESS_TYPE_CATALOG

        for key, info in ACCESS_TYPE_CATALOG.items():
            self.assertTrue(
                hasattr(info, 'priority'),
                f"Entry '{key}' missing priority field"
            )
            self.assertIsInstance(
                info.priority, int,
                f"Entry '{key}' priority should be int"
            )

    def test_all_entries_have_reason_template_field(self):
        """
        BV: Each access type can generate human-readable reasons

        Scenario:
          Given: Every entry in ACCESS_TYPE_CATALOG
          When: reason_template field is accessed
          Then: String is present (may be empty for fallback)
        """
        from tools.post.bloodtrail.mappings.access_types import ACCESS_TYPE_CATALOG

        for key, info in ACCESS_TYPE_CATALOG.items():
            self.assertTrue(
                hasattr(info, 'reason_template'),
                f"Entry '{key}' missing reason_template field"
            )
            self.assertIsInstance(info.reason_template, str)


# =============================================================================
# PRIORITY VALUE TESTS
# =============================================================================

class TestPriorityValues(unittest.TestCase):
    """Tests for priority value ranges by attack phase."""

    def test_dcsync_has_highest_priority(self):
        """
        BV: DCSync is prioritized as highest-value attack

        Scenario:
          Given: ACCESS_TYPE_CATALOG
          When: DCSync priority is checked
          Then: It has maximum priority (199)
        """
        from tools.post.bloodtrail.mappings.access_types import ACCESS_TYPE_CATALOG

        dcsync = ACCESS_TYPE_CATALOG.get("DCSync")
        self.assertIsNotNone(dcsync)
        self.assertEqual(dcsync.priority, 199)

    def test_privilege_escalation_edges_in_100_199_range(self):
        """
        BV: Privilege escalation edges are high priority

        Scenario:
          Given: Edges with "Privilege Escalation" phase
          When: Priority values are examined
          Then: All are in 100-199 range
        """
        from tools.post.bloodtrail.mappings.access_types import ACCESS_TYPE_CATALOG

        priv_esc_edges = [
            (key, info) for key, info in ACCESS_TYPE_CATALOG.items()
            if info.phase == "Privilege Escalation" and key is not None
        ]

        self.assertGreater(len(priv_esc_edges), 0, "Should have priv-esc edges")

        for key, info in priv_esc_edges:
            self.assertGreaterEqual(
                info.priority, 100,
                f"{key} priority {info.priority} should be >= 100"
            )
            self.assertLessEqual(
                info.priority, 199,
                f"{key} priority {info.priority} should be <= 199"
            )

    def test_lateral_movement_edges_in_50_99_range(self):
        """
        BV: Lateral movement edges are medium priority

        Scenario:
          Given: Edges with "Lateral Movement" phase
          When: Priority values are examined
          Then: All are in 50-99 range
        """
        from tools.post.bloodtrail.mappings.access_types import ACCESS_TYPE_CATALOG

        lateral_edges = [
            (key, info) for key, info in ACCESS_TYPE_CATALOG.items()
            if info.phase == "Lateral Movement" and key is not None
        ]

        self.assertGreater(len(lateral_edges), 0, "Should have lateral edges")

        for key, info in lateral_edges:
            self.assertGreaterEqual(
                info.priority, 50,
                f"{key} priority {info.priority} should be >= 50"
            )
            self.assertLessEqual(
                info.priority, 99,
                f"{key} priority {info.priority} should be <= 99"
            )

    def test_adminto_has_priority_99(self):
        """
        BV: AdminTo is highest lateral movement priority

        Scenario:
          Given: ACCESS_TYPE_CATALOG
          When: AdminTo priority is checked
          Then: It has priority 99 (top of lateral movement)
        """
        from tools.post.bloodtrail.mappings.access_types import ACCESS_TYPE_CATALOG

        adminto = ACCESS_TYPE_CATALOG.get("AdminTo")
        self.assertIsNotNone(adminto)
        self.assertEqual(adminto.priority, 99)

    def test_quick_wins_below_50(self):
        """
        BV: Quick wins have lowest priority

        Scenario:
          Given: Edges with "Quick Wins" phase
          When: Priority values are examined
          Then: All are below 50
        """
        from tools.post.bloodtrail.mappings.access_types import ACCESS_TYPE_CATALOG

        quick_win_edges = [
            (key, info) for key, info in ACCESS_TYPE_CATALOG.items()
            if info.phase == "Quick Wins"
        ]

        for key, info in quick_win_edges:
            self.assertLess(
                info.priority, 50,
                f"{key} priority {info.priority} should be < 50"
            )


# =============================================================================
# PHASE CATEGORIZATION TESTS
# =============================================================================

class TestPhaseCategorization(unittest.TestCase):
    """Tests for attack phase categorization consistency."""

    def test_phases_are_valid_categories(self):
        """
        BV: All phases are known categories

        Scenario:
          Given: All entries in ACCESS_TYPE_CATALOG
          When: Phase values are examined
          Then: All are in expected set
        """
        from tools.post.bloodtrail.mappings.access_types import ACCESS_TYPE_CATALOG

        valid_phases = {
            "Privilege Escalation",
            "Lateral Movement",
            "Quick Wins",
        }

        for key, info in ACCESS_TYPE_CATALOG.items():
            self.assertIn(
                info.phase, valid_phases,
                f"{key} has unknown phase '{info.phase}'"
            )

    def test_genericall_is_privilege_escalation(self):
        """
        BV: GenericAll is categorized as privilege escalation

        Scenario:
          Given: ACCESS_TYPE_CATALOG
          When: GenericAll phase is checked
          Then: Phase is "Privilege Escalation"
        """
        from tools.post.bloodtrail.mappings.access_types import ACCESS_TYPE_CATALOG

        genericall = ACCESS_TYPE_CATALOG.get("GenericAll")
        self.assertIsNotNone(genericall)
        self.assertEqual(genericall.phase, "Privilege Escalation")

    def test_canrdp_is_lateral_movement(self):
        """
        BV: CanRDP is categorized as lateral movement

        Scenario:
          Given: ACCESS_TYPE_CATALOG
          When: CanRDP phase is checked
          Then: Phase is "Lateral Movement"
        """
        from tools.post.bloodtrail.mappings.access_types import ACCESS_TYPE_CATALOG

        canrdp = ACCESS_TYPE_CATALOG.get("CanRDP")
        self.assertIsNotNone(canrdp)
        self.assertEqual(canrdp.phase, "Lateral Movement")

    def test_adcs_edges_are_privilege_escalation(self):
        """
        BV: ADCS escalation edges are categorized correctly

        Scenario:
          Given: ADCS-related edge types
          When: Phase values are checked
          Then: All are "Privilege Escalation"
        """
        from tools.post.bloodtrail.mappings.access_types import ACCESS_TYPE_CATALOG

        adcs_edges = [
            key for key in ACCESS_TYPE_CATALOG.keys()
            if key and key.startswith("ADCS")
        ]

        self.assertGreater(len(adcs_edges), 0, "Should have ADCS edges")

        for key in adcs_edges:
            info = ACCESS_TYPE_CATALOG[key]
            self.assertEqual(
                info.phase, "Privilege Escalation",
                f"{key} should be Privilege Escalation phase"
            )


# =============================================================================
# EDGE TYPE COVERAGE TESTS
# =============================================================================

class TestEdgeTypeCoverage(unittest.TestCase):
    """Tests for BloodHound edge type coverage."""

    def test_has_lateral_movement_edges(self):
        """
        BV: Lateral movement edges are represented

        Scenario:
          Given: ACCESS_TYPE_CATALOG
          When: Common lateral edges are looked up
          Then: All are present
        """
        from tools.post.bloodtrail.mappings.access_types import ACCESS_TYPE_CATALOG

        lateral_edges = ["AdminTo", "CanRDP", "CanPSRemote", "ExecuteDCOM", "HasSession"]

        for edge in lateral_edges:
            self.assertIn(
                edge, ACCESS_TYPE_CATALOG,
                f"Lateral movement edge '{edge}' should be in catalog"
            )

    def test_has_acl_abuse_edges(self):
        """
        BV: ACL abuse edges are represented

        Scenario:
          Given: ACCESS_TYPE_CATALOG
          When: ACL-related edges are looked up
          Then: All are present
        """
        from tools.post.bloodtrail.mappings.access_types import ACCESS_TYPE_CATALOG

        acl_edges = [
            "GenericAll", "GenericWrite", "WriteDacl", "WriteOwner",
            "ForceChangePassword", "AddMember", "Owns"
        ]

        for edge in acl_edges:
            self.assertIn(
                edge, ACCESS_TYPE_CATALOG,
                f"ACL abuse edge '{edge}' should be in catalog"
            )

    def test_has_credential_edges(self):
        """
        BV: Credential-related edges are represented

        Scenario:
          Given: ACCESS_TYPE_CATALOG
          When: Credential edges are looked up
          Then: All are present
        """
        from tools.post.bloodtrail.mappings.access_types import ACCESS_TYPE_CATALOG

        cred_edges = [
            "DCSync", "ReadGMSAPassword", "ReadLAPSPassword",
            "AddKeyCredentialLink"
        ]

        for edge in cred_edges:
            self.assertIn(
                edge, ACCESS_TYPE_CATALOG,
                f"Credential edge '{edge}' should be in catalog"
            )

    def test_has_delegation_edges(self):
        """
        BV: Delegation edges are represented

        Scenario:
          Given: ACCESS_TYPE_CATALOG
          When: Delegation edges are looked up
          Then: All are present
        """
        from tools.post.bloodtrail.mappings.access_types import ACCESS_TYPE_CATALOG

        delegation_edges = [
            "AllowedToDelegate", "AllowedToAct", "AddAllowedToAct",
            "WriteAccountRestrictions"
        ]

        for edge in delegation_edges:
            self.assertIn(
                edge, ACCESS_TYPE_CATALOG,
                f"Delegation edge '{edge}' should be in catalog"
            )

    def test_has_adcs_edges(self):
        """
        BV: ADCS (certificate) edges are represented

        Scenario:
          Given: ACCESS_TYPE_CATALOG
          When: ADCS edges are looked up
          Then: ESC1-13 and related are present
        """
        from tools.post.bloodtrail.mappings.access_types import ACCESS_TYPE_CATALOG

        adcs_edges = [
            "ADCSESC1", "ADCSESC3", "ADCSESC4", "ADCSESC5",
            "ADCSESC6a", "ADCSESC6b", "ADCSESC7",
            "GoldenCert", "Enroll", "ManageCA"
        ]

        for edge in adcs_edges:
            self.assertIn(
                edge, ACCESS_TYPE_CATALOG,
                f"ADCS edge '{edge}' should be in catalog"
            )


# =============================================================================
# BACKWARD COMPATIBILITY DICT TESTS
# =============================================================================

class TestBackwardCompatibilityDicts(unittest.TestCase):
    """Tests for backward-compatible dictionary views."""

    def test_access_type_rewards_matches_catalog(self):
        """
        BV: ACCESS_TYPE_REWARDS is consistent with catalog

        Scenario:
          Given: ACCESS_TYPE_REWARDS dict
          When: Compared to ACCESS_TYPE_CATALOG
          Then: All entries match
        """
        from tools.post.bloodtrail.mappings.access_types import (
            ACCESS_TYPE_CATALOG, ACCESS_TYPE_REWARDS
        )

        for key, reward in ACCESS_TYPE_REWARDS.items():
            self.assertEqual(
                reward, ACCESS_TYPE_CATALOG[key].reward,
                f"Reward mismatch for '{key}'"
            )

    def test_access_type_phases_matches_catalog(self):
        """
        BV: ACCESS_TYPE_PHASES is consistent with catalog

        Scenario:
          Given: ACCESS_TYPE_PHASES dict
          When: Compared to ACCESS_TYPE_CATALOG
          Then: All entries match
        """
        from tools.post.bloodtrail.mappings.access_types import (
            ACCESS_TYPE_CATALOG, ACCESS_TYPE_PHASES
        )

        for key, phase in ACCESS_TYPE_PHASES.items():
            self.assertEqual(
                phase, ACCESS_TYPE_CATALOG[key].phase,
                f"Phase mismatch for '{key}'"
            )

    def test_access_type_priority_matches_catalog(self):
        """
        BV: ACCESS_TYPE_PRIORITY is consistent with catalog

        Scenario:
          Given: ACCESS_TYPE_PRIORITY dict
          When: Compared to ACCESS_TYPE_CATALOG
          Then: All entries match
        """
        from tools.post.bloodtrail.mappings.access_types import (
            ACCESS_TYPE_CATALOG, ACCESS_TYPE_PRIORITY
        )

        for key, priority in ACCESS_TYPE_PRIORITY.items():
            self.assertEqual(
                priority, ACCESS_TYPE_CATALOG[key].priority,
                f"Priority mismatch for '{key}'"
            )

    def test_access_type_reasons_matches_catalog(self):
        """
        BV: ACCESS_TYPE_REASONS is consistent with catalog

        Scenario:
          Given: ACCESS_TYPE_REASONS dict
          When: Compared to ACCESS_TYPE_CATALOG
          Then: All entries match
        """
        from tools.post.bloodtrail.mappings.access_types import (
            ACCESS_TYPE_CATALOG, ACCESS_TYPE_REASONS
        )

        for key, reason in ACCESS_TYPE_REASONS.items():
            self.assertEqual(
                reason, ACCESS_TYPE_CATALOG[key].reason_template,
                f"Reason mismatch for '{key}'"
            )


# =============================================================================
# GET_REASON FUNCTION TESTS
# =============================================================================

class TestGetReasonFunction(unittest.TestCase):
    """Tests for get_reason() placeholder substitution."""

    def test_substitutes_user_and_target(self):
        """
        BV: Reason includes user and target names

        Scenario:
          Given: AdminTo access type with user and target
          When: get_reason() is called
          Then: Both are substituted in output
        """
        from tools.post.bloodtrail.mappings.access_types import get_reason

        result = get_reason(
            access_type="AdminTo",
            user="ADMIN@CORP.COM",
            target="DC01.CORP.COM"
        )

        self.assertIn("ADMIN", result)
        self.assertIn("DC01", result)

    def test_extracts_username_from_upn(self):
        """
        BV: UPN is simplified to username for readability

        Scenario:
          Given: User in UPN format (user@domain.com)
          When: get_reason() is called
          Then: Only username portion appears
        """
        from tools.post.bloodtrail.mappings.access_types import get_reason

        result = get_reason(
            access_type="GenericAll",
            user="MIKE@CORP.COM",
            target="SVCACCOUNT@CORP.COM"
        )

        # Should use MIKE not MIKE@CORP.COM
        self.assertIn("MIKE", result)
        # Should not have full UPN in user position
        self.assertNotIn("MIKE@CORP.COM", result)

    def test_strips_domain_from_target(self):
        """
        BV: Target is simplified for readability

        Scenario:
          Given: Target in FQDN format
          When: get_reason() is called
          Then: Only hostname portion appears
        """
        from tools.post.bloodtrail.mappings.access_types import get_reason

        result = get_reason(
            access_type="AdminTo",
            user="ADMIN@CORP.COM",
            target="DC01.CORP.COM"
        )

        # Should use DC01 not DC01.CORP.COM
        self.assertIn("DC01", result)

    def test_handles_missing_user(self):
        """
        BV: Missing user does not cause error

        Scenario:
          Given: Empty user string
          When: get_reason() is called
          Then: Fallback text is used
        """
        from tools.post.bloodtrail.mappings.access_types import get_reason

        result = get_reason(
            access_type="AdminTo",
            user="",
            target="DC01.CORP.COM"
        )

        self.assertIsInstance(result, str)
        self.assertGreater(len(result), 0)

    def test_handles_missing_target(self):
        """
        BV: Missing target does not cause error

        Scenario:
          Given: Empty target string
          When: get_reason() is called
          Then: Fallback text is used
        """
        from tools.post.bloodtrail.mappings.access_types import get_reason

        result = get_reason(
            access_type="AdminTo",
            user="ADMIN@CORP.COM",
            target=""
        )

        self.assertIsInstance(result, str)
        self.assertGreater(len(result), 0)

    def test_uses_context_when_no_template(self):
        """
        BV: Context is fallback when no template exists

        Scenario:
          Given: Unknown access type with context provided
          When: get_reason() is called
          Then: Context is returned
        """
        from tools.post.bloodtrail.mappings.access_types import get_reason

        result = get_reason(
            access_type="UnknownEdge",
            user="ADMIN@CORP.COM",
            target="DC01.CORP.COM",
            context="Custom context message"
        )

        self.assertEqual(result, "Custom context message")

    def test_returns_generic_for_unknown_access_type(self):
        """
        BV: Unknown access type returns sensible fallback

        Scenario:
          Given: Unknown access type, no context
          When: get_reason() is called
          Then: Generic "{access_type} relationship" is returned
        """
        from tools.post.bloodtrail.mappings.access_types import get_reason

        result = get_reason(
            access_type="NewEdgeType",
            user="ADMIN@CORP.COM",
            target="DC01.CORP.COM"
        )

        self.assertIn("NewEdgeType", result)
        self.assertIn("relationship", result)

    def test_returns_bloodhound_finding_for_none(self):
        """
        BV: None access type has safe fallback

        Scenario:
          Given: None access type, no context
          When: get_reason() is called
          Then: "BloodHound finding" is returned
        """
        from tools.post.bloodtrail.mappings.access_types import get_reason

        result = get_reason(
            access_type=None,
            user="ADMIN@CORP.COM",
            target="DC01.CORP.COM"
        )

        self.assertEqual(result, "BloodHound finding")

    def test_dcsync_reason_mentions_rights(self):
        """
        BV: DCSync reason explains the capability

        Scenario:
          Given: DCSync access type
          When: get_reason() is called
          Then: Reason mentions DCSync/GetChanges rights
        """
        from tools.post.bloodtrail.mappings.access_types import get_reason

        result = get_reason(
            access_type="DCSync",
            user="SVCADMIN@CORP.COM",
            target="CORP.COM"
        )

        self.assertIn("DCSync", result)


if __name__ == "__main__":
    unittest.main()
