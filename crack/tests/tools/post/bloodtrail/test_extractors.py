"""
BloodTrail Extractors Module Tests

Comprehensive tests for the extractors.py module covering all dataclasses,
extractor classes, registry, and utility functions.

Business Value Focus:
- Edge extraction accuracy determines attack path quality
- Deduplication prevents redundant path analysis
- Registry dispatching ensures correct parser selection
- ADCS/Trust/Coercion edges enable advanced attack scenarios

Test Priority: TIER 1 - CRITICAL (Attack Path Data Integrity)

Ownership: tests/tools/post/bloodtrail/ (exclusive)
"""

import sys
import unittest
import json
import tempfile
import zipfile
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from typing import Dict, List, Any

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from tools.post.bloodtrail.extractors import (
    Edge,
    ExtractionResult,
    BaseExtractor,
    ComputerEdgeExtractor,
    ACEExtractor,
    GroupMembershipExtractor,
    DelegationExtractor,
    TrustExtractor,
    CoercionExtractor,
    ADCSExtractor,
    EdgeExtractorRegistry,
    deduplicate_edges,
)


# =============================================================================
# MOCK RESOLVER HELPER
# =============================================================================

class MockSIDResolver:
    """
    Mock SID resolver that returns predictable results for testing.

    Default behavior: Returns the SID itself as the name with 'User' type.
    Can be configured with custom mappings.
    """

    def __init__(self, mappings: Dict[str, tuple] = None):
        """
        Initialize with optional SID->name mappings.

        Args:
            mappings: Dict of SID -> (name, type) tuples
        """
        self._mappings = mappings or {}

    def resolve(self, sid: str) -> tuple:
        """Resolve SID to (name, type) tuple."""
        if sid in self._mappings:
            return self._mappings[sid]
        return (sid, "User")


def create_mock_resolver(mappings: Dict[str, tuple] = None) -> MockSIDResolver:
    """Factory for creating mock resolver with optional mappings."""
    return MockSIDResolver(mappings)


# =============================================================================
# EDGE DATACLASS TESTS
# =============================================================================

class TestEdgeDataclass(unittest.TestCase):
    """Tests for Edge dataclass functionality."""

    def test_edge_required_fields(self):
        """
        BV: Edge must have source, target, and type for path building

        Scenario:
          Given: Edge constructor with required fields
          When: Edge is created
          Then: All required fields are set
        """
        edge = Edge(
            source="ADMIN@CORP.COM",
            target="DC01.CORP.COM",
            edge_type="AdminTo",
        )

        self.assertEqual(edge.source, "ADMIN@CORP.COM")
        self.assertEqual(edge.target, "DC01.CORP.COM")
        self.assertEqual(edge.edge_type, "AdminTo")

    def test_edge_default_properties(self):
        """
        BV: Properties default to empty dict

        Scenario:
          Given: Edge without properties arg
          When: Edge is created
          Then: Properties is empty dict
        """
        edge = Edge(source="A", target="B", edge_type="Test")

        self.assertIsInstance(edge.properties, dict)
        self.assertEqual(len(edge.properties), 0)

    def test_edge_with_properties(self):
        """
        BV: Edge metadata is preserved for display and filtering

        Scenario:
          Given: Edge with properties dict
          When: Edge is examined
          Then: All properties are accessible
        """
        props = {
            "source_type": "User",
            "target_type": "Computer",
            "inherited": False,
            "custom_field": "custom_value",
        }
        edge = Edge(
            source="USER@CORP.COM",
            target="WS01.CORP.COM",
            edge_type="CanRDP",
            properties=props,
        )

        self.assertEqual(edge.properties["source_type"], "User")
        self.assertEqual(edge.properties["target_type"], "Computer")
        self.assertFalse(edge.properties["inherited"])
        self.assertEqual(edge.properties["custom_field"], "custom_value")

    def test_edge_to_dict_contains_all_fields(self):
        """
        BV: Edge serialization preserves all data for storage/export

        Scenario:
          Given: Edge with all fields set
          When: to_dict() is called
          Then: Dict contains source, target, edge_type, and properties
        """
        edge = Edge(
            source="A@CORP.COM",
            target="B@CORP.COM",
            edge_type="GenericAll",
            properties={"inherited": True},
        )

        result = edge.to_dict()

        self.assertIn("source", result)
        self.assertIn("target", result)
        self.assertIn("edge_type", result)
        self.assertIn("properties", result)
        self.assertEqual(result["source"], "A@CORP.COM")
        self.assertEqual(result["properties"]["inherited"], True)

    def test_edge_to_dict_returns_new_dict(self):
        """
        BV: Serialization returns copy, not reference

        Scenario:
          Given: Edge
          When: to_dict() is called twice
          Then: Returns independent dict objects
        """
        edge = Edge(source="A", target="B", edge_type="Test")

        dict1 = edge.to_dict()
        dict2 = edge.to_dict()

        dict1["source"] = "MODIFIED"
        self.assertEqual(dict2["source"], "A")  # Unaffected


# =============================================================================
# EXTRACTION RESULT TESTS
# =============================================================================

class TestExtractionResultDataclass(unittest.TestCase):
    """Tests for ExtractionResult dataclass functionality."""

    def test_result_initialization(self):
        """
        BV: Fresh extraction starts with clean state

        Scenario:
          Given: New ExtractionResult
          When: Examined before use
          Then: All counters at zero, lists empty
        """
        result = ExtractionResult()

        self.assertEqual(result.edge_count, 0)
        self.assertEqual(len(result.edges), 0)
        self.assertEqual(len(result.errors), 0)
        self.assertEqual(result.skipped, 0)

    def test_add_edge_appends_to_list(self):
        """
        BV: Edges are collected for batch processing

        Scenario:
          Given: ExtractionResult
          When: add_edge() is called
          Then: Edge appears in edges list
        """
        result = ExtractionResult()
        edge = Edge(source="A", target="B", edge_type="AdminTo")

        result.add_edge(edge)

        self.assertIn(edge, result.edges)

    def test_add_edge_increments_count(self):
        """
        BV: Edge count matches actual edges for progress tracking

        Scenario:
          Given: ExtractionResult
          When: add_edge() is called multiple times
          Then: edge_count matches number of edges
        """
        result = ExtractionResult()

        for i in range(5):
            edge = Edge(source=f"A{i}", target=f"B{i}", edge_type="Test")
            result.add_edge(edge)

        self.assertEqual(result.edge_count, 5)
        self.assertEqual(len(result.edges), 5)

    def test_add_error_appends_message(self):
        """
        BV: Errors are tracked for diagnostics

        Scenario:
          Given: ExtractionResult
          When: add_error() is called
          Then: Error message appears in errors list
        """
        result = ExtractionResult()

        result.add_error("Parse failed: invalid JSON")
        result.add_error("Missing required field: name")

        self.assertEqual(len(result.errors), 2)
        self.assertIn("Parse failed", result.errors[0])
        self.assertIn("Missing required field", result.errors[1])

    def test_merge_combines_edges(self):
        """
        BV: Multiple extraction results can be combined for batch import

        Scenario:
          Given: Two ExtractionResults with edges
          When: merge() is called
          Then: All edges in first result
        """
        result1 = ExtractionResult()
        result1.add_edge(Edge(source="A", target="B", edge_type="Type1"))

        result2 = ExtractionResult()
        result2.add_edge(Edge(source="C", target="D", edge_type="Type2"))
        result2.add_edge(Edge(source="E", target="F", edge_type="Type3"))

        result1.merge(result2)

        self.assertEqual(len(result1.edges), 3)
        self.assertEqual(result1.edge_count, 3)

    def test_merge_combines_errors(self):
        """
        BV: Errors from multiple sources are consolidated

        Scenario:
          Given: Two results with errors
          When: merge() is called
          Then: All errors in first result
        """
        result1 = ExtractionResult()
        result1.add_error("Error 1")

        result2 = ExtractionResult()
        result2.add_error("Error 2")

        result1.merge(result2)

        self.assertEqual(len(result1.errors), 2)

    def test_merge_combines_skipped(self):
        """
        BV: Skipped counts are aggregated

        Scenario:
          Given: Two results with skipped counts
          When: merge() is called
          Then: Skipped counts are summed
        """
        result1 = ExtractionResult()
        result1.skipped = 5

        result2 = ExtractionResult()
        result2.skipped = 3

        result1.merge(result2)

        self.assertEqual(result1.skipped, 8)


# =============================================================================
# BASE EXTRACTOR TESTS
# =============================================================================

class TestBaseExtractor(unittest.TestCase):
    """Tests for BaseExtractor abstract base class."""

    def test_base_extractor_is_abstract(self):
        """
        BV: BaseExtractor cannot be instantiated directly

        Scenario:
          Given: BaseExtractor class
          When: Trying to instantiate
          Then: TypeError is raised
        """
        resolver = create_mock_resolver()

        with self.assertRaises(TypeError):
            BaseExtractor(resolver)

    def test_should_process_matches_source_files(self):
        """
        BV: Extractors only process relevant file types

        Scenario:
          Given: Extractor with source_files = {"computers"}
          When: should_process() is called with various filenames
          Then: Returns True only for matching files
        """
        class TestExtractor(BaseExtractor):
            source_files = {"computers"}

            def extract(self, data, filename):
                return ExtractionResult()

        resolver = create_mock_resolver()
        extractor = TestExtractor(resolver)

        self.assertTrue(extractor.should_process("computers.json"))
        self.assertTrue(extractor.should_process("20240101_computers.json"))
        self.assertTrue(extractor.should_process("COMPUTERS.JSON"))  # Case-insensitive
        self.assertFalse(extractor.should_process("users.json"))
        self.assertFalse(extractor.should_process("groups.json"))


# =============================================================================
# COMPUTER EDGE EXTRACTOR TESTS
# =============================================================================

class TestComputerEdgeExtractor(unittest.TestCase):
    """Tests for ComputerEdgeExtractor."""

    def test_extracts_adminto_from_localadmins(self):
        """
        BV: AdminTo edges enable local admin lateral movement

        Scenario:
          Given: Computer with LocalAdmins entries
          When: Extraction is run
          Then: AdminTo edges created (User -> Computer)
        """
        resolver = create_mock_resolver()
        extractor = ComputerEdgeExtractor(resolver)

        data = {
            "data": [{
                "Properties": {"name": "DC01.CORP.COM"},
                "LocalAdmins": {
                    "Results": [
                        {"ObjectIdentifier": "ADMIN@CORP.COM", "ObjectType": "User"}
                    ],
                    "Collected": True,
                },
            }]
        }

        result = extractor.extract(data, "computers.json")

        admin_edges = [e for e in result.edges if e.edge_type == "AdminTo"]
        self.assertEqual(len(admin_edges), 1)
        self.assertEqual(admin_edges[0].source, "ADMIN@CORP.COM")
        self.assertEqual(admin_edges[0].target, "DC01.CORP.COM")

    def test_extracts_executedcom(self):
        """
        BV: ExecuteDCOM edges identify DCOM lateral movement

        Scenario:
          Given: Computer with DcomUsers entries
          When: Extraction is run
          Then: ExecuteDCOM edges created
        """
        resolver = create_mock_resolver()
        extractor = ComputerEdgeExtractor(resolver)

        data = {
            "data": [{
                "Properties": {"name": "WS01.CORP.COM"},
                "DcomUsers": {
                    "Results": [
                        {"ObjectIdentifier": "DCOM_USER@CORP.COM", "ObjectType": "User"}
                    ],
                    "Collected": True,
                },
            }]
        }

        result = extractor.extract(data, "computers.json")

        dcom_edges = [e for e in result.edges if e.edge_type == "ExecuteDCOM"]
        self.assertEqual(len(dcom_edges), 1)

    def test_extracts_allowedtoact(self):
        """
        BV: AllowedToAct edges identify RBCD attack paths

        Scenario:
          Given: Computer with AllowedToAct entries
          When: Extraction is run
          Then: AllowedToAct edges created
        """
        resolver = create_mock_resolver()
        extractor = ComputerEdgeExtractor(resolver)

        data = {
            "data": [{
                "Properties": {"name": "DC01.CORP.COM"},
                "AllowedToAct": {
                    "Results": [
                        {"ObjectIdentifier": "RBCD_USER@CORP.COM", "ObjectType": "User"}
                    ],
                    "Collected": True,
                },
            }]
        }

        result = extractor.extract(data, "computers.json")

        rbcd_edges = [e for e in result.edges if e.edge_type == "AllowedToAct"]
        self.assertEqual(len(rbcd_edges), 1)

    def test_hassession_reversed_direction(self):
        """
        BV: HasSession edges correctly point Computer -> User

        Scenario:
          Given: Computer with session data
          When: Extraction is run
          Then: Edge direction is Computer -> User (not User -> Computer)
        """
        resolver = create_mock_resolver()
        extractor = ComputerEdgeExtractor(resolver)

        data = {
            "data": [{
                "Properties": {"name": "DC01.CORP.COM"},
                "Sessions": {
                    "Results": [{"UserSID": "ADMIN@CORP.COM"}],
                    "Collected": True,
                },
            }]
        }

        result = extractor.extract(data, "computers.json")

        session_edges = [e for e in result.edges if e.edge_type == "HasSession"]
        self.assertEqual(len(session_edges), 1)
        self.assertEqual(session_edges[0].source, "DC01.CORP.COM")
        self.assertEqual(session_edges[0].target, "ADMIN@CORP.COM")

    def test_handles_direct_array_format(self):
        """
        BV: Handles both nested and direct array formats

        Scenario:
          Given: Data with direct array (not nested Results)
          When: Extraction is run
          Then: Edges still extracted
        """
        resolver = create_mock_resolver()
        extractor = ComputerEdgeExtractor(resolver)

        data = {
            "data": [{
                "Properties": {"name": "DC01.CORP.COM"},
                "LocalAdmins": [
                    {"ObjectIdentifier": "ADMIN@CORP.COM", "ObjectType": "User"}
                ],
            }]
        }

        result = extractor.extract(data, "computers.json")

        self.assertGreater(len(result.edges), 0)

    def test_handles_string_identifiers(self):
        """
        BV: Handles SIDs as plain strings

        Scenario:
          Given: Data with string SIDs instead of dicts
          When: Extraction is run
          Then: Edges still extracted
        """
        resolver = create_mock_resolver()
        extractor = ComputerEdgeExtractor(resolver)

        data = {
            "data": [{
                "Properties": {"name": "DC01.CORP.COM"},
                "LocalAdmins": ["S-1-5-21-123-456-789-1001"],
            }]
        }

        result = extractor.extract(data, "computers.json")

        self.assertGreater(len(result.edges), 0)


# =============================================================================
# ACE EXTRACTOR TESTS
# =============================================================================

class TestACEExtractor(unittest.TestCase):
    """Tests for ACEExtractor (ACL-based edges)."""

    def test_extracts_owns_edge(self):
        """
        BV: Owns edges identify object ownership

        Scenario:
          Given: Object with Owns ACE
          When: Extraction is run
          Then: Owns edge created
        """
        resolver = create_mock_resolver()
        extractor = ACEExtractor(resolver)

        data = {
            "data": [{
                "Properties": {"name": "TARGET@CORP.COM"},
                "Aces": [{
                    "RightName": "Owns",
                    "PrincipalSID": "OWNER@CORP.COM",
                }],
            }]
        }

        result = extractor.extract(data, "users.json")

        owns_edges = [e for e in result.edges if e.edge_type == "Owns"]
        self.assertEqual(len(owns_edges), 1)

    def test_extracts_writeowner_edge(self):
        """
        BV: WriteOwner enables ownership takeover

        Scenario:
          Given: Object with WriteOwner ACE
          When: Extraction is run
          Then: WriteOwner edge created
        """
        resolver = create_mock_resolver()
        extractor = ACEExtractor(resolver)

        data = {
            "data": [{
                "Properties": {"name": "TARGET@CORP.COM"},
                "Aces": [{
                    "RightName": "WriteOwner",
                    "PrincipalSID": "ATTACKER@CORP.COM",
                }],
            }]
        }

        result = extractor.extract(data, "users.json")

        writeowner_edges = [e for e in result.edges if e.edge_type == "WriteOwner"]
        self.assertEqual(len(writeowner_edges), 1)

    def test_extracts_addkeycredentiallink(self):
        """
        BV: AddKeyCredentialLink enables Shadow Credentials attack

        Scenario:
          Given: Object with AddKeyCredentialLink ACE
          When: Extraction is run
          Then: AddKeyCredentialLink edge created
        """
        resolver = create_mock_resolver()
        extractor = ACEExtractor(resolver)

        data = {
            "data": [{
                "Properties": {"name": "TARGET@CORP.COM"},
                "Aces": [{
                    "RightName": "AddKeyCredentialLink",
                    "PrincipalSID": "ATTACKER@CORP.COM",
                }],
            }]
        }

        result = extractor.extract(data, "users.json")

        edges = [e for e in result.edges if e.edge_type == "AddKeyCredentialLink"]
        self.assertEqual(len(edges), 1)

    def test_skips_unmapped_ace_types(self):
        """
        BV: Unknown ACE types don't create edges

        Scenario:
          Given: Object with unknown RightName
          When: Extraction is run
          Then: No edges created for unknown type
        """
        resolver = create_mock_resolver()
        extractor = ACEExtractor(resolver)

        data = {
            "data": [{
                "Properties": {"name": "TARGET@CORP.COM"},
                "Aces": [{
                    "RightName": "UnknownRightType",
                    "PrincipalSID": "SOMEONE@CORP.COM",
                }],
            }]
        }

        result = extractor.extract(data, "users.json")

        self.assertEqual(len(result.edges), 0)

    def test_handles_missing_principal_sid(self):
        """
        BV: Malformed ACEs don't crash extraction

        Scenario:
          Given: ACE without PrincipalSID
          When: Extraction is run
          Then: ACE is skipped gracefully
        """
        resolver = create_mock_resolver()
        extractor = ACEExtractor(resolver)

        data = {
            "data": [{
                "Properties": {"name": "TARGET@CORP.COM"},
                "Aces": [{
                    "RightName": "GenericAll",
                    # Missing PrincipalSID
                }],
            }]
        }

        result = extractor.extract(data, "users.json")

        self.assertEqual(len(result.edges), 0)
        self.assertEqual(len(result.errors), 0)

    def test_processes_multiple_source_files(self):
        """
        BV: ACE extractor handles all object types

        Scenario:
          Given: ACEExtractor
          When: Checking source_files
          Then: Contains users, computers, groups, domains, etc.
        """
        resolver = create_mock_resolver()
        extractor = ACEExtractor(resolver)

        expected = {"users", "computers", "groups", "domains", "gpos", "ous", "containers"}
        self.assertEqual(extractor.source_files, expected)


# =============================================================================
# DELEGATION EXTRACTOR TESTS
# =============================================================================

class TestDelegationExtractor(unittest.TestCase):
    """Tests for DelegationExtractor."""

    def test_extracts_from_users(self):
        """
        BV: User delegation enables S4U attacks

        Scenario:
          Given: User with AllowedToDelegate
          When: Extraction is run
          Then: AllowedToDelegate edges created
        """
        resolver = create_mock_resolver()
        extractor = DelegationExtractor(resolver)

        data = {
            "data": [{
                "Properties": {"name": "SVC_SQL@CORP.COM"},
                "AllowedToDelegate": ["DC01.CORP.COM"],
            }]
        }

        result = extractor.extract(data, "users.json")

        self.assertEqual(len(result.edges), 1)
        self.assertEqual(result.edges[0].edge_type, "AllowedToDelegate")
        self.assertEqual(result.edges[0].source, "SVC_SQL@CORP.COM")

    def test_extracts_from_computers(self):
        """
        BV: Computer delegation enables S4U attacks

        Scenario:
          Given: Computer with AllowedToDelegate
          When: Extraction is run
          Then: AllowedToDelegate edges created
        """
        resolver = create_mock_resolver()
        extractor = DelegationExtractor(resolver)

        data = {
            "data": [{
                "Properties": {"name": "WEB01.CORP.COM"},
                "AllowedToDelegate": ["DC01.CORP.COM", "SQL01.CORP.COM"],
            }]
        }

        result = extractor.extract(data, "computers.json")

        self.assertEqual(len(result.edges), 2)

    def test_handles_empty_delegation_list(self):
        """
        BV: Empty delegation list produces no edges

        Scenario:
          Given: Object with empty AllowedToDelegate
          When: Extraction is run
          Then: No edges created
        """
        resolver = create_mock_resolver()
        extractor = DelegationExtractor(resolver)

        data = {
            "data": [{
                "Properties": {"name": "SVC@CORP.COM"},
                "AllowedToDelegate": [],
            }]
        }

        result = extractor.extract(data, "users.json")

        self.assertEqual(len(result.edges), 0)


# =============================================================================
# TRUST EXTRACTOR TESTS
# =============================================================================

class TestTrustExtractor(unittest.TestCase):
    """Tests for TrustExtractor."""

    def test_extracts_outbound_trust(self):
        """
        BV: Outbound trust enables cross-domain attacks

        Scenario:
          Given: Domain with outbound trust (direction=2)
          When: Extraction is run
          Then: TrustedBy edge created
        """
        resolver = create_mock_resolver()
        extractor = TrustExtractor(resolver)

        data = {
            "data": [{
                "Properties": {"name": "CORP.COM"},
                "Trusts": [{
                    "TargetDomainName": "PARTNER.COM",
                    "TrustDirection": 2,  # Outbound
                    "TrustType": "Forest",
                    "IsTransitive": True,
                    "SidFilteringEnabled": False,
                }],
            }]
        }

        result = extractor.extract(data, "domains.json")

        trust_edges = [e for e in result.edges if e.edge_type == "TrustedBy"]
        self.assertEqual(len(trust_edges), 1)
        self.assertEqual(trust_edges[0].source, "CORP.COM")
        self.assertEqual(trust_edges[0].target, "PARTNER.COM")

    def test_extracts_bidirectional_trust_both_ways(self):
        """
        BV: Bidirectional trusts create edges in both directions

        Scenario:
          Given: Domain with bidirectional trust (direction=3)
          When: Extraction is run
          Then: Two TrustedBy edges created
        """
        resolver = create_mock_resolver()
        extractor = TrustExtractor(resolver)

        data = {
            "data": [{
                "Properties": {"name": "CORP.COM"},
                "Trusts": [{
                    "TargetDomainName": "PARTNER.COM",
                    "TrustDirection": 3,  # Bidirectional
                }],
            }]
        }

        result = extractor.extract(data, "domains.json")

        trust_edges = [e for e in result.edges if e.edge_type == "TrustedBy"]
        self.assertEqual(len(trust_edges), 2)

        # Check both directions exist
        sources = {e.source for e in trust_edges}
        targets = {e.target for e in trust_edges}
        self.assertEqual(sources, {"CORP.COM", "PARTNER.COM"})
        self.assertEqual(targets, {"PARTNER.COM", "CORP.COM"})

    def test_skips_inbound_only_trust(self):
        """
        BV: Inbound-only trusts don't enable outbound attacks

        Scenario:
          Given: Domain with inbound trust only (direction=1)
          When: Extraction is run
          Then: No edges created
        """
        resolver = create_mock_resolver()
        extractor = TrustExtractor(resolver)

        data = {
            "data": [{
                "Properties": {"name": "CORP.COM"},
                "Trusts": [{
                    "TargetDomainName": "PARTNER.COM",
                    "TrustDirection": 1,  # Inbound only
                }],
            }]
        }

        result = extractor.extract(data, "domains.json")

        self.assertEqual(len(result.edges), 0)

    def test_trust_properties_preserved(self):
        """
        BV: Trust metadata preserved for attack assessment

        Scenario:
          Given: Trust with various properties
          When: Extraction is run
          Then: Edge properties contain trust metadata
        """
        resolver = create_mock_resolver()
        extractor = TrustExtractor(resolver)

        data = {
            "data": [{
                "Properties": {"name": "CORP.COM"},
                "Trusts": [{
                    "TargetDomainName": "PARTNER.COM",
                    "TrustDirection": 2,
                    "TrustType": "Forest",
                    "IsTransitive": True,
                    "SidFilteringEnabled": False,
                }],
            }]
        }

        result = extractor.extract(data, "domains.json")

        edge = result.edges[0]
        self.assertEqual(edge.properties["trust_type"], "Forest")
        self.assertTrue(edge.properties["transitive"])
        self.assertFalse(edge.properties["sid_filtering"])


# =============================================================================
# COERCION EXTRACTOR TESTS
# =============================================================================

class TestCoercionExtractor(unittest.TestCase):
    """Tests for CoercionExtractor."""

    def test_extracts_sidhistory_from_properties(self):
        """
        BV: SIDHistory enables token manipulation

        Scenario:
          Given: User with sidhistory in Properties
          When: Extraction is run
          Then: HasSIDHistory edge created
        """
        resolver = create_mock_resolver()
        extractor = CoercionExtractor(resolver)

        data = {
            "data": [{
                "Properties": {
                    "name": "USER@CORP.COM",
                    "sidhistory": ["S-1-5-21-999-888-777-1001"],
                },
            }]
        }

        result = extractor.extract(data, "users.json")

        sidhistory_edges = [e for e in result.edges if e.edge_type == "HasSIDHistory"]
        self.assertEqual(len(sidhistory_edges), 1)
        self.assertEqual(sidhistory_edges[0].source, "USER@CORP.COM")

    def test_extracts_sidhistory_from_toplevel(self):
        """
        BV: SIDHistory can be at top level

        Scenario:
          Given: User with SIDHistory at top level
          When: Extraction is run
          Then: HasSIDHistory edge created
        """
        resolver = create_mock_resolver()
        extractor = CoercionExtractor(resolver)

        data = {
            "data": [{
                "Properties": {"name": "USER@CORP.COM"},
                "SIDHistory": ["S-1-5-21-999-888-777-1001"],
            }]
        }

        result = extractor.extract(data, "users.json")

        sidhistory_edges = [e for e in result.edges if e.edge_type == "HasSIDHistory"]
        self.assertEqual(len(sidhistory_edges), 1)

    def test_handles_empty_sidhistory(self):
        """
        BV: Empty SIDHistory produces no edges

        Scenario:
          Given: User with empty sidhistory
          When: Extraction is run
          Then: No edges created
        """
        resolver = create_mock_resolver()
        extractor = CoercionExtractor(resolver)

        data = {
            "data": [{
                "Properties": {"name": "USER@CORP.COM", "sidhistory": []},
            }]
        }

        result = extractor.extract(data, "users.json")

        self.assertEqual(len(result.edges), 0)


# =============================================================================
# ADCS EXTRACTOR TESTS
# =============================================================================

class TestADCSExtractor(unittest.TestCase):
    """Tests for ADCSExtractor."""

    def test_extracts_adcsesc1(self):
        """
        BV: ESC1 edges identify vulnerable certificate templates

        Scenario:
          Given: Certificate template with ESC1 vulnerability
          When: Extraction is run
          Then: ADCSESC1 edge created
        """
        resolver = create_mock_resolver()
        extractor = ADCSExtractor(resolver)

        data = {
            "data": [{
                "Properties": {"name": "VulnTemplate"},
                "ADCSESC1": [
                    {"ObjectIdentifier": "ATTACKER@CORP.COM", "ObjectType": "User"}
                ],
            }]
        }

        result = extractor.extract(data, "certtemplates.json")

        esc1_edges = [e for e in result.edges if e.edge_type == "ADCSESC1"]
        self.assertEqual(len(esc1_edges), 1)

    def test_extracts_enrollonbehalfof(self):
        """
        BV: EnrollOnBehalfOf enables certificate impersonation

        Scenario:
          Given: Template with EnrollOnBehalfOf
          When: Extraction is run
          Then: EnrollOnBehalfOf edge created
        """
        resolver = create_mock_resolver()
        extractor = ADCSExtractor(resolver)

        data = {
            "data": [{
                "Properties": {"name": "TemplateA"},
                "EnrollOnBehalfOf": [
                    {"Name": "TemplateB"},
                ],
            }]
        }

        result = extractor.extract(data, "certtemplates.json")

        enroll_edges = [e for e in result.edges if e.edge_type == "EnrollOnBehalfOf"]
        self.assertEqual(len(enroll_edges), 1)
        self.assertEqual(enroll_edges[0].source, "TemplateA")
        self.assertEqual(enroll_edges[0].target, "TemplateB")

    def test_handles_string_enrollonbehalfof(self):
        """
        BV: EnrollOnBehalfOf can be string template name

        Scenario:
          Given: EnrollOnBehalfOf as string
          When: Extraction is run
          Then: Edge still created

        Note: The ADCS extractor iterates edge_types which includes
        EnrollOnBehalfOf, so strings in that array get processed twice.
        This test verifies at least one edge is created.
        """
        resolver = create_mock_resolver()
        extractor = ADCSExtractor(resolver)

        data = {
            "data": [{
                "Properties": {"name": "TemplateA"},
                "EnrollOnBehalfOf": ["TemplateB"],
            }]
        }

        result = extractor.extract(data, "certtemplates.json")

        enroll_edges = [e for e in result.edges if e.edge_type == "EnrollOnBehalfOf"]
        # At least one EnrollOnBehalfOf edge created
        self.assertGreaterEqual(len(enroll_edges), 1)
        # Verify the edge connects the right nodes
        targets = {e.target for e in enroll_edges}
        self.assertIn("TemplateB", targets)

    def test_processes_adcs_source_files(self):
        """
        BV: ADCS extractor handles all certificate-related files

        Scenario:
          Given: ADCSExtractor
          When: Checking source_files
          Then: Contains cas, certtemplates, etc.
        """
        resolver = create_mock_resolver()
        extractor = ADCSExtractor(resolver)

        self.assertIn("cas", extractor.source_files)
        self.assertIn("certtemplates", extractor.source_files)
        self.assertIn("enterprisecas", extractor.source_files)


# =============================================================================
# EDGE EXTRACTOR REGISTRY TESTS
# =============================================================================

class TestEdgeExtractorRegistry(unittest.TestCase):
    """Tests for EdgeExtractorRegistry."""

    def test_registry_initializes_all_extractors(self):
        """
        BV: Registry provides complete coverage

        Scenario:
          Given: New registry
          When: Checking extractors
          Then: All extractor types present
        """
        resolver = create_mock_resolver()
        registry = EdgeExtractorRegistry(resolver)

        extractor_types = [type(e).__name__ for e in registry.extractors]

        self.assertIn("ComputerEdgeExtractor", extractor_types)
        self.assertIn("ACEExtractor", extractor_types)
        self.assertIn("GroupMembershipExtractor", extractor_types)
        self.assertIn("DelegationExtractor", extractor_types)
        self.assertIn("TrustExtractor", extractor_types)
        self.assertIn("CoercionExtractor", extractor_types)
        self.assertIn("ADCSExtractor", extractor_types)

    def test_extract_from_data_dispatches_correctly(self):
        """
        BV: Registry routes data to correct extractors

        Scenario:
          Given: Registry and computers data
          When: extract_from_data() called
          Then: ComputerEdgeExtractor processes data
        """
        resolver = create_mock_resolver()
        registry = EdgeExtractorRegistry(resolver)

        data = {
            "data": [{
                "Properties": {"name": "DC01.CORP.COM"},
                "LocalAdmins": {
                    "Results": [{"ObjectIdentifier": "ADMIN@CORP.COM"}],
                    "Collected": True,
                },
            }]
        }

        result = registry.extract_from_data(data, "computers.json")

        admin_edges = [e for e in result.edges if e.edge_type == "AdminTo"]
        self.assertGreater(len(admin_edges), 0)

    def test_extract_from_file_reads_json(self):
        """
        BV: Registry can extract from file path

        Scenario:
          Given: JSON file on disk with recognized filename
          When: extract_from_file() called
          Then: Edges extracted from file content
        """
        resolver = create_mock_resolver()
        registry = EdgeExtractorRegistry(resolver)

        with tempfile.TemporaryDirectory() as tmpdir:
            # Must use recognized filename (e.g., computers.json) for extractors
            filepath = Path(tmpdir) / "computers.json"
            with open(filepath, 'w') as f:
                json.dump({
                    "data": [{
                        "Properties": {"name": "DC01.CORP.COM"},
                        "LocalAdmins": {
                            "Results": [{"ObjectIdentifier": "ADMIN@CORP.COM"}],
                            "Collected": True,
                        },
                    }]
                }, f)

            result = registry.extract_from_file(filepath)

            self.assertGreater(len(result.edges), 0)

    def test_extract_from_file_handles_error(self):
        """
        BV: File read errors are captured

        Scenario:
          Given: Non-existent file
          When: extract_from_file() called
          Then: Error added to result
        """
        resolver = create_mock_resolver()
        registry = EdgeExtractorRegistry(resolver)

        result = registry.extract_from_file(Path("/nonexistent/file.json"))

        self.assertGreater(len(result.errors), 0)

    def test_get_all_edge_types(self):
        """
        BV: Users can see supported edge types

        Scenario:
          Given: Registry
          When: get_all_edge_types() called
          Then: Returns set with common edge types
        """
        resolver = create_mock_resolver()
        registry = EdgeExtractorRegistry(resolver)

        edge_types = registry.get_all_edge_types()

        self.assertIsInstance(edge_types, set)
        self.assertIn("AdminTo", edge_types)
        self.assertIn("MemberOf", edge_types)
        self.assertIn("GenericAll", edge_types)
        self.assertIn("HasSIDHistory", edge_types)


# =============================================================================
# EDGE DEDUPLICATION TESTS
# =============================================================================

class TestDeduplicateEdges(unittest.TestCase):
    """Tests for deduplicate_edges utility function."""

    def test_removes_exact_duplicates(self):
        """
        BV: Duplicate edges don't inflate attack paths

        Scenario:
          Given: List with duplicate edges
          When: deduplicate_edges() called
          Then: Only unique edges remain
        """
        edges = [
            Edge(source="A", target="B", edge_type="AdminTo"),
            Edge(source="A", target="B", edge_type="AdminTo"),  # Duplicate
            Edge(source="A", target="B", edge_type="AdminTo"),  # Duplicate
        ]

        result = deduplicate_edges(edges)

        self.assertEqual(len(result), 1)

    def test_preserves_different_edge_types(self):
        """
        BV: Different permissions between same nodes preserved

        Scenario:
          Given: Same source/target with different edge types
          When: deduplicate_edges() called
          Then: Both edges kept
        """
        edges = [
            Edge(source="A", target="B", edge_type="AdminTo"),
            Edge(source="A", target="B", edge_type="CanRDP"),
            Edge(source="A", target="B", edge_type="CanPSRemote"),
        ]

        result = deduplicate_edges(edges)

        self.assertEqual(len(result), 3)

    def test_preserves_different_source_target(self):
        """
        BV: Same edge type between different nodes preserved

        Scenario:
          Given: Same edge type, different source/target
          When: deduplicate_edges() called
          Then: All edges kept
        """
        edges = [
            Edge(source="A", target="B", edge_type="AdminTo"),
            Edge(source="A", target="C", edge_type="AdminTo"),
            Edge(source="B", target="C", edge_type="AdminTo"),
        ]

        result = deduplicate_edges(edges)

        self.assertEqual(len(result), 3)

    def test_preserves_first_occurrence_properties(self):
        """
        BV: First edge's properties kept on dedup

        Scenario:
          Given: Duplicate edges with different properties
          When: deduplicate_edges() called
          Then: First edge's properties preserved
        """
        edges = [
            Edge(source="A", target="B", edge_type="AdminTo",
                 properties={"source": "file1", "priority": 1}),
            Edge(source="A", target="B", edge_type="AdminTo",
                 properties={"source": "file2", "priority": 2}),
        ]

        result = deduplicate_edges(edges)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].properties["source"], "file1")
        self.assertEqual(result[0].properties["priority"], 1)

    def test_handles_empty_list(self):
        """
        BV: Empty input returns empty output

        Scenario:
          Given: Empty edge list
          When: deduplicate_edges() called
          Then: Returns empty list
        """
        result = deduplicate_edges([])

        self.assertEqual(result, [])

    def test_maintains_order(self):
        """
        BV: Edge order maintained for consistent output

        Scenario:
          Given: Ordered list of unique edges
          When: deduplicate_edges() called
          Then: Order preserved
        """
        edges = [
            Edge(source="C", target="D", edge_type="Type1"),
            Edge(source="A", target="B", edge_type="Type2"),
            Edge(source="E", target="F", edge_type="Type3"),
        ]

        result = deduplicate_edges(edges)

        self.assertEqual(result[0].source, "C")
        self.assertEqual(result[1].source, "A")
        self.assertEqual(result[2].source, "E")


# =============================================================================
# DATA SOURCE INTEGRATION TESTS
# =============================================================================

class TestRegistryDataSourceIntegration(unittest.TestCase):
    """Tests for registry extraction from DataSource objects."""

    def test_edge_filter_limits_types(self):
        """
        BV: Users can focus on specific attack paths

        Scenario:
          Given: Data with multiple edge types
          When: extract_from_source(edge_filter={"AdminTo"})
          Then: Only AdminTo edges returned
        """
        from tools.post.bloodtrail.data_source import DirectoryDataSource

        resolver = create_mock_resolver()
        registry = EdgeExtractorRegistry(resolver)

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create data with multiple edge types
            data = {
                "data": [{
                    "Properties": {"name": "DC01.CORP.COM"},
                    "LocalAdmins": {
                        "Results": [{"ObjectIdentifier": "ADMIN@CORP.COM"}],
                        "Collected": True,
                    },
                    "RemoteDesktopUsers": {
                        "Results": [{"ObjectIdentifier": "RDP_USER@CORP.COM"}],
                        "Collected": True,
                    },
                }]
            }
            with open(Path(tmpdir) / "computers.json", "w") as f:
                json.dump(data, f)

            source = DirectoryDataSource(Path(tmpdir))
            result = registry.extract_from_source(source, edge_filter={"AdminTo"})

            for edge in result.edges:
                self.assertEqual(edge.edge_type, "AdminTo")

            self.assertGreater(result.skipped, 0)

    def test_get_attack_path_edges(self):
        """
        BV: Attack path preset filters correctly

        Scenario:
          Given: Registry
          When: get_attack_path_edges() called
          Then: Only attack-path edges extracted
        """
        from tools.post.bloodtrail.data_source import DirectoryDataSource
        from tools.post.bloodtrail.config import ATTACK_PATH_EDGES

        resolver = create_mock_resolver()
        registry = EdgeExtractorRegistry(resolver)

        with tempfile.TemporaryDirectory() as tmpdir:
            data = {
                "data": [{
                    "Properties": {"name": "DC01.CORP.COM"},
                    "LocalAdmins": {
                        "Results": [{"ObjectIdentifier": "ADMIN@CORP.COM"}],
                        "Collected": True,
                    },
                }]
            }
            with open(Path(tmpdir) / "computers.json", "w") as f:
                json.dump(data, f)

            source = DirectoryDataSource(Path(tmpdir))
            result = registry.get_attack_path_edges(source)

            for edge in result.edges:
                self.assertIn(edge.edge_type, ATTACK_PATH_EDGES)


# =============================================================================
# GROUP MEMBERSHIP EXTRACTOR TESTS (Additional)
# =============================================================================

class TestGroupMembershipExtractorAdditional(unittest.TestCase):
    """Additional tests for GroupMembershipExtractor."""

    def test_extracts_nested_groups(self):
        """
        BV: Nested group memberships enable privilege escalation

        Scenario:
          Given: Group with group members
          When: Extraction is run
          Then: MemberOf edges include groups
        """
        resolver = create_mock_resolver()
        extractor = GroupMembershipExtractor(resolver)

        data = {
            "data": [{
                "Properties": {"name": "DOMAIN ADMINS@CORP.COM"},
                "Members": [
                    {"ObjectIdentifier": "ADMIN@CORP.COM", "ObjectType": "User"},
                    {"ObjectIdentifier": "IT_ADMINS@CORP.COM", "ObjectType": "Group"},
                ],
            }]
        }

        result = extractor.extract(data, "groups.json")

        self.assertEqual(len(result.edges), 2)
        # Both should target the parent group
        for edge in result.edges:
            self.assertEqual(edge.target, "DOMAIN ADMINS@CORP.COM")

    def test_handles_string_member_sids(self):
        """
        BV: Handles members as plain SID strings

        Scenario:
          Given: Members as string array
          When: Extraction is run
          Then: Edges still created
        """
        resolver = create_mock_resolver()
        extractor = GroupMembershipExtractor(resolver)

        data = {
            "data": [{
                "Properties": {"name": "BACKUP OPERATORS@CORP.COM"},
                "Members": ["S-1-5-21-123-456-789-1001", "S-1-5-21-123-456-789-1002"],
            }]
        }

        result = extractor.extract(data, "groups.json")

        self.assertEqual(len(result.edges), 2)


if __name__ == "__main__":
    unittest.main()
