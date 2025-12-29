"""
BloodTrail Edge Extraction Tests

Business Value Focus:
- Edge extraction must correctly identify all relationship types
- AdminTo, CanRDP, CanPSRemote edges enable lateral movement detection
- ACL abuse edges (GenericAll, WriteDacl) enable privilege escalation
- Edge deduplication prevents redundant attack path analysis

Ownership: tests/tools/post/bloodtrail/ (exclusive)
"""

import sys
import unittest
from pathlib import Path
from unittest.mock import patch, Mock, MagicMock
import json
import tempfile

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


# =============================================================================
# EDGE CLASS TESTS
# =============================================================================

class TestEdgeClass(unittest.TestCase):
    """Tests for Edge dataclass functionality."""

    def test_edge_stores_basic_properties(self):
        """
        BV: Edge data is accessible for attack path building

        Scenario:
          Given: Edge with source, target, and type
          When: Edge is examined
          Then: All properties are accessible
        """
        from tools.post.bloodtrail.extractors import Edge

        edge = Edge(
            source="ADMIN@CORP.COM",
            target="DC01.CORP.COM",
            edge_type="AdminTo",
        )

        self.assertEqual(edge.source, "ADMIN@CORP.COM")
        self.assertEqual(edge.target, "DC01.CORP.COM")
        self.assertEqual(edge.edge_type, "AdminTo")

    def test_edge_stores_properties_dict(self):
        """
        BV: Edge metadata is preserved for display

        Scenario:
          Given: Edge with properties dict
          When: Edge is examined
          Then: Properties are accessible
        """
        from tools.post.bloodtrail.extractors import Edge

        edge = Edge(
            source="ADMIN@CORP.COM",
            target="DC01.CORP.COM",
            edge_type="AdminTo",
            properties={"source_type": "User", "inherited": False},
        )

        self.assertEqual(edge.properties["source_type"], "User")
        self.assertFalse(edge.properties["inherited"])

    def test_edge_to_dict_serializes(self):
        """
        BV: Edges can be serialized for storage/export

        Scenario:
          Given: Edge object
          When: to_dict() is called
          Then: Dict representation is returned
        """
        from tools.post.bloodtrail.extractors import Edge

        edge = Edge(
            source="ADMIN@CORP.COM",
            target="DC01.CORP.COM",
            edge_type="AdminTo",
        )

        result = edge.to_dict()

        self.assertIsInstance(result, dict)
        self.assertEqual(result["source"], "ADMIN@CORP.COM")
        self.assertEqual(result["edge_type"], "AdminTo")


# =============================================================================
# EXTRACTION RESULT TESTS
# =============================================================================

class TestExtractionResult(unittest.TestCase):
    """Tests for ExtractionResult dataclass."""

    def test_result_initialized_empty(self):
        """
        BV: Fresh extraction starts with clean state

        Scenario:
          Given: New ExtractionResult
          When: Examined before extraction
          Then: All counters are zero
        """
        from tools.post.bloodtrail.extractors import ExtractionResult

        result = ExtractionResult()

        self.assertEqual(result.edge_count, 0)
        self.assertEqual(len(result.edges), 0)
        self.assertEqual(len(result.errors), 0)

    def test_add_edge_increments_count(self):
        """
        BV: Edge count matches actual edges

        Scenario:
          Given: ExtractionResult
          When: add_edge() is called
          Then: edge_count is incremented
        """
        from tools.post.bloodtrail.extractors import ExtractionResult, Edge

        result = ExtractionResult()
        edge = Edge(source="A", target="B", edge_type="AdminTo")

        result.add_edge(edge)

        self.assertEqual(result.edge_count, 1)
        self.assertEqual(len(result.edges), 1)

    def test_merge_combines_results(self):
        """
        BV: Multiple extraction results can be combined

        Scenario:
          Given: Two ExtractionResults
          When: merge() is called
          Then: Edges and counts are combined
        """
        from tools.post.bloodtrail.extractors import ExtractionResult, Edge

        result1 = ExtractionResult()
        result1.add_edge(Edge(source="A", target="B", edge_type="AdminTo"))

        result2 = ExtractionResult()
        result2.add_edge(Edge(source="C", target="D", edge_type="CanRDP"))

        result1.merge(result2)

        self.assertEqual(result1.edge_count, 2)
        self.assertEqual(len(result1.edges), 2)


# =============================================================================
# COMPUTER EDGE EXTRACTOR TESTS
# =============================================================================

class TestComputerEdgeExtractor(unittest.TestCase):
    """Tests for ComputerEdgeExtractor."""

    def _create_mock_resolver(self):
        """Create mock SID resolver that returns name as-is."""
        resolver = Mock()
        resolver.resolve.side_effect = lambda sid: (sid, "User")
        return resolver

    def test_extracts_adminto_edges(self):
        """
        BV: AdminTo edges enable lateral movement detection

        Scenario:
          Given: Computer with LocalAdmins entries
          When: Extraction is run
          Then: AdminTo edges are created
        """
        from tools.post.bloodtrail.extractors import ComputerEdgeExtractor

        resolver = self._create_mock_resolver()
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
        self.assertGreater(len(admin_edges), 0)

        # Verify edge direction: User -> Computer
        edge = admin_edges[0]
        self.assertEqual(edge.source, "ADMIN@CORP.COM")
        self.assertEqual(edge.target, "DC01.CORP.COM")

    def test_extracts_canrdp_edges(self):
        """
        BV: CanRDP edges identify RDP access for lateral movement

        Scenario:
          Given: Computer with RemoteDesktopUsers entries
          When: Extraction is run
          Then: CanRDP edges are created
        """
        from tools.post.bloodtrail.extractors import ComputerEdgeExtractor

        resolver = self._create_mock_resolver()
        extractor = ComputerEdgeExtractor(resolver)

        data = {
            "data": [{
                "Properties": {"name": "WS01.CORP.COM"},
                "RemoteDesktopUsers": {
                    "Results": [
                        {"ObjectIdentifier": "USER@CORP.COM", "ObjectType": "User"}
                    ],
                    "Collected": True,
                },
            }]
        }

        result = extractor.extract(data, "computers.json")

        rdp_edges = [e for e in result.edges if e.edge_type == "CanRDP"]
        self.assertGreater(len(rdp_edges), 0)

    def test_extracts_canpsremote_edges(self):
        """
        BV: CanPSRemote edges identify WinRM access

        Scenario:
          Given: Computer with PSRemoteUsers entries
          When: Extraction is run
          Then: CanPSRemote edges are created
        """
        from tools.post.bloodtrail.extractors import ComputerEdgeExtractor

        resolver = self._create_mock_resolver()
        extractor = ComputerEdgeExtractor(resolver)

        data = {
            "data": [{
                "Properties": {"name": "WS01.CORP.COM"},
                "PSRemoteUsers": {
                    "Results": [
                        {"ObjectIdentifier": "USER@CORP.COM", "ObjectType": "User"}
                    ],
                    "Collected": True,
                },
            }]
        }

        result = extractor.extract(data, "computers.json")

        psremote_edges = [e for e in result.edges if e.edge_type == "CanPSRemote"]
        self.assertGreater(len(psremote_edges), 0)

    def test_extracts_hassession_edges(self):
        """
        BV: HasSession edges identify credential harvesting opportunities

        Scenario:
          Given: Computer with Sessions entries
          When: Extraction is run
          Then: HasSession edges are created (Computer -> User)
        """
        from tools.post.bloodtrail.extractors import ComputerEdgeExtractor

        resolver = self._create_mock_resolver()
        extractor = ComputerEdgeExtractor(resolver)

        data = {
            "data": [{
                "Properties": {"name": "DC01.CORP.COM"},
                "Sessions": {
                    "Results": [
                        {"UserSID": "ADMIN@CORP.COM"}
                    ],
                    "Collected": True,
                },
            }]
        }

        result = extractor.extract(data, "computers.json")

        session_edges = [e for e in result.edges if e.edge_type == "HasSession"]
        self.assertGreater(len(session_edges), 0)

        # HasSession is Computer -> User (reverse of others)
        edge = session_edges[0]
        self.assertEqual(edge.source, "DC01.CORP.COM")
        self.assertEqual(edge.target, "ADMIN@CORP.COM")

    def test_skips_uncollected_data(self):
        """
        BV: Uncollected data doesn't create false edges

        Scenario:
          Given: Computer with Collected=False
          When: Extraction is run
          Then: No edges are created for that field
        """
        from tools.post.bloodtrail.extractors import ComputerEdgeExtractor

        resolver = self._create_mock_resolver()
        extractor = ComputerEdgeExtractor(resolver)

        data = {
            "data": [{
                "Properties": {"name": "DC01.CORP.COM"},
                "LocalAdmins": {
                    "Results": [
                        {"ObjectIdentifier": "ADMIN@CORP.COM", "ObjectType": "User"}
                    ],
                    "Collected": False,  # Not collected
                },
            }]
        }

        result = extractor.extract(data, "computers.json")

        # Should have no edges
        self.assertEqual(len(result.edges), 0)

    def test_handles_missing_computer_name(self):
        """
        BV: Malformed data doesn't crash extraction

        Scenario:
          Given: Computer entry without name
          When: Extraction is run
          Then: Entry is skipped, no crash
        """
        from tools.post.bloodtrail.extractors import ComputerEdgeExtractor

        resolver = self._create_mock_resolver()
        extractor = ComputerEdgeExtractor(resolver)

        data = {
            "data": [{
                "Properties": {},  # Missing name
                "LocalAdmins": {"Results": [], "Collected": True},
            }]
        }

        # Should not raise exception
        result = extractor.extract(data, "computers.json")

        self.assertEqual(len(result.edges), 0)


# =============================================================================
# ACE EXTRACTOR TESTS
# =============================================================================

class TestACEExtractor(unittest.TestCase):
    """Tests for ACEExtractor (ACL-based permissions)."""

    def _create_mock_resolver(self):
        """Create mock SID resolver."""
        resolver = Mock()
        resolver.resolve.side_effect = lambda sid: (sid, "User")
        return resolver

    def test_extracts_genericall_edges(self):
        """
        BV: GenericAll edges identify full control permissions

        Scenario:
          Given: Object with GenericAll ACE
          When: Extraction is run
          Then: GenericAll edge is created
        """
        from tools.post.bloodtrail.extractors import ACEExtractor

        resolver = self._create_mock_resolver()
        extractor = ACEExtractor(resolver)

        data = {
            "data": [{
                "Properties": {"name": "TARGET_USER@CORP.COM"},
                "Aces": [
                    {
                        "RightName": "GenericAll",
                        "PrincipalSID": "ATTACKER@CORP.COM",
                        "PrincipalType": "User",
                        "IsInherited": False,
                    }
                ],
            }]
        }

        result = extractor.extract(data, "users.json")

        genericall_edges = [e for e in result.edges if e.edge_type == "GenericAll"]
        self.assertGreater(len(genericall_edges), 0)

        edge = genericall_edges[0]
        self.assertEqual(edge.source, "ATTACKER@CORP.COM")
        self.assertEqual(edge.target, "TARGET_USER@CORP.COM")

    def test_extracts_writedacl_edges(self):
        """
        BV: WriteDacl edges identify ACL modification capability

        Scenario:
          Given: Object with WriteDacl ACE
          When: Extraction is run
          Then: WriteDacl edge is created
        """
        from tools.post.bloodtrail.extractors import ACEExtractor

        resolver = self._create_mock_resolver()
        extractor = ACEExtractor(resolver)

        data = {
            "data": [{
                "Properties": {"name": "TARGET@CORP.COM"},
                "Aces": [
                    {"RightName": "WriteDacl", "PrincipalSID": "ATTACKER@CORP.COM"},
                ],
            }]
        }

        result = extractor.extract(data, "users.json")

        writedacl_edges = [e for e in result.edges if e.edge_type == "WriteDacl"]
        self.assertGreater(len(writedacl_edges), 0)

    def test_extracts_forcechangepassword_edges(self):
        """
        BV: ForceChangePassword enables account takeover

        Scenario:
          Given: Object with ForceChangePassword ACE
          When: Extraction is run
          Then: ForceChangePassword edge is created
        """
        from tools.post.bloodtrail.extractors import ACEExtractor

        resolver = self._create_mock_resolver()
        extractor = ACEExtractor(resolver)

        data = {
            "data": [{
                "Properties": {"name": "TARGET@CORP.COM"},
                "Aces": [
                    {"RightName": "ForceChangePassword", "PrincipalSID": "HELPDESK@CORP.COM"},
                ],
            }]
        }

        result = extractor.extract(data, "users.json")

        fcp_edges = [e for e in result.edges if e.edge_type == "ForceChangePassword"]
        self.assertGreater(len(fcp_edges), 0)

    def test_extracts_dcsync_edges(self):
        """
        BV: GetChanges/GetChangesAll edges identify DCSync capability

        Scenario:
          Given: Domain object with DCSync ACEs
          When: Extraction is run
          Then: GetChanges and GetChangesAll edges are created
        """
        from tools.post.bloodtrail.extractors import ACEExtractor

        resolver = self._create_mock_resolver()
        extractor = ACEExtractor(resolver)

        data = {
            "data": [{
                "Properties": {"name": "CORP.COM"},
                "Aces": [
                    {"RightName": "GetChanges", "PrincipalSID": "ATTACKER@CORP.COM"},
                    {"RightName": "GetChangesAll", "PrincipalSID": "ATTACKER@CORP.COM"},
                ],
            }]
        }

        result = extractor.extract(data, "domains.json")

        getchanges_edges = [e for e in result.edges if "GetChanges" in e.edge_type]
        self.assertGreaterEqual(len(getchanges_edges), 2)

    def test_records_inherited_flag(self):
        """
        BV: Inherited ACEs are marked for analysis

        Scenario:
          Given: ACE with IsInherited=True
          When: Extraction is run
          Then: Edge has inherited property set
        """
        from tools.post.bloodtrail.extractors import ACEExtractor

        resolver = self._create_mock_resolver()
        extractor = ACEExtractor(resolver)

        data = {
            "data": [{
                "Properties": {"name": "TARGET@CORP.COM"},
                "Aces": [
                    {
                        "RightName": "GenericAll",
                        "PrincipalSID": "ATTACKER@CORP.COM",
                        "IsInherited": True,
                    }
                ],
            }]
        }

        result = extractor.extract(data, "users.json")

        edge = result.edges[0]
        self.assertTrue(edge.properties.get("inherited"))


# =============================================================================
# GROUP MEMBERSHIP EXTRACTOR TESTS
# =============================================================================

class TestGroupMembershipExtractor(unittest.TestCase):
    """Tests for GroupMembershipExtractor."""

    def _create_mock_resolver(self):
        """Create mock SID resolver."""
        resolver = Mock()
        resolver.resolve.side_effect = lambda sid: (sid, "User")
        return resolver

    def test_extracts_memberof_edges(self):
        """
        BV: MemberOf edges enable group-based path finding

        Scenario:
          Given: Group with Members array
          When: Extraction is run
          Then: MemberOf edges are created (Member -> Group)
        """
        from tools.post.bloodtrail.extractors import GroupMembershipExtractor

        resolver = self._create_mock_resolver()
        extractor = GroupMembershipExtractor(resolver)

        data = {
            "data": [{
                "Properties": {"name": "DOMAIN ADMINS@CORP.COM"},
                "Members": [
                    {"ObjectIdentifier": "ADMIN@CORP.COM", "ObjectType": "User"},
                    {"ObjectIdentifier": "SVCADMIN@CORP.COM", "ObjectType": "User"},
                ],
            }]
        }

        result = extractor.extract(data, "groups.json")

        memberof_edges = [e for e in result.edges if e.edge_type == "MemberOf"]
        self.assertEqual(len(memberof_edges), 2)

        # Verify edge direction: Member -> Group
        for edge in memberof_edges:
            self.assertEqual(edge.target, "DOMAIN ADMINS@CORP.COM")


# =============================================================================
# DELEGATION EXTRACTOR TESTS
# =============================================================================

class TestDelegationExtractor(unittest.TestCase):
    """Tests for DelegationExtractor."""

    def _create_mock_resolver(self):
        """Create mock SID resolver."""
        resolver = Mock()
        resolver.resolve.side_effect = lambda sid: (sid, "Computer")
        return resolver

    def test_extracts_allowedtodelegate_edges(self):
        """
        BV: AllowedToDelegate edges identify S4U attack paths

        Scenario:
          Given: User/Computer with AllowedToDelegate array
          When: Extraction is run
          Then: AllowedToDelegate edges are created
        """
        from tools.post.bloodtrail.extractors import DelegationExtractor

        resolver = self._create_mock_resolver()
        extractor = DelegationExtractor(resolver)

        data = {
            "data": [{
                "Properties": {"name": "WEBSVC@CORP.COM"},
                "AllowedToDelegate": ["DC01.CORP.COM", "FILES01.CORP.COM"],
            }]
        }

        result = extractor.extract(data, "users.json")

        delegation_edges = [e for e in result.edges if e.edge_type == "AllowedToDelegate"]
        self.assertEqual(len(delegation_edges), 2)


# =============================================================================
# EDGE EXTRACTOR REGISTRY TESTS
# =============================================================================

class TestEdgeExtractorRegistry(unittest.TestCase):
    """Tests for EdgeExtractorRegistry."""

    def _create_mock_resolver(self):
        """Create mock SID resolver."""
        resolver = Mock()
        resolver.resolve.side_effect = lambda sid: (sid, "User")
        return resolver

    def test_extracts_from_data(self):
        """
        BV: Registry dispatches to appropriate extractors

        Scenario:
          Given: JSON data with filename
          When: extract_from_data() is called
          Then: Correct extractor processes the data
        """
        from tools.post.bloodtrail.extractors import EdgeExtractorRegistry

        resolver = self._create_mock_resolver()
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

        # Should have extracted AdminTo edges
        admin_edges = [e for e in result.edges if e.edge_type == "AdminTo"]
        self.assertGreater(len(admin_edges), 0)

    def test_get_all_edge_types_returns_set(self):
        """
        BV: Users can see all supported edge types

        Scenario:
          Given: Registry with extractors
          When: get_all_edge_types() is called
          Then: Set of all edge types is returned
        """
        from tools.post.bloodtrail.extractors import EdgeExtractorRegistry

        resolver = self._create_mock_resolver()
        registry = EdgeExtractorRegistry(resolver)

        edge_types = registry.get_all_edge_types()

        self.assertIsInstance(edge_types, set)
        self.assertIn("AdminTo", edge_types)
        self.assertIn("MemberOf", edge_types)
        self.assertIn("GenericAll", edge_types)


# =============================================================================
# EDGE DEDUPLICATION TESTS
# =============================================================================

class TestEdgeDeduplication(unittest.TestCase):
    """Tests for edge deduplication functionality."""

    def test_deduplicate_removes_exact_duplicates(self):
        """
        BV: Duplicate edges don't inflate path counts

        Scenario:
          Given: List with duplicate edges
          When: deduplicate_edges() is called
          Then: Only one copy remains
        """
        from tools.post.bloodtrail.extractors import deduplicate_edges, Edge

        edges = [
            Edge(source="A", target="B", edge_type="AdminTo"),
            Edge(source="A", target="B", edge_type="AdminTo"),  # Duplicate
            Edge(source="C", target="D", edge_type="AdminTo"),
        ]

        result = deduplicate_edges(edges)

        self.assertEqual(len(result), 2)

    def test_deduplicate_keeps_different_edge_types(self):
        """
        BV: Different edge types between same nodes are preserved

        Scenario:
          Given: Same source/target with different edge types
          When: deduplicate_edges() is called
          Then: Both edges are kept
        """
        from tools.post.bloodtrail.extractors import deduplicate_edges, Edge

        edges = [
            Edge(source="A", target="B", edge_type="AdminTo"),
            Edge(source="A", target="B", edge_type="CanRDP"),
        ]

        result = deduplicate_edges(edges)

        self.assertEqual(len(result), 2)

    def test_deduplicate_preserves_first_occurrence(self):
        """
        BV: First edge (with potentially better properties) is kept

        Scenario:
          Given: Duplicate edges with different properties
          When: deduplicate_edges() is called
          Then: First occurrence is preserved
        """
        from tools.post.bloodtrail.extractors import deduplicate_edges, Edge

        edges = [
            Edge(source="A", target="B", edge_type="AdminTo", properties={"source": "file1"}),
            Edge(source="A", target="B", edge_type="AdminTo", properties={"source": "file2"}),
        ]

        result = deduplicate_edges(edges)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].properties["source"], "file1")


# =============================================================================
# DATA SOURCE INTEGRATION TESTS
# =============================================================================

class TestDataSourceIntegration(unittest.TestCase):
    """Tests for extraction from directory/ZIP data sources."""

    def _create_mock_resolver(self):
        """Create mock SID resolver."""
        resolver = Mock()
        resolver.resolve.side_effect = lambda sid: (sid, "User")
        return resolver

    def test_extracts_from_directory_source(self):
        """
        BV: Users can extract edges from BloodHound output directory

        Scenario:
          Given: Directory with BloodHound JSON files
          When: extract_from_source() is called
          Then: Edges are extracted from all files
        """
        from tools.post.bloodtrail.extractors import EdgeExtractorRegistry
        from tools.post.bloodtrail.data_source import DirectoryDataSource

        resolver = self._create_mock_resolver()
        registry = EdgeExtractorRegistry(resolver)

        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)

            # Create test files
            computers_data = {
                "data": [{
                    "Properties": {"name": "DC01.CORP.COM"},
                    "LocalAdmins": {
                        "Results": [{"ObjectIdentifier": "ADMIN@CORP.COM"}],
                        "Collected": True,
                    },
                }]
            }
            with open(tmppath / "computers.json", "w") as f:
                json.dump(computers_data, f)

            data_source = DirectoryDataSource(tmppath)
            result = registry.extract_from_source(data_source)

            self.assertGreater(len(result.edges), 0)

    def test_edge_filter_limits_types(self):
        """
        BV: Users can focus on specific edge types

        Scenario:
          Given: Data with multiple edge types
          When: extract_from_source(edge_filter={"AdminTo"}) is called
          Then: Only AdminTo edges are returned
        """
        from tools.post.bloodtrail.extractors import EdgeExtractorRegistry
        from tools.post.bloodtrail.data_source import DirectoryDataSource

        resolver = self._create_mock_resolver()
        registry = EdgeExtractorRegistry(resolver)

        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)

            # Create data with multiple edge types
            computers_data = {
                "data": [{
                    "Properties": {"name": "DC01.CORP.COM"},
                    "LocalAdmins": {
                        "Results": [{"ObjectIdentifier": "ADMIN@CORP.COM"}],
                        "Collected": True,
                    },
                    "RemoteDesktopUsers": {
                        "Results": [{"ObjectIdentifier": "USER@CORP.COM"}],
                        "Collected": True,
                    },
                }]
            }
            with open(tmppath / "computers.json", "w") as f:
                json.dump(computers_data, f)

            data_source = DirectoryDataSource(tmppath)
            result = registry.extract_from_source(data_source, edge_filter={"AdminTo"})

            # Should only have AdminTo edges
            for edge in result.edges:
                self.assertEqual(edge.edge_type, "AdminTo")


if __name__ == "__main__":
    unittest.main()
