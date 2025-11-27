"""
Edge Extractors for BloodHound Data

Extracts relationship data from BloodHound JSON exports and converts
to Neo4j edge format for import.
"""

import json
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, List, Optional, Set, Iterator
from dataclasses import dataclass, field

from .config import ACE_EDGE_MAPPINGS, ATTACK_PATH_EDGES
from .sid_resolver import SIDResolver


@dataclass
class Edge:
    """Represents a Neo4j edge to be created"""
    source: str           # Source node name
    target: str           # Target node name
    edge_type: str        # Relationship type (e.g., AdminTo, GenericAll)
    properties: Dict = field(default_factory=dict)  # Edge properties

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "target": self.target,
            "edge_type": self.edge_type,
            "properties": self.properties,
        }


@dataclass
class ExtractionResult:
    """Result of edge extraction"""
    edges: List[Edge] = field(default_factory=list)
    edge_count: int = 0
    errors: List[str] = field(default_factory=list)
    skipped: int = 0

    def add_edge(self, edge: Edge):
        self.edges.append(edge)
        self.edge_count += 1

    def add_error(self, msg: str):
        self.errors.append(msg)

    def merge(self, other: "ExtractionResult"):
        self.edges.extend(other.edges)
        self.edge_count += other.edge_count
        self.errors.extend(other.errors)
        self.skipped += other.skipped


class BaseExtractor(ABC):
    """
    Base class for BloodHound edge extractors.

    Subclasses implement extract() to process specific JSON file types
    and return edges for Neo4j import.
    """

    # Edge types this extractor produces
    edge_types: Set[str] = set()

    # JSON file types this extractor processes (e.g., "computers", "users")
    source_files: Set[str] = set()

    def __init__(self, resolver: SIDResolver):
        self.resolver = resolver

    @abstractmethod
    def extract(self, data: dict, filename: str) -> ExtractionResult:
        """
        Extract edges from BloodHound JSON data.

        Args:
            data: Parsed JSON data from BloodHound export
            filename: Source filename for error reporting

        Returns:
            ExtractionResult with extracted edges
        """
        pass

    def should_process(self, filename: str) -> bool:
        """Check if this extractor should process the given file"""
        fname_lower = filename.lower()
        return any(src in fname_lower for src in self.source_files)


class ComputerEdgeExtractor(BaseExtractor):
    """
    Extracts edges from computers.json:
    - AdminTo (LocalAdmins)
    - CanPSRemote (PSRemoteUsers)
    - CanRDP (RemoteDesktopUsers)
    - ExecuteDCOM (DcomUsers)
    - HasSession (Sessions)
    - AllowedToAct (Resource-based constrained delegation)
    """

    edge_types = {"AdminTo", "CanPSRemote", "CanRDP", "ExecuteDCOM", "HasSession", "AllowedToAct"}
    source_files = {"computers"}

    # Mapping of JSON field -> edge type
    FIELD_MAPPINGS = {
        "LocalAdmins": "AdminTo",
        "PSRemoteUsers": "CanPSRemote",
        "RemoteDesktopUsers": "CanRDP",
        "DcomUsers": "ExecuteDCOM",
        "Sessions": "HasSession",
        "AllowedToAct": "AllowedToAct",
    }

    def extract(self, data: dict, filename: str) -> ExtractionResult:
        result = ExtractionResult()

        for computer in data.get("data", []):
            target_name = computer.get("Properties", {}).get("name")
            if not target_name:
                result.add_error(f"Computer missing name in {filename}")
                continue

            # Process each relationship type
            for field_name, edge_type in self.FIELD_MAPPINGS.items():
                field_data = computer.get(field_name, {})

                # Handle both direct arrays and nested Results
                if isinstance(field_data, dict):
                    results = field_data.get("Results", [])
                    collected = field_data.get("Collected", True)
                    if not collected:
                        continue  # Skip uncollected data
                elif isinstance(field_data, list):
                    results = field_data
                else:
                    continue

                for item in results:
                    # Get source SID
                    if isinstance(item, dict):
                        source_sid = item.get("ObjectIdentifier") or item.get("UserSID")
                        obj_type = item.get("ObjectType", "Unknown")
                    elif isinstance(item, str):
                        source_sid = item
                        obj_type = "Unknown"
                    else:
                        continue

                    if not source_sid:
                        continue

                    # Resolve SID to name
                    source_name, _ = self.resolver.resolve(source_sid)

                    # Create edge (source -> target for most, reverse for HasSession)
                    if edge_type == "HasSession":
                        # HasSession: Computer -[:HasSession]-> User
                        edge = Edge(
                            source=target_name,
                            target=source_name,
                            edge_type=edge_type,
                            properties={"source_type": "Computer", "target_type": obj_type}
                        )
                    else:
                        # Others: Principal -[:EdgeType]-> Computer
                        edge = Edge(
                            source=source_name,
                            target=target_name,
                            edge_type=edge_type,
                            properties={"source_type": obj_type, "target_type": "Computer"}
                        )

                    result.add_edge(edge)

        return result


class ACEExtractor(BaseExtractor):
    """
    Extracts ACL-based edges from all object types:
    - GenericAll, GenericWrite, WriteDacl, WriteOwner, Owns
    - ForceChangePassword, AddKeyCredentialLink
    - GetChanges, GetChangesAll (DCSync rights on Domain objects)
    - And other ACE-based permissions
    """

    edge_types = set(ACE_EDGE_MAPPINGS.values())
    source_files = {"users", "computers", "groups", "domains", "gpos", "ous", "containers"}

    def extract(self, data: dict, filename: str) -> ExtractionResult:
        result = ExtractionResult()

        for obj in data.get("data", []):
            target_name = obj.get("Properties", {}).get("name")
            if not target_name:
                continue

            # Process ACEs
            for ace in obj.get("Aces", []):
                right_name = ace.get("RightName")
                principal_sid = ace.get("PrincipalSID")
                is_inherited = ace.get("IsInherited", False)
                principal_type = ace.get("PrincipalType", "Unknown")

                if not right_name or not principal_sid:
                    continue

                # Map to Neo4j edge type
                edge_type = ACE_EDGE_MAPPINGS.get(right_name)
                if not edge_type:
                    continue  # Skip unmapped ACE types

                # Resolve principal SID
                source_name, resolved_type = self.resolver.resolve(principal_sid)

                # Create edge: Principal -[:Right]-> Object
                edge = Edge(
                    source=source_name,
                    target=target_name,
                    edge_type=edge_type,
                    properties={
                        "inherited": is_inherited,
                        "source_type": principal_type or resolved_type,
                    }
                )
                result.add_edge(edge)

        return result


class GroupMembershipExtractor(BaseExtractor):
    """
    Extracts group membership edges from groups.json:
    - MemberOf: Member -> Group relationship
    """

    edge_types = {"MemberOf"}
    source_files = {"groups"}

    def extract(self, data: dict, filename: str) -> ExtractionResult:
        result = ExtractionResult()

        for group in data.get("data", []):
            group_name = group.get("Properties", {}).get("name")
            if not group_name:
                continue

            # Process Members array
            members = group.get("Members", [])
            for member in members:
                if isinstance(member, dict):
                    member_sid = member.get("ObjectIdentifier")
                    member_type = member.get("ObjectType", "Unknown")
                elif isinstance(member, str):
                    member_sid = member
                    member_type = "Unknown"
                else:
                    continue

                if not member_sid:
                    continue

                # Resolve member SID
                member_name, resolved_type = self.resolver.resolve(member_sid)

                # Create edge: Member -[:MemberOf]-> Group
                edge = Edge(
                    source=member_name,
                    target=group_name,
                    edge_type="MemberOf",
                    properties={
                        "source_type": member_type or resolved_type,
                        "target_type": "Group"
                    }
                )
                result.add_edge(edge)

        return result


class DelegationExtractor(BaseExtractor):
    """
    Extracts delegation edges from users and computers:
    - AllowedToDelegate: Constrained delegation targets
    """

    edge_types = {"AllowedToDelegate"}
    source_files = {"users", "computers"}

    def extract(self, data: dict, filename: str) -> ExtractionResult:
        result = ExtractionResult()

        for obj in data.get("data", []):
            source_name = obj.get("Properties", {}).get("name")
            if not source_name:
                continue

            # Process AllowedToDelegate array
            delegates = obj.get("AllowedToDelegate", [])
            for delegate_sid in delegates:
                if not delegate_sid:
                    continue

                # Resolve delegate SID
                target_name, target_type = self.resolver.resolve(delegate_sid)

                # Create edge: Source -[:AllowedToDelegate]-> Target
                edge = Edge(
                    source=source_name,
                    target=target_name,
                    edge_type="AllowedToDelegate",
                    properties={"target_type": target_type}
                )
                result.add_edge(edge)

        return result


class EdgeExtractorRegistry:
    """
    Registry of all edge extractors.

    Provides a unified interface for extracting edges from BloodHound data.
    """

    def __init__(self, resolver: SIDResolver):
        self.resolver = resolver
        self.extractors: List[BaseExtractor] = [
            ComputerEdgeExtractor(resolver),
            ACEExtractor(resolver),
            GroupMembershipExtractor(resolver),
            DelegationExtractor(resolver),
        ]

    def extract_from_file(self, json_path: Path) -> ExtractionResult:
        """Extract edges from a single JSON file"""
        result = ExtractionResult()

        try:
            with open(json_path) as f:
                data = json.load(f)
        except Exception as e:
            result.add_error(f"Failed to load {json_path}: {e}")
            return result

        filename = json_path.name

        for extractor in self.extractors:
            if extractor.should_process(filename):
                extractor_result = extractor.extract(data, filename)
                result.merge(extractor_result)

        return result

    def extract_from_directory(
        self,
        data_dir: Path,
        edge_filter: Optional[Set[str]] = None
    ) -> ExtractionResult:
        """
        Extract edges from all JSON files in directory.

        Args:
            data_dir: Directory containing BloodHound JSON exports
            edge_filter: Optional set of edge types to extract (None = all)

        Returns:
            ExtractionResult with all extracted edges
        """
        result = ExtractionResult()
        data_dir = Path(data_dir)

        for json_path in data_dir.glob("*.json"):
            file_result = self.extract_from_file(json_path)
            result.merge(file_result)

        # Apply edge type filter
        if edge_filter:
            filtered_edges = [e for e in result.edges if e.edge_type in edge_filter]
            result.skipped = len(result.edges) - len(filtered_edges)
            result.edges = filtered_edges
            result.edge_count = len(filtered_edges)

        return result

    def get_attack_path_edges(self, data_dir: Path) -> ExtractionResult:
        """Extract only attack-path relevant edges"""
        return self.extract_from_directory(data_dir, edge_filter=ATTACK_PATH_EDGES)

    def get_all_edge_types(self) -> Set[str]:
        """Return all supported edge types"""
        all_types = set()
        for extractor in self.extractors:
            all_types.update(extractor.edge_types)
        return all_types


def deduplicate_edges(edges: List[Edge]) -> List[Edge]:
    """
    Remove duplicate edges (same source, target, edge_type).

    Keeps first occurrence (typically has better properties).
    """
    seen = set()
    unique = []

    for edge in edges:
        key = (edge.source, edge.target, edge.edge_type)
        if key not in seen:
            seen.add(key)
            unique.append(edge)

    return unique
