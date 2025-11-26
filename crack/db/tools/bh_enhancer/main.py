"""
BloodHound Edge Enhancer - Main Orchestration

Coordinates edge extraction from BloodHound JSON and batch import to Neo4j.
"""

import time
from pathlib import Path
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field

from neo4j import GraphDatabase
from neo4j.exceptions import ServiceUnavailable, AuthError

from .config import Neo4jConfig, DEFAULT_BATCH_SIZE, ATTACK_PATH_EDGES
from .sid_resolver import SIDResolver
from .extractors import (
    EdgeExtractorRegistry,
    ExtractionResult,
    Edge,
    deduplicate_edges,
)


@dataclass
class ImportStats:
    """Statistics from edge import"""
    edges_extracted: int = 0
    edges_deduplicated: int = 0
    edges_imported: int = 0
    edges_skipped: int = 0
    edges_failed: int = 0
    batches_processed: int = 0
    duration_seconds: float = 0.0
    errors: List[str] = field(default_factory=list)

    def summary(self) -> str:
        return (
            f"Extracted: {self.edges_extracted}, "
            f"Deduplicated: {self.edges_deduplicated}, "
            f"Imported: {self.edges_imported}, "
            f"Failed: {self.edges_failed}, "
            f"Time: {self.duration_seconds:.2f}s"
        )


class BatchExecutor:
    """
    Executes batched Neo4j edge creation.

    Uses UNWIND for efficient bulk imports with proper error handling.
    """

    def __init__(self, driver, batch_size: int = DEFAULT_BATCH_SIZE):
        self.driver = driver
        self.batch_size = batch_size
        self.stats = ImportStats()

    def create_edges(self, edges: List[Edge], verbose: bool = False) -> ImportStats:
        """
        Bulk create edges in Neo4j using batched UNWIND queries.

        Args:
            edges: List of Edge objects to create
            verbose: Print progress messages

        Returns:
            ImportStats with results
        """
        start_time = time.time()
        self.stats = ImportStats()
        self.stats.edges_extracted = len(edges)

        # Deduplicate
        unique_edges = deduplicate_edges(edges)
        self.stats.edges_deduplicated = len(edges) - len(unique_edges)

        # Group edges by type for efficient batch processing
        edges_by_type: Dict[str, List[Edge]] = {}
        for edge in unique_edges:
            if edge.edge_type not in edges_by_type:
                edges_by_type[edge.edge_type] = []
            edges_by_type[edge.edge_type].append(edge)

        # Process each edge type
        for edge_type, type_edges in edges_by_type.items():
            if verbose:
                print(f"  Importing {len(type_edges)} {edge_type} edges...")

            self._import_edge_batch(edge_type, type_edges, verbose)

        self.stats.duration_seconds = time.time() - start_time
        return self.stats

    def _import_edge_batch(
        self,
        edge_type: str,
        edges: List[Edge],
        verbose: bool
    ):
        """Import a batch of edges of the same type"""
        # Process in batches
        for i in range(0, len(edges), self.batch_size):
            batch = edges[i:i + self.batch_size]
            self.stats.batches_processed += 1

            # Convert to dict format for Neo4j parameters
            edge_data = [
                {"source": e.source, "target": e.target, "props": e.properties}
                for e in batch
            ]

            # Dynamic query based on edge type
            # Note: Can't use $edge_type as parameter for relationship type
            query = f"""
            UNWIND $edges AS edge
            MATCH (source {{name: edge.source}})
            MATCH (target {{name: edge.target}})
            MERGE (source)-[r:{edge_type}]->(target)
            ON CREATE SET r += edge.props
            RETURN count(r) AS created
            """

            try:
                with self.driver.session() as session:
                    result = session.run(query, edges=edge_data)
                    record = result.single()
                    created = record["created"] if record else 0
                    self.stats.edges_imported += created
                    # Edges that didn't match nodes
                    failed = len(batch) - created
                    self.stats.edges_failed += failed

            except Exception as e:
                self.stats.errors.append(f"{edge_type} batch {i//self.batch_size}: {e}")
                self.stats.edges_failed += len(batch)


class BHEnhancer:
    """
    Main orchestrator for BloodHound edge enhancement.

    Example:
        enhancer = BHEnhancer(
            bh_data_dir=Path("/path/to/bh/json"),
            neo4j_config=Neo4jConfig()
        )
        stats = enhancer.run(preset="attack-paths", verbose=True)
    """

    def __init__(
        self,
        bh_data_dir: Path,
        neo4j_config: Optional[Neo4jConfig] = None
    ):
        self.bh_data_dir = Path(bh_data_dir)
        self.config = neo4j_config or Neo4jConfig()
        self.driver = None
        self.resolver = None
        self.registry = None

    def connect(self) -> bool:
        """Establish Neo4j connection"""
        try:
            self.driver = GraphDatabase.driver(
                self.config.uri,
                auth=(self.config.user, self.config.password)
            )
            # Test connection
            with self.driver.session() as session:
                session.run("RETURN 1")
            return True
        except AuthError:
            print(f"[!] Neo4j authentication failed (user: {self.config.user})")
            return False
        except ServiceUnavailable:
            print(f"[!] Neo4j not available at {self.config.uri}")
            return False
        except Exception as e:
            print(f"[!] Neo4j connection error: {e}")
            return False

    def close(self):
        """Close Neo4j connection"""
        if self.driver:
            self.driver.close()

    def initialize(self) -> bool:
        """Initialize resolver and registry"""
        try:
            print(f"[*] Loading SIDs from {self.bh_data_dir}...")
            self.resolver = SIDResolver(self.bh_data_dir)
            print(f"[+] Loaded {len(self.resolver)} SID mappings")

            self.registry = EdgeExtractorRegistry(self.resolver)
            return True
        except FileNotFoundError as e:
            print(f"[!] {e}")
            return False
        except Exception as e:
            print(f"[!] Initialization error: {e}")
            return False

    def run(
        self,
        preset: Optional[str] = None,
        edge_filter: Optional[Set[str]] = None,
        dry_run: bool = False,
        verbose: bool = False
    ) -> ImportStats:
        """
        Run the edge enhancement pipeline.

        Args:
            preset: "attack-paths" for attack-path focused edges, None for all
            edge_filter: Specific edge types to extract (overrides preset)
            dry_run: Extract but don't import (validation mode)
            verbose: Print detailed progress

        Returns:
            ImportStats with results
        """
        stats = ImportStats()

        # Initialize
        if not self.initialize():
            return stats

        # Determine edge filter
        if edge_filter:
            filter_set = edge_filter
        elif preset == "attack-paths":
            filter_set = ATTACK_PATH_EDGES
            if verbose:
                print(f"[*] Using attack-paths preset ({len(filter_set)} edge types)")
        else:
            filter_set = None  # All edges

        # Extract edges
        print(f"[*] Extracting edges from {self.bh_data_dir}...")
        result = self.registry.extract_from_directory(
            self.bh_data_dir,
            edge_filter=filter_set
        )

        stats.edges_extracted = result.edge_count
        if result.errors:
            stats.errors.extend(result.errors)

        # Summary by edge type
        if verbose:
            edge_counts: Dict[str, int] = {}
            for edge in result.edges:
                edge_counts[edge.edge_type] = edge_counts.get(edge.edge_type, 0) + 1
            print(f"[+] Extracted {result.edge_count} edges:")
            for etype, count in sorted(edge_counts.items()):
                print(f"    {etype}: {count}")

        if result.skipped:
            print(f"[*] Skipped {result.skipped} edges (filtered out)")

        # Dry run - stop here
        if dry_run:
            print(f"[*] Dry run complete. Would import {result.edge_count} edges.")
            return stats

        # Connect to Neo4j
        if not self.connect():
            return stats

        try:
            # Import edges
            print(f"[*] Importing edges to Neo4j...")
            executor = BatchExecutor(self.driver, self.config.batch_size)
            import_stats = executor.create_edges(result.edges, verbose=verbose)

            # Merge stats
            stats.edges_imported = import_stats.edges_imported
            stats.edges_failed = import_stats.edges_failed
            stats.edges_deduplicated = import_stats.edges_deduplicated
            stats.batches_processed = import_stats.batches_processed
            stats.duration_seconds = import_stats.duration_seconds
            stats.errors.extend(import_stats.errors)

            print(f"[+] {import_stats.summary()}")

            if import_stats.errors and verbose:
                print(f"[!] Errors encountered:")
                for err in import_stats.errors[:5]:
                    print(f"    {err}")

        finally:
            self.close()

        return stats

    def validate(self, verbose: bool = False) -> Dict:
        """
        Validate BloodHound data without importing.

        Returns summary of what would be imported.
        """
        if not self.initialize():
            return {"error": "Failed to initialize"}

        result = self.registry.extract_from_directory(self.bh_data_dir)

        # Count by type
        edge_counts: Dict[str, int] = {}
        for edge in result.edges:
            edge_counts[edge.edge_type] = edge_counts.get(edge.edge_type, 0) + 1

        # Check resolver stats
        resolver_stats = self.resolver.get_stats()

        return {
            "total_edges": result.edge_count,
            "edges_by_type": edge_counts,
            "extraction_errors": result.errors,
            "resolver_stats": resolver_stats,
            "supported_edge_types": list(self.registry.get_all_edge_types()),
        }


def quick_enhance(
    bh_dir: str,
    uri: str = "bolt://localhost:7687",
    user: str = "neo4j",
    password: str = "Neo4j123",
    preset: str = "attack-paths"
) -> ImportStats:
    """
    Quick enhancement function for one-liner usage.

    Example:
        from bh_enhancer import quick_enhance
        stats = quick_enhance("/path/to/bh/json")
    """
    config = Neo4jConfig(uri=uri, user=user, password=password)
    enhancer = BHEnhancer(Path(bh_dir), config)
    return enhancer.run(preset=preset, verbose=True)
