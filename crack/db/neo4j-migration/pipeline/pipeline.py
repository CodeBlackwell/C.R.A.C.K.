"""
Unified Neo4j data pipeline orchestrating transformation, validation, and import.
"""

import sys
from pathlib import Path
from typing import List, Dict, Any, Optional

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from schema import SchemaRegistry, SchemaLoadError
from validation import FieldValidator, ValidationResult
from .csv_writer import CSVWriter, CSVWriteReport, CSVWriteStats


class PipelineError(Exception):
    """Pipeline execution error"""
    pass


class Neo4jPipeline:
    """
    Unified pipeline for Neo4j data transformation and import.

    Orchestrates the complete workflow:
    1. Load schema from YAML
    2. Extract data using extractors
    3. Validate extracted data (optional)
    4. Write CSV files
    5. Import to Neo4j (optional)
    6. Report statistics
    """

    def __init__(
        self,
        schema_path: str,
        output_dir: str,
        validate: bool = True,
        verbose: bool = False
    ):
        """
        Initialize pipeline.

        Args:
            schema_path: Path to YAML schema file
            output_dir: Directory for CSV output
            validate: Enable validation of extracted data
            verbose: Enable verbose logging
        """
        self.schema_path = Path(schema_path)
        self.output_dir = Path(output_dir)
        self.validate = validate
        self.verbose = verbose

        # Pipeline components
        self.schema_registry: Optional[SchemaRegistry] = None
        self.csv_writer: Optional[CSVWriter] = None
        self.validator: Optional[FieldValidator] = None

        # Results
        self.validation_results: List[ValidationResult] = []
        self.csv_report: Optional[CSVWriteReport] = None

    def load_schema(self, extractor_module) -> SchemaRegistry:
        """
        Load schema from YAML and register extractors.

        Args:
            extractor_module: Module containing extractor functions

        Returns:
            SchemaRegistry with loaded schema

        Raises:
            PipelineError: If schema loading fails
        """
        if self.verbose:
            print(f"Loading schema from {self.schema_path}...")

        try:
            registry = SchemaRegistry(str(self.schema_path))
            registry.register_extractors(extractor_module)
            registry.validate(strict=False)

            schema = registry.get_schema()
            if self.verbose:
                print(f"  Loaded {len(schema.nodes)} node types, "
                      f"{len(schema.relationships)} relationship types")

            self.schema_registry = registry
            return registry

        except SchemaLoadError as e:
            raise PipelineError(f"Schema loading failed: {e}")

    def transform(
        self,
        commands: List[Dict],
        chains: List[Dict],
        cheatsheets: List[Dict]
    ) -> CSVWriteReport:
        """
        Transform data to CSV files.

        Args:
            commands: List of command dictionaries
            chains: List of attack chain dictionaries
            cheatsheets: List of cheatsheet dictionaries

        Returns:
            CSVWriteReport with write statistics

        Raises:
            PipelineError: If transformation fails
        """
        if not self.schema_registry:
            raise PipelineError("Schema not loaded. Call load_schema() first.")

        schema = self.schema_registry.get_schema()
        self.csv_writer = CSVWriter(str(self.output_dir))

        if self.validate:
            self.validator = FieldValidator()
            self.validation_results = []

        print()
        print("Transforming data to Neo4j CSV format...")
        print()

        # Extract and write node CSVs
        print("Generating node CSVs...")
        node_stats = []
        for spec in schema.nodes:
            if self.verbose:
                print(f"  {spec.csv_filename}... ({spec.description})")
            else:
                print(f"  {spec.label}...", end=" ")

            if not spec.extractor:
                print("SKIPPED (no extractor)")
                continue

            # Extract data
            data = spec.extractor(commands, chains, cheatsheets)

            # Validate if requested
            if self.validator:
                result = self.validator.validate_node_extraction(
                    spec.label,
                    spec.fieldnames,
                    spec.id_field,
                    data
                )
                self.validation_results.append(result)

            # Write CSV
            stat = self.csv_writer.write_csv(spec.csv_filename, data, spec.fieldnames)
            node_stats.append(stat)

            if not self.verbose:
                print(f"{len(data)} rows")

        # Extract and write relationship CSVs
        print()
        print("Generating relationship CSVs...")
        relationship_stats = []
        for spec in schema.relationships:
            if self.verbose:
                print(f"  {spec.csv_filename}... ({spec.description})")
            else:
                print(f"  {spec.rel_type}...", end=" ")

            if not spec.extractor:
                print("SKIPPED (no extractor)")
                continue

            # Extract data
            data = spec.extractor(commands, chains, cheatsheets)

            # Validate if requested
            if self.validator:
                result = self.validator.validate_relationship_extraction(
                    spec.rel_type,
                    spec.fieldnames,
                    spec.start_id_col,
                    spec.end_id_col,
                    data
                )
                self.validation_results.append(result)

            # Write CSV
            stat = self.csv_writer.write_csv(spec.csv_filename, data, spec.fieldnames)
            relationship_stats.append(stat)

            if not self.verbose:
                print(f"{len(data)} rows")

        # Create report
        self.csv_report = CSVWriteReport(
            output_dir=str(self.output_dir),
            node_stats=node_stats,
            relationship_stats=relationship_stats
        )

        return self.csv_report

    def print_reports(self):
        """Print validation and CSV write reports"""
        # Print validation report if validation was enabled
        if self.validator and self.validation_results:
            self.validator.print_validation_report(self.validation_results)

        # Print CSV write report
        if self.csv_report:
            self.csv_report.print_report()

    def has_validation_errors(self) -> bool:
        """Check if validation found any errors"""
        if not self.validation_results:
            return False
        return any(r.has_errors for r in self.validation_results)

    def run_transform(
        self,
        commands: List[Dict],
        chains: List[Dict],
        cheatsheets: List[Dict],
        extractor_module
    ) -> bool:
        """
        Run complete transformation pipeline.

        Args:
            commands: List of command dictionaries
            chains: List of attack chain dictionaries
            cheatsheets: List of cheatsheet dictionaries
            extractor_module: Module containing extractor functions

        Returns:
            True if successful, False if validation errors occurred
        """
        try:
            # Load schema
            self.load_schema(extractor_module)

            # Transform data
            self.transform(commands, chains, cheatsheets)

            # Print reports
            self.print_reports()

            # Check for validation errors
            if self.has_validation_errors():
                print()
                print("⚠ Transformation completed with validation errors")
                return False

            print()
            print("✓ Transformation completed successfully")
            return True

        except PipelineError as e:
            print(f"\n✗ Pipeline error: {e}")
            return False
        except Exception as e:
            print(f"\n✗ Unexpected error: {e}")
            import traceback
            traceback.print_exc()
            return False
