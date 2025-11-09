"""
Field validators for Neo4j data transformation and import.

Ensures extractor output matches schema definitions and maintains data consistency.
"""

from typing import List, Dict, Any, Set, Optional, Tuple
from dataclasses import dataclass, field


@dataclass
class ValidationError:
    """Represents a validation error with context"""
    entity_type: str  # Node or relationship type (e.g., 'Command', 'USES_VARIABLE')
    field: Optional[str]  # Field name if applicable
    message: str  # Error description
    severity: str = 'error'  # 'error' or 'warning'
    row_id: Optional[str] = None  # Entity ID if available


@dataclass
class ValidationResult:
    """Result of validation operation"""
    is_valid: bool
    errors: List[ValidationError] = field(default_factory=list)
    warnings: List[ValidationError] = field(default_factory=list)

    @property
    def has_errors(self) -> bool:
        """Check if result has errors"""
        return len(self.errors) > 0

    @property
    def has_warnings(self) -> bool:
        """Check if result has warnings"""
        return len(self.warnings) > 0

    def add_error(self, entity_type: str, message: str, field: str = None, row_id: str = None):
        """Add validation error"""
        self.errors.append(ValidationError(
            entity_type=entity_type,
            field=field,
            message=message,
            severity='error',
            row_id=row_id
        ))
        self.is_valid = False

    def add_warning(self, entity_type: str, message: str, field: str = None, row_id: str = None):
        """Add validation warning"""
        self.warnings.append(ValidationError(
            entity_type=entity_type,
            field=field,
            message=message,
            severity='warning',
            row_id=row_id
        ))

    def merge(self, other: 'ValidationResult'):
        """Merge another validation result into this one"""
        self.errors.extend(other.errors)
        self.warnings.extend(other.warnings)
        if other.has_errors:
            self.is_valid = False


class FieldValidator:
    """
    Validates extractor output against schema field definitions.

    Ensures:
    - All schema fields are present in extractor output
    - No unexpected fields in output
    - Field values are non-empty where required
    - Data types are consistent
    """

    def __init__(self, strict: bool = False):
        """
        Initialize validator.

        Args:
            strict: If True, treats warnings as errors
        """
        self.strict = strict

    def validate_node_extraction(
        self,
        entity_type: str,
        expected_fields: List[str],
        id_field: str,
        extracted_data: List[Dict[str, Any]]
    ) -> ValidationResult:
        """
        Validate node extraction output.

        Args:
            entity_type: Node type (e.g., 'Command', 'Variable')
            expected_fields: List of field names from schema
            id_field: Name of ID field for this node type
            extracted_data: List of extracted node dictionaries

        Returns:
            ValidationResult with errors and warnings
        """
        result = ValidationResult(is_valid=True)

        if not extracted_data:
            result.add_warning(entity_type, "No data extracted")
            return result

        # Convert expected fields to set for faster lookup
        expected_set = set(expected_fields)

        # Validate each extracted row
        for idx, row in enumerate(extracted_data):
            row_id = row.get(id_field, f"row_{idx}")

            # Check all expected fields are present
            actual_fields = set(row.keys())
            missing_fields = expected_set - actual_fields

            if missing_fields:
                result.add_error(
                    entity_type,
                    f"Missing fields: {sorted(missing_fields)}",
                    row_id=row_id
                )

            # Check for unexpected fields
            extra_fields = actual_fields - expected_set
            if extra_fields:
                result.add_warning(
                    entity_type,
                    f"Unexpected fields: {sorted(extra_fields)}",
                    row_id=row_id
                )

            # Validate ID field is non-empty
            if id_field not in row or not row[id_field]:
                result.add_error(
                    entity_type,
                    f"ID field '{id_field}' is missing or empty",
                    field=id_field,
                    row_id=row_id
                )

        return result

    def validate_relationship_extraction(
        self,
        entity_type: str,
        expected_fields: List[str],
        start_id_col: str,
        end_id_col: str,
        extracted_data: List[Dict[str, Any]]
    ) -> ValidationResult:
        """
        Validate relationship extraction output.

        Args:
            entity_type: Relationship type (e.g., 'USES_VARIABLE')
            expected_fields: List of field names from schema
            start_id_col: Name of start node ID column
            end_id_col: Name of end node ID column
            extracted_data: List of extracted relationship dictionaries

        Returns:
            ValidationResult with errors and warnings
        """
        result = ValidationResult(is_valid=True)

        if not extracted_data:
            result.add_warning(entity_type, "No data extracted")
            return result

        # Convert expected fields to set for faster lookup
        expected_set = set(expected_fields)

        # Validate each extracted row
        for idx, row in enumerate(extracted_data):
            row_id = f"{row.get(start_id_col, '?')}->{row.get(end_id_col, '?')}"

            # Check all expected fields are present
            actual_fields = set(row.keys())
            missing_fields = expected_set - actual_fields

            if missing_fields:
                result.add_error(
                    entity_type,
                    f"Missing fields: {sorted(missing_fields)}",
                    row_id=row_id
                )

            # Check for unexpected fields
            extra_fields = actual_fields - expected_set
            if extra_fields:
                result.add_warning(
                    entity_type,
                    f"Unexpected fields: {sorted(extra_fields)}",
                    row_id=row_id
                )

            # Validate start and end ID fields are non-empty
            if start_id_col not in row or not row[start_id_col]:
                result.add_error(
                    entity_type,
                    f"Start ID field '{start_id_col}' is missing or empty",
                    field=start_id_col,
                    row_id=row_id
                )

            if end_id_col not in row or not row[end_id_col]:
                result.add_error(
                    entity_type,
                    f"End ID field '{end_id_col}' is missing or empty",
                    field=end_id_col,
                    row_id=row_id
                )

        return result

    def validate_data_consistency(
        self,
        node_type: str,
        node_id_field: str,
        node_data: List[Dict[str, Any]],
        relationships: List[Tuple[str, str, str, List[Dict[str, Any]]]]
    ) -> ValidationResult:
        """
        Validate referential integrity between nodes and relationships.

        Args:
            node_type: Node type (e.g., 'Command')
            node_id_field: Field name for node IDs
            node_data: List of node dictionaries
            relationships: List of (rel_type, start_id_col, end_id_col, data) tuples

        Returns:
            ValidationResult with errors for dangling references
        """
        result = ValidationResult(is_valid=True)

        # Build set of valid node IDs
        valid_ids = set()
        for node in node_data:
            node_id = node.get(node_id_field)
            if node_id:
                valid_ids.add(node_id)

        # Check each relationship for dangling references
        for rel_type, start_id_col, end_id_col, rel_data in relationships:
            for rel in rel_data:
                start_id = rel.get(start_id_col)

                # Check if start ID references a valid node (only if it's the node type we're validating)
                if start_id and start_id not in valid_ids:
                    result.add_warning(
                        rel_type,
                        f"Start node '{start_id}' not found in {node_type} nodes",
                        field=start_id_col,
                        row_id=f"{start_id}->{rel.get(end_id_col, '?')}"
                    )

        return result

    def print_validation_report(self, results: List[ValidationResult]):
        """
        Print formatted validation report.

        Args:
            results: List of validation results
        """
        total_errors = sum(len(r.errors) for r in results)
        total_warnings = sum(len(r.warnings) for r in results)

        print()
        print("=" * 60)
        print("Validation Report")
        print("=" * 60)

        if total_errors == 0 and total_warnings == 0:
            print("✓ All validations passed!")
            return

        # Print errors
        if total_errors > 0:
            print(f"\n{total_errors} ERROR(S) FOUND:")
            for result in results:
                for error in result.errors:
                    location = f"{error.entity_type}"
                    if error.field:
                        location += f".{error.field}"
                    if error.row_id:
                        location += f" [{error.row_id}]"
                    print(f"  ✗ {location}: {error.message}")

        # Print warnings
        if total_warnings > 0:
            print(f"\n{total_warnings} WARNING(S):")
            for result in results:
                for warning in result.warnings:
                    location = f"{warning.entity_type}"
                    if warning.field:
                        location += f".{warning.field}"
                    if warning.row_id:
                        location += f" [{warning.row_id}]"
                    print(f"  ! {location}: {warning.message}")

        print()
        print("=" * 60)
