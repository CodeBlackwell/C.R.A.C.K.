"""
Unified schema definitions for Neo4j data pipeline.

This module provides base classes for both data extraction (transform) and
Neo4j import stages, ensuring consistency and reducing code duplication.
"""

from dataclasses import dataclass, field
from typing import List, Callable, Dict, Any, Optional
import inspect


@dataclass
class BaseSpec:
    """
    Base specification for all data transformations.

    Provides common fields shared by both node and relationship specs.
    """
    csv_filename: str
    description: str = field(default="")

    def validate(self) -> List[str]:
        """
        Validate spec configuration.

        Returns:
            List of validation error messages (empty if valid)
        """
        errors = []

        if not self.csv_filename:
            errors.append(f"{self.__class__.__name__}: csv_filename cannot be empty")

        if not self.csv_filename.endswith('.csv'):
            errors.append(
                f"{self.__class__.__name__}: csv_filename must end with .csv, "
                f"got '{self.csv_filename}'"
            )

        return errors


@dataclass
class NodeSpec(BaseSpec):
    """
    Unified node specification for extraction AND import.

    This single spec serves both purposes:
    - Extraction: Defines how to extract node data from source
    - Import: Defines how to import nodes into Neo4j

    Example:
        NodeSpec(
            csv_filename='commands.csv',
            name='commands',
            label='Command',
            id_field='id',
            fieldnames=['id', 'name', 'category', 'command'],
            extractor=extract_commands_csv,
            description='Command definitions'
        )
    """
    name: str = ""               # Entity name (e.g., 'commands', 'tags')
    label: str = ""              # Neo4j node label (e.g., 'Command', 'Tag')
    id_field: str = "id"         # Field used as unique ID ('id', 'name')
    fieldnames: List[str] = field(default_factory=list)  # CSV column names in order
    extractor: Optional[Callable[[List[Dict], List[Dict], List[Dict]], List[Dict]]] = None

    def validate(self) -> List[str]:
        """Validate node spec configuration"""
        errors = super().validate()

        if not self.name:
            errors.append(f"{self.csv_filename}: name cannot be empty")

        if not self.label:
            errors.append(f"{self.csv_filename}: label cannot be empty")

        if not self.id_field:
            errors.append(f"{self.csv_filename}: id_field cannot be empty")

        if not self.fieldnames:
            errors.append(f"{self.csv_filename}: fieldnames cannot be empty")

        if self.id_field not in self.fieldnames:
            errors.append(
                f"{self.csv_filename}: id_field '{self.id_field}' not in fieldnames: "
                f"{self.fieldnames}"
            )

        # Validate extractor signature if provided
        if self.extractor:
            try:
                sig = inspect.signature(self.extractor)
                params = list(sig.parameters.keys())
                expected = ['commands', 'chains', 'cheatsheets']
                if params != expected:
                    errors.append(
                        f"{self.csv_filename}: extractor signature must be "
                        f"{expected}, got {params}"
                    )
            except Exception as e:
                errors.append(
                    f"{self.csv_filename}: failed to inspect extractor signature: {e}"
                )

        return errors


@dataclass
class RelationshipSpec(BaseSpec):
    """
    Unified relationship specification for extraction AND import.

    This single spec serves both purposes:
    - Extraction: Defines how to extract relationship data from source
    - Import: Defines how to create relationships in Neo4j

    Example:
        RelationshipSpec(
            name='command_has_variable',
            rel_type='USES_VARIABLE',
            csv_filename='command_has_variable.csv',
            start_label='Command',
            end_label='Variable',
            start_id_col='command_id',
            end_id_col='variable_id',
            start_id_field='id',
            end_id_field='name',
            fieldnames=['command_id', 'variable_id', 'position', 'example'],
            extractor=extract_command_variables_rels,
            description='Command uses variable'
        )
    """
    name: str = ""               # Relationship name (e.g., 'command_has_variable')
    rel_type: str = ""           # Neo4j relationship type ('USES_VARIABLE')
    start_label: str = ""        # Start node label ('Command')
    end_label: str = ""          # End node label ('Variable')
    start_id_col: str = ""       # CSV column with start node ID
    end_id_col: str = ""         # CSV column with end node ID
    start_id_field: str = 'id'   # Field in start node used as ID
    end_id_field: str = 'id'     # Field in end node used as ID
    fieldnames: Optional[List[str]] = None  # CSV column names (None = just start/end IDs)
    extractor: Optional[Callable[[List[Dict], List[Dict], List[Dict]], List[Dict]]] = None

    def __post_init__(self):
        """Set default fieldnames if not provided"""
        if self.fieldnames is None:
            self.fieldnames = [self.start_id_col, self.end_id_col]

    def validate(self) -> List[str]:
        """Validate relationship spec configuration"""
        errors = super().validate()

        if not self.name:
            errors.append(f"{self.csv_filename}: name cannot be empty")

        if not self.rel_type:
            errors.append(f"{self.csv_filename}: rel_type cannot be empty")

        if not self.start_label:
            errors.append(f"{self.csv_filename}: start_label cannot be empty")

        if not self.end_label:
            errors.append(f"{self.csv_filename}: end_label cannot be empty")

        if not self.start_id_col:
            errors.append(f"{self.csv_filename}: start_id_col cannot be empty")

        if not self.end_id_col:
            errors.append(f"{self.csv_filename}: end_id_col cannot be empty")

        # Validate ID columns are in fieldnames
        if self.fieldnames:
            if self.start_id_col not in self.fieldnames:
                errors.append(
                    f"{self.csv_filename}: start_id_col '{self.start_id_col}' "
                    f"not in fieldnames: {self.fieldnames}"
                )

            if self.end_id_col not in self.fieldnames:
                errors.append(
                    f"{self.csv_filename}: end_id_col '{self.end_id_col}' "
                    f"not in fieldnames: {self.fieldnames}"
                )

        # Validate extractor signature if provided
        if self.extractor:
            try:
                sig = inspect.signature(self.extractor)
                params = list(sig.parameters.keys())
                expected = ['commands', 'chains', 'cheatsheets']
                if params != expected:
                    errors.append(
                        f"{self.csv_filename}: extractor signature must be "
                        f"{expected}, got {params}"
                    )
            except Exception as e:
                errors.append(
                    f"{self.csv_filename}: failed to inspect extractor signature: {e}"
                )

        return errors


@dataclass
class SchemaDefinition:
    """
    Complete schema definition for the Neo4j data pipeline.

    Encapsulates all node and relationship specs with validation.
    """
    nodes: List[NodeSpec] = field(default_factory=list)
    relationships: List[RelationshipSpec] = field(default_factory=list)

    def validate(self) -> List[str]:
        """
        Validate entire schema.

        Returns:
            List of all validation errors across all specs
        """
        errors = []

        # Validate individual specs
        for spec in self.nodes:
            errors.extend(spec.validate())

        for spec in self.relationships:
            errors.extend(spec.validate())

        # Check for duplicate CSV filenames
        csv_files = {}
        for spec in self.nodes + self.relationships:
            if spec.csv_filename in csv_files:
                errors.append(
                    f"Duplicate CSV filename '{spec.csv_filename}' in specs: "
                    f"{csv_files[spec.csv_filename]} and {spec.name}"
                )
            else:
                csv_files[spec.csv_filename] = spec.name

        # Check for duplicate node labels
        labels = {}
        for spec in self.nodes:
            if spec.label in labels:
                errors.append(
                    f"Duplicate node label '{spec.label}' in specs: "
                    f"{labels[spec.label]} and {spec.name}"
                )
            else:
                labels[spec.label] = spec.name

        # Check for duplicate relationship types (allowed, but warn)
        rel_types = {}
        for spec in self.relationships:
            if spec.rel_type in rel_types:
                # This is actually OK (same rel type can connect different node pairs)
                # Just track for informational purposes
                rel_types[spec.rel_type].append(spec.name)
            else:
                rel_types[spec.rel_type] = [spec.name]

        return errors

    def get_node_spec(self, name: str) -> Optional[NodeSpec]:
        """Get node spec by name"""
        for spec in self.nodes:
            if spec.name == name:
                return spec
        return None

    def get_relationship_spec(self, name: str) -> Optional[RelationshipSpec]:
        """Get relationship spec by name"""
        for spec in self.relationships:
            if spec.name == name:
                return spec
        return None
