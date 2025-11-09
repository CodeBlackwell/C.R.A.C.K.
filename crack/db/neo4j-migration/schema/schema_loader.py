"""
Schema loader for Neo4j data pipeline.

Loads schema definitions from YAML and creates NodeSpec/RelationshipSpec objects.
Provides validation and centralized schema access.
"""

import yaml
from pathlib import Path
from typing import Dict, Any, List, Optional, Callable
import logging

from .shared_schema import NodeSpec, RelationshipSpec, SchemaDefinition


logger = logging.getLogger(__name__)


class SchemaLoadError(Exception):
    """Raised when schema cannot be loaded or is invalid"""
    pass


class SchemaRegistry:
    """
    Centralized schema registry for the Neo4j data pipeline.

    Responsibilities:
    1. Load schema from YAML file
    2. Validate schema consistency
    3. Provide access to node and relationship specs
    4. Register extractor functions

    Example:
        registry = SchemaRegistry('schema/neo4j_schema.yaml')
        registry.register_extractors(extractor_module)

        schema = registry.get_schema()
        for node_spec in schema.nodes:
            data = node_spec.extractor(commands, chains, cheatsheets)
    """

    def __init__(self, schema_path: str):
        """
        Initialize schema registry.

        Args:
            schema_path: Path to YAML schema file

        Raises:
            SchemaLoadError: If schema file cannot be loaded or is invalid
        """
        self.schema_path = Path(schema_path)
        self.extractor_registry: Dict[str, Callable] = {}
        self._schema: Optional[SchemaDefinition] = None

        # Load schema immediately
        self._load_schema()

    def _load_schema(self):
        """
        Load schema from YAML file.

        Raises:
            SchemaLoadError: If file doesn't exist or YAML is invalid
        """
        if not self.schema_path.exists():
            raise SchemaLoadError(
                f"Schema file not found: {self.schema_path}"
            )

        try:
            with open(self.schema_path) as f:
                schema_data = yaml.safe_load(f)
        except yaml.YAMLError as e:
            raise SchemaLoadError(
                f"Failed to parse YAML schema: {e}"
            )
        except Exception as e:
            raise SchemaLoadError(
                f"Failed to read schema file: {e}"
            )

        if not isinstance(schema_data, dict):
            raise SchemaLoadError(
                f"Schema must be a dictionary, got {type(schema_data)}"
            )

        # Build schema definition
        nodes = self._load_node_specs(schema_data.get('nodes', {}))
        relationships = self._load_relationship_specs(
            schema_data.get('relationships', {})
        )

        self._schema = SchemaDefinition(nodes=nodes, relationships=relationships)

        logger.info(
            f"Loaded schema: {len(nodes)} node types, "
            f"{len(relationships)} relationship types"
        )

    def _load_node_specs(self, nodes_data: Dict[str, Any]) -> List[NodeSpec]:
        """
        Load node specifications from YAML data.

        Args:
            nodes_data: Dictionary of node definitions from YAML

        Returns:
            List of NodeSpec objects
        """
        specs = []

        for node_key, node_config in nodes_data.items():
            try:
                spec = NodeSpec(
                    name=node_config['name'],
                    label=node_config['label'],
                    csv_filename=node_config['csv_filename'],
                    id_field=node_config['id_field'],
                    fieldnames=node_config['fields'],
                    description=node_config.get('description', ''),
                    extractor=None  # Will be set by register_extractors()
                )

                # Store extractor name for later registration
                extractor_name = node_config.get('extractor')
                if extractor_name:
                    spec._extractor_name = extractor_name

                specs.append(spec)

            except KeyError as e:
                raise SchemaLoadError(
                    f"Node '{node_key}' missing required field: {e}"
                )
            except Exception as e:
                raise SchemaLoadError(
                    f"Failed to load node '{node_key}': {e}"
                )

        return specs

    def _load_relationship_specs(
        self,
        rels_data: Dict[str, Any]
    ) -> List[RelationshipSpec]:
        """
        Load relationship specifications from YAML data.

        Args:
            rels_data: Dictionary of relationship definitions from YAML

        Returns:
            List of RelationshipSpec objects
        """
        specs = []

        for rel_key, rel_config in rels_data.items():
            try:
                spec = RelationshipSpec(
                    name=rel_config['name'],
                    rel_type=rel_config['rel_type'],
                    csv_filename=rel_config['csv_filename'],
                    start_label=rel_config['start_label'],
                    end_label=rel_config['end_label'],
                    start_id_col=rel_config['start_id_col'],
                    end_id_col=rel_config['end_id_col'],
                    start_id_field=rel_config.get('start_id_field', 'id'),
                    end_id_field=rel_config.get('end_id_field', 'id'),
                    fieldnames=rel_config.get('fields'),
                    description=rel_config.get('description', ''),
                    extractor=None  # Will be set by register_extractors()
                )

                # Store extractor name for later registration
                extractor_name = rel_config.get('extractor')
                if extractor_name:
                    spec._extractor_name = extractor_name

                specs.append(spec)

            except KeyError as e:
                raise SchemaLoadError(
                    f"Relationship '{rel_key}' missing required field: {e}"
                )
            except Exception as e:
                raise SchemaLoadError(
                    f"Failed to load relationship '{rel_key}': {e}"
                )

        return specs

    def register_extractors(self, extractor_module):
        """
        Register extractor functions from a module.

        Links extractor functions to specs based on extractor names in YAML.

        Args:
            extractor_module: Module containing extractor functions

        Example:
            from extraction import extractors
            registry.register_extractors(extractors)
        """
        # Build extractor registry from module
        for attr_name in dir(extractor_module):
            if not attr_name.startswith('_'):
                attr = getattr(extractor_module, attr_name)
                if callable(attr):
                    self.extractor_registry[attr_name] = attr

        # Link extractors to specs
        missing_extractors = []

        for spec in self._schema.nodes + self._schema.relationships:
            extractor_name = getattr(spec, '_extractor_name', None)
            if extractor_name:
                if extractor_name in self.extractor_registry:
                    spec.extractor = self.extractor_registry[extractor_name]
                else:
                    missing_extractors.append(
                        f"{spec.name}: {extractor_name}"
                    )

        if missing_extractors:
            logger.warning(
                f"Missing {len(missing_extractors)} extractor functions: "
                f"{', '.join(missing_extractors)}"
            )

        logger.info(
            f"Registered {len(self.extractor_registry)} extractor functions"
        )

    def validate(self, strict: bool = True) -> List[str]:
        """
        Validate schema consistency.

        Args:
            strict: If True, raises SchemaLoadError on validation errors

        Returns:
            List of validation errors (empty if valid)

        Raises:
            SchemaLoadError: If strict=True and validation fails
        """
        errors = self._schema.validate()

        # Check that all specs have extractors registered
        for spec in self._schema.nodes + self._schema.relationships:
            if not spec.extractor:
                errors.append(
                    f"{spec.name}: No extractor function registered"
                )

        if errors:
            error_msg = f"Schema validation failed:\n" + "\n".join(
                f"  - {e}" for e in errors
            )
            logger.error(error_msg)

            if strict:
                raise SchemaLoadError(error_msg)
        else:
            logger.info("Schema validation passed")

        return errors

    def get_schema(self) -> SchemaDefinition:
        """Get the complete schema definition"""
        return self._schema

    def get_node_specs(self) -> List[NodeSpec]:
        """Get all node specifications"""
        return self._schema.nodes

    def get_relationship_specs(self) -> List[RelationshipSpec]:
        """Get all relationship specifications"""
        return self._schema.relationships

    def get_node_spec(self, name: str) -> Optional[NodeSpec]:
        """Get node spec by name"""
        return self._schema.get_node_spec(name)

    def get_relationship_spec(self, name: str) -> Optional[RelationshipSpec]:
        """Get relationship spec by name"""
        return self._schema.get_relationship_spec(name)

    def reload(self):
        """Reload schema from YAML file"""
        self._load_schema()
        logger.info("Schema reloaded")
