"""
Schema Validation Tests - Command Editor

Tests that tool schemas (gobuster, nmap, nikto, etc.) are valid JSON
and contain required fields with correct types.
"""

import json
import pytest
from pathlib import Path


def test_gobuster_schema_loads():
    """
    PROVES: Gobuster schema is valid JSON and can be loaded without errors

    GIVEN: gobuster.json schema file exists
    WHEN: Schema is loaded with json.load()
    THEN: No exceptions raised and tool name matches
    """
    schema_path = Path(__file__).parent.parent / "schemas" / "gobuster.json"

    with open(schema_path) as f:
        schema = json.load(f)

    assert schema['tool'] == 'gobuster'


def test_gobuster_schema_has_required_fields():
    """
    PROVES: Schema contains all required structural fields

    GIVEN: gobuster.json schema loaded
    WHEN: Checking for required top-level and nested fields
    THEN: All required fields present with correct required flags

    VALUE: Ensures AdvancedEditor can build forms from schema
    """
    schema_path = Path(__file__).parent.parent / "schemas" / "gobuster.json"

    with open(schema_path) as f:
        schema = json.load(f)

    # Top-level structure
    assert 'tool' in schema
    assert 'subcommands' in schema
    assert 'common_params' in schema
    assert 'parameters' in schema
    assert 'flags' in schema

    # Required parameters (using short identifiers)
    assert 'u' in schema['parameters']  # url
    assert 'w' in schema['parameters']  # wordlist

    # Required parameter properties
    assert schema['parameters']['u']['required'] is True
    assert schema['parameters']['w']['required'] is True
    assert schema['parameters']['o']['required'] is False  # output


def test_gobuster_parameter_types_valid():
    """
    PROVES: All parameter types are valid for form rendering

    GIVEN: gobuster.json schema with parameter definitions
    WHEN: Validating parameter type field values
    THEN: All types are from allowed set

    VALUE: Prevents schema typos that would break form generation
    """
    schema_path = Path(__file__).parent.parent / "schemas" / "gobuster.json"

    with open(schema_path) as f:
        schema = json.load(f)

    valid_types = ['text', 'number', 'path', 'enum', 'boolean']

    for param_name, param_def in schema['parameters'].items():
        assert 'type' in param_def, f"Parameter {param_name} missing 'type' field"
        assert param_def['type'] in valid_types, \
            f"Parameter {param_name} has invalid type: {param_def['type']}"


def test_nmap_schema_loads():
    """
    PROVES: Nmap schema is valid JSON and can be loaded without errors

    GIVEN: nmap.json schema file exists
    WHEN: Schema is loaded with json.load()
    THEN: No exceptions raised and tool name matches

    VALUE: Ensures nmap schema can be parsed for command editor
    """
    schema_path = Path(__file__).parent.parent / "schemas" / "nmap.json"

    with open(schema_path) as f:
        schema = json.load(f)

    assert schema['tool'] == 'nmap'


def test_nmap_schema_has_required_fields():
    """
    PROVES: Schema contains all required structural fields

    GIVEN: nmap.json schema loaded
    WHEN: Checking for required top-level and nested fields
    THEN: All required fields present with correct required flags

    VALUE: Ensures AdvancedEditor can build forms from schema
    """
    schema_path = Path(__file__).parent.parent / "schemas" / "nmap.json"

    with open(schema_path) as f:
        schema = json.load(f)

    # Top-level structure
    assert 'tool' in schema
    assert 'parameters' in schema
    assert 'flags' in schema

    # Required target parameter
    assert 'target' in schema['parameters']
    assert schema['parameters']['target']['required'] is True


def test_nmap_parameter_types_valid():
    """
    PROVES: Parameter types are valid including enum with options

    GIVEN: nmap.json schema with parameter definitions
    WHEN: Validating parameter type field values
    THEN: All types are from allowed set and enum has options

    VALUE: Prevents schema typos and ensures enum parameters renderable
    """
    schema_path = Path(__file__).parent.parent / "schemas" / "nmap.json"

    with open(schema_path) as f:
        schema = json.load(f)

    valid_types = ['text', 'number', 'path', 'enum', 'boolean']

    for param_name, param_def in schema['parameters'].items():
        assert 'type' in param_def, f"Parameter {param_name} missing 'type' field"
        assert param_def['type'] in valid_types, \
            f"Parameter {param_name} has invalid type: {param_def['type']}"

    # Verify enum has options (timing parameter, uses short identifier 'T')
    assert 'options' in schema['parameters']['T']
    assert len(schema['parameters']['T']['options']) == 6


def test_sqlmap_schema_loads():
    """
    PROVES: SQLMap schema is valid JSON and can be loaded without errors

    GIVEN: sqlmap.json schema file exists
    WHEN: Schema is loaded with json.load()
    THEN: No exceptions raised and tool name matches

    VALUE: Ensures sqlmap schema can be parsed for command editor
    """
    schema_path = Path(__file__).parent.parent / "schemas" / "sqlmap.json"

    with open(schema_path) as f:
        schema = json.load(f)

    assert schema['tool'] == 'sqlmap'


def test_sqlmap_schema_has_required_fields():
    """
    PROVES: Schema contains all required structural fields

    GIVEN: sqlmap.json schema loaded
    WHEN: Checking for required top-level and nested fields
    THEN: All required fields present with correct required flags

    VALUE: Ensures AdvancedEditor can build forms from schema
    """
    schema_path = Path(__file__).parent.parent / "schemas" / "sqlmap.json"

    with open(schema_path) as f:
        schema = json.load(f)

    # Top-level structure
    assert 'tool' in schema
    assert 'parameters' in schema
    assert 'flags' in schema

    # Required url parameter
    assert 'url' in schema['parameters']
    assert schema['parameters']['url']['required'] is True


def test_sqlmap_parameter_types_valid():
    """
    PROVES: Parameter types are valid including multiple enum validations

    GIVEN: sqlmap.json schema with parameter definitions
    WHEN: Validating parameter type field values
    THEN: All types are from allowed set and all enums have options

    VALUE: Prevents schema typos and ensures enum parameters renderable
    """
    schema_path = Path(__file__).parent.parent / "schemas" / "sqlmap.json"

    with open(schema_path) as f:
        schema = json.load(f)

    valid_types = ['text', 'number', 'path', 'enum', 'boolean']

    for param_name, param_def in schema['parameters'].items():
        assert 'type' in param_def, f"Parameter {param_name} missing 'type' field"
        assert param_def['type'] in valid_types, \
            f"Parameter {param_name} has invalid type: {param_def['type']}"

    # Verify all enum fields have options
    assert 'options' in schema['parameters']['level']
    assert len(schema['parameters']['level']['options']) == 5
    assert 'options' in schema['parameters']['risk']
    assert len(schema['parameters']['risk']['options']) == 3
    assert 'options' in schema['parameters']['technique']
    assert len(schema['parameters']['technique']['options']) == 6


def test_nikto_schema_loads():
    """
    PROVES: Nikto schema is valid JSON and can be loaded without errors

    GIVEN: nikto.json schema file exists
    WHEN: Schema is loaded with json.load()
    THEN: No exceptions raised and tool name matches

    VALUE: Ensures nikto schema can be parsed for command editor
    """
    schema_path = Path(__file__).parent.parent / "schemas" / "nikto.json"

    with open(schema_path) as f:
        schema = json.load(f)

    assert schema['tool'] == 'nikto'


def test_nikto_schema_has_required_fields():
    """
    PROVES: Schema contains all required structural fields

    GIVEN: nikto.json schema loaded
    WHEN: Checking for required top-level and nested fields
    THEN: All required fields present with correct required flags

    VALUE: Ensures AdvancedEditor can build forms from schema
    """
    schema_path = Path(__file__).parent.parent / "schemas" / "nikto.json"

    with open(schema_path) as f:
        schema = json.load(f)

    # Top-level structure
    assert 'tool' in schema
    assert 'parameters' in schema
    assert 'flags' in schema

    # Required host parameter
    assert 'host' in schema['parameters']
    assert schema['parameters']['host']['required'] is True
    assert schema['parameters']['output']['required'] is False


def test_nikto_parameter_types_valid():
    """
    PROVES: Parameter types are valid including enum with options

    GIVEN: nikto.json schema with parameter definitions
    WHEN: Validating parameter type field values
    THEN: All types are from allowed set and enum has options

    VALUE: Prevents schema typos and ensures enum parameters renderable
    """
    schema_path = Path(__file__).parent.parent / "schemas" / "nikto.json"

    with open(schema_path) as f:
        schema = json.load(f)

    valid_types = ['text', 'number', 'path', 'enum', 'boolean']

    for param_name, param_def in schema['parameters'].items():
        assert 'type' in param_def, f"Parameter {param_name} missing 'type' field"
        assert param_def['type'] in valid_types, \
            f"Parameter {param_name} has invalid type: {param_def['type']}"

    # Verify enum has options (tuning parameter)
    assert 'options' in schema['parameters']['tuning']
    assert len(schema['parameters']['tuning']['options']) == 10  # 1-9 + x


def test_hydra_schema_loads():
    """
    PROVES: Hydra schema is valid JSON and can be loaded without errors

    GIVEN: hydra.json schema file exists
    WHEN: Schema is loaded with json.load()
    THEN: No exceptions raised and tool name matches

    VALUE: Ensures hydra schema can be parsed for command editor
    """
    schema_path = Path(__file__).parent.parent / "schemas" / "hydra.json"

    with open(schema_path) as f:
        schema = json.load(f)

    assert schema['tool'] == 'hydra'


def test_hydra_schema_has_required_fields():
    """
    PROVES: Schema contains all required structural fields

    GIVEN: hydra.json schema loaded
    WHEN: Checking for required top-level and nested fields
    THEN: All required fields present with correct required flags

    VALUE: Ensures AdvancedEditor can build forms from schema
    """
    schema_path = Path(__file__).parent.parent / "schemas" / "hydra.json"

    with open(schema_path) as f:
        schema = json.load(f)

    # Top-level structure
    assert 'tool' in schema
    assert 'parameters' in schema
    assert 'flags' in schema

    # Required parameters
    assert 'service' in schema['parameters']
    assert 'target' in schema['parameters']

    # Required parameter flags
    assert schema['parameters']['service']['required'] is True
    assert schema['parameters']['target']['required'] is True


def test_hydra_parameter_types_valid():
    """
    PROVES: Parameter types are valid including enum with options

    GIVEN: hydra.json schema with parameter definitions
    WHEN: Validating parameter type field values
    THEN: All types are from allowed set and enum has options

    VALUE: Prevents schema typos and ensures enum parameters renderable
    """
    schema_path = Path(__file__).parent.parent / "schemas" / "hydra.json"

    with open(schema_path) as f:
        schema = json.load(f)

    valid_types = ['text', 'number', 'path', 'enum', 'boolean']

    for param_name, param_def in schema['parameters'].items():
        assert 'type' in param_def, f"Parameter {param_name} missing 'type' field"
        assert param_def['type'] in valid_types, \
            f"Parameter {param_name} has invalid type: {param_def['type']}"

    # Verify service enum has options
    assert 'options' in schema['parameters']['service']
    assert 'ssh' in schema['parameters']['service']['options']
    assert 'ftp' in schema['parameters']['service']['options']
