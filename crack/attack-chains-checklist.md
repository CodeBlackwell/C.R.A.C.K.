# Attack Chains Implementation Checklist

## Phase 1: Schema Definition and Structure

- [x] Create `crack/reference/schemas/` directory for schema definitions
- [x] Define `attack_chain.schema.json` with minimal required fields (id, name, description, steps)
- [x] Establish ID naming convention pattern: `{platform}-{category}-{technique}-{variant}`
- [x] Add version field with semantic versioning (start with 1.0.0)
- [x] Define metadata object with required fields (author, created, updated, tags, category)
- [x] Add difficulty rating enum (beginner, intermediate, advanced, expert)
- [x] Include time_estimate and oscp_relevant boolean fields
- [x] Define step structure with command_ref as required field
- [x] Create JSON Schema validation rules for all field types
- [x] Document schema in `crack/reference/schemas/README.md`

## Phase 2: Directory Structure Setup

- [x] Create `crack/reference/data/attack_chains/` base directory
- [x] Create category subdirectories (enumeration, privilege_escalation, lateral_movement, persistence)
- [x] Add `metadata.json` manifest file at attack_chains root
- [x] Create `crack/reference/chains/` module directory
- [x] Add `__init__.py` with module exports
- [x] Create empty `loader.py`, `validator.py`, `registry.py` files
- [x] Set up `crack/reference/data/chain_templates/` for reusable patterns
- [x] Update `.gitignore` to exclude compiled/cached chain files

## Phase 3: Core Classes Implementation

- [x] Implement `ChainLoader` class in `loader.py`
  - [x] Add `load_chain(filepath)` method
  - [x] Add `load_all_chains()` method
  - [x] Implement JSON deserialization with error handling
  - [x] Add schema validation on load
- [x] Implement `ChainValidator` class in `validator.py`
  - [x] Create `validate_schema(chain_dict)` method
  - [x] Add `validate_command_refs(chain_dict)` method
  - [x] Implement `check_circular_dependencies()` method
  - [x] Add detailed error message formatting
- [x] Implement `ChainRegistry` class in `registry.py`
  - [x] Create singleton pattern for registry
  - [x] Add `register_chain(chain)` method
  - [x] Implement `get_chain(id)` method
  - [x] Add `filter_chains(criteria)` method
  - [x] Implement caching mechanism

## Phase 4: Command Reference Integration

- [ ] Create `CommandResolver` class
  - [ ] Add `resolve_command_ref(ref_id)` method
  - [ ] Implement batch validation of command references
  - [ ] Add error reporting for missing commands
  - [ ] Create method to extract all command_refs from a chain
- [ ] Update ChainValidator to use CommandResolver
- [ ] Add command existence validation to chain loading process
- [ ] Create unit tests for command resolution

## Phase 5: Data Models

- [ ] Create `models/attack_chain.py` with Chain dataclass
- [ ] Define `models/chain_step.py` with Step dataclass
- [ ] Add `models/chain_metadata.py` for metadata structure
- [ ] Implement `from_dict()` and `to_dict()` methods for serialization
- [ ] Add validation methods to model classes
- [ ] Create type hints for all model attributes
- [ ] Document model relationships and constraints

## Phase 6: CLI Integration

- [ ] Add `chains` subcommand to `crack reference` command group
- [ ] Implement `crack reference chains list` command
  - [ ] Add filtering options (--category, --platform, --difficulty)
  - [ ] Include output formatting (table, json, yaml)
- [ ] Implement `crack reference chains show <chain_id>` command
  - [ ] Display full chain details
  - [ ] Show resolved command information
- [ ] Add `crack reference chains validate` command
  - [ ] Validate single chain or all chains
  - [ ] Report validation errors with context
- [ ] Update `crack/cli.py` to register new commands
- [ ] Add help text and examples for all commands

## Phase 7: Validation Framework

- [ ] Create `tools/validate_chains.py` standalone validator
- [ ] Add pre-commit hook for chain validation
- [ ] Implement strict vs lenient validation modes
- [ ] Create validation report generator
- [ ] Add schema version compatibility checking
- [ ] Implement deprecation warnings for old schema versions
- [ ] Set up CI/CD validation step

## Phase 8: Testing Infrastructure

- [ ] Create `tests/reference/test_chains/` directory
- [ ] Write unit tests for ChainLoader
- [ ] Write unit tests for ChainValidator
- [ ] Write unit tests for ChainRegistry
- [ ] Create fixture chains for testing (valid and invalid examples)
- [ ] Add integration tests for full chain lifecycle
- [ ] Mock command reference system for isolated testing
- [ ] Create test helper for generating valid chain JSON
- [ ] Add performance tests for loading many chains
- [ ] Ensure 80%+ code coverage

## Phase 9: Documentation

- [ ] Document schema format with field descriptions
- [ ] Create chain authoring guide
- [ ] Write developer documentation for extending the system
- [ ] Add docstrings to all classes and methods
- [ ] Create example chains demonstrating all features
- [ ] Document naming conventions and best practices
- [ ] Add troubleshooting guide for common issues

## Phase 10: Performance Optimization

- [ ] Implement lazy loading for chain definitions
- [ ] Create metadata index for fast filtering
- [ ] Add caching layer with invalidation strategy
- [ ] Implement compiled chain format for fast loading
- [ ] Add performance benchmarks
- [ ] Optimize command reference resolution
- [ ] Create chain loading progress indicators

## Phase 11: Migration Preparation

- [ ] Analyze existing track system attack_chains.json
- [ ] Map existing structure to new schema
- [ ] Create migration script for existing chains
- [ ] Document migration path for track integration
- [ ] Add compatibility layer for old format
- [ ] Plan deprecation timeline for old system

## Phase 12: Final Validation

- [ ] Run full test suite
- [ ] Validate all chain files load correctly
- [ ] Confirm CLI commands work as expected
- [ ] Test with sample attack chain data
- [ ] Verify command reference resolution
- [ ] Check performance with multiple chains
- [ ] Document any known limitations
- [ ] Create MVP demonstration script

## Post-MVP Considerations

- [ ] Plan branching logic implementation
- [ ] Design parameter substitution system
- [ ] Consider chain composition (chains referencing other chains)
- [ ] Plan integration points with track system
- [ ] Design chain execution engine
- [ ] Consider versioning strategy for chain updates
- [ ] Plan for chain sharing/distribution mechanism