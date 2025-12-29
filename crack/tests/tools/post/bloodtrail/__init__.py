"""
BloodTrail Test Suite

Comprehensive tests for the BloodTrail BloodHound enhancement toolkit.

Test Modules:
- test_query_runner.py - Query execution and connection handling (BV:CRITICAL)
- test_property_importer.py - Property import for quick-wins detection (BV:HIGH)
- test_variable_substitution.py - Cypher injection prevention (BV:CRITICAL)
- test_edge_extraction.py - Edge extraction from BloodHound data (BV:HIGH)
- test_command_suggester.py - Attack command suggestions (BV:HIGH)

Ownership: tests/tools/post/bloodtrail/ (exclusive)
"""
