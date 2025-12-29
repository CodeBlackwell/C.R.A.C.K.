"""
PRISM Parser Test Suite

Comprehensive tests for the PRISM parsing module.

Test Modules:
- test_parser_registry.py: Parser auto-detection (BV:CRITICAL)
- test_mimikatz_parser.py: Mimikatz credential extraction (BV:HIGH)
- test_nmap_parser.py: Nmap host/port parsing (BV:HIGH)
- test_credential_models.py: Credential model properties (BV:MEDIUM)
- test_deduplication.py: Credential deduplication (BV:HIGH)

Business Value Focus:
- Parser detection accuracy (correct parser selected)
- Credential extraction completeness (no data loss)
- Deduplication correctness (no false positives/negatives)
- Encoding handling (UTF-8, latin-1, mixed)
"""
