"""
Domain-Specific Assertion Helpers for CRACK Tests

Provides reusable assertion functions with clear, contextual error messages.
All assertions follow the pattern: assert_<domain>_<condition>

Business Value Focus:
- Consistent assertion patterns across all test modules
- Clear error messages for faster debugging
- Type-safe validations that catch data corruption
- Security-focused assertions (parameter binding, no injection)

Usage Examples:
    from tests.assertions import assert_credential_valid, assert_no_duplicates

    def test_credential_extraction(self):
        cred = parser.extract_credential(line)
        assert_credential_valid(cred)

    def test_deduplication(self):
        creds = summary.deduplicate().credentials
        assert_no_duplicates(creds)

    def test_query_safety(self):
        query = runner.build_query(user_input)
        assert_neo4j_params_safe(query)
"""

import re
import sys
from pathlib import Path
from typing import List, Dict, Any, Optional, Set

# Ensure crack package is importable
PROJECT_ROOT = Path(__file__).parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tools.post.prism.models.credential import Credential, CredentialType


# =============================================================================
# Credential Assertions
# =============================================================================

def assert_credential_valid(credential: Credential, context: str = "") -> None:
    """
    Assert credential has all required fields properly populated.

    BV: Catches data corruption from parsing or serialization errors.

    Args:
        credential: Credential to validate.
        context: Optional context for error message.

    Raises:
        AssertionError: If credential is invalid with details.

    Validations:
        - username is non-empty string
        - domain is string (can be empty)
        - cred_type is valid CredentialType enum
        - value is string (can be empty for null passwords)
    """
    prefix = f"[{context}] " if context else ""

    assert credential is not None, f"{prefix}Credential is None"

    assert isinstance(credential.username, str), \
        f"{prefix}Credential.username must be str, got {type(credential.username)}"
    assert len(credential.username) > 0, \
        f"{prefix}Credential.username is empty"

    assert isinstance(credential.domain, str), \
        f"{prefix}Credential.domain must be str, got {type(credential.domain)}"

    assert isinstance(credential.cred_type, CredentialType), \
        f"{prefix}Credential.cred_type must be CredentialType enum, got {type(credential.cred_type)}"

    assert isinstance(credential.value, str), \
        f"{prefix}Credential.value must be str, got {type(credential.value)}"


def assert_credential_matches(
    actual: Credential,
    expected: Dict[str, Any],
    context: str = ""
) -> None:
    """
    Assert credential matches expected field values.

    BV: Verifies parsing accuracy for specific fields.

    Args:
        actual: Credential to check.
        expected: Dict of field->value expectations.
        context: Optional context for error message.

    Raises:
        AssertionError: If any field doesn't match.

    Example:
        assert_credential_matches(cred, {
            "username": "administrator",
            "domain": "CORP",
            "cred_type": CredentialType.NTLM
        })
    """
    prefix = f"[{context}] " if context else ""

    for field, expected_value in expected.items():
        actual_value = getattr(actual, field, None)
        assert actual_value == expected_value, \
            f"{prefix}Credential.{field} mismatch: expected {expected_value!r}, got {actual_value!r}"


def assert_no_duplicates(credentials: List[Credential], context: str = "") -> None:
    """
    Assert no duplicate credentials by dedup_key.

    BV: Verifies deduplication correctness - prevents clutter and false positives.

    Args:
        credentials: List of credentials to check.
        context: Optional context for error message.

    Raises:
        AssertionError: If duplicates found with details.
    """
    prefix = f"[{context}] " if context else ""

    seen: Set[tuple] = set()
    duplicates: List[Credential] = []

    for cred in credentials:
        key = cred.dedup_key
        if key in seen:
            duplicates.append(cred)
        else:
            seen.add(key)

    assert len(duplicates) == 0, \
        f"{prefix}Found {len(duplicates)} duplicate credentials: {duplicates[:3]}"


def assert_high_value_credentials(
    credentials: List[Credential],
    min_count: int = 1,
    context: str = ""
) -> None:
    """
    Assert minimum number of high-value credentials present.

    BV: Ensures high-value creds are correctly identified for prioritization.

    Args:
        credentials: List of credentials to check.
        min_count: Minimum expected high-value credentials.
        context: Optional context for error message.

    Raises:
        AssertionError: If fewer than min_count high-value creds found.
    """
    prefix = f"[{context}] " if context else ""

    high_value = [c for c in credentials if c.high_value]
    assert len(high_value) >= min_count, \
        f"{prefix}Expected at least {min_count} high-value credentials, found {len(high_value)}"


def assert_credential_type_count(
    credentials: List[Credential],
    cred_type: CredentialType,
    expected_count: int,
    context: str = ""
) -> None:
    """
    Assert exact count of credentials with specific type.

    BV: Verifies parser extracts all expected credential types.

    Args:
        credentials: List of credentials to check.
        cred_type: Credential type to count.
        expected_count: Expected count for this type.
        context: Optional context for error message.

    Raises:
        AssertionError: If count doesn't match.
    """
    prefix = f"[{context}] " if context else ""

    actual_count = sum(1 for c in credentials if c.cred_type == cred_type)
    assert actual_count == expected_count, \
        f"{prefix}Expected {expected_count} {cred_type.value} credentials, found {actual_count}"


# =============================================================================
# Neo4j Query Safety Assertions
# =============================================================================

# Pattern to detect potential Cypher injection
UNSAFE_CYPHER_PATTERNS = [
    r"['\"].*\+.*['\"]",  # String concatenation
    r"\$\{.*\}",          # Template literal injection
    r"[^$]\w+\s*=\s*['\"]",  # Direct string assignment (not parameterized)
]


def assert_neo4j_params_safe(query: str, params: Dict[str, Any] = None, context: str = "") -> None:
    """
    Assert Neo4j query uses safe parameter binding.

    BV: Prevents Cypher injection vulnerabilities in dynamic queries.

    Args:
        query: Cypher query string.
        params: Query parameters dict.
        context: Optional context for error message.

    Raises:
        AssertionError: If query appears to use unsafe patterns.

    Checks:
        - No string concatenation in WHERE clauses
        - Parameters use $param syntax
        - No template literal injection patterns
    """
    prefix = f"[{context}] " if context else ""

    # Check for unsafe patterns
    for pattern in UNSAFE_CYPHER_PATTERNS:
        if re.search(pattern, query):
            assert False, \
                f"{prefix}Query contains potentially unsafe pattern matching '{pattern}': {query[:100]}..."

    # If params provided, check they're referenced in query
    if params:
        for param_name in params.keys():
            param_ref = f"${param_name}"
            # Params should be referenced (unless for UNWIND etc.)
            if param_ref not in query and f"${{{param_name}}}" not in query:
                # This is a warning, not necessarily an error
                pass

    # Check for common injection patterns in WHERE clauses
    where_match = re.search(r"WHERE\s+.*", query, re.IGNORECASE)
    if where_match:
        where_clause = where_match.group(0)
        # Should use parameters, not inline strings with user data
        if re.search(r"=\s*['\"][^$]", where_clause):
            assert False, \
                f"{prefix}WHERE clause appears to use inline strings instead of parameters: {where_clause[:50]}..."


def assert_neo4j_query_valid(query: str, context: str = "") -> None:
    """
    Assert Neo4j query has valid basic structure.

    BV: Catches malformed queries before database execution.

    Args:
        query: Cypher query string.
        context: Optional context for error message.

    Raises:
        AssertionError: If query structure is invalid.

    Checks:
        - Non-empty query
        - Contains Cypher keyword (MATCH, CREATE, MERGE, etc.)
        - Balanced parentheses and brackets
    """
    prefix = f"[{context}] " if context else ""

    assert query and len(query.strip()) > 0, \
        f"{prefix}Query is empty"

    # Must contain at least one Cypher keyword
    cypher_keywords = ['MATCH', 'CREATE', 'MERGE', 'DELETE', 'RETURN', 'WITH', 'UNWIND', 'CALL']
    has_keyword = any(kw in query.upper() for kw in cypher_keywords)
    assert has_keyword, \
        f"{prefix}Query missing Cypher keyword: {query[:50]}..."

    # Check balanced parentheses
    paren_count = query.count('(') - query.count(')')
    assert paren_count == 0, \
        f"{prefix}Unbalanced parentheses in query (diff={paren_count}): {query[:50]}..."

    # Check balanced brackets
    bracket_count = query.count('[') - query.count(']')
    assert bracket_count == 0, \
        f"{prefix}Unbalanced brackets in query (diff={bracket_count}): {query[:50]}..."


# =============================================================================
# Collection Assertions
# =============================================================================

def assert_contains_credential_with(
    credentials: List[Credential],
    **field_values
) -> Credential:
    """
    Assert list contains credential matching all specified field values.

    BV: Verifies specific credential was extracted from output.

    Args:
        credentials: List of credentials to search.
        **field_values: Field-value pairs to match.

    Returns:
        The matching Credential.

    Raises:
        AssertionError: If no matching credential found.

    Example:
        cred = assert_contains_credential_with(
            creds, username="administrator", domain="CORP"
        )
    """
    for cred in credentials:
        matches = all(
            getattr(cred, field, None) == value
            for field, value in field_values.items()
        )
        if matches:
            return cred

    assert False, \
        f"No credential found matching {field_values} in {len(credentials)} credentials"


def assert_all_credentials_have(
    credentials: List[Credential],
    field: str,
    context: str = ""
) -> None:
    """
    Assert all credentials have non-empty value for specified field.

    BV: Ensures parser populates required fields for all credentials.

    Args:
        credentials: List of credentials to check.
        field: Field name to verify.
        context: Optional context for error message.

    Raises:
        AssertionError: If any credential missing the field value.
    """
    prefix = f"[{context}] " if context else ""

    missing = []
    for i, cred in enumerate(credentials):
        value = getattr(cred, field, None)
        if value is None or (isinstance(value, str) and len(value) == 0):
            missing.append((i, cred))

    assert len(missing) == 0, \
        f"{prefix}Found {len(missing)} credentials with missing '{field}': {missing[:3]}"


# =============================================================================
# Summary Assertions
# =============================================================================

def assert_summary_not_empty(summary, context: str = "") -> None:
    """
    Assert parsed summary contains at least some data.

    BV: Verifies parser actually extracted something from input.

    Args:
        summary: ParsedSummary to check.
        context: Optional context for error message.

    Raises:
        AssertionError: If summary is completely empty.
    """
    prefix = f"[{context}] " if context else ""

    has_data = (
        len(getattr(summary, 'credentials', [])) > 0 or
        len(getattr(summary, 'sessions', [])) > 0 or
        len(getattr(summary, 'tickets', [])) > 0
    )

    assert has_data, \
        f"{prefix}ParsedSummary contains no data (credentials, sessions, or tickets)"


def assert_summary_source_valid(summary, expected_tool: str = None, context: str = "") -> None:
    """
    Assert summary has valid source metadata.

    BV: Ensures source tracking for audit/provenance.

    Args:
        summary: ParsedSummary to check.
        expected_tool: Expected source_tool value (optional).
        context: Optional context for error message.

    Raises:
        AssertionError: If source metadata is invalid.
    """
    prefix = f"[{context}] " if context else ""

    assert hasattr(summary, 'source_file'), \
        f"{prefix}Summary missing source_file attribute"
    assert hasattr(summary, 'source_tool'), \
        f"{prefix}Summary missing source_tool attribute"

    if expected_tool:
        assert summary.source_tool == expected_tool, \
            f"{prefix}Summary source_tool mismatch: expected {expected_tool!r}, got {summary.source_tool!r}"


# =============================================================================
# Aggregated Assertions Class (for fixture injection)
# =============================================================================

class CrackAssertions:
    """
    Collection of all assertion helpers for fixture injection.

    Usage via pytest fixture:
        def test_something(assertions):
            assertions.assert_credential_valid(cred)
            assertions.assert_no_duplicates(creds)
    """

    # Credential assertions
    assert_credential_valid = staticmethod(assert_credential_valid)
    assert_credential_matches = staticmethod(assert_credential_matches)
    assert_no_duplicates = staticmethod(assert_no_duplicates)
    assert_high_value_credentials = staticmethod(assert_high_value_credentials)
    assert_credential_type_count = staticmethod(assert_credential_type_count)
    assert_contains_credential_with = staticmethod(assert_contains_credential_with)
    assert_all_credentials_have = staticmethod(assert_all_credentials_have)

    # Neo4j assertions
    assert_neo4j_params_safe = staticmethod(assert_neo4j_params_safe)
    assert_neo4j_query_valid = staticmethod(assert_neo4j_query_valid)

    # Summary assertions
    assert_summary_not_empty = staticmethod(assert_summary_not_empty)
    assert_summary_source_valid = staticmethod(assert_summary_source_valid)


# Export all assertion functions
__all__ = [
    # Credential assertions
    "assert_credential_valid",
    "assert_credential_matches",
    "assert_no_duplicates",
    "assert_high_value_credentials",
    "assert_credential_type_count",
    "assert_contains_credential_with",
    "assert_all_credentials_have",
    # Neo4j assertions
    "assert_neo4j_params_safe",
    "assert_neo4j_query_valid",
    # Summary assertions
    "assert_summary_not_empty",
    "assert_summary_source_valid",
    # Aggregated class
    "CrackAssertions",
]
