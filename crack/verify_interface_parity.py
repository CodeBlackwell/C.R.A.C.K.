#!/usr/bin/env python3
"""
Verify interface parity between SQL and Neo4j adapters

Ensures both adapters have identical method signatures for seamless router integration
"""

import inspect
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from reference.core.sql_adapter import SQLCommandRegistryAdapter
from reference.core.neo4j_adapter import Neo4jCommandRegistryAdapter, Neo4jConnectionError


def get_public_methods(cls):
    """Get all public methods from a class"""
    methods = {}
    for name, method in inspect.getmembers(cls, predicate=inspect.ismethod):
        if not name.startswith('_'):
            try:
                sig = inspect.signature(method)
                methods[name] = {
                    'signature': str(sig),
                    'params': list(sig.parameters.keys())
                }
            except:
                pass

    # Also check for wrapped functions (like @lru_cache)
    for name in dir(cls):
        if name.startswith('_') or name in methods:
            continue
        attr = getattr(cls, name)
        if callable(attr):
            try:
                sig = inspect.signature(attr)
                methods[name] = {
                    'signature': str(sig),
                    'params': list(sig.parameters.keys())
                }
            except:
                pass

    return methods


def main():
    """Compare interfaces"""
    print("=" * 70)
    print("Interface Parity Verification: SQL vs Neo4j Adapters")
    print("=" * 70)

    # Get methods from both adapters
    sql_methods = get_public_methods(SQLCommandRegistryAdapter)
    neo4j_methods = get_public_methods(Neo4jCommandRegistryAdapter)

    # Required methods (from spec)
    required_methods = [
        'get_command',
        'search',
        'filter_by_category',
        'filter_by_tags',
        'get_quick_wins',
        'get_oscp_high',
        'find_alternatives',
        'find_prerequisites',
        'get_attack_chain_path',
        'get_stats',
        'health_check',
        'interactive_fill',
        'get_all_commands',
        'get_subcategories',
    ]

    print(f"\nRequired Methods: {len(required_methods)}")
    print("-" * 70)

    all_present = True
    signature_matches = []
    signature_mismatches = []

    for method_name in required_methods:
        sql_present = method_name in sql_methods
        neo4j_present = method_name in neo4j_methods

        if sql_present and neo4j_present:
            # Compare signatures
            sql_sig = sql_methods[method_name]['signature']
            neo4j_sig = neo4j_methods[method_name]['signature']

            # Normalize signatures (remove self)
            sql_params = [p for p in sql_methods[method_name]['params'] if p != 'self']
            neo4j_params = [p for p in neo4j_methods[method_name]['params'] if p != 'self']

            if sql_params == neo4j_params:
                signature_matches.append(method_name)
                print(f"✓ {method_name:30} - Both adapters")
            else:
                signature_mismatches.append({
                    'method': method_name,
                    'sql': sql_params,
                    'neo4j': neo4j_params
                })
                print(f"⚠ {method_name:30} - Signature mismatch")
                all_present = False
        elif sql_present:
            print(f"✗ {method_name:30} - Only in SQL adapter")
            all_present = False
        elif neo4j_present:
            print(f"✗ {method_name:30} - Only in Neo4j adapter")
            all_present = False
        else:
            print(f"✗ {method_name:30} - Missing from both adapters")
            all_present = False

    # Check for extra methods
    print("\n" + "=" * 70)
    print("Additional Methods (Not Required)")
    print("-" * 70)

    sql_extra = set(sql_methods.keys()) - set(required_methods)
    neo4j_extra = set(neo4j_methods.keys()) - set(required_methods)

    if sql_extra:
        print(f"\nSQL-only methods ({len(sql_extra)}):")
        for method in sorted(sql_extra):
            print(f"  - {method}")

    if neo4j_extra:
        print(f"\nNeo4j-only methods ({len(neo4j_extra)}):")
        for method in sorted(neo4j_extra):
            print(f"  - {method}")

    # Signature mismatch details
    if signature_mismatches:
        print("\n" + "=" * 70)
        print("Signature Mismatches")
        print("-" * 70)
        for mismatch in signature_mismatches:
            print(f"\nMethod: {mismatch['method']}")
            print(f"  SQL:    {mismatch['sql']}")
            print(f"  Neo4j:  {mismatch['neo4j']}")

    # Summary
    print("\n" + "=" * 70)
    print("Summary")
    print("=" * 70)
    print(f"Required methods present: {len(signature_matches)}/{len(required_methods)}")
    print(f"Signature matches: {len(signature_matches)}")
    print(f"Signature mismatches: {len(signature_mismatches)}")

    if all_present and len(signature_mismatches) == 0:
        print("\n✓ PASS: Both adapters have identical interfaces")
        print("✓ Router integration ready for Phase 4")
        return 0
    else:
        print(f"\n✗ FAIL: Interface parity issues detected")
        return 1


if __name__ == '__main__':
    sys.exit(main())
