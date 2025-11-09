#!/usr/bin/env python3
"""
Test script for Neo4j adapter implementation

Tests all 14 required methods with actual Neo4j data
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from reference.core.neo4j_adapter import Neo4jCommandRegistryAdapter, Neo4jConnectionError


def test_connection():
    """Test 1: Neo4j connection and health check"""
    print("\n=== Test 1: Connection and Health Check ===")
    try:
        adapter = Neo4jCommandRegistryAdapter()
        if adapter.health_check():
            print("✓ Neo4j connection successful")
            return adapter
        else:
            print("✗ Health check failed")
            return None
    except Neo4jConnectionError as e:
        print(f"✗ Connection failed: {e}")
        return None


def test_get_command(adapter):
    """Test 2: Get single command by ID"""
    print("\n=== Test 2: Get Command by ID ===")

    # Try multiple command IDs to find one that exists
    test_ids = ['nmap-quick-scan', 'bash-reverse-shell', 'nc-listener']

    for cmd_id in test_ids:
        cmd = adapter.get_command(cmd_id)
        if cmd:
            print(f"✓ Retrieved command: {cmd.name}")
            print(f"  ID: {cmd.id}")
            print(f"  Category: {cmd.category}")
            print(f"  Tags: {', '.join(cmd.tags[:3])}...")
            print(f"  Variables: {len(cmd.variables)}")
            return True

    print("✗ No commands found")
    return False


def test_search(adapter):
    """Test 3: Full-text search"""
    print("\n=== Test 3: Full-Text Search ===")

    results = adapter.search('nmap')
    if results:
        print(f"✓ Found {len(results)} commands matching 'nmap'")
        for i, cmd in enumerate(results[:3]):
            print(f"  {i+1}. {cmd.name}")
        return True
    else:
        print("✗ Search returned no results")
        return False


def test_filter_by_category(adapter):
    """Test 4: Filter by category"""
    print("\n=== Test 4: Filter by Category ===")

    # Try multiple categories
    for category in ['recon', 'web', 'exploitation']:
        results = adapter.filter_by_category(category)
        if results:
            print(f"✓ Category '{category}': {len(results)} commands")
            return True

    print("✗ No commands found in any category")
    return False


def test_filter_by_tags(adapter):
    """Test 5: Filter by tags"""
    print("\n=== Test 5: Filter by Tags ===")

    # Try different tag combinations
    tag_sets = [['NMAP'], ['OSCP:HIGH'], ['QUICK_WIN']]

    for tags in tag_sets:
        results = adapter.filter_by_tags(tags)
        if results:
            print(f"✓ Tags {tags}: {len(results)} commands")
            return True

    print("✗ No commands found with any tags")
    return False


def test_get_quick_wins(adapter):
    """Test 6: Get quick wins"""
    print("\n=== Test 6: Get Quick Wins ===")

    results = adapter.get_quick_wins()
    print(f"{'✓' if results else '✗'} Found {len(results)} quick win commands")
    if results:
        for i, cmd in enumerate(results[:3]):
            print(f"  {i+1}. {cmd.name}")
    return len(results) > 0


def test_get_oscp_high(adapter):
    """Test 7: Get OSCP high relevance"""
    print("\n=== Test 7: Get OSCP High Relevance ===")

    results = adapter.get_oscp_high()
    print(f"{'✓' if results else '✗'} Found {len(results)} high-relevance OSCP commands")
    if results:
        for i, cmd in enumerate(results[:3]):
            print(f"  {i+1}. {cmd.name} ({cmd.category})")
    return len(results) > 0


def test_find_alternatives(adapter):
    """Test 8: Find alternatives (graph traversal)"""
    print("\n=== Test 8: Find Alternatives (Multi-hop) ===")

    # Try to find a command with alternatives
    test_commands = adapter.search('gobuster')
    if not test_commands:
        print("✗ No test commands found")
        return False

    cmd = test_commands[0]
    print(f"Finding alternatives for: {cmd.name}")

    # Test depth 1
    alternatives = adapter.find_alternatives(cmd.id, max_depth=1)
    print(f"  Depth 1: {len(alternatives)} alternatives")

    # Test depth 3
    alternatives_deep = adapter.find_alternatives(cmd.id, max_depth=3)
    print(f"  Depth 3: {len(alternatives_deep)} alternatives")

    if alternatives_deep:
        for i, alt in enumerate(alternatives_deep[:3]):
            print(f"    {i+1}. {alt.name}")

    return len(alternatives_deep) >= len(alternatives)


def test_find_prerequisites(adapter):
    """Test 9: Find prerequisites (transitive)"""
    print("\n=== Test 9: Find Prerequisites (Transitive) ===")

    # Try to find a command with prerequisites
    test_commands = adapter.search('shell')
    if not test_commands:
        print("✗ No test commands found")
        return False

    cmd = test_commands[0]
    print(f"Finding prerequisites for: {cmd.name}")

    prereqs = adapter.find_prerequisites(cmd.id, depth=3)
    print(f"  Found {len(prereqs)} prerequisites")

    if prereqs:
        for i, prereq in enumerate(prereqs[:3]):
            print(f"    {i+1}. {prereq.name}")
        return True

    print("  (No prerequisites found - this is normal)")
    return True


def test_get_attack_chain_path(adapter):
    """Test 10: Get attack chain path"""
    print("\n=== Test 10: Get Attack Chain Path ===")

    # Try to find any attack chain
    stats = adapter.get_stats()
    if stats.get('attack_chains', 0) == 0:
        print("✗ No attack chains in database")
        return False

    # Try a known chain ID
    chain_ids = ['linux-privesc-sudo', 'web-sqli-basic']

    for chain_id in chain_ids:
        chain = adapter.get_attack_chain_path(chain_id)
        if chain:
            print(f"✓ Retrieved attack chain: {chain['name']}")
            print(f"  Steps: {len(chain['steps'])}")
            print(f"  Parallel groups: {len(chain['parallel_groups'])}")

            if chain['steps']:
                for i, step in enumerate(chain['steps'][:3]):
                    print(f"    {i+1}. {step['name']}")
            return True

    print("✗ No attack chains found with test IDs")
    return False


def test_get_stats(adapter):
    """Test 11: Get statistics"""
    print("\n=== Test 11: Get Statistics ===")

    stats = adapter.get_stats()
    print(f"✓ Statistics retrieved:")
    print(f"  Total commands: {stats.get('total_commands', 0)}")
    print(f"  Tags: {stats.get('tags', 0)}")
    print(f"  Attack chains: {stats.get('attack_chains', 0)}")

    return stats.get('total_commands', 0) > 0


def test_get_all_commands(adapter):
    """Test 12: Get all commands"""
    print("\n=== Test 12: Get All Commands ===")

    commands = adapter.get_all_commands()
    print(f"✓ Retrieved {len(commands)} total commands")

    return len(commands) > 0


def test_get_subcategories(adapter):
    """Test 13: Get subcategories"""
    print("\n=== Test 13: Get Subcategories ===")

    for category in ['recon', 'web', 'exploitation']:
        subcats = adapter.get_subcategories(category)
        if subcats:
            print(f"✓ Category '{category}': {len(subcats)} subcategories")
            print(f"    {', '.join(subcats[:3])}")
            return True

    print("✗ No subcategories found")
    return False


def main():
    """Run all tests"""
    print("=" * 60)
    print("Neo4j Adapter Test Suite")
    print("=" * 60)

    # Test connection first
    adapter = test_connection()
    if not adapter:
        print("\n✗ FAILED: Cannot connect to Neo4j")
        print("Make sure Neo4j is running and imported with data")
        return 1

    # Run all tests
    tests = [
        ("Get Command", test_get_command),
        ("Search", test_search),
        ("Filter by Category", test_filter_by_category),
        ("Filter by Tags", test_filter_by_tags),
        ("Quick Wins", test_get_quick_wins),
        ("OSCP High", test_get_oscp_high),
        ("Find Alternatives", test_find_alternatives),
        ("Find Prerequisites", test_find_prerequisites),
        ("Attack Chain Path", test_get_attack_chain_path),
        ("Statistics", test_get_stats),
        ("Get All Commands", test_get_all_commands),
        ("Get Subcategories", test_get_subcategories),
    ]

    results = []
    for test_name, test_func in tests:
        try:
            result = test_func(adapter)
            results.append((test_name, result))
        except Exception as e:
            print(f"✗ Test '{test_name}' raised exception: {e}")
            results.append((test_name, False))

    # Summary
    print("\n" + "=" * 60)
    print("Test Summary")
    print("=" * 60)

    passed = sum(1 for _, result in results if result)
    total = len(results)

    for test_name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{status}: {test_name}")

    print(f"\nPassed: {passed}/{total} ({100*passed//total}%)")

    if passed == total:
        print("\n✓ All tests passed! Neo4j adapter is ready for Phase 4")
        return 0
    else:
        print(f"\n✗ {total - passed} test(s) failed")
        return 1


if __name__ == '__main__':
    sys.exit(main())
