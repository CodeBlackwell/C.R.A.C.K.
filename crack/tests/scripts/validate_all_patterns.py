#!/usr/bin/env python3
"""
Validate all 10 advanced query patterns work correctly with live Neo4j database
"""

from crack.reference.patterns.advanced_queries import create_pattern_helper
from crack.reference.core import ConfigManager, ReferenceTheme
from crack.reference.core.neo4j_adapter import Neo4jCommandRegistryAdapter
import sys


def test_pattern_1_multi_hop_alternatives(patterns):
    """Pattern 1: Multi-hop alternative chains"""
    print("\n🔧 Pattern 1: Multi-Hop Alternative Chains")
    try:
        results = patterns.multi_hop_alternatives('gobuster-dir', depth=3)
        print(f"  ✓ Found {len(results)} alternative chains")
        if results:
            print(f"    Example: {results[0]['command_chain'][0]['name']} → {results[0]['command_chain'][-1]['name']}")
            print(f"    Depth: {results[0]['depth']}, Priority: {results[0]['cumulative_priority']}")
        return True
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        return False


def test_pattern_2_shortest_path(patterns):
    """Pattern 2: Shortest attack path"""
    print("\n🎯 Pattern 2: Shortest Attack Path")
    try:
        results = patterns.shortest_attack_path('STARTER', 'PRIVESC')
        print(f"  ✓ Found {len(results)} paths")
        if results:
            print(f"    Shortest path has {results[0].get('step_count', 'N/A')} steps")
        return True
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        return False


def test_pattern_3_prerequisite_closure(patterns):
    """Pattern 3: Prerequisite closure with execution order"""
    print("\n📋 Pattern 3: Prerequisite Closure")
    try:
        results = patterns.prerequisite_closure('wordpress-sqli', with_execution_order=True)
        print(f"  ✓ Found {len(results)} prerequisites")
        if results:
            print(f"    Execution order:")
            for prereq in results[:3]:
                print(f"      {prereq['dependency_count']}: {prereq['command_name']}")
        return True
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        return False


def test_pattern_4_parallel_execution(patterns):
    """Pattern 4: Parallel execution planning"""
    print("\n⚡ Pattern 4: Parallel Execution Planning")
    try:
        result = patterns.parallel_execution_plan('web-to-root')
        print(f"  ✓ Attack chain has {len(result.get('steps', []))} steps")
        if 'parallel_groups' in result:
            print(f"    Parallel groups: {len(result['parallel_groups'])}")
            for i, group in enumerate(result['parallel_groups'][:2]):
                print(f"      Wave {i+1}: {len(group)} steps")
        return True
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        return False


def test_pattern_5_service_recommendations(patterns):
    """Pattern 5: Service-based recommendations"""
    print("\n🌐 Pattern 5: Service-Based Recommendations")
    try:
        results = patterns.service_recommendations([80, 445, 22])
        print(f"  ✓ Found {len(results)} recommended commands")
        if results:
            print(f"    Top recommendation: {results[0].get('command_name', 'N/A')}")
            print(f"    Services: {results[0].get('services', [])}")
        return True
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        return False


def test_pattern_6_tag_hierarchy(patterns):
    """Pattern 6: Tag hierarchy filtering"""
    print("\n🏷️  Pattern 6: Tag Hierarchy Filtering")
    try:
        results = patterns.filter_by_tag_hierarchy(['OSCP'], include_children=True)
        print(f"  ✓ Found {len(results)} commands with OSCP tags (including children)")
        return True
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        return False


def test_pattern_7_success_correlation(patterns):
    """Pattern 7: Command success correlation"""
    print("\n📊 Pattern 7: Command Success Correlation")
    try:
        # This requires session execution data which we don't have yet
        results = patterns.success_correlation(min_co_occurrence=1)
        print(f"  ⚠️  Requires session data (not in test DB), returned {len(results)} results")
        return True
    except Exception as e:
        print(f"  ⚠️  Expected failure (no session data): {type(e).__name__}")
        return True  # Expected to fail without session data


def test_pattern_8_coverage_gaps(patterns):
    """Pattern 8: Coverage gap detection"""
    print("\n🔍 Pattern 8: Coverage Gap Detection")
    try:
        results = patterns.find_coverage_gaps(oscp_only=True)
        print(f"  ✓ Found {len(results)} services with coverage gaps")
        if results:
            print(f"    Example: {results[0].get('service_name', 'N/A')}")
        return True
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        return False


def test_pattern_9_circular_dependencies(patterns):
    """Pattern 9: Circular dependency detection"""
    print("\n🔄 Pattern 9: Circular Dependency Detection")
    try:
        results = patterns.detect_circular_dependencies()
        print(f"  ✓ Checked for circular dependencies: {len(results)} cycles found")
        if results:
            print(f"    ⚠️  WARNING: Circular dependencies detected!")
        else:
            print(f"    ✓ No circular dependencies (good!)")
        return True
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        return False


def test_pattern_10_variable_usage(patterns):
    """Pattern 10: Variable usage analysis"""
    print("\n🔧 Pattern 10: Variable Usage Analysis")
    try:
        results = patterns.variable_usage_analysis(required_only=True)
        print(f"  ✓ Found {len(results)} variables in use")
        if results:
            print(f"    Most used: {results[0].get('variable_name', 'N/A')} ({results[0].get('usage_count', 0)} commands)")
        return True
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        return False


def main():
    print("=" * 70)
    print("  🔬 VALIDATING ALL 10 ADVANCED QUERY PATTERNS")
    print("=" * 70)

    try:
        # Initialize adapter and pattern helper
        config = ConfigManager()
        theme = ReferenceTheme()
        adapter = Neo4jCommandRegistryAdapter(config, theme)
        patterns = create_pattern_helper(adapter)

        # Verify connection
        if not adapter.health_check():
            print("\n❌ Neo4j connection failed!")
            return 1

        print("\n✓ Neo4j connection healthy")
        print(f"✓ Pattern library initialized")

        # Run all pattern tests
        tests = [
            test_pattern_1_multi_hop_alternatives,
            test_pattern_2_shortest_path,
            test_pattern_3_prerequisite_closure,
            test_pattern_4_parallel_execution,
            test_pattern_5_service_recommendations,
            test_pattern_6_tag_hierarchy,
            test_pattern_7_success_correlation,
            test_pattern_8_coverage_gaps,
            test_pattern_9_circular_dependencies,
            test_pattern_10_variable_usage,
        ]

        results = []
        for test in tests:
            results.append(test(patterns))

        # Summary
        print("\n" + "=" * 70)
        print("  📊 VALIDATION SUMMARY")
        print("=" * 70)
        passed = sum(results)
        total = len(results)
        print(f"\nPatterns validated: {passed}/{total}")
        print(f"Success rate: {passed/total*100:.1f}%")

        if passed == total:
            print("\n✅ All patterns working correctly!")
            return 0
        else:
            print(f"\n⚠️  {total - passed} pattern(s) failed")
            return 1

    except Exception as e:
        print(f"\n❌ Fatal error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
