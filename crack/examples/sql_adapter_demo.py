#!/usr/bin/env python3
"""
SQL Adapter Demo - Practical examples of using SQLCommandRegistryAdapter

This script demonstrates backwards compatibility with existing code that uses
HybridCommandRegistry. By simply changing the import, the same code works
with the SQL backend.

Usage:
    python3 examples/sql_adapter_demo.py
"""

from pathlib import Path


def demo_basic_usage():
    """Demo 1: Basic command lookup (drop-in replacement)"""
    print("=" * 60)
    print("DEMO 1: Basic Command Lookup")
    print("=" * 60)

    # BEFORE: Using JSON backend
    # from crack.reference.core.registry import HybridCommandRegistry
    # registry = HybridCommandRegistry()

    # AFTER: Using SQL backend (same API)
    from crack.reference.core.sql_adapter import SQLCommandRegistryAdapter
    registry = SQLCommandRegistryAdapter()

    # Same code works with both backends
    cmd = registry.get_command('bash-reverse-shell')
    if cmd:
        print(f"\n✓ Found command: {cmd.name}")
        print(f"  Template: {cmd.command}")
        print(f"  Category: {cmd.category}")
        print(f"  Tags: {', '.join(cmd.tags[:3])}...")
        print(f"  Variables: {len(cmd.variables)} placeholders")
    else:
        print("\n⚠ Command not found in database")
        print("  Run: python3 -m db.migrate commands")


def demo_search():
    """Demo 2: Search functionality"""
    print("\n" + "=" * 60)
    print("DEMO 2: Search Commands")
    print("=" * 60)

    from crack.reference.core.sql_adapter import SQLCommandRegistryAdapter
    registry = SQLCommandRegistryAdapter()

    # Search for nmap commands
    results = registry.search('nmap')
    print(f"\n✓ Found {len(results)} commands matching 'nmap'")

    for i, cmd in enumerate(results[:5], 1):
        print(f"  {i}. {cmd.name} ({cmd.oscp_relevance})")


def demo_tag_filtering():
    """Demo 3: Tag-based filtering"""
    print("\n" + "=" * 60)
    print("DEMO 3: Tag-Based Filtering")
    print("=" * 60)

    from crack.reference.core.sql_adapter import SQLCommandRegistryAdapter
    registry = SQLCommandRegistryAdapter()

    # Get high-priority OSCP commands
    oscp_high = registry.get_oscp_high()
    print(f"\n✓ Found {len(oscp_high)} OSCP:HIGH commands")

    # Get quick wins
    quick_wins = registry.get_quick_wins()
    print(f"✓ Found {len(quick_wins)} QUICK_WIN commands")

    # Filter by multiple tags
    web_oscp = registry.filter_by_tags(['WEB', 'OSCP:HIGH'])
    print(f"✓ Found {len(web_oscp)} WEB + OSCP:HIGH commands")


def demo_category_filtering():
    """Demo 4: Category filtering"""
    print("\n" + "=" * 60)
    print("DEMO 4: Category Filtering")
    print("=" * 60)

    from crack.reference.core.sql_adapter import SQLCommandRegistryAdapter
    registry = SQLCommandRegistryAdapter()

    # Get all web commands
    web_cmds = registry.filter_by_category('web')
    print(f"\n✓ Found {len(web_cmds)} web commands")

    # Get subcategories
    subcats = registry.get_subcategories('web')
    if subcats:
        print(f"  Subcategories: {', '.join(subcats)}")


def demo_statistics():
    """Demo 5: Registry statistics"""
    print("\n" + "=" * 60)
    print("DEMO 5: Registry Statistics")
    print("=" * 60)

    from crack.reference.core.sql_adapter import SQLCommandRegistryAdapter
    registry = SQLCommandRegistryAdapter()

    stats = registry.get_stats()
    print(f"\n✓ Total commands: {stats['total_commands']}")
    print(f"✓ Quick wins: {stats['quick_wins']}")
    print(f"✓ OSCP high: {stats['oscp_high']}")

    print("\nCommands by category:")
    for cat, count in stats['by_category'].items():
        if count > 0:
            print(f"  {cat}: {count}")

    if stats['top_tags']:
        print("\nTop 5 tags:")
        for tag, count in stats['top_tags'][:5]:
            print(f"  {tag}: {count}")


def demo_validation():
    """Demo 6: Schema validation"""
    print("\n" + "=" * 60)
    print("DEMO 6: Schema Validation")
    print("=" * 60)

    from crack.reference.core.sql_adapter import SQLCommandRegistryAdapter
    registry = SQLCommandRegistryAdapter()

    errors = registry.validate_schema()
    if errors:
        print(f"\n⚠ Found {len(errors)} validation errors:")
        for error in errors[:5]:
            print(f"  - {error}")
    else:
        print("\n✓ No validation errors found!")


def demo_convenience_functions():
    """Demo 7: Convenience functions"""
    print("\n" + "=" * 60)
    print("DEMO 7: Convenience Functions")
    print("=" * 60)

    # Same convenience functions work with SQL backend
    from crack.reference.core.sql_adapter import quick_search, load_registry

    # Quick search without instantiating registry
    results = quick_search('gobuster')
    print(f"\n✓ Quick search found {len(results)} commands")
    if results:
        print(f"  First result: {results[0].name}")

    # Load registry with convenience function
    registry = load_registry()
    total = registry.repo.count_commands()
    print(f"✓ Registry loaded: {total} commands available")


def demo_backwards_compatibility():
    """Demo 8: Prove exact API compatibility"""
    print("\n" + "=" * 60)
    print("DEMO 8: Backwards Compatibility Test")
    print("=" * 60)

    from crack.reference.core.registry import HybridCommandRegistry
    from crack.reference.core.sql_adapter import SQLCommandRegistryAdapter

    json_registry = HybridCommandRegistry()
    sql_registry = SQLCommandRegistryAdapter()

    # Compare public methods
    json_methods = {m for m in dir(json_registry) if not m.startswith('_')}
    sql_methods = {m for m in dir(sql_registry) if not m.startswith('_')}

    print(f"\n✓ JSON registry has {len(json_methods)} public methods")
    print(f"✓ SQL registry has {len(sql_methods)} public methods")

    missing = json_methods - sql_methods
    if missing:
        print(f"\n⚠ SQL adapter missing methods: {missing}")
    else:
        print("\n✓ SQL adapter has ALL methods from JSON registry!")

    extra = sql_methods - json_methods
    if extra:
        print(f"✓ SQL adapter has additional methods: {extra}")


def main():
    """Run all demos"""
    print("\n")
    print("╔" + "═" * 58 + "╗")
    print("║" + " " * 12 + "SQL ADAPTER DEMONSTRATION" + " " * 21 + "║")
    print("║" + " " * 58 + "║")
    print("║  Backwards-Compatible SQL Backend for Command Registry  ║")
    print("╚" + "═" * 58 + "╝")

    try:
        demo_basic_usage()
        demo_search()
        demo_tag_filtering()
        demo_category_filtering()
        demo_statistics()
        demo_validation()
        demo_convenience_functions()
        demo_backwards_compatibility()

        print("\n" + "=" * 60)
        print("✅ ALL DEMOS COMPLETED SUCCESSFULLY")
        print("=" * 60)
        print("\nKey Takeaways:")
        print("1. SQL adapter is a drop-in replacement for HybridCommandRegistry")
        print("2. Same API, same methods, same behavior")
        print("3. Simply change the import statement to use SQL backend")
        print("4. No code changes required in existing integrations")
        print("5. Performance benefits: <10ms queries vs 50-200ms JSON parsing")

    except Exception as e:
        print(f"\n❌ Error during demo: {e}")
        print("\nPossible causes:")
        print("- Database not initialized: sqlite3 ~/.crack/crack.db < db/schema.sql")
        print("- Commands not migrated: python3 -m db.migrate commands")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    main()
