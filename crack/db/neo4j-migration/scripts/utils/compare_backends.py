#!/usr/bin/env python3
"""
Compare Backends - Quick comparison between JSON and Neo4j data

Usage: python3 compare_backends.py
"""

import json
from pathlib import Path
from collections import Counter

# ANSI colors
class Colors:
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    RED = '\033[31m'
    BLUE = '\033[36m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RESET = '\033[0m'

def get_json_stats():
    """Get statistics from JSON files"""
    stats = {
        'commands': 0,
        'categories': Counter(),
        'oscp_relevance': Counter(),
        'ids': set()
    }

    commands_dir = Path('/home/kali/Desktop/OSCP/crack/reference/data/commands')
    for json_file in commands_dir.rglob('*.json'):
        try:
            with open(json_file) as f:
                data = json.load(f)

            for cmd in data.get('commands', []):
                stats['commands'] += 1
                stats['ids'].add(cmd.get('id'))
                stats['categories'][cmd.get('category', 'MISSING')] += 1
                stats['oscp_relevance'][cmd.get('oscp_relevance', 'MISSING')] += 1

        except Exception:
            pass

    return stats

def get_neo4j_stats():
    """Get statistics from Neo4j"""
    try:
        from crack.reference.core import Neo4jCommandRegistryAdapter, ConfigManager, ReferenceTheme

        adapter = Neo4jCommandRegistryAdapter(
            config_manager=ConfigManager(),
            theme=ReferenceTheme()
        )

        if not adapter.health_check():
            return None

        stats = {
            'commands': 0,
            'categories': Counter(),
            'oscp_relevance': Counter(),
            'ids': set()
        }

        # Get command count
        query = "MATCH (c:Command) RETURN count(c) AS count"
        results = adapter._execute_read(query)
        stats['commands'] = results[0]['count'] if results else 0

        # Get categories
        query = "MATCH (c:Command) RETURN c.category AS category, count(c) AS count"
        results = adapter._execute_read(query)
        for r in results:
            stats['categories'][r['category'] or 'MISSING'] = r['count']

        # Get OSCP relevance
        query = "MATCH (c:Command) RETURN c.oscp_relevance AS relevance, count(c) AS count"
        results = adapter._execute_read(query)
        for r in results:
            stats['oscp_relevance'][r['relevance'] or 'MISSING'] = r['count']

        # Get all IDs
        query = "MATCH (c:Command) RETURN c.id AS id"
        results = adapter._execute_read(query)
        stats['ids'] = {r['id'] for r in results}

        return stats

    except Exception as e:
        return None

def main():
    print(f"\n{Colors.BOLD}{'=' * 70}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.BLUE}JSON vs NEO4J - COMPARISON REPORT{Colors.RESET}")
    print(f"{Colors.BOLD}{'=' * 70}{Colors.RESET}\n")

    # Get stats from both backends
    print("Gathering statistics...")
    json_stats = get_json_stats()
    neo4j_stats = get_neo4j_stats()

    if neo4j_stats is None:
        print(f"{Colors.RED}✗ Neo4j unavailable - cannot compare{Colors.RESET}")
        print(f"{Colors.YELLOW}  Make sure Neo4j is running: sudo neo4j start{Colors.RESET}\n")
        return 1

    print(f"{Colors.GREEN}✓ Data collected from both backends{Colors.RESET}\n")

    # Command counts
    print(f"{Colors.BOLD}Command Counts:{Colors.RESET}")
    print(f"  JSON:   {json_stats['commands']:6d}")
    print(f"  Neo4j:  {neo4j_stats['commands']:6d}")

    diff = json_stats['commands'] - neo4j_stats['commands']
    if diff > 0:
        pct_missing = diff / json_stats['commands'] * 100
        print(f"  {Colors.RED}Missing in Neo4j: {diff:6d} ({pct_missing:.1f}%){Colors.RESET}")
    elif diff < 0:
        print(f"  {Colors.YELLOW}Extra in Neo4j: {-diff:6d}{Colors.RESET}")
    else:
        print(f"  {Colors.GREEN}✓ Counts match{Colors.RESET}")

    # Categories comparison
    print(f"\n{Colors.BOLD}Categories Comparison:{Colors.RESET}")
    all_categories = set(json_stats['categories'].keys()) | set(neo4j_stats['categories'].keys())

    print(f"  {'Category':20s} {'JSON':>8s} {'Neo4j':>8s} {'Diff':>8s}")
    print(f"  {'-' * 50}")

    for category in sorted(all_categories):
        json_count = json_stats['categories'][category]
        neo4j_count = neo4j_stats['categories'][category]
        diff = json_count - neo4j_count

        if diff == 0:
            status = Colors.DIM
        elif diff > 0:
            status = Colors.YELLOW
        else:
            status = Colors.RED

        print(f"  {category:20s} {json_count:8d} {neo4j_count:8d} {status}{diff:+8d}{Colors.RESET}")

    # OSCP relevance comparison
    print(f"\n{Colors.BOLD}OSCP Relevance Comparison:{Colors.RESET}")
    all_relevance = set(json_stats['oscp_relevance'].keys()) | set(neo4j_stats['oscp_relevance'].keys())

    print(f"  {'Relevance':15s} {'JSON':>8s} {'Neo4j':>8s} {'Diff':>8s}")
    print(f"  {'-' * 45}")

    for relevance in ['high', 'medium', 'low', 'MISSING']:
        if relevance in all_relevance:
            json_count = json_stats['oscp_relevance'][relevance]
            neo4j_count = neo4j_stats['oscp_relevance'][relevance]
            diff = json_count - neo4j_count

            if diff == 0:
                status = Colors.DIM
            elif diff > 0:
                status = Colors.YELLOW
            else:
                status = Colors.RED

            print(f"  {relevance:15s} {json_count:8d} {neo4j_count:8d} {status}{diff:+8d}{Colors.RESET}")

    # ID differences
    print(f"\n{Colors.BOLD}Command ID Comparison:{Colors.RESET}")

    json_only = json_stats['ids'] - neo4j_stats['ids']
    neo4j_only = neo4j_stats['ids'] - json_stats['ids']
    common = json_stats['ids'] & neo4j_stats['ids']

    print(f"  Common IDs:           {len(common):6d}")
    print(f"  {Colors.YELLOW}Only in JSON:          {len(json_only):6d}{Colors.RESET}")
    print(f"  {Colors.RED}Only in Neo4j:         {len(neo4j_only):6d}{Colors.RESET}")

    if json_only:
        print(f"\n  {Colors.YELLOW}Sample IDs in JSON but not Neo4j (first 10):{Colors.RESET}")
        for cmd_id in sorted(json_only)[:10]:
            print(f"    - {cmd_id}")
        if len(json_only) > 10:
            print(f"    ... and {len(json_only) - 10} more")

    if neo4j_only:
        print(f"\n  {Colors.RED}Sample IDs in Neo4j but not JSON (first 10):{Colors.RESET}")
        for cmd_id in sorted(neo4j_only)[:10]:
            print(f"    - {cmd_id}")
        if len(neo4j_only) > 10:
            print(f"    ... and {len(neo4j_only) - 10} more")

    # Migration status
    print(f"\n{Colors.BOLD}{'=' * 70}{Colors.RESET}")

    if diff == 0 and not json_only:
        print(f"{Colors.GREEN}✓ Backends in sync - migration complete{Colors.RESET}")
    elif neo4j_stats['commands'] == 0:
        print(f"{Colors.RED}✗ Neo4j database is empty{Colors.RESET}")
        print(f"{Colors.YELLOW}  Action: Run migration script to load {json_stats['commands']} commands{Colors.RESET}")
    elif json_only:
        pct_migrated = len(common) / len(json_stats['ids']) * 100
        print(f"{Colors.YELLOW}⚠ Migration incomplete ({pct_migrated:.1f}% migrated){Colors.RESET}")
        print(f"{Colors.YELLOW}  {len(json_only)} commands still need migration{Colors.RESET}")
    else:
        print(f"{Colors.GREEN}✓ All JSON commands migrated to Neo4j{Colors.RESET}")

    print(f"{Colors.BOLD}{'=' * 70}{Colors.RESET}\n")

    return 0

if __name__ == '__main__':
    main()
