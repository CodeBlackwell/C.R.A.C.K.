#!/usr/bin/env python3
"""
Health check script for CRACK dual-backend system

Tests connectivity to both PostgreSQL and Neo4j databases
and reports on their operational status.

Usage:
    python health_check.py

Exit codes:
    0 - Both databases operational
    1 - PostgreSQL OK, Neo4j DOWN (fallback mode)
    2 - PostgreSQL DOWN (critical)
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../..', '..'))

from typing import Tuple


def check_postgresql() -> Tuple[bool, str]:
    """Test PostgreSQL connection and schema"""
    try:
        import psycopg2
        from db.config import get_db_config

        config = get_db_config()
        conn = psycopg2.connect(**config)
        cursor = conn.cursor()

        cursor.execute("SELECT version();")
        version = cursor.fetchone()[0]
        pg_version = version.split()[1] if version else "unknown"

        cursor.execute("SELECT COUNT(*) FROM commands;")
        count = cursor.fetchone()[0]

        conn.close()
        return True, f"PostgreSQL OK - v{pg_version}, {count} commands"

    except ImportError:
        return False, "PostgreSQL FAILED: psycopg2 not installed"
    except Exception as e:
        return False, f"PostgreSQL FAILED: {e}"


def check_neo4j() -> Tuple[bool, str]:
    """Test Neo4j connection and plugins"""
    try:
        from neo4j import GraphDatabase
        from db.config import get_neo4j_config

        config = get_neo4j_config()
        driver = GraphDatabase.driver(
            config['uri'],
            auth=(config['user'], config['password']),
            max_connection_lifetime=config['max_connection_lifetime'],
            max_connection_pool_size=config['max_connection_pool_size']
        )

        with driver.session(database=config['database']) as session:
            result = session.run("CALL dbms.components() YIELD name, versions RETURN name, versions[0] AS version")
            record = result.single()
            neo4j_version = record['version'] if record else "unknown"

            try:
                result = session.run("RETURN apoc.version() AS version")
                apoc_version = result.single()['version']
                apoc_status = f", APOC v{apoc_version}"
            except:
                apoc_status = ", APOC not installed"

            result = session.run("MATCH (n:Command) RETURN count(n) AS count")
            count = result.single()['count']

        driver.close()
        return True, f"Neo4j OK - v{neo4j_version}, {count} Command nodes{apoc_status}"

    except ImportError:
        return False, "Neo4j FAILED: neo4j driver not installed (pip install neo4j>=5.15.0)"
    except Exception as e:
        return False, f"Neo4j FAILED: {e}"


def check_docker_services() -> Tuple[bool, str]:
    """Check if Docker containers are running"""
    try:
        import subprocess

        result = subprocess.run(
            ['docker', 'ps', '--filter', 'name=crack-', '--format', '{{.Names}}\t{{.Status}}'],
            capture_output=True,
            text=True,
            timeout=5
        )

        if result.returncode == 0:
            services = result.stdout.strip().split('\n') if result.stdout.strip() else []
            if services:
                return True, f"Docker OK - {len(services)} container(s) running"
            else:
                return False, "Docker OK but no CRACK containers running (run: docker compose up -d)"
        else:
            return False, "Docker command failed"

    except FileNotFoundError:
        return False, "Docker not installed"
    except Exception as e:
        return False, f"Docker check failed: {e}"


def main():
    """Run all health checks and report status"""
    print("=" * 60)
    print("CRACK Dual Backend Health Check")
    print("=" * 60)

    docker_ok, docker_msg = check_docker_services()
    print(f"[{'✓' if docker_ok else '✗'}] {docker_msg}")

    pg_ok, pg_msg = check_postgresql()
    print(f"[{'✓' if pg_ok else '✗'}] {pg_msg}")

    neo4j_ok, neo4j_msg = check_neo4j()
    print(f"[{'✓' if neo4j_ok else '✗'}] {neo4j_msg}")

    print("=" * 60)

    if pg_ok and neo4j_ok:
        print("Status: ALL SYSTEMS OPERATIONAL")
        print("\nNext steps:")
        print("  1. Run data migration: python db/neo4j-migration/scripts/migrate_data.py")
        print("  2. Verify schema: cypher-shell -u neo4j -p crack_password < db/neo4j-migration/scripts/create_schema.cypher")
        return 0
    elif pg_ok:
        print("Status: PostgreSQL OK, Neo4j DOWN (fallback mode)")
        print("\nAction required:")
        print("  1. Start Neo4j: docker compose up -d neo4j")
        print("  2. Check Neo4j logs: docker logs crack-neo4j")
        return 1
    else:
        print("Status: CRITICAL - PostgreSQL DOWN")
        print("\nAction required:")
        print("  1. Start PostgreSQL: docker compose up -d postgresql")
        print("  2. Check PostgreSQL logs: docker logs crack-postgresql")
        return 2


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\nHealth check interrupted by user")
        sys.exit(130)
