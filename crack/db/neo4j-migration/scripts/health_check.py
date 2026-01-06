#!/usr/bin/env python3
"""
Health check script for CRACK Neo4j backend

Tests connectivity to Neo4j database and reports operational status.

Usage:
    python health_check.py

Exit codes:
    0 - Neo4j operational
    1 - Neo4j DOWN
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../..', '..'))

from typing import Tuple


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
            ['docker', 'ps', '--filter', 'name=crack-neo4j', '--format', '{{.Names}}\t{{.Status}}'],
            capture_output=True,
            text=True,
            timeout=5
        )

        if result.returncode == 0:
            services = result.stdout.strip().split('\n') if result.stdout.strip() else []
            if services:
                return True, f"Docker OK - Neo4j container running"
            else:
                return False, "Docker OK but Neo4j container not running (run: docker compose up -d neo4j)"
        else:
            return False, "Docker command failed"

    except FileNotFoundError:
        return False, "Docker not installed"
    except Exception as e:
        return False, f"Docker check failed: {e}"


def main():
    """Run all health checks and report status"""
    print("=" * 60)
    print("CRACK Neo4j Backend Health Check")
    print("=" * 60)

    docker_ok, docker_msg = check_docker_services()
    print(f"[{'✓' if docker_ok else '✗'}] {docker_msg}")

    neo4j_ok, neo4j_msg = check_neo4j()
    print(f"[{'✓' if neo4j_ok else '✗'}] {neo4j_msg}")

    print("=" * 60)

    if neo4j_ok:
        print("Status: NEO4J OPERATIONAL")
        print("\nNext steps:")
        print("  1. Verify schema: cypher-shell -u neo4j -p $NEO4J_PASSWORD < db/neo4j-migration/scripts/create_schema.cypher")
        print("  2. Use CLI: crack reference <query>")
        return 0
    else:
        print("Status: CRITICAL - Neo4j DOWN")
        print("\nAction required:")
        print("  1. Start Neo4j: docker compose up -d neo4j")
        print("  2. Check Neo4j logs: docker logs crack-neo4j")
        print("  3. Verify credentials: NEO4J_AUTH=neo4j/$NEO4J_PASSWORD")
        return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\nHealth check interrupted by user")
        sys.exit(130)
