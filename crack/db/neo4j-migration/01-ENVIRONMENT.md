# 01 - Environment Setup

## Prerequisites
None - Start here for Neo4j development environment

## Overview

Complete guide to setting up Neo4j development environment for CRACK toolkit integration.

---

## Installation Options

### Option A: Docker Compose (Recommended)

**Advantages**:
- Isolated environment
- Easy cleanup
- Consistent across systems
- Production-ready

**File**: `db/neo4j-migration/docker-compose.yml` (NEW)

```yaml
version: '3.8'

services:
  neo4j:
    image: neo4j:5.15-community
    container_name: crack-neo4j
    ports:
      - "7474:7474"  # HTTP (Browser UI)
      - "7687:7687"  # Bolt (Python driver)
    environment:
      - NEO4J_AUTH=neo4j/crack_password
      - NEO4J_PLUGINS=["apoc", "graph-data-science"]
      - NEO4J_dbms_memory_heap_initial__size=512m
      - NEO4J_dbms_memory_heap_max__size=2g
      - NEO4J_dbms_memory_pagecache_size=512m
      - NEO4J_dbms_security_procedures_unrestricted=apoc.*,gds.*
    volumes:
      - neo4j_data:/data
      - neo4j_logs:/logs
      - neo4j_import:/var/lib/neo4j/import
      - neo4j_plugins:/plugins
    networks:
      - crack_network

  postgresql:
    image: postgres:15-alpine
    container_name: crack-postgresql
    ports:
      - "5432:5432"
    environment:
      - POSTGRES_DB=crack
      - POSTGRES_USER=crack_user
      - POSTGRES_PASSWORD=crack_pass
    volumes:
      - pg_data:/var/lib/postgresql/data
      - ../schema.sql:/docker-entrypoint-initdb.d/01-schema.sql:ro
      - ../migrations:/docker-entrypoint-initdb.d/migrations:ro
    networks:
      - crack_network

volumes:
  neo4j_data:
  neo4j_logs:
  neo4j_import:
  neo4j_plugins:
  pg_data:

networks:
  crack_network:
    driver: bridge
```

**Start Services**:
```bash
cd /home/kali/Desktop/OSCP/crack/db/neo4j-migration
docker-compose up -d

# Verify
docker ps | grep crack
docker logs crack-neo4j
docker logs crack-postgresql
```

**Access**:
- Neo4j Browser: http://localhost:7474
- PostgreSQL: `psql -h localhost -U crack_user -d crack`

**Credentials**:
- Neo4j: `neo4j` / `crack_password`
- PostgreSQL: `crack_user` / `crack_pass`

---

### Option B: Native Installation (Linux)

**Neo4j Community Edition**:
```bash
# Import GPG key
wget -O - https://debian.neo4j.com/neotechnology.gpg.key | sudo apt-key add -

# Add repository
echo 'deb https://debian.neo4j.com stable latest' | sudo tee /etc/apt/sources.list.d/neo4j.list

# Install
sudo apt update
sudo apt install neo4j=1:5.15.0

# Configure
sudo nano /etc/neo4j/neo4j.conf
# Uncomment: dbms.default_listen_address=0.0.0.0
# Set: dbms.memory.heap.initial_size=512m
# Set: dbms.memory.heap.max_size=2g

# Start service
sudo systemctl enable neo4j
sudo systemctl start neo4j
sudo systemctl status neo4j

# Set initial password
cypher-shell -u neo4j -p neo4j
# ALTER CURRENT USER SET PASSWORD FROM 'neo4j' TO 'crack_password';
```

---

## Python Dependencies

### Update pyproject.toml

**File**: `/home/kali/Desktop/OSCP/crack/pyproject.toml`

```toml
[project]
dependencies = [
    "psycopg2-binary>=2.9.0",  # PostgreSQL (existing)
    "neo4j>=5.15.0",           # Neo4j driver (NEW)
    "redis>=5.0.0",            # Caching (optional, recommended)
]

[project.optional-dependencies]
dev = [
    "pytest>=7.0.0",
    "pytest-asyncio>=0.21.0",
    "pytest-benchmark>=4.0.0",  # Performance testing
]
```

**Install**:
```bash
cd /home/kali/Desktop/OSCP/crack
pip install -e .[dev]

# Verify
python -c "import neo4j; print(neo4j.__version__)"
```

---

## Configuration Files

### Database Connection Config

**File**: `db/config.py` (MODIFY)

```python
import os
from typing import Dict, Any

def get_postgresql_config() -> Dict[str, Any]:
    """Existing PostgreSQL configuration"""
    return {
        'host': os.getenv('POSTGRES_HOST', 'localhost'),
        'port': int(os.getenv('POSTGRES_PORT', 5432)),
        'database': os.getenv('POSTGRES_DB', 'crack'),
        'user': os.getenv('POSTGRES_USER', 'crack_user'),
        'password': os.getenv('POSTGRES_PASSWORD', 'crack_pass'),
    }

def get_neo4j_config() -> Dict[str, Any]:
    """Neo4j connection configuration (NEW)"""
    return {
        'uri': os.getenv('NEO4J_URI', 'bolt://localhost:7687'),
        'user': os.getenv('NEO4J_USER', 'neo4j'),
        'password': os.getenv('NEO4J_PASSWORD', 'crack_password'),
        'database': os.getenv('NEO4J_DATABASE', 'neo4j'),  # 'neo4j' is default
        'max_connection_lifetime': 3600,  # 1 hour
        'max_connection_pool_size': 50,
        'connection_acquisition_timeout': 60,  # seconds
        'encrypted': False,  # Use True for production with SSL
    }

def get_redis_config() -> Dict[str, Any]:
    """Redis caching configuration (optional)"""
    return {
        'host': os.getenv('REDIS_HOST', 'localhost'),
        'port': int(os.getenv('REDIS_PORT', 6379)),
        'db': int(os.getenv('REDIS_DB', 0)),
        'password': os.getenv('REDIS_PASSWORD', None),
        'socket_timeout': 5,
        'decode_responses': True,
    }
```

---

### Environment Variables

**File**: `.env` (NEW, add to .gitignore)

```bash
# PostgreSQL
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_DB=crack
POSTGRES_USER=crack_user
POSTGRES_PASSWORD=crack_pass

# Neo4j
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=crack_password
NEO4J_DATABASE=neo4j

# Redis (optional)
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_DB=0

# Feature flags
ENABLE_NEO4J=true
ENABLE_REDIS_CACHE=false
NEO4J_FALLBACK_TO_PG=true
```

**Load in Python**:
```python
from dotenv import load_dotenv
load_dotenv()
```

---

## Initial Verification

### Test PostgreSQL Connection

```bash
# From command line
psql -h localhost -U crack_user -d crack -c "SELECT version();"

# From Python
python3 << EOF
import psycopg2
from db.config import get_postgresql_config

config = get_postgresql_config()
conn = psycopg2.connect(**config)
cursor = conn.cursor()
cursor.execute("SELECT COUNT(*) FROM commands;")
print(f"Commands in database: {cursor.fetchone()[0]}")
conn.close()
EOF
```

**Expected Output**: `Commands in database: 1200` (approximate)

---

### Test Neo4j Connection

```bash
# From cypher-shell
cypher-shell -u neo4j -p crack_password
# RETURN "Connection successful" AS message;

# From Python
python3 << EOF
from neo4j import GraphDatabase
from db.config import get_neo4j_config

config = get_neo4j_config()
driver = GraphDatabase.driver(
    config['uri'],
    auth=(config['user'], config['password'])
)

with driver.session() as session:
    result = session.run("RETURN 'Connection successful' AS message")
    print(result.single()['message'])

driver.close()
EOF
```

**Expected Output**: `Connection successful`

---

### Verify Neo4j Browser Access

1. Open browser: http://localhost:7474
2. Login: `neo4j` / `crack_password`
3. Run test query:
   ```cypher
   RETURN "Neo4j is running" AS status
   ```

**Expected**: Result table showing status message

---

## Plugin Installation (Optional but Recommended)

### APOC (Awesome Procedures on Cypher)

**Provides**:
- Batch operations
- Graph algorithms
- Data import/export utilities

**Installation** (Docker):
Already included in docker-compose.yml via `NEO4J_PLUGINS`

**Installation** (Native):
```bash
# Download APOC
cd /var/lib/neo4j/plugins
sudo wget https://github.com/neo4j/apoc/releases/download/5.15.0/apoc-5.15.0-core.jar

# Enable in config
sudo nano /etc/neo4j/neo4j.conf
# Add: dbms.security.procedures.unrestricted=apoc.*

# Restart
sudo systemctl restart neo4j

# Verify
cypher-shell -u neo4j -p crack_password
# RETURN apoc.version() AS version;
```

---

### Graph Data Science (GDS)

**Provides**:
- Shortest path algorithms (Dijkstra, A*)
- Community detection
- Centrality calculations

**Installation** (Docker):
Already included in docker-compose.yml

**Installation** (Native):
```bash
cd /var/lib/neo4j/plugins
sudo wget https://graphdatascience.ninja/neo4j-graph-data-science-2.5.0.jar

# Enable
sudo nano /etc/neo4j/neo4j.conf
# Add: dbms.security.procedures.unrestricted=apoc.*,gds.*

# Restart
sudo systemctl restart neo4j

# Verify
cypher-shell
# RETURN gds.version() AS version;
```

---

## Health Check Script

**File**: `db/neo4j-migration/scripts/health_check.py`

```python
#!/usr/bin/env python3
"""Health check for dual backend system"""

import sys
from typing import Tuple
import psycopg2
from neo4j import GraphDatabase
from db.config import get_postgresql_config, get_neo4j_config

def check_postgresql() -> Tuple[bool, str]:
    """Test PostgreSQL connection and schema"""
    try:
        config = get_postgresql_config()
        conn = psycopg2.connect(**config)
        cursor = conn.cursor()

        # Check schema version
        cursor.execute("SELECT version, applied_at FROM schema_version ORDER BY applied_at DESC LIMIT 1;")
        version, applied = cursor.fetchone()

        # Check command count
        cursor.execute("SELECT COUNT(*) FROM commands;")
        count = cursor.fetchone()[0]

        conn.close()
        return True, f"PostgreSQL OK - Schema v{version}, {count} commands"

    except Exception as e:
        return False, f"PostgreSQL FAILED: {e}"

def check_neo4j() -> Tuple[bool, str]:
    """Test Neo4j connection and APOC"""
    try:
        config = get_neo4j_config()
        driver = GraphDatabase.driver(
            config['uri'],
            auth=(config['user'], config['password'])
        )

        with driver.session() as session:
            # Check connection
            result = session.run("RETURN 1 AS test")
            assert result.single()['test'] == 1

            # Check APOC (optional)
            try:
                result = session.run("RETURN apoc.version() AS version")
                apoc_version = result.single()['version']
                apoc_status = f", APOC v{apoc_version}"
            except:
                apoc_status = ", APOC not installed"

            # Check node count
            result = session.run("MATCH (n:Command) RETURN count(n) AS count")
            count = result.single()['count']

        driver.close()
        return True, f"Neo4j OK - {count} Command nodes{apoc_status}"

    except Exception as e:
        return False, f"Neo4j FAILED: {e}"

if __name__ == "__main__":
    print("=" * 60)
    print("CRACK Dual Backend Health Check")
    print("=" * 60)

    pg_ok, pg_msg = check_postgresql()
    print(f"[{'✓' if pg_ok else '✗'}] {pg_msg}")

    neo4j_ok, neo4j_msg = check_neo4j()
    print(f"[{'✓' if neo4j_ok else '✗'}] {neo4j_msg}")

    print("=" * 60)

    if pg_ok and neo4j_ok:
        print("Status: ALL SYSTEMS OPERATIONAL")
        sys.exit(0)
    elif pg_ok:
        print("Status: PostgreSQL OK, Neo4j DOWN (fallback mode)")
        sys.exit(1)
    else:
        print("Status: CRITICAL - PostgreSQL DOWN")
        sys.exit(2)
```

**Run**:
```bash
cd /home/kali/Desktop/OSCP/crack
python db/neo4j-migration/scripts/health_check.py
```

**Expected Output**:
```
============================================================
CRACK Dual Backend Health Check
============================================================
[✓] PostgreSQL OK - Schema v1.0.0, 1247 commands
[✓] Neo4j OK - 0 Command nodes, APOC v5.15.0
============================================================
Status: ALL SYSTEMS OPERATIONAL
```

---

## Troubleshooting

### Issue: Neo4j Container Won't Start

**Symptoms**: `docker logs crack-neo4j` shows permission errors

**Solution**:
```bash
# Fix volume permissions
sudo chown -R 7474:7474 neo4j_data neo4j_logs

# Or recreate with user mapping
docker-compose down -v
docker-compose up -d
```

---

### Issue: Connection Refused on Port 7687

**Check Neo4j is listening**:
```bash
sudo netstat -tulpn | grep 7687
# Should show: tcp ... LISTEN ... java
```

**Check firewall**:
```bash
sudo ufw status
sudo ufw allow 7687/tcp
```

---

### Issue: "Database does not exist" Error

**Symptoms**: Python driver raises `DatabaseUnavailable`

**Solution**:
Neo4j Community Edition only supports one database named `neo4j`

```python
# Correct
config = {'database': 'neo4j'}

# Wrong (Enterprise only)
config = {'database': 'crack'}
```

---

### Issue: Memory Allocation Failed

**Symptoms**: Neo4j logs show `OutOfMemoryError`

**Solution**: Reduce heap size in docker-compose.yml
```yaml
environment:
  - NEO4J_dbms_memory_heap_max__size=1g  # Reduced from 2g
```

---

## Next Steps

Once environment is verified:

1. **Review Schema Design**: [02-SCHEMA-DESIGN.md](02-SCHEMA-DESIGN.md)
2. **Run Initial Migration**: [03-MIGRATION-SCRIPTS.md](03-MIGRATION-SCRIPTS.md)
3. **Develop Adapter**: [04-ADAPTER-IMPLEMENTATION.md](04-ADAPTER-IMPLEMENTATION.md)

---

## See Also

- [00-ARCHITECTURE.md](00-ARCHITECTURE.md#component-architecture) - System design
- [Neo4j Operations Manual](https://neo4j.com/docs/operations-manual/current/)
- [Neo4j Python Driver Docs](https://neo4j.com/docs/api/python-driver/current/)

---

**Document Version**: 1.0.0
**Last Updated**: 2025-11-08
**Owner**: Infrastructure Team
**Status**: Ready for Implementation
