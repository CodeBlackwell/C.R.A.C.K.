# Neo4j Integration - Quick Start Guide

## Phase 1: Environment Setup (COMPLETE)

All foundation files have been created. Follow these steps to activate the dual-backend system.

## Prerequisites

- Docker and Docker Compose installed
- Python 3.8+ with pip

## Installation Steps

### 1. Install Docker (if not already installed)

```bash
sudo apt update
sudo apt install docker.io docker-compose-plugin
sudo systemctl enable docker
sudo systemctl start docker
sudo usermod -aG docker $USER
# Log out and back in for group changes to take effect
```

### 2. Install Python Dependencies

```bash
cd /home/kali/Desktop/OSCP/crack
pip install -e .
# This will install neo4j>=5.15.0 along with other dependencies
```

### 3. Start Database Services

```bash
cd /home/kali/Desktop/OSCP/crack
docker compose up -d
```

Wait for services to initialize (30-60 seconds):
```bash
docker logs -f crack-neo4j
# Press Ctrl+C when you see "Started."
```

### 4. Initialize Neo4j Schema

```bash
docker exec -i crack-neo4j cypher-shell -u neo4j -p crack_password < db/neo4j-migration/scripts/create_schema.cypher
```

### 5. Verify Installation

```bash
python db/neo4j-migration/scripts/health_check.py
```

Expected output:
```
============================================================
CRACK Dual Backend Health Check
============================================================
[✓] Docker OK - 2 container(s) running
[✓] PostgreSQL OK - v15.x, 1200+ commands
[✓] Neo4j OK - v5.15.0, 0 Command nodes, APOC v5.15.0
============================================================
Status: ALL SYSTEMS OPERATIONAL
```

## Access Services

### Neo4j Browser UI
- URL: http://localhost:7474
- Username: `neo4j`
- Password: `crack_password`

### PostgreSQL
```bash
docker exec -it crack-postgresql psql -U crack_user -d crack
```

### Neo4j Cypher Shell
```bash
docker exec -it crack-neo4j cypher-shell -u neo4j -p crack_password
```

## Common Commands

### Start Services
```bash
docker compose up -d
```

### Stop Services
```bash
docker compose down
```

### View Logs
```bash
docker logs crack-postgresql
docker logs crack-neo4j
```

### Restart a Service
```bash
docker compose restart neo4j
docker compose restart postgresql
```

### Check Service Status
```bash
docker compose ps
```

## Troubleshooting

### Issue: Port already in use
```bash
# Check what's using the port
sudo netstat -tulpn | grep 7687
sudo netstat -tulpn | grep 5432

# Stop conflicting service or change port in docker-compose.yml
```

### Issue: Permission denied
```bash
# Add user to docker group
sudo usermod -aG docker $USER
# Log out and back in
```

### Issue: Neo4j won't start
```bash
# Check logs
docker logs crack-neo4j

# Increase memory if needed
# Edit docker-compose.yml and reduce heap size to 1g
docker compose down
docker compose up -d
```

### Issue: Connection refused
```bash
# Verify services are running
docker ps | grep crack

# Restart services
docker compose restart
```

## What's Next?

Phase 1 is complete. Next steps:

1. **Phase 2: Data Migration** - Import existing PostgreSQL data into Neo4j
2. **Phase 3: Adapter Development** - Create Neo4j adapter for graph queries
3. **Phase 4: Router Integration** - Intelligent backend selection
4. **Phase 5: Advanced Features** - Multi-hop queries, attack path finding

## Files Created in Phase 1

1. `/home/kali/Desktop/OSCP/crack/docker-compose.yml` - Service definitions
2. `/home/kali/Desktop/OSCP/crack/db/config.py` - Updated with Neo4j config
3. `/home/kali/Desktop/OSCP/crack/db/neo4j-migration/scripts/create_schema.cypher` - Schema definition
4. `/home/kali/Desktop/OSCP/crack/db/neo4j-migration/scripts/health_check.py` - Health checker
5. `/home/kali/Desktop/OSCP/crack/pyproject.toml` - Updated with neo4j dependency

## Support

For detailed documentation, see:
- `/home/kali/Desktop/OSCP/crack/db/neo4j-migration/PHASE1_COMPLETE.md`
- `/home/kali/Desktop/OSCP/crack/db/neo4j-migration/01-ENVIRONMENT.md`
- `/home/kali/Desktop/OSCP/crack/db/neo4j-migration/00-ARCHITECTURE.md`

---

**Status**: Phase 1 Complete - Ready for Phase 2
**Date**: 2025-11-08
