# PostgreSQL Backend Setup

## Overview

The CRACK Reference System supports two backends:

1. **JSON Backend** (Default) - Human-editable, slower searches
2. **PostgreSQL Backend** (Recommended) - 10-20x faster, optimized for large command sets

## Quick Setup

### 1. Check Current Backend

```bash
crack reference netcat
```

**Output with JSON backend:**
```
ℹ PostgreSQL connection failed, using JSON backend
✓ Using JSON backend
```

**Output with SQL backend:**
```
✓ Using SQL backend (150+ commands loaded)
```

### 2. Enable PostgreSQL Backend

```bash
# Navigate to crack directory
cd /home/kali/Desktop/OSCP/crack

# Run migration script (auto-creates schema + imports all JSON commands)
python3 -m db.migrate commands
```

**Expected output:**
```
🚀 Starting command migration...

📋 Creating database schema...
✓ Database schema created successfully
🔍 Scanning reference/data/commands for JSON files...
✓ Found 18 JSON files

📄 Processing: exploitation/general.json
  ✓ Command: bash-reverse-shell
  ✓ Command: nc-reverse-shell
  ...
📄 Processing: post-exploit/linux.json
  ✓ Command: linux-ufw-disable
  ...

🔗 Processing command relationships...
✓ Created 45 command relationships

============================================================
📊 MIGRATION STATISTICS
============================================================
Commands migrated:      150
Flags created:          320
Variables created:      180
Tags created:           85
Relations created:      45
Indicators created:     210

✓ No errors encountered
============================================================

✅ Migration complete!
```

**What it does automatically:**
1. Creates PostgreSQL database if needed
2. Creates all tables from schema.sql
3. Recursively finds all 18 JSON files in reference/data/commands/
4. Imports commands with metadata (flags, variables, tags, indicators)
5. Creates command relationships (alternatives, prerequisites, next_steps)

### 3. Verify Setup

```bash
crack reference netcat
```

**Should now show:**
```
✓ Using SQL backend (150+ commands loaded)
```

## Troubleshooting

### PostgreSQL Not Installed

**Error:**
```
ImportError: No module named 'psycopg2'
```

**Fix:**
```bash
# Install PostgreSQL client library
pip install psycopg2-binary

# Or install full PostgreSQL (if not installed)
sudo apt update
sudo apt install postgresql postgresql-contrib python3-psycopg2
```

### PostgreSQL Service Not Running

**Error:**
```
psycopg2.OperationalError: could not connect to server
```

**Fix:**
```bash
# Check PostgreSQL status
sudo systemctl status postgresql

# Start PostgreSQL service
sudo systemctl start postgresql

# Enable on boot (optional)
sudo systemctl enable postgresql
```

### Database Not Created

**Error:**
```
psycopg2.OperationalError: database "crack" does not exist
```

**Fix:**
```bash
# Create database manually
sudo -u postgres createdb crack

# Grant permissions (optional, for security)
sudo -u postgres psql -c "CREATE USER crack_user WITH PASSWORD 'crack_pass';"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE crack TO crack_user;"

# Re-run migration
cd /home/kali/Desktop/OSCP/crack
python3 -m db.migrate commands
```

### Schema Outdated

**Error:**
```
⚠ SQL database schema outdated
  Run: python3 -m db.migrate commands
```

**Fix:**
```bash
cd /home/kali/Desktop/OSCP/crack
python3 -m db.migrate commands
```

### Database Locked

**Error:**
```
⚠ SQL database locked by another process
```

**Fix:**
```bash
# Check for active connections
sudo -u postgres psql -c "SELECT * FROM pg_stat_activity WHERE datname='crack';"

# Kill blocking process (if safe)
sudo -u postgres psql -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='crack';"
```

## Performance Comparison

| Operation | JSON Backend | PostgreSQL Backend |
|-----------|--------------|-------------------|
| Search "firewall" | ~150ms | ~8ms |
| Filter by category | ~80ms | ~4ms |
| Filter by tags | ~120ms | ~6ms |
| Load registry | ~200ms | ~15ms |

**Recommendation:** Use PostgreSQL backend for:
- Fast searches during OSCP exam
- Large command sets (100+ commands)
- Frequent filtering operations

## Database Location

- **PostgreSQL:** `sudo -u postgres psql crack`
- **JSON Files:** `crack/reference/data/commands/`

## Switching Backends

The system **auto-detects** and falls back gracefully:
1. Tries PostgreSQL first (if available)
2. Falls back to JSON automatically (if PostgreSQL fails)
3. No configuration needed - works out of the box

## Maintenance

### Update Commands
```bash
# Edit JSON files
vim crack/reference/data/commands/web/sql-injection.json

# Re-import to PostgreSQL
cd crack
python3 -m db.migrate commands
```

### Backup Database
```bash
# Backup PostgreSQL
sudo -u postgres pg_dump crack > crack_backup.sql

# Restore PostgreSQL
sudo -u postgres psql crack < crack_backup.sql

# JSON is already version controlled (no backup needed)
```

### Reset Database
```bash
# Drop and recreate
sudo -u postgres psql -c "DROP DATABASE crack;"
sudo -u postgres psql -c "CREATE DATABASE crack;"

# Re-import
cd /home/kali/Desktop/OSCP/crack
python3 -m db.migrate commands
```

## Configuration

Database connection settings in `crack/db/config.py`:

```python
def get_db_config():
    return {
        'dbname': 'crack',
        'user': 'postgres',
        'password': '',  # Default: no password
        'host': 'localhost',
        'port': 5432
    }
```

**To customize:**
1. Edit `crack/db/config.py`
2. Update connection parameters
3. Re-run `python3 -m db.migrate commands`

## FAQ

**Q: Do I need PostgreSQL for OSCP exam?**
A: No, JSON backend works fine. PostgreSQL is optional for faster searches.

**Q: Will switching backends lose my custom commands?**
A: No, JSON files are always synchronized. Edit JSON, re-run migration.

**Q: Can I use both backends?**
A: System uses PostgreSQL if available, otherwise JSON. Edit JSON files for both.

**Q: How do I add new commands?**
A: Always edit JSON files in `crack/reference/data/commands/`, then re-run `python3 -m db.migrate commands`.

## See Also

- [Command Authoring Guide](attack-chain-authoring-guide.md)
- [Tag System](tags.md)
- [Placeholder System](placeholders.md)
- [Database Schema](../db/schema.sql)
