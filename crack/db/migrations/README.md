# Database Migrations

Schema version migrations for the CRACK SQL database.

## Migration Files

| Version | File | Description | Status |
|---------|------|-------------|--------|
| 1.0.0 | 001_initial.sql | Initial 17-table schema | ✓ Applied |

## Usage

### Apply Migrations

```bash
# Automatic (recommended)
python3 -m crack.db.migrate apply

# Manual (for testing)
sqlite3 ~/.crack/crack.db < db/migrations/001_initial.sql
```

### Check Schema Version

```bash
sqlite3 ~/.crack/crack.db "SELECT * FROM schema_version ORDER BY applied_at DESC LIMIT 1;"
```

### Rollback (if needed)

```bash
# Full reset
rm ~/.crack/crack.db
sqlite3 ~/.crack/crack.db < db/schema.sql
```

## Migration Naming Convention

Format: `{version}_{description}.sql`

Examples:
- `001_initial.sql` - Initial schema
- `002_add_indices.sql` - Performance optimization
- `003_add_wordlist_tables.sql` - New feature

## Creating New Migrations

1. **Create SQL file**: `db/migrations/00X_feature_name.sql`

2. **Add migration logic**:
```sql
-- Migration: 002_add_indices
-- Description: Add performance indices for common queries
-- Date: 2025-01-15

CREATE INDEX idx_commands_full_text ON commands(name, description);
CREATE INDEX idx_session_findings_created ON session_findings(created_at DESC);

-- Update schema version
INSERT INTO schema_version (version, description) VALUES
('1.1.0', 'Added performance indices for command search and finding timeline');
```

3. **Test migration**:
```bash
# On test database
sqlite3 test_crack.db < db/migrations/002_add_indices.sql

# Verify
sqlite3 test_crack.db ".indices commands"
```

4. **Update this README** with new migration entry

## Best Practices

- **Backwards Compatible**: Migrations should not break existing data
- **Idempotent**: Use `IF NOT EXISTS` for CREATE statements
- **Tested**: Test on copy of production database first
- **Documented**: Add comments explaining WHY, not just WHAT
- **Atomic**: Each migration is self-contained
- **Versioned**: Update schema_version table at end

## Migration Template

```sql
-- ============================================================================
-- Migration: {version}_{description}
-- Description: {what and why}
-- Date: {YYYY-MM-DD}
-- ============================================================================

BEGIN TRANSACTION;

-- Your migration statements here
-- ...

-- Update schema version
INSERT INTO schema_version (version, description) VALUES
('{version}', '{description}');

COMMIT;
```

## Troubleshooting

**Foreign Key Errors**:
```bash
# Enable FK constraints (SQLite)
sqlite3 ~/.crack/crack.db "PRAGMA foreign_keys=ON;"
```

**Lock Errors**:
```bash
# Close all connections to database
# SQLite only allows one writer at a time
```

**Validation Errors**:
```bash
# Check schema integrity
sqlite3 ~/.crack/crack.db "PRAGMA integrity_check;"
```
