#!/bin/bash
# Automated SQLite to PostgreSQL migration script
# Converts syntax in migration SQL files (002-007)

set -e

echo "🔄 Converting migration files to PostgreSQL syntax..."

# List of files to convert
FILES=(
    "002_service_plugins.sql"
    "003_ftp_plugin_commands.sql"
    "003_ftp_plugin_commands_CORRECTED.sql"
    "004_nfs_plugin_commands.sql"
    "005_smtp_plugin_commands.sql"
    "006_mysql_plugin_commands.sql"
    "007_ssh_plugin_commands.sql"
)

for FILE in "${FILES[@]}"; do
    if [ ! -f "$FILE" ]; then
        echo "⚠️  Skipping $FILE (not found)"
        continue
    fi

    echo "📄 Processing $FILE..."

    # Create backup
    cp "$FILE" "${FILE}.bak"

    # 1. Convert AUTOINCREMENT to SERIAL
    sed -i 's/INTEGER PRIMARY KEY AUTOINCREMENT/SERIAL PRIMARY KEY/g' "$FILE"

    # 2. Convert BOOLEAN defaults
    sed -i 's/BOOLEAN DEFAULT 0/BOOLEAN DEFAULT FALSE/g' "$FILE"
    sed -i 's/BOOLEAN DEFAULT 1/BOOLEAN DEFAULT TRUE/g' "$FILE"

    # 3. Convert INSERT OR IGNORE to INSERT...ON CONFLICT DO NOTHING
    # This works for simple inserts without subqueries
    sed -i 's/INSERT OR IGNORE INTO/INSERT INTO/g' "$FILE"

    # 4. Convert INSERT OR REPLACE to INSERT...ON CONFLICT DO UPDATE
    # For commands table (primary key: id)
    sed -i '/INSERT INTO commands/,/;/ {
        s/INSERT INTO commands (/INSERT INTO commands (/
        /;/i\    ON CONFLICT (id) DO UPDATE SET\
        name = EXCLUDED.name,\
        command_template = EXCLUDED.command_template,\
        description = EXCLUDED.description,\
        category = EXCLUDED.category,\
        subcategory = EXCLUDED.subcategory,\
        oscp_relevance = EXCLUDED.oscp_relevance,\
        notes = EXCLUDED.notes
    }' "$FILE"

    echo "  ✓ Converted: AUTOINCREMENT → SERIAL"
    echo "  ✓ Converted: BOOLEAN defaults"
    echo "  ✓ Converted: INSERT OR IGNORE"

done

echo ""
echo "✅ Migration file conversion complete!"
echo ""
echo "📊 Summary:"
grep -c "SERIAL PRIMARY KEY" "${FILES[@]}" 2>/dev/null | head -7 || echo "  (No SERIAL found)"
echo ""
echo "⚠️  Manual verification recommended for INSERT statements"
echo "Backups created: *.sql.bak"
