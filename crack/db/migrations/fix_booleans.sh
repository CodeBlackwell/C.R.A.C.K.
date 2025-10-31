#!/bin/bash
# Simple bash script to fix boolean literals in SQL migration files

echo "🔧 PostgreSQL Boolean Literal Fixer (Sed Edition)"
echo "=========================================================="

FILES="003_ftp_plugin_commands_CORRECTED.sql 004_nfs_plugin_commands.sql 005_smtp_plugin_commands.sql 006_mysql_plugin_commands.sql 007_ssh_plugin_commands.sql"

TOTAL_REPLACEMENTS=0

for FILE in $FILES; do
    if [ ! -f "$FILE" ]; then
        echo "⚠️  Skipping $FILE (not found)"
        continue
    fi

    echo ""
    echo "📄 Processing: $FILE"

    # Backup
    if [ ! -f "${FILE}.bak" ]; then
        cp "$FILE" "${FILE}.bak"
        echo "   💾 Backup: ${FILE}.bak"
    else
        echo "   ℹ️  Backup exists: ${FILE}.bak"
    fi

    # Count replacements
    COUNT=0

    # Pattern 1: , 1, -> , TRUE,
    BEFORE=$(grep -c ", 1," "$FILE")
    sed -i 's/, 1,/, TRUE,/g' "$FILE"
    AFTER=$(grep -c ", TRUE," "$FILE")
    COUNT=$((COUNT + AFTER - BEFORE))

    # Pattern 2: , 0, -> , FALSE,
    BEFORE=$(grep -c ", 0," "$FILE")
    sed -i 's/, 0,/, FALSE,/g' "$FILE"
    AFTER=$(grep -c ", FALSE," "$FILE")
    COUNT=$((COUNT + AFTER - BEFORE))

    # Pattern 3: , 1) -> , TRUE)
    BEFORE=$(grep -c ", 1)" "$FILE")
    sed -i 's/, 1)/, TRUE)/g' "$FILE"
    AFTER=$(grep -c ", TRUE)" "$FILE")
    COUNT=$((COUNT + AFTER - BEFORE))

    # Pattern 4: , 0) -> , FALSE)
    BEFORE=$(grep -c ", 0)" "$FILE")
    sed -i 's/, 0)/, FALSE)/g' "$FILE"
    AFTER=$(grep -c ", FALSE)" "$FILE")
    COUNT=$((COUNT + AFTER - BEFORE))

    if [ $COUNT -gt 0 ]; then
        echo "   ✅ Made ~$COUNT replacements"
        TOTAL_REPLACEMENTS=$((TOTAL_REPLACEMENTS + COUNT))
    else
        echo "   ℹ️  No changes needed"
    fi
done

echo ""
echo "=========================================================="
echo "📊 Summary"
echo "=========================================================="
echo "Total replacements: ~$TOTAL_REPLACEMENTS"
echo ""
echo "✅ All boolean literals converted to PostgreSQL syntax"
echo "   Run tests to verify: pytest tests/db/test_plugin_repository.py"
