#!/bin/bash
# Markdown Cleanup Script
# WARNING: This script will delete files. Review MARKDOWN_CLEANUP_PLAN.md first.

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Base directory
BASE_DIR="/home/kali/Desktop/OSCP/crack"
cd "$BASE_DIR"

echo -e "${YELLOW}=== Markdown Cleanup Script ===${NC}"
echo "This script will:"
echo "  1. Delete 72+ junk/historical files"
echo "  2. Reorganize reference documentation"
echo "  3. Consolidate 25 redundant READMEs"
echo "  4. Archive development documentation"
echo ""
echo -e "${RED}WARNING: This will delete files. Backup created first.${NC}"
echo ""
read -p "Press Enter to create backup and continue, or Ctrl+C to cancel..."

# Create backup
echo -e "\n${GREEN}Creating backup...${NC}"
BACKUP_FILE="$HOME/oscp_markdown_backup_$(date +%Y%m%d_%H%M%S).tar.gz"
find "$BASE_DIR" -name "*.md" -print0 | tar -czf "$BACKUP_FILE" --null -T -
echo "Backup created: $BACKUP_FILE"

# Phase 1: Delete Junk Files
echo -e "\n${YELLOW}=== Phase 1: Deleting junk files ===${NC}"

# Root-level historical files
echo "Deleting root-level historical files..."
rm -fv "$BASE_DIR/IMPORT_SCRIPT_FIX_SUMMARY.md"
rm -fv "$BASE_DIR/IMPLEMENTATION_SUMMARY.md"
rm -fv "$BASE_DIR/LIVE_DB_VALIDATION_REPORT.md"
rm -fv "$BASE_DIR/STATE_CONDITIONS_REMOVAL_SUMMARY.md"
rm -fv "$BASE_DIR/PHASE3_COMPLETION_REPORT.md"

# Audit reports directory (entire directory)
echo "Deleting docs/audit-reports directory..."
rm -rfv "$BASE_DIR/docs/audit-reports/"

# Neo4j migration phase reports
echo "Deleting neo4j-migration historical reports..."
find "$BASE_DIR/db/neo4j-migration" -maxdepth 1 -name "PHASE*.md" -delete -print
find "$BASE_DIR/db/neo4j-migration" -maxdepth 1 -name "*SUMMARY*.md" -delete -print
find "$BASE_DIR/db/neo4j-migration" -maxdepth 1 -name "*REPORT*.md" -delete -print
find "$BASE_DIR/db/neo4j-migration/data" -name "PHASE*.md" -delete -print
find "$BASE_DIR/db/neo4j-migration/data" -name "*SUMMARY*.md" -delete -print
find "$BASE_DIR/db/neo4j-migration/data" -name "*REPORT*.md" -delete -print

# db/scripts bloat
echo "Deleting db/scripts bloat..."
rm -fv "$BASE_DIR/db/scripts/GENERATION_SUMMARY.md"
rm -fv "$BASE_DIR/db/scripts/FINAL_REPORT.md"
rm -fv "$BASE_DIR/db/docs/COMPREHENSIVE_DATABASE_EXPANSION_REPORT.md"

# Old archive files
echo "Deleting old archive files..."
rm -rfv "$BASE_DIR/docs/archive/2025-10-09/"
rm -rfv "$BASE_DIR/docs/archive/2025-10-10/"

# Phase 2: Reorganize Reference Data
echo -e "\n${YELLOW}=== Phase 2: Reorganizing reference documentation ===${NC}"

# Create proper docs structure
echo "Creating reference/docs/active-directory/ structure..."
mkdir -pv "$BASE_DIR/reference/docs/active-directory"

# Move NEW reference files to proper location
if [ -f "$BASE_DIR/reference/data/ACTIVE_DIRECTORY_SESSION_ENUMERATION_ADDITIONS.md" ]; then
    echo "Moving session enumeration additions..."
    mv -v "$BASE_DIR/reference/data/ACTIVE_DIRECTORY_SESSION_ENUMERATION_ADDITIONS.md" \
       "$BASE_DIR/reference/docs/active-directory/session-enumeration-additions.md"
fi

if [ -f "$BASE_DIR/reference/data/AD_SESSION_ENUM_QUICK_REF.md" ]; then
    echo "Moving session enumeration quick reference..."
    mv -v "$BASE_DIR/reference/data/AD_SESSION_ENUM_QUICK_REF.md" \
       "$BASE_DIR/reference/docs/active-directory/session-enum-quick-ref.md"
fi

# Move formatting guide
if [ -f "$BASE_DIR/reference/data/cheatsheets/FORMATTING_SUMMARY.md" ]; then
    echo "Moving formatting guide..."
    mv -v "$BASE_DIR/reference/data/cheatsheets/FORMATTING_SUMMARY.md" \
       "$BASE_DIR/reference/docs/formatting-guide.md"
fi

# Phase 3: Consolidate READMEs
echo -e "\n${YELLOW}=== Phase 3: Consolidating redundant READMEs ===${NC}"

# Delete tiny/redundant READMEs
echo "Deleting tiny READMEs..."
rm -fv "$BASE_DIR/.claude/agents/README.md"
rm -fv "$BASE_DIR/track/services/plugin_docs/agent_reports/README.md"
rm -fv "$BASE_DIR/track/services/plugin_docs/archive/README.md"
rm -fv "$BASE_DIR/track/services/plugin_docs/implementations/README.md"
rm -fv "$BASE_DIR/track/services/plugin_docs/summaries/README.md"
rm -fv "$BASE_DIR/reference/data/chain_templates/README.md"
rm -fv "$BASE_DIR/reference/schemas/README.md"
rm -fv "$BASE_DIR/reference/models/README.md"

# Consolidate mining_reports READMEs
echo "Deleting mining_reports subdirectory READMEs..."
find "$BASE_DIR/track/services/plugin_docs/mining_reports" -mindepth 2 -name "README.md" -delete -print

# Phase 4: Archive Development Docs
echo -e "\n${YELLOW}=== Phase 4: Archiving development documentation ===${NC}"

# Create archive structure
echo "Creating archive directories..."
mkdir -pv "$BASE_DIR/track/docs/archive/development"
mkdir -pv "$BASE_DIR/track/docs/archive/nmap-cookbook"
mkdir -pv "$BASE_DIR/track/docs/archive/panel-implementation"

# Move implementation docs (if directory exists)
if [ -d "$BASE_DIR/track/docs/implementation" ]; then
    echo "Moving implementation docs..."
    mv -v "$BASE_DIR/track/docs/implementation"/*.md \
       "$BASE_DIR/track/docs/archive/development/" 2>/dev/null || true
    rmdir "$BASE_DIR/track/docs/implementation" 2>/dev/null || true
fi

# Move nmap cookbook (if directory exists)
if [ -d "$BASE_DIR/track/docs/nmap_cookbook" ]; then
    echo "Moving nmap cookbook..."
    mv -v "$BASE_DIR/track/docs/nmap_cookbook"/*.md \
       "$BASE_DIR/track/docs/archive/nmap-cookbook/" 2>/dev/null || true
    rmdir "$BASE_DIR/track/docs/nmap_cookbook" 2>/dev/null || true
fi

# Move panel implementation docs (if directory exists)
if [ -d "$BASE_DIR/track/docs/panels" ]; then
    echo "Moving panel implementation docs..."
    mv -v "$BASE_DIR/track/docs/panels"/*.md \
       "$BASE_DIR/track/docs/archive/panel-implementation/" 2>/dev/null || true
    rmdir "$BASE_DIR/track/docs/panels" 2>/dev/null || true
fi

# Cleanup Summary
echo -e "\n${GREEN}=== Cleanup Complete ===${NC}"
echo ""
echo "Statistics:"
TOTAL_MD_NOW=$(find "$BASE_DIR" -name "*.md" | wc -l)
echo "  Total markdown files now: $TOTAL_MD_NOW"
echo "  Backup location: $BACKUP_FILE"
echo ""
echo "New documentation structure:"
echo "  reference/docs/active-directory/ - Active Directory guides"
echo "  track/docs/archive/ - Archived development docs"
echo ""
echo -e "${YELLOW}Next steps:${NC}"
echo "  1. Review changes: git status"
echo "  2. Stage new files: git add reference/data/cheatsheets/ reference/data/commands/"
echo "  3. Review moved files: git status"
echo "  4. Test reference system: crack reference --stats"
echo "  5. Run tests: python3 -m pytest tests/"
echo ""
echo -e "${GREEN}Done!${NC}"
