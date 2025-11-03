# Database Validation System

## Overview

The CRACK database validation system ensures data integrity, proper normalization, and valid relationships across all command definitions.

## Usage

```bash
# Run complete validation
crack db validate

# View validation after database setup
crack db setup && crack db validate

# Check validation after updates
crack db update && crack db validate
```

## Validation Categories

### 1. Schema Validation
- ✅ All 17 required tables exist
- ✅ Proper foreign key constraints
- ✅ No missing schema elements

### 2. Command Validation
- ✅ All commands have required fields (id, name, command, description)
- ✅ Command IDs are unique
- ✅ Categories are valid enum values
- ✅ No duplicate definitions

### 3. Relationship Validation
- ✅ All command_relations point to existing commands
- ✅ No self-references
- ✅ Relation types are valid (prerequisite/alternative/next_step)
- ✅ No orphaned relationships

### 4. Normalization Validation
- ✅ Flags extracted to `command_flags` table
- ✅ Variables extracted to `variables` + `command_vars` tables
- ✅ Tags extracted to `tags` + `command_tags` tables
- ✅ Indicators stored in `command_indicators` table

### 5. Cross-Reference Validation
- ✅ All command_vars reference valid variables
- ✅ All command_tags reference valid tags
- ✅ All placeholders have variable definitions
- ✅ No broken foreign keys

### 6. Data Quality Validation
- ✅ No TODO/FIXME markers in production
- ✅ No empty descriptions
- ✅ OSCP relevance values are valid
- ✅ Example values exist for required variables

### 7. Unresolved Relations Check
- ⚠️ Identifies command references that don't map to IDs
- 📊 Compares JSON relations vs database relations
- 🎯 Estimates remaining work for complete coverage

## Current Status

After initial database setup:

```
✓ Schema Validation: PASSED (17/17 tables)
✓ Command Validation: PASSED (196 commands)
✓ Relationship Validation: PASSED (235 relations)
✓ Normalization: PASSED (696 flags, 53 variables, 151 tags)
✓ Cross-References: PASSED
✓ Data Quality: PASSED
⚠ Unresolved Relations: 963 estimated

Overall: PASSED with warnings
```

## Unresolved Relations

The 963 unresolved relations represent command references in JSON files that couldn't be mapped to command IDs. These include:

1. **Tool Commands** (~220): CLI tools not yet in database (e.g., `fping`, `masscan`, `ffuf`)
2. **GUI Tools** (~8): Applications requiring step-by-step guidance (e.g., `burp`, `wappalyzer`)
3. **Built-in Commands** (~68): Native OS commands (e.g., `cat`, `ls`, `chmod`)
4. **Descriptive Guidance** (~667): Multi-step procedures and conditional workflows

## Roadmap to Zero Warnings

See main project plan for phases to resolve all 963 unresolved relations:

- **Phase 1:** Already Exists (60 entries) - Verify & link existing commands
- **Phase 2:** Priority CLI Tools (18 entries) - Add critical OSCP tools
- **Phase 3:** Standard CLI Tools (56 entries) - Fill toolkit gaps
- **Phase 4:** Built-in Commands (68 entries) - Document basic OS commands
- **Phase 5:** GUI Tools (8 entries) - Add guided procedures
- **Phase 6:** Descriptive Procedures (753 entries) - Convert to command definitions

## Validation Output

### Terminal Output
- ✅ Color-coded status indicators
- 📊 Statistics summary
- ⚠️ Error and warning lists
- 🎯 Actionable recommendations

### Programmatic Access
```python
from crack.db.validate import DatabaseValidator
from crack.db.config import get_db_config

validator = DatabaseValidator(get_db_config())
results = validator.run_all_validations()

# Check status
if results['overall_status'] == 'PASSED':
    print("Database valid!")

# Get statistics
print(f"Commands: {results['stats']['commands']}")
print(f"Unresolved: {results['stats']['unresolved_relations']}")

# Export to JSON
import json
with open('validation_report.json', 'w') as f:
    json.dump(results, f, indent=2)
```

## Integration Points

### Pre-commit Hook
```bash
#!/bin/bash
# .git/hooks/pre-commit

if ! crack db validate --strict; then
    echo "Database validation failed - fix issues before committing"
    exit 1
fi
```

### CI/CD Pipeline
```yaml
# .github/workflows/validation.yml
- name: Validate Database
  run: |
    crack db setup
    crack db validate --format=json > validation_report.json

- name: Upload Validation Report
  uses: actions/upload-artifact@v2
  with:
    name: validation-report
    path: validation_report.json
```

### Development Workflow
```bash
# After adding new commands
vim reference/data/commands/new-tool.json
crack db update
crack db validate

# Track progress
crack db validate | grep "Unresolved Relations"
```

## Error Types

### Critical Errors (Fail Validation)
- Missing required tables
- Duplicate command IDs
- Broken foreign key relationships
- Self-referencing commands
- Invalid category values

### Warnings (Pass with Warnings)
- Unresolved command references
- Missing descriptions
- TODO markers in code
- Empty example values

## Troubleshooting

### "Missing table" Error
```bash
# Recreate schema
crack db reset
crack db setup
```

### "Broken relation" Error
```bash
# Re-import commands
crack db update
```

### High Unresolved Count
```bash
# This is expected - work through phases to add missing commands
# Track progress: 963 → 903 → 885 → ... → 0
```

## See Also

- `db/validate.py` - Validation implementation
- `db/cli.py` - CLI integration
- `db/migrate.py` - Migration system
- `reference/docs/POSTGRESQL_SETUP.md` - Setup guide
