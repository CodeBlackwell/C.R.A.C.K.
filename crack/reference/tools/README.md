# Command Enrichment Toolkit

Development tools to streamline command documentation enrichment.

## Tools Overview

### 1. Validation Tool (`validate_commands.py`)
Audits field completeness and generates enrichment priorities.

**Usage:**
```bash
# Show current quality metrics
python3 validate_commands.py

# Export enrichment priority list
python3 validate_commands.py --export enrichment_list.json --limit 50

# Custom data directory
python3 validate_commands.py --data-dir /path/to/commands
```

**Output:**
- Global field coverage statistics
- Per-category breakdown
- Top N commands needing enrichment
- Missing field analysis

### 2. Metrics Dashboard (`metrics_dashboard.py`)
Visual progress tracking with quality scoring.

**Usage:**
```bash
# Display dashboard
python3 metrics_dashboard.py

# Export detailed report
python3 metrics_dashboard.py --export metrics_report.json
```

**Features:**
- Overall quality score (A-F grading)
- Category performance breakdown
- Field coverage visualization
- Actionable recommendations

**Scoring System:**
- Critical fields: 70% of overall score
- Educational fields: 30% of overall score
- Grades: A (90%+), B (80-89%), C (70-79%), D (60-69%), F (<60%)

### 3. Enrichment CLI (`enrich_command.py`)
Interactive tool for adding missing fields.

**Usage:**
```bash
# Show command status
python3 enrich_command.py <COMMAND_ID> --show

# Interactively enrich all empty fields
python3 enrich_command.py <COMMAND_ID>

# Enrich specific fields only
python3 enrich_command.py <COMMAND_ID> --fields use_cases advantages disadvantages
```

**Interactive Mode:**
- Multi-line JSON input support
- Skip fields with 'skip' command
- Save and exit with 'quit' command
- End JSON input with '.' on blank line

**Example Session:**
```
Field: use_cases
Type: list
Example: ["Initial reconnaissance", "Service detection"]

Use cases (list of scenarios):
(For JSON input, enter on multiple lines, then '.' on blank line to finish)
["Initial network discovery",
"Verify open ports after exploitation",
"Map attack surface"]
.

✓ Added use_cases
```

### 4. Template Generator (`template_generator.py`)
Generates smart field templates based on command analysis.

**Usage:**
```bash
# Generate template (preview only)
python3 template_generator.py <COMMAND_ID>

# Apply template to command (dry run)
python3 template_generator.py <COMMAND_ID> --apply --dry-run

# Apply template and save changes
python3 template_generator.py <COMMAND_ID> --apply
```

**Smart Detection:**
- Tool-specific templates (nmap, curl, ssh, python, netcat)
- Category-specific templates (enumeration, exploitation, pivoting, etc.)
- Automatic prerequisite detection
- Flag analysis
- Variable extraction

**Supported Tools:**
- nmap: Network scanning templates
- netcat: Shell and transfer templates
- curl: Web application testing templates
- ssh: Tunneling and pivoting templates
- python: Scripting and server templates

## Enrichment Workflow

### Phase 1: Assessment
```bash
# 1. Run metrics dashboard to see current state
python3 metrics_dashboard.py

# 2. Identify worst-performing categories and commands
python3 validate_commands.py --limit 20

# 3. Export prioritized enrichment list
python3 validate_commands.py --export work_queue.json --limit 50
```

### Phase 2: Batch Template Application
```bash
# Generate templates for top priority commands
# Review and apply in bulk

for cmd_id in $(jq -r '.[].id' work_queue.json | head -10); do
    echo "Processing: $cmd_id"
    python3 template_generator.py "$cmd_id" --apply
done
```

### Phase 3: Manual Enrichment
```bash
# Interactively enrich commands with custom content
python3 enrich_command.py <COMMAND_ID>

# Focus on fields not well-handled by templates:
# - flag_explanations (specific to each command)
# - troubleshooting (command-specific issues)
# - references (authoritative sources)
```

### Phase 4: Progress Tracking
```bash
# Re-run dashboard to see improvements
python3 metrics_dashboard.py --export progress_report.json

# Compare with baseline
diff baseline_report.json progress_report.json
```

### Phase 5: Neo4j Migration
```bash
# After enrichment, migrate to Neo4j
cd ../../db/neo4j-migration/scripts
./run_migration.sh

# Validate migration
python3 health_check.py
```

## Field Reference

### Critical Fields (70% weight)
- `flag_explanations`: Dict of flag: description
- `variables`: List of variable definitions
- `prerequisites`: List of required conditions
- `success_indicators`: List of success outputs
- `failure_indicators`: List of error outputs
- `next_steps`: List of follow-up actions
- `alternatives`: List of alternative command IDs

### Educational Fields (30% weight)
- `use_cases`: List of scenarios
- `advantages`: List of benefits
- `disadvantages`: List of limitations
- `output_analysis`: List of interpretation guides
- `common_uses`: List of typical applications
- `references`: List of dicts with title/url
- `troubleshooting`: Dict of issue: solution

## Quality Targets

**Minimum Viable Command:**
- 60% overall score (Grade D)
- All critical fields populated
- At least 3 educational fields

**High Quality Command:**
- 80% overall score (Grade B)
- All critical fields fully detailed
- All educational fields populated

**Exemplar Command:**
- 90% overall score (Grade A)
- Comprehensive critical fields
- Rich educational content
- Multiple references
- Detailed troubleshooting

## Tips

### Efficient Enrichment
1. **Use templates first**: Let the generator create baseline content
2. **Batch similar commands**: Enrich all nmap commands together (shared context)
3. **Copy from exemplars**: Reference existing high-quality commands
4. **Focus critical fields**: Prioritize flag_explanations and troubleshooting

### Quality Over Quantity
- Don't add generic content just to fill fields
- Empty field better than wrong/misleading information
- Use skip in interactive mode for uncertain fields
- Mark fields for later review if needed

### Time Estimates
- Template generation + review: 5 minutes per command
- Interactive enrichment: 15-30 minutes per command
- High-quality exemplar: 1-2 hours per command

## Maintenance

### Regular Tasks
```bash
# Weekly: Check overall progress
python3 metrics_dashboard.py

# After major changes: Validate data integrity
python3 validate_commands.py

# Before releases: Export current state
python3 metrics_dashboard.py --export release_metrics.json
```

### Tracking Goals
Monitor these metrics over time:
- Average overall score (target: 70%+)
- Critical field coverage (target: 80%+)
- Educational field coverage (target: 50%+)
- Grade F percentage (target: <20%)

## Integration

### With Neo4j
After enriching commands, migrate to Neo4j for advanced querying:
```bash
cd ../../db/neo4j-migration/scripts
python3 import_to_neo4j.py
```

### With CLI
Enriched fields automatically display in CLI:
```bash
crack reference <command-id>
```

### With Track Module
Track module can leverage enriched metadata for recommendations and alternatives.

## Troubleshooting

**Template not applying:**
- Check command ID is correct
- Verify JSON file is writable
- Use --dry-run to preview changes

**Interactive mode exits immediately:**
- Ensure Python 3.7+ is installed
- Check terminal supports interactive input
- Try --show first to verify command exists

**Metrics show 0% coverage:**
- Verify data directory path is correct
- Check JSON files match naming pattern
- Ensure at least one command exists

## Future Enhancements

Potential additions:
- Batch enrichment web UI
- AI-assisted field generation
- Cross-command consistency checker
- Duplicate content detector
- Reference link validator
