# Command Enrichment Toolkit - Quick Start

## 5-Minute Setup

```bash
cd /home/kali/Desktop/OSCP/crack/reference/tools

# Test all tools work
./test_toolkit.sh

# See current state
python3 metrics_dashboard.py
```

## Daily Workflow

### 1. Morning: Check Progress
```bash
python3 metrics_dashboard.py
```

### 2. Get Work Items
```bash
# See worst 10 commands
python3 validate_commands.py --limit 10
```

### 3. Enrich Commands

**Option A: Quick (5 min/command)**
```bash
# Generate and apply template
python3 template_generator.py <COMMAND_ID> --apply

# Review and tweak manually if needed
```

**Option B: Thorough (15-30 min/command)**
```bash
# Generate template first
python3 template_generator.py <COMMAND_ID> --apply

# Then interactively add custom details
python3 enrich_command.py <COMMAND_ID>
```

### 4. Track Progress
```bash
# Re-run dashboard to see improvements
python3 metrics_dashboard.py
```

## Common Tasks

### Preview Command Status
```bash
python3 enrich_command.py <COMMAND_ID> --show
```

### Generate Template (No Apply)
```bash
python3 template_generator.py <COMMAND_ID>
```

### Dry Run Template Application
```bash
python3 template_generator.py <COMMAND_ID> --apply --dry-run
```

### Export Priority List
```bash
python3 validate_commands.py --export work_queue.json --limit 50
```

### Focus on Specific Category
```bash
# Find all pivoting commands
jq -r '.[] | select(.category == "pivoting") | .id' work_queue.json
```

## Interactive Enrichment Tips

### JSON Input Format
```
Field: use_cases
Type: list

Use cases:
["First use case",
"Second use case",
"Third use case"]
.
```

### Commands
- Type `skip` to skip current field
- Type `quit` to save and exit
- Type `.` on blank line to finish JSON input

## Quality Goals

| Metric | Current | Target |
|--------|---------|--------|
| Average Overall | 16.1% | 70%+ |
| Critical Fields | 23.1% | 80%+ |
| Educational Fields | 0.0% | 50%+ |
| Grade F Commands | 95.1% | <20% |

## Focus Areas (Priority Order)

1. **Prerequisites** (6.6% coverage) - Highest impact, easiest to add
2. **Success/Failure Indicators** (14.8% coverage) - Critical for users
3. **Next Steps** (16.4% coverage) - Guides workflow
4. **Flag Explanations** (31.1% coverage) - Command-specific, needs manual work
5. **Educational Fields** (0% coverage) - Use template generator

## Weekly Targets

### Week 1: Foundation (20 commands)
- Apply templates to 20 worst commands
- Focus on prerequisites, indicators, next_steps
- Target: Average score 25%

### Week 2: Critical Fields (30 commands)
- Add flag_explanations manually
- Enhance troubleshooting sections
- Target: Average score 40%

### Week 3: Educational (40 commands)
- Use template generator for educational fields
- Add use_cases, advantages, disadvantages
- Target: Average score 55%

### Week 4: Polish (32 remaining)
- Complete all remaining commands
- Add references and detailed output_analysis
- Target: Average score 70%+

## Batch Operations

### Apply Templates to Top 10
```bash
for cmd_id in $(python3 validate_commands.py --export /dev/stdout --limit 10 | jq -r '.[].id'); do
    echo "Enriching: $cmd_id"
    python3 template_generator.py "$cmd_id" --apply
done
```

### Check Category Coverage
```bash
python3 validate_commands.py | grep -A 7 "CATEGORY BREAKDOWN"
```

## Troubleshooting

**Command not found:**
- Verify command ID is correct
- Check command exists in JSON files

**Template not applying:**
- Use --dry-run to see what would be applied
- Check file permissions

**Interactive mode stuck:**
- Press Ctrl+C to exit
- Use template generator for bulk operations

## Migration to Neo4j

After enrichment batch:
```bash
cd ../../db/neo4j-migration/scripts
./run_migration.sh
python3 health_check.py
```

## Help

Full documentation: `README.md`

Tool-specific help:
```bash
python3 validate_commands.py --help
python3 metrics_dashboard.py --help
python3 enrich_command.py --help
python3 template_generator.py --help
```
