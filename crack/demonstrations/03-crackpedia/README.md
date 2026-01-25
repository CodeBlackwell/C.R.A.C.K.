# Video 03: Crackpedia (GUI Command Encyclopedia)

**Duration:** 10-12 min | **Focus:** Visual command reference and relationships

## Samples Needed

Place in `samples/`:

- [ ] N/A - Uses live Neo4j database

## Scripts

Place in `scripts/`:

- [ ] `talking_points.md` - Section-by-section narration
- [ ] `navigation_flow.md` - UI navigation sequence
- [ ] `search_queries.txt` - Search terms to demo

## Pre-Recording Setup

- [ ] Neo4j running with full command database
- [ ] Verify: `crack reference --stats` shows 795+ commands
- [ ] Test Crackpedia launches without errors
- [ ] Test all 4 views work (Commands, Chains, Cheatsheets, Writeups)
- [ ] Clear any previous search history

## Key Demo Flow

```bash
# Launch
crackpedia

# In GUI:
# 1. Search "sqli" - show filtering
# 2. Arrow keys to navigate results
# 3. Select "nmap" - show relationship graph
# 4. Click yellow node (alternative) - graph updates
# 5. Check Details panel - flags, variables
# 6. Switch to Chains tab
# 7. Search "kerberoast" - show DAG
# 8. Click step node - show details
# 9. Switch to Cheatsheets tab
# 10. Browse categories
```

## Key Shots

1. 3-panel layout overview (wide establishing shot)
2. Real-time search filtering
3. Relationship graph expanding on node click
4. Attack chain DAG visualization
5. Flag explanations panel (zoom)
6. Keyboard navigation demo

## UI Elements to Highlight

- Neo4j connection badge (top right)
- OSCP relevance badges on commands
- Graph color legend (yellow/red/green)
- Category accordion navigation
- Keyboard shortcuts overlay

## Thumbnail Concept

3-panel dark GUI with glowing cyan graph nodes
Text: "734 Commands"
