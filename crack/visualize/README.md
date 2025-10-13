# CRACK Attack Chain Visualizer

Dynamic graph visualization for attack chains with search/filter integration.

## Features

- **Dynamic Filtering:** Search by name, ID, category, tags, difficulty
- **Multiple Visualization Modes:**
  - **Detail:** Single chain step-by-step graph
  - **Relationships:** Multi-chain activation diagrams
  - **Overview:** Ecosystem category tree
- **Multiple Output Formats:**
  - **ASCII:** Terminal-native visualization (default)
  - **DOT:** GraphViz export for PNG/SVG generation
- **Integration:** Seamlessly integrates with ChainRegistry and filtering system

## Quick Start

```bash
# View specific chain
crack visualize chains linux-privesc-sudo

# Search and visualize
crack visualize chains "docker privilege"

# Filter by tag
crack visualize chains --tag QUICK_WIN --tag OSCP

# View all chains (ecosystem)
crack visualize chains --all

# Export to DOT format
crack visualize chains linux-privesc-sudo --format dot -o graph.dot

# Generate PNG (requires graphviz)
dot -Tpng graph.dot -o graph.png
```

## CLI Usage

### Filtering Options

```bash
--all                          # Visualize entire ecosystem
--category CATEGORY            # Filter by category
--tag TAG                      # Filter by tag (repeatable)
--difficulty LEVEL             # beginner|intermediate|advanced
--oscp-only                    # Only OSCP-relevant chains
--search TERM                  # Search names/descriptions
```

### Display Options

```bash
--mode MODE                    # detail|relationships|overview (auto-detect)
--related                      # Show related chains
--show-activations             # Include activation edges
```

### Output Options

```bash
--format FORMAT                # ascii|dot (default: ascii)
-o, --output FILE              # Export to file
--no-color                     # Disable colors
-i, --interactive              # Show selection menu if multiple results
```

## Examples

### Example 1: Visualize Single Chain (Detail Mode)

```bash
$ crack visualize chains linux-privesc-sudo
```

**Output:**
```
======================================================================
Linux Privilege Escalation - Sudo Exploitation
======================================================================
Category: privilege_escalation | Difficulty: beginner

Exploit GTFOBins-listed binaries allowed via NOPASSWD sudo.

┌──────────────────────────────────────────────┐
│ 1. Check Sudo Permissions                   │
│   check-sudo-privs                           │
│   [OSCP:HIGH]                                │
└───────────────────┬──────────────────────────┘
                    │
                    ──► [requires]
                    │
┌──────────────────────────────────────────────┐
│ 2. Analyze Sudoers Configuration             │
│   [AUTOMATED]                                │
└───────────────────┬──────────────────────────┘
                    │
              ┌─────┴─────┐
              │           │
        [exploitable]  [not found]
              │           │
              ▼           ▼
      ┌──────────┐   ┌─────────────┐
      │ Exploit  │   │ Try SUID    │
      │          │   │ (activates) │
      └──────────┘   └─────────────┘

Legend:
  ──► Dependency edge
  ··► Activation edge (chain switching)
  [condition] Edge label
```

### Example 2: Filter by Tag (Relationships Mode)

```bash
$ crack visualize chains --tag QUICK_WIN
```

**Output:**
```
======================================================================
Attack Chain Relationships (8 chains)
======================================================================

┌────────────────────┐
│ linux-privesc-enum │
│ [Privilege Esc]    │
│ [OSCP]             │
└─────────┬──────────┘
          │
     ┌────┴───┬──────┬──────┐
     │        │      │      │
     ▼        ▼      ▼      ▼
  ┌─────┐ ┌──────┐  ...   ...
  │Sudo │ │ SUID │
  │     │ │      │
  └─────┘ └──────┘

Activation Summary:
  Sudo: 3 activation(s)
  SUID: 2 activation(s)
  Docker: 1 activation(s)
```

### Example 3: Ecosystem Overview

```bash
$ crack visualize chains --all
```

**Output:**
```
======================================================================
CRACK Attack Chain Ecosystem (25 chains across 4 categories)
======================================================================

[Privilege Escalation] (12 chains)
  ├─ linux-privesc-enum (OSCP, beginner)
  ├─ linux-privesc-sudo (OSCP, QUICK_WIN, beginner)
  ├─ linux-privesc-suid-basic (QUICK_WIN, beginner)
  ├─ linux-privesc-docker (OSCP, intermediate)
  └─ linux-capabilities (OSCP, intermediate)

[Enumeration] (8 chains)
  ├─ web-enum-basic (OSCP, beginner)
  ├─ smb-enum-shares (OSCP, beginner)
  └─ ad-enum-kerberos (OSCP, advanced)

[Lateral Movement] (3 chains)
  ├─ pass-the-hash (OSCP, intermediate)
  └─ psexec-pivot (OSCP, intermediate)

[Exploitation] (2 chains)
  └─ buffer-overflow-basic (OSCP, intermediate)

Total: 25 chains | OSCP-Relevant: 20
```

### Example 4: DOT Export + PNG Generation

```bash
# Export to DOT format
$ crack visualize chains linux-privesc-sudo --format dot -o privesc.dot
✓ Graph exported to: privesc.dot

Generate PNG:
  dot -Tpng privesc.dot -o graph.png

Generate SVG:
  dot -Tsvg privesc.dot -o graph.svg

# Generate PNG
$ dot -Tpng privesc.dot -o privesc.png
```

### Example 5: Interactive Selection

```bash
$ crack visualize chains "privilege" -i

Found 12 matching chains:

  [1] linux-privesc-sudo (OSCP:HIGH, QUICK_WIN)
      Category: privilege_escalation

  [2] linux-privesc-suid-basic (QUICK_WIN)
      Category: privilege_escalation

  [3] linux-privesc-docker (OSCP)
      Category: privilege_escalation

  ... and 9 more

Options:
  [1-10] Select specific chain
  [a] Visualize all results
  [q] Cancel

Select: 1

[Shows detailed graph for selected chain]
```

## Architecture

### Core Components

```
visualize/
├── __init__.py          # Module exports
├── cli.py               # CLI interface
├── models.py            # Graph data models (GraphNode, GraphEdge, Graph)
├── graph_builder.py     # Chain → Graph conversion
├── filters.py           # Search/filter integration
└── renderers/
    ├── ascii_renderer.py   # Terminal visualization
    └── dot_renderer.py     # GraphViz export
```

### Visualization Modes

**Detail Mode** (single chain):
- Each step becomes a node
- Dependencies shown as edges
- Conditional branches visualized
- Tags and metadata displayed

**Relationships Mode** (multi-chain):
- Each chain becomes a node
- Activation edges between chains
- Grouped by category
- Confidence levels shown

**Overview Mode** (ecosystem):
- Category hierarchy
- Chains grouped under categories
- OSCP/QUICK_WIN highlighting
- Summary statistics

### Integration Points

**ChainRegistry:**
- `get_chain_by_id()`
- `get_all_chains()`
- `search_chains()`

**ChainFilter:**
- Tag filtering
- Category filtering
- Metadata filtering

**ActivationManager:**
- Cross-chain activation detection
- Confidence scoring

## Development

### Adding New Renderers

```python
# visualize/renderers/my_renderer.py
from ..models import Graph

class MyRenderer:
    def render(self, graph: Graph) -> str:
        # Custom rendering logic
        return output_string

# visualize/renderers/__init__.py
from .my_renderer import MyRenderer
__all__ = ['AsciiRenderer', 'DotRenderer', 'MyRenderer']
```

### Extending Graph Builder

```python
from visualize import ChainGraphBuilder

builder = ChainGraphBuilder()

# Custom graph mode
def build_custom(chains):
    graph = Graph()
    graph.metadata['mode'] = 'custom'
    # Build custom graph structure
    return graph
```

## Testing

```bash
# Test module imports
python3 -c "from visualize import ChainGraphBuilder, ChainFilter"

# Test with real chain
crack visualize chains linux-privesc-sudo

# Test filters
crack visualize chains --tag OSCP --category privilege_escalation

# Test export
crack visualize chains --all --format dot -o test.dot
```

## Troubleshooting

### "Chain registry not available"
**Solution:** Ensure `crack.reference.chains` is installed and ChainRegistry can be imported.

### "No chains match criteria"
**Solution:** Check filter parameters. Try `--all` to see all available chains first.

### Colors not displaying
**Solution:** Use `--no-color` flag or ensure terminal supports ANSI colors.

### DOT file won't generate PNG
**Solution:** Install GraphViz: `sudo apt-get install graphviz`

## Future Enhancements

- [ ] HTML renderer with interactive D3.js/vis.js
- [ ] Real-time session overlay (highlight completed steps)
- [ ] Finding activation visualization
- [ ] Diff view (compare chain variations)
- [ ] Export to Mermaid format
- [ ] Integration with crack track (task completion visualization)

## See Also

- `reference/chains/README.md` - Attack chain system documentation
- `reference/chains/filtering/README.md` - Filter system details
- `CLAUDE.md` - CRACK project architecture

## License

Part of CRACK (Comprehensive Recon & Attack Creation Kit)
