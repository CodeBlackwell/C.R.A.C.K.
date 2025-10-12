# Intelligence System TUI Integration

## Current Status (V2.0)

### Stage 4 Complete: Passive Integration

The intelligence system is **fully initialized and operational** in TUISessionV2, but not yet displayed in the UI.

**What's Working:**
- ✅ Intelligence orchestrator initialized in `TUISessionV2.__init__()`
- ✅ Method 1 (Correlation) + Method 2 (Methodology) active
- ✅ 15 attack chains loaded from JSON
- ✅ `get_intelligence_suggestions()` method available
- ✅ Zero UI changes (backward compatible)

**How to Access Intelligence:**
```python
# In any TUI panel or method:
suggestions = self.get_intelligence_suggestions(max_tasks=5)

# Each suggestion contains:
{
    'id': 'chain-sqli-to-shell-step-0',
    'name': '⛓️ [SQL Injection] Confirm SQLi',
    'type': 'executable',
    'status': 'pending',
    'priority': 85.3,  # 0-130 score
    'phase_alignment': True,
    'intelligence_source': 'methodology',
    'metadata': {
        'command': 'sqlmap -u http://192.168.45.100/page.php?id=1 --batch',
        'category': 'attack_chain',
        'chain_id': 'sqli-to-shell',
        'step_id': 'sqli-confirm',
        'chain_progress': 0.0,
        'success_indicators': ['injectable', 'parameter: id'],
        'failure_indicators': ['not injectable'],
        'estimated_time_minutes': 5
    }
}
```

## Planned: V2.1 GuidancePanel

### Vision

A dedicated panel showing **intelligence-powered next steps** with:
- Top 5 prioritized suggestions
- Attack chain progress indicators
- Quick-win opportunities highlighted
- One-keystroke execution

### Integration Points

**1. Add Panel Class**
```python
# track/interactive/panels/guidance_panel.py

from typing import List, Dict, Any
from rich.panel import Panel
from rich.table import Table

class GuidancePanel:
    """Intelligence-powered guidance panel"""

    def __init__(self, session: 'TUISessionV2'):
        self.session = session
        self.theme = session.theme

    def render(self) -> Panel:
        """Render guidance panel with intelligence suggestions"""
        # Get suggestions
        suggestions = self.session.get_intelligence_suggestions(max_tasks=5)

        if not suggestions:
            return Panel("[dim]No intelligence suggestions available[/]",
                        title="🧠 Intelligence Guidance",
                        border_style=self.theme.panel_border())

        # Build table
        table = Table(show_header=True, box=None)
        table.add_column("#", style="cyan", width=3)
        table.add_column("Priority", style="magenta", width=8)
        table.add_column("Suggestion", style="white")
        table.add_column("Source", style="dim", width=12)

        for i, suggestion in enumerate(suggestions, 1):
            priority = suggestion.get('priority', 0)
            name = suggestion.get('name', 'Unknown')
            source = suggestion['metadata'].get('category', 'Unknown')

            # Color-code by priority
            if priority >= 80:
                priority_str = f"[bold red]{priority:.1f}[/]"
            elif priority >= 60:
                priority_str = f"[bold yellow]{priority:.1f}[/]"
            else:
                priority_str = f"[bold green]{priority:.1f}[/]"

            table.add_row(
                str(i),
                priority_str,
                name,
                source
            )

        return Panel(table,
                    title="🧠 Intelligence Guidance",
                    subtitle="[dim]Press number to execute[/]",
                    border_style=self.theme.panel_border())
```

**2. Wire into TUISessionV2**
```python
# In TUISessionV2.__init__()
self.guidance_panel = GuidancePanel(self)

# In TUISessionV2.run() main loop
if user_choice == 'g':  # Guidance shortcut
    panel_output = self.guidance_panel.render()
    self.console.print(panel_output)
```

**3. Add Keyboard Shortcut**
```python
# In TUISessionV2.__init__()
self.shortcut_handler.shortcuts['g'] = {
    'description': 'Intelligence Guidance',
    'handler': self._show_guidance_panel,
    'scope': 'global',
    'priority': 40
}

def _show_guidance_panel(self):
    """Show intelligence guidance panel"""
    panel = self.guidance_panel.render()
    self.console.print(panel)

    # Allow user to select suggestion
    choice = self.hotkey_handler.read_key()
    if choice.isdigit():
        idx = int(choice) - 1
        suggestions = self.get_intelligence_suggestions(max_tasks=5)
        if 0 <= idx < len(suggestions):
            suggestion = suggestions[idx]
            # Execute suggestion command
            self._execute_intelligence_suggestion(suggestion)
```

**4. Execution Integration**
```python
def _execute_intelligence_suggestion(self, suggestion: Dict[str, Any]):
    """Execute an intelligence suggestion"""
    command = suggestion['metadata'].get('command')
    if not command:
        self.console.print("[red]No command available[/]")
        return

    # Use existing task execution logic
    self._execute_command(command)

    # Update chain progress if applicable
    if suggestion['metadata'].get('category') == 'attack_chain':
        chain_id = suggestion['metadata']['chain_id']
        step_id = suggestion['metadata']['step_id']

        # Get command output
        output = self.last_command_output  # Assuming this is tracked

        # Check step completion
        executor = self.orchestrator.methodology_engine.chain_executor
        step = suggestion['metadata'].get('step')
        success = executor.check_step_completion(step, output)

        # Update progress
        executor.update_progress(chain_id, step_id, output, success)

        if success:
            self.console.print("[green]✓ Step completed successfully[/]")
        else:
            self.console.print("[yellow]⚠ Step may have failed - check output[/]")
```

### Dashboard Integration (Alternative)

Instead of a separate panel, add intelligence suggestions to the **Dashboard Panel**:

```python
# In DashboardPanel.render()
def render(self) -> Panel:
    # ... existing dashboard content ...

    # Add intelligence section
    if hasattr(self.session, 'orchestrator') and self.session.orchestrator:
        suggestions = self.session.get_intelligence_suggestions(max_tasks=3)
        if suggestions:
            table.add_section()  # Visual separator
            table.add_row("[bold cyan]🧠 Intelligence Suggestions[/]", "")

            for i, suggestion in enumerate(suggestions, 1):
                priority = suggestion.get('priority', 0)
                name = suggestion.get('name', 'Unknown')
                table.add_row(
                    f"  [{i}] {name}",
                    f"[magenta]{priority:.1f}[/]"
                )

    return Panel(table, title="Dashboard", border_style="cyan")
```

## Configuration

**Enable/Disable Intelligence:**
```json
// ~/.crack/config.json
{
  "intelligence": {
    "enabled": true,
    "correlation": {
      "enabled": true
    },
    "methodology": {
      "enabled": true
    }
  }
}
```

**Disable Intelligence:**
```json
{
  "intelligence": {
    "enabled": false
  }
}
```

When disabled, `TUISessionV2.orchestrator` will be `None` and `get_intelligence_suggestions()` returns empty list.

## Testing

**Manual Test:**
```bash
# Start TUI with intelligence enabled
crack track --tui 192.168.45.100 --debug

# In Python console:
from crack.track.interactive.tui_session_v2 import TUISessionV2
session = TUISessionV2('192.168.45.100')
suggestions = session.get_intelligence_suggestions()
print(f"Got {len(suggestions)} suggestions")
for s in suggestions:
    print(f"  - {s['name']} (priority: {s['priority']:.1f})")
```

**Automated Test:**
```python
def test_tui_intelligence_integration():
    """Test TUISessionV2 intelligence integration"""
    session = TUISessionV2('192.168.45.100')

    # Verify orchestrator initialized
    assert session.orchestrator is not None

    # Verify suggestions available
    suggestions = session.get_intelligence_suggestions(max_tasks=5)
    assert isinstance(suggestions, list)

    # Verify suggestion structure
    if suggestions:
        suggestion = suggestions[0]
        assert 'id' in suggestion
        assert 'name' in suggestion
        assert 'priority' in suggestion
        assert 'metadata' in suggestion
```

## Minimalist Implementation (Recommended for V2.1)

**Step 1:** Add guidance shortcut (`g`) that prints top 3 suggestions
**Step 2:** Allow numeric selection (1-3) to execute
**Step 3:** Show success/failure based on indicators
**Step 4:** Update chain progress automatically

**Total Lines:** ~100 lines (GuidancePanel + integration)

**No New Dependencies:** Reuses existing ExecutionOverlay, OutputOverlay

**Backward Compatible:** Works even if intelligence disabled

## Future Enhancements (V2.2+)

- Live suggestion updates as findings added
- Chain progress visualization (progress bars)
- Suggestion filtering by category
- Export suggestions to tasks automatically
- Success rate tracking per suggestion type

## Event Flow

```
User Action → Finding Added
    ↓
EventBus.emit('finding_added')
    ↓
CorrelationIntelligence.on_finding_added()
    ↓
TaskOrchestrator.generate_next_tasks()
    ↓
Merge correlation + methodology + chains
    ↓
Score with TaskScorer
    ↓
Sort by priority
    ↓
Return top N
    ↓
GuidancePanel.render() (V2.1)
    ↓
User selects suggestion
    ↓
Execute command
    ↓
Check success indicators
    ↓
Update chain progress
    ↓
LOOP
```

## Status

**V2.0 (Current):**
- ✅ Intelligence initialized
- ✅ Suggestions available via API
- ❌ No UI yet (passive integration)

**V2.1 (Planned):**
- 🔲 GuidancePanel implementation
- 🔲 Keyboard shortcuts
- 🔲 One-keystroke execution
- 🔲 Chain progress updates

**V2.2 (Future):**
- 🔲 Live suggestion updates
- 🔲 Progress visualization
- 🔲 Success tracking
- 🔲 Auto-task generation
