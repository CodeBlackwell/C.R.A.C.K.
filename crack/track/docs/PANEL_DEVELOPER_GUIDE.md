# CRACK Track TUI - Panel Developer Guide

**Quick-start guide for building TUI panels with Rich library**

## Table of Contents
1. [Architecture Overview](#1-architecture-overview)
2. [Foundation Concepts](#2-foundation-concepts)
3. [Panel Structure](#3-panel-structure)
4. [Input Handling](#4-input-handling)
5. [State Management](#5-state-management)
6. [Debug Logging](#6-debug-logging)
7. [Panel Registration](#7-panel-registration)
8. [Tutorial: Findings Browser](#8-tutorial-findings-browser)
9. [Advanced Patterns](#9-advanced-patterns)
10. [Testing](#10-testing)
11. [Common Pitfalls](#11-common-pitfalls)
12. [Reference](#12-reference)

---

## 1. Architecture Overview

```
TUISessionV2
  ↓
Layout (3-panel: header, content, footer)
  ↓
Panel Loops (state-specific)
  ↓
Render Methods → Input Processing → State Updates → Display Refresh
```

**Key Files:**
- `tui_session_v2.py` - Main controller
- `tui_config.py` - Config panel (reference)
- `panels/` - Individual panel modules

**Data Flow:** Input → Parse → Validate → Execute → Update State → Refresh Display

---

## 2. Foundation Concepts

### Live Display Pattern
```python
with Live(layout, console=console, screen=False, auto_refresh=False) as live:
    live.refresh()        # Update display
    live.stop()           # Freeze for input
    user_input = input()  # Get input
    live.start()          # Resume
```

**Critical Rule:** Always `stop()` before `input()`, then `start()` after.

### Panel Structure
```python
from rich.panel import Panel
from rich.table import Table
from rich import box

panel = Panel(
    content,                      # Table, Text, etc.
    title="[bold]Title[/]",
    border_style="cyan",
    box=box.ROUNDED              # NEVER use box=None
)
```

### Layout Organization
```python
layout = Layout()
layout.split_column(
    Layout(name='header', size=3),   # Fixed height
    Layout(name='menu'),              # Flexible
    Layout(name='footer', size=3)     # Fixed height
)
```

---

## 3. Panel Structure

Every panel has three components:

### 1. Data Source
```python
# From profile
tasks = self.profile.task_tree.get_all_tasks()

# From config
config = ConfigPanel.load_config()

# From engine
recommendations = RecommendationEngine.get_recommendations(self.profile)
```

### 2. Render Method
```python
@classmethod
def render_panel(cls, data: Dict) -> Panel:
    """Convert data to Rich Panel"""
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Label", style="bold cyan", width=12)
    table.add_column("Value", style="white")

    for key, value in data.items():
        table.add_row(f"{key}:", value)

    return Panel(table, title="[bold]Panel[/]", border_style="cyan")
```

### 3. Update Logic
```python
def _refresh_panels(self, layout: Layout):
    """Refresh all panels with current state"""
    layout['header'].update(self._render_header())
    layout['menu'].update(self._render_menu())
    layout['footer'].update(self._render_footer())
```

**Refresh Triggers:**
- Before input prompt (show latest state)
- After user action (show updates)
- After state transition (show new panel)

---

## 4. Input Handling

### Standard Pattern
```python
def _panel_loop(self, live: Live, layout: Layout):
    running = True

    while running:
        # Refresh and display
        self._refresh_panels(layout)
        live.refresh()

        # Get input
        live.stop()
        self.console.print("\n[bold bright_yellow]Choice:[/] ", end="")

        try:
            user_input = input().strip()
        except (EOFError, KeyboardInterrupt):
            live.start()
            return

        live.start()

        # Process
        if user_input:
            result = self._process_input(user_input)
            if result == 'exit':
                running = False
```

### Input Processing
```python
def _process_input(self, user_input: str) -> Optional[str]:
    """
    Returns: 'exit', 'continue', 'back', or None
    """
    # Global shortcuts
    if user_input.lower() == 'q':
        return 'exit'

    # Panel-specific actions
    if user_input in ['1', '2', '3']:
        self._handle_choice(user_input)
        return None

    # Invalid
    self.console.print(f"[red]Invalid: {user_input}[/]")
    return None
```

### Validation
```python
def _handle_edit(self, choice: str):
    live.stop()

    try:
        new_value = input("New value: ").strip()

        if not self._validate(new_value):
            self.console.print("[red]Invalid[/]")
            return

        self._save(new_value)
    finally:
        time.sleep(0.5)
        live.start()  # ALWAYS restart

def _validate_port(self, port_str: str) -> bool:
    try:
        port = int(port_str)
        return 1 <= port <= 65535
    except ValueError:
        return False
```

---

## 5. State Management

### State Flags
```python
class TUISessionV2(InteractiveSession):
    def __init__(self, target: str, debug: bool = False):
        super().__init__(target)

        # State flags
        self.config_confirmed = False
        self.current_panel = 'config'
        self.show_help = False
        self.debug_mode = debug
```

### State Transitions
```python
def run(self):
    layout = self._build_layout()

    with Live(layout, ...) as live:
        # State 1: Config (mandatory)
        if not self.config_confirmed:
            self._config_panel_loop(live, layout)

        # State 2: Main dashboard
        if self.config_confirmed:
            self.current_panel = 'dashboard'
            self._main_loop(live, layout)
```

### Navigation Stack
```python
class NavigationStack:
    def __init__(self):
        self.stack = ['dashboard']

    def push(self, panel_name: str):
        self.stack.append(panel_name)

    def pop(self) -> str:
        if len(self.stack) > 1:
            self.stack.pop()
        return self.stack[-1]

    def breadcrumb(self) -> str:
        return " > ".join(self.stack)
```

---

## 6. Debug Logging

### Strategic Chokepoint Pattern
Log at critical decision points only:

```python
from ..debug_logger import get_debug_logger
from ..log_types import LogCategory, LogLevel

class FindingsPanel(BasePanel):
    def __init__(self, session):
        self.debug_logger = session.debug_logger

        # Chokepoint 1: Initialization
        self.debug_logger.log("Panel initialized",
                             category=LogCategory.SYSTEM_INIT,
                             level=LogLevel.INFO)

    def render(self, layout: Layout):
        # Chokepoint 2: Rendering
        self.debug_logger.log("Rendering panel",
                             category=LogCategory.UI_RENDER,
                             level=LogLevel.DEBUG,
                             filter=self.filter_type,
                             count=len(self.data))

    def process_input(self, user_input: str):
        # Chokepoint 3: Input
        self.debug_logger.log("Processing input",
                             category=LogCategory.UI_INPUT,
                             level=LogLevel.TRACE,
                             input=user_input)

        # Chokepoint 4: State transition
        if state_changed:
            self.debug_logger.log("State changed",
                                 category=LogCategory.STATE_TRANSITION,
                                 level=LogLevel.INFO,
                                 old=old_state,
                                 new=new_state)
```

### Log Categories
- `UI.RENDER` - Panel rendering
- `UI.INPUT` - Input processing
- `UI.MENU` - Menu operations
- `STATE.TRANSITION` - State changes
- `EXECUTION.START/END` - Task execution

### Enable Logging
```bash
# Development
crack track --tui <target> --debug --debug-categories=UI:VERBOSE,STATE:VERBOSE

# Specific category
crack track --tui <target> --debug --debug-categories=UI.INPUT:TRACE

# View logs
tail -f .debug_logs/tui_debug_*.log
grep "\[UI.INPUT\]" .debug_logs/tui_debug_*.log
```

---

## 7. Panel Registration

### Base Panel Class
```python
# panels/base.py
from abc import ABC, abstractmethod

class BasePanel(ABC):
    def __init__(self, session: 'TUISessionV2'):
        self.session = session
        self.console = session.console
        self.profile = session.profile

    @abstractmethod
    def render(self, layout: Layout) -> None:
        pass

    @abstractmethod
    def process_input(self, user_input: str) -> Optional[str]:
        pass

    def run(self, live: Live, layout: Layout):
        """Standard panel loop"""
        running = True

        while running:
            self.render(layout)
            live.refresh()

            live.stop()
            try:
                user_input = input().strip()
            except (EOFError, KeyboardInterrupt):
                live.start()
                return 'exit'
            live.start()

            if user_input:
                result = self.process_input(user_input)
                if result in ['exit', 'back', 'continue']:
                    return result
```

### Panel Implementation
```python
# panels/dashboard_panel.py
from .base import BasePanel

class DashboardPanel(BasePanel):
    def render(self, layout: Layout):
        layout['header'].update(self._render_header())
        layout['menu'].update(self._render_menu())
        layout['footer'].update(self._render_footer())

    def _render_menu(self) -> Panel:
        table = Table(show_header=False, box=None)
        table.add_column("Num", style="bold", width=4)
        table.add_column("Action")

        table.add_row("1.", "Execute next task")
        table.add_row("2.", "Browse tasks")
        table.add_row("q.", "Quit")

        return Panel(table, title="[bold]Dashboard[/]", border_style="cyan")

    def process_input(self, user_input: str):
        if user_input.lower() == 'q':
            return 'exit'
        elif user_input == '1':
            return 'next_task'
        elif user_input == '2':
            return 'task_list'
        else:
            self.console.print(f"[red]Invalid: {user_input}[/]")
            return None
```

### Integration
```python
# tui_session_v2.py
from .panels.dashboard_panel import DashboardPanel

class TUISessionV2(InteractiveSession):
    def __init__(self, target: str):
        super().__init__(target)
        self.dashboard_panel = DashboardPanel(self)
        self.current_panel = 'config'

    def run(self):
        layout = self._build_layout()

        with Live(layout, ...) as live:
            if not self.config_confirmed:
                self._config_panel_loop(live, layout)

            while self.config_confirmed:
                if self.current_panel == 'dashboard':
                    result = self.dashboard_panel.run(live, layout)

                    if result == 'exit':
                        break
                    elif result == 'task_list':
                        self.current_panel = 'task_list'
```

---

## 8. Tutorial: Findings Browser

Build a paginated findings browser with filtering.

### Step 1: Create Panel
```python
# panels/findings_panel.py
from .base import BasePanel
from typing import Optional

class FindingsPanel(BasePanel):
    def __init__(self, session):
        super().__init__(session)
        self.debug_logger = session.debug_logger
        self.filter_type = 'all'
        self.current_page = 1
        self.per_page = 10

    def render(self, layout: Layout):
        self.debug_logger.log("Rendering findings",
                             category=LogCategory.UI_RENDER,
                             count=len(self.profile.findings or []))

        layout['header'].update(self._render_header())
        layout['menu'].update(self._render_findings_table())
        layout['footer'].update(self._render_footer())

    def _render_header(self) -> Panel:
        breadcrumb = "Dashboard > Findings"
        title = f"[bold cyan]CRACK Track[/] | {breadcrumb}"
        return Panel(title, border_style="cyan", box=box.HEAVY)

    def _render_findings_table(self) -> Panel:
        findings = self._get_filtered_findings()

        # Pagination
        total = len(findings)
        total_pages = (total + self.per_page - 1) // self.per_page
        start = (self.current_page - 1) * self.per_page
        end = start + self.per_page
        page_findings = findings[start:end]

        # Build table
        table = Table(show_header=True, box=box.SIMPLE, padding=(0, 1))
        table.add_column("#", style="bold", width=3)
        table.add_column("Type", style="cyan", width=12)
        table.add_column("Description")
        table.add_column("Source", style="dim", width=15)

        for i, finding in enumerate(page_findings, start + 1):
            icon = self._get_icon(finding.get('type'))
            desc = finding.get('description', 'N/A')[:47] + "..." if len(desc) > 50 else desc

            table.add_row(
                str(i),
                f"{icon} {finding.get('type')}",
                desc,
                finding.get('source', 'N/A')[:15]
            )

        if not page_findings:
            table.add_row("", "[dim]No findings[/]", "", "")

        title = f"Filter: {self.filter_type.title()}"
        subtitle = f"Page {self.current_page}/{total_pages} | Total: {total}"

        return Panel(table, title=title, subtitle=subtitle, border_style="magenta")

    def _render_footer(self) -> Panel:
        shortcuts = "[cyan](f)[/] Filter | [cyan](n)[/] Next | [cyan](p)[/] Prev | [cyan](b)[/] Back | [cyan](q)[/] Quit"
        return Panel(shortcuts, border_style="cyan", box=box.HEAVY)

    def _get_filtered_findings(self) -> list:
        findings = self.profile.findings or []
        if self.filter_type == 'all':
            return findings
        return [f for f in findings if f.get('type') == self.filter_type]

    def _get_icon(self, finding_type: str) -> str:
        icons = {
            'vulnerability': '🔓',
            'directory': '📁',
            'credential': '🔑',
            'user': '👤',
            'note': '📝'
        }
        return icons.get(finding_type, '•')

    def process_input(self, user_input: str) -> Optional[str]:
        self.debug_logger.log("Processing input",
                             category=LogCategory.UI_INPUT,
                             input=user_input)

        if user_input.lower() == 'q':
            return 'exit'
        elif user_input.lower() == 'b':
            return 'back'
        elif user_input.lower() == 'f':
            old_filter = self.filter_type
            self._show_filter_menu()
            if old_filter != self.filter_type:
                self.debug_logger.log("Filter changed",
                                     category=LogCategory.STATE_TRANSITION,
                                     old=old_filter, new=self.filter_type)
            return None
        elif user_input.lower() == 'n':
            findings = self._get_filtered_findings()
            total_pages = (len(findings) + self.per_page - 1) // self.per_page
            if self.current_page < total_pages:
                self.current_page += 1
            return None
        elif user_input.lower() == 'p':
            if self.current_page > 1:
                self.current_page -= 1
            return None
        else:
            self.console.print(f"[red]Invalid: {user_input}[/]")
            return None

    def _show_filter_menu(self):
        self.console.print("\n[bold cyan]Filter:[/]")
        self.console.print("  1. All  2. Vulnerabilities  3. Directories")
        self.console.print("  4. Credentials  5. Users  6. Notes")
        self.console.print("\n[cyan]Select [1-6]:[/] ", end="")

        choice = input().strip()

        filter_map = {
            '1': 'all', '2': 'vulnerability', '3': 'directory',
            '4': 'credential', '5': 'user', '6': 'note'
        }

        if choice in filter_map:
            self.filter_type = filter_map[choice]
            self.current_page = 1
            self.console.print(f"[green]✓ Filter: {self.filter_type}[/]")
        else:
            self.console.print("[red]Invalid[/]")

        time.sleep(0.5)
```

### Step 2: Register in Session
```python
# tui_session_v2.py
from .panels.findings_panel import FindingsPanel

class TUISessionV2(InteractiveSession):
    def __init__(self, target: str):
        super().__init__(target)
        self.findings_panel = FindingsPanel(self)

    def run(self):
        # ... existing code ...
        while self.config_confirmed:
            if self.current_panel == 'findings':
                result = self.findings_panel.run(live, layout)

                if result == 'exit':
                    break
                elif result == 'back':
                    self.current_panel = 'dashboard'
```

### Step 3: Test
```bash
crack track --tui 192.168.1.1

# Debug mode
crack track --tui 192.168.1.1 --debug --debug-categories=UI:VERBOSE,STATE:VERBOSE

# Check logs
tail -f .debug_logs/tui_debug_*.log
grep "Findings" .debug_logs/tui_debug_*.log
```

---

## 9. Advanced Patterns

### Split View Layout
```python
def _build_split_layout(self) -> Layout:
    layout = Layout()
    layout.split_column(
        Layout(name='header', size=5),
        Layout(name='workspace'),
        Layout(name='footer', size=3)
    )
    layout['workspace'].split_row(
        Layout(name='details', ratio=40),
        Layout(name='output', ratio=60)
    )
    return layout
```

### Stage Navigator
```python
def _render_stage_navigator(self, stages: list, current: int) -> str:
    parts = []
    for i, stage in enumerate(stages):
        if stage['status'] == 'completed':
            parts.append(f"[green][✓ {stage['name']}][/]")
        elif i == current:
            parts.append(f"[cyan][● {stage['name']}][/]")
        else:
            parts.append(f"[dim][○ {stage['name']}][/]")
    return " → ".join(parts)
```

### Live Output Streaming
```python
from threading import Thread

def _execute_with_live_output(self, command: str, output_ref: list):
    def stream():
        proc = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, text=True)
        for line in proc.stdout:
            output_ref.append(line.rstrip())
        proc.wait()

    thread = Thread(target=stream, daemon=True)
    thread.start()

    while thread.is_alive():
        self._refresh_output_panel(output_ref)
        live.refresh()
        time.sleep(0.5)
```

---

## 10. Testing

### Manual Checklist
- [ ] Renders on 80x24 terminal
- [ ] Text doesn't overflow
- [ ] All menu options work
- [ ] Invalid input handled
- [ ] Ctrl+C/D handled
- [ ] Navigation works (to, from, back)
- [ ] Data updates correctly
- [ ] Empty data handled
- [ ] Debug logs show key events

### Debug Workflow
```bash
# Enable comprehensive logging
crack track --tui 192.168.1.1 --debug \
  --debug-categories=UI:TRACE,STATE:VERBOSE --debug-timing

# Reproduce issue, then analyze
grep -A 5 ERROR .debug_logs/tui_debug_*.log
grep "\[UI.INPUT\]" .debug_logs/tui_debug_*.log
grep "\[STATE.TRANSITION\]" .debug_logs/tui_debug_*.log
```

### Unit Tests
```python
# tests/track/interactive/test_findings_panel.py
import pytest
from unittest.mock import Mock

@pytest.fixture
def mock_session():
    session = Mock()
    session.profile = TargetProfile('192.168.1.1')
    session.console = Mock()
    session.debug_logger = Mock()
    return session

def test_filter_findings(mock_session):
    panel = FindingsPanel(mock_session)
    mock_session.profile.findings = [
        {'type': 'vulnerability', 'description': 'SQLi'},
        {'type': 'directory', 'description': '/admin'},
    ]

    panel.filter_type = 'vulnerability'
    filtered = panel._get_filtered_findings()

    assert len(filtered) == 1
    assert filtered[0]['type'] == 'vulnerability'

def test_pagination(mock_session):
    panel = FindingsPanel(mock_session)
    mock_session.profile.findings = [{'type': 'general'} for _ in range(25)]
    panel.per_page = 10
    panel.current_page = 1

    filtered = panel._get_filtered_findings()
    start = (panel.current_page - 1) * panel.per_page
    page = filtered[start:start + panel.per_page]

    assert len(page) == 10
```

---

## 11. Common Pitfalls

### 1. Forgetting to Restart Live
**Problem:** `live.stop()` without `live.start()` → UI freezes

**Solution:**
```python
live.stop()
try:
    user_input = input()
finally:
    live.start()  # ALWAYS restart
```

### 2. Using box=None
**Problem:** `Panel("Content", box=None)` → Crash

**Solution:** `Panel("Content", box=box.ROUNDED)`

### 3. Not Handling EOF/Interrupt
**Problem:** Ctrl+C crashes app

**Solution:**
```python
try:
    user_input = input()
except (EOFError, KeyboardInterrupt):
    live.start()
    return 'exit'
```

### 4. Mutating During Iteration
**Problem:** Modifying list while iterating

**Solution:** `for item in list(original_list):`

### 5. Over-Logging
**Problem:** Logging every loop iteration → noise

**Solution:** Log at chokepoints only (init, render, input, transitions)

---

## 12. Reference

### Essential Imports
```python
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.layout import Layout
from rich import box
from ..debug_logger import get_debug_logger
from ..log_types import LogCategory, LogLevel
```

### Panel Loop Template
```python
def _panel_loop(self, live: Live, layout: Layout):
    self.debug_logger.log("Panel started", category=LogCategory.SYSTEM_INIT)
    running = True

    while running:
        self._refresh_panels(layout)
        live.refresh()
        live.stop()

        try:
            user_input = input().strip()
        except (EOFError, KeyboardInterrupt):
            live.start()
            return

        live.start()

        if user_input:
            result = self._process_input(user_input)
            if result == 'exit':
                running = False
```

### Debug Commands
```bash
# Development
crack track --tui <target> --debug --debug-categories=UI:VERBOSE,STATE:VERBOSE

# Specific category
crack track --tui <target> --debug --debug-categories=UI.INPUT:TRACE

# View logs
tail -f .debug_logs/tui_debug_*.log
grep "\[UI.INPUT\]" .debug_logs/tui_debug_*.log
grep "\[ERROR\]" .debug_logs/tui_debug_*.log
```

### Reference Examples
- **Config Panel** (`tui_config.py`) - Form-based input with validation
- **Dashboard** (`tui_session_v2.py`) - Menu navigation hub
- **Session** (`session.py`) - Debug logger initialization

---

## Next Steps

1. **Study reference panels** (`tui_config.py`, `tui_session_v2.py`)
2. **Build first panel** (follow tutorial Section 8)
3. **Add debug logging** (Section 6 patterns)
4. **Review architecture** (`TUI_ARCHITECTURE.md`, `track/README.md`)
5. **Implement advanced features** (Section 9)

---

**Document Version:** 2.1 (Reduced)
**Last Updated:** 2025-10-10
**Reduction:** 1,500 lines removed (63% reduction)
**Changes:** Condensed verbose explanations, removed duplicate examples, consolidated patterns
