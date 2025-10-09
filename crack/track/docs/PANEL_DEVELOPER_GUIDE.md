# CRACK Track TUI - Panel Developer Guide

**Complete step-by-step guide for building TUI panels**

## Table of Contents
1. [Introduction](#1-introduction)
2. [Architecture Overview](#2-architecture-overview)
3. [Foundation Concepts](#3-foundation-concepts)
4. [Panel Anatomy](#4-panel-anatomy)
5. [Input Handling](#5-input-handling)
6. [State Management](#6-state-management)
7. [Panel Registration](#7-panel-registration)
8. [Step-by-Step Tutorial](#8-step-by-step-tutorial)
9. [Advanced Patterns](#9-advanced-patterns)
10. [Testing Guidelines](#10-testing-guidelines)
11. [Common Pitfalls](#11-common-pitfalls)
12. [Reference Examples](#12-reference-examples)

---

## 1. Introduction

### Purpose
This guide teaches you how to build TUI (Text User Interface) panels for CRACK Track using the Rich library. You'll learn the complete workflow from panel design to integration.

### Prerequisites
- Python 3.8+
- Rich library (`pip install rich`)
- Understanding of CRACK Track core concepts (TargetProfile, TaskNode, etc.)
- Familiarity with object-oriented Python

### What You'll Build
By the end of this guide, you'll know how to:
- Create a new panel from scratch
- Handle user input and validation
- Manage state transitions
- Integrate panels into the main TUI session
- Test panel behavior

---

## 2. Architecture Overview

### System Components

```
TUISessionV2 (Main Controller)
    ↓
Layout (3-panel structure)
    ├── Header Panel
    ├── Menu/Content Panel (dynamic)
    └── Footer Panel
    ↓
Panel Loops (state-specific)
    ├── _config_panel_loop()
    ├── _main_loop()
    ├── _task_list_loop()  (future)
    └── _task_workspace_loop()  (future)
    ↓
Render Methods
    ├── _render_header()
    ├── _render_menu()
    ├── _render_footer()
    └── Panel-specific renderers
    ↓
Input Processing
    ├── _process_input()
    └── Panel-specific processors
```

### Key Files
```
track/interactive/
├── tui_session_v2.py       # Main controller
├── tui_config.py           # Config Panel (reference example)
├── tui_layout.py           # Layout manager (future)
├── tui_panels.py           # Panel renderers (future)
└── panels/                 # Individual panel modules (future)
    ├── dashboard_panel.py
    ├── task_list_panel.py
    ├── task_workspace.py
    └── findings_panel.py
```

### Data Flow
```
User Input
    ↓
Input Loop (live.stop() → get input → live.start())
    ↓
Input Processor (parse, validate)
    ↓
Action Handler (execute, update state)
    ↓
State Update (profile, flags)
    ↓
Panel Refresh (re-render with new data)
    ↓
Display Update (live.refresh())
```

---

## 3. Foundation Concepts

### 3.1 Rich Library Basics

#### Live Display
The `Live` context manager provides dynamic terminal updates without flooding:

```python
from rich.live import Live
from rich.layout import Layout

layout = Layout()

with Live(
    layout,
    console=console,
    screen=False,      # Don't take over entire screen (allows input)
    refresh_per_second=4,
    auto_refresh=False # Manual refresh only (prevents input interference)
) as live:
    # Update panels
    layout['header'].update(some_panel)

    # Refresh display
    live.refresh()

    # Stop for input
    live.stop()
    user_input = input("Choice: ")
    live.start()
```

**Key Pattern:** Always `stop()` before `input()`, then `start()` after.

#### Panel
The basic building block - a bordered box with content:

```python
from rich.panel import Panel
from rich import box

panel = Panel(
    "Content here",
    title="[bold]Panel Title[/]",
    subtitle="[dim]Optional subtitle[/]",
    border_style="cyan",
    box=box.ROUNDED  # NEVER use box=None (causes errors)
)
```

#### Layout
Organizes panels into regions:

```python
from rich.layout import Layout

# Create layout
layout = Layout()

# Split into 3 vertical sections
layout.split_column(
    Layout(name='header', size=3),   # Fixed height
    Layout(name='menu'),              # Flexible height
    Layout(name='footer', size=3)     # Fixed height
)

# Update regions
layout['header'].update(header_panel)
layout['menu'].update(menu_panel)
layout['footer'].update(footer_panel)
```

#### Table
Structured data display:

```python
from rich.table import Table

table = Table(
    show_header=False,  # Hide column headers
    box=None,           # No table borders (panel provides border)
    padding=(0, 2)      # Vertical, horizontal padding
)

table.add_column("Label", style="bold cyan", width=12)
table.add_column("Value", style="white")

table.add_row("LHOST:", "192.168.45.200")
table.add_row("LPORT:", "4444")
```

### 3.2 Layout System

#### Simple 3-Panel Layout
```python
def _build_layout(self) -> Layout:
    """Standard 3-panel layout"""
    layout = Layout()
    layout.split_column(
        Layout(name='header', size=3),
        Layout(name='menu'),
        Layout(name='footer', size=3)
    )
    return layout
```

#### Multi-Panel Split View (Task Workspace)
```python
def _build_workspace_layout(self) -> Layout:
    """Split-view layout for task workspace"""
    layout = Layout()

    # Vertical split
    layout.split_column(
        Layout(name='header', size=5),
        Layout(name='workspace'),
        Layout(name='footer', size=3)
    )

    # Horizontal split for workspace
    layout['workspace'].split_row(
        Layout(name='details', ratio=40),  # 40% width
        Layout(name='output', ratio=60)    # 60% width
    )

    return layout
```

### 3.3 Live Display Pattern

**Critical Rule:** Input blocks the terminal. You must `stop()` Live before getting input.

```python
def _panel_loop(self, live: Live, layout: Layout):
    """Standard panel loop pattern"""
    running = True

    while running:
        # 1. Refresh display
        self._refresh_panels(layout)
        live.refresh()

        # 2. Stop live for input
        live.stop()

        # 3. Get user input
        self.console.print("\n[bold bright_yellow]Choice:[/] ", end="")
        try:
            user_input = input().strip()
        except (EOFError, KeyboardInterrupt):
            live.start()  # ALWAYS restart before exiting
            return

        # 4. Resume live
        live.start()

        # 5. Process input
        if user_input:
            result = self._process_input(user_input)
            if result == 'exit':
                running = False
```

**Why this pattern?**
- `live.refresh()` updates display
- `live.stop()` freezes display, allows input
- `input()` blocks until user presses Enter
- `live.start()` resumes dynamic updates

---

## 4. Panel Anatomy

Every panel has three core components:

### 4.1 Data Source
Where the panel gets its information:

```python
# Config Panel: Loads from JSON file
config = ConfigPanel.load_config()

# Dashboard Panel: Uses profile + recommendations
profile = self.profile
recommendations = RecommendationEngine.get_recommendations(profile)

# Task List Panel: Uses profile task tree
tasks = self.profile.task_tree.get_all_tasks()
```

### 4.2 Render Method
Converts data into a Rich Panel:

```python
@classmethod
def render_panel(cls, config: Dict[str, Any], target: Optional[str] = None) -> Panel:
    """
    Render configuration panel

    Args:
        config: Config dictionary from ~/.crack/config.json
        target: Target IP (shown but not editable)

    Returns:
        Rich Panel object
    """
    # Build content (Table, Text, etc.)
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Variable", style="bold cyan", width=12)
    table.add_column("Value", style="white")

    # Add rows
    for var_name, description in cls.KEY_VARIABLES:
        value = cls.get_variable(config, var_name)
        table.add_row(f"{var_name}:", value)

    # Add menu options
    table.add_row("", "")
    table.add_row("[bold]1.[/]", "Edit LHOST")
    table.add_row("[bold]2.[/]", "Edit LPORT")
    # ... more options

    # Wrap in Panel
    return Panel(
        table,
        title="[bold white on blue] Configuration Setup [/]",
        subtitle="[dim]Confirm settings before starting enumeration[/]",
        border_style="blue",
        box=box.DOUBLE
    )
```

### 4.3 Update Logic
When and how the panel refreshes:

```python
def _refresh_panels(self, layout: Layout):
    """Refresh all panels with current state"""

    # Header: Updates with current target/phase
    header = self._render_header()
    layout['header'].update(header)

    # Menu: Updates with current choices/recommendations
    menu = self._render_menu()
    layout['menu'].update(menu)

    # Footer: Updates with context-aware shortcuts
    footer = self._render_footer()
    layout['footer'].update(footer)
```

**When to refresh:**
- Before every input prompt (show latest state)
- After user action (show updated data)
- After state transition (show new panel)

---

## 5. Input Handling

### 5.1 Input Loop Pattern

```python
def _panel_loop(self, live: Live, layout: Layout):
    """Panel-specific input loop"""
    running = True

    while running:
        # Render current state
        self._refresh_panels(layout)
        live.refresh()

        # Get input
        live.stop()
        self.console.print("\n[bold bright_yellow]Choice:[/] ", end="")

        try:
            user_input = input().strip()
        except (EOFError, KeyboardInterrupt):
            live.start()
            return  # Exit loop

        live.start()

        # Process input
        if user_input:
            result = self._process_input(user_input)

            # Handle special results
            if result == 'exit':
                running = False
            elif result == 'continue':
                return  # Exit to parent
```

### 5.2 Input Processing

```python
def _process_input(self, user_input: str) -> Optional[str]:
    """
    Process user input for this panel

    Returns:
        'exit' - Quit application
        'continue' - Transition to next panel
        None - Refresh and continue loop
    """
    # Global shortcuts (work in all panels)
    if user_input.lower() == 'q':
        return 'exit'

    if user_input.lower() == 'h':
        self._show_help()
        return None

    # Panel-specific actions
    if user_input in ['1', '2', '3', '4']:
        self._handle_edit(user_input)
        return None

    elif user_input == '5':
        self._confirm_and_continue()
        return 'continue'

    else:
        self.console.print(f"[red]Invalid input: {user_input}[/]")
        return None
```

### 5.3 Validation Pattern

```python
def _handle_edit(self, choice: str):
    """Handle variable editing with validation"""
    var_map = {'1': 'LHOST', '2': 'LPORT', '3': 'WORDLIST', '4': 'INTERFACE'}
    var_name = var_map[choice]

    # Stop live for multi-step input
    live.stop()

    # Get current value
    current = ConfigPanel.get_variable(config, var_name)
    self.console.print(f"\n[cyan]{var_name}:[/] [dim](current: {current})[/]")
    self.console.print("[cyan]New value (or Enter to keep):[/] ", end="")

    try:
        new_value = input().strip()

        if new_value:
            # Validate based on type
            if var_name == 'LPORT':
                if not self._validate_port(new_value):
                    self.console.print("[red]Invalid port number[/]")
                    live.start()
                    return

            elif var_name == 'LHOST':
                if not self._validate_ip(new_value):
                    self.console.print("[red]Invalid IP address[/]")
                    live.start()
                    return

            # Save if valid
            ConfigPanel.set_variable(config, var_name, new_value)
            ConfigPanel.save_config(config)
            self.console.print(f"[green]✓ Updated {var_name}[/]")
        else:
            self.console.print("[dim]No change[/]")

    except (EOFError, KeyboardInterrupt):
        pass

    finally:
        # Small pause to show result
        time.sleep(0.5)

        # ALWAYS restart live
        live.start()

def _validate_port(self, port_str: str) -> bool:
    """Validate port number"""
    try:
        port = int(port_str)
        return 1 <= port <= 65535
    except ValueError:
        return False

def _validate_ip(self, ip_str: str) -> bool:
    """Validate IP address"""
    import ipaddress
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False
```

### 5.4 Error Handling

```python
def _safe_input_loop(self):
    """Input loop with comprehensive error handling"""
    try:
        user_input = input().strip()

    except EOFError:
        # Ctrl+D pressed - treat as quit
        self.console.print("\n[yellow]EOF detected[/]")
        return 'exit'

    except KeyboardInterrupt:
        # Ctrl+C pressed - treat as back/cancel
        self.console.print("\n[yellow]Interrupted[/]")
        return 'cancel'

    except Exception as e:
        # Unexpected error
        self.console.print(f"\n[red]Input error: {e}[/]")
        return None

    return user_input
```

---

## 6. State Management

### 6.1 State Flags

Use boolean flags to track panel state:

```python
class TUISessionV2(InteractiveSession):
    def __init__(self, target: str, resume: bool = False, screened: bool = False, debug: bool = False):
        super().__init__(target, resume, screened)

        # State flags
        self.config_confirmed = False   # Config panel completed
        self.current_panel = 'config'   # Active panel name
        self.show_help = False          # Help overlay active
        self.output_expanded = False    # Output panel expanded
        self.debug_mode = debug         # Debug output enabled
```

### 6.2 State Transitions

```python
def run(self):
    """Main TUI loop with state-based flow"""
    layout = self._build_layout()

    with Live(layout, ...) as live:
        # State 1: Config Panel (MANDATORY)
        if not self.config_confirmed:
            self._config_panel_loop(live, layout)

        # State 2: Main Dashboard (after config)
        if self.config_confirmed:
            self.current_panel = 'dashboard'
            self._main_loop(live, layout)
```

### 6.3 Navigation Stack

For complex navigation, use a stack:

```python
class NavigationStack:
    """Track panel history for back navigation"""

    def __init__(self):
        self.stack = ['dashboard']  # Start at dashboard
        self.max_depth = 5

    def push(self, panel_name: str):
        """Navigate to new panel"""
        if len(self.stack) >= self.max_depth:
            # Force back to dashboard if too deep
            self.stack = ['dashboard']
        self.stack.append(panel_name)

    def pop(self) -> str:
        """Go back to previous panel"""
        if len(self.stack) > 1:
            self.stack.pop()
        return self.stack[-1]

    def current(self) -> str:
        """Get current panel"""
        return self.stack[-1]

    def breadcrumb(self) -> str:
        """Get breadcrumb trail"""
        return " > ".join(self.stack)
```

Usage:
```python
# Initialize
self.nav_stack = NavigationStack()

# Navigate forward
self.nav_stack.push('task_list')
self.nav_stack.push('task_workspace')

# Navigate back
previous = self.nav_stack.pop()  # Returns 'task_list'

# Show breadcrumb
breadcrumb = self.nav_stack.breadcrumb()  # "dashboard > task_list > task_workspace"
```

---

## 7. Panel Registration

### 7.1 File Organization

**Option A: Inline (Current Pattern)**
All panels in `tui_session_v2.py`:
```python
# tui_session_v2.py
class TUISessionV2(InteractiveSession):
    def _config_panel_loop(self, live, layout):
        # Config panel logic here
        pass

    def _main_loop(self, live, layout):
        # Dashboard panel logic here
        pass

    def _task_list_loop(self, live, layout):
        # Task list panel logic here
        pass
```

**Option B: Modular (Recommended for Scale)**
Separate files in `panels/` directory:
```
panels/
├── __init__.py
├── base.py              # Base panel class
├── config_panel.py      # Config panel (existing)
├── dashboard_panel.py   # Dashboard
├── task_list_panel.py   # Task list
└── task_workspace.py    # Task workspace
```

### 7.2 Base Panel Class

```python
# panels/base.py
from abc import ABC, abstractmethod
from typing import Optional, Dict, Any
from rich.panel import Panel
from rich.layout import Layout
from rich.live import Live

class BasePanel(ABC):
    """Base class for all TUI panels"""

    def __init__(self, session: 'TUISessionV2'):
        self.session = session
        self.console = session.console
        self.profile = session.profile

    @abstractmethod
    def render(self, layout: Layout) -> None:
        """Render panel content into layout"""
        pass

    @abstractmethod
    def process_input(self, user_input: str) -> Optional[str]:
        """
        Process user input

        Returns:
            'exit' - Quit application
            'back' - Go to previous panel
            'continue' - Go to next panel
            None - Refresh current panel
        """
        pass

    def run(self, live: Live, layout: Layout):
        """Standard panel loop"""
        running = True

        while running:
            # Refresh
            self.render(layout)
            live.refresh()

            # Get input
            live.stop()
            self.console.print("\n[bold bright_yellow]Choice:[/] ", end="")

            try:
                user_input = input().strip()
            except (EOFError, KeyboardInterrupt):
                live.start()
                return 'exit'

            live.start()

            # Process
            if user_input:
                result = self.process_input(user_input)

                if result in ['exit', 'back', 'continue']:
                    return result
```

### 7.3 Panel Implementation

```python
# panels/dashboard_panel.py
from .base import BasePanel
from rich.panel import Panel
from rich.table import Table
from rich import box

class DashboardPanel(BasePanel):
    """Main dashboard panel"""

    def render(self, layout: Layout) -> None:
        """Render dashboard"""
        # Header
        header = self._render_header()
        layout['header'].update(header)

        # Content
        dashboard = self._render_dashboard()
        layout['menu'].update(dashboard)

        # Footer
        footer = self._render_footer()
        layout['footer'].update(footer)

    def _render_dashboard(self) -> Panel:
        """Render dashboard content"""
        from ...recommendations.engine import RecommendationEngine

        # Get data
        recommendations = RecommendationEngine.get_recommendations(self.profile)
        progress = self.profile.get_progress()

        # Build table
        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column("Num", style="bold bright_white", width=4)
        table.add_column("Action", style="white")

        table.add_row("1.", "Execute next task")
        table.add_row("2.", f"Browse all tasks ({progress['total']} available)")
        table.add_row("3.", "Quick wins ⚡")
        table.add_row("4.", "Document finding")
        table.add_row("5.", f"Browse findings ({len(self.profile.findings)} total)")
        table.add_row("6.", "Help")
        table.add_row("7.", "Exit")

        return Panel(
            table,
            title="[bold cyan]CRACK Track Dashboard[/]",
            subtitle=f"[dim]Phase: {self.profile.phase} | Progress: {progress['completed']}/{progress['total']}[/]",
            border_style="cyan",
            box=box.ROUNDED
        )

    def _render_header(self) -> Panel:
        """Render header"""
        title = f"[bold cyan]CRACK Track TUI[/] | [white]Target:[/] {self.profile.target}"
        return Panel(title, border_style="cyan", box=box.HEAVY)

    def _render_footer(self) -> Panel:
        """Render footer"""
        shortcuts = "[cyan](s)[/] Status | [cyan](t)[/] Tree | [cyan](h)[/] Help | [cyan](q)[/] Quit"
        return Panel(shortcuts, border_style="cyan", box=box.HEAVY)

    def process_input(self, user_input: str) -> Optional[str]:
        """Process dashboard input"""
        # Global shortcuts
        if user_input.lower() == 'q':
            return 'exit'

        if user_input.lower() == 'h':
            self._show_help()
            return None

        if user_input.lower() == 's':
            self._show_status()
            return None

        if user_input.lower() == 't':
            self._show_tree()
            return None

        # Menu options
        if user_input == '1':
            # Execute next task
            return 'next_task'

        elif user_input == '2':
            # Browse tasks
            return 'task_list'

        elif user_input == '3':
            # Quick wins
            return 'quick_wins'

        elif user_input == '4':
            # Document finding
            return 'add_finding'

        elif user_input == '5':
            # Browse findings
            return 'findings'

        elif user_input == '6':
            self._show_help()
            return None

        elif user_input == '7':
            return 'exit'

        else:
            self.console.print(f"[red]Invalid choice: {user_input}[/]")
            return None

    def _show_help(self):
        """Show help overlay"""
        help_text = """
[bold cyan]Dashboard Help[/]

[bold yellow]Actions:[/]
  1 - Execute recommended task
  2 - Browse all tasks
  3 - Show quick wins
  4 - Document finding
  5 - Browse findings
  6 - Show this help
  7 - Exit

[bold yellow]Shortcuts:[/]
  s - Status
  t - Task tree
  h - Help
  q - Quit
"""
        self.console.print(Panel(help_text, title="[bold]Help[/]", border_style="blue", box=box.DOUBLE))
        input("\nPress Enter to continue...")

    def _show_status(self):
        """Show status overlay"""
        progress = self.profile.get_progress()
        status_text = f"""
[bold cyan]Target:[/] {self.profile.target}
[bold cyan]Phase:[/] {self.profile.phase}
[bold cyan]Progress:[/] {progress['completed']}/{progress['total']} tasks
[bold cyan]Ports:[/] {len(self.profile.ports) if self.profile.ports else 0}
[bold cyan]Findings:[/] {len(self.profile.findings) if self.profile.findings else 0}
"""
        self.console.print(Panel(status_text, title="[bold]Status[/]", border_style="green", box=box.ROUNDED))
        input("\nPress Enter to continue...")

    def _show_tree(self):
        """Show task tree overlay"""
        all_tasks = self.profile.task_tree.get_all_tasks()

        if not all_tasks:
            tree_text = "[dim]No tasks yet[/]"
        else:
            lines = []
            for task in all_tasks[:20]:
                symbol = '✓' if task.status == 'completed' else '•'
                color = 'green' if task.status == 'completed' else 'yellow'
                lines.append(f"[{color}]{symbol}[/] {task.name}")
            tree_text = "\n".join(lines)

        self.console.print(Panel(tree_text, title="[bold]Task Tree[/]", border_style="blue", box=box.ROUNDED))
        input("\nPress Enter to continue...")
```

### 7.4 Integration into Main Session

```python
# tui_session_v2.py
from .panels.dashboard_panel import DashboardPanel
from .panels.task_list_panel import TaskListPanel

class TUISessionV2(InteractiveSession):
    def __init__(self, target: str, resume: bool = False, screened: bool = False, debug: bool = False):
        super().__init__(target, resume, screened)

        # Initialize panels
        self.dashboard_panel = DashboardPanel(self)
        self.task_list_panel = TaskListPanel(self)

        # Navigation state
        self.current_panel = 'config'
        self.config_confirmed = False

    def run(self):
        """Main TUI loop with panel routing"""
        layout = self._build_layout()

        with Live(layout, ...) as live:
            # Config panel (mandatory)
            if not self.config_confirmed:
                self._config_panel_loop(live, layout)

            # Route to panels
            while self.config_confirmed:
                if self.current_panel == 'dashboard':
                    result = self.dashboard_panel.run(live, layout)

                    if result == 'exit':
                        break
                    elif result == 'task_list':
                        self.current_panel = 'task_list'

                elif self.current_panel == 'task_list':
                    result = self.task_list_panel.run(live, layout)

                    if result == 'exit':
                        break
                    elif result == 'back':
                        self.current_panel = 'dashboard'
```

---

## 8. Step-by-Step Tutorial

### Build a Simple "Findings Browser" Panel

**Goal:** Create a panel that shows all findings with filtering.

#### Step 1: Create Panel File

```python
# panels/findings_panel.py
from .base import BasePanel
from rich.panel import Panel
from rich.table import Table
from rich.layout import Layout
from rich import box
from typing import Optional

class FindingsPanel(BasePanel):
    """Findings browser panel"""

    def __init__(self, session: 'TUISessionV2'):
        super().__init__(session)

        # Panel state
        self.filter_type = 'all'  # all, vulnerability, directory, credential, note
        self.current_page = 1
        self.per_page = 10

    def render(self, layout: Layout) -> None:
        """Render findings panel"""
        # Header
        header = self._render_header()
        layout['header'].update(header)

        # Content (findings table)
        content = self._render_findings_table()
        layout['menu'].update(content)

        # Footer
        footer = self._render_footer()
        layout['footer'].update(footer)

    def _render_header(self) -> Panel:
        """Render header with breadcrumb"""
        breadcrumb = f"Dashboard > Findings Browser"
        title = f"[bold cyan]CRACK Track TUI[/] | [white]{breadcrumb}[/]"
        return Panel(title, border_style="cyan", box=box.HEAVY)

    def _render_findings_table(self) -> Panel:
        """Render findings table with pagination"""
        # Get filtered findings
        findings = self._get_filtered_findings()

        # Calculate pagination
        total = len(findings)
        total_pages = (total + self.per_page - 1) // self.per_page
        start = (self.current_page - 1) * self.per_page
        end = start + self.per_page
        page_findings = findings[start:end]

        # Build table
        table = Table(show_header=True, box=box.SIMPLE, padding=(0, 1))
        table.add_column("#", style="bold bright_white", width=3)
        table.add_column("Type", style="cyan", width=12)
        table.add_column("Description", style="white")
        table.add_column("Source", style="dim", width=15)

        # Add findings
        for i, finding in enumerate(page_findings, start + 1):
            # Get icon based on type
            icon = self._get_finding_icon(finding.get('type', 'general'))
            type_label = f"{icon} {finding.get('type', 'general')}"

            # Truncate long descriptions
            desc = finding.get('description', 'N/A')
            if len(desc) > 50:
                desc = desc[:47] + "..."

            source = finding.get('source', 'N/A')
            if len(source) > 15:
                source = source[:12] + "..."

            table.add_row(
                str(i),
                type_label,
                desc,
                source
            )

        # If no findings
        if not page_findings:
            table.add_row("", "[dim]No findings found[/]", "", "")

        # Panel title
        filter_label = f"Filter: {self.filter_type.title()}" if self.filter_type != 'all' else "All Findings"
        title = f"[bold]{filter_label}[/]"
        subtitle = f"[dim]Page {self.current_page}/{total_pages} | Total: {total} findings[/]"

        return Panel(
            table,
            title=title,
            subtitle=subtitle,
            border_style="magenta",
            box=box.ROUNDED
        )

    def _render_footer(self) -> Panel:
        """Render footer with actions"""
        shortcuts = "[cyan](f)[/] Filter | [cyan](n)[/] Next Page | [cyan](p)[/] Prev Page | [cyan](b)[/] Back | [cyan](q)[/] Quit"
        return Panel(shortcuts, border_style="cyan", box=box.HEAVY)

    def _get_filtered_findings(self) -> list:
        """Get findings filtered by type"""
        findings = self.profile.findings or []

        if self.filter_type == 'all':
            return findings
        else:
            return [f for f in findings if f.get('type') == self.filter_type]

    def _get_finding_icon(self, finding_type: str) -> str:
        """Get icon for finding type"""
        icons = {
            'vulnerability': '🔓',
            'directory': '📁',
            'credential': '🔑',
            'user': '👤',
            'note': '📝',
            'general': '•'
        }
        return icons.get(finding_type, '•')

    def process_input(self, user_input: str) -> Optional[str]:
        """Process findings panel input"""
        # Global shortcuts
        if user_input.lower() == 'q':
            return 'exit'

        if user_input.lower() == 'b':
            return 'back'

        # Filter
        if user_input.lower() == 'f':
            self._show_filter_menu()
            return None

        # Pagination
        if user_input.lower() == 'n':
            findings = self._get_filtered_findings()
            total_pages = (len(findings) + self.per_page - 1) // self.per_page

            if self.current_page < total_pages:
                self.current_page += 1
            else:
                self.console.print("[yellow]Already on last page[/]")
            return None

        if user_input.lower() == 'p':
            if self.current_page > 1:
                self.current_page -= 1
            else:
                self.console.print("[yellow]Already on first page[/]")
            return None

        # Invalid input
        self.console.print(f"[red]Invalid input: {user_input}[/]")
        return None

    def _show_filter_menu(self):
        """Show filter selection menu"""
        self.console.print("\n[bold cyan]Filter Options:[/]")
        self.console.print("  1. All findings")
        self.console.print("  2. Vulnerabilities only")
        self.console.print("  3. Directories only")
        self.console.print("  4. Credentials only")
        self.console.print("  5. Users only")
        self.console.print("  6. Notes only")
        self.console.print("\n[cyan]Select filter [1-6]:[/] ", end="")

        choice = input().strip()

        filter_map = {
            '1': 'all',
            '2': 'vulnerability',
            '3': 'directory',
            '4': 'credential',
            '5': 'user',
            '6': 'note'
        }

        if choice in filter_map:
            self.filter_type = filter_map[choice]
            self.current_page = 1  # Reset to page 1 when filtering
            self.console.print(f"[green]✓ Filter set to: {self.filter_type.title()}[/]")
        else:
            self.console.print("[red]Invalid choice[/]")

        time.sleep(0.5)
```

#### Step 2: Register Panel in Main Session

```python
# tui_session_v2.py
from .panels.findings_panel import FindingsPanel

class TUISessionV2(InteractiveSession):
    def __init__(self, target: str, resume: bool = False, screened: bool = False, debug: bool = False):
        super().__init__(target, resume, screened)

        # Initialize panels
        self.findings_panel = FindingsPanel(self)

        # State
        self.current_panel = 'config'
        self.config_confirmed = False

    def run(self):
        """Main TUI loop"""
        layout = self._build_layout()

        with Live(layout, ...) as live:
            # Config panel
            if not self.config_confirmed:
                self._config_panel_loop(live, layout)

            # Panel routing
            while self.config_confirmed:
                if self.current_panel == 'findings':
                    result = self.findings_panel.run(live, layout)

                    if result == 'exit':
                        break
                    elif result == 'back':
                        self.current_panel = 'dashboard'
```

#### Step 3: Add Navigation from Dashboard

```python
# panels/dashboard_panel.py (modified)
def process_input(self, user_input: str) -> Optional[str]:
    """Process dashboard input"""
    # ... existing code ...

    elif user_input == '5':
        # Browse findings
        return 'findings'  # Signals transition to findings panel
```

#### Step 4: Test the Panel

```bash
# Run with TUI
crack track --tui 192.168.45.100

# Navigate: Config (press 5) → Dashboard (press 5) → Findings Panel
```

---

## 9. Advanced Patterns

### 9.1 Multi-Panel Split View

```python
def _build_split_layout(self) -> Layout:
    """Create split-view layout (task workspace)"""
    layout = Layout()

    # Vertical split
    layout.split_column(
        Layout(name='header', size=5),
        Layout(name='workspace'),
        Layout(name='footer', size=3)
    )

    # Horizontal split for workspace
    layout['workspace'].split_row(
        Layout(name='details', ratio=40),
        Layout(name='output', ratio=60)
    )

    return layout

def _render_split_view(self, layout: Layout):
    """Render split-view workspace"""
    # Left panel: Task details
    details = self._render_task_details()
    layout['workspace']['details'].update(details)

    # Right panel: Command output
    output = self._render_command_output()
    layout['workspace']['output'].update(output)
```

### 9.2 Dynamic Stage Navigation

```python
def _render_stage_navigator(self, stages: list, current: int) -> str:
    """Render visual stage progress"""
    parts = []

    for i, stage in enumerate(stages):
        if stage['status'] == 'completed':
            parts.append(f"[green][✓ {stage['name']}][/]")
        elif i == current:
            parts.append(f"[cyan][● {stage['name']}][/]")
        else:
            parts.append(f"[dim][○ {stage['name']}][/]")

    return " → ".join(parts)

# Usage:
# [✓ Initial] → [● Targeted] → [○ Deep Scan]
```

### 9.3 Live Output Streaming

```python
import subprocess
from threading import Thread

def _execute_with_live_output(self, command: str, output_panel_ref: list):
    """Execute command and stream output to panel"""

    def stream_output():
        """Background thread to stream output"""
        process = subprocess.Popen(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )

        for line in process.stdout:
            output_panel_ref.append(line.rstrip())

        process.wait()
        output_panel_ref.append(f"\n[green]✓ Exit code: {process.returncode}[/]")

    # Start background thread
    thread = Thread(target=stream_output, daemon=True)
    thread.start()

    # Main loop refreshes output panel
    while thread.is_alive():
        # Refresh output panel (shows new lines)
        self._refresh_output_panel(output_panel_ref)
        live.refresh()
        time.sleep(0.5)
```

### 9.4 Overlay Panels

```python
def _show_overlay(self, live: Live, content: Panel):
    """Show temporary overlay panel"""
    # Save current layout state
    saved_state = self._save_layout_state()

    # Create overlay layout
    overlay_layout = Layout()
    overlay_layout.split_column(
        Layout(name='overlay', ratio=80),
        Layout(name='prompt', size=1)
    )
    overlay_layout['overlay'].update(content)
    overlay_layout['prompt'].update(Panel("[dim]Press any key to close[/]", box=None))

    # Show overlay
    live.update(overlay_layout)
    live.refresh()

    # Wait for input
    input()

    # Restore previous layout
    self._restore_layout_state(saved_state)
    live.refresh()
```

---

## 10. Testing Guidelines

### 10.1 Manual Testing Checklist

```markdown
## Panel Testing Checklist

### Rendering
- [ ] Panel displays correctly on 80x24 terminal
- [ ] Panel displays correctly on 120x40 terminal
- [ ] Text doesn't overflow borders
- [ ] Colors are visible on dark background
- [ ] Colors are visible on light background

### Input Handling
- [ ] All menu options work
- [ ] Invalid input shows error message
- [ ] Ctrl+C handled gracefully
- [ ] Ctrl+D (EOF) handled gracefully
- [ ] Empty input handled (no crash)

### Navigation
- [ ] Can navigate TO this panel
- [ ] Can navigate BACK from this panel
- [ ] Can navigate FORWARD to next panel
- [ ] Breadcrumb shows correct path
- [ ] Quit (q) works from this panel

### Data
- [ ] Panel shows correct data
- [ ] Panel updates after user action
- [ ] Panel handles empty data gracefully
- [ ] Panel handles large datasets (100+ items)

### Edge Cases
- [ ] Handles missing profile data
- [ ] Handles corrupted config
- [ ] Handles network timeouts (if applicable)
- [ ] Handles permission errors (if applicable)
```

### 10.2 Unit Testing

```python
# tests/track/interactive/test_findings_panel.py
import pytest
from unittest.mock import Mock, patch
from track.interactive.panels.findings_panel import FindingsPanel
from track.core.state import TargetProfile

@pytest.fixture
def mock_session():
    """Create mock TUI session"""
    session = Mock()
    session.profile = TargetProfile('192.168.45.100')
    session.console = Mock()
    return session

@pytest.fixture
def findings_panel(mock_session):
    """Create findings panel"""
    return FindingsPanel(mock_session)

def test_render_empty_findings(findings_panel, mock_session):
    """Test rendering with no findings"""
    mock_session.profile.findings = []

    # Should not crash
    mock_layout = Mock()
    findings_panel.render(mock_layout)

    # Should show "No findings" message
    assert mock_layout['menu'].update.called

def test_filter_findings_by_type(findings_panel, mock_session):
    """Test filtering findings"""
    # Add test data
    mock_session.profile.findings = [
        {'type': 'vulnerability', 'description': 'SQLi'},
        {'type': 'directory', 'description': '/admin'},
        {'type': 'vulnerability', 'description': 'XSS'},
    ]

    # Filter for vulnerabilities
    findings_panel.filter_type = 'vulnerability'
    filtered = findings_panel._get_filtered_findings()

    assert len(filtered) == 2
    assert all(f['type'] == 'vulnerability' for f in filtered)

def test_pagination(findings_panel, mock_session):
    """Test pagination logic"""
    # Add 25 findings
    mock_session.profile.findings = [
        {'type': 'general', 'description': f'Finding {i}'}
        for i in range(25)
    ]

    findings_panel.per_page = 10

    # Page 1 should show findings 0-9
    findings_panel.current_page = 1
    filtered = findings_panel._get_filtered_findings()
    start = (findings_panel.current_page - 1) * findings_panel.per_page
    end = start + findings_panel.per_page
    page_findings = filtered[start:end]

    assert len(page_findings) == 10
    assert page_findings[0]['description'] == 'Finding 0'

def test_process_input_quit(findings_panel):
    """Test quit input"""
    result = findings_panel.process_input('q')
    assert result == 'exit'

def test_process_input_back(findings_panel):
    """Test back input"""
    result = findings_panel.process_input('b')
    assert result == 'back'

def test_process_input_next_page(findings_panel, mock_session):
    """Test next page navigation"""
    # Add enough findings for 3 pages
    mock_session.profile.findings = [{'type': 'general'} for _ in range(25)]
    findings_panel.per_page = 10
    findings_panel.current_page = 1

    # Next page
    result = findings_panel.process_input('n')
    assert result is None
    assert findings_panel.current_page == 2

def test_process_input_invalid(findings_panel):
    """Test invalid input"""
    result = findings_panel.process_input('xyz')
    assert result is None
    assert findings_panel.console.print.called
```

---

## 11. Common Pitfalls

### 11.1 Forgetting to Restart Live

**Problem:**
```python
live.stop()
user_input = input()
# FORGOT live.start() - UI frozen!
```

**Solution:**
```python
live.stop()
try:
    user_input = input()
finally:
    live.start()  # ALWAYS restart, even on error
```

### 11.2 Using box=None

**Problem:**
```python
panel = Panel("Content", box=None)  # CRASH!
```

**Solution:**
```python
from rich import box
panel = Panel("Content", box=box.ROUNDED)  # Use ANY box style
```

### 11.3 Not Handling EOF/Interrupt

**Problem:**
```python
user_input = input()  # Ctrl+C crashes
```

**Solution:**
```python
try:
    user_input = input()
except (EOFError, KeyboardInterrupt):
    live.start()
    return 'exit'
```

### 11.4 Mutating Data During Iteration

**Problem:**
```python
for finding in self.profile.findings:
    if some_condition:
        self.profile.findings.remove(finding)  # CRASH!
```

**Solution:**
```python
# Create copy for iteration
for finding in list(self.profile.findings):
    if some_condition:
        self.profile.findings.remove(finding)
```

### 11.5 Blocking Without Live Stop

**Problem:**
```python
# Live is running
time.sleep(5)  # UI frozen for 5 seconds
```

**Solution:**
```python
live.stop()
time.sleep(5)
live.start()
```

---

## 12. Reference Examples

### Config Panel (Simple Form)
**File:** `track/interactive/tui_config.py`
**Pattern:** Form-based data entry with validation
**Key Features:**
- Edit variables (LHOST, LPORT, etc.)
- Validation (IP, port range)
- Persistence to JSON
- MANDATORY screen (cannot skip)

### Dashboard Panel (Menu Hub)
**File:** `track/interactive/tui_session_v2.py` (lines 198-232)
**Pattern:** Central navigation hub with numbered menu
**Key Features:**
- Recommendations display
- Progress tracking
- Menu navigation
- Shortcuts (s, t, h, q)

### Findings Browser (Data Table)
**File:** Tutorial example above
**Pattern:** Paginated data table with filtering
**Key Features:**
- Pagination (10 per page)
- Filtering by type
- Icon-based type display
- Empty state handling

---

## Quick Reference Card

### Essential Imports
```python
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.layout import Layout
from rich import box
```

### Panel Loop Template
```python
def _panel_loop(self, live: Live, layout: Layout):
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

### Input Processing Template
```python
def _process_input(self, user_input: str) -> Optional[str]:
    if user_input.lower() == 'q':
        return 'exit'
    elif user_input.lower() == 'b':
        return 'back'
    elif user_input in ['1', '2', '3']:
        self._handle_choice(user_input)
        return None
    else:
        self.console.print(f"[red]Invalid: {user_input}[/]")
        return None
```

### Panel Rendering Template
```python
def _render_panel(self) -> Panel:
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Label", style="bold cyan")
    table.add_column("Value", style="white")

    table.add_row("Item 1", "Value 1")
    table.add_row("Item 2", "Value 2")

    return Panel(
        table,
        title="[bold]Panel Title[/]",
        border_style="cyan",
        box=box.ROUNDED
    )
```

---

## Next Steps

1. **Study reference panels:**
   - Config Panel (`tui_config.py`) - Form pattern
   - Dashboard Panel (`tui_session_v2.py`) - Menu pattern

2. **Build your first panel:**
   - Follow Step-by-Step Tutorial (Section 8)
   - Start simple, add features incrementally

3. **Review architecture docs:**
   - `TUI_ARCHITECTURE.md` - Complete system design
   - `track/README.md` - Module overview

4. **Implement Phase 2 panels:**
   - Dashboard with overlays
   - Status/Help/Tree overlays
   - Test thoroughly

5. **Advanced topics:**
   - Multi-panel split views
   - Live output streaming
   - Dynamic stage navigation

---

**Document Version:** 1.0
**Last Updated:** 2025-10-09
**Author:** CRACK Track Development Team
