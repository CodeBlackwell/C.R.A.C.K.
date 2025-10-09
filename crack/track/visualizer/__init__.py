"""
Minimalist visualization via introspection

Philosophy: The crack track already contains all data structures.
We introspect and format - we don't rebuild.
"""

import sys
import inspect
from typing import Dict, Any, List, Optional
from textwrap import wrap


# ============ UNIVERSAL RENDERER ============

def render(obj, style='tree', depth=0, max_depth=10, show_status=False, **opts):
    """Universal renderer - handles dict, list, object via introspection"""
    if isinstance(obj, dict):
        return _render_dict(obj, style, depth, max_depth, show_status, **opts)
    elif isinstance(obj, list):
        return _render_list(obj, style, depth, max_depth, **opts)
    elif hasattr(obj, 'to_dict'):
        return render(obj.to_dict(), style, depth, max_depth, show_status, **opts)
    elif hasattr(obj, '__dict__'):
        return render(vars(obj), style, depth, max_depth, show_status, **opts)
    return str(obj)


# ============ VIEW FUNCTIONS ============

def view_architecture(style='tree'):
    """Introspect modules and show component map

    Args:
        style: Visualization style (tree, columnar, compact)
    """
    from ..core import state, task_tree, events, storage
    from ..services.registry import ServiceRegistry
    from ..phases.definitions import PHASES

    # Tree style (default, detailed)
    if style == 'tree':
        output = []
        output.append("┌─────────────────────────────────────────────────────────────┐")
        output.append("│                    CRACK Track Architecture                  │")
        output.append("└─────────────────────────────────────────────────────────────┘")
        output.append("")
        output.append("[Core Layer]")
        output.append("  ├─► TargetProfile (state.py)")
        output.append("  │     ├─► Manages: ports, findings, credentials, notes")
        output.append("  │     ├─► Contains: TaskTree (hierarchical)")
        output.append("  │     └─► Storage: ~/.crack/targets/{TARGET}.json")
        output.append("  │")
        output.append("  ├─► TaskNode (task_tree.py)")
        output.append("  │     ├─► Status: pending → in-progress → completed/skipped")
        output.append("  │     ├─► Metadata: command, tags, flags, alternatives")
        output.append("  │     └─► Hierarchy: parent/child relationships")
        output.append("  │")
        output.append("  └─► EventBus (events.py)")
        output.append("        └─► Events: port_discovered, service_detected, plugin_tasks_generated")
        output.append("")
        output.append(f"[Plugin Layer]")
        output.append(f"  ├─► ServiceRegistry (@register decorator)")
        output.append(f"  │     ├─► Auto-discovery on import")
        output.append(f"  │     └─► Event-driven task generation")
        output.append(f"  │")
        output.append(f"  └─► Service Plugins ({len(ServiceRegistry._plugins)} registered)")

        # Show first 6 plugins
        plugins = list(ServiceRegistry._plugins.keys())[:6]
        for i, name in enumerate(plugins):
            prefix = "        └─► " if i == len(plugins) - 1 else "        ├─► "
            output.append(f"{prefix}{name.upper()}")

        if len(ServiceRegistry._plugins) > 6:
            output.append(f"        └─► [{len(ServiceRegistry._plugins) - 6} more...]")

        output.append("")
        output.append("[Phase System]")
        phases = " → ".join(PHASES.keys())
        output.append(f"  {phases}")

        return '\n'.join(output)

    # Columnar style (compact table)
    elif style == 'columnar':
        output = []
        output.append("=" * 80)
        output.append("CRACK Track Architecture".center(80))
        output.append("=" * 80)
        output.append("")
        output.append(f"{'Component':<30} | {'Details':<47}")
        output.append("-" * 80)
        output.append(f"{'TargetProfile':<30} | {'Manages ports, findings, credentials, notes':<47}")
        output.append(f"{'TaskNode':<30} | {'Hierarchical task tracking with metadata':<47}")
        output.append(f"{'EventBus':<30} | {'Event-driven plugin communication':<47}")
        output.append(f"{'ServiceRegistry':<30} | {'Auto-discovers and registers plugins':<47}")
        output.append(f"{'Service Plugins':<30} | {f'{len(ServiceRegistry._plugins)} plugins registered':<47}")
        output.append(f"{'Phase System':<30} | {'5-phase OSCP methodology':<47}")
        output.append("-" * 80)
        return '\n'.join(output)

    # Compact style (minimal)
    else:  # compact
        return f"""CRACK Track Architecture
Core: TargetProfile, TaskNode, EventBus
Plugins: {len(ServiceRegistry._plugins)} registered (ServiceRegistry)
Phases: discovery → service-detection → service-specific → exploitation → post-exploitation"""


def view_plugin_flow(style='tree'):
    """Show event-driven plugin flow using actual registry

    Args:
        style: Visualization style (tree, columnar, compact) - only tree supported
    """
    # Plugin flow is inherently sequential, so tree is most appropriate
    # Other styles would lose clarity
    output = []
    output.append("[Nmap Parser] → parse_file()")
    output.append("       │")
    output.append("       ├─► emit: port_discovered(port=80, state='open')")
    output.append("       ├─► emit: service_detected(port=80, service='http', version='...')")
    output.append("       └─► emit: version_detected(...)")
    output.append("                    ▼")
    output.append("       [EventBus] → notifies all listeners")
    output.append("                    ▼")
    output.append("       [ServiceRegistry] → match plugin by detect()")
    output.append("                    ▼")
    output.append("       [Plugin] → detect() returns True")
    output.append("                    ▼")
    output.append("       [Plugin] → get_task_tree()")
    output.append("                    │")
    output.append("                    ├─► Generate enumeration tasks")
    output.append("                    └─► Apply OSCP methodology")
    output.append("                              ▼")
    output.append("       emit: plugin_tasks_generated(task_tree={...})")
    output.append("                              ▼")
    output.append("       [TargetProfile] → add_task() → integrates into tree")
    return '\n'.join(output)


def view_task_tree(target: str, style='tree'):
    """Load profile and render task tree

    Args:
        target: Target IP/hostname
        style: Visualization style (only tree supported for task trees)
    """
    from ..core.state import TargetProfile

    profile = TargetProfile.load(target)
    if not profile:
        return f"Error: Target '{target}' not found"

    output = []
    output.append(f"{target} Task Tree [Phase: {profile.phase}]")
    output.append("━" * 60)

    # Progress summary
    stats = profile.get_progress()
    pct = int(stats['completed'] / stats['total'] * 100) if stats['total'] else 0
    output.append(f"Progress: {stats['completed']}/{stats['total']} ({pct}%)  "
                  f"✓ Completed: {stats['completed']}  "
                  f"⧗ In Progress: {stats['in_progress']}  "
                  f"○ Pending: {stats['pending']}")
    output.append("")

    # Render tree
    output.append(_render_task_node(profile.task_tree, depth=0))
    output.append("")
    output.append("Legend: [✓] Completed  [⧗] In Progress  [○] Pending  [⊘] Skipped")

    return '\n'.join(output)


def view_progress(target: str, style='tree'):
    """Live progress bars from profile stats

    Args:
        target: Target IP/hostname
        style: Visualization style (only tree supported for progress)
    """
    from ..core.state import TargetProfile

    profile = TargetProfile.load(target)
    if not profile:
        return f"Error: Target '{target}' not found"

    stats = profile.get_progress()

    output = []
    output.append("╔═══════════════════════════════════════════════════════════╗")
    output.append(f"║           Target: {target:^30}              ║")
    output.append("╚═══════════════════════════════════════════════════════════╝")
    output.append("")
    output.append(f"Phase: {profile.phase:20}    Status: {profile.status}")
    output.append("")
    output.append("Overall Progress:")
    output.append(_progress_bar(stats['completed'], stats['total'], width=40))
    output.append("")
    output.append("By Status:")
    output.append(f"  ✓ Completed     {_progress_bar(stats['completed'], stats['total'], width=20, char='█')}  {stats['completed']} tasks")
    output.append(f"  ⧗ In Progress   {_progress_bar(stats['in_progress'], stats['total'], width=20, char='█')}  {stats['in_progress']} task{'s' if stats['in_progress'] != 1 else ''}")
    output.append(f"  ○ Pending       {_progress_bar(stats['pending'], stats['total'], width=20, char='█')}  {stats['pending']} tasks")
    output.append(f"  ⊘ Skipped       {_progress_bar(stats['skipped'], stats['total'], width=20, char='░')}  {stats['skipped']} tasks")

    # Show quick wins
    pending_tasks = profile.task_tree.get_all_pending()
    quick_wins = [t for t in pending_tasks if 'QUICK_WIN' in t.metadata.get('tags', [])]

    if quick_wins:
        output.append("")
        output.append(f"Quick Wins Remaining: {len(quick_wins)}")
        for task in quick_wins[:3]:
            output.append(f"  • {task.name}")

    return '\n'.join(output)


def view_phase_flow(target: Optional[str] = None, style='tree'):
    """Phase progression from PHASES dict

    Args:
        target: Optional target to highlight current phase
        style: Visualization style (only tree supported for phase flow)
    """
    from ..phases.definitions import get_phase_order, PHASES
    from ..core.state import TargetProfile

    phases = get_phase_order()
    current = None

    if target:
        profile = TargetProfile.load(target)
        if profile:
            current = profile.phase

    output = []
    for i, phase in enumerate(phases):
        marker = ' ◄── Current Phase' if phase == current else ''
        phase_info = PHASES.get(phase, {})
        description = phase_info.get('description', '')

        output.append("┏" + "━" * 30 + "┓")
        output.append(f"┃  {phase_info.get('name', phase):^26}  ┃{marker}")
        output.append("┗" + "━" * 30 + "┛")

        if description:
            output.append(f"  {description}")

        if i < len(phases) - 1:
            output.append("       │")
            output.append("       ▼")

    return '\n'.join(output)


def view_decision_tree(phase: str = 'discovery', style='tree'):
    """Decision tree from factory

    Args:
        phase: Phase name for decision tree
        style: Visualization style (only tree supported for decision trees)
    """
    from ..interactive.decision_trees import DecisionTreeFactory

    tree = DecisionTreeFactory.create_phase_tree(phase)
    if not tree:
        return f"Error: No decision tree for phase '{phase}'"

    output = []
    output.append(f"Interactive Mode - {phase.title()} Phase Decision Tree")
    output.append("═" * 60)
    output.append("")
    output.append(f"[ROOT: {tree.root.id}]")
    output.append(f"? {tree.root.question}")
    output.append("")

    for i, choice in enumerate(tree.root.choices, 1):
        action_info = f"ACTION: {choice.action}" if choice.action else f"NEXT: {choice.next_node}"
        output.append(f"  {i}. {choice.id} → {action_info}")
        output.append(f"     └─ {choice.label}")
        if choice.description:
            output.append(f"        {choice.description}")
        output.append("")

    output.append("Navigation: [Select] → [Action/Next Node] → [Result]")
    output.append("History: [Back 'b'] [Root 'r'] [Quit 'q']")

    return '\n'.join(output)


def view_plugin_graph(style='tree'):
    """Visualize plugin phase flow and dependencies

    Args:
        style: Visualization style (tree for full flow, compact for matrix)
    """
    from ..services.registry import ServiceRegistry
    from .plugin_graph import build_phase_graph, build_trigger_matrix

    if style == 'compact':
        # Just show trigger matrix
        return build_trigger_matrix(ServiceRegistry._plugins, style='tree')

    # Full phase flow diagram (default)
    return build_phase_graph(ServiceRegistry._plugins)


def view_master(style='tree', focus=None, output_file=None):
    """Comprehensive master visualization - ALL plugin ecosystem data

    Shows programmatically generated data:
    - 127 plugins across 5 OSCP phases
    - 115 ports coverage
    - Attack chains and triggers
    - Task generation details
    - Tag-based capabilities
    - Service overlaps

    Args:
        style: tree (full 8 sections), compact (summary), columnar (tables)
        focus: Optional section (summary, phases, ports, chains, tags, overlaps, tasks, graph)
        output_file: If provided, export to markdown file (untruncated). If None, return terminal output.

    Returns:
        Visualization string (terminal format if output_file is None, markdown if output_file provided)
    """
    from ..services.registry import ServiceRegistry
    from .master import build_master_visualization, export_markdown

    # If output file specified, generate markdown export
    if output_file:
        return export_markdown(ServiceRegistry._plugins, style, focus)

    # Otherwise, return terminal output (truncated)
    return build_master_visualization(ServiceRegistry._plugins, style, focus)


def view_themes(style='tree'):
    """Preview all available color themes

    Args:
        style: Visualization style (only tree supported for themes)
    """
    from .themes import THEMES, colorize

    output = []
    output.append("=" * 70)
    output.append("Color Theme Preview".center(70))
    output.append("=" * 70)
    output.append("")

    sample_text = """[completed]✓ Completed Task[/completed]
[in-progress]⧗ In Progress Task[/in-progress]
[pending]○ Pending Task[/pending]
[phase]Phase: Service Enumeration[/phase]
[plugin]Plugin: HTTP Enumeration[/plugin]"""

    for theme_name in ['oscp', 'dark', 'light', 'mono']:
        output.append(f"── {theme_name.upper()} Theme ──")
        colored = colorize(sample_text, theme_name)
        output.append(colored)
        output.append("")

    output.append("=" * 70)
    output.append("Usage: crack track --viz architecture --viz-color --viz-theme <name>")
    output.append("Available themes: oscp, dark, light, mono")

    return '\n'.join(output)


def view_plugins(style='tree'):
    """Plugin registry dump

    Args:
        style: Visualization style (tree, columnar, compact)
    """
    from ..services.registry import ServiceRegistry

    if style == 'compact':
        # Compact: Just counts
        return f"Service Plugin Registry: {len(ServiceRegistry._plugins)} plugins loaded"

    elif style == 'columnar':
        # Columnar: Simple table
        output = []
        output.append("=" * 70)
        output.append(f"Service Plugin Registry - {len(ServiceRegistry._plugins)} Plugins".center(70))
        output.append("=" * 70)
        output.append(f"{'Plugin Name':<30} | {'Class':<37}")
        output.append("-" * 70)
        for name, plugin in list(ServiceRegistry._plugins.items())[:20]:
            output.append(f"{name:<30} | {plugin.__class__.__name__:<37}")
        if len(ServiceRegistry._plugins) > 20:
            output.append(f"... and {len(ServiceRegistry._plugins) - 20} more")
        return '\n'.join(output)

    # Tree style (default)
    output = []
    output.append(f"Service Plugin Registry [{len(ServiceRegistry._plugins)} plugins loaded]")
    output.append("═" * 60)
    output.append("")

    # Group plugins by category
    network = []
    database = []
    exploitation = []
    other = []

    for name, plugin in ServiceRegistry._plugins.items():
        plugin_info = f"  ├─► {name} ({plugin.__class__.__name__})"
        if hasattr(plugin, 'default_ports') and plugin.default_ports:
            plugin_info += f"\n      Ports: {', '.join(map(str, plugin.default_ports[:5]))}"
        if hasattr(plugin, 'service_names') and plugin.service_names:
            plugin_info += f"\n      Services: {', '.join(plugin.service_names[:3])}"

        # Categorize
        if name in ['http', 'smb', 'ssh', 'ftp', 'smtp']:
            network.append(plugin_info)
        elif name in ['mysql', 'sql', 'nfs']:
            database.append(plugin_info)
        elif any(x in name for x in ['exploit', 'bof', 'heap', 'privesc']):
            exploitation.append(plugin_info)
        else:
            other.append(plugin_info)

    if network:
        output.append("[Network Services]")
        output.extend(network)
        output.append("")

    if database:
        output.append("[Database Services]")
        output.extend(database)
        output.append("")

    if exploitation:
        output.append("[Exploitation Plugins]")
        output.extend(exploitation[:5])
        if len(exploitation) > 5:
            output.append(f"  └─► [{len(exploitation) - 5} more...]")
        output.append("")

    if other:
        output.append("[Other Plugins]")
        output.extend(other[:3])
        if len(other) > 3:
            output.append(f"  └─► [{len(other) - 3} more...]")

    return '\n'.join(output)


# ============ FORMATTERS ============

def _render_dict(d, style, depth, max_depth, show_status=False, **opts):
    """Format dict as tree/columnar/compact"""
    if style == 'tree':
        return '\n'.join(_tree_lines(d, depth, max_depth))
    elif style == 'columnar':
        return _columnar_layout(d)
    return str(d)


def _render_list(lst, style, depth, max_depth, **opts):
    """Format list items"""
    lines = []
    for i, item in enumerate(lst):
        lines.append(f"  {i+1}. {item}")
    return '\n'.join(lines)


def _tree_lines(d, depth=0, max_depth=10):
    """Generate tree lines with box-drawing chars"""
    indent = '  ' * depth
    items = list(d.items()) if isinstance(d, dict) else [(str(i), v) for i, v in enumerate(d)]

    for i, (k, v) in enumerate(items):
        is_last = i == len(items) - 1
        prefix = '└─► ' if is_last else '├─► '

        yield f"{indent}{prefix}{k}"

        if isinstance(v, dict) and depth < max_depth:
            yield from _tree_lines(v, depth+1, max_depth)
        elif isinstance(v, list) and depth < max_depth and v:
            sub_indent = '  ' * (depth + 1)
            for item in v[:3]:
                yield f"{sub_indent}  • {item}"
            if len(v) > 3:
                yield f"{sub_indent}  • [{len(v) - 3} more...]"


def _render_task_node(node, depth=0, is_last=False, prefix=''):
    """Recursively render task node as tree"""
    lines = []

    # Status icon
    status_icons = {
        'completed': '[✓]',
        'in-progress': '[⧗]',
        'pending': '[○]',
        'skipped': '[⊘]'
    }
    icon = status_icons.get(node.status, '[?]')

    # Build line
    if depth == 0:
        line = f"{node.id}: {node.name} {icon}"
    else:
        connector = '└─► ' if is_last else '├─► '
        line = f"{prefix}{connector}{icon} {node.name}"

        # Show command if present
        if node.metadata.get('command'):
            cmd = node.metadata['command']
            if len(cmd) > 50:
                cmd = cmd[:47] + '...'
            lines.append(line)
            line = f"{prefix}{'    ' if is_last else '│   '}    ({cmd})"

    lines.append(line)

    # Render children
    for i, child in enumerate(node.children):
        child_is_last = i == len(node.children) - 1
        child_prefix = prefix + ('    ' if is_last else '│   ') if depth > 0 else ''
        lines.append(_render_task_node(child, depth+1, child_is_last, child_prefix))

    return '\n'.join(lines)


def _columnar_layout(data):
    """3-column layout: Component | Details | Status"""
    lines = []
    lines.append(f"{'Component':<30} | {'Details':<40}")
    lines.append("-" * 73)

    for key, value in data.items():
        value_str = str(value)[:40]
        lines.append(f"{key:<30} | {value_str:<40}")

    return '\n'.join(lines)


def _progress_bar(current, total, width=40, char='█'):
    """ASCII progress bar"""
    if total == 0:
        return f"[{'░' * width}] 0% (0/0)"

    pct = current / total
    filled = int(pct * width)
    empty = width - filled
    bar = char * filled + '░' * empty

    return f"[{bar}] {int(pct * 100)}% ({current}/{total})"


# ============ VISUALIZER CLASS ============

class Visualizer:
    """
    Convenience wrapper for visualize() function

    Provides object-oriented interface to visualization system
    """

    @staticmethod
    def render(view: str, target: Optional[str] = None, **opts):
        """Render a visualization view"""
        return visualize(view, target, **opts)

    @staticmethod
    def architecture(**opts):
        """Render architecture view"""
        return view_architecture(opts.get('style', 'tree'))

    @staticmethod
    def plugin_flow(**opts):
        """Render plugin flow view"""
        return view_plugin_flow(opts.get('style', 'tree'))

    @staticmethod
    def task_tree(target: str, **opts):
        """Render task tree for target"""
        return view_task_tree(target, opts.get('style', 'tree'))

    @staticmethod
    def progress(target: str, **opts):
        """Render progress view for target"""
        return view_progress(target, opts.get('style', 'tree'))


# ============ CLI ENTRY POINT ============

def visualize(view: str, target: Optional[str] = None, **opts):
    """Main entry point - route to view function

    Args:
        view: View name (architecture, plugin-flow, task-tree, etc.)
        target: Optional target IP/hostname
        **opts: Options including:
            - style: Visualization style (tree, columnar, compact)
            - color: Enable colored output
            - theme: Color theme (oscp, dark, light, mono)
            - phase: Phase for decision-tree view
    """
    style = opts.get('style', 'tree')

    views = {
        'architecture': lambda: view_architecture(style=style),
        'plugin-flow': lambda: view_plugin_flow(style=style),
        'plugin-graph': lambda: view_plugin_graph(style=style),
        'master': lambda: view_master(style=style, focus=opts.get('focus'), output_file=opts.get('output_file')),
        'task-tree': lambda: view_task_tree(target, style=style) if target else "Error: target required",
        'progress': lambda: view_progress(target, style=style) if target else "Error: target required",
        'phase-flow': lambda: view_phase_flow(target, style=style),
        'decision-tree': lambda: view_decision_tree(opts.get('phase', 'discovery'), style=style),
        'plugins': lambda: view_plugins(style=style),
        'themes': lambda: view_themes(style=style)
    }

    if view not in views:
        return f"Error: Unknown view '{view}'. Available: {', '.join(views.keys())}"

    try:
        output = views[view]()

        # Apply colors if terminal and requested
        if opts.get('color') and sys.stdout.isatty():
            from .themes import colorize
            output = colorize(output, opts.get('theme', 'oscp'))

        return output

    except Exception as e:
        return f"Error rendering {view}: {e}"


__all__ = ['visualize', 'Visualizer', 'view_architecture', 'view_plugin_flow', 'view_plugin_graph', 'view_master',
           'view_task_tree', 'view_progress', 'view_phase_flow', 'view_decision_tree', 'view_plugins', 'view_themes']
