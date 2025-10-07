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

def view_architecture():
    """Introspect modules and show component map"""
    from ..core import state, task_tree, events, storage
    from ..services.registry import ServiceRegistry
    from ..phases.definitions import PHASES

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


def view_plugin_flow():
    """Show event-driven plugin flow using actual registry"""
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


def view_task_tree(target: str):
    """Load profile and render task tree"""
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


def view_progress(target: str):
    """Live progress bars from profile stats"""
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


def view_phase_flow(target: Optional[str] = None):
    """Phase progression from PHASES dict"""
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


def view_decision_tree(phase: str = 'discovery'):
    """Decision tree from factory"""
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


def view_plugins():
    """Plugin registry dump"""
    from ..services.registry import ServiceRegistry

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
        return f"[{'░' * width}] 0%"

    pct = current / total
    filled = int(pct * width)
    empty = width - filled
    bar = char * filled + '░' * empty

    return f"[{bar}] {int(pct * 100)}% ({current}/{total})"


# ============ CLI ENTRY POINT ============

def visualize(view: str, target: Optional[str] = None, **opts):
    """Main entry point - route to view function"""
    views = {
        'architecture': view_architecture,
        'plugin-flow': view_plugin_flow,
        'task-tree': lambda: view_task_tree(target) if target else "Error: target required",
        'progress': lambda: view_progress(target) if target else "Error: target required",
        'phase-flow': lambda: view_phase_flow(target),
        'decision-tree': lambda: view_decision_tree(opts.get('phase', 'discovery')),
        'plugins': view_plugins
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


__all__ = ['visualize', 'view_architecture', 'view_plugin_flow', 'view_task_tree',
           'view_progress', 'view_phase_flow', 'view_decision_tree', 'view_plugins']
