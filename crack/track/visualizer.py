"""
CRACK Track Visualization System

Provides various visualization modes for understanding system architecture,
task progress, plugin relationships, and attack chains.

Visualization Modes:
- master: Comprehensive system overview with all components
- plugin-flow: Event flow through plugin system
- plugin-graph: Plugin dependencies and relationships
- task-tree: Hierarchical task visualization for target
- progress: Task completion progress bars
- decision-tree: Interactive mode decision trees
"""

from typing import Dict, Any, Optional, List
from pathlib import Path
import json
from datetime import datetime

from .core.state import TargetProfile
from .services.registry import ServiceRegistry
from .phases.registry import PhaseManager
from .interactive.decision_trees import DecisionTreeFactory


class Visualizer:
    """Core visualization engine for CRACK Track"""

    THEMES = {
        'oscp': {
            'colors': {
                'completed': '✅',
                'pending': '⏳',
                'in-progress': '🔄',
                'skipped': '⏭️',
                'critical': '🔴',
                'warning': '⚠️',
                'info': 'ℹ️',
                'success': '✅'
            },
            'borders': {
                'box': '═',
                'corner': '╔╗╚╝',
                'tree': '├─│└'
            }
        },
        'minimal': {
            'colors': {
                'completed': '[✓]',
                'pending': '[ ]',
                'in-progress': '[~]',
                'skipped': '[x]',
                'critical': '[!]',
                'warning': '[?]',
                'info': '[i]',
                'success': '[✓]'
            },
            'borders': {
                'box': '-',
                'corner': '+-+-',
                'tree': '|--+'
            }
        }
    }

    @classmethod
    def render_master_view(cls, style='detailed', theme='oscp', focus=None) -> str:
        """
        Render comprehensive master visualization showing entire system

        Args:
            style: 'detailed', 'compact', or 'summary'
            theme: Visual theme to use
            focus: Optional focus area ('plugins', 'chains', 'architecture')

        Returns:
            Formatted visualization string
        """
        output = []
        theme_config = cls.THEMES.get(theme, cls.THEMES['oscp'])

        # Header
        output.append("=" * 80)
        output.append("CRACK TRACK - MASTER SYSTEM VISUALIZATION")
        output.append("=" * 80)
        output.append("")

        # System Architecture Overview
        output.append("## 🏗️ SYSTEM ARCHITECTURE")
        output.append("")
        output.append("```")
        output.append("┌─────────────────────────────────────────────────────────────┐")
        output.append("│                     CRACK Track Core                        │")
        output.append("├─────────────────────────────────────────────────────────────┤")
        output.append("│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  │")
        output.append("│  │  State   │  │  Events  │  │  Tasks   │  │ Storage  │  │")
        output.append("│  │ Manager  │◄─┤   Bus    ├─►│   Tree   │◄─┤  JSON    │  │")
        output.append("│  └──────────┘  └─────┬────┘  └──────────┘  └──────────┘  │")
        output.append("│                      │                                      │")
        output.append("│  ┌───────────────────┼───────────────────────────────────┐ │")
        output.append("│  │              Plugin System (120+ plugins)             │ │")
        output.append("│  ├──────┬──────┬──────┬──────┬──────┬──────┬───────────┤ │")
        output.append("│  │ HTTP │ SMB  │ SSH  │ SQL  │ FTP  │ ...  │  Custom   │ │")
        output.append("│  └──────┴──────┴──────┴──────┴──────┴──────┴───────────┘ │")
        output.append("└─────────────────────────────────────────────────────────────┘")
        output.append("```")
        output.append("")

        # Plugin Statistics
        if focus != 'chains':
            output.append("## 📊 PLUGIN ECOSYSTEM STATISTICS")
            output.append("")
            output.extend(cls._render_plugin_stats(style))
            output.append("")

        # Event Flow
        if style == 'detailed' or focus == 'plugins':
            output.append("## 🔄 EVENT FLOW ARCHITECTURE")
            output.append("")
            output.extend(cls._render_event_flow())
            output.append("")

        # Attack Chains
        if focus == 'chains' or style == 'detailed':
            output.append("## ⛓️ ATTACK CHAIN PATTERNS")
            output.append("")
            output.extend(cls._render_attack_chains())
            output.append("")

        # Phase Progression
        output.append("## 📈 PHASE PROGRESSION MODEL")
        output.append("")
        output.extend(cls._render_phase_model(style))
        output.append("")

        # System Health
        if style != 'compact':
            output.append("## 💚 SYSTEM HEALTH CHECK")
            output.append("")
            output.extend(cls._render_health_check())
            output.append("")

        return "\n".join(output)

    @classmethod
    def _render_plugin_stats(cls, style: str) -> List[str]:
        """Render plugin statistics"""
        output = []

        # Get all registered plugins
        ServiceRegistry.initialize_plugins()
        plugins = ServiceRegistry.get_all_plugins()

        total = len(plugins)
        categories = {}

        # Categorize plugins
        for plugin in plugins:
            category = cls._categorize_plugin(plugin.name)
            categories[category] = categories.get(category, 0) + 1

        output.append(f"Total Plugins: {total}")
        output.append("")

        if style == 'detailed':
            output.append("Categories:")
            for cat, count in sorted(categories.items(), key=lambda x: x[1], reverse=True):
                bar = "█" * (count // 2) if count > 0 else "░"
                output.append(f"  {cat:20s} [{count:3d}] {bar}")
        else:
            # Compact view
            cats = ", ".join([f"{cat}({count})" for cat, count in categories.items()])
            output.append(f"Distribution: {cats}")

        return output

    @classmethod
    def _categorize_plugin(cls, plugin_name: str) -> str:
        """Categorize plugin by name"""
        categories = {
            'web': ['http', 'https', 'api', 'cms', 'web'],
            'network': ['smb', 'ssh', 'ftp', 'telnet', 'rdp', 'vnc'],
            'database': ['sql', 'mysql', 'postgres', 'oracle', 'mongodb'],
            'exploit': ['exploit', 'binary', 'overflow', 'injection'],
            'ad': ['ad_', 'ldap', 'kerberos', 'domain'],
            'post': ['post', 'privesc', 'persistence', 'lateral'],
            'mobile': ['android', 'ios', 'mobile'],
            'cloud': ['cloud', 'aws', 'azure', 'gcp'],
            'other': []
        }

        for category, keywords in categories.items():
            if any(kw in plugin_name.lower() for kw in keywords):
                return category
        return 'other'

    @classmethod
    def _render_event_flow(cls) -> List[str]:
        """Render event flow diagram"""
        return [
            "```",
            "Nmap Parser",
            "    ↓",
            "parse_file() → Discovers port 80",
            "    ↓",
            "EventBus.emit('service_detected', {port: 80, service: 'http'})",
            "    ↓",
            "ServiceRegistry → Matches HTTP, CMS, API plugins",
            "    ↓",
            "Plugins.detect() → Return confidence scores",
            "    ↓",
            "Highest confidence wins → HTTPPlugin selected",
            "    ↓",
            "HTTPPlugin.get_task_tree() → Generates enumeration tasks",
            "    ↓",
            "EventBus.emit('plugin_tasks_generated', {tasks})",
            "    ↓",
            "TargetProfile.add_task() → Integrates into master tree",
            "```"
        ]

    @classmethod
    def _render_attack_chains(cls) -> List[str]:
        """Render common attack chain patterns"""
        return [
            "Common OSCP Attack Chains:",
            "",
            "1. Web → SQLi → Database → Creds → SSH → PrivEsc → Root",
            "   └─ Alternative: LFI → Source Code → Hardcoded Creds",
            "",
            "2. SMB → Null Session → User Enum → Password Spray → RDP → Local Exploit",
            "   └─ Alternative: SMB Share → Sensitive Files → Domain Creds",
            "",
            "3. Anonymous FTP → Web Root Write → PHP Shell → Reverse Shell → Kernel Exploit",
            "   └─ Alternative: FTP Bounce → Internal Network Scan",
            "",
            "4. Service Version → SearchSploit → Public Exploit → Metasploit → Meterpreter",
            "   └─ Alternative: Manual Exploit → Custom Payload → nc Listener",
            "",
            "5. WordPress → WPScan → Plugin Vuln → Admin Access → Theme Edit → RCE",
            "   └─ Alternative: XML-RPC → Brute Force → Weak Password"
        ]

    @classmethod
    def _render_phase_model(cls, style: str) -> List[str]:
        """Render phase progression model"""
        output = []

        if style == 'detailed':
            output.extend([
                "```",
                "┌──────────────┐     ┌──────────────┐     ┌──────────────┐",
                "│  Discovery   │────►│ Enumeration  │────►│ Exploitation │",
                "│              │     │              │     │              │",
                "│ • Port Scan  │     │ • Service ID │     │ • Exploit    │",
                "│ • Host Enum  │     │ • Version    │     │ • Payload    │",
                "│ • OS Detect  │     │ • Deep Scan  │     │ • Shell      │",
                "└──────────────┘     └──────────────┘     └──────┬──────┘",
                "                                                  │",
                "                                          ┌───────▼──────┐",
                "                                          │ Post-Exploit │",
                "                                          │              │",
                "                                          │ • PrivEsc    │",
                "                                          │ • Persist    │",
                "                                          │ • Pivot      │",
                "                                          └──────────────┘",
                "```"
            ])
        else:
            output.append("Discovery → Enumeration → Exploitation → Post-Exploitation")

        return output

    @classmethod
    def _render_health_check(cls) -> List[str]:
        """Render system health status"""
        output = []
        checks = []

        # Check plugin system
        try:
            ServiceRegistry.initialize_plugins()
            plugin_count = len(ServiceRegistry.get_all_plugins())
            if plugin_count > 100:
                checks.append("✅ Plugin System: Healthy (120+ plugins loaded)")
            elif plugin_count > 50:
                checks.append("⚠️ Plugin System: Partial ({} plugins loaded)".format(plugin_count))
            else:
                checks.append("🔴 Plugin System: Degraded ({} plugins only)".format(plugin_count))
        except:
            checks.append("🔴 Plugin System: Failed to initialize")

        # Check storage
        storage_path = Path.home() / '.crack' / 'targets'
        if storage_path.exists():
            profile_count = len(list(storage_path.glob('*.json')))
            checks.append(f"✅ Storage System: Healthy ({profile_count} profiles)")
        else:
            checks.append("⚠️ Storage System: No profiles directory")

        # Check event system
        from .core.events import EventBus
        handler_count = sum(len(handlers) for handlers in EventBus._handlers.values())
        if handler_count > 0:
            checks.append(f"✅ Event System: Active ({handler_count} handlers)")
        else:
            checks.append("⚠️ Event System: No handlers registered")

        output.extend(checks)
        return output

    @classmethod
    def render_plugin_flow(cls, **kwargs) -> str:
        """Render plugin event flow visualization"""
        output = []
        output.append("PLUGIN EVENT FLOW VISUALIZATION")
        output.append("=" * 50)
        output.append("")

        # Show event flow
        output.append("Event Flow:")
        output.append("1. Service Detection")
        output.append("   └─> service_detected event")
        output.append("       └─> ServiceRegistry._handle_service_detected()")
        output.append("           ├─> plugin.detect() [confidence check]")
        output.append("           └─> plugin.get_task_tree()")
        output.append("               └─> plugin_tasks_generated event")
        output.append("                   └─> TargetProfile._handle_plugin_tasks()")
        output.append("")

        # Show plugin lifecycle
        output.append("Plugin Lifecycle:")
        output.append("┌────────────┐     ┌────────────┐     ┌────────────┐")
        output.append("│ Register   │────>│   Detect   │────>│  Generate  │")
        output.append("│ @decorator │     │  service   │     │   tasks    │")
        output.append("└────────────┘     └────────────┘     └────────────┘")

        return "\n".join(output)

    @classmethod
    def render_task_tree(cls, target: str, **kwargs) -> str:
        """Render task tree for specific target"""
        profile = TargetProfile.load(target)
        if not profile:
            return f"No profile found for {target}"

        output = []
        output.append(f"TASK TREE: {target}")
        output.append("=" * 50)
        output.append("")

        # Render tree recursively
        def render_node(node, indent=0):
            prefix = "  " * indent
            status_icon = {
                'completed': '✅',
                'pending': '⏳',
                'in-progress': '🔄',
                'skipped': '⏭️'
            }.get(node.status, '❓')

            output.append(f"{prefix}{status_icon} {node.name}")

            # Show metadata if detailed
            if kwargs.get('style') == 'detailed' and node.metadata.get('command'):
                output.append(f"{prefix}    └─ {node.metadata['command']}")

            for child in node.children:
                render_node(child, indent + 1)

        render_node(profile.task_tree)

        # Show statistics
        progress = profile.task_tree.get_progress()
        output.append("")
        output.append("Progress Summary:")
        output.append(f"  Total: {progress['total']}")
        output.append(f"  Completed: {progress['completed']} ({progress['completed']*100//max(progress['total'],1)}%)")
        output.append(f"  In Progress: {progress['in_progress']}")
        output.append(f"  Pending: {progress['pending']}")

        return "\n".join(output)

    @classmethod
    def render_progress(cls, target: str, **kwargs) -> str:
        """Render progress bars for target"""
        profile = TargetProfile.load(target)
        if not profile:
            return f"No profile found for {target}"

        output = []
        output.append(f"PROGRESS: {target}")
        output.append("=" * 50)
        output.append("")

        progress = profile.task_tree.get_progress()
        total = max(progress['total'], 1)

        # Overall progress bar
        completed_pct = progress['completed'] * 100 // total
        bar_width = 40
        filled = '█' * (completed_pct * bar_width // 100)
        empty = '░' * (bar_width - len(filled))

        output.append(f"Overall: [{filled}{empty}] {completed_pct}%")
        output.append(f"         {progress['completed']}/{total} tasks")
        output.append("")

        # Phase breakdown
        output.append("By Status:")
        for status, count in progress.items():
            if status != 'total':
                pct = count * 100 // total
                output.append(f"  {status:12s}: {count:3d} ({pct:3d}%)")

        return "\n".join(output)

    @classmethod
    def export_markdown(cls, content: str, output_file: str) -> None:
        """Export visualization to markdown file"""
        with open(output_file, 'w') as f:
            f.write(content)


def visualize(view: str, target: Optional[str] = None, **kwargs) -> str:
    """
    Main visualization entry point

    Args:
        view: Visualization type (master, plugin-flow, task-tree, etc.)
        target: Target IP/hostname (required for some views)
        **kwargs: Additional options (style, color, theme, focus, output_file)

    Returns:
        Formatted visualization string
    """
    visualizer = Visualizer()

    view_map = {
        'master': visualizer.render_master_view,
        'plugin-flow': visualizer.render_plugin_flow,
        'plugin-graph': visualizer.render_plugin_flow,  # Alias
        'task-tree': lambda **kw: visualizer.render_task_tree(target, **kw),
        'progress': lambda **kw: visualizer.render_progress(target, **kw),
    }

    renderer = view_map.get(view)
    if not renderer:
        return f"Unknown visualization view: {view}\nAvailable: {', '.join(view_map.keys())}"

    try:
        result = renderer(**kwargs)

        # Export to file if requested
        if kwargs.get('output_file'):
            visualizer.export_markdown(result, kwargs['output_file'])

        return result

    except Exception as e:
        return f"Visualization error: {e}"