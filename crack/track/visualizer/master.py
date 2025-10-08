"""
Comprehensive master visualization for CRACK Track plugin ecosystem

Programmatically generates visualization showing:
- 127 plugins across 5 OSCP phases
- 115 ports coverage
- Attack chains and triggers
- Task generation details
- Tag-based capabilities
- Service overlaps
"""

from typing import Dict, List, Any, Optional, Tuple
from collections import defaultdict


# ============ DATA EXTRACTION ENGINE ============

def extract_tasks_recursive(node: Dict, depth: int = 0, max_depth: int = 3) -> List[Dict]:
    """Recursively extract all tasks from task tree

    Args:
        node: Task tree node
        depth: Current depth
        max_depth: Maximum recursion depth

    Returns:
        List of task dicts with metadata
    """
    tasks = []

    # Add current node if it's a task (not just parent container)
    if node.get('type') in ['command', 'research', 'manual']:
        tasks.append({
            'id': node.get('id'),
            'name': node.get('name'),
            'type': node.get('type'),
            'metadata': node.get('metadata', {})
        })

    # Recurse into children
    if depth < max_depth:
        for child in node.get('children', []):
            tasks.extend(extract_tasks_recursive(child, depth + 1, max_depth))

    return tasks


def detect_triggers_from_services(data: Dict) -> Dict[str, List[str]]:
    """Programmatically detect which plugins trigger others

    Uses heuristics:
    - Service name overlap (http → web-attacks)
    - Port overlap (22 → linux-enumeration)
    - Name patterns (privesc → persistence)

    Args:
        data: Extracted plugin data

    Returns:
        Dict mapping plugin_name -> [triggered_plugin_names]
    """
    triggers = defaultdict(list)

    # 1. Explicit trigger rules (based on common patterns)
    trigger_rules = {
        'http': ['xss-attacks', 'injection-attacks', 'ssrf-attacks', 'ssti-attacks',
                 'jwt-attacks', 'session-attacks', 'auth-bypass', 'wordpress', 'cms', 'graphql'],
        'smb': ['credential-theft', 'lateral-movement', 'ad-attacks'],
        'ssh': ['linux-privesc', 'linux-enumeration'],
        'ftp': ['credential-theft'],
        'cms': ['wordpress'],
        'wordpress': ['injection-attacks', 'auth-bypass'],
    }

    # 2. Pattern-based triggers (post-exploit chains)
    post_exploit_triggers = ['persistence', 'ad-persistence', 'c2-operations']
    for plugin in data['plugins']:
        name = plugin['name']
        if any(x in name for x in ['privesc', 'post-exploit', 'credential-theft', 'lateral-movement']):
            triggers[name] = post_exploit_triggers.copy()

    # 3. Apply explicit rules
    for source, targets in trigger_rules.items():
        # Only add triggers if plugins exist
        existing_targets = [t for t in targets if any(p['name'] == t for p in data['plugins'])]
        if existing_targets:
            triggers[source] = existing_targets

    return dict(triggers)


def categorize_by_phase(plugins: List[Dict]) -> Dict[str, List[Dict]]:
    """Categorize plugins into OSCP phases

    Phases:
    1. discovery - none (handled by nmap)
    2. service-detection - network service plugins
    3. service-specific - enumeration and app-specific
    4. exploitation - exploit and attack vector plugins
    5. post-exploitation - privesc and persistence

    Args:
        plugins: List of plugin dicts

    Returns:
        Dict mapping phase -> [plugins]
    """
    phases = {
        'discovery': [],
        'service-detection': [],
        'service-specific': [],
        'exploitation': [],
        'post-exploitation': []
    }

    for plugin in plugins:
        name = plugin['name']

        # Service detection (network services)
        if name in ['http', 'smb', 'ssh', 'ftp', 'sql', 'mysql', 'postgresql', 'smtp', 'nfs']:
            phases['service-detection'].append(plugin)

        # Post-exploitation
        elif any(x in name for x in ['privesc', 'post-exploit', 'persistence']):
            phases['post-exploitation'].append(plugin)

        # Exploitation
        elif any(x in name for x in ['exploit', 'bof', 'heap', 'attacks']):
            phases['exploitation'].append(plugin)

        # Everything else is service-specific enumeration
        else:
            phases['service-specific'].append(plugin)

    return phases


def extract_all_plugin_data(plugins: Dict) -> Dict:
    """Master data extraction - introspects all 127 plugins

    Args:
        plugins: ServiceRegistry._plugins dict

    Returns:
        Comprehensive data dict with all metadata
    """
    data = {
        'plugins': [],
        'port_map': defaultdict(list),
        'service_map': defaultdict(list),
        'tag_map': defaultdict(list),
        'triggers': {},
        'task_details': {},
        'overlaps': [],
        'stats': {},
        'phases': {}
    }

    for name, plugin in plugins.items():
        # 1. Basic metadata
        plugin_data = {
            'name': name,
            'ports': getattr(plugin, 'default_ports', [])[:] if hasattr(plugin, 'default_ports') else [],
            'services': getattr(plugin, 'service_names', [])[:] if hasattr(plugin, 'service_names') else [],
            'class': plugin.__class__.__name__
        }

        # 2. Generate task tree to extract tasks/tags
        try:
            tree = plugin.get_task_tree('target', 80, {'service': name, 'version': 'test'})
            tasks = extract_tasks_recursive(tree)
            plugin_data['tasks'] = tasks
            plugin_data['task_count'] = len(tasks)

            # Extract all tags
            all_tags = set()
            for task in tasks:
                all_tags.update(task.get('metadata', {}).get('tags', []))
            plugin_data['tags'] = sorted(all_tags)

            # Build tag map
            for tag in all_tags:
                data['tag_map'][tag].append(name)

            # Store task details for detailed view
            data['task_details'][name] = tasks

        except Exception as e:
            plugin_data['tasks'] = []
            plugin_data['task_count'] = 0
            plugin_data['tags'] = []

        # 3. Port mapping
        for port in plugin_data['ports']:
            data['port_map'][port].append(name)

        # 4. Service mapping (detect overlaps)
        for service in plugin_data['services']:
            data['service_map'][service].append(name)

        data['plugins'].append(plugin_data)

    # 5. Detect service overlaps
    data['overlaps'] = [(svc, plugins) for svc, plugins in data['service_map'].items()
                        if len(plugins) > 1]

    # 6. Detect triggers programmatically
    data['triggers'] = detect_triggers_from_services(data)

    # 7. Categorize by phase
    data['phases'] = categorize_by_phase(data['plugins'])

    # 8. Stats
    data['stats'] = {
        'total_plugins': len(plugins),
        'total_ports': len(data['port_map']),
        'total_services': len(data['service_map']),
        'total_overlaps': len(data['overlaps']),
        'total_triggers': sum(len(v) for v in data['triggers'].values()),
        'total_tags': len(data['tag_map']),
        'total_tasks': sum(p['task_count'] for p in data['plugins'])
    }

    return data


# ============ SECTION BUILDERS ============

def build_executive_summary(data: Dict) -> str:
    """Section 1: Executive summary with key stats"""
    output = []
    stats = data['stats']

    output.append("╔═══════════════════════════════════════════════════════════════════════╗")
    output.append("║               CRACK TRACK - MASTER PLUGIN ECOSYSTEM                   ║")
    output.append("╠═══════════════════════════════════════════════════════════════════════╣")
    output.append(f"║  Total Plugins: {stats['total_plugins']:<16} Port Coverage: {stats['total_ports']:<16} ║")
    output.append(f"║  Service Overlap: {stats['total_overlaps']:<13} Attack Chains: {stats['total_triggers']:<16} ║")
    output.append(f"║  Total Tasks: {stats['total_tasks']:<17} Unique Tags: {stats['total_tags']:<18} ║")

    # OSCP-specific stats
    oscp_high = len(data['tag_map'].get('OSCP:HIGH', []))
    quick_wins = len(data['tag_map'].get('QUICK_WIN', []))
    output.append(f"║  OSCP:HIGH: {oscp_high:<19} Quick Wins: {quick_wins:<20} ║")
    output.append("╚═══════════════════════════════════════════════════════════════════════╝")

    return '\n'.join(output)


def build_phase_matrix(data: Dict, truncate: bool = True) -> str:
    """Section 2: Plugins organized by OSCP phase

    Args:
        data: Extracted plugin data
        truncate: If True, show only first 10 plugins per phase. If False, show all.
    """
    output = []
    output.append("")
    output.append("=" * 80)
    output.append("PHASE-PLUGIN MATRIX".center(80))
    output.append("=" * 80)
    output.append("")

    phase_names = {
        'discovery': 'PHASE 1: DISCOVERY',
        'service-detection': 'PHASE 2: SERVICE DETECTION',
        'service-specific': 'PHASE 3: SERVICE-SPECIFIC ENUMERATION',
        'exploitation': 'PHASE 4: EXPLOITATION',
        'post-exploitation': 'PHASE 5: POST-EXPLOITATION'
    }

    for phase_key, phase_name in phase_names.items():
        plugins = data['phases'].get(phase_key, [])
        output.append(f"{phase_name} ({len(plugins)} plugins)")
        output.append("-" * 80)

        if not plugins:
            output.append("  (handled externally by nmap)" if phase_key == 'discovery' else "  (no plugins)")
        else:
            # Show plugins with details
            display_plugins = plugins if not truncate else plugins[:10]
            for plugin in display_plugins:
                name = plugin['name']
                ports = ', '.join(map(str, plugin['ports'][:4])) if plugin['ports'] else 'N/A'
                tasks = plugin['task_count']
                tags = ', '.join([t for t in plugin['tags'] if 'OSCP' in t or t == 'QUICK_WIN'][:2])

                output.append(f"  [{name.upper():<20}] Ports: {ports:<15} Tasks: {tasks:<3} Tags: {tags}")

            if truncate and len(plugins) > 10:
                output.append(f"  ... and {len(plugins) - 10} more plugins")

        output.append("")

    return '\n'.join(output)


def build_port_coverage_map(data: Dict, truncate: bool = True) -> str:
    """Section 3: Port → Plugin mapping

    Args:
        data: Extracted plugin data
        truncate: If True, show only first 20 ports. If False, show all.
    """
    output = []
    output.append("=" * 80)
    output.append("PORT COVERAGE MAP".center(80))
    output.append("=" * 80)
    output.append(f"Total Ports Covered: {data['stats']['total_ports']}")
    output.append("")

    # Show most commonly covered ports
    port_items = sorted(data['port_map'].items(), key=lambda x: (len(x[1]), -x[0]), reverse=True)

    output.append(f"{'Top 20 Ports' if truncate else 'All Ports'}:")
    display_ports = port_items[:20] if truncate else port_items
    for i, (port, plugins) in enumerate(display_ports, 1):
        plugin_list = ', '.join([p.upper() for p in plugins[:5]])
        if len(plugins) > 5:
            plugin_list += f' (+{len(plugins) - 5} more)'
        output.append(f"  {i:2}. Port {port:<6} → {plugin_list}")

    if truncate and len(port_items) > 20:
        output.append(f"  ... and {len(port_items) - 20} more ports")

    return '\n'.join(output)


def build_attack_chains(data: Dict, truncate: bool = True) -> str:
    """Section 4: Plugin → Task → Trigger chains

    Args:
        data: Extracted plugin data
        truncate: If True, show only http/smb/ssh with 5 tasks/triggers. If False, show all.
    """
    output = []
    output.append("")
    output.append("=" * 80)
    output.append("ATTACK CHAIN VISUALIZATION".center(80))
    output.append("=" * 80)
    output.append("")

    # Show detailed chains for key plugins
    key_plugins = ['http', 'smb', 'ssh'] if truncate else [p['name'] for p in data['plugins'] if data['triggers'].get(p['name'])]

    for plugin_name in key_plugins:
        if plugin_name not in data['triggers']:
            continue

        plugin_data = next((p for p in data['plugins'] if p['name'] == plugin_name), None)
        if not plugin_data:
            continue

        output.append(f"[{plugin_name.upper()} PLUGIN] Port {plugin_data['ports'][0] if plugin_data['ports'] else 'N/A'}")
        output.append("       │")
        output.append(f"       ├─► Generates {plugin_data['task_count']} tasks:")

        # Show tasks
        display_tasks = plugin_data['tasks'][:5] if truncate else plugin_data['tasks']
        for i, task in enumerate(display_tasks, 1):
            tags = ', '.join(task['metadata'].get('tags', [])[:2])
            output.append(f"       │   {i}. {task['name']} ({tags})")

        if truncate and plugin_data['task_count'] > 5:
            output.append(f"       │   ... and {plugin_data['task_count'] - 5} more tasks")

        # Show triggers
        triggers = data['triggers'].get(plugin_name, [])
        if triggers:
            output.append("       │")
            output.append(f"       └─► Triggers {len(triggers)} downstream plugins:")
            display_triggers = triggers[:5] if truncate else triggers
            for trigger in display_triggers:
                output.append(f"           ├─► [{trigger.upper()}]")
            if truncate and len(triggers) > 5:
                output.append(f"           └─► ... and {len(triggers) - 5} more")

        output.append("")

    return '\n'.join(output)


def build_tag_matrix(data: Dict, truncate: bool = True) -> str:
    """Section 5: Tag-based capability grouping

    Args:
        data: Extracted plugin data
        truncate: If True, show only first 10 plugins per tag. If False, show all.
    """
    output = []
    output.append("=" * 80)
    output.append("CAPABILITY ANALYSIS (Tag-Based)".center(80))
    output.append("=" * 80)
    output.append("")

    # Priority tags
    priority_tags = ['OSCP:HIGH', 'QUICK_WIN', 'AUTOMATED', 'MANUAL', 'OSCP:MEDIUM']

    for tag in priority_tags:
        plugins = data['tag_map'].get(tag, [])
        if not plugins:
            continue

        output.append(f"{tag}: {len(plugins)} plugins")
        display_plugins = plugins[:10] if truncate else plugins
        plugin_list = ', '.join(display_plugins)
        if truncate and len(plugins) > 10:
            plugin_list += f' ... (+{len(plugins) - 10} more)'
        output.append(f"  → {plugin_list}")
        output.append("")

    return '\n'.join(output)


def build_service_overlap(data: Dict, truncate: bool = True) -> str:
    """Section 6: Services handled by multiple plugins

    Args:
        data: Extracted plugin data
        truncate: If True, show only first 15 overlaps. If False, show all.
    """
    output = []
    output.append("=" * 80)
    output.append("MULTI-PLUGIN SERVICES (Overlaps)".center(80))
    output.append("=" * 80)
    output.append(f"Total Services with Multiple Handlers: {len(data['overlaps'])}")
    output.append("")

    # Sort by number of plugins handling each service
    sorted_overlaps = sorted(data['overlaps'], key=lambda x: len(x[1]), reverse=True)

    display_overlaps = sorted_overlaps[:15] if truncate else sorted_overlaps
    for service, plugins in display_overlaps:
        plugin_list = ', '.join([p.upper() for p in plugins])
        output.append(f"  '{service}' → {plugin_list}")

    if truncate and len(sorted_overlaps) > 15:
        output.append(f"  ... and {len(sorted_overlaps) - 15} more overlapping services")

    return '\n'.join(output)


def build_task_generation(data: Dict, truncate: bool = True) -> str:
    """Section 7: Task generation details

    Args:
        data: Extracted plugin data
        truncate: If True, show only http/smb/ssh with 3 tasks. If False, show all.
    """
    output = []
    output.append("")
    output.append("=" * 80)
    output.append("TASK GENERATION BY PLUGIN (Sampled)".center(80))
    output.append("=" * 80)
    output.append("")

    # Show detailed task breakdown
    sample_plugins = ['http', 'smb', 'ssh'] if truncate else list(data['task_details'].keys())

    for plugin_name in sample_plugins:
        tasks = data['task_details'].get(plugin_name, [])
        if not tasks:
            continue

        output.append(f"{plugin_name.upper()} Plugin → {len(tasks)} tasks")
        output.append("-" * 80)

        display_tasks = tasks[:3] if truncate else tasks
        for i, task in enumerate(display_tasks, 1):
            output.append(f"  {i}. {task['name']}")
            metadata = task.get('metadata', {})
            if metadata.get('tags'):
                output.append(f"     Tags: {', '.join(metadata['tags'])}")
            if metadata.get('command'):
                cmd = metadata['command']
                if len(cmd) > 70:
                    cmd = cmd[:67] + '...'
                output.append(f"     Command: {cmd}")

        if truncate and len(tasks) > 3:
            output.append(f"  ... and {len(tasks) - 3} more tasks")
        output.append("")

    return '\n'.join(output)


def build_relationship_graph(data: Dict, truncate: bool = True) -> str:
    """Section 8: Complete plugin dependency graph

    Args:
        data: Extracted plugin data
        truncate: Not used (graph is already minimal), kept for consistency
    """
    output = []
    output.append("=" * 80)
    output.append("PLUGIN DEPENDENCY GRAPH".center(80))
    output.append("=" * 80)
    output.append(f"Total Trigger Relationships: {data['stats']['total_triggers']}")
    output.append("")

    for source, targets in sorted(data['triggers'].items()):
        output.append(f"[{source.upper()}]")
        output.append(f"  ↓ ({len(targets)} triggers)")
        for i, target in enumerate(targets):
            is_last = i == len(targets) - 1
            prefix = "  └─► " if is_last else "  ├─► "
            output.append(f"{prefix}{target}")
        output.append("")

    return '\n'.join(output)


# ============ MAIN RENDERER ============

def build_master_visualization(plugins: Dict, style: str = 'tree', focus: Optional[str] = None, truncate: bool = True) -> str:
    """Master comprehensive visualization builder

    Args:
        plugins: ServiceRegistry._plugins
        style: tree (full), compact (summary), columnar (tables)
        focus: Optional section to show only
        truncate: If True, limit output for terminal readability. If False, show all data (for markdown export)

    Returns:
        Formatted visualization string
    """
    # 1. Extract all data programmatically
    data = extract_all_plugin_data(plugins)

    # 2. Build all sections with truncate parameter
    sections = {
        'summary': build_executive_summary(data),
        'phases': build_phase_matrix(data, truncate=truncate),
        'ports': build_port_coverage_map(data, truncate=truncate),
        'chains': build_attack_chains(data, truncate=truncate),
        'tags': build_tag_matrix(data, truncate=truncate),
        'overlaps': build_service_overlap(data, truncate=truncate),
        'tasks': build_task_generation(data, truncate=truncate),
        'graph': build_relationship_graph(data, truncate=truncate)
    }

    # 3. Handle focus mode
    if focus:
        if focus not in sections:
            return f"Error: Unknown focus '{focus}'. Available: {', '.join(sections.keys())}"
        return sections[focus]

    # 4. Render based on style
    if style == 'compact':
        return render_compact(sections, data)
    elif style == 'columnar':
        return render_columnar(data, truncate=truncate)
    else:  # tree (full)
        return render_full(sections)


def render_full(sections: Dict) -> str:
    """Full rendering - all 8 sections"""
    output = []

    # Add all sections in order
    section_order = ['summary', 'phases', 'ports', 'chains', 'tags', 'overlaps', 'tasks', 'graph']

    for section_name in section_order:
        output.append(sections[section_name])
        output.append("")  # Spacing between sections

    return '\n'.join(output)


def render_compact(sections: Dict, data: Dict) -> str:
    """Compact rendering - summary + key metrics"""
    output = []

    # Summary
    output.append(sections['summary'])
    output.append("")

    # Quick phase breakdown
    output.append("PHASE BREAKDOWN:")
    for phase, plugins in data['phases'].items():
        output.append(f"  {phase}: {len(plugins)} plugins")
    output.append("")

    # Top capabilities
    output.append("TOP CAPABILITIES:")
    for tag in ['OSCP:HIGH', 'QUICK_WIN']:
        count = len(data['tag_map'].get(tag, []))
        output.append(f"  {tag}: {count} plugins")
    output.append("")

    # Key triggers
    output.append("KEY ATTACK CHAINS:")
    for plugin in ['http', 'smb', 'ssh']:
        if plugin in data['triggers']:
            output.append(f"  {plugin} → {len(data['triggers'][plugin])} downstream plugins")

    return '\n'.join(output)


def render_columnar(data: Dict, truncate: bool = True) -> str:
    """Columnar rendering - table format

    Args:
        data: Extracted plugin data
        truncate: If True, show only first 30 plugins. If False, show all.
    """
    output = []

    output.append("=" * 120)
    output.append("PLUGIN ECOSYSTEM TABLE".center(120))
    output.append("=" * 120)
    output.append(f"{'Plugin':<25} | {'Ports':<20} | {'Tasks':<6} | {'Triggers':<8} | {'Tags':<40}")
    output.append("-" * 120)

    # Sort by task count
    sorted_plugins = sorted(data['plugins'], key=lambda x: x['task_count'], reverse=True)

    display_plugins = sorted_plugins[:30] if truncate else sorted_plugins
    for plugin in display_plugins:
        name = plugin['name']
        ports = ', '.join(map(str, plugin['ports'][:3]))
        if len(plugin['ports']) > 3:
            ports += '...'
        tasks = plugin['task_count']
        triggers = len(data['triggers'].get(name, []))
        tags = ', '.join([t for t in plugin['tags'] if 'OSCP' in t or t == 'QUICK_WIN'][:2])

        output.append(f"{name:<25} | {ports:<20} | {tasks:<6} | {triggers:<8} | {tags:<40}")

    if truncate and len(sorted_plugins) > 30:
        output.append(f"... and {len(sorted_plugins) - 30} more plugins")

    output.append("=" * 120)

    return '\n'.join(output)


def export_markdown(plugins: Dict, style: str = 'tree', focus: Optional[str] = None) -> str:
    """Export master visualization as clean markdown (untruncated)

    Generates complete, untruncated output suitable for documentation:
    - Shows ALL plugins (not just first 10)
    - Shows ALL ports (not just first 20)
    - Shows ALL tasks/triggers/overlaps
    - Strips ANSI color codes
    - Strips box-drawing characters
    - Clean markdown formatting

    Args:
        plugins: ServiceRegistry._plugins
        style: tree (full), compact (summary), columnar (tables)
        focus: Optional section to show only

    Returns:
        Clean markdown string ready for file export
    """
    import re

    # Build visualization with truncate=False for complete data
    output = build_master_visualization(plugins, style=style, focus=focus, truncate=False)

    # Strip ANSI color codes
    ansi_escape = re.compile(r'\033\[[0-9;]+m')
    output = ansi_escape.sub('', output)

    # Convert box-drawing characters to markdown
    # Convert headers with box chars to markdown headers
    output = output.replace('╔═', '## ')
    output = output.replace('║', '')
    output = output.replace('╠═', '')
    output = output.replace('╚═', '')
    output = output.replace('═╗', '')
    output = output.replace('═╣', '')
    output = output.replace('═╝', '')

    # Clean up excessive whitespace
    lines = []
    for line in output.split('\n'):
        # Remove lines that are just box chars
        if line.strip() and not all(c in '═║╔╗╚╝╠╣─' for c in line.strip()):
            lines.append(line.rstrip())

    # Add markdown header
    header = [
        "# CRACK Track - Master Plugin Ecosystem",
        "",
        "**Complete Plugin Documentation** - Generated untruncated export",
        ""
    ]

    return '\n'.join(header + lines)
