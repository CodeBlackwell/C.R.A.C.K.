"""
Plugin dependency graph visualization

Shows how plugins trigger each other across OSCP phases
"""

from typing import Dict, List, Set, Tuple
from collections import defaultdict


def categorize_plugins(plugins: Dict) -> Dict[str, List[str]]:
    """Group plugins by phase/category

    Categories:
    - Service Detection (triggered by nmap)
    - Enumeration (triggered by service plugins)
    - Exploitation (triggered by findings)
    - Post-Exploitation (triggered by shell access)
    - Attack Vectors (triggered by web/app findings)
    """
    categories = {
        'service_detection': [],
        'enumeration': [],
        'exploitation': [],
        'post_exploitation': [],
        'attack_vectors': []
    }

    for name, plugin in plugins.items():
        # Service detection plugins (network services)
        if name in ['http', 'smb', 'ssh', 'ftp', 'sql', 'mysql', 'postgresql', 'smtp', 'nfs']:
            categories['service_detection'].append(name)

        # Post-exploitation plugins
        elif 'privesc' in name or 'post-exploit' in name or 'persistence' in name:
            categories['post_exploitation'].append(name)

        # Exploitation plugins
        elif 'exploit' in name or 'bof' in name or name in ['windows-bof', 'heap-exploit']:
            categories['exploitation'].append(name)

        # Attack vectors (web attacks, injection, etc.)
        elif any(x in name for x in ['injection', 'xss', 'ssrf', 'ssti', 'jwt', 'auth-bypass']):
            categories['attack_vectors'].append(name)

        # Everything else is enumeration
        else:
            categories['enumeration'].append(name)

    return categories


def detect_plugin_triggers(plugins: Dict) -> Dict[str, List[str]]:
    """Detect which plugins might trigger other plugins

    Returns:
        Dict mapping plugin_name -> [list of plugins it might trigger]

    Logic:
    - HTTP plugin finds web app → triggers web attack plugins
    - SMB plugin finds shares → triggers credential plugins
    - Any service → triggers exploit research
    - Shell access → triggers post-exploit plugins
    """
    triggers = defaultdict(list)

    # HTTP triggers web attack plugins
    web_attacks = ['xss-attacks', 'injection-attacks', 'ssrf-attacks', 'ssti-attacks',
                   'jwt-attacks', 'session-attacks', 'auth-bypass']
    triggers['http'] = web_attacks + ['wordpress', 'cms', 'graphql']

    # SMB triggers credential/lateral movement
    triggers['smb'] = ['credential-theft', 'lateral-movement', 'ad-attacks']

    # SSH triggers privilege escalation
    triggers['ssh'] = ['linux-privesc', 'linux-enumeration']

    # Any shell access triggers post-exploit
    post_exploit_triggers = ['linux-privesc', 'windows-privesc', 'post-exploit',
                             'credential-theft', 'lateral-movement']
    for plugin_name in post_exploit_triggers:
        if plugin_name in plugins:
            triggers[plugin_name] = ['persistence', 'ad-persistence', 'c2-operations']

    # Web apps trigger CMS-specific plugins
    triggers['cms'] = ['wordpress']
    triggers['wordpress'] = ['injection-attacks', 'auth-bypass']

    return dict(triggers)


def build_phase_graph(plugins: Dict) -> str:
    """Build phased plugin flow diagram

    Shows OSCP attack progression across phases
    """
    categories = categorize_plugins(plugins)
    triggers = detect_plugin_triggers(plugins)

    output = []
    output.append("=" * 80)
    output.append("PLUGIN PHASE FLOW - OSCP Attack Chain".center(80))
    output.append("=" * 80)
    output.append("")

    # Phase 1: Discovery
    output.append("┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓")
    output.append("┃  PHASE 1: DISCOVERY                                                       ┃")
    output.append("┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛")
    output.append("")
    output.append("  [Nmap Scan] → Discovers open ports")
    output.append("       │")
    output.append("       ├──► Port 80 (HTTP)")
    output.append("       ├──► Port 445 (SMB)")
    output.append("       ├──► Port 22 (SSH)")
    output.append("       └──► Port 3306 (MySQL)")
    output.append("")
    output.append("                    ▼")
    output.append("")

    # Phase 2: Service Detection
    output.append("┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓")
    output.append("┃  PHASE 2: SERVICE DETECTION                                               ┃")
    output.append("┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛")
    output.append("")
    output.append(f"  Service Plugins Activated: {len(categories['service_detection'])}")
    output.append("")

    # Show first 6 service plugins
    for plugin_name in categories['service_detection'][:6]:
        downstream = triggers.get(plugin_name, [])
        if downstream:
            output.append(f"  ├─► [{plugin_name.upper()}] → Triggers {len(downstream)} downstream plugins")
        else:
            output.append(f"  ├─► [{plugin_name.upper()}]")

    if len(categories['service_detection']) > 6:
        output.append(f"  └─► [...{len(categories['service_detection']) - 6} more service plugins]")

    output.append("")
    output.append("                    ▼")
    output.append("")

    # Phase 3: Enumeration
    output.append("┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓")
    output.append("┃  PHASE 3: SERVICE-SPECIFIC ENUMERATION                                    ┃")
    output.append("┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛")
    output.append("")

    # Show example: HTTP plugin flow
    if 'http' in triggers:
        output.append("  Example: HTTP Service Chain")
        output.append("  ┌─────────────────────────────────────────────────────────────┐")
        output.append("  │ [HTTP Plugin]                                               │")
        output.append("  │   ├─► whatweb (tech fingerprinting)                         │")
        output.append("  │   ├─► gobuster (directory enum)                             │")
        output.append("  │   ├─► nikto (vuln scan)                                     │")
        output.append("  │   └─► Findings: WordPress detected                          │")
        output.append("  └─────────────────────────────────────────────────────────────┘")
        output.append("                    │")
        output.append("                    ├──► Triggers: [wordpress] plugin")
        output.append("                    ├──► Triggers: [cms] plugin")

        for attack in triggers['http'][:3]:
            output.append(f"                    ├──► Triggers: [{attack}] plugin")

        if len(triggers['http']) > 3:
            output.append(f"                    └──► [...{len(triggers['http']) - 3} more attack plugins]")

    output.append("")
    output.append(f"  Total Enumeration Plugins: {len(categories['enumeration'])}")
    output.append(f"  Total Attack Vector Plugins: {len(categories['attack_vectors'])}")
    output.append("")
    output.append("                    ▼")
    output.append("")

    # Phase 4: Exploitation
    output.append("┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓")
    output.append("┃  PHASE 4: EXPLOITATION                                                    ┃")
    output.append("┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛")
    output.append("")
    output.append(f"  Exploitation Plugins Active: {len(categories['exploitation'])}")
    output.append("")
    output.append("  Attack Vectors:")

    for plugin_name in categories['attack_vectors'][:5]:
        output.append(f"    ├─► {plugin_name}")

    if len(categories['attack_vectors']) > 5:
        output.append(f"    └─► [...{len(categories['attack_vectors']) - 5} more vectors]")

    output.append("")
    output.append("  Result: Shell Access Obtained ✓")
    output.append("")
    output.append("                    ▼")
    output.append("")

    # Phase 5: Post-Exploitation
    output.append("┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓")
    output.append("┃  PHASE 5: POST-EXPLOITATION                                               ┃")
    output.append("┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛")
    output.append("")
    output.append(f"  Post-Exploit Plugins: {len(categories['post_exploitation'])}")
    output.append("")

    for plugin_name in categories['post_exploitation'][:8]:
        output.append(f"  ├─► {plugin_name}")

    if len(categories['post_exploitation']) > 8:
        output.append(f"  └─► [...{len(categories['post_exploitation']) - 8} more]")

    output.append("")
    output.append("=" * 80)

    # Summary statistics
    output.append("")
    output.append("PLUGIN CHAIN SUMMARY:")
    output.append(f"  • Service Detection: {len(categories['service_detection'])} plugins")
    output.append(f"  • Enumeration: {len(categories['enumeration'])} plugins")
    output.append(f"  • Attack Vectors: {len(categories['attack_vectors'])} plugins")
    output.append(f"  • Exploitation: {len(categories['exploitation'])} plugins")
    output.append(f"  • Post-Exploitation: {len(categories['post_exploitation'])} plugins")
    output.append(f"  • Total Trigger Relationships: {sum(len(v) for v in triggers.values())}")

    return '\n'.join(output)


def build_trigger_matrix(plugins: Dict, style='tree') -> str:
    """Build plugin trigger matrix showing dependencies

    Args:
        plugins: Dict of plugin_name -> plugin_object
        style: Visualization style (tree, compact)
    """
    triggers = detect_plugin_triggers(plugins)

    if style == 'compact':
        output = []
        output.append("Plugin Trigger Matrix:")
        for source, targets in sorted(triggers.items()):
            output.append(f"  {source} → {', '.join(targets[:3])}")
            if len(targets) > 3:
                output.append(f"           ({len(targets) - 3} more...)")
        return '\n'.join(output)

    # Tree style (default)
    output = []
    output.append("=" * 80)
    output.append("PLUGIN TRIGGER RELATIONSHIPS".center(80))
    output.append("=" * 80)
    output.append("")

    for source, targets in sorted(triggers.items()):
        output.append(f"[{source.upper()}]")
        for i, target in enumerate(targets):
            is_last = i == len(targets) - 1
            prefix = "  └──► " if is_last else "  ├──► "
            output.append(f"{prefix}{target}")
        output.append("")

    return '\n'.join(output)
