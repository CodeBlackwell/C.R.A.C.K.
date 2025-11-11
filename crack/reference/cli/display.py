"""
CLI display handler for command output formatting
"""

import json
from typing import List, Dict, Any

from reference.cli.base import BaseCLIHandler
from reference.core.registry import Command


class DisplayCLI(BaseCLIHandler):
    """Handler for displaying commands in various formats"""

    def __init__(self, registry=None, placeholder_engine=None, theme=None):
        """Initialize display handler

        Args:
            registry: HybridCommandRegistry instance
            placeholder_engine: PlaceholderEngine instance
            theme: ReferenceTheme instance
        """
        super().__init__(theme)
        self.registry = registry
        self.placeholder_engine = placeholder_engine

    def display_commands(self, commands: List[Command], format: str = 'text', verbose: bool = False):
        """Display commands in requested format

        Args:
            commands: List of Command objects to display
            format: Output format (text, json, markdown)
            verbose: Show detailed information
        """
        if format == 'json':
            data = [cmd.to_dict() for cmd in commands]
            print(json.dumps(data, indent=2))

        elif format == 'markdown':
            for cmd in commands:
                print(f"## {cmd.name}")
                print(f"```bash\n{cmd.command}\n```")
                print(f"{cmd.description}\n")
                if verbose:
                    if cmd.tags:
                        print(f"**Tags**: {', '.join(cmd.tags)}")
                    if cmd.oscp_relevance:
                        print(f"**OSCP**: {cmd.oscp_relevance.upper()}")
                    print()

        else:  # text format
            for i, cmd in enumerate(commands, 1):
                print(f"\n{self.theme.muted(f'{i}.')} [{self.theme.primary(cmd.id)}] {self.theme.command_name(cmd.name)}")
                print(f"   {self.theme.secondary(cmd.command)}")

                if verbose:
                    print(f"   {'━' * 70}")
                    print(f"   Description: {cmd.description}")

                    # Show autofilled command
                    if self.placeholder_engine:
                        filled = self.placeholder_engine.substitute(cmd.command)
                        if filled != cmd.command:
                            print(f"\n   Autofilled Example:")
                            print(f"   {filled}")

                    # Prerequisites
                    if cmd.prerequisites:
                        print(f"\n   Prerequisites:")
                        for j, prereq in enumerate(cmd.prerequisites, 1):
                            # Auto-fill prerequisites too
                            if self.placeholder_engine:
                                prereq_filled = self.placeholder_engine.substitute(prereq)
                                print(f"     {j}. {prereq_filled}")
                            else:
                                print(f"     {j}. {prereq}")

                    # Variables
                    if cmd.variables:
                        print(f"\n   Variables:")
                        for var in cmd.variables:
                            req_str = "(required)" if var.required else "(optional)"
                            example = f" [e.g., {var.example}]" if var.example else ""
                            print(f"     <{var.name.strip('<>')}> - {var.description}{example} {req_str}")

                    # Flag explanations
                    if cmd.flag_explanations:
                        print(f"\n   Flags:")
                        for flag, explanation in cmd.flag_explanations.items():
                            print(f"     {flag}: {explanation}")

                    # Success/Failure indicators
                    if cmd.success_indicators:
                        print(f"\n   ✓ Success Indicators:")
                        for indicator in cmd.success_indicators:
                            print(f"     • {indicator}")

                    if cmd.failure_indicators:
                        print(f"\n   ✗ Failure Indicators:")
                        for indicator in cmd.failure_indicators:
                            print(f"     • {indicator}")

                    # Troubleshooting
                    if cmd.troubleshooting:
                        print(f"\n   Troubleshooting:")
                        for error, solution in cmd.troubleshooting.items():
                            # Auto-fill troubleshooting commands
                            if self.placeholder_engine:
                                solution_filled = self.placeholder_engine.substitute(solution)
                                print(f"     • {error}")
                                print(f"       → {solution_filled}")
                            else:
                                print(f"     • {error}")
                                print(f"       → {solution}")

                    # Next steps
                    if cmd.next_steps:
                        print(f"\n   Next Steps:")
                        for j, step in enumerate(cmd.next_steps, 1):
                            print(f"     {j}. {step}")

                    # Alternatives (resolve IDs)
                    if cmd.alternatives and self.registry:
                        print(f"\n   Alternatives:")
                        for j, alt in enumerate(cmd.alternatives, 1):
                            ref = self.registry.get_command(alt)
                            if ref:  # Command ID found
                                print(f"     {j}. [{alt}] {ref.name}")
                            else:  # Free text
                                print(f"     {j}. {alt}")

                    # Tags and OSCP relevance
                    if cmd.tags:
                        print(f"\n   Tags: {', '.join(cmd.tags)}")
                    if cmd.oscp_relevance:
                        print(f"   OSCP Relevance: {cmd.oscp_relevance.upper()}")

                    # Notes
                    if cmd.notes:
                        print(f"\n   Notes: {cmd.notes}")

    def show_command_details(self, cmd: Command):
        """Display full details for a single command (colorized, verbose)

        Args:
            cmd: Command object to display
        """
        # Header
        print(f"\n{'═' * 70}")
        print(f"{self.theme.command_name(cmd.name)}")
        print(f"{'═' * 70}")

        # Command ID
        print(f"\n{self.theme.primary('ID:')} {self.theme.secondary(cmd.id)}")

        # Category and subcategory
        category_display = cmd.category
        if cmd.subcategory:
            category_display = f"{cmd.category} > {cmd.subcategory}"
        print(f"{self.theme.primary('Category:')} {self.theme.secondary(category_display)}")

        # OSCP Relevance
        if cmd.oscp_relevance:
            relevance_color = self.theme.success if cmd.oscp_relevance == 'high' else self.theme.warning if cmd.oscp_relevance == 'medium' else self.theme.hint
            print(f"{self.theme.primary('OSCP Relevance:')} {relevance_color(cmd.oscp_relevance.upper())}")

        # Tags
        if cmd.tags:
            tags_str = ', '.join([self.theme.secondary(tag) for tag in cmd.tags])
            print(f"{self.theme.primary('Tags:')} {tags_str}")

        # Description
        print(f"\n{self.theme.primary('Description:')}")
        print(f"  {cmd.description}")

        # Command template
        print(f"\n{self.theme.primary('Command Template:')}")
        print(f"  {self.theme.command_name(cmd.command)}")

        # Autofilled example
        if self.placeholder_engine:
            filled = self.placeholder_engine.substitute(cmd.command)
            if filled != cmd.command:
                print(f"\n{self.theme.primary('Autofilled Example:')}")
                print(f"  {self.theme.success(filled)}")

        # Prerequisites
        if cmd.prerequisites:
            print(f"\n{self.theme.primary('Prerequisites:')}")
            for i, prereq in enumerate(cmd.prerequisites, 1):
                if self.placeholder_engine:
                    prereq_filled = self.placeholder_engine.substitute(prereq)
                    print(f"  {self.theme.hint(f'{i}.')} {prereq_filled}")
                else:
                    print(f"  {self.theme.hint(f'{i}.')} {prereq}")

        # Variables
        if cmd.variables:
            print(f"\n{self.theme.primary('Variables:')}")
            for var in cmd.variables:
                req_str = self.theme.error("(required)") if var.required else self.theme.hint("(optional)")
                var_name = self.theme.secondary(f"<{var.name.strip('<>')}>")
                example = f" {self.theme.hint(f'[e.g., {var.example}]')}" if var.example else ""
                print(f"  {var_name} - {var.description}{example} {req_str}")

        # Flag explanations
        if cmd.flag_explanations:
            print(f"\n{self.theme.primary('Flag Explanations:')}")
            for flag, explanation in cmd.flag_explanations.items():
                print(f"  {self.theme.secondary(flag)}: {explanation}")

        # Success indicators
        if cmd.success_indicators:
            print(f"\n{self.theme.success('✓ Success Indicators:')}")
            for indicator in cmd.success_indicators:
                print(f"  {self.theme.hint('•')} {indicator}")

        # Failure indicators
        if cmd.failure_indicators:
            print(f"\n{self.theme.error('✗ Failure Indicators:')}")
            for indicator in cmd.failure_indicators:
                print(f"  {self.theme.hint('•')} {indicator}")

        # Troubleshooting
        if cmd.troubleshooting:
            print(f"\n{self.theme.primary('Troubleshooting:')}")
            for error, solution in cmd.troubleshooting.items():
                if self.placeholder_engine:
                    solution_filled = self.placeholder_engine.substitute(solution)
                    print(f"  {self.theme.warning('•')} {error}")
                    print(f"    {self.theme.hint('→')} {solution_filled}")
                else:
                    print(f"  {self.theme.warning('•')} {error}")
                    print(f"    {self.theme.hint('→')} {solution}")

        # Next steps
        if cmd.next_steps:
            print(f"\n{self.theme.primary('Next Steps:')}")
            for i, step in enumerate(cmd.next_steps, 1):
                print(f"  {self.theme.hint(f'{i}.')} {step}")

        # Alternatives
        if cmd.alternatives and self.registry:
            print(f"\n{self.theme.primary('Alternatives:')}")
            for i, alt in enumerate(cmd.alternatives, 1):
                ref = self.registry.get_command(alt)
                if ref:
                    print(f"  {self.theme.hint(f'{i}.')} [{self.theme.secondary(alt)}] {ref.name}")
                else:
                    print(f"  {self.theme.hint(f'{i}.')} {alt}")

        # Use Cases
        if cmd.use_cases:
            print(f"\n{self.theme.primary('Use Cases:')}")
            for i, use_case in enumerate(cmd.use_cases, 1):
                print(f"  {self.theme.hint(f'{i}.')} {use_case}")

        # Advantages
        if cmd.advantages:
            print(f"\n{self.theme.success('✓ Advantages:')}")
            for advantage in cmd.advantages:
                print(f"  {self.theme.hint('•')} {advantage}")

        # Disadvantages
        if cmd.disadvantages:
            print(f"\n{self.theme.warning('⚠ Disadvantages:')}")
            for disadvantage in cmd.disadvantages:
                print(f"  {self.theme.hint('•')} {disadvantage}")

        # Output Analysis
        if cmd.output_analysis:
            print(f"\n{self.theme.primary('Output Analysis:')}")
            for i, analysis in enumerate(cmd.output_analysis, 1):
                print(f"  {self.theme.hint(f'{i}.')} {analysis}")

        # Common Uses
        if cmd.common_uses:
            print(f"\n{self.theme.primary('Common Uses:')}")
            for i, common_use in enumerate(cmd.common_uses, 1):
                print(f"  {self.theme.hint(f'{i}.')} {common_use}")

        # References
        if cmd.references:
            print(f"\n{self.theme.primary('References:')}")
            for i, ref in enumerate(cmd.references, 1):
                if isinstance(ref, dict):
                    title = ref.get('title', ref.get('name', 'Reference'))
                    url = ref.get('url', ref.get('link', ''))
                    if url:
                        print(f"  {self.theme.hint(f'{i}.')} {title}: {self.theme.secondary(url)}")
                    else:
                        print(f"  {self.theme.hint(f'{i}.')} {title}")
                else:
                    print(f"  {self.theme.hint(f'{i}.')} {ref}")

        # Notes
        if cmd.notes:
            print(f"\n{self.theme.primary('Notes:')}")
            print(f"  {cmd.notes}")

        # Footer with usage hints
        print(f"\n{'─' * 70}")
        print(f"{self.theme.hint('Use')} {self.theme.secondary(f'crack reference {cmd.id} -i')} {self.theme.hint('to interactively fill and execute')}")
        print(f"{'═' * 70}\n")

    def show_command_tree(self, registry):
        """Display command tree structure

        Args:
            registry: HybridCommandRegistry instance
        """
        print("\n" + "="*60)
        print(" "*20 + "CRACK REFERENCE TREE")
        print("="*60)

        # Organize commands by category
        categories = {}
        for cmd in registry.commands.values():
            if cmd.category not in categories:
                categories[cmd.category] = []
            categories[cmd.category].append(cmd)

        # Display each category
        category_names = {
            'recon': '🔍 Reconnaissance',
            'web': '🌐 Web Testing',
            'exploitation': '💥 Exploitation',
            'post-exploit': '🔓 Post-Exploitation',
            'file-transfer': '📁 File Transfer',
            'pivoting': '🔄 Pivoting',
            'custom': '⚙️  Custom'
        }

        for cat_key in ['recon', 'web', 'exploitation', 'post-exploit', 'file-transfer', 'pivoting', 'custom']:
            if cat_key in categories and categories[cat_key]:
                commands = sorted(categories[cat_key], key=lambda x: x.id)
                print(f"\n{category_names.get(cat_key, cat_key)} ({len(commands)} commands)")
                print("─" * 50)

                # Group commands by type
                if cat_key == 'recon':
                    groups = {
                        'Network': ['nmap-', 'port-'],
                        'Services': ['dns-', 'smb-', 'snmp-'],
                        'Other': []
                    }
                elif cat_key == 'web':
                    groups = {
                        'Discovery': ['gobuster-', 'nikto-', 'whatweb-'],
                        'SQLi': ['sqli-', 'sqlmap-'],
                        'Other': ['xss-', 'lfi-', 'wfuzz-', 'curl-']
                    }
                elif cat_key == 'exploitation':
                    groups = {
                        'Shells': ['bash-', 'python-', 'nc-', 'powershell-'],
                        'Payloads': ['msfvenom-', 'php-'],
                        'Tools': ['searchsploit', 'hydra-', 'web-shell']
                    }
                elif cat_key == 'post-exploit':
                    groups = {
                        'Linux': ['linux-'],
                        'Windows': ['windows-']
                    }
                elif cat_key == 'file-transfer':
                    groups = {
                        'HTTP': ['python-http', 'wget-', 'curl-', 'certutil-', 'powershell-download'],
                        'Network': ['smb-', 'ftp-', 'scp-', 'nc-file'],
                        'Encoding': ['base64-', 'debug-', 'dns-', 'php-download', 'perl-', 'vbscript-']
                    }
                else:
                    groups = {'All': []}

                # Assign commands to groups
                grouped = {k: [] for k in groups.keys()}
                for cmd in commands:
                    assigned = False
                    for group_name, prefixes in groups.items():
                        if group_name == 'Other' or group_name == 'All':
                            continue
                        for prefix in prefixes:
                            if cmd.id.startswith(prefix) or cmd.id == prefix:
                                grouped[group_name].append(cmd)
                                assigned = True
                                break
                        if assigned:
                            break
                    if not assigned:
                        if 'Other' in grouped:
                            grouped['Other'].append(cmd)
                        elif 'All' in grouped:
                            grouped['All'].append(cmd)

                # Display groups
                for group_name in groups.keys():
                    if grouped[group_name]:
                        print(f"  ├─ {group_name}:")
                        for i, cmd in enumerate(grouped[group_name]):
                            is_last = (i == len(grouped[group_name]) - 1)
                            prefix = "  │   └─" if is_last else "  │   ├─"
                            # Show tags for important commands
                            tag_str = ""
                            if "QUICK_WIN" in cmd.tags:
                                tag_str = " [QUICK WIN]"
                            elif cmd.oscp_relevance == "high":
                                tag_str = " [HIGH]"
                            print(f"{prefix} {cmd.id}: {cmd.name[:40]}{tag_str}")

        print("\n" + "="*60)
        print(f"\nTotal Commands: {len(registry.commands)}")
        print(f"Quick Wins: {len(registry.get_quick_wins())}")
        print(f"OSCP High Relevance: {len(registry.get_oscp_high())}")
        print("\nUse 'crack reference <query>' to search commands")
        print("Use 'crack reference <command-id> -i' to fill and execute")
        print("="*60)
