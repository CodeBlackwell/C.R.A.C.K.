"""
Prompt Builder - Generate contextual prompts and menus

Creates menus, questions, and prompts based on:
- Current phase (discovery, enumeration, exploitation)
- Target profile state (ports found, services detected, etc.)
- Available tasks (pending, completed)
- Recommendations from engine
"""

from typing import List, Dict, Any, Optional
from .display import DisplayManager


class PromptBuilder:
    """Generate context-aware prompts and menus"""

    @classmethod
    def build_main_menu(cls, profile, recommendations: Dict[str, Any]) -> tuple:
        """
        Build main interactive menu based on current state

        Args:
            profile: TargetProfile instance
            recommendations: Recommendations from RecommendationEngine

        Returns:
            Tuple of (prompt_text, choices_list)
        """
        choices = []

        # Get current phase
        phase = profile.phase

        # Always show next recommended action if available
        if recommendations.get('next'):
            next_task = recommendations['next']
            choices.append({
                'id': 'next',
                'label': 'Execute next recommended task',
                'description': next_task.name,
                'task': next_task
            })

        # Show quick wins if available
        quick_wins = recommendations.get('quick_wins', [])
        if quick_wins:
            choices.append({
                'id': 'quick-wins',
                'label': 'Show quick wins (fast, high-value tasks)',
                'description': f'{len(quick_wins)} quick win(s) available'
            })

        # Phase-specific options
        if phase == 'discovery':
            choices.extend(cls._get_discovery_choices(profile))
        elif phase in ['service-detection', 'service-specific']:
            choices.extend(cls._get_enumeration_choices(profile))
        elif phase == 'exploitation':
            choices.extend(cls._get_exploitation_choices(profile))

        # Common options (always available)
        choices.append({
            'id': 'import',
            'label': 'Import scan results',
            'description': 'Import nmap XML/gnmap file'
        })

        choices.append({
            'id': 'finding',
            'label': 'Document finding',
            'description': 'Add vulnerability, credential, or note'
        })

        # Phase 6.5: Alternative commands option
        choices.append({
            'id': 'alternatives',
            'label': 'Alternative commands',
            'description': 'Browse and execute alternative commands'
        })

        choices.append({
            'id': 'show-status',
            'label': 'Show full status',
            'description': 'View complete task tree and progress'
        })

        choices.append({
            'id': 'exit',
            'label': 'Exit interactive mode',
            'description': 'Save and exit'
        })

        # Build prompt text
        phase_title = phase.replace('-', ' ').title()
        prompt_text = f"\n{phase_title} - What would you like to do?"

        return (prompt_text, choices)

    @classmethod
    def _get_discovery_choices(cls, profile) -> List[Dict[str, Any]]:
        """Get discovery phase specific choices - DYNAMIC from scan profiles"""
        from ..core.scan_profiles import get_profiles_for_phase

        choices = []

        # Check if ports discovered
        if not profile.ports:
            # Load scan profiles dynamically for discovery phase
            environment = profile.metadata.get('environment', 'lab') if hasattr(profile, 'metadata') else 'lab'
            available_profiles = get_profiles_for_phase('discovery', environment)

            # Add each profile as a choice
            for scan_profile in available_profiles:
                profile_id = scan_profile['id']
                choices.append({
                    'id': f'scan-{profile_id}',
                    'label': scan_profile['name'],
                    'description': f"{scan_profile['use_case']} ({scan_profile['estimated_time']})",
                    'scan_profile': scan_profile,  # Attach full profile for handler
                    'tags': scan_profile.get('tags', [])
                })

            # Always offer custom scan option
            choices.append({
                'id': 'custom-scan',
                'label': 'Custom scan command',
                'description': 'Enter your own nmap command'
            })
        else:
            # Ports found, suggest service scan
            num_ports = len(profile.ports)
            choices.append({
                'id': 'service-scan',
                'label': 'Run service version scan',
                'description': f'Enumerate services on {num_ports} discovered port(s)'
            })

        return choices

    @classmethod
    def _get_enumeration_choices(cls, profile) -> List[Dict[str, Any]]:
        """Get enumeration phase specific choices"""
        choices = []

        # Get pending service enumeration tasks
        pending = profile.task_tree.get_all_pending()

        if pending:
            choices.append({
                'id': 'enumerate-all',
                'label': 'Enumerate all services',
                'description': 'Run all pending enumeration tasks'
            })

            choices.append({
                'id': 'select-tasks',
                'label': 'Select specific tasks to run',
                'description': 'Choose which enumeration tasks to execute'
            })

        return choices

    @classmethod
    def _get_exploitation_choices(cls, profile) -> List[Dict[str, Any]]:
        """Get exploitation phase specific choices"""
        choices = []

        # Check for findings that might be exploitable
        if profile.findings:
            choices.append({
                'id': 'research-exploits',
                'label': 'Research exploits',
                'description': 'Search for exploits based on findings'
            })

        return choices

    @classmethod
    def build_task_selection_menu(cls, tasks: List[Any]) -> tuple:
        """
        Build menu for selecting specific tasks

        Args:
            tasks: List of TaskNode objects

        Returns:
            Tuple of (prompt_text, choices_list)
        """
        choices = []

        for task in tasks:
            # Extract task info
            if hasattr(task, 'id'):
                task_id = task.id
                name = task.name
                description = task.metadata.get('description', '')
                tags = task.metadata.get('tags', [])
            else:
                task_id = task.get('id')
                name = task.get('name')
                description = task.get('description', '')
                tags = task.get('tags', [])

            # Build choice
            choice = {
                'id': task_id,
                'label': name,
                'description': description,
                'task': task
            }

            # Add tag indicators
            if 'QUICK_WIN' in tags:
                choice['label'] += ' ⚡'
            if 'OSCP:HIGH' in tags:
                choice['label'] += ' 🎯'

            choices.append(choice)

        prompt_text = "\nSelect task to execute (or 'back' to return):"
        return (prompt_text, choices)

    @classmethod
    def build_import_prompt(cls) -> str:
        """Build file import prompt"""
        return "\nEnter path to scan file (nmap XML/gnmap): "

    @classmethod
    def build_finding_type_menu(cls) -> tuple:
        """Build menu for selecting finding type"""
        choices = [
            {
                'id': 'vulnerability',
                'label': 'Vulnerability',
                'description': 'Security vulnerability or weakness'
            },
            {
                'id': 'credential',
                'label': 'Credential',
                'description': 'Username/password or authentication token'
            },
            {
                'id': 'directory',
                'label': 'Directory/File',
                'description': 'Interesting directory or file discovered'
            },
            {
                'id': 'user',
                'label': 'User/Account',
                'description': 'User account or email address'
            },
            {
                'id': 'note',
                'label': 'General Note',
                'description': 'Freeform observation or note'
            }
        ]

        prompt_text = "\nWhat type of finding?"
        return (prompt_text, choices)

    @classmethod
    def build_credential_form(cls) -> List[Dict[str, Any]]:
        """
        Build guided form for credential entry

        Returns:
            List of field definitions
        """
        return [
            {
                'name': 'username',
                'type': str,
                'required': True,
                'prompt': 'Username',
                'example': 'admin'
            },
            {
                'name': 'password',
                'type': str,
                'required': False,
                'prompt': 'Password (leave empty if hash/token)',
                'example': 'password123'
            },
            {
                'name': 'service',
                'type': str,
                'required': True,
                'prompt': 'Service',
                'example': 'ssh, http, mysql, smb'
            },
            {
                'name': 'port',
                'type': int,
                'required': False,
                'prompt': 'Port number',
                'example': '22, 80, 3306, 445'
            },
            {
                'name': 'source',
                'type': str,
                'required': True,
                'prompt': 'Where found (REQUIRED for OSCP)',
                'example': 'Found in /var/www/config.php'
            }
        ]

    @classmethod
    def build_finding_form(cls, finding_type: str) -> List[Dict[str, Any]]:
        """
        Build guided form for finding entry

        Args:
            finding_type: Type of finding (vulnerability, directory, etc.)

        Returns:
            List of field definitions
        """
        return [
            {
                'name': 'description',
                'type': str,
                'required': True,
                'prompt': f'{finding_type.title()} description',
                'example': 'SQL injection in id parameter' if finding_type == 'vulnerability' else None
            },
            {
                'name': 'source',
                'type': str,
                'required': True,
                'prompt': 'How discovered (REQUIRED for OSCP)',
                'example': 'Manual testing: sqlmap -u "http://target/page.php?id=1"'
            }
        ]

    @classmethod
    def build_quick_wins_menu(cls, tasks: List[Any]) -> tuple:
        """
        Build menu showing quick win tasks

        Args:
            tasks: List of quick win TaskNode objects

        Returns:
            Tuple of (prompt_text, choices_list)
        """
        choices = []

        for task in tasks[:5]:  # Limit to top 5
            choices.append({
                'id': task.id,
                'label': task.name,
                'description': task.metadata.get('description', ''),
                'task': task
            })

        choices.append({
            'id': 'execute-all',
            'label': 'Execute all quick wins',
            'description': 'Run all quick win tasks in sequence'
        })

        choices.append({
            'id': 'back',
            'label': 'Back to main menu',
            'description': None
        })

        prompt_text = "\n⚡ Quick Wins - Fast, high-value tasks:"
        return (prompt_text, choices)

    @classmethod
    def build_context_display(cls, profile, last_action: str = None) -> str:
        """
        Build complete context display (banner + summary)

        Args:
            profile: TargetProfile instance
            last_action: Description of last action

        Returns:
            Formatted context string
        """
        # Use DisplayManager for banner
        banner = DisplayManager.format_context_banner(profile, last_action=last_action)

        # Add port summary if ports discovered
        summary = []
        if profile.ports:
            summary.append(f"\nDiscovered ports: {len(profile.ports)}")

            # Show up to 5 ports
            port_list = sorted(profile.ports.keys())[:5]
            for port in port_list:
                info = profile.ports[port]
                service = info.get('service', 'unknown')
                version = info.get('version', '')
                summary.append(f"  • {port}/{service} {version}".strip())

            if len(profile.ports) > 5:
                summary.append(f"  ... and {len(profile.ports) - 5} more")

        # Add findings summary
        if profile.findings:
            summary.append(f"\nFindings: {len(profile.findings)}")

        # Add credentials summary
        if profile.credentials:
            summary.append(f"Credentials: {len(profile.credentials)}")

        return banner + "\n".join(summary)

    @classmethod
    def build_help_text(cls) -> str:
        """Build help text for interactive mode"""
        help_text = f"""
Interactive Mode Help
{'=' * 50}

NAVIGATION:
  • Enter number (1, 2, 3) to select menu option
  • Type keyword to match menu item
  • Use shortcuts for quick actions

KEYBOARD SHORTCUTS:
  s - Show full status and task tree
  t - Show task tree only
  r - Show recommendations
  n - Execute next recommended task
  c - Change confirmation mode
  x - Command templates (quick OSCP commands)
  w - Select wordlist (for gobuster, hydra, etc.)
  alt - Alternative commands (browse and execute alternatives)
  ch - Command history (browse and search)
  pl - Port lookup reference (common OSCP ports)
  tf - Task filter (filter by status, port, service, tags)
  qn - Quick note (add note without forms)
  tt - Time tracker dashboard (time management)
  pd - Progress dashboard (visual progress overview)
  qx - Quick export (export view to file/clipboard)
  fc - Finding correlator (analyze findings)
  qe - Quick execute (run commands without task creation)
  ss - Session snapshot (save/restore checkpoints)
  tr - Task retry (retry failed tasks with editing)
  be - Batch execute (run multiple tasks with dependencies)
  sa - Success analyzer (task success rates and optimization)
  wr - Workflow recorder (record and replay task sequences)
  sg - Smart suggest (AI-lite pattern-based suggestions)
  b - Go back to previous menu
  h - Show this help
  q - Quit and save

COMMANDS:
  back  - Return to previous menu
  menu  - Return to main menu
  exit  - Exit interactive mode
  !cmd  - Execute shell command

DATA ENTRY:
  • Follow guided prompts
  • Press Enter for default values
  • Use Ctrl+C to cancel operation

OSCP EXAM NOTES:
  • Always document SOURCE for findings/creds
  • Manual alternatives provided for all tools
  • Command explanations included
  • Time estimates shown for planning

Type 'menu' to return to main menu.
"""
        return help_text
