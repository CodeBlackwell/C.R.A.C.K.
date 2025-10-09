"""
CRACK Track - Session Management Integration

Integrates session management into CRACK Track interactive mode:
- Display active sessions in context
- Quick session switching (shortcut 's')
- Auto-suggest listeners based on open ports
- Session status in menu
"""

from typing import List, Dict, Any, Optional
from datetime import datetime

# Import session components (will be available after import)
try:
    from crack.sessions.manager import SessionManager
    from crack.sessions.storage.base import SessionStorage
    from crack.sessions.config import SessionConfig
    from crack.sessions.models import Session
    SESSION_AVAILABLE = True
except ImportError:
    SESSION_AVAILABLE = False


class SessionIntegration:
    """
    Integrate session management into CRACK Track interactive mode.

    Features:
    - Display active sessions in context
    - Quick session operations from Track
    - Auto-suggest listeners based on discovered services
    - Session lifecycle tracking
    """

    def __init__(self, target_profile):
        """
        Initialize session integration.

        Args:
            target_profile: TargetProfile instance from Track
        """
        self.profile = target_profile

        if SESSION_AVAILABLE:
            self.session_manager = SessionManager(
                SessionStorage(),
                SessionConfig()
            )
            self.enabled = True
        else:
            self.session_manager = None
            self.enabled = False

    def get_active_sessions_display(self) -> str:
        """
        Format active sessions for display in Track context.

        Returns:
            Formatted string showing active sessions

        Example Output:
            [Sessions: 2 active]
            * tcp-abc123: 192.168.45.150:4444 (bash, PTY)
            * http-def456: 192.168.45.151:8080 (beacon, polling)
        """
        if not self.enabled:
            return ""

        # Filter sessions for this target
        target_ip = self.profile.target
        sessions = self.session_manager.list_sessions({
            'target': target_ip,
            'status': 'active'
        })

        if not sessions:
            return "[Sessions: None active]"

        lines = [f"[Sessions: {len(sessions)} active]"]

        for s in sessions:
            # Status indicator
            if s.capabilities.has_pty:
                status_emoji = "+"
            else:
                status_emoji = "-"

            # Shell type
            shell = s.shell_type or 'unknown'

            # Additional info
            info_parts = []
            if s.type in ['http', 'https']:
                info_parts.append('beacon')
            if s.capabilities.has_pty:
                info_parts.append('PTY')

            info_str = ', '.join(info_parts) if info_parts else 'basic'

            lines.append(
                f"  [{status_emoji}] {s.type}-{s.id[:6]}: "
                f"{s.target}:{s.port} ({shell}, {info_str})"
            )

        return "\n".join(lines)

    def get_session_count(self) -> Dict[str, int]:
        """
        Get session counts for target.

        Returns:
            Dictionary with session counts:
            {
                'total': 3,
                'active': 2,
                'dead': 1,
                'tcp': 1,
                'http': 1
            }
        """
        if not self.enabled:
            return {'total': 0, 'active': 0}

        target_ip = self.profile.target
        all_sessions = self.session_manager.list_sessions({'target': target_ip})

        counts = {
            'total': len(all_sessions),
            'active': 0,
            'dead': 0,
            'tcp': 0,
            'http': 0,
            'dns': 0,
            'icmp': 0
        }

        for s in all_sessions:
            if s.status == 'active':
                counts['active'] += 1
            elif s.status == 'dead':
                counts['dead'] += 1

            if s.type in counts:
                counts[s.type] += 1

        return counts

    def suggest_listeners(self) -> List[str]:
        """
        Suggest listener commands based on discovered ports.

        Analyzes open ports from profile and suggests appropriate listeners:
        - Port 80/443/8080/8443 -> HTTP beacon listener
        - Port 53 -> DNS tunnel (if authoritative domain available)
        - Any port -> TCP listener
        - ICMP allowed -> ICMP tunnel

        Returns:
            List of suggested listener commands

        Example:
            [
                "crack session start tcp --port 4444",
                "crack session start http --port 8080",
                "# Port 80 detected - consider HTTP beacon for firewall evasion"
            ]
        """
        if not self.enabled:
            return []

        suggestions = []
        open_ports = self._get_open_ports()

        # Analyze ports and suggest appropriate listeners
        has_web = any(p in [80, 443, 8080, 8443] for p in open_ports)
        has_dns = 53 in open_ports

        # Always suggest TCP listener
        suggestions.append("crack session start tcp --port 4444")

        # Suggest HTTP beacon if web ports open (firewall evasion)
        if has_web:
            suggestions.append("crack session start http --port 8080")
            suggestions.append("# Web ports detected - HTTP beacon for stealth")

        # Suggest DNS tunnel if DNS open
        if has_dns:
            suggestions.append("sudo crack session start dns --domain tunnel.evil.com")
            suggestions.append("# DNS detected - tunnel for restricted networks")

        # Always suggest ICMP as last resort
        suggestions.append("sudo crack session start icmp")
        suggestions.append("# ICMP tunnel for maximum stealth")

        return suggestions

    def get_listener_recommendations(self) -> Dict[str, Any]:
        """
        Get detailed listener recommendations based on target analysis.

        Returns:
            Dictionary with recommendations:
            {
                'primary': 'tcp',  # Most suitable listener
                'alternatives': ['http', 'dns'],
                'reasons': {
                    'tcp': 'Standard reverse shell',
                    'http': 'Web ports open (80, 443)',
                    'dns': 'DNS server detected'
                }
            }
        """
        if not self.enabled:
            return {'primary': 'tcp', 'alternatives': [], 'reasons': {}}

        open_ports = self._get_open_ports()

        recommendations = {
            'primary': 'tcp',
            'alternatives': [],
            'reasons': {}
        }

        # Default reason for TCP
        recommendations['reasons']['tcp'] = 'Standard reverse shell (always recommended)'

        # Check for web servers
        web_ports = [p for p in open_ports if p in [80, 443, 8080, 8443]]
        if web_ports:
            recommendations['alternatives'].append('http')
            recommendations['reasons']['http'] = \
                f"Web server detected on port(s) {', '.join(map(str, web_ports))} - " \
                f"HTTP beacon for firewall evasion"

            # If HTTPS, suggest it
            if 443 in web_ports or 8443 in web_ports:
                recommendations['alternatives'].append('https')
                recommendations['reasons']['https'] = \
                    "HTTPS for encrypted beacon traffic"

        # Check for DNS
        if 53 in open_ports:
            recommendations['alternatives'].append('dns')
            recommendations['reasons']['dns'] = \
                "DNS server detected - tunnel for restricted networks"

        # Always suggest ICMP as fallback
        recommendations['alternatives'].append('icmp')
        recommendations['reasons']['icmp'] = \
            "ICMP tunnel for maximum stealth (if ICMP allowed)"

        return recommendations

    def _get_open_ports(self) -> List[int]:
        """
        Extract open ports from target profile.

        Returns:
            List of open port numbers
        """
        open_ports = []

        # Parse from profile state
        if hasattr(self.profile, 'nmap_scan') and self.profile.nmap_scan:
            # Extract from nmap data
            for port_data in self.profile.nmap_scan.get('ports', []):
                if port_data.get('state') == 'open':
                    open_ports.append(port_data['port'])

        return open_ports

    def get_session_shortcut_menu(self) -> str:
        """
        Generate session management shortcut menu for Track interactive mode.

        Returns:
            Formatted menu string

        Example:
            Session Commands:
              s - View/manage sessions
              ls - Start listener
              us - Upgrade session
              ks - Kill session
        """
        if not self.enabled:
            return ""

        menu = [
            "Session Commands:",
            "  s  - View/manage sessions",
            "  ls - Start listener (wizard)",
            "  us - Upgrade session to PTY",
            "  ks - Kill session"
        ]

        return "\n".join(menu)

    def handle_session_shortcut(self) -> Optional[str]:
        """
        Handle 's' shortcut - view and manage sessions.

        Returns:
            Status message or None
        """
        if not self.enabled:
            return "[!] Session management not available"

        target_ip = self.profile.target
        sessions = self.session_manager.list_sessions({
            'target': target_ip
        })

        if not sessions:
            print("\n[!] No sessions for this target")
            print("\n[*] Start a listener:")

            suggestions = self.suggest_listeners()
            for i, cmd in enumerate(suggestions[:3], 1):  # Show top 3
                print(f"    {i}. {cmd}")

            return None

        # Display sessions
        print("\n=== Active Sessions ===")
        for i, s in enumerate(sessions, 1):
            status = "[+]" if s.status == 'active' else "[x]"
            pty = "PTY" if s.capabilities.has_pty else "basic"
            print(f"{i}. {status} {s.type}-{s.id[:8]}: {s.target}:{s.port} "
                  f"({s.shell_type or 'unknown'}, {pty})")

        # Session actions
        print("\nActions:")
        print("  [1-9] - View session details")
        print("  u<N>  - Upgrade session N to PTY")
        print("  k<N>  - Kill session N")
        print("  q     - Back to Track")

        choice = input("\nSelect action: ").strip()

        if choice == 'q':
            return None

        # Parse choice
        if choice.isdigit():
            idx = int(choice) - 1
            if 0 <= idx < len(sessions):
                self._display_session_details(sessions[idx])
        elif choice.startswith('u') and choice[1:].isdigit():
            idx = int(choice[1:]) - 1
            if 0 <= idx < len(sessions):
                return self._upgrade_session_interactive(sessions[idx])
        elif choice.startswith('k') and choice[1:].isdigit():
            idx = int(choice[1:]) - 1
            if 0 <= idx < len(sessions):
                return self._kill_session_interactive(sessions[idx])

        return None

    def handle_listener_shortcut(self) -> Optional[str]:
        """
        Handle 'ls' shortcut - start listener wizard.

        Returns:
            Status message or None
        """
        if not self.enabled:
            return "[!] Session management not available"

        print("\n=== Start Listener ===")
        print("\nAvailable listener types:")
        print("  1. TCP (standard reverse shell)")
        print("  2. HTTP/HTTPS (beacon for firewall evasion)")
        print("  3. DNS (tunnel for restricted networks)")
        print("  4. ICMP (tunnel for maximum stealth)")

        # Get recommendations
        recommendations = self.get_listener_recommendations()

        print(f"\n[*] Recommended: {recommendations['primary']}")
        if recommendations['alternatives']:
            print(f"[*] Alternatives: {', '.join(recommendations['alternatives'][:2])}")

        choice = input("\nSelect listener type [1-4] or 'q' to cancel: ").strip()

        if choice == 'q':
            return None

        type_map = {'1': 'tcp', '2': 'http', '3': 'dns', '4': 'icmp'}
        listener_type = type_map.get(choice)

        if not listener_type:
            return "[!] Invalid choice"

        # Generate command
        if listener_type == 'tcp':
            port = input("Listen port [4444]: ").strip() or "4444"
            cmd = f"crack session start tcp --port {port}"
        elif listener_type == 'http':
            port = input("Listen port [8080]: ").strip() or "8080"
            https = input("Use HTTPS? [y/N]: ").strip().lower() == 'y'
            if https:
                cmd = f"crack session start https --port {port}"
            else:
                cmd = f"crack session start http --port {port}"
        elif listener_type == 'dns':
            domain = input("Authoritative domain: ").strip()
            if not domain:
                return "[!] Domain required for DNS tunnel"
            cmd = f"sudo crack session start dns --domain {domain}"
        elif listener_type == 'icmp':
            cmd = "sudo crack session start icmp"
        else:
            return "[!] Invalid listener type"

        print(f"\n[*] Run this command in a new terminal:")
        print(f"    {cmd}")

        return f"[*] Listener command generated: {cmd}"

    def _display_session_details(self, session: Session):
        """Display detailed information about a session."""
        print(f"\n{'='*60}")
        print(f"Session ID: {session.id}")
        print(f"Type: {session.type} | Protocol: {session.protocol}")
        print(f"Target: {session.target}:{session.port}")
        print(f"Status: {session.status}")
        print(f"Shell: {session.shell_type or 'unknown'}")
        print(f"Created: {session.created_at.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Last Seen: {session.last_seen.strftime('%Y-%m-%d %H:%M:%S')}")

        print(f"\nCapabilities:")
        print(f"  PTY: {session.capabilities.has_pty}")
        print(f"  History: {session.capabilities.has_history}")
        print(f"  Tab Completion: {session.capabilities.has_tab_completion}")

        if session.capabilities.detected_tools:
            print(f"  Detected Tools: {', '.join(session.capabilities.detected_tools)}")

        print(f"{'='*60}")

    def _upgrade_session_interactive(self, session: Session) -> str:
        """Upgrade session interactively."""
        print(f"\n[+] Upgrading session {session.id[:8]}")

        # Check if already upgraded
        if session.capabilities.has_pty:
            return f"[!] Session already has PTY"

        # Show upgrade options
        print("\nUpgrade methods:")
        print("  1. Auto (recommended)")
        print("  2. Python")
        print("  3. Python3")
        print("  4. Script")

        choice = input("\nSelect method [1]: ").strip() or "1"

        method_map = {
            '1': 'auto',
            '2': 'python',
            '3': 'python3',
            '4': 'script'
        }

        method = method_map.get(choice, 'auto')

        # Execute upgrade command
        cmd = f"crack session upgrade {session.id[:8]} --method {method}"
        print(f"\n[*] Run in session terminal:")
        print(f"    {cmd}")

        return f"[*] Upgrade command generated"

    def _kill_session_interactive(self, session: Session) -> str:
        """Kill session interactively."""
        confirm = input(f"\n[!] Kill session {session.id[:8]}? [y/N]: ").strip().lower()

        if confirm != 'y':
            return "[*] Cancelled"

        if self.session_manager.kill_session(session.id):
            return f"[+] Session {session.id[:8]} terminated"
        else:
            return f"[!] Failed to kill session"


def add_session_shortcuts_to_track():
    """
    Add session management shortcuts to Track interactive mode.

    This function registers session shortcuts with Track's shortcut handler.
    Should be called during Track interactive mode initialization.
    """
    # This would integrate with track/interactive/shortcuts.py
    # For now, this is a placeholder showing the integration pattern

    session_shortcuts = {
        's': ('View/manage sessions', 'handle_sessions_shortcut'),
        'ls': ('Start listener', 'handle_listener_shortcut'),
        'us': ('Upgrade session', 'handle_upgrade_shortcut'),
        'ks': ('Kill session', 'handle_kill_shortcut')
    }

    return session_shortcuts
