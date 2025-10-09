"""
Context resolution for variable auto-filling

Resolves variable values from execution context in priority order:
1. Task metadata (port, service from current task)
2. Profile state (target IP, discovered services)
3. Config (LHOST, LPORT, wordlists from ~/.crack/config.json)
4. None (will prompt user)
"""

from typing import Optional, Dict, Any

try:
    from ...reference.core.config import ConfigManager
except ImportError:
    # Fallback if config module not available
    ConfigManager = None

try:
    from ..wordlists.manager import WordlistManager
except ImportError:
    # Fallback if wordlist module not available (Phase 1 not complete)
    WordlistManager = None


# Context-aware wordlist mappings for different attack scenarios
# NOTE: Paths verified for Kali Linux 2024+ system paths
WORDLIST_CONTEXT = {
    'web-enumeration': {
        'default': '/usr/share/wordlists/dirb/common.txt',
        'thorough': '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt',
        'quick': '/usr/share/wordlists/dirb/small.txt'
    },
    'password-cracking': {
        'default': '/usr/share/wordlists/rockyou.txt',
        'ssh': '/usr/share/seclists/Passwords/Default-Credentials/ssh-betterdefaultpasslist.txt',
        'ftp': '/usr/share/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt',
        'http-auth': '/usr/share/seclists/Passwords/Default-Credentials/http-betterdefaultpasslist.txt'
    },
    'parameter-fuzzing': {
        'default': '/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt',
        'sqli': '/usr/share/seclists/Fuzzing/SQLi/Generic-SQLi.txt',
        'xss': '/usr/share/seclists/Fuzzing/XSS-Fuzzing.txt'
    },
    'subdomain-enum': {
        'default': '/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt',
        'thorough': '/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt'
    },
    'vhost-enum': {
        'default': '/usr/share/seclists/Discovery/DNS/namelist.txt'
    }
}


class ContextResolver:
    """Resolve variables from execution context"""

    def __init__(self, profile=None, task=None, config=None, auto_load_config=True):
        """
        Initialize context resolver

        Args:
            profile: TargetProfile instance (optional)
            task: TaskNode instance (optional)
            config: ConfigManager instance, path to config, or None (optional)
            auto_load_config: Whether to auto-load config if not provided (default True)
        """
        self.profile = profile
        self.task = task

        # Handle config loading
        if config is None and auto_load_config and ConfigManager is not None:
            # Try to load default config
            try:
                self.config = ConfigManager()
            except Exception:
                # Config doesn't exist or can't be loaded - graceful fallback
                self.config = None
        elif isinstance(config, str):
            # Config path provided
            try:
                self.config = ConfigManager(config_path=config)
            except Exception:
                self.config = None
        else:
            # ConfigManager instance provided or explicit None
            self.config = config

    def resolve(self, variable_name: str, context_hints: Optional[Dict[str, Any]] = None) -> Optional[str]:
        """
        Auto-resolve variable from context with context awareness

        Args:
            variable_name: Variable name (without angle brackets)
            context_hints: Additional hints like {'purpose': 'web-enumeration', 'service': 'ssh'}

        Returns:
            Resolved value or None if not found in context
        """
        # Normalize variable name (remove <> if present)
        var_name = variable_name.strip('<>')

        # Special handling for WORDLIST - context-aware selection
        if var_name == 'WORDLIST':
            wordlist = self._resolve_wordlist(context_hints or {})
            if wordlist:
                return wordlist

        # Priority 1: Task metadata (port, service, etc.)
        if self.task:
            task_value = self._resolve_from_task(var_name)
            if task_value is not None:
                return task_value

        # Priority 2: Profile state (target, discovered services)
        if self.profile:
            profile_value = self._resolve_from_profile(var_name)
            if profile_value is not None:
                return profile_value

        # Priority 3: Config (LHOST, LPORT, wordlists)
        if self.config:
            config_value = self._resolve_from_config(var_name)
            if config_value is not None:
                return config_value

        # Not found - will need to prompt user
        return None

    def _resolve_wordlist(self, context_hints: Dict[str, Any]) -> Optional[str]:
        """
        Resolve WORDLIST with context awareness

        Enhanced with dynamic wordlist discovery via WordlistManager.
        Falls back to static WORDLIST_CONTEXT if manager unavailable.

        Context hints determine which wordlist to use:
        - purpose: 'web-enumeration', 'password-cracking', 'parameter-fuzzing', etc.
        - service: 'ssh', 'ftp', 'http-auth' (for password cracking)
        - variant: 'default', 'thorough', 'quick' (for web enum)

        Resolution priority:
        1. Task metadata (explicit wordlist)
        2. Dynamic manager suggestions (if available)
        3. Static context mapping (fallback)
        4. Config WORDLIST variable

        Args:
            context_hints: Dictionary with 'purpose', 'service', 'variant' keys

        Returns:
            Wordlist path or None
        """
        purpose = context_hints.get('purpose')
        service = context_hints.get('service')
        variant = context_hints.get('variant', 'default')

        # Priority 1: Check for explicit wordlist in task metadata
        if self.task and hasattr(self.task, 'metadata'):
            task_wordlist = self.task.metadata.get('wordlist')
            if task_wordlist:
                return task_wordlist

        # Priority 2: Static context mapping with service-specific support
        # Check this BEFORE dynamic resolution to ensure service-specific wordlists are respected
        if purpose and purpose in WORDLIST_CONTEXT:
            context_map = WORDLIST_CONTEXT[purpose]

            # For password-cracking, check service-specific wordlist first
            if purpose == 'password-cracking' and service:
                service_wordlist = context_map.get(service)
                if service_wordlist:
                    return service_wordlist

            # Otherwise use variant (default, thorough, quick)
            wordlist = context_map.get(variant)
            if wordlist:
                return wordlist

        # Priority 3: Try dynamic suggestions from WordlistManager
        # Only use dynamic resolution if static mapping didn't find anything
        if WordlistManager is not None:
            dynamic_wordlist = self._resolve_wordlist_dynamic(purpose, service, variant)
            if dynamic_wordlist:
                return dynamic_wordlist

        # Infer purpose from task metadata if not provided
        if not purpose and self.task and hasattr(self.task, 'metadata'):
            inferred_purpose = self._infer_purpose_from_task()
            if inferred_purpose:
                # Try static mapping first (service-specific support)
                if inferred_purpose in WORDLIST_CONTEXT:
                    context_map = WORDLIST_CONTEXT[inferred_purpose]

                    # If service in context hints and purpose is password-cracking, use service-specific
                    if inferred_purpose == 'password-cracking' and service:
                        service_wordlist = context_map.get(service)
                        if service_wordlist:
                            return service_wordlist

                    wordlist = context_map.get(variant, context_map.get('default'))
                    if wordlist:
                        return wordlist

                # Fallback to dynamic resolution with inferred purpose
                if WordlistManager is not None:
                    dynamic_wordlist = self._resolve_wordlist_dynamic(inferred_purpose, service, variant)
                    if dynamic_wordlist:
                        return dynamic_wordlist

        # Priority 4: Fallback to config WORDLIST variable
        if self.config:
            config_wordlist = self._resolve_from_config('WORDLIST')
            if config_wordlist:
                return config_wordlist

        return None

    def _resolve_wordlist_dynamic(self, purpose: Optional[str], service: Optional[str], variant: str) -> Optional[str]:
        """
        Resolve wordlist dynamically using WordlistManager

        Queries discovered wordlists by category and selects best match.

        Args:
            purpose: Attack purpose ('web-enumeration', 'password-cracking', etc.)
            service: Service type ('ssh', 'ftp', 'http-auth')
            variant: Variant ('default', 'thorough', 'quick')

        Returns:
            Wordlist path or None
        """
        if not purpose:
            return None

        try:
            # Initialize manager with default paths
            manager = WordlistManager()

            # Map purpose to category
            category_map = {
                'web-enumeration': 'web',
                'password-cracking': 'passwords',
                'parameter-fuzzing': 'web',  # Parameter fuzzing uses web wordlists
                'subdomain-enum': 'subdomains',
                'vhost-enum': 'subdomains',
                'username-enum': 'usernames'
            }

            category = category_map.get(purpose)
            if not category:
                return None

            # Get wordlists for category
            wordlists = manager.get_by_category(category)
            if not wordlists:
                return None

            # Select wordlist based on variant and service
            selected = self._select_best_wordlist(wordlists, purpose, service, variant)
            return selected.path if selected else None

        except Exception:
            # Graceful degradation - manager not available or error occurred
            return None

    def _select_best_wordlist(self, wordlists, purpose: str, service: Optional[str], variant: str):
        """
        Select best wordlist from available options

        Selection criteria:
        - Service-specific first (for password cracking)
        - Variant preference (quick < default < thorough)
        - Common patterns (common.txt, rockyou.txt, etc.)

        Args:
            wordlists: List of WordlistEntry objects
            purpose: Attack purpose
            service: Service type (optional)
            variant: Size variant

        Returns:
            WordlistEntry or None
        """
        if not wordlists:
            return None

        # For password cracking, check service-specific wordlists
        if purpose == 'password-cracking' and service:
            service_patterns = {
                'ssh': ['ssh', 'unix'],
                'ftp': ['ftp'],
                'http-auth': ['http', 'web']
            }
            patterns = service_patterns.get(service, [])
            for pattern in patterns:
                for wl in wordlists:
                    if pattern in wl.name.lower() or pattern in wl.path.lower():
                        return wl

        # Variant-based selection
        if variant == 'quick':
            # Prefer small wordlists (small.txt, top1000, etc.)
            quick_patterns = ['small', 'short', 'quick', 'top1000', 'top100']
            for pattern in quick_patterns:
                for wl in wordlists:
                    if pattern in wl.name.lower():
                        return wl
            # Fallback: smallest file
            return min(wordlists, key=lambda w: w.line_count)

        elif variant == 'thorough':
            # Prefer large wordlists (big, large, all, etc.)
            thorough_patterns = ['big', 'large', 'all', 'complete', 'directory-list', 'top1million']
            for pattern in thorough_patterns:
                for wl in wordlists:
                    if pattern in wl.name.lower():
                        return wl
            # Fallback: largest file
            return max(wordlists, key=lambda w: w.line_count)

        else:  # variant == 'default'
            # Prefer common default wordlists
            default_patterns = {
                'web': ['common.txt', 'common', 'medium'],
                'passwords': ['rockyou', 'common-passwords'],
                'subdomains': ['subdomains-top', 'namelist'],
                'usernames': ['common-user', 'names']
            }

            category = wordlists[0].category if wordlists else 'general'
            patterns = default_patterns.get(category, ['common'])

            for pattern in patterns:
                for wl in wordlists:
                    if pattern in wl.name.lower():
                        return wl

            # Fallback: first wordlist
            return wordlists[0]

    def _infer_purpose_from_task(self) -> Optional[str]:
        """
        Infer attack purpose from task metadata

        Returns:
            Purpose string ('web-enumeration', 'password-cracking', etc.) or None
        """
        if not self.task or not hasattr(self.task, 'metadata'):
            return None

        metadata = self.task.metadata
        task_id = self.task.task_id if hasattr(self.task, 'task_id') else ''

        # Check task ID patterns
        if any(tool in task_id.lower() for tool in ['gobuster', 'dirb', 'dirbuster', 'ffuf']):
            return 'web-enumeration'

        if any(tool in task_id.lower() for tool in ['hydra', 'medusa', 'ncrack']):
            return 'password-cracking'

        # Check service type
        service = metadata.get('service', '').lower()
        if service in ['http', 'https']:
            # Could be web-enumeration or http-auth password cracking
            # Default to web-enumeration unless explicitly password attack
            if 'brute' in task_id.lower() or 'password' in task_id.lower():
                return 'password-cracking'
            return 'web-enumeration'

        if service in ['ssh', 'ftp', 'smb']:
            # These are typically password cracking targets
            return 'password-cracking'

        # Check alternative_context if present
        alt_context = metadata.get('alternative_context', {})
        if 'purpose' in alt_context:
            return alt_context['purpose']

        return None

    def _resolve_from_task(self, var_name: str) -> Optional[str]:
        """Resolve from task metadata"""
        if not self.task or not hasattr(self.task, 'metadata'):
            return None

        metadata = self.task.metadata

        # Common task-level variables
        if var_name == 'PORT':
            port = metadata.get('port')
            return str(port) if port is not None else None

        if var_name == 'SERVICE':
            return metadata.get('service')

        if var_name == 'VERSION':
            return metadata.get('version')

        # Check metadata directly for any other variables
        if var_name.lower() in metadata:
            value = metadata[var_name.lower()]
            return str(value) if value is not None else None

        return None

    def _resolve_from_profile(self, var_name: str) -> Optional[str]:
        """Resolve from profile state"""
        if not self.profile:
            return None

        # Target IP/hostname
        if var_name in ['TARGET', 'TARGET_IP', 'TARGET_HOST']:
            return self.profile.target

        # Phase
        if var_name == 'PHASE':
            return self.profile.phase

        # Common port (if only one port discovered)
        if var_name == 'PORT' and len(self.profile.ports) == 1:
            return str(list(self.profile.ports.keys())[0])

        # Try to get from profile metadata
        if hasattr(self.profile, 'metadata') and var_name in self.profile.metadata:
            value = self.profile.metadata[var_name]
            return str(value) if value is not None else None

        return None

    def _resolve_from_config(self, var_name: str) -> Optional[str]:
        """
        Resolve from config (~/.crack/config.json)

        Supports ConfigManager interface with get_variable() method
        and fallback to direct dictionary access
        """
        if not self.config:
            return None

        # Priority 1: Use ConfigManager.get_variable() if available (cleaner API)
        if hasattr(self.config, 'get_variable'):
            try:
                value = self.config.get_variable(var_name)
                if value:  # get_variable returns empty string if not found
                    return value
            except Exception:
                pass

        # Priority 2: Try to get from config.config['variables']
        if hasattr(self.config, 'config'):
            config_dict = self.config.config
            if 'variables' in config_dict and var_name in config_dict['variables']:
                var_config = config_dict['variables'][var_name]
                if isinstance(var_config, dict):
                    return var_config.get('value')
                return str(var_config) if var_config else None

        # Priority 3: Direct attribute access (backward compatibility)
        if hasattr(self.config, 'variables') and var_name in self.config.variables:
            var_config = self.config.variables[var_name]
            if isinstance(var_config, dict):
                return var_config.get('value')
            return str(var_config) if var_config else None

        return None

    def get_resolution_source(self, variable_name: str, context_hints: Optional[Dict[str, Any]] = None) -> Optional[str]:
        """
        Get the source of resolution for debugging

        Args:
            variable_name: Variable name
            context_hints: Optional context hints for resolution

        Returns:
            Source name ('task', 'profile', 'config', 'context') or None
        """
        var_name = variable_name.strip('<>')

        # Special case for WORDLIST with context
        if var_name == 'WORDLIST' and context_hints:
            wordlist = self._resolve_wordlist(context_hints)
            if wordlist:
                # Check if it came from context mapping vs config
                purpose = context_hints.get('purpose')
                if purpose and purpose in WORDLIST_CONTEXT:
                    return 'context'

        if self.task and self._resolve_from_task(var_name) is not None:
            return 'task'

        if self.profile and self._resolve_from_profile(var_name) is not None:
            return 'profile'

        if self.config and self._resolve_from_config(var_name) is not None:
            return 'config'

        return None

    def get_all_resolvable(self, context_hints: Optional[Dict[str, Any]] = None) -> Dict[str, str]:
        """
        Get all variables that can be resolved from context

        Args:
            context_hints: Optional context hints for resolution

        Returns:
            Dictionary of {variable_name: value} for all resolvable variables
        """
        resolvable = {}

        # Common variables to check
        common_vars = [
            'TARGET', 'TARGET_IP', 'TARGET_HOST',
            'PORT', 'SERVICE', 'VERSION',
            'LHOST', 'LPORT',
            'WORDLIST', 'THREADS', 'INTERFACE',
            'PHASE'
        ]

        for var in common_vars:
            value = self.resolve(var, context_hints=context_hints)
            if value is not None:
                resolvable[var] = value

        return resolvable
