"""
Tests for Phase 5.3: Context-Aware Wordlist Selection

Tests prove that wordlist resolution adapts based on attack context:
- Web directory enumeration gets dirb/common.txt
- Password cracking gets rockyou.txt
- Service-specific (SSH, FTP) gets appropriate wordlists
- Fallback to config default when no context provided
"""

import pytest
from crack.track.alternatives.context import ContextResolver, WORDLIST_CONTEXT
from crack.track.core.state import TargetProfile
from crack.track.core.task_tree import TaskNode


class TestWordlistContextMapping:
    """Test that WORDLIST_CONTEXT mapping is properly defined"""

    def test_web_enumeration_context_exists(self):
        """PROVES: Web enumeration context has default, thorough, and quick wordlists"""
        assert 'web-enumeration' in WORDLIST_CONTEXT
        assert 'default' in WORDLIST_CONTEXT['web-enumeration']
        assert 'thorough' in WORDLIST_CONTEXT['web-enumeration']
        assert 'quick' in WORDLIST_CONTEXT['web-enumeration']

        # Verify paths
        assert '/usr/share/wordlists/dirb/common.txt' in WORDLIST_CONTEXT['web-enumeration']['default']

    def test_password_cracking_context_exists(self):
        """PROVES: Password cracking context has default and service-specific wordlists"""
        assert 'password-cracking' in WORDLIST_CONTEXT
        assert 'default' in WORDLIST_CONTEXT['password-cracking']
        assert 'ssh' in WORDLIST_CONTEXT['password-cracking']
        assert 'ftp' in WORDLIST_CONTEXT['password-cracking']
        assert 'http-auth' in WORDLIST_CONTEXT['password-cracking']

        # Verify default is rockyou
        assert 'rockyou.txt' in WORDLIST_CONTEXT['password-cracking']['default']

    def test_parameter_fuzzing_context_exists(self):
        """PROVES: Parameter fuzzing context exists with fuzzing wordlists"""
        assert 'parameter-fuzzing' in WORDLIST_CONTEXT
        assert 'default' in WORDLIST_CONTEXT['parameter-fuzzing']
        assert 'sqli' in WORDLIST_CONTEXT['parameter-fuzzing']
        assert 'xss' in WORDLIST_CONTEXT['parameter-fuzzing']


class TestWebEnumerationWordlistResolution:
    """Test web enumeration gets correct wordlists"""

    def test_web_enum_with_explicit_purpose(self, temp_crack_home):
        """PROVES: Explicit purpose='web-enumeration' returns web wordlist"""
        profile = TargetProfile('192.168.45.100')
        context = ContextResolver(profile=profile)

        context_hints = {'purpose': 'web-enumeration'}
        wordlist = context.resolve('WORDLIST', context_hints=context_hints)

        assert wordlist is not None
        assert '/usr/share/wordlists/dirb/common.txt' in wordlist

    def test_web_enum_with_thorough_variant(self, temp_crack_home):
        """PROVES: Web enum with variant='thorough' returns large wordlist"""
        profile = TargetProfile('192.168.45.100')
        context = ContextResolver(profile=profile)

        context_hints = {'purpose': 'web-enumeration', 'variant': 'thorough'}
        wordlist = context.resolve('WORDLIST', context_hints=context_hints)

        assert wordlist is not None
        assert 'directory-list' in wordlist
        assert 'medium' in wordlist

    def test_web_enum_with_quick_variant(self, temp_crack_home):
        """PROVES: Web enum with variant='quick' returns small wordlist"""
        profile = TargetProfile('192.168.45.100')
        context = ContextResolver(profile=profile)

        context_hints = {'purpose': 'web-enumeration', 'variant': 'quick'}
        wordlist = context.resolve('WORDLIST', context_hints=context_hints)

        assert wordlist is not None
        assert 'small.txt' in wordlist

    def test_gobuster_task_infers_web_enum_purpose(self, temp_crack_home):
        """PROVES: Task with 'gobuster' in ID automatically infers web-enumeration purpose"""
        profile = TargetProfile('192.168.45.100')
        task = TaskNode(task_id='gobuster-80', name='Directory Brute-force', task_type='command')
        task.metadata['service'] = 'http'
        task.metadata['port'] = 80

        context = ContextResolver(profile=profile, task=task)

        # No explicit context hints - should infer from task
        wordlist = context.resolve('WORDLIST')

        assert wordlist is not None
        assert '/usr/share/wordlists/dirb/common.txt' in wordlist

    def test_http_service_task_infers_web_enum(self, temp_crack_home):
        """PROVES: HTTP service task infers web-enumeration purpose"""
        profile = TargetProfile('192.168.45.100')
        task = TaskNode(task_id='http-enum-80', name='HTTP Enumeration', task_type='command')
        task.metadata['service'] = 'http'
        task.metadata['port'] = 80

        context = ContextResolver(profile=profile, task=task)

        wordlist = context.resolve('WORDLIST')

        assert wordlist is not None
        assert 'dirb' in wordlist or 'common.txt' in wordlist


class TestPasswordCrackingWordlistResolution:
    """Test password cracking gets correct wordlists"""

    def test_password_cracking_default_wordlist(self, temp_crack_home):
        """PROVES: Password cracking with no service gets rockyou.txt"""
        profile = TargetProfile('192.168.45.100')
        context = ContextResolver(profile=profile)

        context_hints = {'purpose': 'password-cracking'}
        wordlist = context.resolve('WORDLIST', context_hints=context_hints)

        assert wordlist is not None
        assert 'rockyou.txt' in wordlist

    def test_hydra_task_infers_password_cracking(self, temp_crack_home):
        """PROVES: Task with 'hydra' in ID infers password-cracking purpose"""
        profile = TargetProfile('192.168.45.100')
        task = TaskNode(task_id='hydra-ssh-22', name='SSH Brute Force', task_type='command')
        task.metadata['service'] = 'ssh'
        task.metadata['port'] = 22

        context = ContextResolver(profile=profile, task=task)

        wordlist = context.resolve('WORDLIST')

        assert wordlist is not None
        assert 'rockyou.txt' in wordlist or 'ssh-passwords.txt' in wordlist


class TestServiceSpecificWordlistResolution:
    """Test service-specific wordlists"""

    def test_ssh_service_gets_ssh_wordlist(self, temp_crack_home):
        """PROVES: SSH password cracking gets SSH-specific wordlist"""
        profile = TargetProfile('192.168.45.100')
        context = ContextResolver(profile=profile)

        context_hints = {'purpose': 'password-cracking', 'service': 'ssh'}
        wordlist = context.resolve('WORDLIST', context_hints=context_hints)

        assert wordlist is not None
        assert 'ssh-passwords.txt' in wordlist

    def test_ftp_service_gets_ftp_wordlist(self, temp_crack_home):
        """PROVES: FTP password cracking gets FTP-specific wordlist"""
        profile = TargetProfile('192.168.45.100')
        context = ContextResolver(profile=profile)

        context_hints = {'purpose': 'password-cracking', 'service': 'ftp'}
        wordlist = context.resolve('WORDLIST', context_hints=context_hints)

        assert wordlist is not None
        assert 'ftp' in wordlist.lower()

    def test_http_auth_gets_http_wordlist(self, temp_crack_home):
        """PROVES: HTTP auth brute force gets HTTP-specific wordlist"""
        profile = TargetProfile('192.168.45.100')
        context = ContextResolver(profile=profile)

        context_hints = {'purpose': 'password-cracking', 'service': 'http-auth'}
        wordlist = context.resolve('WORDLIST', context_hints=context_hints)

        assert wordlist is not None
        assert 'http' in wordlist.lower()

    def test_ssh_service_in_task_metadata_infers_password_cracking(self, temp_crack_home):
        """PROVES: SSH service in task metadata infers password-cracking context"""
        profile = TargetProfile('192.168.45.100')
        task = TaskNode(task_id='ssh-enum-22', name='SSH Enumeration', task_type='command')
        task.metadata['service'] = 'ssh'
        task.metadata['port'] = 22

        context = ContextResolver(profile=profile, task=task)

        wordlist = context.resolve('WORDLIST')

        assert wordlist is not None
        # Should get password wordlist, not web wordlist
        assert 'dirb' not in wordlist
        assert 'rockyou' in wordlist or 'password' in wordlist.lower()


class TestConfigFallbackWordlist:
    """Test fallback to config default"""

    def test_no_context_falls_back_to_config(self, temp_crack_home, mock_config):
        """PROVES: No context hints falls back to config WORDLIST variable"""
        profile = TargetProfile('192.168.45.100')

        # Create mock config with WORDLIST
        mock_config.config['variables']['WORDLIST']['value'] = '/custom/wordlist.txt'

        context = ContextResolver(profile=profile, config=mock_config)

        # No context hints
        wordlist = context.resolve('WORDLIST')

        assert wordlist == '/custom/wordlist.txt'

    def test_unknown_purpose_falls_back_to_config(self, temp_crack_home, mock_config):
        """PROVES: Unknown purpose falls back to config"""
        profile = TargetProfile('192.168.45.100')

        mock_config.config['variables']['WORDLIST']['value'] = '/default/wordlist.txt'

        context = ContextResolver(profile=profile, config=mock_config)

        # Unknown purpose
        context_hints = {'purpose': 'unknown-purpose'}
        wordlist = context.resolve('WORDLIST', context_hints=context_hints)

        assert wordlist == '/default/wordlist.txt'

    def test_no_config_returns_none(self, temp_crack_home):
        """PROVES: No config and no context returns None (will prompt user)"""
        profile = TargetProfile('192.168.45.100')

        # No config provided, disable auto-loading
        context = ContextResolver(profile=profile, config=None, auto_load_config=False)

        # No context hints
        wordlist = context.resolve('WORDLIST')

        assert wordlist is None


class TestTaskMetadataWordlistOverride:
    """Test that task metadata wordlist overrides context"""

    def test_task_wordlist_overrides_context(self, temp_crack_home):
        """PROVES: Explicit wordlist in task metadata overrides context mapping"""
        profile = TargetProfile('192.168.45.100')
        task = TaskNode(task_id='gobuster-80', name='Gobuster', task_type='command')
        task.metadata['service'] = 'http'
        task.metadata['port'] = 80
        task.metadata['wordlist'] = '/custom/task/wordlist.txt'

        context = ContextResolver(profile=profile, task=task)

        # Even with web-enumeration context, should use task wordlist
        context_hints = {'purpose': 'web-enumeration'}
        wordlist = context.resolve('WORDLIST', context_hints=context_hints)

        assert wordlist == '/custom/task/wordlist.txt'


class TestAlternativeContextPurpose:
    """Test alternative_context metadata field"""

    def test_alternative_context_purpose_used(self, temp_crack_home):
        """PROVES: Task's alternative_context['purpose'] is used for inference"""
        profile = TargetProfile('192.168.45.100')
        task = TaskNode(task_id='custom-task', name='Custom Task', task_type='command')
        task.metadata['alternative_context'] = {
            'purpose': 'parameter-fuzzing'
        }

        context = ContextResolver(profile=profile, task=task)

        wordlist = context.resolve('WORDLIST')

        assert wordlist is not None
        assert 'parameter' in wordlist.lower() or 'burp' in wordlist

    def test_alternative_context_with_service(self, temp_crack_home):
        """PROVES: alternative_context with service and purpose works correctly"""
        profile = TargetProfile('192.168.45.100')
        task = TaskNode(task_id='custom-brute', name='Brute Force', task_type='command')
        task.metadata['alternative_context'] = {
            'purpose': 'password-cracking',
            'service': 'ssh'
        }

        context = ContextResolver(profile=profile, task=task, auto_load_config=False)

        # Pass context hints that include service from alternative_context
        context_hints = task.metadata['alternative_context']
        wordlist = context.resolve('WORDLIST', context_hints=context_hints)

        assert wordlist is not None
        assert 'ssh' in wordlist.lower()


class TestResolutionSourceTracking:
    """Test get_resolution_source for debugging"""

    def test_context_source_for_wordlist(self, temp_crack_home):
        """PROVES: Resolution source is 'context' when using context mapping"""
        profile = TargetProfile('192.168.45.100')
        context = ContextResolver(profile=profile)

        context_hints = {'purpose': 'web-enumeration'}

        # Resolve first
        wordlist = context.resolve('WORDLIST', context_hints=context_hints)
        assert wordlist is not None

        # Check source
        source = context.get_resolution_source('WORDLIST', context_hints=context_hints)
        assert source == 'context'

    def test_config_source_for_wordlist_fallback(self, temp_crack_home, mock_config):
        """PROVES: Resolution source is 'config' when falling back to config"""
        profile = TargetProfile('192.168.45.100')
        mock_config.config['variables']['WORDLIST']['value'] = '/custom/wordlist.txt'

        context = ContextResolver(profile=profile, config=mock_config)

        # No context hints
        wordlist = context.resolve('WORDLIST')
        assert wordlist == '/custom/wordlist.txt'

        # Check source
        source = context.get_resolution_source('WORDLIST')
        assert source == 'config'


class TestEndToEndWordlistWorkflow:
    """End-to-end workflow tests"""

    def test_gobuster_alternative_gets_web_wordlist(self, temp_crack_home):
        """
        PROVES: Complete workflow - gobuster task automatically gets web wordlist

        Workflow:
        1. Create profile with HTTP service
        2. Create gobuster task
        3. Resolve WORDLIST without explicit hints
        4. Should automatically infer web-enumeration and return dirb wordlist
        """
        # Step 1: Create profile
        profile = TargetProfile('192.168.45.100')
        profile.ports[80] = {
            'state': 'open',
            'service': 'http',
            'version': 'Apache 2.4.41'
        }

        # Step 2: Create gobuster task
        task = TaskNode(
            task_id='gobuster-dir-80',
            name='Directory Brute-force (Port 80)',
            task_type='command'
        )
        task.metadata['service'] = 'http'
        task.metadata['port'] = 80
        task.metadata['command'] = 'gobuster dir -u http://192.168.45.100:80 -w <WORDLIST>'

        # Step 3: Create context resolver
        context = ContextResolver(profile=profile, task=task)

        # Step 4: Resolve WORDLIST (no explicit hints - should infer)
        wordlist = context.resolve('WORDLIST')

        # Step 5: Verify
        assert wordlist is not None
        assert '/usr/share/wordlists/dirb/common.txt' in wordlist
        assert 'rockyou' not in wordlist  # Should NOT get password list

    def test_hydra_ssh_alternative_gets_password_wordlist(self, temp_crack_home):
        """
        PROVES: SSH hydra task automatically gets password wordlist

        Workflow:
        1. Create profile with SSH service
        2. Create hydra task
        3. Resolve WORDLIST
        4. Should get password wordlist, not web wordlist
        """
        # Step 1: Profile with SSH
        profile = TargetProfile('192.168.45.100')
        profile.ports[22] = {
            'state': 'open',
            'service': 'ssh',
            'version': 'OpenSSH 8.2p1'
        }

        # Step 2: Hydra SSH task
        task = TaskNode(
            task_id='hydra-ssh-22',
            name='SSH Password Brute Force',
            task_type='command'
        )
        task.metadata['service'] = 'ssh'
        task.metadata['port'] = 22
        task.metadata['command'] = 'hydra -L users.txt -P <WORDLIST> ssh://192.168.45.100'

        # Step 3: Context resolver
        context = ContextResolver(profile=profile, task=task)

        # Step 4: Resolve
        wordlist = context.resolve('WORDLIST')

        # Step 5: Verify
        assert wordlist is not None
        assert 'dirb' not in wordlist  # Should NOT get web wordlist
        assert 'rockyou' in wordlist or 'password' in wordlist.lower()

    def test_get_all_resolvable_includes_wordlist(self, temp_crack_home):
        """
        PROVES: get_all_resolvable() includes WORDLIST with context hints

        Workflow:
        1. Create context with task
        2. Call get_all_resolvable with context hints
        3. WORDLIST should be in resolvable dict
        """
        profile = TargetProfile('192.168.45.100')
        task = TaskNode(task_id='gobuster-80', name='Gobuster', task_type='command')
        task.metadata['service'] = 'http'
        task.metadata['port'] = 80

        context = ContextResolver(profile=profile, task=task)

        # Get all resolvable with context hints
        context_hints = {'purpose': 'web-enumeration'}
        resolvable = context.get_all_resolvable(context_hints=context_hints)

        assert 'WORDLIST' in resolvable
        assert '/usr/share/wordlists/dirb/common.txt' in resolvable['WORDLIST']
