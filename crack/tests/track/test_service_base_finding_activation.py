"""Tests for finding-based plugin activation"""

import pytest
from crack.track.services.base import ServicePlugin
from crack.track.core.constants import FindingTypes


class TestDetectFromFindingBaseClass:
    """Test base class detect_from_finding implementation"""

    def test_default_returns_zero(self):
        """Base class default implementation returns 0"""

        class MinimalPlugin(ServicePlugin):
            @property
            def name(self): return "test"
            def detect(self, port_info): return 0
            def get_task_tree(self, target, port, service_info): return {}

        plugin = MinimalPlugin()
        finding = {'type': 'shell_obtained', 'description': 'Got shell'}

        confidence = plugin.detect_from_finding(finding)
        assert confidence == 0, "Default should return 0 for opt-in behavior"

    def test_accepts_optional_profile(self):
        """Method accepts optional profile parameter"""
        from crack.track.core.state import TargetProfile

        class TestPlugin(ServicePlugin):
            @property
            def name(self): return "test"
            def detect(self, port_info): return 0
            def get_task_tree(self, target, port, service_info): return {}

        plugin = TestPlugin()
        finding = {'type': 'test', 'description': 'Test'}
        profile = TargetProfile('192.168.1.1')

        # Should not raise exception
        confidence = plugin.detect_from_finding(finding, profile)
        assert confidence == 0

    def test_signature_compatibility(self):
        """Verify method signature matches documentation"""
        import inspect

        sig = inspect.signature(ServicePlugin.detect_from_finding)
        params = list(sig.parameters.keys())

        assert 'finding' in params, "Must accept finding parameter"
        assert 'profile' in params, "Must accept profile parameter"
        # Check that profile has a default value (None is the default for optional params)
        assert sig.parameters['profile'].default is not inspect.Parameter.empty, "profile should be optional"

    def test_plugin_can_override(self):
        """Plugin can override with custom logic"""

        class CustomPlugin(ServicePlugin):
            @property
            def name(self): return "custom"
            def detect(self, port_info): return 0
            def get_task_tree(self, target, port, service_info): return {}

            def detect_from_finding(self, finding, profile=None):
                if finding.get('type') == 'shell_obtained':
                    return 100
                return 0

        plugin = CustomPlugin()

        # Should activate on shell_obtained
        finding = {'type': 'shell_obtained', 'description': 'Got shell'}
        assert plugin.detect_from_finding(finding) == 100

        # Should not activate on other finding
        finding = {'type': 'other', 'description': 'Other'}
        assert plugin.detect_from_finding(finding) == 0


class TestFindingTypesConstants:
    """Test FindingTypes constants exist and are usable"""

    def test_finding_types_exist(self):
        """All essential finding types are defined"""
        assert hasattr(FindingTypes, 'SHELL_OBTAINED')
        assert hasattr(FindingTypes, 'OS_LINUX')
        assert hasattr(FindingTypes, 'OS_WINDOWS')
        assert hasattr(FindingTypes, 'CMS_WORDPRESS')
        assert hasattr(FindingTypes, 'CREDENTIAL_FOUND')
        assert hasattr(FindingTypes, 'DOMAIN_JOINED')
        assert hasattr(FindingTypes, 'CONTAINER_DETECTED')

    def test_finding_types_are_strings(self):
        """Finding types are string constants"""
        assert isinstance(FindingTypes.SHELL_OBTAINED, str)
        assert isinstance(FindingTypes.OS_LINUX, str)
        assert isinstance(FindingTypes.CMS_WORDPRESS, str)

    def test_finding_types_lowercase_snake_case(self):
        """Finding types follow lowercase_snake_case convention"""
        assert FindingTypes.SHELL_OBTAINED == 'shell_obtained'
        assert FindingTypes.OS_LINUX == 'os_linux'
        assert FindingTypes.CMS_WORDPRESS == 'cms_wordpress'

    def test_shell_types_comprehensive(self):
        """All shell access types defined"""
        assert FindingTypes.SHELL_OBTAINED == 'shell_obtained'
        assert FindingTypes.LOW_PRIVILEGE_SHELL == 'low_privilege_shell'
        assert FindingTypes.HIGH_PRIVILEGE_SHELL == 'high_privilege_shell'
        assert FindingTypes.ROOT_SHELL == 'root_shell'
        assert FindingTypes.SYSTEM_SHELL == 'system_shell'
        assert FindingTypes.ADMIN_SHELL == 'admin_shell'

    def test_os_types_comprehensive(self):
        """All OS detection types defined"""
        assert FindingTypes.OS_DETECTED == 'os_detected'
        assert FindingTypes.OS_LINUX == 'os_linux'
        assert FindingTypes.OS_WINDOWS == 'os_windows'
        assert FindingTypes.OS_MACOS == 'os_macos'
        assert FindingTypes.OS_BSD == 'os_bsd'

    def test_cms_types_comprehensive(self):
        """All CMS detection types defined"""
        assert FindingTypes.CMS_DETECTED == 'cms_detected'
        assert FindingTypes.CMS_WORDPRESS == 'cms_wordpress'
        assert FindingTypes.CMS_JOOMLA == 'cms_joomla'
        assert FindingTypes.CMS_DRUPAL == 'cms_drupal'

    def test_vulnerability_types_comprehensive(self):
        """Common vulnerability types defined"""
        assert FindingTypes.VULNERABILITY_FOUND == 'vulnerability'
        assert FindingTypes.SQL_INJECTION == 'sql_injection'
        assert FindingTypes.XSS_FOUND == 'xss_found'
        assert FindingTypes.LFI_FOUND == 'lfi_found'
        assert FindingTypes.RFI_FOUND == 'rfi_found'

    def test_environment_types_comprehensive(self):
        """Environment detection types defined"""
        assert FindingTypes.CONTAINER_DETECTED == 'container_detected'
        assert FindingTypes.DOCKER_DETECTED == 'docker_detected'
        assert FindingTypes.KUBERNETES_DETECTED == 'kubernetes_detected'
        assert FindingTypes.DOMAIN_JOINED == 'domain_joined'
        assert FindingTypes.CLOUD_DETECTED == 'cloud_detected'

    def test_credential_types_comprehensive(self):
        """Credential finding types defined"""
        assert FindingTypes.CREDENTIAL_FOUND == 'credential_found'
        assert FindingTypes.SSH_CREDENTIAL == 'ssh_credential'
        assert FindingTypes.DATABASE_CREDENTIAL == 'database_credential'
        assert FindingTypes.API_KEY_FOUND == 'api_key_found'

    def test_active_directory_types_comprehensive(self):
        """Active Directory finding types defined"""
        assert FindingTypes.AD_DETECTED == 'ad_detected'
        assert FindingTypes.KERBEROASTABLE_USER == 'kerberoastable_user'
        assert FindingTypes.AS_REP_ROASTABLE == 'as_rep_roastable'
        assert FindingTypes.ADCS_DETECTED == 'adcs_detected'

    def test_finding_priority_levels(self):
        """FindingPriority levels defined"""
        from crack.track.core.constants import FindingPriority

        assert FindingPriority.CRITICAL == 'critical'
        assert FindingPriority.HIGH == 'high'
        assert FindingPriority.MEDIUM == 'medium'
        assert FindingPriority.LOW == 'low'
        assert FindingPriority.INFO == 'info'

    def test_no_duplicate_values(self):
        """Ensure no duplicate constant values"""
        values = []
        for attr in dir(FindingTypes):
            if not attr.startswith('_'):
                value = getattr(FindingTypes, attr)
                if isinstance(value, str):
                    values.append(value)

        # Check for duplicates
        assert len(values) == len(set(values)), "Found duplicate finding type values"

    def test_constants_immutable(self):
        """Constants should be strings (immutable)"""
        import inspect

        for name, value in inspect.getmembers(FindingTypes):
            if not name.startswith('_') and not inspect.ismethod(value):
                assert isinstance(value, str), f"{name} should be string constant"
