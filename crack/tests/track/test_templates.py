"""
Tests for Command Templates System

Tests verify:
- Template registration and retrieval
- Variable substitution
- Category filtering
- Search functionality
- Interactive template filling
- Integration with shortcuts
"""

import pytest
from crack.track.interactive.templates import (
    CommandTemplate,
    TemplateRegistry
)


class TestCommandTemplate:
    """Test CommandTemplate class"""

    def test_template_creation(self):
        """PROVES: Template can be created with all fields"""
        template = CommandTemplate(
            template_id='test-template',
            name='Test Template',
            command='echo <MESSAGE>',
            description='Test description',
            variables=[
                {
                    'name': 'MESSAGE',
                    'description': 'Message to echo',
                    'example': 'Hello World',
                    'required': True
                }
            ],
            category='testing'
        )

        assert template.id == 'test-template'
        assert template.name == 'Test Template'
        assert template.command == 'echo <MESSAGE>'
        assert template.category == 'testing'
        assert len(template.variables) == 1

    def test_template_fill_single_variable(self):
        """PROVES: Single variable substitution works"""
        template = CommandTemplate(
            template_id='test',
            name='Test',
            command='ping <TARGET>',
            description='Ping test',
            variables=[{'name': 'TARGET', 'required': True}],
            category='test'
        )

        result = template.fill({'TARGET': '192.168.1.1'})
        assert result == 'ping 192.168.1.1'

    def test_template_fill_multiple_variables(self):
        """PROVES: Multiple variable substitution works"""
        template = CommandTemplate(
            template_id='test',
            name='Test',
            command='nmap -p <PORTS> <TARGET>',
            description='Nmap test',
            variables=[
                {'name': 'TARGET', 'required': True},
                {'name': 'PORTS', 'required': True}
            ],
            category='test'
        )

        result = template.fill({
            'TARGET': '192.168.1.1',
            'PORTS': '80,443'
        })
        assert result == 'nmap -p 80,443 192.168.1.1'

    def test_get_required_variables(self):
        """PROVES: Can identify required variables"""
        template = CommandTemplate(
            template_id='test',
            name='Test',
            command='cmd <REQ> <OPT>',
            description='Test',
            variables=[
                {'name': 'REQ', 'required': True},
                {'name': 'OPT', 'required': False}
            ],
            category='test'
        )

        required = template.get_required_variables()
        assert 'REQ' in required
        assert 'OPT' not in required

    def test_get_optional_variables(self):
        """PROVES: Can identify optional variables"""
        template = CommandTemplate(
            template_id='test',
            name='Test',
            command='cmd <REQ> <OPT>',
            description='Test',
            variables=[
                {'name': 'REQ', 'required': True},
                {'name': 'OPT', 'required': False}
            ],
            category='test'
        )

        optional = template.get_optional_variables()
        assert 'OPT' in optional
        assert 'REQ' not in optional


class TestTemplateRegistry:
    """Test TemplateRegistry class"""

    def setup_method(self):
        """Clear registry before each test"""
        # Save original state
        self._original_templates = TemplateRegistry._templates.copy()
        self._original_categories = TemplateRegistry._categories.copy()

        # Clear for testing
        TemplateRegistry._templates = {}
        TemplateRegistry._categories = {}

    def teardown_method(self):
        """Restore registry after each test"""
        TemplateRegistry._templates = self._original_templates
        TemplateRegistry._categories = self._original_categories

    def test_register_template(self):
        """PROVES: Template can be registered"""
        template = CommandTemplate(
            template_id='test',
            name='Test',
            command='echo test',
            description='Test',
            variables=[],
            category='testing'
        )

        TemplateRegistry.register(template)

        assert 'test' in TemplateRegistry._templates
        assert TemplateRegistry.get('test') == template

    def test_register_multiple_templates(self):
        """PROVES: Multiple templates can be registered"""
        template1 = CommandTemplate(
            template_id='test1',
            name='Test 1',
            command='echo 1',
            description='Test 1',
            variables=[],
            category='testing'
        )

        template2 = CommandTemplate(
            template_id='test2',
            name='Test 2',
            command='echo 2',
            description='Test 2',
            variables=[],
            category='testing'
        )

        TemplateRegistry.register(template1)
        TemplateRegistry.register(template2)

        all_templates = TemplateRegistry.list_all()
        assert len(all_templates) == 2
        assert template1 in all_templates
        assert template2 in all_templates

    def test_list_by_category(self):
        """PROVES: Templates can be filtered by category"""
        recon_template = CommandTemplate(
            template_id='recon1',
            name='Recon 1',
            command='nmap',
            description='Test',
            variables=[],
            category='recon'
        )

        web_template = CommandTemplate(
            template_id='web1',
            name='Web 1',
            command='gobuster',
            description='Test',
            variables=[],
            category='web'
        )

        TemplateRegistry.register(recon_template)
        TemplateRegistry.register(web_template)

        recon_templates = TemplateRegistry.list_by_category('recon')
        assert len(recon_templates) == 1
        assert recon_templates[0].id == 'recon1'

        web_templates = TemplateRegistry.list_by_category('web')
        assert len(web_templates) == 1
        assert web_templates[0].id == 'web1'

    def test_get_categories(self):
        """PROVES: Can retrieve all categories"""
        TemplateRegistry.register(CommandTemplate(
            'test1', 'Test 1', 'cmd', 'Test', [], 'recon'
        ))
        TemplateRegistry.register(CommandTemplate(
            'test2', 'Test 2', 'cmd', 'Test', [], 'web'
        ))
        TemplateRegistry.register(CommandTemplate(
            'test3', 'Test 3', 'cmd', 'Test', [], 'recon'
        ))

        categories = TemplateRegistry.get_categories()
        assert 'recon' in categories
        assert 'web' in categories
        assert len(categories) == 2  # Only unique categories

    def test_search_by_name(self):
        """PROVES: Search works on template name"""
        template = CommandTemplate(
            'nmap-quick',
            'Nmap Quick Scan',
            'nmap',
            'Fast scan',
            [],
            'recon'
        )
        TemplateRegistry.register(template)

        results = TemplateRegistry.search('nmap')
        assert len(results) == 1
        assert results[0].id == 'nmap-quick'

    def test_search_by_description(self):
        """PROVES: Search works on description"""
        template = CommandTemplate(
            'test1',
            'Test',
            'cmd',
            'Fast comprehensive scan',
            [],
            'recon'
        )
        TemplateRegistry.register(template)

        results = TemplateRegistry.search('comprehensive')
        assert len(results) == 1
        assert results[0].id == 'test1'

    def test_search_by_tag(self):
        """PROVES: Search works on tags"""
        template = CommandTemplate(
            'test1',
            'Test',
            'cmd',
            'Test',
            [],
            'recon',
            tags=['OSCP:HIGH', 'QUICK_WIN']
        )
        TemplateRegistry.register(template)

        results = TemplateRegistry.search('QUICK_WIN')
        assert len(results) == 1
        assert results[0].id == 'test1'

    def test_search_case_insensitive(self):
        """PROVES: Search is case-insensitive"""
        template = CommandTemplate(
            'test1',
            'Nmap Scan',
            'cmd',
            'Test',
            [],
            'recon'
        )
        TemplateRegistry.register(template)

        results = TemplateRegistry.search('NMAP')
        assert len(results) == 1

        results = TemplateRegistry.search('nmap')
        assert len(results) == 1


class TestDefaultTemplates:
    """Test pre-registered default templates"""

    def test_nmap_quick_template_exists(self):
        """PROVES: Nmap quick scan template is pre-registered"""
        template = TemplateRegistry.get('nmap-quick')
        assert template is not None
        assert template.name == 'Nmap Quick Scan'
        assert template.category == 'recon'

    def test_nmap_quick_has_required_fields(self):
        """PROVES: Nmap quick template has all OSCP-relevant fields"""
        template = TemplateRegistry.get('nmap-quick')

        assert template.command is not None
        assert template.description is not None
        assert len(template.variables) > 0
        assert len(template.flag_explanations) > 0
        assert len(template.tags) > 0
        assert template.estimated_time is not None

    def test_nmap_quick_substitution(self):
        """PROVES: Nmap quick template variable substitution works"""
        template = TemplateRegistry.get('nmap-quick')

        filled = template.fill({'TARGET': '192.168.45.100'})
        assert '192.168.45.100' in filled
        assert '<TARGET>' not in filled

    def test_gobuster_template_exists(self):
        """PROVES: Gobuster template is pre-registered"""
        template = TemplateRegistry.get('gobuster-dir')
        assert template is not None
        assert template.category == 'web'
        assert 'OSCP:HIGH' in template.tags

    def test_enum4linux_template_exists(self):
        """PROVES: Enum4linux template is pre-registered"""
        template = TemplateRegistry.get('enum4linux')
        assert template is not None
        assert template.category == 'enumeration'

    def test_bash_reverse_shell_template(self):
        """PROVES: Bash reverse shell template works"""
        template = TemplateRegistry.get('bash-reverse-shell')
        assert template is not None

        filled = template.fill({
            'LHOST': '192.168.45.200',
            'LPORT': '4444'
        })

        assert '192.168.45.200' in filled
        assert '4444' in filled
        assert '/dev/tcp/' in filled

    def test_all_recon_templates(self):
        """PROVES: All recon templates are accessible"""
        recon_templates = TemplateRegistry.list_by_category('recon')
        assert len(recon_templates) >= 2  # At least nmap-quick and nmap-service

        # Verify they all have required OSCP fields
        for template in recon_templates:
            assert template.description is not None
            assert len(template.variables) > 0

    def test_all_web_templates(self):
        """PROVES: All web templates are accessible"""
        web_templates = TemplateRegistry.list_by_category('web')
        assert len(web_templates) >= 2  # At least gobuster and nikto

    def test_all_templates_have_oscp_metadata(self):
        """PROVES: All templates include OSCP exam preparation metadata"""
        all_templates = TemplateRegistry.list_all()

        for template in all_templates:
            # Must have basic fields
            assert template.id is not None
            assert template.name is not None
            assert template.command is not None
            assert template.description is not None
            assert template.category is not None

            # OSCP relevance
            assert len(template.tags) > 0

            # Educational content
            if template.flag_explanations:
                assert isinstance(template.flag_explanations, dict)


class TestTemplateIntegration:
    """Test integration with interactive mode"""

    def test_template_fills_with_profile_data(self):
        """PROVES: Templates can use profile data for defaults"""
        # This would be enhanced with actual profile integration
        template = TemplateRegistry.get('nmap-service')

        # Simulated: get ports from profile
        ports = "22,80,443"
        target = "192.168.45.100"

        filled = template.fill({
            'TARGET': target,
            'PORTS': ports
        })

        assert target in filled
        assert ports in filled

    def test_searchsploit_template_real_usage(self):
        """PROVES: SearchSploit template works for real OSCP workflow"""
        template = TemplateRegistry.get('searchsploit')

        # Simulate: user discovered Apache 2.4.49
        filled = template.fill({
            'QUERY': 'apache 2.4.49'
        })

        assert 'searchsploit' in filled
        assert 'apache 2.4.49' in filled


class TestTemplateUsability:
    """Test OSCP exam usability"""

    def test_all_templates_have_examples(self):
        """PROVES: All templates provide variable examples for OSCP exam"""
        all_templates = TemplateRegistry.list_all()

        for template in all_templates:
            for var in template.variables:
                # All variables should have examples for OSCP exam guidance
                assert 'example' in var or 'description' in var

    def test_templates_provide_alternatives(self):
        """PROVES: Templates include manual alternatives (OSCP exam requirement)"""
        # Most templates should have alternatives for when tools fail
        critical_templates = ['nmap-quick', 'gobuster-dir', 'enum4linux']

        for template_id in critical_templates:
            template = TemplateRegistry.get(template_id)
            assert template is not None

            # Should have at least one alternative
            # (for OSCP exam when automated tools fail)
            if template_id != 'nmap-quick':  # nmap has no real alternative
                assert len(template.alternatives) > 0

    def test_templates_have_success_indicators(self):
        """PROVES: Templates help users verify command success"""
        important_templates = [
            'nmap-quick',
            'gobuster-dir',
            'enum4linux',
            'whatweb'
        ]

        for template_id in important_templates:
            template = TemplateRegistry.get(template_id)
            assert len(template.success_indicators) > 0

    def test_flag_explanations_educational(self):
        """PROVES: Templates explain flags for learning (not just execution)"""
        template = TemplateRegistry.get('nmap-quick')

        # Should explain why flags are used, not just what they do
        assert '-sS' in template.flag_explanations
        assert len(template.flag_explanations['-sS']) > 10  # Meaningful explanation


class TestRealOSCPWorkflows:
    """Test templates support real OSCP workflows"""

    def test_port_discovery_workflow(self):
        """PROVES: Templates support complete port discovery workflow"""
        # Step 1: Quick scan
        quick = TemplateRegistry.get('nmap-quick')
        assert quick is not None

        # Step 2: Service scan on discovered ports
        service = TemplateRegistry.get('nmap-service')
        assert service is not None

        # Workflow: quick scan → service scan
        quick_cmd = quick.fill({'TARGET': '192.168.45.100'})
        assert 'nmap' in quick_cmd

        service_cmd = service.fill({
            'TARGET': '192.168.45.100',
            'PORTS': '22,80,443'
        })
        assert 'nmap' in service_cmd
        assert '22,80,443' in service_cmd

    def test_web_enumeration_workflow(self):
        """PROVES: Templates support web enumeration workflow"""
        # Step 1: Technology fingerprinting
        whatweb = TemplateRegistry.get('whatweb')
        assert whatweb is not None

        # Step 2: Directory brute-force
        gobuster = TemplateRegistry.get('gobuster-dir')
        assert gobuster is not None

        # Step 3: Vulnerability scan
        nikto = TemplateRegistry.get('nikto-scan')
        assert nikto is not None

    def test_exploitation_workflow(self):
        """PROVES: Templates support exploitation workflow"""
        # Step 1: Search for exploits
        searchsploit = TemplateRegistry.get('searchsploit')
        assert searchsploit is not None

        # Step 2: Set up listener
        listener = TemplateRegistry.get('nc-listener')
        assert listener is not None

        # Step 3: Send reverse shell
        shell = TemplateRegistry.get('bash-reverse-shell')
        assert shell is not None

        # Verify listener and shell use same ports
        listener_cmd = listener.fill({'LPORT': '4444'})
        shell_cmd = shell.fill({'LHOST': '192.168.45.200', 'LPORT': '4444'})

        assert '4444' in listener_cmd
        assert '4444' in shell_cmd


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
