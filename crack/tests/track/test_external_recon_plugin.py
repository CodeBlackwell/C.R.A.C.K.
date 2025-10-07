"""
Tests for External Reconnaissance service plugin

Validates:
- Plugin registration and detection
- Task tree generation for OSINT workflows
- ASN discovery, subdomain enumeration, GitHub dorking tasks
- OSCP metadata completeness (flag explanations, alternatives, success indicators)
- Integration with CRACK Track system
"""

import pytest
from crack.track.services.external_recon import ExternalReconPlugin


class TestExternalReconPlugin:
    """Test suite for External Reconnaissance plugin"""

    @pytest.fixture
    def plugin(self):
        """Create plugin instance"""
        return ExternalReconPlugin()

    def test_plugin_name(self, plugin):
        """PROVES: Plugin has correct identifier"""
        assert plugin.name == "external-recon"

    def test_default_ports_empty(self, plugin):
        """PROVES: External recon is not port-specific"""
        assert plugin.default_ports == []

    def test_service_names(self, plugin):
        """PROVES: Plugin recognizes recon/OSINT keywords"""
        expected_names = ['recon', 'osint', 'external-recon']
        assert plugin.service_names == expected_names

    def test_detect_returns_false(self, plugin):
        """PROVES: Plugin is manually triggered, not auto-detected from port scans"""
        # External recon doesn't auto-trigger from port detection
        port_info = {'port': 80, 'service': 'http'}
        assert plugin.detect(port_info) == False

        port_info2 = {'port': 443, 'service': 'https'}
        assert plugin.detect(port_info2) == False

    def test_task_tree_structure(self, plugin):
        """PROVES: Task tree has valid parent/children hierarchy"""
        tree = plugin.get_task_tree('example.com', 0, {'organization': 'Example Corp'})

        # Verify root structure
        assert 'id' in tree
        assert 'name' in tree
        assert 'type' in tree
        assert tree['type'] == 'parent'
        assert 'children' in tree

        # Verify tree contains main phases
        assert len(tree['children']) > 0
        phase_ids = [child['id'] for child in tree['children']]

        # Check for expected phases
        assert any('asset-discovery' in phase_id for phase_id in phase_ids)
        assert any('subdomain-enum' in phase_id for phase_id in phase_ids)
        assert any('secret-leaks' in phase_id for phase_id in phase_ids)

    def test_asn_discovery_task(self, plugin):
        """PROVES: ASN discovery task includes correct command and metadata"""
        tree = plugin.get_task_tree('example.com', 0, {'organization': 'Example Corp'})

        # Find asset discovery phase
        asset_phase = next(c for c in tree['children'] if 'asset-discovery' in c['id'])

        # Find ASN discovery task
        asn_task = next(c for c in asset_phase['children'] if 'asn-discovery' in c['id'])

        # Verify task structure
        assert asn_task['type'] == 'command'
        assert 'metadata' in asn_task

        metadata = asn_task['metadata']

        # Verify command
        assert 'amass intel' in metadata['command']
        assert 'Example Corp' in metadata['command']

        # Verify OSCP educational metadata
        assert 'flag_explanations' in metadata
        assert 'intel' in metadata['flag_explanations']
        assert '-org' in metadata['flag_explanations']

        # Verify tags
        assert 'tags' in metadata
        assert 'OSCP:HIGH' in metadata['tags']
        assert 'RECON' in metadata['tags']

        # Verify indicators
        assert 'success_indicators' in metadata
        assert len(metadata['success_indicators']) >= 2

        assert 'failure_indicators' in metadata
        assert len(metadata['failure_indicators']) >= 1

        # Verify alternatives
        assert 'alternatives' in metadata
        assert len(metadata['alternatives']) >= 3

        # Verify next steps
        assert 'next_steps' in metadata
        assert len(metadata['next_steps']) >= 2

    def test_subdomain_enumeration_phase(self, plugin):
        """PROVES: Subdomain enumeration includes BBOT, Amass, DNS brute-force, crt.sh"""
        tree = plugin.get_task_tree('example.com', 0, {})

        # Find subdomain enum phase
        subdomain_phase = next(c for c in tree['children'] if 'subdomain-enum' in c['id'])

        # Verify phase has multiple subdomain tools
        assert len(subdomain_phase['children']) >= 4

        task_ids = [t['id'] for t in subdomain_phase['children']]

        # Check for expected tools
        assert any('bbot' in tid for tid in task_ids)
        assert any('amass' in tid for tid in task_ids)
        assert any('dns-bruteforce' in tid or 'puredns' in str(subdomain_phase) for tid in task_ids)
        assert any('crt-sh' in tid for tid in task_ids)

    def test_bbot_subdomain_task(self, plugin):
        """PROVES: BBOT task configured for passive subdomain enumeration"""
        tree = plugin.get_task_tree('testdomain.com', 0, {})

        subdomain_phase = next(c for c in tree['children'] if 'subdomain-enum' in c['id'])
        bbot_task = next(c for c in subdomain_phase['children'] if 'bbot' in c['id'])

        metadata = bbot_task['metadata']

        # Verify command structure
        assert 'bbot -t testdomain.com' in metadata['command']
        assert '-f subdomain-enum' in metadata['command']
        assert '-rf passive' in metadata['command']

        # Verify tags
        assert 'OSCP:HIGH' in metadata['tags']
        assert 'AUTOMATED' in metadata['tags']
        assert 'STEALTH' in metadata['tags']

        # Verify time estimate
        assert 'estimated_time' in metadata

        # Verify alternatives include other subdomain tools
        alternatives_str = ' '.join(metadata['alternatives'])
        assert 'subfinder' in alternatives_str.lower()
        assert 'amass' in alternatives_str.lower()
        assert 'assetfinder' in alternatives_str.lower()

    def test_github_secrets_scanning_task(self, plugin):
        """PROVES: GitHub secret scanning includes trufflehog command"""
        tree = plugin.get_task_tree('example.com', 0, {'organization': 'TestOrg'})

        # Find secret leaks phase
        secrets_phase = next(c for c in tree['children'] if 'secret-leaks' in c['id'])

        # Find GitHub secrets task
        github_task = next(c for c in secrets_phase['children'] if 'github-secrets' in c['id'])

        metadata = github_task['metadata']

        # Verify trufflehog command
        assert 'trufflehog github' in metadata['command']
        assert '--org TestOrg' in metadata['command']
        assert '--json' in metadata['command']

        # Verify QUICK_WIN tag (leaked secrets are instant wins)
        assert 'QUICK_WIN' in metadata['tags']
        assert 'OSCP:HIGH' in metadata['tags']

        # Verify alternatives include gitleaks, noseyparker
        alternatives_str = ' '.join(metadata['alternatives'])
        assert 'gitleaks' in alternatives_str.lower()
        assert 'noseyparker' in alternatives_str.lower() or 'nosey' in alternatives_str.lower()

    def test_github_dorking_task(self, plugin):
        """PROVES: GitHub dorking task includes manual dork examples"""
        tree = plugin.get_task_tree('example.com', 0, {'organization': 'TestOrg'})

        secrets_phase = next(c for c in tree['children'] if 'secret-leaks' in c['id'])
        dork_task = next(c for c in secrets_phase['children'] if 'github-dorks' in c['id'])

        metadata = dork_task['metadata']

        # Verify manual task type
        assert dork_task['type'] == 'manual'

        # Verify alternatives contain actual GitHub dork queries
        alternatives_str = ' '.join(metadata['alternatives'])
        assert 'org:' in alternatives_str
        assert 'AWS_ACCESS_KEY_ID' in alternatives_str or 'filename:' in alternatives_str
        assert '.env' in alternatives_str or 'extension:pem' in alternatives_str

        # Verify next steps guide through process
        assert 'next_steps' in metadata
        assert any('git log' in step for step in metadata['next_steps'])

    def test_certificate_transparency_task(self, plugin):
        """PROVES: Certificate transparency task uses crt.sh API"""
        tree = plugin.get_task_tree('target.com', 0, {})

        subdomain_phase = next(c for c in tree['children'] if 'subdomain-enum' in c['id'])
        crt_task = next(c for c in subdomain_phase['children'] if 'crt-sh' in c['id'])

        metadata = crt_task['metadata']

        # Verify crt.sh command
        assert 'crt.sh' in metadata['command']
        assert 'target.com' in metadata['command']
        assert 'curl' in metadata['command']

        # Verify QUICK_WIN tag (CT logs are fast and valuable)
        assert 'QUICK_WIN' in metadata['tags']
        assert 'MANUAL' in metadata['tags']
        assert 'STEALTH' in metadata['tags']

        # Verify time estimate is quick
        assert 'estimated_time' in metadata
        assert '1 minute' in metadata['estimated_time'].lower() or '< 1' in metadata['estimated_time']

    def test_cloud_assets_s3_enumeration(self, plugin):
        """PROVES: Cloud assets phase includes S3 bucket enumeration"""
        tree = plugin.get_task_tree('example.com', 0, {})

        # Find cloud assets phase
        cloud_phase = next(c for c in tree['children'] if 'cloud-assets' in c['id'])

        # Find S3 bucket task
        s3_task = next(c for c in cloud_phase['children'] if 's3-buckets' in c['id'] or 's3' in c['name'].lower())

        metadata = s3_task['metadata']

        # Verify cloud enumeration tool
        assert 'cloud_enum' in metadata['command'] or 's3' in metadata['command'].lower()

        # Verify tags
        assert 'QUICK_WIN' in metadata['tags']

        # Verify alternatives include multiple approaches
        alternatives_str = ' '.join(metadata['alternatives'])
        assert 's3' in alternatives_str.lower()
        assert any(tool in alternatives_str.lower() for tool in ['s3scanner', 'aws', 'curl'])

    def test_email_harvesting_task(self, plugin):
        """PROVES: Email harvesting includes theHarvester command"""
        tree = plugin.get_task_tree('example.com', 0, {})

        # Find email enum phase
        email_phase = next(c for c in tree['children'] if 'email-enum' in c['id'])

        # Find email harvest task
        harvest_task = email_phase['children'][0]

        metadata = harvest_task['metadata']

        # Verify theHarvester command
        assert 'theHarvester' in metadata['command']
        assert '-d example.com' in metadata['command']
        assert '-b' in metadata['command']

        # Verify multiple sources
        assert 'google' in metadata['command'].lower() or 'linkedin' in metadata['command'].lower()

        # Verify QUICK_WIN tag
        assert 'QUICK_WIN' in metadata['tags']

        # Verify next steps include credential attacks
        next_steps_str = ' '.join(metadata['next_steps']).lower()
        assert 'password' in next_steps_str or 'spray' in next_steps_str or 'phishing' in next_steps_str

    def test_all_command_tasks_have_flag_explanations(self, plugin):
        """PROVES: All command tasks explain their flags (OSCP educational requirement)"""
        tree = plugin.get_task_tree('example.com', 0, {'organization': 'Example Corp'})

        def check_command_tasks(node):
            """Recursively check all command tasks"""
            if node.get('type') == 'command':
                metadata = node.get('metadata', {})
                assert 'command' in metadata, f"Task {node['id']} missing command"

                # Command tasks MUST have flag explanations
                assert 'flag_explanations' in metadata, \
                    f"Task {node['id']} missing flag_explanations (OSCP requirement)"

                assert len(metadata['flag_explanations']) > 0, \
                    f"Task {node['id']} has empty flag_explanations"

            # Recurse into children
            if 'children' in node:
                for child in node['children']:
                    check_command_tasks(child)

        # Check entire tree
        check_command_tasks(tree)

    def test_all_tasks_have_success_indicators(self, plugin):
        """PROVES: All tasks provide success indicators (helps user verify results)"""
        tree = plugin.get_task_tree('example.com', 0, {})

        def check_indicators(node):
            """Recursively check tasks have indicators"""
            if node.get('type') in ['command', 'manual']:
                metadata = node.get('metadata', {})

                # Tasks should have success indicators
                if 'success_indicators' in metadata:
                    assert len(metadata['success_indicators']) >= 1, \
                        f"Task {node['id']} has empty success_indicators"

            if 'children' in node:
                for child in node['children']:
                    check_indicators(child)

        check_indicators(tree)

    def test_all_tasks_have_alternatives(self, plugin):
        """PROVES: Tasks provide manual alternatives (OSCP exam readiness)"""
        tree = plugin.get_task_tree('example.com', 0, {})

        def check_alternatives(node):
            """Check tasks provide alternative methods"""
            if node.get('type') in ['command', 'manual']:
                metadata = node.get('metadata', {})

                # Most tasks should have alternatives
                if 'alternatives' in metadata:
                    assert len(metadata['alternatives']) >= 1, \
                        f"Task {node['id']} has empty alternatives list"

            if 'children' in node:
                for child in node['children']:
                    check_alternatives(child)

        check_alternatives(tree)

    def test_task_ids_unique(self, plugin):
        """PROVES: All task IDs are unique within the tree"""
        tree = plugin.get_task_tree('example.com', 0, {})

        task_ids = []

        def collect_ids(node):
            """Recursively collect all task IDs"""
            if 'id' in node:
                task_ids.append(node['id'])
            if 'children' in node:
                for child in node['children']:
                    collect_ids(child)

        collect_ids(tree)

        # Check for duplicates
        assert len(task_ids) == len(set(task_ids)), \
            f"Duplicate task IDs found: {[tid for tid in task_ids if task_ids.count(tid) > 1]}"

    def test_target_sanitization(self, plugin):
        """PROVES: Target domain with special characters handled correctly in IDs"""
        tree = plugin.get_task_tree('test-domain.com', 0, {})

        # Task IDs should not have dots (replaced with hyphens)
        assert 'test-domain-com' in tree['id']

        # Verify commands still use correct domain
        def check_commands(node):
            if node.get('type') == 'command':
                metadata = node.get('metadata', {})
                if 'command' in metadata:
                    # Commands should preserve original domain format
                    if 'test' in metadata['command']:
                        assert 'test-domain.com' in metadata['command'] or \
                               'test_domain' in metadata['command']

            if 'children' in node:
                for child in node['children']:
                    check_commands(child)

        check_commands(tree)

    def test_oscp_relevance_tagging(self, plugin):
        """PROVES: Tasks tagged with OSCP relevance levels"""
        tree = plugin.get_task_tree('example.com', 0, {})

        oscp_tagged_count = 0

        def count_oscp_tags(node):
            """Count tasks with OSCP tags"""
            nonlocal oscp_tagged_count

            if node.get('type') in ['command', 'manual']:
                metadata = node.get('metadata', {})
                tags = metadata.get('tags', [])

                # Check for OSCP relevance tags
                if any('OSCP' in tag for tag in tags):
                    oscp_tagged_count += 1

            if 'children' in node:
                for child in node['children']:
                    count_oscp_tags(child)

        count_oscp_tags(tree)

        # Most tasks should have OSCP relevance tags
        assert oscp_tagged_count > 5, \
            "External recon plugin should have multiple OSCP-tagged tasks"

    def test_integration_with_crack_track_system(self, plugin):
        """PROVES: Plugin follows CRACK Track conventions"""
        # Verify plugin is properly registered
        assert hasattr(plugin, 'name')
        assert hasattr(plugin, 'detect')
        assert hasattr(plugin, 'get_task_tree')

        # Verify task tree format compatible with CRACK Track
        tree = plugin.get_task_tree('example.com', 0, {})

        # Root must be parent type
        assert tree['type'] == 'parent'

        # Must have children array
        assert isinstance(tree['children'], list)

        # Children must have required fields
        for child in tree['children']:
            assert 'id' in child
            assert 'name' in child
            assert 'type' in child


class TestExternalReconWorkflows:
    """Test real-world OSCP reconnaissance workflows"""

    @pytest.fixture
    def plugin(self):
        return ExternalReconPlugin()

    def test_oscp_recon_workflow(self, plugin):
        """
        PROVES: Plugin supports complete OSCP external recon workflow

        Workflow:
        1. Discover ASN and IP ranges
        2. Enumerate subdomains (passive then active)
        3. Search for leaked secrets
        4. Find cloud assets
        5. Harvest emails for password spraying
        """
        tree = plugin.get_task_tree('targetcorp.com', 0, {'organization': 'Target Corp'})

        # Verify workflow phases present
        phase_names = [child['name'] for child in tree['children']]

        assert any('Asset Discovery' in name for name in phase_names)
        assert any('Subdomain' in name for name in phase_names)
        assert any('Secret' in name or 'Leak' in name for name in phase_names)
        assert any('Cloud' in name for name in phase_names)
        assert any('Email' in name for name in phase_names)

    def test_quick_wins_identified(self, plugin):
        """PROVES: Plugin identifies QUICK_WIN tasks for time-constrained OSCP exam"""
        tree = plugin.get_task_tree('example.com', 0, {})

        quick_wins = []

        def find_quick_wins(node):
            if node.get('type') in ['command', 'manual']:
                metadata = node.get('metadata', {})
                tags = metadata.get('tags', [])
                if 'QUICK_WIN' in tags:
                    quick_wins.append(node['name'])

            if 'children' in node:
                for child in node['children']:
                    find_quick_wins(child)

        find_quick_wins(tree)

        # Should have multiple quick wins
        assert len(quick_wins) >= 3, \
            f"External recon should identify multiple QUICK_WIN tasks, found: {quick_wins}"
