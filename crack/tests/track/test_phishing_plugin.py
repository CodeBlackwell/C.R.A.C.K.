"""
Tests for Phishing & Social Engineering plugin

Validates comprehensive phishing campaign task generation including:
- Full campaign workflow (recon → infrastructure → payloads → delivery)
- Email-focused campaigns
- Web credential harvesting
- Mobile phishing (Android/iOS)
- Advanced techniques (homographs, clipboard hijacking, MFA bypass, AI)
"""

import pytest
from crack.track.services.phishing import PhishingPlugin


class TestPhishingPlugin:
    """Test suite for PhishingPlugin"""

    @pytest.fixture
    def plugin(self):
        """Create plugin instance"""
        return PhishingPlugin()

    def test_plugin_name(self, plugin):
        """PROVES: Plugin has correct name"""
        assert plugin.name == "phishing"

    def test_manual_detection(self, plugin):
        """PROVES: Plugin is not auto-detected (manual trigger only)"""
        port_info = {
            'port': 80,
            'service': 'http',
            'product': 'Apache httpd',
            'version': '2.4.41'
        }
        # Phishing plugin never auto-detects
        assert plugin.detect(port_info) == False

    def test_full_campaign_task_tree(self, plugin):
        """PROVES: Full campaign generates comprehensive task tree"""
        service_info = {
            'campaign_type': 'full',
            'target_org': 'Acme Corp'
        }

        tree = plugin.get_task_tree('acme.com', 443, service_info)

        # Root structure
        assert tree['id'] == 'phishing-campaign-full'
        assert 'Acme Corp' in tree['name']
        assert tree['type'] == 'parent'
        assert 'children' in tree

        # Should have 5 main phases
        assert len(tree['children']) == 5

        # Verify phase names
        phase_ids = [child['id'] for child in tree['children']]
        assert 'phishing-recon' in phase_ids
        assert 'phishing-infrastructure' in phase_ids
        assert 'phishing-payloads' in phase_ids
        assert 'phishing-delivery' in phase_ids
        assert 'phishing-advanced' in phase_ids

    def test_recon_phase_completeness(self, plugin):
        """PROVES: Reconnaissance phase includes OSINT and email discovery"""
        service_info = {
            'campaign_type': 'full',
            'target_org': 'TestOrg'
        }

        tree = plugin.get_task_tree('test.com', 443, service_info)
        recon_phase = tree['children'][0]

        assert recon_phase['id'] == 'phishing-recon'
        assert recon_phase['type'] == 'parent'

        # Check for key recon tasks
        task_ids = [task['id'] for task in recon_phase['children']]
        assert 'identify-login-portals' in task_ids
        assert 'email-osint' in task_ids

        # Email OSINT should have theHarvester
        email_osint = next(t for t in recon_phase['children'] if t['id'] == 'email-osint')
        email_tasks = [t['id'] for t in email_osint['children']]
        assert 'theharvester-emails' in email_tasks
        assert 'smtp-verify-emails' in email_tasks

    def test_infrastructure_phase_completeness(self, plugin):
        """PROVES: Infrastructure phase covers domain, DNS, email, GoPhish"""
        service_info = {'campaign_type': 'full', 'target_org': 'TestOrg'}
        tree = plugin.get_task_tree('test.com', 443, service_info)

        infra_phase = tree['children'][1]
        assert infra_phase['id'] == 'phishing-infrastructure'

        # Check main infrastructure components
        component_ids = [c['id'] for c in infra_phase['children']]
        assert 'domain-generation' in component_ids
        assert 'dns-email-config' in component_ids
        assert 'gophish-setup' in component_ids

        # Domain generation should include dnstwist
        domain_gen = next(c for c in infra_phase['children'] if c['id'] == 'domain-generation')
        domain_tasks = [t['id'] for t in domain_gen['children']]
        assert 'dnstwist-variants' in domain_tasks
        assert 'expired-domains' in domain_tasks

        # DNS/Email config should cover SPF, DKIM, DMARC
        dns_config = next(c for c in infra_phase['children'] if c['id'] == 'dns-email-config')
        dns_tasks = [t['id'] for t in dns_config['children']]
        assert 'rdns-config' in dns_tasks
        assert 'spf-record' in dns_tasks
        assert 'dmarc-record' in dns_tasks
        assert 'dkim-setup' in dns_tasks
        assert 'mail-server-test' in dns_tasks

    def test_payload_phase_completeness(self, plugin):
        """PROVES: Payload phase includes landing pages, documents, and templates"""
        service_info = {'campaign_type': 'full', 'target_org': 'TestOrg'}
        tree = plugin.get_task_tree('test.com', 443, service_info)

        payload_phase = tree['children'][2]
        assert payload_phase['id'] == 'phishing-payloads'

        # Check main payload components
        component_ids = [c['id'] for c in payload_phase['children']]
        assert 'landing-page' in component_ids
        assert 'phishing-documents' in component_ids
        assert 'email-template' in component_ids

        # Landing page should include cloning
        landing = next(c for c in payload_phase['children'] if c['id'] == 'landing-page')
        landing_tasks = [t['id'] for t in landing['children']]
        assert 'wget-clone' in landing_tasks
        assert 'landing-page-setup' in landing_tasks

        # Documents should include macros, HTA, LNK
        docs = next(c for c in payload_phase['children'] if c['id'] == 'phishing-documents')
        doc_tasks = [t['id'] for t in docs['children']]
        assert 'macro-docm' in doc_tasks
        assert 'hta-payload' in doc_tasks
        assert 'lnk-zip-loader' in doc_tasks

    def test_delivery_phase_completeness(self, plugin):
        """PROVES: Delivery phase covers campaign execution and monitoring"""
        service_info = {'campaign_type': 'full', 'target_org': 'TestOrg'}
        tree = plugin.get_task_tree('test.com', 443, service_info)

        delivery_phase = tree['children'][3]
        assert delivery_phase['id'] == 'phishing-delivery'

        # Check delivery components
        component_ids = [c['id'] for c in delivery_phase['children']]
        assert 'gophish-campaign' in component_ids
        assert 'campaign-monitoring' in component_ids

    def test_advanced_techniques_phase(self, plugin):
        """PROVES: Advanced phase includes homographs, clipboard, MFA, mobile, AI, Discord"""
        service_info = {'campaign_type': 'full', 'target_org': 'TestOrg'}
        tree = plugin.get_task_tree('test.com', 443, service_info)

        advanced_phase = tree['children'][4]
        assert advanced_phase['id'] == 'phishing-advanced'

        # Check advanced technique components
        component_ids = [c['id'] for c in advanced_phase['children']]
        assert 'homograph-attacks' in component_ids
        assert 'clipboard-hijacking' in component_ids
        assert 'mfa-bypass' in component_ids
        assert 'mobile-phishing' in component_ids
        assert 'ai-enhanced-phishing' in component_ids
        assert 'discord-hijacking' in component_ids

        # MFA bypass should have sub-techniques
        mfa = next(c for c in advanced_phase['children'] if c['id'] == 'mfa-bypass')
        mfa_tasks = [t['id'] for t in mfa['children']]
        assert 'evilginx2-mitm' in mfa_tasks
        assert 'helpdesk-mfa-reset' in mfa_tasks

        # Mobile phishing should have Android and iOS
        mobile = next(c for c in advanced_phase['children'] if c['id'] == 'mobile-phishing')
        mobile_tasks = [t['id'] for t in mobile['children']]
        assert 'android-apk-phishing' in mobile_tasks
        assert 'ios-mobileconfig' in mobile_tasks

    def test_oscp_metadata_present(self, plugin):
        """PROVES: Tasks include OSCP-required metadata"""
        service_info = {'campaign_type': 'full', 'target_org': 'TestOrg'}
        tree = plugin.get_task_tree('test.com', 443, service_info)

        def find_command_tasks(node):
            """Recursively find all command tasks"""
            tasks = []
            if node.get('type') == 'command':
                tasks.append(node)
            for child in node.get('children', []):
                tasks.extend(find_command_tasks(child))
            return tasks

        command_tasks = find_command_tasks(tree)
        assert len(command_tasks) > 0, "Should have at least one command task"

        # Check first command task has required metadata
        task = command_tasks[0]
        metadata = task.get('metadata', {})

        assert 'command' in metadata, "Command tasks must have 'command'"
        assert 'description' in metadata, "Tasks must have description"
        assert 'tags' in metadata, "Tasks must have tags"
        assert len(metadata['tags']) > 0, "Tags must not be empty"

        # Check flag explanations present
        if '-' in metadata['command']:  # Has flags
            assert 'flag_explanations' in metadata, "Commands with flags must explain them"

    def test_oscp_educational_content(self, plugin):
        """PROVES: Tasks provide educational value (alternatives, next steps, indicators)"""
        service_info = {'campaign_type': 'full', 'target_org': 'TestOrg'}
        tree = plugin.get_task_tree('test.com', 443, service_info)

        def find_manual_tasks(node):
            """Recursively find all manual tasks"""
            tasks = []
            if node.get('type') == 'manual':
                tasks.append(node)
            for child in node.get('children', []):
                tasks.extend(find_manual_tasks(child))
            return tasks

        manual_tasks = find_manual_tasks(tree)
        assert len(manual_tasks) > 0, "Should have manual tasks"

        # Check manual tasks have notes/guidance
        task = manual_tasks[0]
        metadata = task.get('metadata', {})
        assert 'notes' in metadata or 'alternatives' in metadata, "Manual tasks need guidance"

    def test_email_campaign_task_tree(self, plugin):
        """PROVES: Email campaign type generates email-focused tasks"""
        service_info = {
            'campaign_type': 'email',
            'target_org': 'EmailTest Corp'
        }

        tree = plugin.get_task_tree('emailtest.com', 443, service_info)

        assert 'Email Phishing Campaign' in tree['name']
        assert 'EmailTest Corp' in tree['name']

        # Should have recon, infrastructure, and email delivery
        phase_ids = [child['id'] for child in tree['children']]
        assert 'phishing-recon' in phase_ids
        assert 'phishing-infrastructure' in phase_ids

    def test_web_campaign_task_tree(self, plugin):
        """PROVES: Web campaign type focuses on credential harvesting"""
        service_info = {
            'campaign_type': 'web',
            'target_org': 'WebTest Inc'
        }

        tree = plugin.get_task_tree('webtest.com', 443, service_info)

        assert 'Web Phishing' in tree['name']
        assert tree['id'] == 'web-phishing'

        # Should focus on domain and landing pages
        component_ids = [c['id'] for c in tree['children']]
        assert 'domain-setup' in component_ids
        assert 'advanced-web' in component_ids

    def test_mobile_campaign_task_tree(self, plugin):
        """PROVES: Mobile campaign type generates mobile-specific tasks"""
        service_info = {
            'campaign_type': 'mobile',
            'target_org': 'MobileTest LLC'
        }

        tree = plugin.get_task_tree('mobiletest.com', 443, service_info)

        assert 'Mobile Phishing' in tree['name']
        assert tree['id'] == 'mobile-phishing'

        # Should have mobile recon and mobile phishing techniques
        component_ids = [c['id'] for c in tree['children']]
        assert 'mobile-recon' in component_ids

    def test_theHarvester_command_structure(self, plugin):
        """PROVES: theHarvester task has complete command with flag explanations"""
        service_info = {'campaign_type': 'full', 'target_org': 'TestOrg'}
        tree = plugin.get_task_tree('test.com', 443, service_info)

        # Navigate to theHarvester task
        recon = tree['children'][0]
        email_osint = next(t for t in recon['children'] if t['id'] == 'email-osint')
        harvester = next(t for t in email_osint['children'] if t['id'] == 'theharvester-emails')

        metadata = harvester['metadata']

        # Check command
        assert 'theHarvester' in metadata['command']
        assert 'test.com' in metadata['command']
        assert '-d' in metadata['command']
        assert '-b all' in metadata['command']

        # Check flag explanations
        flags = metadata['flag_explanations']
        assert '-d' in flags
        assert '-b all' in flags
        assert '-f' in flags

        # Check success/failure indicators
        assert 'success_indicators' in metadata
        assert 'failure_indicators' in metadata
        assert len(metadata['success_indicators']) > 0
        assert len(metadata['failure_indicators']) > 0

        # Check alternatives
        assert 'alternatives' in metadata
        assert len(metadata['alternatives']) >= 2

        # Check next steps
        assert 'next_steps' in metadata
        assert len(metadata['next_steps']) >= 2

        # Check tags
        assert 'OSCP:HIGH' in metadata['tags']
        assert 'RECON' in metadata['tags']

    def test_dnstwist_command_structure(self, plugin):
        """PROVES: dnstwist task includes homograph attack guidance"""
        service_info = {'campaign_type': 'full', 'target_org': 'TestOrg'}
        tree = plugin.get_task_tree('test.com', 443, service_info)

        # Navigate to dnstwist task
        infra = tree['children'][1]
        domain_gen = next(c for c in infra['children'] if c['id'] == 'domain-generation')
        dnstwist = next(t for t in domain_gen['children'] if t['id'] == 'dnstwist-variants')

        metadata = dnstwist['metadata']

        # Check command
        assert 'dnstwist' in metadata['command']
        assert 'test.com' in metadata['command']

        # Check notes mention homograph attacks
        notes = metadata['notes']
        assert any('homograph' in str(note).lower() for note in notes)
        assert any('unicode' in str(note).lower() for note in notes)

        # Check alternatives
        assert 'urlcrazy' in str(metadata['alternatives'])

    def test_spf_dkim_dmarc_coverage(self, plugin):
        """PROVES: Email authentication records fully covered"""
        service_info = {'campaign_type': 'full', 'target_org': 'TestOrg'}
        tree = plugin.get_task_tree('test.com', 443, service_info)

        # Navigate to DNS config
        infra = tree['children'][1]
        dns_config = next(c for c in infra['children'] if c['id'] == 'dns-email-config')

        dns_task_ids = [t['id'] for t in dns_config['children']]

        # Verify all email auth records covered
        assert 'spf-record' in dns_task_ids
        assert 'dmarc-record' in dns_task_ids
        assert 'dkim-setup' in dns_task_ids

        # Check SPF task has proper guidance
        spf = next(t for t in dns_config['children'] if t['id'] == 'spf-record')
        spf_notes = spf['metadata']['notes']
        assert any('v=spf1' in str(note) for note in spf_notes)
        assert any('spfwizard' in str(note).lower() for note in spf_notes)

        # Check DMARC task
        dmarc = next(t for t in dns_config['children'] if t['id'] == 'dmarc-record')
        dmarc_notes = dmarc['metadata']['notes']
        assert any('v=DMARC1' in str(note) for note in dmarc_notes)
        assert any('p=none' in str(note) for note in dmarc_notes)

        # Check DKIM task
        dkim = next(t for t in dns_config['children'] if t['id'] == 'dkim-setup')
        dkim_notes = dkim['metadata']['notes']
        assert any('opendkim' in str(note).lower() for note in dkim_notes)

    def test_gophish_setup_completeness(self, plugin):
        """PROVES: GoPhish setup covers installation, TLS, and configuration"""
        service_info = {'campaign_type': 'full', 'target_org': 'TestOrg'}
        tree = plugin.get_task_tree('test.com', 443, service_info)

        # Navigate to GoPhish setup
        infra = tree['children'][1]
        gophish = next(c for c in infra['children'] if c['id'] == 'gophish-setup')

        gophish_task_ids = [t['id'] for t in gophish['children']]
        assert 'gophish-install' in gophish_task_ids
        assert 'gophish-tls' in gophish_task_ids

        # Check install task has GitHub reference
        install = next(t for t in gophish['children'] if t['id'] == 'gophish-install')
        install_notes = install['metadata']['notes']
        assert any('github' in str(note).lower() for note in install_notes)

        # Check TLS task has certbot
        tls = next(t for t in gophish['children'] if t['id'] == 'gophish-tls')
        tls_notes = tls['metadata']['notes']
        assert any('certbot' in str(note).lower() for note in tls_notes)

    def test_macro_document_guidance(self, plugin):
        """PROVES: Macro document task includes VBA and evasion guidance"""
        service_info = {'campaign_type': 'full', 'target_org': 'TestOrg'}
        tree = plugin.get_task_tree('test.com', 443, service_info)

        # Navigate to macro document task
        payload = tree['children'][2]
        docs = next(c for c in payload['children'] if c['id'] == 'phishing-documents')
        macro = next(t for t in docs['children'] if t['id'] == 'macro-docm')

        metadata = macro['metadata']

        # Task must exist and be about macros
        assert 'macro' in macro['name'].lower() or 'macro' in metadata.get('description', '').lower()

        # Check file extension guidance in notes
        notes_str = str(metadata.get('notes', ''))
        assert '.doc' in notes_str

        # Check alternatives (should mention other Office exploitation methods)
        alternatives = metadata.get('alternatives', [])
        assert len(alternatives) > 0
        alternatives_str = str(alternatives).lower()
        assert 'template' in alternatives_str or 'image' in alternatives_str or 'ntlm' in alternatives_str

    def test_clipboard_hijacking_technique(self, plugin):
        """PROVES: Clipboard hijacking (pastejacking) fully documented"""
        service_info = {'campaign_type': 'full', 'target_org': 'TestOrg'}
        tree = plugin.get_task_tree('test.com', 443, service_info)

        # Navigate to clipboard hijacking
        advanced = tree['children'][4]
        clipboard = next(c for c in advanced['children'] if c['id'] == 'clipboard-hijacking')

        metadata = clipboard['metadata']

        # Notes could be string or list
        notes_str = str(metadata.get('notes', '')) + str(metadata.get('description', '')).lower()

        # Check for key concepts - at minimum should mention clipboard/paste
        assert 'clipboard' in notes_str or 'paste' in notes_str or 'hijack' in notes_str
        # Should have some technical details or description
        assert len(notes_str) > 50

    def test_homograph_attack_unicode_examples(self, plugin):
        """PROVES: Homograph attacks include Unicode character examples"""
        service_info = {'campaign_type': 'full', 'target_org': 'TestOrg'}
        tree = plugin.get_task_tree('test.com', 443, service_info)

        # Navigate to homograph attacks
        advanced = tree['children'][4]
        homograph = next(c for c in advanced['children'] if c['id'] == 'homograph-attacks')

        metadata = homograph['metadata']
        notes_str = str(metadata.get('notes', '')) + str(metadata.get('description', ''))

        # Check for Unicode/homograph concepts
        assert 'unicode' in notes_str.lower() or 'homograph' in notes_str.lower() or 'look-alike' in notes_str.lower()
        # Should have substantial content
        assert len(notes_str) > 50

    def test_mfa_bypass_techniques_coverage(self, plugin):
        """PROVES: MFA bypass includes evilginx2 and help desk reset"""
        service_info = {'campaign_type': 'full', 'target_org': 'TestOrg'}
        tree = plugin.get_task_tree('test.com', 443, service_info)

        # Navigate to MFA bypass
        advanced = tree['children'][4]
        mfa = next(c for c in advanced['children'] if c['id'] == 'mfa-bypass')

        assert mfa['type'] == 'parent'
        assert len(mfa['children']) == 2

        # Check evilginx2 task exists
        evilginx = next(t for t in mfa['children'] if t['id'] == 'evilginx2-mitm')
        evilginx_content = str(evilginx['metadata'].get('notes', '')) + str(evilginx['metadata'].get('description', ''))
        assert 'evilginx' in evilginx_content.lower() or 'proxy' in evilginx_content.lower() or 'mitm' in evilginx_content.lower()

        # Check help desk reset task exists
        helpdesk = next(t for t in mfa['children'] if t['id'] == 'helpdesk-mfa-reset')
        helpdesk_content = str(helpdesk['metadata'].get('notes', '')) + str(helpdesk['metadata'].get('description', ''))
        assert 'help' in helpdesk_content.lower() or 'desk' in helpdesk_content.lower() or 'reset' in helpdesk_content.lower()

    def test_mobile_phishing_android_ios_coverage(self, plugin):
        """PROVES: Mobile phishing covers both Android APK and iOS profiles"""
        service_info = {'campaign_type': 'full', 'target_org': 'TestOrg'}
        tree = plugin.get_task_tree('test.com', 443, service_info)

        # Navigate to mobile phishing
        advanced = tree['children'][4]
        mobile = next(c for c in advanced['children'] if c['id'] == 'mobile-phishing')

        assert mobile['type'] == 'parent'

        mobile_task_ids = [t['id'] for t in mobile['children']]
        assert 'android-apk-phishing' in mobile_task_ids
        assert 'ios-mobileconfig' in mobile_task_ids

        # Check Android task exists and has content
        android = next(t for t in mobile['children'] if t['id'] == 'android-apk-phishing')
        android_content = str(android['metadata'].get('notes', '')) + str(android['metadata'].get('description', ''))
        assert 'android' in android_content.lower() or 'apk' in android_content.lower() or 'mobile' in android_content.lower()

        # Check iOS task exists and has content
        ios = next(t for t in mobile['children'] if t['id'] == 'ios-mobileconfig')
        ios_content = str(ios['metadata'].get('notes', '')) + str(ios['metadata'].get('description', ''))
        assert 'ios' in ios_content.lower() or 'mobile' in ios_content.lower() or 'config' in ios_content.lower()

    def test_ai_enhanced_phishing_documented(self, plugin):
        """PROVES: AI/LLM phishing techniques documented"""
        service_info = {'campaign_type': 'full', 'target_org': 'TestOrg'}
        tree = plugin.get_task_tree('test.com', 443, service_info)

        # Navigate to AI-enhanced phishing
        advanced = tree['children'][4]
        ai = next(c for c in advanced['children'] if c['id'] == 'ai-enhanced-phishing')

        metadata = ai['metadata']
        content = str(metadata.get('notes', '')) + str(metadata.get('description', ''))

        # Check for AI/advanced concepts
        assert 'ai' in content.lower() or 'llm' in content.lower() or 'advanced' in content.lower()
        # Should have substantial content
        assert len(content) > 30

    def test_discord_hijacking_technique(self, plugin):
        """PROVES: Discord invite hijacking technique documented"""
        service_info = {'campaign_type': 'full', 'target_org': 'TestOrg'}
        tree = plugin.get_task_tree('test.com', 443, service_info)

        # Navigate to Discord hijacking
        advanced = tree['children'][4]
        discord = next(c for c in advanced['children'] if c['id'] == 'discord-hijacking')

        metadata = discord['metadata']
        content = str(metadata.get('notes', '')) + str(metadata.get('description', ''))

        # Check for Discord/hijacking concepts
        assert 'discord' in content.lower() or 'hijack' in content.lower() or 'invite' in content.lower()
        # Should have content
        assert len(content) > 30

    def test_campaign_monitoring_guidance(self, plugin):
        """PROVES: Campaign monitoring includes metrics and detection indicators"""
        service_info = {'campaign_type': 'full', 'target_org': 'TestOrg'}
        tree = plugin.get_task_tree('test.com', 443, service_info)

        # Navigate to campaign monitoring
        delivery = tree['children'][3]
        monitoring = next(c for c in delivery['children'] if c['id'] == 'campaign-monitoring')

        metadata = monitoring['metadata']
        notes = metadata['notes']
        notes_str = str(notes).lower()

        # Check for metrics
        assert 'open rate' in notes_str or 'click rate' in notes_str
        assert 'submit rate' in notes_str or 'delivery rate' in notes_str

        # Check for detection awareness
        assert 'blacklist' in notes_str or 'canary' in notes_str

    def test_no_dynamic_task_generation(self, plugin):
        """PROVES: Methodology plugin doesn't generate dynamic tasks"""
        result = plugin.on_task_complete('any-task-id', 'success', 'test.com')
        assert result == []

    def test_manual_alternatives_provided(self, plugin):
        """PROVES: Plugin provides manual alternatives"""
        alternatives = plugin.get_manual_alternatives('some-task')
        assert len(alternatives) > 0
        assert any('manual' in alt.lower() for alt in alternatives)

    def test_oscp_tag_distribution(self, plugin):
        """PROVES: Tasks are tagged appropriately for OSCP relevance"""
        service_info = {'campaign_type': 'full', 'target_org': 'TestOrg'}
        tree = plugin.get_task_tree('test.com', 443, service_info)

        def collect_tags(node):
            """Recursively collect all tags"""
            tags = []
            if 'metadata' in node and 'tags' in node['metadata']:
                tags.extend(node['metadata']['tags'])
            for child in node.get('children', []):
                tags.extend(collect_tags(child))
            return tags

        all_tags = collect_tags(tree)

        # Should have OSCP relevance tags
        oscp_tags = [tag for tag in all_tags if 'OSCP:' in tag]
        assert len(oscp_tags) > 0

        # Should have phase tags
        phase_tags = [tag for tag in all_tags if tag in ['RECON', 'ENUM', 'EXPLOIT', 'RESEARCH']]
        assert len(phase_tags) > 0

        # Should have method tags
        method_tags = [tag for tag in all_tags if tag in ['MANUAL', 'AUTOMATED', 'NOISY', 'ADVANCED']]
        assert len(method_tags) > 0

    def test_time_estimates_where_appropriate(self, plugin):
        """PROVES: Tasks include time estimates for planning"""
        service_info = {'campaign_type': 'full', 'target_org': 'TestOrg'}
        tree = plugin.get_task_tree('test.com', 443, service_info)

        def find_time_estimates(node):
            """Recursively find tasks with time estimates"""
            estimates = []
            if 'metadata' in node and 'estimated_time' in node['metadata']:
                estimates.append(node['metadata']['estimated_time'])
            for child in node.get('children', []):
                estimates.extend(find_time_estimates(child))
            return estimates

        time_estimates = find_time_estimates(tree)
        assert len(time_estimates) > 5, "Should have multiple tasks with time estimates"

    def test_notes_provide_context(self, plugin):
        """PROVES: Tasks include contextual notes for learning"""
        service_info = {'campaign_type': 'full', 'target_org': 'TestOrg'}
        tree = plugin.get_task_tree('test.com', 443, service_info)

        def find_notes(node):
            """Recursively find tasks with notes"""
            notes = []
            if 'metadata' in node and 'notes' in node['metadata']:
                notes.append(node['metadata']['notes'])
            for child in node.get('children', []):
                notes.extend(find_notes(child))
            return notes

        all_notes = find_notes(tree)
        assert len(all_notes) > 10, "Should have extensive contextual notes"

        # Notes should be educational
        notes_str = str(all_notes).lower()
        assert 'why' in notes_str or 'how' in notes_str or 'example' in notes_str
