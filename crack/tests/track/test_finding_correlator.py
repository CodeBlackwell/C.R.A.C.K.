"""
Tests for Finding Correlator (fc) tool

Validates correlation detection patterns and attack chain identification.
"""

import pytest
from datetime import datetime
from crack.track.core.state import TargetProfile
from crack.track.core.task_tree import TaskNode
from crack.track.interactive.session import InteractiveSession


class TestFindingCorrelator:
    """Test suite for fc (Finding Correlator) tool"""

    def test_fc_shortcut_exists(self):
        """PROVES: fc shortcut is registered"""
        from crack.track.interactive.shortcuts import ShortcutHandler
        from crack.track.interactive.session import InteractiveSession

        # Create mock session
        profile = TargetProfile('192.168.45.100')
        session = InteractiveSession(profile.target)

        handler = ShortcutHandler(session)

        # Verify shortcut exists
        assert 'fc' in handler.shortcuts
        assert handler.shortcuts['fc'][0] == 'Finding correlator'
        assert handler.shortcuts['fc'][1] == 'finding_correlator'

    def test_fc_handler_callable(self):
        """PROVES: fc handler method exists and is callable"""
        from crack.track.interactive.session import InteractiveSession

        profile = TargetProfile('192.168.45.100')
        session = InteractiveSession(profile.target)

        # Verify method exists
        assert hasattr(session, 'handle_finding_correlator')
        assert callable(session.handle_finding_correlator)

    def test_service_credential_correlation(self):
        """PROVES: Detects service + credential correlation"""
        profile = TargetProfile('192.168.45.100')

        # Add SMB port
        profile.add_port(445, state='open', service='smb', source='test')

        # Add credential from HTTP
        profile.add_credential(
            username='admin',
            password='password123',
            service='http',
            port=80,
            source='test'
        )

        session = InteractiveSession(profile.target)
        session.profile = profile

        # Find correlations
        correlations = session._find_correlations()

        # Should find SMB + credential correlation
        smb_corrs = [c for c in correlations if c['type'] == 'service_credential']
        assert len(smb_corrs) > 0
        assert 'smb' in smb_corrs[0]['title'].lower()
        assert smb_corrs[0]['priority'] == 'high'

    def test_cve_version_correlation(self):
        """PROVES: Detects CVE + version correlation"""
        profile = TargetProfile('192.168.45.100')

        # Add Apache 2.4.41 (known CVE)
        profile.add_port(
            80,
            state='open',
            service='http',
            product='Apache httpd',
            version='2.4.41',
            source='test'
        )

        session = InteractiveSession(profile.target)
        session.profile = profile

        # Find correlations
        correlations = session._find_correlations()

        # Should find CVE correlation
        cve_corrs = [c for c in correlations if c['type'] == 'cve_match']
        assert len(cve_corrs) > 0
        assert 'apache' in cve_corrs[0]['title'].lower()
        assert '2.4.41' in cve_corrs[0]['title']
        assert 'CVE' in cve_corrs[0]['elements'][1]

    def test_credential_reuse_correlation(self):
        """PROVES: Detects credential reuse opportunities"""
        profile = TargetProfile('192.168.45.100')

        # Add multiple services
        profile.add_port(22, state='open', service='ssh', source='test')
        profile.add_port(445, state='open', service='smb', source='test')
        profile.add_port(3306, state='open', service='mysql', source='test')

        # Add credential from HTTP
        profile.add_credential(
            username='admin',
            password='password123',
            service='http',
            port=80,
            source='test'
        )

        session = InteractiveSession(profile.target)
        session.profile = profile

        # Find correlations
        correlations = session._find_correlations()

        # Should find credential reuse correlation
        reuse_corrs = [c for c in correlations if c['type'] == 'credential_reuse']
        assert len(reuse_corrs) > 0
        assert reuse_corrs[0]['priority'] == 'medium'
        assert 'reuse' in reuse_corrs[0]['title'].lower()

    def test_directory_upload_correlation(self):
        """PROVES: Detects upload directory patterns"""
        profile = TargetProfile('192.168.45.100')

        # Add web service
        profile.add_port(80, state='open', service='http', source='test')

        # Add upload/writable finding
        profile.add_finding(
            finding_type='directory',
            description='Writable upload directory found at /var/www/uploads',
            source='test'
        )

        session = InteractiveSession(profile.target)
        session.profile = profile

        # Find correlations
        correlations = session._find_correlations()

        # Should find upload correlation
        upload_corrs = [c for c in correlations if c['type'] == 'upload_directory']
        assert len(upload_corrs) > 0
        assert 'upload' in upload_corrs[0]['title'].lower()

    def test_correlation_ranking(self):
        """PROVES: Correlations are ranked by priority"""
        profile = TargetProfile('192.168.45.100')

        # Add data for multiple correlation types
        profile.add_port(445, state='open', service='smb', source='test')
        profile.add_port(80, state='open', service='http', source='test')

        profile.add_credential(
            username='admin',
            password='password123',
            service='http',
            source='test'
        )

        profile.add_finding(
            finding_type='directory',
            description='Upload directory',
            source='test'
        )

        session = InteractiveSession(profile.target)
        session.profile = profile

        # Find and rank correlations
        correlations = session._find_correlations()
        ranked = session._rank_correlations(correlations)

        # High priority should come first
        if len(ranked) > 1:
            first_priority = ranked[0]['priority']
            assert first_priority == 'high'

    def test_no_correlations_found(self):
        """PROVES: Handles case when no correlations exist"""
        profile = TargetProfile('192.168.45.100')

        # Only add a single port, no credentials or findings
        profile.add_port(80, state='open', service='http', source='test')

        session = InteractiveSession(profile.target)
        session.profile = profile

        # Find correlations
        correlations = session._find_correlations()

        # Should handle gracefully (may have some, may not)
        assert isinstance(correlations, list)

    def test_multiple_correlations(self):
        """PROVES: Can detect multiple correlation types simultaneously"""
        profile = TargetProfile('192.168.45.100')

        # Add complex scenario
        profile.add_port(445, state='open', service='smb', source='test')
        profile.add_port(80, state='open', service='http', product='Apache httpd', version='2.4.41', source='test')

        profile.add_credential(
            username='admin',
            password='password123',
            service='http',
            source='test'
        )

        profile.add_finding(
            finding_type='vulnerability',
            description='LFI vulnerability in file parameter',
            source='test'
        )

        profile.add_finding(
            finding_type='directory',
            description='Writable directory /var/www/upload',
            source='test'
        )

        session = InteractiveSession(profile.target)
        session.profile = profile

        # Find correlations
        correlations = session._find_correlations()

        # Should find multiple types
        assert len(correlations) >= 2
        correlation_types = {c['type'] for c in correlations}
        assert len(correlation_types) >= 2

    def test_recommendation_generation(self):
        """PROVES: Generates actionable recommendations"""
        profile = TargetProfile('192.168.45.100')

        # Add SMB + credentials
        profile.add_port(445, state='open', service='smb', source='test')

        profile.add_credential(
            username='admin',
            password='password123',
            service='http',
            source='test'
        )

        session = InteractiveSession(profile.target)
        session.profile = profile

        # Find correlations
        correlations = session._find_correlations()

        # Verify recommendation exists and is actionable
        smb_corrs = [c for c in correlations if c['type'] == 'service_credential']
        if smb_corrs:
            recommendation = smb_corrs[0]['recommendation']
            assert recommendation
            assert 'smbclient' in recommendation
            assert '192.168.45.100' in recommendation

    def test_lfi_upload_correlation(self):
        """PROVES: Detects LFI + writable directory correlation"""
        profile = TargetProfile('192.168.45.100')

        # Add LFI finding
        profile.add_finding(
            finding_type='vulnerability',
            description='LFI vulnerability in page parameter',
            source='test'
        )

        # Add writable directory
        profile.add_finding(
            finding_type='directory',
            description='Writable upload directory',
            source='test'
        )

        session = InteractiveSession(profile.target)
        session.profile = profile

        # Find correlations
        correlations = session._find_correlations()

        # Should find LFI + upload correlation
        lfi_corrs = [c for c in correlations if c['type'] == 'lfi_upload']
        assert len(lfi_corrs) > 0
        assert lfi_corrs[0]['priority'] == 'high'
        assert 'lfi' in lfi_corrs[0]['title'].lower()

    def test_sqli_database_correlation(self):
        """PROVES: Detects SQLi + database port correlation"""
        profile = TargetProfile('192.168.45.100')

        # Add MySQL port
        profile.add_port(3306, state='open', service='mysql', source='test')

        # Add SQLi finding
        profile.add_finding(
            finding_type='vulnerability',
            description='SQL injection in id parameter',
            source='test'
        )

        session = InteractiveSession(profile.target)
        session.profile = profile

        # Find correlations
        correlations = session._find_correlations()

        # Should find SQLi + DB correlation
        sqli_corrs = [c for c in correlations if c['type'] == 'sqli_db']
        assert len(sqli_corrs) > 0
        assert sqli_corrs[0]['priority'] == 'high'
        assert 'sql' in sqli_corrs[0]['title'].lower()

    def test_username_enumeration_correlation(self):
        """PROVES: Detects username enumeration pattern"""
        profile = TargetProfile('192.168.45.100')

        # Add SSH service
        profile.add_port(22, state='open', service='ssh', source='test')

        # Add user findings (no credentials yet)
        profile.add_finding(
            finding_type='user',
            description='Valid username: admin',
            source='test'
        )

        profile.add_finding(
            finding_type='user',
            description='Valid username: root',
            source='test'
        )

        session = InteractiveSession(profile.target)
        session.profile = profile

        # Find correlations
        correlations = session._find_correlations()

        # Should find username enumeration correlation
        user_corrs = [c for c in correlations if c['type'] == 'user_enum']
        assert len(user_corrs) > 0
        assert user_corrs[0]['priority'] == 'medium'

    def test_service_auth_command_generation(self):
        """PROVES: Generates correct authentication commands"""
        profile = TargetProfile('192.168.45.100')
        session = InteractiveSession(profile.target)
        session.profile = profile

        # Test SSH command
        ssh_cmd = session._get_service_auth_command('ssh', 22, 'admin', 'password123')
        assert 'ssh' in ssh_cmd
        assert 'admin' in ssh_cmd

        # Test SMB command
        smb_cmd = session._get_service_auth_command('smb', 445, 'admin', 'password123')
        assert 'smbclient' in smb_cmd
        assert '192.168.45.100' in smb_cmd

        # Test MySQL command
        mysql_cmd = session._get_service_auth_command('mysql', 3306, 'root', 'password')
        assert 'mysql' in mysql_cmd
        assert 'root' in mysql_cmd

    def test_known_vulnerability_detection(self):
        """PROVES: Detects known CVEs from product versions"""
        profile = TargetProfile('192.168.45.100')
        session = InteractiveSession(profile.target)
        session.profile = profile

        # Test Apache 2.4.41
        result = session._check_known_vulnerabilities('Apache httpd', '2.4.41')
        assert result is not None
        assert 'CVE' in result['cve_id']

        # Test vsftpd backdoor
        result = session._check_known_vulnerabilities('vsftpd', '2.3.4')
        assert result is not None
        assert 'Backdoor' in result['cve_id']

        # Test unknown version
        result = session._check_known_vulnerabilities('Apache httpd', '9.9.9')
        assert result is None

    def test_correlation_task_creation(self, capsys):
        """PROVES: Can create tasks from correlations"""
        profile = TargetProfile('192.168.45.100')

        # Add data for correlation
        profile.add_port(445, state='open', service='smb', source='test')

        profile.add_credential(
            username='admin',
            password='password123',
            service='http',
            source='test'
        )

        session = InteractiveSession(profile.target)
        session.profile = profile

        # Find correlations
        correlations = session._find_correlations()
        high_priority = [c for c in correlations if c['priority'] == 'high']

        # Create tasks
        if high_priority:
            initial_task_count = len(list(profile.task_tree.children))
            session._create_correlation_tasks(high_priority)

            # Verify tasks were created
            final_task_count = len(list(profile.task_tree.children))
            assert final_task_count > initial_task_count

            # Verify output
            captured = capsys.readouterr()
            assert 'Created' in captured.out

    def test_weak_auth_correlation(self):
        """PROVES: Detects weak authentication patterns"""
        profile = TargetProfile('192.168.45.100')

        # Add web service
        profile.add_port(80, state='open', service='http', source='test')

        # Add basic auth finding
        profile.add_finding(
            finding_type='vulnerability',
            description='HTTP Basic Authentication with no lockout',
            source='test'
        )

        session = InteractiveSession(profile.target)
        session.profile = profile

        # Find correlations
        correlations = session._find_correlations()

        # Should find weak auth correlation
        weak_auth_corrs = [c for c in correlations if c['type'] == 'weak_auth']
        assert len(weak_auth_corrs) > 0
        assert weak_auth_corrs[0]['priority'] == 'medium'


class TestEdgeCases:
    """Test edge cases and error handling"""

    def test_empty_profile(self):
        """PROVES: Handles empty profile gracefully"""
        profile = TargetProfile('192.168.45.100')
        session = InteractiveSession(profile.target)
        session.profile = profile

        # Find correlations on empty profile
        correlations = session._find_correlations()

        # Should return empty list, not error
        assert isinstance(correlations, list)
        assert len(correlations) == 0

    def test_credentials_without_services(self):
        """PROVES: Handles credentials with no matching services"""
        profile = TargetProfile('192.168.45.100')

        # Add credential but no compatible services
        profile.add_credential(
            username='admin',
            password='password123',
            service='http',
            source='test'
        )

        session = InteractiveSession(profile.target)
        session.profile = profile

        # Should not crash
        correlations = session._find_correlations()
        assert isinstance(correlations, list)

    def test_mixed_priority_ranking(self):
        """PROVES: Correctly ranks mixed priority correlations"""
        profile = TargetProfile('192.168.45.100')
        session = InteractiveSession(profile.target)

        # Create mock correlations with mixed priorities
        correlations = [
            {'priority': 'low', 'elements': ['a', 'b']},
            {'priority': 'high', 'elements': ['c', 'd', 'e']},
            {'priority': 'medium', 'elements': ['f']},
            {'priority': 'high', 'elements': ['g']}
        ]

        ranked = session._rank_correlations(correlations)

        # High priority should be first
        assert ranked[0]['priority'] == 'high'
        assert ranked[1]['priority'] == 'high'
        assert ranked[2]['priority'] == 'medium'
        assert ranked[3]['priority'] == 'low'

        # Within same priority, more elements first
        if ranked[0]['priority'] == ranked[1]['priority']:
            assert len(ranked[0]['elements']) >= len(ranked[1]['elements'])
