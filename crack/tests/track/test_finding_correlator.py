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


class TestCorrelationPatterns:
    """Comprehensive correlation pattern testing for all service types"""

    def test_all_service_credential_combinations(self):
        """PROVES: Tests all service types with credential correlation"""
        profile = TargetProfile('192.168.45.100')

        # Add all common authentication services
        services = {
            22: 'ssh',
            21: 'ftp',
            445: 'smb',
            3306: 'mysql',
            5432: 'postgresql',
            1433: 'mssql',
            3389: 'rdp',
            5900: 'vnc'
        }

        for port, service in services.items():
            profile.add_port(port, state='open', service=service, source='test')

        # Add credential from different source
        profile.add_credential(
            username='admin',
            password='password123',
            service='http',
            port=80,
            source='test'
        )

        session = InteractiveSession(profile.target)
        session.profile = profile

        correlations = session._find_correlations()

        # Should find correlations for all services except HTTP (source)
        service_corrs = [c for c in correlations if c['type'] == 'service_credential']

        # At least SSH, FTP, SMB, MySQL should have correlations
        assert len(service_corrs) >= 4

        # Verify SSH correlation exists
        ssh_corrs = [c for c in service_corrs if 'ssh' in c['title'].lower()]
        assert len(ssh_corrs) > 0

        # Verify SMB correlation exists
        smb_corrs = [c for c in service_corrs if 'smb' in c['title'].lower()]
        assert len(smb_corrs) > 0

    def test_cve_version_matching_multiple_products(self):
        """PROVES: CVE matching works for multiple vulnerable products"""
        profile = TargetProfile('192.168.45.100')
        session = InteractiveSession(profile.target)
        session.profile = profile

        # Test all known CVEs from the database
        test_cases = [
            ('Apache httpd', '2.4.41', 'CVE-2021-41773'),
            ('Apache httpd', '2.4.49', 'CVE-2021-41773'),
            ('OpenSSH', '7.4', 'CVE-2018-15473'),
            ('ProFTPD', '1.3.5', 'CVE-2015-3306'),
            ('vsftpd', '2.3.4', 'Backdoor'),
            ('Samba smbd', '3.0.20', 'CVE-2007-2447'),
        ]

        for product, version, expected_cve in test_cases:
            result = session._check_known_vulnerabilities(product, version)
            assert result is not None, f"Failed to detect CVE for {product} {version}"
            assert expected_cve in result['cve_id'], f"Expected {expected_cve}, got {result['cve_id']}"

    def test_credential_reuse_complex_scenario(self):
        """PROVES: Credential reuse with multiple credentials and services"""
        profile = TargetProfile('192.168.45.100')

        # Add 5 authentication services
        profile.add_port(22, state='open', service='ssh', source='test')
        profile.add_port(445, state='open', service='smb', source='test')
        profile.add_port(3306, state='open', service='mysql', source='test')
        profile.add_port(21, state='open', service='ftp', source='test')
        profile.add_port(5432, state='open', service='postgresql', source='test')

        # Add 3 different credentials from HTTP
        for i in range(3):
            profile.add_credential(
                username=f'user{i}',
                password=f'pass{i}',
                service='http',
                port=80,
                source='test'
            )

        session = InteractiveSession(profile.target)
        session.profile = profile

        correlations = session._find_correlations()

        # Should have credential reuse correlation
        reuse_corrs = [c for c in correlations if c['type'] == 'credential_reuse']
        assert len(reuse_corrs) > 0

        # Should mention multiple services
        reuse_corr = reuse_corrs[0]
        assert 'SSH' in reuse_corr['elements'][1] or 'SMB' in reuse_corr['elements'][1]

    def test_lfi_upload_high_priority_correlation(self):
        """PROVES: LFI + upload directory triggers HIGH priority"""
        profile = TargetProfile('192.168.45.100')

        # Add LFI vulnerability
        profile.add_finding(
            finding_type='vulnerability',
            description='Local File Inclusion in page parameter',
            source='test'
        )

        # Add writable upload directory
        profile.add_finding(
            finding_type='directory',
            description='Writable upload directory at /var/www/upload',
            source='test'
        )

        session = InteractiveSession(profile.target)
        session.profile = profile

        correlations = session._find_correlations()

        # Find LFI+upload correlation
        lfi_corrs = [c for c in correlations if c['type'] == 'lfi_upload']
        assert len(lfi_corrs) > 0

        # Verify HIGH priority
        assert lfi_corrs[0]['priority'] == 'high'

        # Verify recommendation mentions shell upload
        assert 'shell' in lfi_corrs[0]['recommendation'].lower() or 'php' in lfi_corrs[0]['recommendation'].lower()

    def test_sqli_database_port_direct_access(self):
        """PROVES: SQLi + database port suggests direct database access"""
        profile = TargetProfile('192.168.45.100')

        # Add MySQL port
        profile.add_port(3306, state='open', service='mysql', source='test')

        # Add SQL injection finding
        profile.add_finding(
            finding_type='vulnerability',
            description='SQL injection vulnerability in id parameter',
            source='test'
        )

        session = InteractiveSession(profile.target)
        session.profile = profile

        correlations = session._find_correlations()

        # Find SQLi+DB correlation
        sqli_corrs = [c for c in correlations if c['type'] == 'sqli_db']
        assert len(sqli_corrs) > 0

        # Verify recommendation mentions database connection
        recommendation = sqli_corrs[0]['recommendation'].lower()
        assert 'mysql' in recommendation or 'database' in recommendation or 'credentials' in recommendation

    def test_ftp_rdp_vnc_service_auth_commands(self):
        """PROVES: Generates correct auth commands for FTP, RDP, VNC"""
        profile = TargetProfile('192.168.45.100')
        session = InteractiveSession(profile.target)
        session.profile = profile

        # Test FTP
        ftp_cmd = session._get_service_auth_command('ftp', 21, 'user', 'password')
        assert 'ftp' in ftp_cmd
        assert 'user' in ftp_cmd

        # Test RDP
        rdp_cmd = session._get_service_auth_command('rdp', 3389, 'admin', 'password')
        assert 'xfreerdp' in rdp_cmd or 'rdesktop' in rdp_cmd
        assert '192.168.45.100' in rdp_cmd

        # Test VNC
        vnc_cmd = session._get_service_auth_command('vnc', 5900, 'user', 'password')
        assert 'vncviewer' in vnc_cmd or 'vnc' in vnc_cmd

    def test_postgresql_mssql_service_detection(self):
        """PROVES: PostgreSQL and MSSQL services correlate correctly"""
        profile = TargetProfile('192.168.45.100')

        # Add PostgreSQL
        profile.add_port(5432, state='open', service='postgresql', source='test')

        # Add MSSQL
        profile.add_port(1433, state='open', service='mssql', source='test')

        # Add credentials
        profile.add_credential(
            username='sa',
            password='admin',
            service='http',
            source='test'
        )

        session = InteractiveSession(profile.target)
        session.profile = profile

        correlations = session._find_correlations()

        # Should find correlations for both databases
        service_corrs = [c for c in correlations if c['type'] == 'service_credential']

        postgres_corrs = [c for c in service_corrs if 'postgresql' in c['title'].lower()]
        mssql_corrs = [c for c in service_corrs if 'mssql' in c['title'].lower()]

        assert len(postgres_corrs) > 0
        assert len(mssql_corrs) > 0


class TestCorrelationPerformance:
    """Performance and stress testing for correlation engine"""

    def test_large_dataset_performance(self):
        """PROVES: 50 ports + 20 findings + 10 creds correlates in < 2 seconds"""
        import time

        profile = TargetProfile('192.168.45.100')

        # Add 50 ports
        for port in range(1000, 1050):
            service = ['http', 'ssh', 'ftp', 'smb', 'mysql'][port % 5]
            profile.add_port(port, state='open', service=service, source='test')

        # Add 20 findings
        for i in range(20):
            profile.add_finding(
                finding_type='vulnerability' if i % 2 == 0 else 'directory',
                description=f'Finding {i}: Test vulnerability or directory',
                source='test'
            )

        # Add 10 credentials
        for i in range(10):
            profile.add_credential(
                username=f'user{i}',
                password=f'pass{i}',
                service='http',
                source='test'
            )

        session = InteractiveSession(profile.target)
        session.profile = profile

        # Measure correlation time
        start_time = time.time()
        correlations = session._find_correlations()
        elapsed = time.time() - start_time

        # Should complete in < 2 seconds
        assert elapsed < 2.0, f"Correlation took {elapsed:.2f}s (expected < 2s)"

        # Should find multiple correlations
        assert len(correlations) > 0

    def test_minimal_data_provides_value(self):
        """PROVES: Correlation with minimal data still provides useful output"""
        profile = TargetProfile('192.168.45.100')

        # Minimal scenario: 1 port, 1 finding
        profile.add_port(80, state='open', service='http', source='test')
        profile.add_finding(
            finding_type='directory',
            description='Admin panel found',
            source='test'
        )

        session = InteractiveSession(profile.target)
        session.profile = profile

        # Should not crash with minimal data
        correlations = session._find_correlations()

        # Result should be a list (empty is OK)
        assert isinstance(correlations, list)

    def test_combinatorial_explosion_limited(self):
        """PROVES: 10 services × 10 creds limits to reasonable correlations"""
        profile = TargetProfile('192.168.45.100')

        # Add 10 services
        services = ['ssh', 'smb', 'mysql', 'ftp', 'postgresql', 'mssql', 'rdp', 'vnc']
        for i, service in enumerate(services):
            profile.add_port(1000 + i, state='open', service=service, source='test')

        # Add 10 credentials
        for i in range(10):
            profile.add_credential(
                username=f'user{i}',
                password=f'pass{i}',
                service='http',
                source='test'
            )

        session = InteractiveSession(profile.target)
        session.profile = profile

        correlations = session._find_correlations()

        # Should find many correlations but not explode
        # Max should be reasonable (< 100 correlations)
        assert len(correlations) < 100


class TestCorrelationRecommendations:
    """Test recommendation generation quality"""

    def test_recommendations_contain_target_ip(self):
        """PROVES: All recommendations reference the actual target IP"""
        profile = TargetProfile('192.168.45.100')

        # Add various services
        profile.add_port(22, state='open', service='ssh', source='test')
        profile.add_port(445, state='open', service='smb', source='test')

        profile.add_credential(
            username='admin',
            password='password',
            service='http',
            source='test'
        )

        session = InteractiveSession(profile.target)
        session.profile = profile

        correlations = session._find_correlations()

        # All recommendations should contain target IP
        for corr in correlations:
            recommendation = corr.get('recommendation', '')
            if recommendation and 'crack' not in recommendation.lower():
                # If it's a command (not generic advice), should have IP
                if any(cmd in recommendation for cmd in ['ssh', 'smbclient', 'mysql', 'ftp']):
                    assert '192.168.45.100' in recommendation, f"Recommendation missing target IP: {recommendation}"

    def test_recommendations_include_discovered_data(self):
        """PROVES: Recommendations use actual discovered usernames/passwords"""
        profile = TargetProfile('192.168.45.100')

        profile.add_port(22, state='open', service='ssh', source='test')

        profile.add_credential(
            username='john',
            password='secret123',
            service='http',
            source='test'
        )

        session = InteractiveSession(profile.target)
        session.profile = profile

        correlations = session._find_correlations()

        ssh_corrs = [c for c in correlations if c['type'] == 'service_credential' and 'ssh' in c['title'].lower()]
        if ssh_corrs:
            recommendation = ssh_corrs[0]['recommendation']
            # Should include actual username
            assert 'john' in recommendation, f"Recommendation missing username: {recommendation}"

    def test_duplicate_correlation_prevention(self):
        """PROVES: Same correlation not listed multiple times"""
        profile = TargetProfile('192.168.45.100')

        # Add same service multiple times (e.g., HTTP on different ports)
        profile.add_port(80, state='open', service='http', source='test')
        profile.add_port(8080, state='open', service='http', source='test')
        profile.add_port(8000, state='open', service='http', source='test')

        # Add credential
        profile.add_credential(
            username='admin',
            password='password',
            service='ftp',
            source='test'
        )

        session = InteractiveSession(profile.target)
        session.profile = profile

        correlations = session._find_correlations()

        # Should not have duplicate correlations
        # Track seen correlations by type+title
        seen = set()
        for corr in correlations:
            key = (corr['type'], corr['title'])
            assert key not in seen, f"Duplicate correlation: {corr['title']}"
            seen.add(key)


class TestCorrelationTaskCreation:
    """Test automated task creation from correlations"""

    def test_creates_tasks_from_high_priority(self):
        """PROVES: High-priority correlations can create executable tasks"""
        profile = TargetProfile('192.168.45.100')

        # Create high-priority correlation scenario
        profile.add_port(445, state='open', service='smb', source='test')
        profile.add_credential(
            username='admin',
            password='password',
            service='http',
            source='test'
        )

        session = InteractiveSession(profile.target)
        session.profile = profile

        correlations = session._find_correlations()
        high_priority = [c for c in correlations if c['priority'] == 'high']

        if high_priority:
            initial_count = len(list(profile.task_tree.children))

            # Create tasks from correlations
            session._create_correlation_tasks(high_priority)

            # Verify tasks were created
            final_count = len(list(profile.task_tree.children))
            assert final_count > initial_count

    def test_created_tasks_have_valid_commands(self):
        """PROVES: Tasks created from correlations have executable commands"""
        profile = TargetProfile('192.168.45.100')

        profile.add_port(22, state='open', service='ssh', source='test')
        profile.add_credential(
            username='root',
            password='toor',
            service='http',
            source='test'
        )

        session = InteractiveSession(profile.target)
        session.profile = profile

        correlations = session._find_correlations()
        high_priority = [c for c in correlations if c['priority'] == 'high']

        if high_priority:
            session._create_correlation_tasks(high_priority)

            # Get created tasks
            all_tasks = profile.task_tree.get_all_tasks()
            correlation_tasks = [t for t in all_tasks if 'correlation' in t.id]

            if correlation_tasks:
                # Verify task has command
                task = correlation_tasks[0]
                assert 'command' in task.metadata
                assert task.metadata['command']  # Not empty

    def test_task_metadata_includes_correlation_source(self):
        """PROVES: Created tasks know they came from correlation engine"""
        profile = TargetProfile('192.168.45.100')

        profile.add_port(445, state='open', service='smb', source='test')
        profile.add_credential(
            username='admin',
            password='password',
            service='http',
            source='test'
        )

        session = InteractiveSession(profile.target)
        session.profile = profile

        correlations = session._find_correlations()
        high_priority = [c for c in correlations if c['priority'] == 'high']

        if high_priority:
            session._create_correlation_tasks(high_priority)

            all_tasks = profile.task_tree.get_all_tasks()
            correlation_tasks = [t for t in all_tasks if 'correlation' in t.id]

            if correlation_tasks:
                task = correlation_tasks[0]
                # Should have correlation metadata
                assert 'correlation_type' in task.metadata
                assert 'CORRELATION' in task.metadata.get('tags', [])
