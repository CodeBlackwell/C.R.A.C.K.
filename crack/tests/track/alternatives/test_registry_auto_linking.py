"""
Tests for Alternative Commands Registry Auto-Linking (Phase 6.3)

Tests pattern matching, service matching, tag matching, and deduplication.
"""

import time
import pytest
from crack.track.alternatives.registry import AlternativeCommandRegistry
from crack.track.alternatives.models import AlternativeCommand, Variable
from crack.track.core.task_tree import TaskNode


class TestRegistryIndexing:
    """Test registry index population during registration"""

    def test_service_index_population(self):
        """PROVES: register() populates _by_service index correctly"""
        # Clear registry
        AlternativeCommandRegistry.clear()

        # Register HTTP alternative
        http_alt = AlternativeCommand(
            id='test-http-alt',
            name='Test HTTP',
            command_template='curl http://<TARGET>',
            category='web-enumeration',
            parent_task_pattern='http-*',
            tags=['OSCP:HIGH']
        )
        AlternativeCommandRegistry.register(http_alt)

        # Verify service index
        assert 'http' in AlternativeCommandRegistry._by_service
        assert 'test-http-alt' in AlternativeCommandRegistry._by_service['http']

    def test_tag_index_population(self):
        """PROVES: register() populates _by_tag index for all tags"""
        # Clear registry
        AlternativeCommandRegistry.clear()

        # Register alternative with multiple tags
        alt = AlternativeCommand(
            id='test-tagged-alt',
            name='Test Tagged',
            command_template='echo test',
            category='test',
            tags=['OSCP:HIGH', 'QUICK_WIN', 'NO_TOOLS']
        )
        AlternativeCommandRegistry.register(alt)

        # Verify tag indexes
        assert 'OSCP:HIGH' in AlternativeCommandRegistry._by_tag
        assert 'QUICK_WIN' in AlternativeCommandRegistry._by_tag
        assert 'NO_TOOLS' in AlternativeCommandRegistry._by_tag

        assert 'test-tagged-alt' in AlternativeCommandRegistry._by_tag['OSCP:HIGH']
        assert 'test-tagged-alt' in AlternativeCommandRegistry._by_tag['QUICK_WIN']
        assert 'test-tagged-alt' in AlternativeCommandRegistry._by_tag['NO_TOOLS']

    def test_service_extraction_from_pattern(self):
        """PROVES: _extract_service_type derives service from parent_task_pattern"""
        AlternativeCommandRegistry.clear()

        # Test HTTP patterns
        http_alt = AlternativeCommand(
            id='test1',
            name='Test',
            command_template='test',
            category='test',
            parent_task_pattern='gobuster-*'
        )
        service = AlternativeCommandRegistry._extract_service_type(http_alt)
        assert service == 'http', "gobuster should map to http service"

        # Test SMB patterns
        smb_alt = AlternativeCommand(
            id='test2',
            name='Test',
            command_template='test',
            category='test',
            parent_task_pattern='smb-*'
        )
        service = AlternativeCommandRegistry._extract_service_type(smb_alt)
        assert service == 'smb'

        # Test SSH patterns
        ssh_alt = AlternativeCommand(
            id='test3',
            name='Test',
            command_template='test',
            category='test',
            parent_task_pattern='ssh-*'
        )
        service = AlternativeCommandRegistry._extract_service_type(ssh_alt)
        assert service == 'ssh'

    def test_service_extraction_from_subcategory(self):
        """PROVES: _extract_service_type derives service from subcategory"""
        AlternativeCommandRegistry.clear()

        alt = AlternativeCommand(
            id='test',
            name='Test',
            command_template='test',
            category='enumeration',
            subcategory='http-methods'
        )
        service = AlternativeCommandRegistry._extract_service_type(alt)
        assert service == 'http', "http-methods subcategory should map to http service"


class TestPatternMatching:
    """Test glob pattern matching for task IDs"""

    def test_glob_pattern_matching_exact(self):
        """PROVES: auto_link_to_task matches exact glob patterns"""
        AlternativeCommandRegistry.clear()

        # Register alternative with pattern
        alt = AlternativeCommand(
            id='alt-gobuster-manual',
            name='Manual Gobuster',
            command_template='curl <TARGET>',
            category='web-enumeration',
            parent_task_pattern='gobuster-*',
            tags=[]
        )
        AlternativeCommandRegistry.register(alt)

        # Create task that matches pattern
        task = TaskNode(
            task_id='gobuster-80',
            name='Gobuster Port 80'
        )

        # Test auto-linking
        matches = AlternativeCommandRegistry.auto_link_to_task(task)
        assert 'alt-gobuster-manual' in matches

    def test_glob_pattern_matching_multiple_ports(self):
        """PROVES: Pattern matches multiple task instances (different ports)"""
        AlternativeCommandRegistry.clear()

        alt = AlternativeCommand(
            id='alt-http-manual',
            name='Manual HTTP',
            command_template='curl <TARGET>',
            category='web-enumeration',
            parent_task_pattern='http-*',
            tags=[]
        )
        AlternativeCommandRegistry.register(alt)

        # Test multiple task IDs with same pattern
        task_80 = TaskNode(task_id='http-80', name='HTTP 80')
        task_443 = TaskNode(task_id='http-443', name='HTTP 443')
        task_8080 = TaskNode(task_id='http-8080', name='HTTP 8080')

        matches_80 = AlternativeCommandRegistry.auto_link_to_task(task_80)
        matches_443 = AlternativeCommandRegistry.auto_link_to_task(task_443)
        matches_8080 = AlternativeCommandRegistry.auto_link_to_task(task_8080)

        assert 'alt-http-manual' in matches_80
        assert 'alt-http-manual' in matches_443
        assert 'alt-http-manual' in matches_8080

    def test_pattern_non_matching(self):
        """PROVES: Pattern does not match unrelated tasks"""
        AlternativeCommandRegistry.clear()

        alt = AlternativeCommand(
            id='alt-smb-enum',
            name='SMB Enum',
            command_template='smbclient <TARGET>',
            category='enumeration',
            parent_task_pattern='smb-*',
            tags=[]
        )
        AlternativeCommandRegistry.register(alt)

        # Create non-matching task
        http_task = TaskNode(task_id='http-80', name='HTTP 80')

        matches = AlternativeCommandRegistry.auto_link_to_task(http_task)
        assert 'alt-smb-enum' not in matches


class TestServiceMatching:
    """Test service-based matching from task metadata"""

    def test_service_matching_from_task_metadata(self):
        """PROVES: auto_link_to_task matches by service type in task metadata"""
        AlternativeCommandRegistry.clear()

        # Register HTTP alternative
        http_alt = AlternativeCommand(
            id='alt-http-test',
            name='HTTP Test',
            command_template='curl <TARGET>',
            category='web-enumeration',
            parent_task_pattern='http-*',
            tags=[]
        )
        AlternativeCommandRegistry.register(http_alt)

        # Create task with service metadata
        task = TaskNode(
            task_id='whatweb-80',
            name='WhatWeb Scan'
        )
        task.metadata['service'] = 'http'

        # Test service matching
        matches = AlternativeCommandRegistry.auto_link_to_task(task)
        assert 'alt-http-test' in matches

    def test_service_matching_multiple_alternatives(self):
        """PROVES: Multiple alternatives match same service"""
        AlternativeCommandRegistry.clear()

        # Register multiple HTTP alternatives
        alt1 = AlternativeCommand(
            id='alt-http-1',
            name='HTTP Alt 1',
            command_template='curl <TARGET>',
            category='web-enumeration',
            parent_task_pattern='http-*',
            tags=[]
        )
        alt2 = AlternativeCommand(
            id='alt-http-2',
            name='HTTP Alt 2',
            command_template='wget <TARGET>',
            category='web-enumeration',
            parent_task_pattern='gobuster-*',
            tags=[]
        )

        AlternativeCommandRegistry.register(alt1)
        AlternativeCommandRegistry.register(alt2)

        # Create task with http service
        task = TaskNode(task_id='nikto-80', name='Nikto Scan')
        task.metadata['service'] = 'http'

        matches = AlternativeCommandRegistry.auto_link_to_task(task)
        assert 'alt-http-1' in matches
        assert 'alt-http-2' in matches

    def test_service_matching_no_match(self):
        """PROVES: No match when service differs"""
        AlternativeCommandRegistry.clear()

        smb_alt = AlternativeCommand(
            id='alt-smb',
            name='SMB Test',
            command_template='smbclient <TARGET>',
            category='enumeration',
            parent_task_pattern='smb-*',
            tags=[]
        )
        AlternativeCommandRegistry.register(smb_alt)

        # Create HTTP task
        task = TaskNode(task_id='http-80', name='HTTP 80')
        task.metadata['service'] = 'http'

        matches = AlternativeCommandRegistry.auto_link_to_task(task)
        assert 'alt-smb' not in matches


class TestTagMatching:
    """Test tag-based matching from task metadata"""

    def test_tag_matching_oscp_high(self):
        """PROVES: auto_link_to_task matches alternatives with OSCP:HIGH tag"""
        AlternativeCommandRegistry.clear()

        alt = AlternativeCommand(
            id='alt-high-priority',
            name='High Priority',
            command_template='test',
            category='test',
            tags=['OSCP:HIGH', 'QUICK_WIN']
        )
        AlternativeCommandRegistry.register(alt)

        # Create task with OSCP:HIGH tag
        task = TaskNode(task_id='test-task', name='Test Task')
        task.metadata['tags'] = ['OSCP:HIGH']

        matches = AlternativeCommandRegistry.auto_link_to_task(task)
        assert 'alt-high-priority' in matches

    def test_tag_matching_quick_win(self):
        """PROVES: QUICK_WIN tag matching works"""
        AlternativeCommandRegistry.clear()

        alt = AlternativeCommand(
            id='alt-quick',
            name='Quick Win',
            command_template='test',
            category='test',
            tags=['QUICK_WIN', 'NO_TOOLS']
        )
        AlternativeCommandRegistry.register(alt)

        task = TaskNode(task_id='test-task', name='Test Task')
        task.metadata['tags'] = ['QUICK_WIN']

        matches = AlternativeCommandRegistry.auto_link_to_task(task)
        assert 'alt-quick' in matches

    def test_tag_matching_multiple_tags(self):
        """PROVES: Multiple tags increase match count"""
        AlternativeCommandRegistry.clear()

        # Register alternatives with different tags
        alt1 = AlternativeCommand(
            id='alt-tag-1',
            name='Alt 1',
            command_template='test',
            category='test',
            tags=['OSCP:HIGH']
        )
        alt2 = AlternativeCommand(
            id='alt-tag-2',
            name='Alt 2',
            command_template='test',
            category='test',
            tags=['QUICK_WIN']
        )
        alt3 = AlternativeCommand(
            id='alt-tag-both',
            name='Alt Both',
            command_template='test',
            category='test',
            tags=['OSCP:HIGH', 'QUICK_WIN']
        )

        AlternativeCommandRegistry.register(alt1)
        AlternativeCommandRegistry.register(alt2)
        AlternativeCommandRegistry.register(alt3)

        # Task with both tags
        task = TaskNode(task_id='test', name='Test')
        task.metadata['tags'] = ['OSCP:HIGH', 'QUICK_WIN']

        matches = AlternativeCommandRegistry.auto_link_to_task(task)
        assert 'alt-tag-1' in matches
        assert 'alt-tag-2' in matches
        assert 'alt-tag-both' in matches


class TestDeduplication:
    """Test deduplication of alternative IDs from multiple matches"""

    def test_deduplication_pattern_and_service(self):
        """PROVES: Deduplication when pattern and service both match"""
        AlternativeCommandRegistry.clear()

        # Alternative matches both by pattern and service
        alt = AlternativeCommand(
            id='alt-duplicate',
            name='Duplicate Match',
            command_template='curl <TARGET>',
            category='web-enumeration',
            parent_task_pattern='http-*',
            tags=[]
        )
        AlternativeCommandRegistry.register(alt)

        # Task matches both pattern and service
        task = TaskNode(task_id='http-80', name='HTTP 80')
        task.metadata['service'] = 'http'

        matches = AlternativeCommandRegistry.auto_link_to_task(task)

        # Should appear only once despite matching twice
        assert matches.count('alt-duplicate') == 1

    def test_deduplication_pattern_service_and_tag(self):
        """PROVES: Deduplication across pattern, service, and tag matches"""
        AlternativeCommandRegistry.clear()

        # Alternative matches pattern, service, AND tag
        alt = AlternativeCommand(
            id='alt-triple-match',
            name='Triple Match',
            command_template='curl <TARGET>',
            category='web-enumeration',
            parent_task_pattern='http-*',
            tags=['OSCP:HIGH']
        )
        AlternativeCommandRegistry.register(alt)

        # Task matches all three ways
        task = TaskNode(task_id='http-80', name='HTTP 80')
        task.metadata['service'] = 'http'
        task.metadata['tags'] = ['OSCP:HIGH']

        matches = AlternativeCommandRegistry.auto_link_to_task(task)

        # Should appear only once despite matching 3 times
        assert matches.count('alt-triple-match') == 1

    def test_deduplication_preserves_order(self):
        """PROVES: Deduplication preserves first occurrence order"""
        AlternativeCommandRegistry.clear()

        # Register in specific order
        alt1 = AlternativeCommand(
            id='alt-first',
            name='First',
            command_template='test',
            category='test',
            parent_task_pattern='test-*',
            tags=['TAG1']
        )
        alt2 = AlternativeCommand(
            id='alt-second',
            name='Second',
            command_template='test',
            category='test',
            parent_task_pattern='test-*',
            tags=['TAG2']
        )

        AlternativeCommandRegistry.register(alt1)
        AlternativeCommandRegistry.register(alt2)

        task = TaskNode(task_id='test-1', name='Test')
        task.metadata['tags'] = ['TAG1', 'TAG2']

        matches = AlternativeCommandRegistry.auto_link_to_task(task)

        # Order should be preserved
        assert matches.index('alt-first') < matches.index('alt-second')


class TestPerformance:
    """Test performance requirements (<100ms)"""

    def test_performance_under_100ms(self):
        """PROVES: auto_link_to_task completes in <100ms with realistic load"""
        AlternativeCommandRegistry.clear()

        # Register 50 alternatives (realistic scale)
        for i in range(50):
            alt = AlternativeCommand(
                id=f'alt-perf-{i}',
                name=f'Performance Test {i}',
                command_template='test',
                category='test',
                parent_task_pattern=f'test-{i % 5}*',
                tags=[f'TAG{i % 10}', 'OSCP:HIGH']
            )
            AlternativeCommandRegistry.register(alt)

        # Create task that matches some alternatives
        task = TaskNode(task_id='test-1-80', name='Test Task')
        task.metadata['service'] = 'http'
        task.metadata['tags'] = ['OSCP:HIGH', 'QUICK_WIN']

        # Measure performance
        start = time.perf_counter()
        matches = AlternativeCommandRegistry.auto_link_to_task(task)
        elapsed_ms = (time.perf_counter() - start) * 1000

        # Verify result
        assert len(matches) > 0, "Should find matches"

        # Performance requirement
        assert elapsed_ms < 100, f"auto_link_to_task took {elapsed_ms:.2f}ms (required: <100ms)"

    def test_performance_with_100_alternatives(self):
        """PROVES: Performance scales well with 100+ alternatives"""
        AlternativeCommandRegistry.clear()

        # Register 100 alternatives
        for i in range(100):
            alt = AlternativeCommand(
                id=f'alt-scale-{i}',
                name=f'Scale Test {i}',
                command_template='test',
                category='test',
                parent_task_pattern=f'pattern-{i % 10}*',
                tags=[f'TAG{i % 15}']
            )
            AlternativeCommandRegistry.register(alt)

        task = TaskNode(task_id='pattern-5-test', name='Test')
        task.metadata['tags'] = ['TAG5']

        start = time.perf_counter()
        matches = AlternativeCommandRegistry.auto_link_to_task(task)
        elapsed_ms = (time.perf_counter() - start) * 1000

        assert len(matches) > 0
        assert elapsed_ms < 100, f"Performance degraded: {elapsed_ms:.2f}ms"


class TestRealWorldScenarios:
    """Test realistic OSCP workflow scenarios"""

    def test_gobuster_task_gets_http_alternatives(self):
        """PROVES: Gobuster task auto-links to HTTP enumeration alternatives"""
        AlternativeCommandRegistry.clear()

        # Register realistic HTTP alternatives
        alt1 = AlternativeCommand(
            id='alt-manual-curl',
            name='Manual Curl Directory Check',
            command_template='curl http://<TARGET>:<PORT>/<DIR>',
            category='web-enumeration',
            parent_task_pattern='gobuster-*',
            tags=['MANUAL', 'NO_TOOLS']
        )
        alt2 = AlternativeCommand(
            id='alt-robots-check',
            name='Check robots.txt',
            command_template='curl http://<TARGET>:<PORT>/robots.txt',
            category='web-enumeration',
            parent_task_pattern='http-*',
            tags=['QUICK_WIN', 'OSCP:HIGH']
        )

        AlternativeCommandRegistry.register(alt1)
        AlternativeCommandRegistry.register(alt2)

        # Create gobuster task
        task = TaskNode(
            task_id='gobuster-80',
            name='Directory Brute-force (Port 80)'
        )
        task.metadata['service'] = 'http'
        task.metadata['port'] = 80
        task.metadata['tags'] = ['OSCP:HIGH']

        matches = AlternativeCommandRegistry.auto_link_to_task(task)

        assert 'alt-manual-curl' in matches
        assert 'alt-robots-check' in matches

    def test_smb_task_gets_smb_alternatives(self):
        """PROVES: SMB enumeration task auto-links to SMB alternatives"""
        AlternativeCommandRegistry.clear()

        alt = AlternativeCommand(
            id='alt-smbclient-manual',
            name='Manual SMB Enumeration',
            command_template='smbclient -L //<TARGET> -N',
            category='enumeration',
            parent_task_pattern='smb-*',
            tags=['MANUAL', 'OSCP:HIGH']
        )
        AlternativeCommandRegistry.register(alt)

        task = TaskNode(task_id='smb-enum-445', name='SMB Enumeration')
        task.metadata['service'] = 'smb'
        task.metadata['port'] = 445

        matches = AlternativeCommandRegistry.auto_link_to_task(task)
        assert 'alt-smbclient-manual' in matches

    def test_task_with_no_matches(self):
        """PROVES: Tasks with no matching alternatives return empty list"""
        AlternativeCommandRegistry.clear()

        # Register HTTP alternative
        alt = AlternativeCommand(
            id='alt-http',
            name='HTTP',
            command_template='curl',
            category='web',
            parent_task_pattern='http-*',
            tags=[]
        )
        AlternativeCommandRegistry.register(alt)

        # Create completely unrelated task
        task = TaskNode(task_id='custom-manual-test', name='Custom Task')
        task.metadata['service'] = 'unknown'

        matches = AlternativeCommandRegistry.auto_link_to_task(task)
        assert matches == []
