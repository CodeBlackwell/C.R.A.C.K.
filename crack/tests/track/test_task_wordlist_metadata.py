"""
Tests for TaskNode wordlist metadata integration (Phase 4)

Validates that tasks can store and persist wordlist selection metadata
without breaking backward compatibility with existing profiles.
"""

import json
import pytest
from datetime import datetime
from crack.track.core.task_tree import TaskNode


class TestWordlistMetadataStorage:
    """Test wordlist metadata storage in TaskNode"""

    def test_default_wordlist_metadata_on_new_task(self):
        """PROVES: New tasks have default wordlist metadata fields"""
        task = TaskNode(
            task_id='test-task-1',
            name='Test Task',
            task_type='command'
        )

        # Verify default wordlist fields exist
        assert 'wordlist' in task.metadata
        assert 'wordlist_purpose' in task.metadata
        assert 'wordlist_variant' in task.metadata

        # Verify default values
        assert task.metadata['wordlist'] is None
        assert task.metadata['wordlist_purpose'] is None
        assert task.metadata['wordlist_variant'] == 'default'

    def test_set_wordlist_metadata_on_task(self):
        """PROVES: Wordlist metadata can be set on tasks"""
        task = TaskNode(
            task_id='gobuster-80',
            name='Directory Brute-force',
            task_type='command'
        )

        # Set wordlist metadata
        task.metadata['wordlist'] = '/usr/share/wordlists/dirb/common.txt'
        task.metadata['wordlist_purpose'] = 'web-enumeration'
        task.metadata['wordlist_variant'] = 'quick'

        # Verify values stored
        assert task.metadata['wordlist'] == '/usr/share/wordlists/dirb/common.txt'
        assert task.metadata['wordlist_purpose'] == 'web-enumeration'
        assert task.metadata['wordlist_variant'] == 'quick'

    def test_wordlist_metadata_persists_across_children(self):
        """PROVES: Child tasks inherit their own metadata (not parent's)"""
        parent = TaskNode(
            task_id='parent',
            name='Parent Task',
            task_type='parent'
        )
        parent.metadata['wordlist_purpose'] = 'web-enumeration'

        child = TaskNode(
            task_id='child',
            name='Child Task',
            task_type='command',
            parent=parent
        )

        # Child has default values (not parent's)
        assert child.metadata['wordlist_purpose'] is None

        # Can set independently
        child.metadata['wordlist_purpose'] = 'password-cracking'
        assert child.metadata['wordlist_purpose'] == 'password-cracking'
        assert parent.metadata['wordlist_purpose'] == 'web-enumeration'


class TestTaskSerialization:
    """Test task serialization/deserialization with wordlist metadata"""

    def test_to_dict_includes_wordlist_metadata(self):
        """PROVES: to_dict() includes wordlist metadata"""
        task = TaskNode(
            task_id='gobuster-80',
            name='Directory Brute-force',
            task_type='command'
        )
        task.metadata['wordlist'] = '/usr/share/wordlists/dirb/common.txt'
        task.metadata['wordlist_purpose'] = 'web-enumeration'
        task.metadata['wordlist_variant'] = 'thorough'

        serialized = task.to_dict()

        # Verify wordlist fields in serialization
        assert 'metadata' in serialized
        assert serialized['metadata']['wordlist'] == '/usr/share/wordlists/dirb/common.txt'
        assert serialized['metadata']['wordlist_purpose'] == 'web-enumeration'
        assert serialized['metadata']['wordlist_variant'] == 'thorough'

    def test_from_dict_restores_wordlist_metadata(self):
        """PROVES: from_dict() restores wordlist metadata"""
        data = {
            'id': 'gobuster-80',
            'name': 'Directory Brute-force',
            'type': 'command',
            'status': 'pending',
            'metadata': {
                'command': 'gobuster dir -u http://target:80 -w common.txt',
                'wordlist': '/usr/share/wordlists/dirb/common.txt',
                'wordlist_purpose': 'web-enumeration',
                'wordlist_variant': 'quick',
                'tags': ['OSCP:HIGH']
            },
            'children': []
        }

        task = TaskNode.from_dict(data)

        # Verify wordlist metadata restored
        assert task.metadata['wordlist'] == '/usr/share/wordlists/dirb/common.txt'
        assert task.metadata['wordlist_purpose'] == 'web-enumeration'
        assert task.metadata['wordlist_variant'] == 'quick'

    def test_roundtrip_preserves_wordlist_metadata(self):
        """PROVES: Serialize → deserialize preserves wordlist metadata"""
        original = TaskNode(
            task_id='ssh-bruteforce-22',
            name='SSH Credential Brute-force',
            task_type='command'
        )
        original.metadata['wordlist'] = '/usr/share/wordlists/rockyou.txt'
        original.metadata['wordlist_purpose'] = 'password-cracking'
        original.metadata['wordlist_variant'] = 'default'
        original.metadata['command'] = 'hydra -P rockyou.txt ssh://target'

        # Serialize
        serialized = original.to_dict()

        # Deserialize
        restored = TaskNode.from_dict(serialized)

        # Verify exact match
        assert restored.id == original.id
        assert restored.metadata['wordlist'] == original.metadata['wordlist']
        assert restored.metadata['wordlist_purpose'] == original.metadata['wordlist_purpose']
        assert restored.metadata['wordlist_variant'] == original.metadata['wordlist_variant']
        assert restored.metadata['command'] == original.metadata['command']


class TestBackwardCompatibility:
    """Test backward compatibility with existing profiles"""

    def test_old_task_without_wordlist_fields_loads_successfully(self):
        """PROVES: Tasks without wordlist fields load with defaults"""
        # Simulate old task saved before Phase 4 implementation
        old_task_data = {
            'id': 'old-task',
            'name': 'Old Task',
            'type': 'command',
            'status': 'pending',
            'metadata': {
                'command': 'nmap -sV target',
                'tags': ['OSCP:HIGH'],
                # NO wordlist fields (simulates pre-Phase 4 save)
            },
            'children': []
        }

        # Load old task
        task = TaskNode.from_dict(old_task_data)

        # Verify task loads successfully
        assert task.id == 'old-task'
        assert task.metadata['command'] == 'nmap -sV target'

        # Verify wordlist fields get defaults (backward compatibility)
        assert 'wordlist' in task.metadata
        assert task.metadata['wordlist'] is None
        assert task.metadata['wordlist_purpose'] is None
        assert task.metadata['wordlist_variant'] == 'default'

    def test_old_task_can_be_updated_with_wordlist_metadata(self):
        """PROVES: Old tasks can be updated with wordlist metadata"""
        old_task_data = {
            'id': 'gobuster-80',
            'name': 'Directory Brute-force',
            'type': 'command',
            'status': 'pending',
            'metadata': {
                'command': 'gobuster dir -u http://target:80 -w common.txt',
                'tags': ['OSCP:HIGH']
                # NO wordlist fields
            },
            'children': []
        }

        # Load old task
        task = TaskNode.from_dict(old_task_data)

        # Update with wordlist metadata
        task.metadata['wordlist'] = '/usr/share/wordlists/dirb/common.txt'
        task.metadata['wordlist_purpose'] = 'web-enumeration'

        # Verify update successful
        assert task.metadata['wordlist'] == '/usr/share/wordlists/dirb/common.txt'
        assert task.metadata['wordlist_purpose'] == 'web-enumeration'

        # Verify task still functional
        serialized = task.to_dict()
        restored = TaskNode.from_dict(serialized)
        assert restored.metadata['wordlist'] == '/usr/share/wordlists/dirb/common.txt'

    def test_mixed_tasks_with_and_without_wordlist_metadata(self):
        """PROVES: Task tree with mixed old/new tasks works correctly"""
        # Parent task (new, has wordlist metadata)
        parent = TaskNode(
            task_id='http-enum-80',
            name='HTTP Enumeration',
            task_type='parent'
        )
        parent.metadata['wordlist_purpose'] = 'web-enumeration'

        # Child 1: New task with wordlist metadata
        child1_data = {
            'id': 'gobuster-80',
            'name': 'Directory Brute-force',
            'type': 'command',
            'status': 'pending',
            'metadata': {
                'wordlist': '/usr/share/wordlists/dirb/common.txt',
                'wordlist_purpose': 'web-enumeration',
                'wordlist_variant': 'quick'
            },
            'children': []
        }
        child1 = TaskNode.from_dict(child1_data, parent=parent)

        # Child 2: Old task WITHOUT wordlist metadata
        child2_data = {
            'id': 'nikto-80',
            'name': 'Nikto Scan',
            'type': 'command',
            'status': 'pending',
            'metadata': {
                'command': 'nikto -h http://target:80'
                # NO wordlist fields
            },
            'children': []
        }
        child2 = TaskNode.from_dict(child2_data, parent=parent)

        parent.children = [child1, child2]

        # Serialize entire tree
        serialized = parent.to_dict()

        # Deserialize
        restored_parent = TaskNode.from_dict(serialized)

        # Verify both children present and correct
        assert len(restored_parent.children) == 2

        # Child 1 (new): Has wordlist metadata
        assert restored_parent.children[0].metadata['wordlist'] == '/usr/share/wordlists/dirb/common.txt'
        assert restored_parent.children[0].metadata['wordlist_purpose'] == 'web-enumeration'

        # Child 2 (old): Has default wordlist metadata
        assert restored_parent.children[1].metadata['wordlist'] is None
        assert restored_parent.children[1].metadata['wordlist_purpose'] is None
        assert restored_parent.children[1].metadata['command'] == 'nikto -h http://target:80'


class TestServicePluginIntegration:
    """Test service plugins set wordlist_purpose correctly"""

    def test_http_plugin_sets_wordlist_purpose(self):
        """PROVES: HTTP plugin sets wordlist_purpose for gobuster"""
        from crack.track.services.http import HTTPPlugin

        plugin = HTTPPlugin()
        service_info = {
            'service': 'http',
            'version': 'Apache 2.4.41',
            'port': 80
        }

        task_tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        # Find gobuster task
        gobuster_task = None
        for child in task_tree['children']:
            if child['id'] == 'gobuster-80':
                gobuster_task = child
                break

        assert gobuster_task is not None
        assert gobuster_task['metadata']['wordlist_purpose'] == 'web-enumeration'

    def test_ssh_plugin_sets_wordlist_purpose(self):
        """PROVES: SSH plugin sets wordlist_purpose for hydra"""
        from crack.track.services.ssh import SSHPlugin

        plugin = SSHPlugin()
        service_info = {
            'service': 'ssh',
            'version': 'OpenSSH 7.4',
            'port': 22
        }

        task_tree = plugin.get_task_tree('192.168.45.100', 22, service_info)

        # Find SSH brute-force task
        bruteforce_task = None
        for child in task_tree['children']:
            if child['id'] == 'ssh-bruteforce-22':
                bruteforce_task = child
                break

        assert bruteforce_task is not None
        assert bruteforce_task['metadata']['wordlist_purpose'] == 'password-cracking'

    def test_ftp_plugin_sets_wordlist_purpose(self):
        """PROVES: FTP plugin sets wordlist_purpose for hydra"""
        from crack.track.services.ftp import FTPPlugin

        plugin = FTPPlugin()
        service_info = {
            'service': 'ftp',
            'version': 'vsftpd 3.0.3',
            'port': 21
        }

        task_tree = plugin.get_task_tree('192.168.45.100', 21, service_info)

        # Find FTP brute-force task (full)
        bruteforce_task = None
        for child in task_tree['children']:
            if child['id'] == 'ftp-bruteforce-21':
                # This is the parent, look in children
                for subchild in child.get('children', []):
                    if subchild['id'] == 'ftp-bruteforce-full-21':
                        bruteforce_task = subchild
                        break
                break

        assert bruteforce_task is not None
        assert bruteforce_task['metadata']['wordlist_purpose'] == 'password-cracking'


class TestWordlistPurposeValues:
    """Test wordlist_purpose taxonomy"""

    def test_valid_wordlist_purposes(self):
        """PROVES: Common wordlist purposes are documented"""
        valid_purposes = [
            'web-enumeration',      # Directory/file brute-forcing
            'password-cracking',    # Credential attacks
            'subdomain-enum',       # DNS subdomain enumeration
            'parameter-fuzzing',    # HTTP parameter discovery
            'username-enum',        # Username enumeration
            'general'               # Generic wordlist
        ]

        # Create tasks with each purpose
        for purpose in valid_purposes:
            task = TaskNode(
                task_id=f'task-{purpose}',
                name=f'Task {purpose}',
                task_type='command'
            )
            task.metadata['wordlist_purpose'] = purpose

            # Verify value accepted
            assert task.metadata['wordlist_purpose'] == purpose

    def test_wordlist_variant_values(self):
        """PROVES: Wordlist variants are documented"""
        valid_variants = [
            'default',    # Standard wordlist
            'quick',      # Small/fast wordlist
            'thorough',   # Large/comprehensive wordlist
            'custom'      # User-provided wordlist
        ]

        for variant in valid_variants:
            task = TaskNode(
                task_id=f'task-{variant}',
                name=f'Task {variant}',
                task_type='command'
            )
            task.metadata['wordlist_variant'] = variant

            assert task.metadata['wordlist_variant'] == variant


class TestRealWorldScenarios:
    """Test real OSCP workflow scenarios"""

    def test_user_selects_wordlist_for_gobuster_task(self):
        """
        PROVES: User workflow - Select wordlist for gobuster task

        Scenario:
        1. System generates gobuster task (from HTTP plugin)
        2. User selects wordlist in interactive mode
        3. Wordlist metadata saved to task
        4. Profile persisted to disk
        5. Profile reloaded - wordlist selection intact
        """
        # Step 1: Create gobuster task (simulates HTTP plugin)
        task = TaskNode(
            task_id='gobuster-80',
            name='Directory Brute-force',
            task_type='command'
        )
        task.metadata['command'] = 'gobuster dir -u http://192.168.45.100:80 -w <WORDLIST>'
        task.metadata['wordlist_purpose'] = 'web-enumeration'

        # Verify initial state
        assert task.metadata['wordlist'] is None

        # Step 2: User selects wordlist
        task.metadata['wordlist'] = '/usr/share/wordlists/dirb/common.txt'
        task.metadata['wordlist_variant'] = 'quick'

        # Step 3: Serialize (save)
        saved_data = task.to_dict()

        # Step 4: Deserialize (load)
        loaded_task = TaskNode.from_dict(saved_data)

        # Step 5: Verify wordlist selection persisted
        assert loaded_task.metadata['wordlist'] == '/usr/share/wordlists/dirb/common.txt'
        assert loaded_task.metadata['wordlist_purpose'] == 'web-enumeration'
        assert loaded_task.metadata['wordlist_variant'] == 'quick'
        assert loaded_task.metadata['command'] == 'gobuster dir -u http://192.168.45.100:80 -w <WORDLIST>'

    def test_multiple_tasks_with_different_wordlists(self):
        """
        PROVES: Different tasks can have different wordlists

        Scenario: User has multiple enumeration tasks, each with appropriate wordlist
        """
        # Web enumeration task
        gobuster = TaskNode(
            task_id='gobuster-80',
            name='Directory Brute-force',
            task_type='command'
        )
        gobuster.metadata['wordlist'] = '/usr/share/wordlists/dirb/common.txt'
        gobuster.metadata['wordlist_purpose'] = 'web-enumeration'

        # SSH brute-force task
        ssh_brute = TaskNode(
            task_id='ssh-bruteforce-22',
            name='SSH Credential Brute-force',
            task_type='command'
        )
        ssh_brute.metadata['wordlist'] = '/usr/share/wordlists/rockyou.txt'
        ssh_brute.metadata['wordlist_purpose'] = 'password-cracking'

        # Verify different wordlists
        assert gobuster.metadata['wordlist'] != ssh_brute.metadata['wordlist']
        assert gobuster.metadata['wordlist_purpose'] != ssh_brute.metadata['wordlist_purpose']

        # Both can coexist in same profile
        root = TaskNode(
            task_id='root',
            name='Enumeration',
            task_type='parent'
        )
        root.children = [gobuster, ssh_brute]

        # Serialize and restore
        serialized = root.to_dict()
        restored = TaskNode.from_dict(serialized)

        # Verify both tasks intact
        assert len(restored.children) == 2
        assert restored.children[0].metadata['wordlist'] == '/usr/share/wordlists/dirb/common.txt'
        assert restored.children[1].metadata['wordlist'] == '/usr/share/wordlists/rockyou.txt'


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
