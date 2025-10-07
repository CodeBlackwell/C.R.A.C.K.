"""
Test MSSQL expansion in SQL plugin

Validates comprehensive MSSQL enumeration and exploitation task generation
"""

import pytest
from crack.track.services.sql import SQLPlugin


class TestMSSQLPlugin:
    """Test MSSQL-specific functionality in SQL plugin"""

    @pytest.fixture
    def plugin(self):
        """Create SQL plugin instance"""
        return SQLPlugin()

    def test_mssql_detection(self, plugin):
        """PROVES: Plugin detects MSSQL on port 1433"""
        port_info = {
            'port': 1433,
            'service': 'ms-sql-s',
            'version': 'Microsoft SQL Server 2017 14.00.1000.00'
        }
        assert plugin.detect(port_info) is True

    def test_mssql_task_generation(self, plugin):
        """PROVES: Comprehensive MSSQL tasks generated"""
        service_info = {
            'port': 1433,
            'service': 'ms-sql-s',
            'version': 'Microsoft SQL Server 2017 14.00.1000.00'
        }

        tree = plugin.get_task_tree('192.168.45.100', 1433, service_info)

        # Root structure
        assert tree['id'] == 'sql-enum-1433'
        assert 'MSSQL' in tree['name']
        assert tree['type'] == 'parent'
        assert 'children' in tree

        # Should have multiple MSSQL-specific tasks
        task_ids = [task['id'] for task in tree['children']]

        # Check for key MSSQL tasks
        assert any('mssql-nmap-enum' in tid for tid in task_ids), "Missing nmap enumeration"
        assert any('xp-cmdshell' in tid for tid in task_ids), "Missing xp_cmdshell tasks"
        assert any('privesc' in tid for tid in task_ids), "Missing privilege escalation"
        assert any('linked-servers' in tid for tid in task_ids), "Missing linked server attacks"
        assert any('cred-theft' in tid for tid in task_ids), "Missing credential theft"
        assert any('file-ops' in tid for tid in task_ids), "Missing file operations"

    def test_xp_cmdshell_task_hierarchy(self, plugin):
        """PROVES: xp_cmdshell has hierarchical subtasks"""
        service_info = {
            'port': 1433,
            'service': 'ms-sql-s',
            'version': ''
        }

        tree = plugin.get_task_tree('192.168.45.100', 1433, service_info)

        # Find xp_cmdshell parent task
        xp_task = None
        for task in tree['children']:
            if 'xp-cmdshell' in task['id']:
                xp_task = task
                break

        assert xp_task is not None, "xp_cmdshell task not found"
        assert xp_task['type'] == 'parent', "xp_cmdshell should be parent container"
        assert 'children' in xp_task, "xp_cmdshell should have child tasks"
        assert len(xp_task['children']) >= 3, "Should have check, enable, execute tasks"

        # Verify child task IDs
        child_ids = [c['id'] for c in xp_task['children']]
        assert any('check' in cid for cid in child_ids), "Missing check task"
        assert any('enable' in cid for cid in child_ids), "Missing enable task"
        assert any('rce' in cid for cid in child_ids), "Missing RCE task"

    def test_oscp_metadata_present(self, plugin):
        """PROVES: MSSQL tasks include OSCP-required metadata"""
        service_info = {
            'port': 1433,
            'service': 'ms-sql-s',
            'version': 'Microsoft SQL Server 2017'
        }

        tree = plugin.get_task_tree('192.168.45.100', 1433, service_info)

        # Find first MSSQL-specific command task (not generic SQL tasks)
        command_task = None
        for task in tree['children']:
            if task.get('type') == 'command' and 'mssql' in task['id']:
                command_task = task
                break

        assert command_task is not None, "No MSSQL command tasks found"

        metadata = command_task.get('metadata', {})

        # Required OSCP fields
        assert 'command' in metadata, "Command missing"
        assert 'description' in metadata, "Description missing"
        assert 'flag_explanations' in metadata, "Flag explanations missing"
        assert 'tags' in metadata, "Tags missing"
        assert 'success_indicators' in metadata, "Success indicators missing"
        assert 'alternatives' in metadata, "Manual alternatives missing"

        # Verify tag format
        assert isinstance(metadata['tags'], list), "Tags should be list"
        assert len(metadata['tags']) > 0, "Should have at least one tag"

    def test_impersonate_privesc_metadata(self, plugin):
        """PROVES: IMPERSONATE privesc task has comprehensive metadata"""
        service_info = {'port': 1433, 'service': 'ms-sql-s', 'version': ''}
        tree = plugin.get_task_tree('192.168.45.100', 1433, service_info)

        # Find IMPERSONATE task
        impersonate_task = None
        for parent_task in tree['children']:
            if parent_task.get('type') == 'parent' and 'privesc' in parent_task['id']:
                for child in parent_task.get('children', []):
                    if 'impersonate' in child['id']:
                        impersonate_task = child
                        break

        assert impersonate_task is not None, "IMPERSONATE task not found"

        metadata = impersonate_task['metadata']

        # Verify comprehensive guidance
        assert 'flag_explanations' in metadata
        assert 'IMPERSONATE permission' in metadata['flag_explanations']
        assert 'success_indicators' in metadata
        assert len(metadata['success_indicators']) >= 2
        assert 'next_steps' in metadata
        assert len(metadata['next_steps']) >= 3
        assert 'alternatives' in metadata
        assert 'notes' in metadata

    def test_netntlm_hash_theft_task(self, plugin):
        """PROVES: NetNTLM hash theft task present with proper technique"""
        service_info = {'port': 1433, 'service': 'ms-sql-s', 'version': ''}
        tree = plugin.get_task_tree('192.168.45.100', 1433, service_info)

        # Find NetNTLM theft task
        ntlm_task = None
        for parent_task in tree['children']:
            if parent_task.get('type') == 'parent' and 'cred-theft' in parent_task['id']:
                for child in parent_task.get('children', []):
                    if 'ntlm-steal' in child['id']:
                        ntlm_task = child
                        break

        assert ntlm_task is not None, "NetNTLM theft task not found"

        metadata = ntlm_task['metadata']

        # Verify xp_dirtree technique
        assert 'xp_dirtree' in metadata['command']
        assert 'OSCP:HIGH' in metadata['tags']
        assert 'QUICK_WIN' in metadata['tags']

        # Verify responder/smbserver in next steps
        next_steps_text = ' '.join(metadata['next_steps'])
        assert 'responder' in next_steps_text.lower() or 'impacket-smbserver' in next_steps_text.lower()

    def test_linked_server_enumeration(self, plugin):
        """PROVES: Linked server enumeration tasks included"""
        service_info = {'port': 1433, 'service': 'ms-sql-s', 'version': ''}
        tree = plugin.get_task_tree('192.168.45.100', 1433, service_info)

        # Find linked server parent task
        linked_task = None
        for task in tree['children']:
            if 'linked-servers' in task['id']:
                linked_task = task
                break

        assert linked_task is not None, "Linked server tasks not found"
        assert linked_task['type'] == 'parent'
        assert len(linked_task['children']) >= 2, "Should have enum and RCE tasks"

        # Verify enumeration child
        child_ids = [c['id'] for c in linked_task['children']]
        assert any('enum-links' in cid for cid in child_ids)

    def test_file_operations_tasks(self, plugin):
        """PROVES: File read/write operations included"""
        service_info = {'port': 1433, 'service': 'ms-sql-s', 'version': ''}
        tree = plugin.get_task_tree('192.168.45.100', 1433, service_info)

        # Find file operations parent
        file_ops = None
        for task in tree['children']:
            if 'file-ops' in task['id']:
                file_ops = task
                break

        assert file_ops is not None, "File operations not found"
        assert file_ops['type'] == 'parent'

        child_ids = [c['id'] for c in file_ops['children']]
        assert any('read-file' in cid for cid in child_ids), "Missing OPENROWSET read"
        assert any('write-file' in cid for cid in child_ids), "Missing Ole Automation write"

    def test_metasploit_reference_task(self, plugin):
        """PROVES: Metasploit modules reference included"""
        service_info = {'port': 1433, 'service': 'ms-sql-s', 'version': ''}
        tree = plugin.get_task_tree('192.168.45.100', 1433, service_info)

        msf_task = None
        for task in tree['children']:
            if 'metasploit' in task['id']:
                msf_task = task
                break

        assert msf_task is not None, "Metasploit reference not found"
        assert 'notes' in msf_task['metadata']

        notes = msf_task['metadata']['notes']
        assert isinstance(notes, list)
        assert len(notes) > 5, "Should list multiple MSF modules"

        # Check for key modules
        notes_text = ' '.join(notes)
        assert 'mssql_escalate_execute_as' in notes_text
        assert 'mssql_ntlm_stealer' in notes_text
        assert 'mssql_linkcrawler' in notes_text

    def test_task_count_comprehensive(self, plugin):
        """PROVES: Comprehensive task coverage (8+ major categories)"""
        service_info = {'port': 1433, 'service': 'ms-sql-s', 'version': ''}
        tree = plugin.get_task_tree('192.168.45.100', 1433, service_info)

        # Count top-level MSSQL tasks (excluding generic SQL tasks)
        mssql_tasks = [t for t in tree['children'] if 'mssql' in t['id']]

        # Should have: enum, xp_cmdshell, privesc, linked, creds, files, advanced, msf
        assert len(mssql_tasks) >= 8, f"Expected 8+ MSSQL task categories, got {len(mssql_tasks)}"

    def test_no_duplicate_task_ids(self, plugin):
        """PROVES: All task IDs are unique"""
        service_info = {'port': 1433, 'service': 'ms-sql-s', 'version': ''}
        tree = plugin.get_task_tree('192.168.45.100', 1433, service_info)

        def collect_ids(node):
            ids = [node['id']]
            if 'children' in node:
                for child in node['children']:
                    ids.extend(collect_ids(child))
            return ids

        all_ids = collect_ids(tree)
        assert len(all_ids) == len(set(all_ids)), "Duplicate task IDs found"
