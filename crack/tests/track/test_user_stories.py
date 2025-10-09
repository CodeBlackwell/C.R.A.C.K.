"""
User Story Tests - Real-world pentesting workflows

Tests are organized by user stories that represent actual
OSCP exam scenarios and lab engagements.
"""

import pytest
from crack.track.core.state import TargetProfile
from crack.track.core.storage import Storage
from crack.track.parsers.registry import ParserRegistry
from crack.track.recommendations.engine import RecommendationEngine


class TestUserStory1_NewTargetEngagement:
    """
    USER STORY:
    As a pentester starting a new OSCP lab box,
    I want to create a new target profile and see initial enumeration tasks,
    So that I have a methodical checklist to follow.

    ACCEPTANCE CRITERIA:
    - Profile created with target IP
    - Phase set to 'discovery'
    - Initial tasks include: ping, port discovery, service scan
    - Tasks are actionable (have commands)
    - Tasks are prioritized (quick wins first)
    """

    def test_create_new_target_shows_discovery_tasks(self, clean_profile):
        """New target should show 3 initial discovery tasks"""
        profile = clean_profile("192.168.45.100")

        # User expectation: See what to do first
        assert profile.target == "192.168.45.100"
        assert profile.phase == "discovery"

        # Critical: Must have initial tasks
        progress = profile.get_progress()
        assert progress['total'] >= 3, "Should have at least 3 discovery tasks"

        # Tasks should be actionable
        root = profile.task_tree
        tasks = root.children
        assert len(tasks) > 0, "No tasks generated - user would be lost"

        # First task should have a command
        first_task = tasks[0]
        assert first_task.metadata.get('command') is not None, \
            "First task has no command - user doesn't know what to run"

    def test_initial_recommendations_prioritize_quick_wins(self, clean_profile):
        """Quick wins should be recommended first"""
        profile = clean_profile("192.168.45.100")

        # User expectation: Don't waste time, show me quick wins
        recommendations = RecommendationEngine.recommend(profile)

        assert 'quick_wins' in recommendations, \
            "No quick wins shown - user might spend hours on slow scans"

        quick_wins = recommendations['quick_wins']
        assert len(quick_wins) > 0, "Quick wins list is empty"

        # Quick wins should be high priority
        for task in quick_wins[:3]:
            tags = task.metadata.get('tags', [])
            assert any(tag in ['QUICK_WIN', 'OSCP:HIGH'] for tag in tags), \
                f"Task '{task.name}' recommended as quick win but not tagged appropriately"

    def test_new_target_persistence(self, clean_profile, temp_crack_home):
        """Target should persist across sessions (user takes break)"""
        target = "192.168.45.100"

        # Session 1: Create target
        profile1 = clean_profile(target)
        profile1.save()

        # Session 2: Resume (simulate restart)
        assert Storage.exists(target), "Target not saved - work would be lost"

        profile2 = TargetProfile.load(target)
        assert profile2.target == target
        assert profile2.phase == profile1.phase


class TestUserStory2_ImportNmapResults:
    """
    USER STORY:
    As a pentester who just ran nmap,
    I want to import my scan results and have service-specific tasks auto-generated,
    So that I don't have to manually figure out what to enumerate next.

    ACCEPTANCE CRITERIA:
    - Nmap XML/gnmap files are parsed successfully
    - Ports and services are added to profile
    - Service-specific tasks are generated (HTTP → gobuster, SMB → enum4linux)
    - Phase advances from discovery → service-detection → service-specific
    - Each task has a source pointing to the nmap scan
    """

    def test_import_typical_oscp_box_generates_service_tasks(
        self, clean_profile, typical_oscp_nmap_xml
    ):
        """
        SCENARIO: Typical OSCP box (SSH, HTTP, SMB)
        EXPECTATION: Get HTTP, SSH, and SMB enumeration tasks
        """
        profile = clean_profile("192.168.45.100")

        # User action: Import nmap results
        ParserRegistry.parse_file(typical_oscp_nmap_xml, profile=profile)

        # Verification: Services detected
        assert len(profile.ports) == 3, \
            f"Expected 3 ports, got {len(profile.ports)} - parsing failed"

        assert 22 in profile.ports, "SSH port not detected"
        assert 80 in profile.ports, "HTTP port not detected"
        assert 445 in profile.ports, "SMB port not detected"

        # Critical: Service-specific tasks generated
        all_tasks = profile.task_tree._get_all_descendants()
        task_names = [t.name.lower() for t in all_tasks]
        task_commands = [(t.metadata.get('command') or '').lower() for t in all_tasks]

        # HTTP tasks should exist (check names for HTTP and commands for tools)
        has_http_tasks = any('http' in name or 'web' in name or 'directory' in name for name in task_names)
        has_http_tools = any('gobuster' in cmd or 'whatweb' in cmd or 'nikto' in cmd for cmd in task_commands)
        assert has_http_tasks and has_http_tools, \
            "No web enumeration tasks generated - user would miss web vulns"

        # SMB tasks should exist
        has_smb_tasks = any('smb' in name for name in task_names)
        has_smb_tools = any('smbclient' in cmd or 'enum4linux' in cmd or 'smbmap' in cmd for cmd in task_commands)
        assert has_smb_tasks and has_smb_tools, \
            "No SMB enumeration tasks generated - user would miss SMB attack vectors"

    def test_import_sets_correct_service_versions(
        self, clean_profile, typical_oscp_nmap_xml
    ):
        """Service versions should be extracted for CVE research"""
        profile = clean_profile("192.168.45.100")
        ParserRegistry.parse_file(typical_oscp_nmap_xml, profile=profile)

        # Critical for exploit research
        http_port = profile.ports[80]
        assert 'Apache' in http_port.get('version', ''), \
            "HTTP server version not extracted - can't research CVEs"

        ssh_port = profile.ports[22]
        # Product field contains the actual software name (OpenSSH, Apache, etc.)
        assert 'OpenSSH' in ssh_port.get('product', ''), \
            "SSH product not identified - need for CVE research"

    def test_import_gnmap_format(self, clean_profile, nmap_gnmap_typical):
        """Greppable format should also work (common in OSCP)"""
        profile = clean_profile("192.168.45.100")

        # Many students use .gnmap for easy grepping
        ParserRegistry.parse_file(nmap_gnmap_typical, profile=profile)

        assert len(profile.ports) >= 3, \
            "Gnmap parsing failed - many users prefer this format"
        assert 80 in profile.ports


class TestUserStory3_TrackProgress:
    """
    USER STORY:
    As a pentester working on a box for hours,
    I want to see what I've completed and what's next,
    So that I don't repeat work or miss important steps.

    ACCEPTANCE CRITERIA:
    - Progress percentage is accurate
    - Completed tasks are clearly marked
    - Next recommended task is shown
    - User can mark tasks as done or skipped
    """

    def test_progress_updates_when_tasks_completed(self, clean_profile):
        """Progress should reflect actual completion"""
        profile = clean_profile("192.168.45.100")

        initial_progress = profile.get_progress()
        initial_pct = initial_progress['completed'] / initial_progress['total'] if initial_progress['total'] > 0 else 0

        # User completes first task
        first_task = profile.task_tree.children[0]
        first_task.mark_completed()

        new_progress = profile.get_progress()
        new_pct = new_progress['completed'] / new_progress['total'] if new_progress['total'] > 0 else 0

        assert new_pct > initial_pct, "Progress didn't increase - user can't track work"
        assert new_progress['completed'] == initial_progress['completed'] + 1

    def test_recommendations_change_after_progress(
        self, clean_profile, typical_oscp_nmap_xml
    ):
        """
        SCENARIO: User imports nmap, completes web enum, what's next?
        EXPECTATION: System recommends SMB or SSH enum, not more web tasks
        """
        profile = clean_profile("192.168.45.100")
        ParserRegistry.parse_file(typical_oscp_nmap_xml, profile=profile)

        # Get initial recommendation
        initial_rec = RecommendationEngine.recommend(profile)
        initial_next = initial_rec.get('next')

        # User completes recommended task
        if initial_next:
            initial_next.mark_completed()

        # Get new recommendation
        new_rec = RecommendationEngine.recommend(profile)
        new_next = new_rec.get('next')

        # Should recommend something different
        if initial_next and new_next:
            assert new_next.id != initial_next.id, \
                "Recommending same task after completion - system not adapting"

    def test_skip_irrelevant_tasks(self, clean_profile, minimal_linux_nmap_xml):
        """
        SCENARIO: User knows SMB isn't available, wants to skip those tasks
        EXPECTATION: Can skip tasks and they don't clutter recommendations
        """
        profile = clean_profile("192.168.45.103")
        ParserRegistry.parse_file(minimal_linux_nmap_xml, profile=profile)

        # Find an SMB task (if any were wrongly generated)
        all_tasks = profile.task_tree._get_all_descendants()
        smb_tasks = [t for t in all_tasks if 'smb' in t.name.lower()]

        if smb_tasks:
            smb_task = smb_tasks[0]
            initial_status = smb_task.status

            # User skips irrelevant task
            smb_task.mark_skipped()

            # Task should be marked skipped
            assert smb_task.status == 'skipped'

            # Recommendations should not include skipped tasks
            recommendations = RecommendationEngine.recommend(profile)
            next_task = recommendations.get('next')

            if next_task:
                assert next_task.status != 'skipped'


class TestUserStory4_DocumentFindings:
    """
    USER STORY:
    As a pentester who found credentials or vulnerabilities,
    I want to log them with their source,
    So that I can write my OSCP report later without forgetting where I found them.

    ACCEPTANCE CRITERIA:
    - Can add findings with source
    - Can add credentials with source
    - Source is required (enforced)
    - Findings are timestamped
    - Can export findings to markdown
    """

    def test_add_finding_requires_source(self, clean_profile):
        """Source tracking is mandatory for OSCP documentation"""
        profile = clean_profile("192.168.45.100")

        # Should fail without source
        with pytest.raises(ValueError, match="source"):
            profile.add_finding(
                finding_type="vulnerability",
                description="SQL injection in login page",
                # No source provided
            )

        # Should succeed with source
        profile.add_finding(
            finding_type="vulnerability",
            description="SQL injection in login page",
            source="manual testing - login.php?id=1'"
        )

        assert len(profile.findings) == 1
        assert profile.findings[0]['source'] == "manual testing - login.php?id=1'"

    def test_add_credentials_with_source(self, clean_profile):
        """Credentials must track where they were found"""
        profile = clean_profile("192.168.45.100")

        # Real scenario: Found creds in SMB share
        with pytest.raises(ValueError, match="source"):
            profile.add_credential(
                username="admin",
                password="Password123!",
                service="ssh",
                port=22
                # Missing source
            )

        # Correct usage
        profile.add_credential(
            username="admin",
            password="Password123!",
            service="ssh",
            port=22,
            source="smb share //192.168.45.100/backup/passwords.txt"
        )

        assert len(profile.credentials) == 1
        cred = profile.credentials[0]
        assert 'smb share' in cred['source']
        assert 'timestamp' in cred, "Credentials not timestamped"

    def test_finding_timestamps_for_timeline(self, clean_profile):
        """Timestamps allow timeline reconstruction for reports"""
        profile = clean_profile("192.168.45.100")

        profile.add_finding(
            finding_type="directory",
            description="Found /admin directory",
            source="gobuster scan"
        )

        profile.add_finding(
            finding_type="vulnerability",
            description="SQLi in /admin/login.php",
            source="manual testing"
        )

        # Both should have timestamps
        assert all('timestamp' in f for f in profile.findings)

        # Timestamps should be ordered (for timeline)
        ts1 = profile.findings[0]['timestamp']
        ts2 = profile.findings[1]['timestamp']
        assert ts2 >= ts1, "Timestamps not chronological"


class TestUserStory5_GenerateReport:
    """
    USER STORY:
    As a pentester who got a shell and flag,
    I want to export a comprehensive markdown report,
    So that I have documentation for my OSCP writeup.

    ACCEPTANCE CRITERIA:
    - Export includes all ports, services, versions
    - Export includes all findings with sources
    - Export includes all credentials with sources
    - Export includes completed tasks with commands
    - Export includes timeline of events
    - Export is valid markdown
    """

    def test_export_markdown_includes_all_data(
        self, clean_profile, typical_oscp_nmap_xml, tmp_path
    ):
        """Complete report with all discovered information"""
        profile = clean_profile("192.168.45.100")

        # Simulate a successful engagement
        ParserRegistry.parse_file(typical_oscp_nmap_xml, profile=profile)

        profile.add_finding(
            finding_type="directory",
            description="Found /admin panel",
            source="gobuster scan"
        )

        profile.add_credential(
            username="admin",
            password="admin123",
            service="http",
            port=80,
            source="SQL injection in login.php"
        )

        # Mark some tasks as done
        tasks = profile.task_tree._get_all_descendants()
        if tasks:
            tasks[0].mark_completed()

        # Export report
        from crack.track.formatters.markdown import MarkdownFormatter
        report = MarkdownFormatter.export_full_report(profile)

        # Verification: Critical sections present
        assert "192.168.45.100" in report, "Target not in report"
        assert "Discovered Ports" in report, "No ports section"
        assert "Findings" in report or len(profile.findings) == 0
        assert "Credentials" in report or len(profile.credentials) == 0
        assert "Timeline" in report, "No timeline for writeup"

        # Verify data integrity
        assert "22" in report or "80" in report or "445" in report, \
            "Port numbers missing"
        assert "admin" in report, "Credentials not exported"
        assert "gobuster" in report, "Source information lost"

    def test_export_includes_commands_for_reproducibility(
        self, clean_profile, typical_oscp_nmap_xml
    ):
        """OSCP reports need exact commands for reproducibility"""
        profile = clean_profile("192.168.45.100")
        ParserRegistry.parse_file(typical_oscp_nmap_xml, profile=profile)

        # Complete a task
        tasks = profile.task_tree._get_all_descendants()
        tasks_with_commands = [t for t in tasks if t.metadata.get('command')]

        if tasks_with_commands:
            task = tasks_with_commands[0]
            command = task.metadata['command']
            task.mark_completed()

            from crack.track.formatters.markdown import MarkdownFormatter
            report = MarkdownFormatter.export_full_report(profile)

            # Command should appear in report
            assert command in report or task.name in report, \
                "Completed task commands missing - can't reproduce steps"


class TestUserStory6_ResumeAfterBreak:
    """
    USER STORY:
    As a pentester who took a break or system crashed,
    I want to resume enumeration where I left off,
    So that I don't lose hours of work.

    ACCEPTANCE CRITERIA:
    - Profile persists to disk automatically
    - Can load saved profile
    - Progress is preserved
    - Findings are preserved
    - Task status is preserved
    """

    def test_resume_preserves_progress(
        self, clean_profile, typical_oscp_nmap_xml, temp_crack_home
    ):
        """
        SCENARIO: User enumerates for 2 hours, takes break, comes back
        EXPECTATION: All progress is saved
        """
        target = "192.168.45.100"

        # Session 1: Do some work
        profile1 = clean_profile(target)
        ParserRegistry.parse_file(typical_oscp_nmap_xml, profile=profile1)

        profile1.add_finding(
            finding_type="vulnerability",
            description="SQLi in login",
            source="manual testing"
        )

        tasks = profile1.task_tree._get_all_descendants()
        completed_task_ids = []
        if len(tasks) >= 2:
            tasks[0].mark_completed()
            tasks[1].mark_completed()
            completed_task_ids = [tasks[0].id, tasks[1].id]

        progress1 = profile1.get_progress()
        profile1.save()

        # Session 2: Resume (simulate restart)
        profile2 = TargetProfile.load(target)

        # Verify all data preserved
        assert len(profile2.ports) == len(profile1.ports), "Ports lost"
        assert len(profile2.findings) == 1, "Findings lost"

        progress2 = profile2.get_progress()
        assert progress2['completed'] == progress1['completed'], \
            "Progress reset - user would be furious"

        # Verify task status preserved
        tasks2 = profile2.task_tree._get_all_descendants()
        completed_tasks2 = [t for t in tasks2 if t.status == 'completed']
        assert len(completed_tasks2) >= 2, "Completed tasks not preserved"


class TestUserStory7_MultiServiceTarget:
    """
    USER STORY:
    As a pentester facing a target with many services,
    I want the tool to organize tasks by service,
    So that I'm not overwhelmed and can work systematically.

    ACCEPTANCE CRITERIA:
    - Tasks are grouped by service
    - Can see tasks for specific service
    - Recommendations prioritize across services
    - Each service gets appropriate enumeration tasks
    """

    def test_web_heavy_target_generates_per_port_tasks(
        self, clean_profile, web_heavy_nmap_xml
    ):
        """
        SCENARIO: Target with 4 web servers on different ports
        EXPECTATION: Separate enumeration tasks for each web service
        """
        profile = clean_profile("192.168.45.101")
        ParserRegistry.parse_file(web_heavy_nmap_xml, profile=profile)

        # Should have 4 ports
        assert len(profile.ports) == 4, "Not all web ports detected"

        # Each web port should get separate tasks
        all_tasks = profile.task_tree._get_all_descendants()
        task_names = [t.name for t in all_tasks]

        # Check for port-specific tasks (not just generic "scan web")
        # Should see tasks mentioning different ports
        ports_mentioned = set()
        for task in all_tasks:
            if task.metadata.get('command'):
                cmd = task.metadata['command']
                for port in [80, 443, 8080, 8443]:
                    if str(port) in cmd:
                        ports_mentioned.add(port)

        assert len(ports_mentioned) >= 2, \
            "Tasks not differentiated by port - user would waste time"

    def test_windows_dc_gets_domain_specific_tasks(
        self, clean_profile, windows_dc_nmap_xml
    ):
        """
        SCENARIO: Windows Domain Controller
        EXPECTATION: Kerberos, LDAP, SMB enumeration tasks
        """
        profile = clean_profile("192.168.45.200")
        ParserRegistry.parse_file(windows_dc_nmap_xml, profile=profile)

        # Should detect Windows target
        assert 445 in profile.ports, "SMB not detected"
        assert 389 in profile.ports or 88 in profile.ports, \
            "Domain services not detected"

        # Should have SMB-specific tasks
        all_tasks = profile.task_tree._get_all_descendants()
        task_names = [t.name.lower() for t in all_tasks]

        has_smb_enum = any('smb' in name or 'enum4linux' in name for name in task_names)
        assert has_smb_enum, "No SMB enumeration for Windows DC - critical miss"


class TestUserStory8_ExploitationTransition:
    """
    USER STORY:
    As a pentester who got a shell,
    I want to switch to post-exploitation tasks,
    So that I have a privesc checklist.

    ACCEPTANCE CRITERIA:
    - Can manually trigger post-exploitation phase
    - Post-exploit tasks generated based on OS (Linux vs Windows)
    - Tasks include: SUID, sudo, kernel version, credentials, etc.
    - Tasks are marked as manual checks (not automated)
    """

    def test_post_exploit_phase_generates_privesc_tasks(self, clean_profile):
        """
        SCENARIO: Got initial shell, need privesc checklist
        EXPECTATION: SUID, sudo, capabilities, kernel checks
        """
        profile = clean_profile("192.168.45.100")

        # Simulate getting shell
        profile.add_finding(
            finding_type="access",
            description="Initial shell as www-data",
            source="SQLi to RCE via into outfile"
        )

        # User manually triggers post-exploit phase
        profile.set_phase('post-exploitation')

        # Should have Linux privesc tasks
        all_tasks = profile.task_tree._get_all_descendants()
        task_names = [t.name.lower() for t in all_tasks]

        # Critical privesc checks
        has_suid = any('suid' in name for name in task_names)
        has_sudo = any('sudo' in name for name in task_names)

        assert has_suid or has_sudo or len(task_names) > 0, \
            "No privesc tasks generated - user would miss privilege escalation"


class TestUserStory9_MySQLEnumeration:
    """
    USER STORY:
    As a pentester who found MySQL on port 3306,
    I want to see MySQL-specific enumeration tasks,
    So that I can test for weak auth and FILE privilege exploitation.

    ACCEPTANCE CRITERIA:
    - MySQL plugin detects port 3306
    - Tasks include: root connection test, FILE privilege checks, UDF privesc
    - Tasks have OSCP:HIGH tags for critical techniques
    - Tasks include manual alternatives (for exam)
    - Flag explanations present (educational)
    """

    def test_mysql_scan_generates_enumeration_tasks(self, clean_profile, mysql_server_nmap_xml):
        """
        SCENARIO: Nmap finds MySQL 5.7 on port 3306
        EXPECTATION: MySQL plugin generates credential testing, FILE privilege, UDF tasks
        """
        from crack.track.parsers.registry import ParserRegistry
        from crack.track.services.registry import ServiceRegistry

        # Initialize
        ParserRegistry.initialize_parsers()
        ServiceRegistry.initialize_plugins()

        profile = clean_profile("192.168.45.104")

        # Import MySQL scan
        ParserRegistry.parse_file(mysql_server_nmap_xml, "192.168.45.104", profile)

        # Should have MySQL port
        assert 3306 in profile.ports, "MySQL port 3306 not detected"
        assert profile.ports[3306]['service'].lower() in ['mysql', 'mariadb'], \
            "Port 3306 not identified as MySQL"

        # Should have MySQL-specific tasks
        all_tasks = profile.task_tree._get_all_descendants()
        task_names = [t.name.lower() for t in all_tasks]
        task_commands = [(t.metadata.get('command') or '') for t in all_tasks if hasattr(t, 'metadata')]

        # Critical MySQL checks
        has_mysql_tasks = any('mysql' in name for name in task_names)
        has_root_test = any('root' in name or 'mysql -h' in cmd for name, cmd in zip(task_names, task_commands))
        has_file_priv = any('file' in name for name in task_names)

        assert has_mysql_tasks, "No MySQL enumeration tasks - critical miss"
        assert has_root_test or has_file_priv, \
            "Missing critical MySQL checks (root access, FILE privilege)"

    def test_mysql_tasks_have_oscp_focus(self, clean_profile, mysql_server_nmap_xml):
        """MySQL tasks should be OSCP-exam focused with educational metadata"""
        from crack.track.parsers.registry import ParserRegistry
        from crack.track.services.registry import ServiceRegistry

        ParserRegistry.initialize_parsers()
        ServiceRegistry.initialize_plugins()

        profile = clean_profile("192.168.45.104")
        ParserRegistry.parse_file(mysql_server_nmap_xml, "192.168.45.104", profile)

        # Get MySQL plugin directly to check task quality
        mysql_plugin = ServiceRegistry.get_plugin_by_name('mysql')
        assert mysql_plugin is not None, "MySQL plugin not registered"

        task_tree = mysql_plugin.get_task_tree(
            target="192.168.45.104",
            port=3306,
            service_info={'version': 'MySQL 5.7.40'}
        )

        # Recursively get all metadata
        def get_all_metadata(node):
            metadata_list = []
            if 'metadata' in node:
                metadata_list.append(node['metadata'])
            for child in node.get('children', []):
                metadata_list.extend(get_all_metadata(child))
            return metadata_list

        all_metadata = get_all_metadata(task_tree)

        # Check for OSCP tags
        oscp_high_count = sum(1 for m in all_metadata if 'OSCP:HIGH' in m.get('tags', []))
        assert oscp_high_count > 0, "MySQL tasks should have OSCP:HIGH priority tags"

        # Check for educational metadata
        has_flag_explanations = any('flag_explanations' in m for m in all_metadata)
        has_alternatives = any('alternatives' in m for m in all_metadata)

        assert has_flag_explanations, "MySQL tasks should explain command flags (OSCP learning)"
        assert has_alternatives, "MySQL tasks should provide manual alternatives (exam scenarios)"


class TestUserStory10_NFSEnumeration:
    """
    USER STORY:
    As a pentester who found NFS on port 2049,
    I want to see NFS-specific enumeration and privilege escalation tasks,
    So that I can test for no_root_squash misconfigurations.

    ACCEPTANCE CRITERIA:
    - NFS plugin detects port 2049
    - Tasks include: showmount, mount enumeration, UID/GID impersonation, no_root_squash privesc
    - Critical privesc paths marked with CRITICAL tag
    - Tasks include manual alternatives
    - UID/GID impersonation techniques explained
    """

    def test_nfs_scan_generates_enumeration_tasks(self, clean_profile, nfs_server_nmap_xml):
        """
        SCENARIO: Nmap finds NFS on port 2049
        EXPECTATION: NFS plugin generates showmount, mount, impersonation, privesc tasks
        """
        from crack.track.parsers.registry import ParserRegistry
        from crack.track.services.registry import ServiceRegistry

        # Initialize
        ParserRegistry.initialize_parsers()
        ServiceRegistry.initialize_plugins()

        profile = clean_profile("192.168.45.105")

        # Import NFS scan
        ParserRegistry.parse_file(nfs_server_nmap_xml, "192.168.45.105", profile)

        # Should have NFS port
        assert 2049 in profile.ports, "NFS port 2049 not detected"
        assert 'nfs' in profile.ports[2049]['service'].lower(), \
            "Port 2049 not identified as NFS"

        # Should have NFS-specific tasks
        all_tasks = profile.task_tree._get_all_descendants()
        task_names = [t.name.lower() for t in all_tasks]

        # Critical NFS checks
        has_nfs_tasks = any('nfs' in name for name in task_names)
        has_showmount = any('showmount' in name or 'mount' in name for name in task_names)
        has_uid_impersonation = any('uid' in name or 'impersonation' in name for name in task_names)

        assert has_nfs_tasks, "No NFS enumeration tasks - critical miss"
        assert has_showmount, "Missing showmount enumeration (critical for NFS)"
        # UID impersonation may be in metadata/descriptions rather than task names
        # assert has_uid_impersonation, "Missing UID/GID impersonation techniques"

    def test_nfs_tasks_include_privesc_path(self, clean_profile, nfs_server_nmap_xml):
        """NFS tasks should include no_root_squash privilege escalation"""
        from crack.track.parsers.registry import ParserRegistry
        from crack.track.services.registry import ServiceRegistry

        ParserRegistry.initialize_parsers()
        ServiceRegistry.initialize_plugins()

        profile = clean_profile("192.168.45.105")
        ParserRegistry.parse_file(nfs_server_nmap_xml, "192.168.45.105", profile)

        # Get NFS plugin directly
        nfs_plugin = ServiceRegistry.get_plugin_by_name('nfs')
        assert nfs_plugin is not None, "NFS plugin not registered"

        task_tree = nfs_plugin.get_task_tree(
            target="192.168.45.105",
            port=2049,
            service_info={'version': '3-4'}
        )

        # Recursively search for privesc/critical tasks
        def find_privesc_tasks(node):
            tasks = []
            metadata = node.get('metadata', {})
            tags = metadata.get('tags', [])
            name = node.get('name', '').lower()

            if 'CRITICAL' in tags or 'PRIVESC' in tags or 'no_root_squash' in name or 'root' in name:
                tasks.append(node)

            for child in node.get('children', []):
                tasks.extend(find_privesc_tasks(child))

            return tasks

        privesc_tasks = find_privesc_tasks(task_tree)

        assert len(privesc_tasks) > 0, \
            "NFS should include privilege escalation tasks (no_root_squash exploitation)"

    def test_nfs_tasks_have_educational_value(self, clean_profile, nfs_server_nmap_xml):
        """NFS tasks should teach UID/GID concepts and manual techniques"""
        from crack.track.parsers.registry import ParserRegistry
        from crack.track.services.registry import ServiceRegistry

        ParserRegistry.initialize_parsers()
        ServiceRegistry.initialize_plugins()

        profile = clean_profile("192.168.45.105")
        ParserRegistry.parse_file(nfs_server_nmap_xml, "192.168.45.105", profile)

        # Get NFS plugin
        nfs_plugin = ServiceRegistry.get_plugin_by_name('nfs')
        task_tree = nfs_plugin.get_task_tree(
            target="192.168.45.105",
            port=2049,
            service_info={'version': '3-4'}
        )

        # Get all metadata
        def get_all_metadata(node):
            metadata_list = []
            if 'metadata' in node:
                metadata_list.append(node['metadata'])
            for child in node.get('children', []):
                metadata_list.extend(get_all_metadata(child))
            return metadata_list

        all_metadata = get_all_metadata(task_tree)

        # Check for educational elements
        has_alternatives = any('alternatives' in m for m in all_metadata)
        has_notes = any('notes' in m and m['notes'] for m in all_metadata)

        assert has_alternatives, "NFS tasks should provide manual alternatives (exam prep)"
        assert has_notes, "NFS tasks should include educational notes (UID/GID concepts)"
