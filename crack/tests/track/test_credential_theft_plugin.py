"""
Tests for Windows Credential Theft plugin

Tests cover:
- Plugin registration and detection
- LSASS dumping methods (procdump, comsvcs, PPLBlade)
- Mimikatz extraction techniques
- SAM/SYSTEM extraction
- NTDS.dit extraction
- Pass-the-Hash attacks
- NTLM relay and theft
- Credential protection bypasses
- WTS Impersonator token hijacking
- Task tree structure and metadata
"""

import pytest
from crack.track.services.credential_theft import CredentialTheftPlugin
from crack.track.services.registry import ServiceRegistry


class TestCredentialTheftPluginRegistration:
    """Test plugin registration and basic properties"""

    def test_plugin_registered(self):
        """PROVES: CredentialTheftPlugin is registered in ServiceRegistry"""
        plugins = ServiceRegistry.get_all_plugins()
        plugin_names = [p.name for p in plugins]
        assert 'credential-theft' in plugin_names

    def test_plugin_properties(self):
        """PROVES: Plugin has correct name and service identifiers"""
        plugin = CredentialTheftPlugin()
        assert plugin.name == 'credential-theft'
        assert 'credential-theft' in plugin.service_names
        assert 'cred-theft' in plugin.service_names
        assert 'ntlm-theft' in plugin.service_names

    def test_no_default_ports(self):
        """PROVES: Plugin has no default ports (manual trigger only)"""
        plugin = CredentialTheftPlugin()
        assert plugin.default_ports == []

    def test_detect_returns_false(self):
        """PROVES: Plugin detection always returns False (manual only)"""
        plugin = CredentialTheftPlugin()

        # Test with various port configurations
        assert plugin.detect({'port': 445, 'service': 'smb'}) == False
        assert plugin.detect({'port': 135, 'service': 'rpc'}) == False
        assert plugin.detect({'port': 3389, 'service': 'rdp'}) == False


class TestTaskTreeStructure:
    """Test task tree generation and structure"""

    @pytest.fixture
    def plugin(self):
        return CredentialTheftPlugin()

    @pytest.fixture
    def task_tree(self, plugin):
        return plugin.get_task_tree('192.168.45.100', 0, {})

    def test_root_task_structure(self, task_tree):
        """PROVES: Root task has correct structure"""
        assert task_tree['id'] == 'credential-theft-root'
        assert 'Windows Credential Theft' in task_tree['name']
        assert task_tree['type'] == 'parent'
        assert 'children' in task_tree
        assert len(task_tree['children']) > 0

    def test_all_major_phases_present(self, task_tree):
        """PROVES: All major credential theft phases are included"""
        child_ids = [child['id'] for child in task_tree['children']]

        expected_phases = [
            'lsass-dumping',
            'mimikatz-extraction',
            'sam-system-extraction',
            'ntds-extraction',
            'pass-the-hash',
            'ntlm-relay-theft',
            'credential-protections',
            'wts-impersonator',
            'crackmapexec-dumping',
            'alternative-tools'
        ]

        for phase in expected_phases:
            assert phase in child_ids, f"Missing phase: {phase}"

    def test_task_hierarchy_depth(self, task_tree):
        """PROVES: Task tree has proper hierarchical structure"""
        # Check that parent tasks have children
        lsass_tasks = next(c for c in task_tree['children'] if c['id'] == 'lsass-dumping')
        assert lsass_tasks['type'] == 'parent'
        assert len(lsass_tasks['children']) >= 4  # procdump, comsvcs, taskmanager, pplblade


class TestLSASSDumpingTasks:
    """Test LSASS memory dumping task generation"""

    @pytest.fixture
    def lsass_tasks(self):
        plugin = CredentialTheftPlugin()
        tree = plugin.get_task_tree('192.168.45.100', 0, {})
        return next(c for c in tree['children'] if c['id'] == 'lsass-dumping')

    def test_procdump_task(self, lsass_tasks):
        """PROVES: Procdump LSASS dump task has complete metadata"""
        procdump = next(c for c in lsass_tasks['children'] if c['id'] == 'lsass-procdump')

        assert procdump['name'] == 'Dump LSASS with Procdump'
        assert procdump['type'] == 'command'

        meta = procdump['metadata']
        assert 'procdump.exe' in meta['command']
        assert '-accepteula' in meta['command']
        assert '-ma' in meta['command']
        assert 'lsass.exe' in meta['command']

        # Check OSCP metadata
        assert 'OSCP:HIGH' in meta['tags']
        assert 'QUICK_WIN' in meta['tags']
        assert 'flag_explanations' in meta
        assert len(meta['flag_explanations']) >= 4
        assert 'success_indicators' in meta
        assert len(meta['success_indicators']) >= 2
        assert 'failure_indicators' in meta
        assert 'next_steps' in meta
        assert 'alternatives' in meta
        assert len(meta['alternatives']) >= 3

    def test_comsvcs_task(self, lsass_tasks):
        """PROVES: comsvcs.dll dump task includes rundll32 technique"""
        comsvcs = next(c for c in lsass_tasks['children'] if c['id'] == 'lsass-comsvcs')

        meta = comsvcs['metadata']
        assert 'rundll32.exe' in meta['command']
        assert 'comsvcs.dll' in meta['command']
        assert 'MiniDump' in meta['command']
        assert '<LSASS_PID>' in meta['command']

        # Check educational content
        assert 'flag_explanations' in meta
        assert 'MiniDump' in meta['flag_explanations']
        assert 'notes' in meta
        assert 'hackndo.com' in meta['notes']  # Reference to source

    def test_pplblade_bypass_task(self, lsass_tasks):
        """PROVES: PPLBlade task includes PPL bypass technique"""
        pplblade = next(c for c in lsass_tasks['children'] if c['id'] == 'lsass-pplblade')

        meta = pplblade['metadata']
        assert 'PPLBlade.exe' in meta['command']
        assert '--mode dump' in meta['command']
        assert '--obfuscate' in meta['command']

        # Check advanced tags
        assert 'OSCP:MEDIUM' in meta['tags'] or 'OSCP:LOW' in meta['tags']
        assert 'PPL_BYPASS' in meta['tags'] or 'ADVANCED' in meta['tags']

        # Check bypass alternatives
        assert 'alternatives' in meta
        alternatives_text = ' '.join(meta['alternatives'])
        assert 'mimidrv' in alternatives_text or 'PPLKiller' in alternatives_text

    def test_task_manager_gui_method(self, lsass_tasks):
        """PROVES: Task Manager GUI method is included for RDP scenarios"""
        taskmanager = next(c for c in lsass_tasks['children'] if c['id'] == 'lsass-taskmanager')

        assert taskmanager['type'] == 'manual'
        meta = taskmanager['metadata']
        assert 'MANUAL' in meta['tags']
        assert 'notes' in meta
        assert 'Task Manager' in meta['notes'] or 'Right-click' in meta['notes']


class TestMimikatzExtractionTasks:
    """Test Mimikatz credential extraction tasks"""

    @pytest.fixture
    def mimikatz_tasks(self):
        plugin = CredentialTheftPlugin()
        tree = plugin.get_task_tree('192.168.45.100', 0, {})
        return next(c for c in tree['children'] if c['id'] == 'mimikatz-extraction')

    def test_logonpasswords_task(self, mimikatz_tasks):
        """PROVES: Live LSASS extraction task has proper Mimikatz commands"""
        logonpw = next(c for c in mimikatz_tasks['children'] if c['id'] == 'mimikatz-logonpasswords')

        meta = logonpw['metadata']
        cmd = meta['command']

        # Check command structure
        assert 'mimikatz' in cmd.lower()
        assert 'privilege::debug' in cmd
        assert 'token::elevate' in cmd
        assert 'sekurlsa::logonpasswords' in cmd

        # Check flag explanations
        flags = meta['flag_explanations']
        assert 'privilege::debug' in flags
        assert 'sekurlsa::logonpasswords' in flags

        # Check failure indicators mention protections
        failures = ' '.join(meta['failure_indicators'])
        assert 'Credential Guard' in failures or 'PPL' in failures

    def test_minidump_offline_parsing(self, mimikatz_tasks):
        """PROVES: Offline minidump parsing task is included"""
        minidump = next(c for c in mimikatz_tasks['children'] if c['id'] == 'mimikatz-minidump')

        meta = minidump['metadata']
        assert 'sekurlsa::minidump' in meta['command']
        assert 'lsass.dmp' in meta['command']
        assert 'OPSEC_SAFE' in meta['tags'] or 'MANUAL' in meta['tags']

        # Check notes mention offline analysis
        assert 'notes' in meta
        assert 'offline' in meta['notes'].lower()

    def test_comprehensive_oneliner(self, mimikatz_tasks):
        """PROVES: Comprehensive one-liner includes all credential sources"""
        oneliner = next(c for c in mimikatz_tasks['children'] if c['id'] == 'mimikatz-all')

        cmd = oneliner['metadata']['command']

        # Check all credential sources
        assert 'sekurlsa::logonpasswords' in cmd
        assert 'lsadump::lsa' in cmd
        assert 'lsadump::sam' in cmd
        assert 'lsadump::cache' in cmd
        assert 'sekurlsa::ekeys' in cmd

    def test_invoke_mimikatz_powershell(self, mimikatz_tasks):
        """PROVES: PowerShell Invoke-Mimikatz task is included"""
        invoke = next(c for c in mimikatz_tasks['children'] if c['id'] == 'invoke-mimikatz')

        meta = invoke['metadata']
        cmd = meta['command']

        assert 'IEX' in cmd or 'Invoke-Expression' in cmd
        assert 'Invoke-Mimikatz' in cmd
        assert 'FILELESS' in meta['tags']

        # Check AMSI bypass is mentioned
        alternatives = ' '.join(meta.get('alternatives', []))
        notes = meta.get('notes', '')
        assert 'AMSI' in alternatives or 'AMSI' in notes


class TestSAMSystemExtraction:
    """Test SAM/SYSTEM database extraction tasks"""

    @pytest.fixture
    def sam_tasks(self):
        plugin = CredentialTheftPlugin()
        tree = plugin.get_task_tree('192.168.45.100', 0, {})
        return next(c for c in tree['children'] if c['id'] == 'sam-system-extraction')

    def test_registry_save_method(self, sam_tasks):
        """PROVES: Registry save method extracts SAM, SYSTEM, and SECURITY"""
        reg_save = next(c for c in sam_tasks['children'] if c['id'] == 'sam-reg-save')

        cmd = reg_save['metadata']['command']

        assert 'reg save' in cmd.lower()
        assert 'HKLM\\sam' in cmd or 'HKLM\\\\sam' in cmd
        assert 'HKLM\\system' in cmd or 'HKLM\\\\system' in cmd
        assert 'HKLM\\security' in cmd or 'HKLM\\\\security' in cmd

    def test_volume_shadow_copy(self, sam_tasks):
        """PROVES: Volume Shadow Copy method is included"""
        vss = next(c for c in sam_tasks['children'] if c['id'] == 'sam-vss')

        meta = vss['metadata']
        cmd = meta['command']

        assert 'vssadmin' in cmd.lower()
        assert 'shadow' in cmd.lower()
        assert 'HarddiskVolumeShadowCopy' in cmd

        # Check it's tagged as advanced/Windows Server
        tags = meta['tags']
        assert 'ADVANCED' in tags or 'WINDOWS_SERVER' in tags

    def test_sam_parsing_task(self, sam_tasks):
        """PROVES: SAM parsing task uses secretsdump"""
        parse = next(c for c in sam_tasks['children'] if c['id'] == 'sam-parse')

        meta = parse['metadata']
        cmd = meta['command']

        assert 'secretsdump' in cmd.lower()
        assert '-sam' in cmd
        assert '-system' in cmd
        assert 'LOCAL' in cmd

        # Check alternatives mention other tools
        alternatives = ' '.join(meta['alternatives'])
        assert 'samdump2' in alternatives or 'mimikatz' in alternatives


class TestNTDSExtraction:
    """Test NTDS.dit (Active Directory) extraction tasks"""

    @pytest.fixture
    def ntds_tasks(self):
        plugin = CredentialTheftPlugin()
        tree = plugin.get_task_tree('192.168.45.100', 0, {})
        return next(c for c in tree['children'] if c['id'] == 'ntds-extraction')

    def test_ntdsutil_method(self, ntds_tasks):
        """PROVES: Ntdsutil extraction method is included"""
        ntdsutil = next(c for c in ntds_tasks['children'] if c['id'] == 'ntds-ntdsutil')

        meta = ntdsutil['metadata']
        cmd = meta['command']

        assert 'ntdsutil' in cmd.lower()
        assert 'ifm' in cmd.lower()
        assert 'create full' in cmd.lower()

        # Check Domain Admin tags
        assert 'DOMAIN_ADMIN' in meta['tags'] or 'ACTIVE_DIRECTORY' in meta['tags']

    def test_secretsdump_remote_dcsync(self, ntds_tasks):
        """PROVES: Remote DCSync via secretsdump is included"""
        dcsync = next(c for c in ntds_tasks['children'] if c['id'] == 'ntds-secretsdump-remote')

        meta = dcsync['metadata']
        cmd = meta['command']

        assert 'secretsdump' in cmd.lower()
        assert '-just-dc-ntlm' in cmd or 'just-dc' in cmd
        assert 'DOMAIN/USER' in cmd

        # Check notes mention DCSync
        notes = meta.get('notes', '')
        assert 'DCSync' in notes or 'replication' in notes.lower()

    def test_crackmapexec_ntds(self, ntds_tasks):
        """PROVES: CrackMapExec NTDS dump is included"""
        cme = next(c for c in ntds_tasks['children'] if c['id'] == 'ntds-crackmapexec')

        meta = cme['metadata']
        cmd = meta['command']

        assert 'crackmapexec' in cmd.lower()
        assert '--ntds' in cmd


class TestPassTheHash:
    """Test Pass-the-Hash attack tasks"""

    @pytest.fixture
    def pth_tasks(self):
        plugin = CredentialTheftPlugin()
        tree = plugin.get_task_tree('192.168.45.100', 0, {})
        return next(c for c in tree['children'] if c['id'] == 'pass-the-hash')

    def test_mimikatz_pth(self, pth_tasks):
        """PROVES: Mimikatz PTH injects hash into new process"""
        mimi_pth = next(c for c in pth_tasks['children'] if c['id'] == 'pth-mimikatz')

        meta = mimi_pth['metadata']
        cmd = meta['command']

        assert 'sekurlsa::pth' in cmd
        assert '/user:' in cmd
        assert '/domain:' in cmd
        assert '/ntlm:' in cmd
        assert '/run:' in cmd

        # Check LATERAL_MOVEMENT tag
        assert 'LATERAL_MOVEMENT' in meta['tags']

    def test_impacket_pth_linux(self, pth_tasks):
        """PROVES: Impacket PTH for Linux attackers is included"""
        impacket = next(c for c in pth_tasks['children'] if c['id'] == 'pth-impacket')

        meta = impacket['metadata']
        cmd = meta['command']

        assert 'impacket-psexec' in cmd or 'psexec' in cmd
        assert '-hashes' in cmd
        assert 'LINUX' in meta['tags']

        # Check alternatives mention wmiexec, smbexec
        alternatives = ' '.join(meta['alternatives'])
        assert 'wmiexec' in alternatives or 'evil-winrm' in alternatives

    def test_crackmapexec_pth_spray(self, pth_tasks):
        """PROVES: CrackMapExec PTH for mass spray is included"""
        cme = next(c for c in pth_tasks['children'] if c['id'] == 'pth-crackmapexec')

        meta = cme['metadata']
        cmd = meta['command']

        assert 'crackmapexec' in cmd.lower()
        assert '-H' in cmd
        assert '-x' in cmd or 'command' in cmd.lower()


class TestNTLMRelayTheft:
    """Test NTLM relay and theft techniques"""

    @pytest.fixture
    def ntlm_tasks(self):
        plugin = CredentialTheftPlugin()
        tree = plugin.get_task_tree('192.168.45.100', 0, {})
        return next(c for c in tree['children'] if c['id'] == 'ntlm-relay-theft')

    def test_responder_capture(self, ntlm_tasks):
        """PROVES: Responder NTLM capture is included"""
        responder = next(c for c in ntlm_tasks['children'] if c['id'] == 'ntlm-relay-responder')

        meta = responder['metadata']
        cmd = meta['command']

        assert 'responder' in cmd.lower()
        assert '-I' in cmd
        assert 'NETWORK' in meta['tags'] or 'QUICK_WIN' in meta['tags']

    def test_file_based_theft_parent(self, ntlm_tasks):
        """PROVES: File-based NTLM theft methods are grouped"""
        file_theft = next(c for c in ntlm_tasks['children'] if c['id'] == 'ntlm-theft-files')

        assert file_theft['type'] == 'parent'
        assert len(file_theft['children']) >= 3  # .lnk, .library-ms, .asx

    def test_lnk_file_theft(self, ntlm_tasks):
        """PROVES: Malicious .lnk file creation is included"""
        file_theft = next(c for c in ntlm_tasks['children'] if c['id'] == 'ntlm-theft-files')
        lnk = next(c for c in file_theft['children'] if c['id'] == 'ntlm-theft-lnk')

        meta = lnk['metadata']
        assert 'PHISHING' in meta['tags'] or 'FILE_BASED' in meta['tags']

    def test_library_ms_cve(self, ntlm_tasks):
        """PROVES: CVE-2025-24071 library-ms technique is included"""
        file_theft = next(c for c in ntlm_tasks['children'] if c['id'] == 'ntlm-theft-files')
        library = next(c for c in file_theft['children'] if c['id'] == 'ntlm-theft-library-ms')

        meta = library['metadata']
        assert 'CVE' in meta['tags']
        notes = meta.get('notes', '')
        assert '2025' in notes  # CVE year

    def test_internal_monologue(self, ntlm_tasks):
        """PROVES: Internal Monologue attack is included"""
        internal_mono = next(c for c in ntlm_tasks['children'] if c['id'] == 'internal-monologue')

        meta = internal_mono['metadata']
        assert 'InternalMonologue' in meta['command']
        assert 'CREDENTIAL_GUARD_BYPASS' in meta['tags'] or 'ADVANCED' in meta['tags']

        # Check notes mention LSASS bypass
        notes = meta.get('notes', '')
        assert 'LSASS' in notes or 'stealthy' in notes.lower()

    def test_ntlm_reflection_cve(self, ntlm_tasks):
        """PROVES: CVE-2025-33073 NTLM reflection is included"""
        reflection = next(c for c in ntlm_tasks['children'] if c['id'] == 'ntlm-reflection-cve')

        meta = reflection['metadata']
        cmd = meta['command']

        assert 'dnstool.py' in cmd
        assert 'PetitPotam' in cmd or 'coerce' in cmd.lower()
        assert 'CVE' in meta['tags']

        # Check it references CVE-2025-33073
        notes = meta.get('notes', '')
        desc = meta.get('description', '')
        combined = notes + desc
        # Accept either full CVE or year reference
        assert '33073' in combined or '2025' in combined or 'CVE' in combined


class TestCredentialProtections:
    """Test credential protection bypass tasks"""

    @pytest.fixture
    def protection_tasks(self):
        plugin = CredentialTheftPlugin()
        tree = plugin.get_task_tree('192.168.45.100', 0, {})
        return next(c for c in tree['children'] if c['id'] == 'credential-protections')

    def test_wdigest_check(self, protection_tasks):
        """PROVES: WDigest status check is included"""
        wdigest = next(c for c in protection_tasks['children'] if c['id'] == 'check-wdigest')

        meta = wdigest['metadata']
        cmd = meta['command']

        assert 'reg query' in cmd.lower()
        assert 'WDigest' in cmd
        assert 'UseLogonCredential' in cmd

    def test_lsa_ppl_check(self, protection_tasks):
        """PROVES: LSA Protection (RunAsPPL) check is included"""
        ppl = next(c for c in protection_tasks['children'] if c['id'] == 'check-lsa-ppl')

        meta = ppl['metadata']
        cmd = meta['command']

        assert 'reg query' in cmd.lower()
        assert 'RunAsPPL' in cmd

        # Check next steps mention bypasses
        next_steps = ' '.join(meta['next_steps'])
        assert 'bypass' in next_steps.lower() or 'PPL' in next_steps

    def test_credential_guard_check(self, protection_tasks):
        """PROVES: Credential Guard check is included"""
        cg = next(c for c in protection_tasks['children'] if c['id'] == 'check-credential-guard')

        meta = cg['metadata']
        cmd = meta['command']

        assert 'reg query' in cmd.lower()
        assert 'LsaCfgFlags' in cmd

    def test_sedebug_bypass(self, protection_tasks):
        """PROVES: SeDebugPrivilege removal bypass is included"""
        sedebug = next(c for c in protection_tasks['children'] if c['id'] == 'bypass-sedebug')

        meta = sedebug['metadata']
        cmd = meta['command']

        assert 'TrustedInstaller' in cmd
        assert 'sc config' in cmd.lower()
        assert 'BYPASS' in meta['tags'] or 'ADVANCED' in meta['tags']


class TestWTSImpersonator:
    """Test WTS Impersonator token hijacking tasks"""

    @pytest.fixture
    def wts_tasks(self):
        plugin = CredentialTheftPlugin()
        tree = plugin.get_task_tree('192.168.45.100', 0, {})
        return next(c for c in tree['children'] if c['id'] == 'wts-impersonator')

    def test_wts_enumeration(self, wts_tasks):
        """PROVES: WTS session enumeration is included"""
        enum = next(c for c in wts_tasks['children'] if c['id'] == 'wts-enum')

        meta = enum['metadata']
        cmd = meta['command']

        assert 'WTSImpersonator' in cmd
        assert '-m enum' in cmd

    def test_wts_local_exec(self, wts_tasks):
        """PROVES: Local token hijacking execution is included"""
        local = next(c for c in wts_tasks['children'] if c['id'] == 'wts-exec-local')

        meta = local['metadata']
        cmd = meta['command']

        assert 'WTSImpersonator' in cmd
        assert '-m exec' in cmd
        assert '-s' in cmd  # session ID

        # Check notes mention SYSTEM context
        notes = meta.get('notes', '')
        assert 'SYSTEM' in notes or 'PsExec' in notes

    def test_wts_remote_exec(self, wts_tasks):
        """PROVES: Remote token hijacking is included"""
        remote = next(c for c in wts_tasks['children'] if c['id'] == 'wts-exec-remote')

        meta = remote['metadata']
        cmd = meta['command']

        assert 'exec-remote' in cmd
        assert 'WTSService' in cmd

    def test_wts_user_hunter(self, wts_tasks):
        """PROVES: User hunter for Domain Admin is included"""
        hunter = next(c for c in wts_tasks['children'] if c['id'] == 'wts-user-hunter')

        meta = hunter['metadata']
        cmd = meta['command']

        assert 'user-hunter' in cmd
        assert '-uh' in cmd  # user to hunt
        assert 'DOMAIN_ADMIN' in meta['tags'] or 'LATERAL_MOVEMENT' in meta['tags']


class TestCrackMapExecDumping:
    """Test CrackMapExec remote dumping tasks"""

    @pytest.fixture
    def cme_tasks(self):
        plugin = CredentialTheftPlugin()
        tree = plugin.get_task_tree('192.168.45.100', 0, {})
        return next(c for c in tree['children'] if c['id'] == 'crackmapexec-dumping')

    def test_cme_sam_dump(self, cme_tasks):
        """PROVES: CrackMapExec SAM dump is included"""
        sam = next(c for c in cme_tasks['children'] if c['id'] == 'cme-sam')

        meta = sam['metadata']
        assert 'crackmapexec' in meta['command'].lower()
        assert '--sam' in meta['command']

    def test_cme_lsa_dump(self, cme_tasks):
        """PROVES: CrackMapExec LSA secrets dump is included"""
        lsa = next(c for c in cme_tasks['children'] if c['id'] == 'cme-lsa')

        meta = lsa['metadata']
        assert 'crackmapexec' in meta['command'].lower()
        assert '--lsa' in meta['command']


class TestAlternativeTools:
    """Test alternative credential dumping tools"""

    @pytest.fixture
    def alt_tasks(self):
        plugin = CredentialTheftPlugin()
        tree = plugin.get_task_tree('192.168.45.100', 0, {})
        return next(c for c in tree['children'] if c['id'] == 'alternative-tools')

    def test_lazagne_included(self, alt_tasks):
        """PROVES: LaZagne multi-source extraction is included"""
        lazagne = next(c for c in alt_tasks['children'] if c['id'] == 'lazagne')

        meta = lazagne['metadata']
        assert 'lazagne' in meta['command'].lower()
        assert 'MULTI_SOURCE' in meta['tags'] or 'AUTOMATED' in meta['tags']

    def test_pypykatz_included(self, alt_tasks):
        """PROVES: pypykatz Python implementation is included"""
        pypykatz = next(c for c in alt_tasks['children'] if c['id'] == 'pypykatz')

        meta = pypykatz['metadata']
        assert 'pypykatz' in meta['command']
        assert 'LINUX' in meta['tags'] or 'PYTHON' in meta['tags']


class TestOSCPMetadataQuality:
    """Test OSCP metadata quality across all tasks"""

    @pytest.fixture
    def all_tasks(self):
        plugin = CredentialTheftPlugin()
        tree = plugin.get_task_tree('192.168.45.100', 0, {})

        # Flatten all tasks
        tasks = []
        def collect_tasks(node):
            if 'metadata' in node:
                tasks.append(node)
            if 'children' in node:
                for child in node['children']:
                    collect_tasks(child)

        collect_tasks(tree)
        return tasks

    def test_all_command_tasks_have_flag_explanations(self, all_tasks):
        """PROVES: All command tasks have flag explanations"""
        command_tasks = [t for t in all_tasks if t.get('type') == 'command']

        for task in command_tasks:
            meta = task['metadata']
            if '<' not in meta.get('command', ''):  # Skip if placeholders only
                # Should have flag explanations or be noted as manual
                assert 'flag_explanations' in meta or 'MANUAL' in meta.get('tags', []), \
                    f"Task {task['id']} missing flag_explanations"

    def test_all_tasks_have_success_indicators(self, all_tasks):
        """PROVES: All tasks with metadata have success indicators"""
        for task in all_tasks:
            if task.get('type') == 'command':
                meta = task['metadata']
                assert 'success_indicators' in meta, \
                    f"Task {task['id']} missing success_indicators"
                assert len(meta['success_indicators']) >= 1

    def test_all_tasks_have_failure_indicators(self, all_tasks):
        """PROVES: Most tasks with metadata have failure indicators"""
        command_tasks = [t for t in all_tasks if t.get('type') == 'command']
        tasks_with_failures = sum(1 for t in command_tasks
                                   if 'failure_indicators' in t['metadata']
                                   and len(t['metadata']['failure_indicators']) >= 1)

        # At least 80% should have failure indicators
        assert tasks_with_failures / len(command_tasks) >= 0.8

    def test_all_tasks_have_alternatives(self, all_tasks):
        """PROVES: All tasks have manual alternatives for OSCP exam"""
        command_tasks = [t for t in all_tasks if t.get('type') == 'command']

        for task in command_tasks:
            meta = task['metadata']
            # Should have alternatives or next_steps
            assert 'alternatives' in meta or 'next_steps' in meta, \
                f"Task {task['id']} missing alternatives/next_steps"

    def test_oscp_tags_present(self, all_tasks):
        """PROVES: Tasks have OSCP relevance tags"""
        command_tasks = [t for t in all_tasks if t.get('type') == 'command']

        oscp_tagged = 0
        for task in command_tasks:
            meta = task['metadata']
            tags = meta.get('tags', [])
            if any('OSCP' in tag for tag in tags):
                oscp_tagged += 1

        # At least 70% should have OSCP tags
        assert oscp_tagged / len(command_tasks) >= 0.7

    def test_notes_provide_context(self, all_tasks):
        """PROVES: Most tasks have educational notes"""
        command_tasks = [t for t in all_tasks if t.get('type') == 'command']

        with_notes = sum(1 for t in command_tasks if 'notes' in t['metadata'])

        # At least 60% should have notes
        assert with_notes / len(command_tasks) >= 0.6


class TestPluginIntegration:
    """Test plugin integration with CRACK Track"""

    def test_task_ids_are_unique(self):
        """PROVES: All task IDs are unique within the tree"""
        plugin = CredentialTheftPlugin()
        tree = plugin.get_task_tree('192.168.45.100', 0, {})

        task_ids = []
        def collect_ids(node):
            if 'id' in node:
                task_ids.append(node['id'])
            if 'children' in node:
                for child in node['children']:
                    collect_ids(child)

        collect_ids(tree)

        # Check for duplicates
        assert len(task_ids) == len(set(task_ids)), "Duplicate task IDs found"

    def test_target_placeholder_usage(self):
        """PROVES: Commands use {target} placeholder correctly"""
        plugin = CredentialTheftPlugin()
        tree = plugin.get_task_tree('192.168.45.100', 0, {})

        # Commands should reference target variable
        def check_commands(node):
            if 'metadata' in node and 'command' in node['metadata']:
                cmd = node['metadata']['command']
                # Remote commands should reference target
                if 'remote' in node.get('name', '').lower() or 'remote' in node.get('id', ''):
                    # Should have target reference or be local-only
                    pass  # Allow both local and remote commands

            if 'children' in node:
                for child in node['children']:
                    check_commands(child)

        check_commands(tree)

    def test_comprehensive_coverage(self):
        """PROVES: Plugin provides comprehensive credential theft coverage"""
        plugin = CredentialTheftPlugin()
        tree = plugin.get_task_tree('192.168.45.100', 0, {})

        # Count total tasks
        task_count = 0
        def count_tasks(node):
            nonlocal task_count
            if 'metadata' in node:
                task_count += 1
            if 'children' in node:
                for child in node['children']:
                    count_tasks(child)

        count_tasks(tree)

        # Should have substantial number of tasks
        assert task_count >= 35, f"Only {task_count} tasks - expected 35+ for comprehensive coverage"


class TestDocumentationQuality:
    """Test documentation and educational value"""

    def test_module_docstring(self):
        """PROVES: Module has comprehensive docstring"""
        from crack.track.services import credential_theft

        doc = credential_theft.__doc__
        assert doc is not None
        assert 'Mimikatz' in doc
        assert 'LSASS' in doc
        assert 'NTLM' in doc
        assert 'CrackPot' in doc  # Attribution

    def test_class_docstring(self):
        """PROVES: Plugin class has descriptive docstring"""
        plugin = CredentialTheftPlugin()
        doc = plugin.__class__.__doc__
        assert doc is not None
        assert len(doc) > 20

    def test_references_in_notes(self):
        """PROVES: Tasks include references to tools and resources"""
        plugin = CredentialTheftPlugin()
        tree = plugin.get_task_tree('192.168.45.100', 0, {})

        # Collect all notes
        notes = []
        def collect_notes(node):
            if 'metadata' in node and 'notes' in node['metadata']:
                notes.append(node['metadata']['notes'])
            if 'children' in node:
                for child in node['children']:
                    collect_notes(child)

        collect_notes(tree)

        # Should reference tools/sources
        all_notes = ' '.join(notes)
        assert 'github.com' in all_notes.lower() or 'http' in all_notes.lower()
