# C2 Configuration Extraction and Analysis Plugin - Summary

## Mission Accomplished

Successfully mined HackTricks AdaptixC2 content and extended CRACK Track post-exploitation plugin with comprehensive C2 analysis capabilities.

---

## Source Material

**File**: `.references/hacktricks/src/generic-methodologies-and-resources/basic-forensic-methodology/adaptixc2-config-extraction-and-ttps.md`

**Size**: 251 lines

**Content**: AdaptixC2 C2 framework configuration extraction, network fingerprinting, persistence mechanisms, and TTPs

**Status**: DELETED after processing

---

## Plugin Extension Details

### Location

**File**: `/home/kali/OSCP/crack/track/services/post_exploit.py`

**Method Added**: `_get_c2_analysis_tasks(target: str, os_type: str = 'windows')`

**Integration**: Added to existing PostExploitPlugin (not a separate plugin)

### Architecture

The C2 analysis extension follows the CRACK Track plugin pattern:
- Hierarchical task tree with parent/child relationships
- Cross-platform support (Windows/Linux command adaptation)
- Complete OSCP metadata on every task
- Educational focus with flag explanations and manual alternatives

---

## Task Structure

### 5 Major Phases

```
C2 Configuration Extraction and Analysis (Root)
├── Process Memory Dump
│   ├── Identify Suspicious Processes
│   └── Dump Suspicious Process Memory
├── Beacon Configuration Extraction
│   ├── Locate Beacon Binaries
│   ├── Extract Strings from Beacon
│   └── Decrypt RC4 Configuration (AdaptixC2)
├── C2 Network Indicators
│   ├── Identify Active C2 Connections
│   ├── Capture C2 Traffic
│   └── HTTP C2 Fingerprinting
├── C2 Persistence Mechanism Hunting
│   ├── Check Startup Folders
│   ├── Check Registry Run Keys
│   ├── Check for DLL Hijacking
│   └── Check Scheduled Tasks
└── C2 Indicators Documentation (OSCP Report Guidance)
```

### Total Tasks

- **5 parent phases**
- **14 command/manual tasks**
- **19 total nodes** in task tree

---

## Key Features Extracted

### 1. Memory Analysis

**Tasks**:
- Identify suspicious processes (powershell, rundll32, regsvr32, mshta, wscript, cscript)
- Dump process memory with procdump (Windows) or gcore (Linux)

**OSCP Value**: Understanding process analysis for post-exploitation documentation

**Commands**:
- Windows: `tasklist /v | findstr /i "powershell rundll32 regsvr32 mshta wscript cscript"`
- Linux: `ps aux | grep -E "powershell|rundll32|regsvr32|mshta|wscript|cscript" | grep -v grep`
- Memory dump: `procdump -ma <PID> beacon_dump.dmp` or `gcore -o beacon_dump <PID>`

### 2. Beacon Configuration Extraction

**Tasks**:
- Locate beacon binaries in staging locations (%TEMP%, %APPDATA%, /tmp, /dev/shm)
- Extract strings looking for C2 indicators (URLs, User-Agents, custom headers)
- Decrypt RC4-packed configurations (AdaptixC2-specific)

**OSCP Value**: Manual binary analysis techniques, understanding C2 configuration structure

**Key Technique**: Complete Python RC4 decryption script included in task metadata
```python
# AdaptixC2 config format: [4 bytes size][N bytes RC4 ciphertext][16 bytes key]
blob = open("beacon.bin","rb").read()
size = struct.unpack("<I", blob[:4])[0]
ct = blob[4:4+size]
key = blob[4+size:4+size+16]
config = rc4(key, ct)
```

**Commands**:
- Find beacons: `dir /s /b C:\Users\*\AppData\*.exe C:\Users\*\AppData\*.dll C:\Temp\*.exe 2>nul`
- Extract strings: `strings -a -n 8 beacon.exe | grep -E "(http|https|tcp|smb|pipe|Mozilla|User-Agent|X-|POST|GET)" | tee beacon_strings.txt`

### 3. Network Indicators

**Tasks**:
- Identify active C2 connections (netstat/ss analysis)
- Capture C2 traffic with tcpdump/Wireshark
- HTTP C2 fingerprinting (User-Agent patterns, custom headers, beaconing intervals)

**OSCP Value**: Network traffic analysis for exam report writing, understanding C2 communication patterns

**C2 Framework Signatures Included**:
- AdaptixC2: `Mozilla/5.0 (Windows NT 6.2; rv:20.0) Gecko/20121202 Firefox/20.0`
- Cobalt Strike: Microsoft Internet Explorer (older), modern Chrome UAs
- Metasploit: Legitimate-looking User-Agents
- Custom headers: X-Beacon-Id, X-App-Id, X-Session-Id

**Commands**:
- Active connections: `netstat -ano | findstr ESTABLISHED` (Windows) or `netstat -antp 2>/dev/null | grep ESTABLISHED` (Linux)
- Traffic capture: `tcpdump -i any -w c2_traffic.pcap host <C2_IP> or port 443 or port 80`
- Wireshark filters: `http.request.method == "POST"`, `http.user_agent contains "Mozilla"`, `http.header contains "X-Beacon"`

### 4. Persistence Hunting

**Tasks**:
- Check startup folders for malicious .lnk shortcuts
- Check registry Run keys (HKCU/HKLM)
- Identify DLL hijacking in user-writable paths
- Check scheduled tasks (Windows) and cron jobs (Linux)

**OSCP Value**: Complete persistence enumeration for post-exploitation phase, MITRE ATT&CK mapping

**MITRE ATT&CK Techniques Referenced**:
- T1547.001 - Registry Run Keys / Startup Folder
- T1574.001 - DLL Search Order Hijacking
- T1053.005 - Scheduled Task (Windows)
- T1053.003 - Cron (Linux)

**Commands**:
- Startup folders: `dir "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"` & `dir "%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Startup"`
- Registry Run keys: `reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run` & `reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
- DLL hijacking: `dir /s /b C:\Users\*\AppData\*.dll`
- Scheduled tasks: `schtasks /query /fo LIST /v | findstr /i "powershell rundll32 wscript"`

### 5. OSCP Report Documentation

**Task**: Comprehensive guidance on documenting C2 indicators for OSCP exam report

**Requirements Covered**:
1. C2 Infrastructure (IP/domain, ports, protocols, User-Agent, custom headers)
2. Beacon Configuration (sleep/jitter, kill date, working hours, chunk size)
3. Persistence Mechanisms (registry keys, startup shortcuts, scheduled tasks, DLL hijacks)
4. IOCs (file hashes MD5/SHA256, file paths, timestamps, process names/PIDs, network connections)
5. Screenshots (extracted config, network traffic, process list, persistence keys)

**CRACK Track Integration**:
```bash
crack track finding <target> --type c2_infrastructure --description "AdaptixC2 beacon found" --source "Memory dump analysis"
crack track note <target> "C2 config: servers=[tech-system.online:443], sleep=4s"
```

---

## OSCP Metadata Quality

### Flag Explanations

**Every command task includes complete flag explanations**:

Example from `c2-strings-analysis`:
```python
'flag_explanations': {
    'strings': 'Extract printable character sequences from binary',
    '-a': 'Scan entire file (not just data sections)',
    '-n 8': 'Minimum string length of 8 characters',
    'grep -E': 'Extended regex for multiple patterns',
    'tee': 'Save output to file while displaying'
}
```

### Success/Failure Indicators

**Example from `c2-active-connections`**:
```python
'success_indicators': [
    'Connections to external IPs on common C2 ports (443, 80, 8443, 4443)',
    'Suspicious processes with outbound connections',
    'Connections to known malicious IPs/domains',
    'Named pipe connections (SMB C2)'
],
'failure_indicators': [
    'No suspicious connections (beacon may be sleeping)',
    'Permission denied (need root/admin)',
    'DNS resolution shows legitimate services'
]
```

### Manual Alternatives

**Every command task provides manual alternatives** for OSCP exam scenarios where tools fail:

Example from `c2-traffic-capture`:
```python
'alternatives': [
    'Windows: Wireshark GUI capture',
    'tshark -i <interface> -w c2.pcap',
    'Netsh trace (built-in Windows packet capture)',
    'Manual: Enable firewall logging to track connections'
]
```

### Next Steps Guidance

**Attack chain progression guidance** included on all tasks:

Example from `c2-strings-analysis`:
```python
'next_steps': [
    'Research extracted domains/IPs',
    'Identify C2 framework by User-Agent patterns',
    'Check for encryption keys or RC4 patterns',
    'Extract configuration blob for decryption'
]
```

### Time Estimates

**OSCP exam time planning** included on most tasks:
- Quick wins: `2-3 minutes`
- Standard analysis: `5-10 minutes`
- Deep analysis: `15-30 minutes`

### OSCP Relevance Tags

**All tasks tagged with OSCP relevance**:
- `OSCP:HIGH` - Critical understanding for post-exploitation (documentation task)
- `OSCP:MEDIUM` - Valuable C2 analysis skills (most tasks)
- Tags also include: `QUICK_WIN`, `MANUAL`, `POST_EXPLOIT`, `RESEARCH`, `WINDOWS`, `LINUX`

---

## Cross-Platform Support

### Windows-Specific Commands
- `tasklist /v | findstr /i "powershell rundll32"`
- `procdump -ma <PID> beacon_dump.dmp`
- `netstat -ano | findstr ESTABLISHED`
- `reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- `schtasks /query /fo LIST /v`

### Linux-Specific Commands
- `ps aux | grep -E "powershell|rundll32|regsvr32"`
- `gcore -o beacon_dump <PID>`
- `netstat -antp 2>/dev/null | grep ESTABLISHED`
- `ls -la ~/.config/autostart/ /etc/xdg/autostart/`
- `crontab -l; ls -la /etc/cron.*`

### Command Adaptation
Tasks automatically select correct command based on `os_type` parameter:
```python
def _get_c2_analysis_tasks(self, target: str, os_type: str = 'windows'):
    # ...
    'command': 'netstat -antp 2>/dev/null | grep ESTABLISHED' if os_type == 'linux'
               else 'netstat -ano | findstr ESTABLISHED'
```

---

## Testing

### Test Suite

**File**: `/home/kali/OSCP/crack/tests/track/test_c2_analysis_plugin.py`

**Tests**: 22 comprehensive tests

**Coverage**:
- Plugin name and structure validation
- Windows/Linux task generation
- All 5 phase structures
- Metadata completeness (flags, indicators, alternatives, tags)
- RC4 decryption script inclusion
- Cross-platform command adaptation
- OSCP report documentation guidance
- Educational value assertions

### Test Results

```
22 passed in 0.02s (100% pass rate)
```

### Key Test Validations

1. **Structure Tests**: Hierarchical task tree, unique IDs, parent/child relationships
2. **Metadata Tests**: All command tasks have flag_explanations, success_indicators, alternatives
3. **OSCP Tests**: All tasks tagged with OSCP relevance, time estimates present
4. **Content Tests**: RC4 script complete, MITRE ATT&CK references, C2 framework signatures
5. **Value Test**: Proves educational value for OSCP exam preparation

---

## Educational Highlights

### 1. Complete RC4 Decryption Implementation

Includes full working Python script for AdaptixC2 config extraction:
- RC4 cipher implementation (no external dependencies)
- Binary parsing with struct module
- Configuration blob location in PE .rdata section
- Config format: `[4 bytes size][N bytes ciphertext][16 bytes key]`

### 2. C2 Framework Fingerprinting

User-Agent patterns for framework identification:
- AdaptixC2: Firefox 20.0 (specific version pattern)
- Cobalt Strike: IE (legacy), modern Chrome
- Metasploit: Legitimate UAs

Custom headers:
- X-Beacon-Id, X-App-Id, X-Session-Id

Beaconing patterns:
- Sleep + jitter timing (observable in traffic)
- Regular callback intervals

### 3. Persistence Mechanisms

Complete coverage of common C2 persistence:
- Registry Run keys (HKCU/HKLM)
- Startup folder shortcuts
- Scheduled tasks
- DLL search order hijacking

Includes detection commands, verification steps, and MITRE ATT&CK mappings.

### 4. OSCP Report Writing Guidance

Task `c2-documentation` provides complete checklist for OSCP exam report:
- What to document (infrastructure, config, persistence, IOCs, screenshots)
- How to document (CRACK Track integration commands)
- What screenshots to take
- Required detail level (file hashes, timestamps, full paths)

---

## OSCP Exam Relevance

### OSCP:MEDIUM Rating Justification

**Why MEDIUM (not HIGH)**:
- C2 configuration extraction is post-exploitation analysis (not primary attack vector)
- Most valuable for report writing and understanding post-exploitation phase
- Not commonly required to achieve shell/privilege escalation

**Why MEDIUM (not LOW)**:
- Understanding C2 traffic patterns helps identify beacons on compromised networks
- Post-exploitation enumeration is part of OSCP methodology
- Report documentation of C2 infrastructure shows thorough understanding
- Persistence mechanism hunting is valuable privilege escalation research

### Exam Value

1. **Report Writing**: Complete documentation of C2 infrastructure for exam report
2. **Network Analysis**: Understanding callback patterns when multiple machines compromised
3. **Persistence Enumeration**: Finding C2 loaders helps understand full attack chain
4. **Binary Analysis**: String extraction and configuration decryption are valuable skills
5. **Methodology**: Systematic post-exploitation enumeration approach

---

## Usage Examples

### Generating C2 Analysis Tasks

```python
from crack.track.services.post_exploit import PostExploitPlugin

plugin = PostExploitPlugin()

# Windows target
win_tasks = plugin._get_c2_analysis_tasks('192.168.45.100', os_type='windows')

# Linux target
linux_tasks = plugin._get_c2_analysis_tasks('10.10.10.50', os_type='linux')
```

### Task Tree Output

```python
{
    'id': 'c2-analysis',
    'name': 'C2 Configuration Extraction and Analysis',
    'type': 'parent',
    'children': [
        {
            'id': 'c2-memory-dump',
            'name': 'Process Memory Dump',
            'type': 'parent',
            'children': [...]
        },
        {
            'id': 'c2-config-extraction',
            'name': 'Beacon Configuration Extraction',
            'type': 'parent',
            'children': [...]
        },
        # ... 3 more phases
    ]
}
```

### Integration with CRACK Track

The C2 analysis tasks can be manually invoked in CRACK Track interactive mode or added as a phase to the post-exploitation workflow.

**Note**: Currently not auto-triggered (requires manual activation), as C2 analysis is situational based on finding active beacons.

---

## Files Modified/Created

### Modified
1. `/home/kali/OSCP/crack/track/services/post_exploit.py`
   - Added `_get_c2_analysis_tasks()` method (575 lines)
   - Comprehensive C2 analysis task generation
   - Cross-platform command support

### Created
2. `/home/kali/OSCP/crack/tests/track/test_c2_analysis_plugin.py`
   - 22 comprehensive tests
   - 100% pass rate
   - Tests structure, metadata, cross-platform, OSCP value

3. `/home/kali/OSCP/crack/C2_ANALYSIS_PLUGIN_SUMMARY.md`
   - This summary document
   - Complete documentation of extension

### Deleted
4. `.references/hacktricks/src/generic-methodologies-and-resources/basic-forensic-methodology/adaptixc2-config-extraction-and-ttps.md`
   - Source material processed and deleted as requested

---

## Code Quality

### Follows Plugin Contribution Guide

- Complete OSCP metadata on all tasks
- Flag explanations for every command
- Success/failure indicators
- Manual alternatives (OSCP exam requirement)
- Next steps guidance
- Time estimates for exam planning
- Proper task tree hierarchy
- Unique task IDs
- Appropriate tags (OSCP:MEDIUM, QUICK_WIN, MANUAL, etc.)

### Type Hints and Documentation

```python
def _get_c2_analysis_tasks(self, target: str, os_type: str = 'windows') -> Dict[str, Any]:
    """C2 beacon configuration extraction and analysis tasks"""
```

### Defensive Coding

- Default values for optional parameters (`os_type='windows'`)
- Conditional command selection based on OS
- Graceful degradation (manual tasks when commands not available)

---

## Key Techniques Documented

1. **Process Memory Dumping**: procdump (Windows), gcore (Linux)
2. **String Extraction**: strings command with regex filtering
3. **RC4 Decryption**: Complete Python implementation
4. **Network Analysis**: netstat, tcpdump, Wireshark filtering
5. **Traffic Fingerprinting**: User-Agent patterns, custom headers, beaconing intervals
6. **Persistence Hunting**: Registry, startup folders, scheduled tasks, DLL hijacking
7. **Binary Analysis**: PE section analysis (.rdata), hex editing, configuration blob extraction
8. **OSCP Documentation**: Complete IOC documentation checklist

---

## Success Metrics

- **22/22 tests passing** (100% pass rate)
- **575 lines** of C2 analysis task definitions
- **19 task nodes** in hierarchical tree
- **5 major phases** covering complete C2 analysis workflow
- **14 command/manual tasks** with complete OSCP metadata
- **100% task coverage** for flag_explanations, success_indicators, alternatives
- **Cross-platform support** (Windows/Linux command adaptation)
- **OSCP:MEDIUM relevance** (valuable post-exploitation understanding)
- **Complete RC4 decryption script** (educational value)
- **MITRE ATT&CK mapping** (4+ techniques referenced)
- **C2 framework fingerprints** (AdaptixC2, Cobalt Strike, Metasploit)

---

## Next Steps

### Future Enhancements

1. **Auto-trigger**: Add logic to auto-generate C2 analysis tasks when suspicious processes detected
2. **Additional C2 Frameworks**: Extend fingerprinting to include Covenant, Empire, PoshC2
3. **Memory Forensics**: Add volatility commands for advanced memory analysis
4. **SSL Interception**: Add mitmproxy/Burp Suite guidance for HTTPS C2 analysis
5. **Beacon Simulation**: Add testing commands to verify C2 detection techniques

### Integration Ideas

1. Add C2 analysis as sub-phase to existing post-exploitation workflow
2. Create interactive mode prompt when suspicious network connections found
3. Auto-document C2 findings with CRACK Track `finding` command
4. Generate YARA rules from extracted configurations

---

## Conclusion

Successfully extended CRACK Track post-exploitation plugin with comprehensive C2 configuration extraction and analysis capabilities. The extension:

- **Follows CRACK Track plugin patterns** (hierarchical tasks, OSCP metadata)
- **Provides educational value** (complete RC4 script, framework fingerprints, MITRE mapping)
- **Supports OSCP exam preparation** (report documentation guidance, manual alternatives)
- **Includes comprehensive tests** (22 tests, 100% pass rate)
- **Covers complete C2 analysis workflow** (memory, config, network, persistence, documentation)

**Source material** processed and deleted as requested.

**Ready for integration** into CRACK Track post-exploitation workflows.
