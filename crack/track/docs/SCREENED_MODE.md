# CRACK Track Screened Mode (-X)

## Table of Contents

- [Overview](#overview)
- [Features](#features)
  - [🎯 Core Capabilities](#-core-capabilities)
  - [🔧 German Engineering Principles](#-german-engineering-principles)
- [Usage](#usage)
  - [Starting Screened Mode](#starting-screened-mode)
  - [Viewing Terminal Output](#viewing-terminal-output)
- [Architecture](#architecture)
  - [Component Overview](#component-overview)
  - [Execution Flow](#execution-flow)
- [Pattern Matching](#pattern-matching)
  - [Supported Tools](#supported-tools)
  - [Base Patterns](#base-patterns)
- [Example Workflow](#example-workflow)
  - [1. Start Screened Session](#1-start-screened-session)
  - [2. Execute Task](#2-execute-task)
  - [3. View Automatic Extractions](#3-view-automatic-extractions)
- [Session Logs](#session-logs)
- [Advanced Usage](#advanced-usage)
  - [Custom Pattern Addition](#custom-pattern-addition)
  - [Terminal Environment](#terminal-environment)
  - [Batch Execution](#batch-execution)
- [Troubleshooting](#troubleshooting)
  - [Terminal Won't Start](#terminal-wont-start)
  - [Output Not Parsing](#output-not-parsing)
  - [Can't Attach to Session](#cant-attach-to-session)
- [Benefits for OSCP](#benefits-for-oscp)
- [Implementation Details](#implementation-details)
  - [Files Created](#files-created)
  - [Key Classes](#key-classes)
- [Future Enhancements](#future-enhancements)
- [Summary](#summary)

---

## Overview

**Screened Mode** is a powerful feature that launches a persistent terminal session for automatic command execution with real-time output parsing and finding extraction. This eliminates the need for manual copy-paste and automatically logs everything for OSCP documentation.

## Features

### 🎯 Core Capabilities
- **Persistent PTY Terminal**: Commands run in a real shell with preserved environment
- **Auto-Parsing**: Output automatically parsed for ports, services, credentials, vulnerabilities
- **Event Logging**: Every command and output logged with timestamps
- **Finding Extraction**: Automatically adds discoveries to your profile
- **Session Attachment**: View terminal in separate window for monitoring

### 🔧 German Engineering Principles
- **Zero External Dependencies**: Uses only Python stdlib (pty, select, os)
- **Clean Architecture**: Strategy pattern for execution modes
- **Efficient Parsing**: Compiled regex patterns for speed
- **Graceful Degradation**: Falls back to subprocess on failure

## Usage

### Starting Screened Mode

```bash
# Interactive mode with screened terminal
crack track -i -X 192.168.45.100

# With session resume
crack track -i -X --resume 192.168.45.100
```

### Viewing Terminal Output

When screened mode starts, you'll see:

```
[SCREENED MODE] Initializing persistent terminal...
[SCREENED] Terminal started successfully

📺 To view terminal output in another window:
   screen -x crack_192_168_45_100
   OR
   tail -f /home/user/.crack/screened/192.168.45.100/session_20240315_143022.log
```

Open a second terminal and run one of these commands to watch live output.

## Architecture

### Component Overview

```
InteractiveSession (session.py)
    ├── ScreenedTerminal (terminal.py)
    │   ├── PTY Master/Slave
    │   ├── Shell Process (bash)
    │   └── Session Logger
    ├── CommandExecutor (command_executor.py)
    │   ├── ScreenedExecutor
    │   └── SubprocessExecutor (fallback)
    └── OutputPatternMatcher (output_patterns.py)
        ├── Base Patterns
        └── Tool-Specific Matchers
```

### Execution Flow

1. **Terminal Initialization**
   - Create PTY (pseudo-terminal) pair
   - Fork bash process with PTY slave
   - Set non-blocking I/O on master

2. **Command Execution**
   - Replace {TARGET} placeholders
   - Write command to PTY master
   - Read output line-by-line
   - Detect completion (prompt pattern)

3. **Output Parsing**
   - Detect tool from command
   - Apply tool-specific patterns
   - Extract findings (ports, services, etc.)
   - Update task status

4. **Profile Updates**
   - Auto-add discovered ports
   - Store found credentials
   - Log vulnerabilities
   - Save with [SCREENED] source tag

## Pattern Matching

### Supported Tools

Tool-specific parsers for optimal extraction:

- **Nmap**: Ports, services, OS detection, NSE scripts
- **Gobuster**: Directories, files, status codes
- **Enum4linux**: Users, shares, groups
- **SQLMap**: Injections, databases, extracted data
- **Nikto**: Vulnerabilities, OSVDB references, server info

### Base Patterns

Generic patterns that work across all tools:

```python
# Port detection
80/tcp open http Apache 2.4.41

# Credential extraction
Username: admin
Password: P@ssw0rd123

# CVE detection
CVE-2021-41773

# Success indicators
Scan complete
Found 5 results

# Failure indicators
Error: Permission denied
Command not found
```

## Example Workflow

### 1. Start Screened Session

```bash
$ crack track -i -X 192.168.45.100

[SCREENED MODE] Initializing persistent terminal...
[SCREENED] Terminal started successfully

📺 To view terminal output in another window:
   tail -f /home/kali/.crack/screened/192.168.45.100/session_20240315_143022.log
```

### 2. Execute Task

```
Choice [or shortcut]: n

Task: Quick TCP Port Scan
Command: nmap -sS -p- --min-rate=1000 192.168.45.100

[SCREENED] Command will run in persistent terminal
Output will be automatically parsed for findings

Execute this command? [Y/n]: y

[SCREENED] Executing...

Command completed successfully

[SCREENED] Extracted findings:
  • ports: 5 found
  • services: 3 found

✓ Task marked complete
```

### 3. View Automatic Extractions

```bash
$ crack track show 192.168.45.100

Ports:
  80/tcp  - http    - Apache 2.4.41    [SCREENED] nmap scan
  443/tcp - https   - nginx 1.18        [SCREENED] nmap scan
  3306/tcp - mysql  - MySQL 5.7.32      [SCREENED] nmap scan
```

## Session Logs

All terminal I/O is logged to:
```
~/.crack/screened/<target>/session_YYYYMMDD_HHMMSS.log
```

Log format:
```
[2024-03-15 14:30:22] [COMMAND] nmap -sV 192.168.45.100
[2024-03-15 14:30:22] [OUTPUT] Starting Nmap 7.94
[2024-03-15 14:30:25] [OUTPUT] 80/tcp open http Apache httpd 2.4.41
[2024-03-15 14:30:35] [OUTPUT] Nmap done: 1 IP address (1 host up)
```

## Advanced Usage

### Custom Pattern Addition

Add patterns to `output_patterns.py`:

```python
# In OutputPatternMatcher.BASE_PATTERNS
'api_keys': [
    re.compile(r'api[_-]?key[:\s]+([A-Za-z0-9]{32,})', re.IGNORECASE),
    re.compile(r'token[:\s]+([A-Za-z0-9]{40,})', re.IGNORECASE),
]
```

### Terminal Environment

Set variables that persist across commands:

```python
# In terminal.py
terminal.set_environment('LHOST', '192.168.45.5')
terminal.set_environment('LPORT', '4444')
```

### Batch Execution

Execute multiple tasks automatically:

```python
# In command_executor.py
batch = BatchExecutor(screened_executor)
results = batch.execute_sequence(pending_tasks, target)
summary = batch.get_summary()
```

## Troubleshooting

### Terminal Won't Start

```bash
# Check PTY availability
python3 -c "import pty; print(pty.openpty())"

# Fallback to subprocess mode
crack track -i 192.168.45.100  # Without -X
```

### Output Not Parsing

```bash
# Check patterns manually
grep -E '(\d+)/(tcp|udp)\s+open' output.txt

# View raw session log
cat ~/.crack/screened/*/session_*.log
```

### Can't Attach to Session

```bash
# List screen sessions
screen -ls

# Force attach if stuck
screen -D -r crack_192_168_45_100

# Use log file instead
tail -f ~/.crack/screened/192.168.45.100/session_*.log
```

## Benefits for OSCP

1. **Documentation**: Every command logged with timestamp
2. **Efficiency**: No manual copy-paste of results
3. **Accuracy**: Automated parsing reduces human error
4. **Speed**: Findings instantly added to profile
5. **Persistence**: Terminal stays alive between commands
6. **Proof**: Complete session logs for report

## Implementation Details

### Files Created

- `core/terminal.py` - PTY terminal management (200 lines)
- `core/command_executor.py` - Execution strategies (150 lines)
- `parsers/output_patterns.py` - Pattern matching (350 lines)
- Modified `interactive/session.py` - Integration (+100 lines)
- Modified `cli.py` - CLI flags (+10 lines)
- `tests/track/test_screened_terminal.py` - Unit tests (400 lines)

### Key Classes

**ScreenedTerminal**
- Manages PTY lifecycle
- Handles I/O operations
- Logs all activity

**CommandExecutor**
- Factory for execution strategies
- Abstracts subprocess vs screened

**OutputPatternMatcher**
- Base and tool-specific patterns
- Real-time line processing
- Finding extraction

**ScreenedExecutor**
- Uses ScreenedTerminal
- Integrates OutputPatternMatcher
- Updates task tree

## Future Enhancements

- [ ] ANSI color preservation in logs
- [ ] Regex pattern hot-reload
- [ ] Multi-command scripts
- [ ] Parallel terminal sessions
- [ ] Web UI for terminal viewing
- [ ] Export to Obsidian format

## Summary

Screened mode transforms CRACK Track into a powerful command automation platform while maintaining the simplicity and transparency needed for OSCP exam preparation. Every command is logged, every output is parsed, and every finding is captured - automatically.

**Total Implementation**: ~500 lines of focused Python using only stdlib.