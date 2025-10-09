# Command Templates System - Usage Guide

## Table of Contents

- [Overview](#overview)
- [Quick Start](#quick-start)
  - [From Interactive Mode](#from-interactive-mode)
  - [Available Shortcuts](#available-shortcuts)
- [Template Categories](#template-categories)
  - [Recon Templates](#recon-templates)
  - [Web Templates](#web-templates)
  - [Enumeration Templates](#enumeration-templates)
  - [Exploitation Templates](#exploitation-templates)
- [Example Workflows](#example-workflows)
  - [Port Discovery](#port-discovery)
  - [Web Enumeration](#web-enumeration)
  - [Exploitation](#exploitation)
- [Template Features](#template-features)
  - [Flag Explanations](#flag-explanations)
  - [Manual Alternatives](#manual-alternatives)
  - [Success Indicators](#success-indicators)
  - [Time Estimates](#time-estimates)
- [Programmatic Usage](#programmatic-usage)
  - [Python API](#python-api)
  - [Search Templates](#search-templates)
  - [Access Template Metadata](#access-template-metadata)
- [Template Structure](#template-structure)
  - [Full Template Example](#full-template-example)
- [OSCP Exam Best Practices](#oscp-exam-best-practices)
- [Tips and Tricks](#tips-and-tricks)
  - [Quick Template Access](#quick-template-access)
  - [Keyword Search](#keyword-search)
  - [Reuse Commands](#reuse-commands)
  - [Combine with Tasks](#combine-with-tasks)
  - [Learn Flag Meanings](#learn-flag-meanings)
- [Troubleshooting](#troubleshooting)
  - [Template Not Found](#template-not-found)
  - [Variable Substitution Failed](#variable-substitution-failed)
  - [Search Returns Nothing](#search-returns-nothing)
- [Advanced Usage](#advanced-usage)
  - [Custom Templates (Future)](#custom-templates-future)
  - [Batch Execution (Future)](#batch-execution-future)
- [Summary](#summary)

---

## Overview

The Command Templates System provides quick access to pre-configured OSCP commands with variable substitution, flag explanations, and manual alternatives. Accessible via the **'x'** shortcut in CRACK Track Interactive Mode.

## Quick Start

### From Interactive Mode

```bash
# Start interactive mode
crack track -i 192.168.45.100

# Press 'x' to open templates menu
x

# Select template by number or keyword
1           # Select first template
nmap        # Search for nmap templates
gobuster    # Search for gobuster

# Fill in variables when prompted
TARGET: 192.168.45.100
PORTS: 22,80,443

# Review final command and execute
Execute command? [y/N]: y
```

### Available Shortcuts

In Interactive Mode:
- **x** - Open command templates menu
- **s** - Show status
- **t** - Show task tree
- **r** - Show recommendations
- **n** - Execute next task
- **c** - Change confirmation mode
- **b** - Go back
- **h** - Help
- **q** - Quit

## Template Categories

### Recon Templates

**nmap-quick** - Fast TCP SYN scan
- Scans all 65535 ports quickly
- Time: 1-5 minutes
- Tags: OSCP:HIGH, QUICK_WIN, RECON

**nmap-service** - Service version detection
- Enumerates services on discovered ports
- Time: 2-5 minutes
- Tags: OSCP:HIGH, ENUM, RECON

**nmap-udp** - UDP port scan
- Top 20 most common UDP ports
- Time: 5-10 minutes
- Tags: OSCP:MEDIUM, RECON, UDP

### Web Templates

**gobuster-dir** - Directory brute-force
- Common extensions: php, html, txt
- Time: 1-10 minutes (depends on wordlist)
- Tags: OSCP:HIGH, QUICK_WIN, WEB

**nikto-scan** - Web vulnerability scanner
- Comprehensive web server checks
- Time: 5-15 minutes
- Tags: OSCP:MEDIUM, WEB, NOISY

**whatweb** - Technology fingerprinting
- Identifies CMS, frameworks, versions
- Time: < 1 minute
- Tags: OSCP:HIGH, QUICK_WIN, WEB

### Enumeration Templates

**enum4linux** - Complete SMB enumeration
- Users, shares, groups, password policy
- Time: 1-3 minutes
- Tags: OSCP:HIGH, QUICK_WIN, ENUM, SMB

**smbclient-list** - List SMB shares
- Null session attempt
- Time: < 1 minute
- Tags: OSCP:HIGH, QUICK_WIN, ENUM, SMB

**ldapsearch-anon** - Anonymous LDAP query
- Domain information enumeration
- Time: 1-2 minutes
- Tags: OSCP:MEDIUM, ENUM, LDAP, AD

### Exploitation Templates

**searchsploit** - Exploit database search
- Search by service, version, or CVE
- Time: < 1 minute
- Tags: OSCP:HIGH, QUICK_WIN, EXPLOIT

**bash-reverse-shell** - Bash TCP reverse shell
- For command injection scenarios
- Time: < 1 minute
- Tags: OSCP:HIGH, QUICK_WIN, SHELL, LINUX

**nc-listener** - Netcat listener
- Start listener for reverse shells
- Time: < 1 minute
- Tags: OSCP:HIGH, QUICK_WIN, SHELL

## Example Workflows

### Port Discovery

```bash
# Step 1: Quick scan
x → nmap-quick → TARGET: 192.168.45.100 → Execute

# Step 2: Service scan on found ports
x → nmap-service → TARGET: 192.168.45.100
                 → PORTS: 22,80,443,3306 → Execute
```

### Web Enumeration

```bash
# Step 1: Technology fingerprinting
x → whatweb → URL: http://192.168.45.100 → Execute

# Step 2: Directory brute-force
x → gobuster-dir → URL: http://192.168.45.100
                 → WORDLIST: /usr/share/wordlists/dirb/common.txt
                 → Execute

# Step 3: Vulnerability scan
x → nikto-scan → URL: http://192.168.45.100 → Execute
```

### Exploitation

```bash
# Terminal 1: Start listener
x → nc-listener → LPORT: 4444 → Execute

# Terminal 2: Send reverse shell
x → bash-reverse-shell → LHOST: 192.168.45.200
                       → LPORT: 4444
                       → Copy command and inject
```

## Template Features

### Flag Explanations

Every template explains what flags do and why:

```
Flag Explanations:
  -sS: TCP SYN scan (stealth scan, requires root)
  -p-: Scan all 65535 ports (default is top 1000)
  --min-rate=1000: Send at least 1000 packets per second (faster scan)
  -oA: Output all formats (REQUIRED for OSCP documentation)
```

### Manual Alternatives

Templates provide manual methods for OSCP exam scenarios:

```
Manual alternatives:
  • nc -zv 192.168.45.100 1-65535 2>&1 | grep succeeded
  • For port in $(seq 1 65535); do nc -zv -w1 192.168.45.100 $port 2>&1; done | grep succeeded
```

### Success Indicators

Templates help verify results:

```
Success indicators:
  ✓ Open ports discovered
  ✓ Scan completes without firewall blocking
  ✓ Service names and versions identified
```

### Time Estimates

Templates include exam time planning:

```
Estimated time: 1-5 minutes
```

## Programmatic Usage

### Python API

```python
from crack.track.interactive.templates import TemplateRegistry

# Get template
template = TemplateRegistry.get('nmap-quick')

# Fill variables
command = template.fill({'TARGET': '192.168.45.100'})

# Execute
import subprocess
subprocess.run(command, shell=True)
```

### Search Templates

```python
# Search by keyword
results = TemplateRegistry.search('nmap')
for t in results:
    print(f"{t.name} [{t.category}]")

# Filter by category
web_templates = TemplateRegistry.list_by_category('web')

# Get all categories
categories = TemplateRegistry.get_categories()
# Returns: ['recon', 'web', 'enumeration', 'exploitation']
```

### Access Template Metadata

```python
template = TemplateRegistry.get('gobuster-dir')

print(f"Name: {template.name}")
print(f"Command: {template.command}")
print(f"Category: {template.category}")
print(f"Tags: {template.tags}")
print(f"Variables: {len(template.variables)}")

# Flag explanations
for flag, explanation in template.flag_explanations.items():
    print(f"{flag}: {explanation}")

# Success indicators
for indicator in template.success_indicators:
    print(f"✓ {indicator}")

# Alternatives
for alt in template.alternatives:
    print(f"• {alt}")
```

## Template Structure

### Full Template Example

```python
CommandTemplate(
    template_id='nmap-quick',
    name='Nmap Quick Scan',
    command='nmap -sS -p- --min-rate=1000 <TARGET> -oA nmap_quick',
    description='Fast TCP SYN scan of all 65535 ports',
    variables=[
        {
            'name': 'TARGET',
            'description': 'Target IP address',
            'example': '192.168.45.100',
            'required': True
        }
    ],
    category='recon',
    flag_explanations={
        '-sS': 'TCP SYN scan (stealth scan, requires root)',
        '-p-': 'Scan all 65535 ports (default is top 1000)',
        '--min-rate=1000': 'Send at least 1000 packets per second',
        '-oA': 'Output all formats (normal, XML, grepable)'
    },
    tags=['OSCP:HIGH', 'QUICK_WIN', 'RECON'],
    alternatives=[
        'masscan -p1-65535 <TARGET> --rate=1000',
        'nc -zv <TARGET> 1-65535 2>&1 | grep succeeded'
    ],
    success_indicators=[
        'Open ports discovered',
        'Scan completes without firewall blocking'
    ],
    estimated_time='1-5 minutes'
)
```

## OSCP Exam Best Practices

### 1. Always Review Commands

Templates show you the final command before execution:

```
Final command:
  nmap -sS -p- --min-rate=1000 192.168.45.100 -oA nmap_quick

Execute command? [y/N]:
```

**REVIEW** before confirming to catch typos or wrong targets.

### 2. Use Manual Alternatives

When automated tools fail or are unavailable:

```
Manual alternatives:
  • nc -zv 192.168.45.100 1-65535 2>&1 | grep succeeded
  • curl http://192.168.45.100/admin
```

**PRACTICE** manual methods before the exam.

### 3. Document Everything

Templates automatically log to profile:

```json
{
  "note": "Executed template: Nmap Quick Scan\nCommand: nmap -sS -p- --min-rate=1000 192.168.45.100 -oA nmap_quick",
  "source": "command templates",
  "timestamp": "2025-10-08T..."
}
```

**VERIFY** source tracking for OSCP report submission.

### 4. Time Management

Use time estimates for exam planning:

```
Fast (< 1 minute):  whatweb, searchsploit, nc-listener
Quick (1-5 min):    nmap-quick, gobuster (small wordlist), enum4linux
Medium (5-15 min):  nmap-service, nikto-scan, gobuster (big wordlist)
Long (15+ min):     Full nmap scan with all scripts
```

**PLAN** your enumeration based on time remaining.

### 5. Success Verification

Use success indicators to verify results:

```
✓ Service names and versions identified
✓ NSE scripts return useful information
✓ No authentication error
```

**CHECK** each indicator before moving to next phase.

## Tips and Tricks

### Quick Template Access

Press **'x'** anywhere in interactive mode to access templates instantly.

### Keyword Search

Type part of template name instead of number:
- `nmap` → Shows all nmap templates
- `web` → Shows all web category templates
- `shell` → Shows reverse shell templates

### Reuse Commands

Templates save to profile notes - copy from history:

```bash
crack track show 192.168.45.100 | grep "command templates"
```

### Combine with Tasks

Use templates for ad-hoc commands while tasks provide structured workflow:

```
Tasks: Structured enumeration (whatweb → gobuster → nikto)
Templates: Quick commands (searchsploit, reverse shells, one-off scans)
```

### Learn Flag Meanings

Read flag explanations to understand commands:

```
-sS: TCP SYN scan (stealth scan, requires root)
```

**WHY** is this better than understanding in exam scenarios.

## Troubleshooting

### Template Not Found

```python
>>> TemplateRegistry.get('missing-template')
None

# List all available
>>> TemplateRegistry.list_all()
```

### Variable Substitution Failed

Check placeholder names match exactly:

```python
# Correct
template.fill({'TARGET': '192.168.45.100'})

# Wrong - case sensitive
template.fill({'target': '192.168.45.100'})  # Won't substitute
```

### Search Returns Nothing

Try broader terms:

```python
# Too specific
TemplateRegistry.search('nmap quick scan')  # May not match

# Better
TemplateRegistry.search('nmap')  # Finds all nmap templates
TemplateRegistry.search('quick')  # Finds quick_win tagged templates
```

## Advanced Usage

### Custom Templates (Future)

Create custom templates in `~/.crack/templates/`:

```python
# ~/.crack/templates/my_templates.py
from crack.track.interactive.templates import TemplateRegistry, CommandTemplate

TemplateRegistry.register(CommandTemplate(
    template_id='custom-scan',
    name='My Custom Scan',
    command='custom_tool <TARGET>',
    description='My specialized scan',
    variables=[{'name': 'TARGET', 'required': True}],
    category='custom'
))
```

### Batch Execution (Future)

Execute multiple templates in sequence:

```python
templates = ['nmap-quick', 'whatweb', 'gobuster-dir']
for tid in templates:
    template = TemplateRegistry.get(tid)
    # Fill and execute
```

## Summary

Command Templates provide:

✅ **Quick Access**: Press 'x' in interactive mode
✅ **Educational**: Flag explanations and manual alternatives
✅ **OSCP-Focused**: Source tracking and time estimates
✅ **Flexible**: Variable substitution for any target
✅ **Safe**: Confirmation required before execution
✅ **Documented**: Auto-logs to profile for reporting

**Use templates for quick command execution while letting tasks guide your structured enumeration workflow.**
