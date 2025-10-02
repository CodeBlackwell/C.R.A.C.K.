# PostgreSQL Error-Based SQLi - Complete Educational Documentation
**Target**: 192.168.145.49 | **Vulnerability**: Error-based SQL Injection
**Database**: PostgreSQL 13.7 | **Final Access**: RCE as postgres user

---

## 📚 Documentation Index

This directory contains comprehensive, educational documentation of a PostgreSQL SQL injection attack chain from discovery to RCE. Each document focuses on specific phases with detailed command breakdowns, current thinking, and lessons learned.

---

### 01. Database Basics Enumeration
**File**: [01_database_basics.md](01_database_basics.md)
**Topics Covered**:
- PostgreSQL version discovery
- Current user identification
- Database name extraction

**Key Techniques**:
- Error-based injection with `CAST() AS int`
- Type coercion for data extraction
- SQL comment termination

**Time**: ~3 minutes | **Difficulty**: Beginner

---

### 02. Privilege & Schema Enumeration
**File**: [02_privilege_and_schema.md](02_privilege_and_schema.md)
**Topics Covered**:
- Superuser privilege verification (CRITICAL finding)
- All database enumeration
- Table discovery in public schema

**Key Techniques**:
- `pg_user` system catalog queries
- `information_schema.tables` enumeration
- `string_agg()` for multi-row aggregation

**Time**: ~3 minutes | **Difficulty**: Intermediate

---

### 03. Data Extraction
**File**: [03_data_extraction.md](03_data_extraction.md)
**Topics Covered**:
- Column enumeration from users table
- Row counting with type coercion
- Complete data extraction (4 user records)

**Key Techniques**:
- `information_schema.columns` queries
- String concatenation with `||` operator
- Multi-column, multi-row aggregation
- Type casting with `::text`

**Time**: ~4 minutes | **Difficulty**: Intermediate

---

### 04. File System Access
**File**: [04_file_system_access.md](04_file_system_access.md)
**Topics Covered**:
- File read capability testing (`/etc/passwd`)
- Database credentials extraction (`dbcon.php`)
- Full user enumeration

**Key Techniques**:
- `pg_read_file()` function (superuser required)
- Offset/length parameters for large files
- Absolute path requirements
- Strategic file targeting (config files, user data)

**Time**: ~8 minutes | **Difficulty**: Intermediate

---

### 05. Remote Code Execution
**File**: [05_remote_code_execution.md](05_remote_code_execution.md)
**Topics Covered**:
- RCE via `COPY FROM PROGRAM`
- Command execution verification (`id`, `whoami`)
- Network configuration discovery

**Key Techniques**:
- Multi-statement injection (`;` separator)
- Temporary table creation for output storage
- Multi-line output handling with `string_agg()`
- stderr redirection (`2>&1`)

**Time**: ~5 minutes | **Difficulty**: Advanced

---

### 06. Privilege Escalation Recon
**File**: [06_privilege_escalation_recon.md](06_privilege_escalation_recon.md)
**Topics Covered**:
- Sudo privileges check (failed - requires password)
- Home directory enumeration
- SUID binary discovery

**Key Techniques**:
- `sudo -l` with error handling
- `ls -la` for detailed file listings
- `find` with permission filters (`-perm -4000`)
- Error suppression (`2>/dev/null`)

**Time**: ~7 minutes | **Difficulty**: Intermediate

---

### 07. Learning from Failures
**File**: [07_learning_from_failures.md](07_learning_from_failures.md)
**Topics Covered**:
- Failed row count attempt (integer cast issue)
- Multi-line file read challenges
- Sudo check without stderr redirection
- Table creation conflicts
- Schema filtering mistakes
- Path traversal blocking

**Key Lessons**:
- Error-based extraction requires type mismatches
- Always redirect stderr for error-prone commands
- Always `DROP TABLE IF EXISTS` before creating
- Filter by schema to avoid system table noise
- `pg_read_file()` requires absolute paths

**Value**: Understanding failures teaches more than successes!

---

### 08. Alternative Payloads
**File**: [08_alternative_payloads.md](08_alternative_payloads.md)
**Topics Covered**:
- Alternative error-based extraction methods
- Different row aggregation techniques
- Alternative RCE methods (UDF, plpythonu, large objects)
- Alternative file read approaches
- Different string concatenation operators
- Comment style variations

**Key Value**:
- Backup methods when primary payloads fail
- WAF/IDS bypass alternatives
- Version compatibility options

**Use Case**: When standard payloads blocked or unavailable

---

### 09. Payload Construction Workflow
**File**: [09_payload_construction_workflow.md](09_payload_construction_workflow.md)
**Topics Covered**:
- Phase-by-phase payload building process
- Testing and validation strategies
- Optimization techniques
- Complete exploitation checklist

**Key Workflows**:
1. Identify injection point
2. Determine database type
3. Test error-based extraction
4. Build data enumeration payloads
5. Build file read payloads
6. Build RCE payloads
7. Optimize for efficiency
8. Validate extracted data

**Value**: Learn to build payloads from scratch (no tool dependency)

---

## 🎯 Quick Reference Summary

### Attack Chain Timeline
```
00:00 - Initial SQLi discovery (crack-sqli scanner)
00:05 - Database version & user enumeration
00:08 - Superuser privilege confirmed ⚡
00:11 - Schema & table discovery
00:15 - Data extraction from users table
00:23 - File read capability (`pg_read_file`)
00:28 - RCE achieved (`COPY FROM PROGRAM`) 🎯
00:35 - Privilege escalation enumeration
```

**Total enumeration time**: ~30 minutes

---

### Critical Findings

| Finding | Impact | Section |
|---------|--------|---------|
| Error-based SQLi in `height` parameter | Data extraction | 01 |
| User `rubben` has superuser privileges | File read + RCE | 02 |
| Database credentials: `rubben:avrillavigne` | Potential SSH/service access | 04 |
| RCE as `postgres` user (UID 106) | Full system compromise path | 05 |
| Member of `ssl-cert` group | Can read SSL private keys | 05 |

---

### Exploitation Templates

**Error-Based Extraction**:
```sql
height=1' AND 1=CAST((SELECT <data>) AS int)--
```

**Multi-Row Aggregation**:
```sql
height=1' AND 1=CAST((SELECT string_agg(<col>, ',') FROM <table> WHERE <filter>) AS int)--
```

**File Read**:
```sql
height=1' AND 1=CAST((SELECT pg_read_file('<path>', 0, <length>)) AS int)--
```

**Command Execution**:
```sql
height=1'; DROP TABLE IF EXISTS cmd_output; CREATE TABLE cmd_output(output text); COPY cmd_output FROM PROGRAM '<command>'; SELECT 1 WHERE 1=CAST((SELECT string_agg(output, chr(10)) FROM cmd_output) AS int)--
```

---

## 📖 How to Use This Documentation

### For OSCP Study:
1. Read documents in order (01 → 09)
2. Understand the "Current Thinking" sections (strategic reasoning)
3. Study "Command Anatomy Breakdown" sections (technical details)
4. Review "Learning from Failures" (troubleshooting skills)
5. Practice building payloads using "Payload Construction Workflow"

### For OSCP Exam:
1. Keep "Quick Reference Summary" open
2. Use "Exploitation Templates" for rapid deployment
3. Reference "Alternative Payloads" when primary methods fail
4. Follow "Payload Construction Workflow" checklist

### For Writeups/Reports:
1. Follow the documentation structure (Current Thinking → Command → Result → Breakdown)
2. Include failed attempts from section 07
3. Explain manual discovery methods (not just automated tools)
4. Show time tracking for realistic exam context

---

## 🎓 Key Learning Outcomes

After studying this documentation, you should be able to:

✅ **Identify SQL injection manually** (without automated scanners)
✅ **Determine database type** from error messages
✅ **Craft error-based extraction payloads** from scratch
✅ **Enumerate database schema** systematically
✅ **Extract multi-row, multi-column data** efficiently
✅ **Read arbitrary files** via PostgreSQL functions
✅ **Achieve RCE** through COPY FROM PROGRAM
✅ **Troubleshoot failed payloads** using type analysis
✅ **Adapt payloads** when primary methods fail
✅ **Build complete attack chains** within exam time constraints

---

## 📊 Documentation Stats

- **Total documents**: 9 comprehensive guides
- **Total commands documented**: 18+ with full breakdowns
- **Failed attempts documented**: 6 with solutions
- **Alternative methods shown**: 20+ variations
- **Time estimates provided**: All phases tracked
- **Target audience**: OSCP students
- **Exam relevance**: 100% applicable

---

## 🔗 Related Files

- **Original enumeration log**: [`../enumeration.md`](../enumeration.md)
- **Scan results**: From crack-sqli tool (initial discovery)
- **Next steps**: Establish reverse shell, test SSH with credentials, privilege escalation

---

## 💡 OSCP Exam Tips from This Lab

1. **Always check superuser status early** - Determines entire attack path
2. **Use `string_agg()` for efficiency** - One request vs many
3. **Document failures, not just successes** - Shows methodology
4. **Build reusable templates** - Save 25+ minutes on future boxes
5. **Understand WHY payloads work** - Troubleshoot when they don't
6. **Time tracking is critical** - Know your pace for exam day
7. **Manual methods > automated tools** - Tools unavailable in exam
8. **Multi-statement injection unlocks RCE** - Don't limit to single statements

---

## 📝 Credits & Context

**Created by**: Claude Code (AI assistant)
**Purpose**: Educational OSCP study material
**Lab**: OSCP Chapter 10 Capstone #3
**Date**: 2025
**Target OS**: Debian 11 (Linux kernel, PostgreSQL 13.7)
**Difficulty**: Intermediate

**Note**: This documentation prioritizes teaching over brevity. Each command is explained in detail to build deep understanding for OSCP exam success.

---

## ⚠️ Legal Disclaimer

This documentation is for authorized penetration testing and educational purposes only. Only attack systems you own or have explicit written permission to test. Unauthorized access to computer systems is illegal.
