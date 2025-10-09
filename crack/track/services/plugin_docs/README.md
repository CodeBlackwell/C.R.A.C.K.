# CRACK Track Service Plugin Documentation

**Comprehensive knowledge base for OSCP/OSEP preparation** - Organized mining reports, plugin guides, and implementation summaries extracted from HackTricks, PEN-300, Nmap Cookbook, and expert security resources.

---

## 📚 Quick Navigation

### 🔍 Mining Reports by Source

Extract knowledge from authoritative security resources, organized by origin:

#### [PEN-300 Course Materials](./mining_reports/pen300/)
**21 comprehensive reports** covering advanced penetration testing techniques from OffSec's OSEP course.

- **Active Directory:** Enumeration fundamentals, credential attacks, delegation, trust relationships
- **Evasion:** AV detection, AMSI bypass, network evasion, AppLocker bypass  
- **Lateral Movement:** RDP techniques, MSSQL attacks, Linux pivoting
- **Post-Exploitation:** Windows/Linux persistence, process injection
- **Methodology:** Client-side recon, phishing, cross-cutting techniques

[➤ Browse PEN-300 Reports](./mining_reports/pen300/)

---

#### [HackTricks Linux Security](./mining_reports/hacktricks_linux/)
**8 focused reports** on Linux enumeration, privilege escalation, and persistence.

- **Enumeration:** System recon, service discovery
- **Privilege Escalation:** SUID/capabilities, kernel exploits, container escape
- **Persistence:** Backdoors, shell escaping techniques
- **Advanced:** Capabilities abuse, restricted environment bypasses

[➤ Browse Linux Security Reports](./mining_reports/hacktricks_linux/)

---

#### [HackTricks macOS Security](./mining_reports/hacktricks_macos/)
**11 comprehensive reports** on macOS penetration testing.

- **macOS:** Enumeration, filesystem, kernel, IPC, process abuse, privilege escalation
- **Enterprise:** MDM bypass, app security, miscellaneous techniques

[➤ Browse macOS Reports](./mining_reports/hacktricks_macos/)

---

#### [HackTricks iOS Security](./mining_reports/hacktricks_ios/)
**6 focused reports** on iOS penetration testing.

- **iOS:** Pentesting methodology, hooking, app analysis, protocols, binary exploitation
- **Testing Environment:** Setup and configuration

[➤ Browse iOS Reports](./mining_reports/hacktricks_ios/)

---

#### [Network Services & Databases](./mining_reports/network_services/)
**10 reports** on network scanning, service enumeration, and database attacks.

- **Nmap Mastery:** Fundamentals, network exploration, host information, large-scale scanning
- **Database Security:** MSSQL exploitation, database plugin enhancements
- **Network Protocols:** Legacy protocols, service enumeration, dev tools

[➤ Browse Network Reports](./mining_reports/network_services/)

---

#### [Web Application Attacks](./mining_reports/web_attacks/)
**6 reports** on web vulnerability research and exploitation.

- **Framework-Specific:** Python/Flask, Ruby on Rails
- **Vulnerability Classes:** SSRF, file upload, redirect attacks
- **Generic Techniques:** Common web attack vectors

[➤ Browse Web Attack Reports](./mining_reports/web_attacks/)

---

#### [Mobile Security](./mining_reports/mobile/)
**4 reports** covering Android and cross-platform mobile pentesting.

- Android security testing
- Mobile pentesting miscellaneous techniques

[➤ Browse Mobile Reports](./mining_reports/mobile/)

---

#### [Binary Exploitation](./mining_reports/binary_exploitation/)
**9 reports** on memory corruption and binary analysis.

- **Stack Exploitation:** Stack overflow techniques, ROP chains
- **Architecture-Specific:** ARM64 exploitation
- **Advanced:** Browser exploitation, reverse shell techniques

[➤ Browse Binary Exploitation Reports](./mining_reports/binary_exploitation/)

---

#### [Miscellaneous Topics](./mining_reports/miscellaneous/)
**10 reports** on cryptography, AI security, hardware hacking, and specialized domains.

- **Cryptography:** Classic attacks, blockchain security
- **Emerging Tech:** LLM attacks, AI security
- **Physical Security:** Radio hacking, hardware exploitation
- **Forensics:** Steganography, reversing techniques

[➤ Browse Miscellaneous Reports](./mining_reports/miscellaneous/)

---

### 🔌 Plugin Documentation

**9 complete plugin guides** - Ready-to-use CRACK Track service plugins with full API documentation.

| Plugin | OSCP Relevance | Description |
|--------|----------------|-------------|
| [Heap Exploitation](./plugin_readmes/heap_exploit_plugin_readme.md) | ⚠️ LOW | Advanced heap vulnerability analysis (CTF/research) |
| [Binary Exploitation](./plugin_readmes/binary_exploit_plugin_readme.md) | ⚠️ LOW | Stack/memory corruption techniques |
| [Phishing](./plugin_readmes/phishing_plugin_readme.md) | ✅ HIGH | Email reconnaissance and phishing campaign automation |
| [Anti-Forensics](./plugin_readmes/anti_forensics_plugin_readme.md) | 🟡 MEDIUM | Evidence cleanup and forensic evasion |
| [OSINT/WiFi](./plugin_readmes/osint_wifi_plugin_readme.md) | ✅ HIGH | Wireless security and OSINT reconnaissance |
| [Lua Exploitation](./plugin_readmes/lua_exploit_plugin_readme.md) | ⚠️ LOW | Lua sandbox escape techniques |
| [Python Web](./plugin_readmes/python_web_plugin_readme.md) | ✅ HIGH | Python/Flask web application testing |
| [C2 Analysis](./plugin_readmes/c2_analysis_plugin_readme.md) | 🟡 MEDIUM | Command & Control infrastructure analysis |
| [Network Attacks](./plugin_readmes/network_attack_plugins_readme.md) | ✅ HIGH | Network-layer attack automation |

[➤ View All Plugin READMEs](./plugin_readmes/)

---

### 🔧 Implementation Summaries

**4 technical implementation documents** tracking plugin development and integration.

- [Nmap Chapter 2 Implementation](./implementations/IMPLEMENTATION_SUMMARY_CH02.md)
- [Nmap Chapter 5 Database Enhancements](./implementations/nmap_ch5_database_implementation.md)
- [Anti-Forensics Implementation](./implementations/anti_forensics_implementation.md)
- [HackTricks Chapter 2 Implementation](./implementations/hacktricks_ch02_implementation.md)

[➤ View Implementation Summaries](./implementations/)

---

### 📊 Agent Cleanup Reports

**3 parallel cleanup reports** from documentation standardization agents (Agents 5, 6, 8).

- Agent 5: Core cleanup operations
- Agent 6: Android/Mobile security reports
- Agent 8: Miscellaneous mining reports

[➤ View Agent Reports](./agent_reports/)

---

### 🗄️ Archive

**Historical documentation** - Planning documents and superseded reports preserved for reference.

- [Planning Documents](./archive/planning/) - Initial plugin development roadmaps
- [Superseded Reports](./archive/superseded/) - Older versions replaced by remine reports
- [Archive Manifest](./archive/ARCHIVE_MANIFEST.md) - Complete inventory

[➤ View Archive](./archive/)

---

## 🔎 Search & Discovery

### By OSCP Relevance

**High Priority (Exam Focus):**
```bash
# PEN-300 AD techniques
grep -r "OSCP:HIGH" mining_reports/pen300/

# Linux privilege escalation
grep -r "OSCP:HIGH" mining_reports/hacktricks_linux/

# Network enumeration
grep -r "OSCP:HIGH" mining_reports/network_services/
```

**Quick Wins (Fast Techniques):**
```bash
# Find 2-5 minute techniques
grep -r "QUICK_WIN" mining_reports/
```

### By Topic

```bash
# Active Directory
find mining_reports/pen300/ -name "*AD*" -o -name "*CREDS*"

# Privilege Escalation
find mining_reports/ -name "*PRIVESC*" -o -name "*ESCAPE*"

# Web Attacks
ls mining_reports/web_attacks/

# Binary/Memory Exploitation
ls mining_reports/binary_exploitation/
```

### By Technique

```bash
# Credential attacks
grep -ri "kerberoast\|asreproast\|ntlm" mining_reports/

# Container escape
grep -ri "docker\|container\|escape" mining_reports/

# Code injection
grep -ri "injection\|rce\|execution" mining_reports/
```

---

## 📖 Documentation Standards

All documents in this collection follow standardized formatting:

### ✅ Table of Contents
- Auto-generated navigation at document start
- Section anchors for quick access

### ✅ Breadcrumb Navigation
- `[← Back to Category Index](../README.md)` links
- Hierarchical navigation paths

### ✅ Cross-References
- Related technique links
- "See Also" sections
- Plugin integration notes

### ✅ OSCP Metadata
- **Relevance Tags:** HIGH/MEDIUM/LOW for exam prioritization
- **Time Estimates:** Planning exam time allocation
- **Success Indicators:** Verification checklists
- **Alternatives:** Manual techniques when tools fail
- **Flag Explanations:** Educational command breakdowns

### ✅ Source Attribution
- Original HackTricks/PEN-300/Nmap URLs
- Mining agent version and date
- Line count and extraction statistics

---

## 🛠️ Using This Documentation

### For OSCP Exam Prep

1. **Start with HIGH priority** reports in `mining_reports/pen300/` and `mining_reports/hacktricks_linux/`
2. **Practice QUICK_WIN** techniques for fast point collection
3. **Study alternatives** - Manual methods for when tools blocked
4. **Time yourself** - Use time estimates to build exam strategy

### For Plugin Development

1. **Browse mining reports** to understand knowledge extraction
2. **Review plugin READMEs** for implementation patterns
3. **Check implementation summaries** for integration examples
4. **Follow contribution guide** in `../PLUGIN_CONTRIBUTION_GUIDE.md`

### For Research

1. **Search by topic** using grep commands above
2. **Cross-reference techniques** via "See Also" links
3. **Check archive** for historical context
4. **Review agent reports** for methodology insights

---

## 📊 Collection Statistics

### Mining Reports: **83 files**
- PEN-300: 21 reports
- HackTricks Linux: 9 reports  
- HackTricks macOS: 11 reports
- HackTricks iOS: 6 reports
- Network/Databases: 10 reports
- Web Attacks: 6 reports
- Mobile: 4 reports
- Binary Exploitation: 9 reports
- Miscellaneous: 10 reports

### Plugin Documentation: **9 complete plugins**
- Service plugins: 6 (heap, binary, lua, python-web, c2, network)
- Reconnaissance plugins: 2 (phishing, osint-wifi)
- Post-exploitation plugins: 1 (anti-forensics)

### Implementation Docs: **4 summaries**
- Nmap integration: 2 documents
- HackTricks integration: 1 document
- Anti-forensics: 1 document

### Archive: **7 historical files**
- Planning documents: 1
- Superseded reports: 3
- Archive documentation: 3

---

## 🤝 Contributing

### Adding New Mining Reports

1. Place in appropriate `mining_reports/` subdirectory
2. Follow naming convention: `source_topic_mining_report.md`
3. Include table of contents, breadcrumbs, OSCP tags
4. Update category README.md

### Creating New Plugins

1. Follow `../PLUGIN_CONTRIBUTION_GUIDE.md`
2. Create plugin README in `plugin_readmes/`
3. Document implementation in `implementations/`
4. Add cross-references to related mining reports

### Documentation Standards

- **Table of Contents:** Auto-generated or manual with anchors
- **Breadcrumbs:** `[← Category](../README.md) | [Subcategory](./README.md)`
- **Cross-refs:** Link related techniques bidirectionally
- **OSCP Tags:** HIGH/MEDIUM/LOW + QUICK_WIN where applicable
- **Time Estimates:** Include for exam planning
- **Alternatives:** Always provide manual methods

---

## 🔗 Quick Links

- **Main Plugin Directory:** [`../`](../)
- **Plugin Contribution Guide:** [`../PLUGIN_CONTRIBUTION_GUIDE.md`](../PLUGIN_CONTRIBUTION_GUIDE.md)
- **Service Registry:** [`../registry.py`](../registry.py)
- **CRACK Track Documentation:** [`../../README.md`](../../README.md)

---

## 📝 Version History

- **v2.0 (2025-10-09):** Complete reorganization - Source-based categories, 13 subdirectories, master index
- **v1.5 (2025-10-08):** Agent cleanup standardization (ToCs, breadcrumbs, cross-refs)
- **v1.0 (2025-10-07):** Initial mining reports and plugin documentation

---

**Last Updated:** 2025-10-09  
**Total Files:** 96+ markdown documents  
**Maintained By:** CRACK Track Development Team
