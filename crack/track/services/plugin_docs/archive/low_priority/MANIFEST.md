# Low Priority Archive Manifest

**Archive Date:** 2025-10-10
**Archived By:** Mining Report Consolidation (Phase 3)
**Total Archived:** 30 reports (516 KB)
**Purpose:** OSCP exam focus - remove low-relevance content from active mining reports

---

## Why These Reports Were Archived

This archive contains valuable pentesting content that has **minimal relevance to the OSCP certification exam**. These reports are preserved for:

- **Advanced certifications** (OSED, OSEP, OSWE, OSMR)
- **Real-world pentesting** beyond OSCP scope
- **Research and CTF challenges**
- **Mobile/hardware/blockchain/AI security specialization**

**OSCP Exam Focus:** The OSCP exam primarily tests:
- Windows and Linux privilege escalation
- Active Directory enumeration and attacks
- Web application vulnerabilities (SQLi, file upload, etc.)
- Network service exploitation (SMB, FTP, SSH, RDP, MSSQL, etc.)
- Buffer overflow basics (x86/x64 stack-based)

These archived reports fall outside that core scope.

---

## Archive Categories

### 1. iOS Security (7 reports, ~100 KB)

**Directory:** `hacktricks_ios/`

| Report | Size | OSCP Relevance |
|--------|------|----------------|
| IOS_PROTOCOLS_MINING_REPORT.md | 16 KB | OSCP:NONE - No iOS targets in exam |
| MINING_REPORT_iOS_TestingEnvironment.md | 14 KB | OSCP:NONE - iOS-specific tooling |
| ios_app_analysis.md | 18 KB | OSCP:NONE - Mobile app analysis |
| ios_binary_exploit_mining_report.md | 19 KB | OSCP:NONE - ARM exploitation |
| ios_hooking_mining_report.md | 15 KB | OSCP:NONE - Frida/iOS-specific |
| ios_pentesting_mining_report.md | 18 KB | OSCP:NONE - iOS pentesting |
| README.md | - | Category index |

**Archive Reason:** OSCP exam does not include iOS targets. Labs and exam focus on Windows/Linux servers and workstations.

---

### 2. macOS Security (11 reports, ~280 KB)

**Directory:** `hacktricks_macos/`

| Report | Size | OSCP Relevance |
|--------|------|----------------|
| MACOS_IPC_MINING_REPORT.md | 24 KB | OSCP:LOW - Rare macOS in labs |
| MACOS_NETWORK_MINING_REPORT.md | 22 KB | OSCP:LOW - Limited macOS presence |
| MACOS_PROCESS_ABUSE_MINING_REPORT.md | 26 KB | OSCP:LOW - macOS-specific techniques |
| MINING_REPORT_MACOS_MDM.md | 20 KB | OSCP:NONE - Enterprise macOS management |
| MINING_REPORT_MACOS_MISC.md | 28 KB | OSCP:LOW - General macOS pentesting |
| macos_active_directory_mining_report.md | 30 KB | OSCP:MEDIUM - Some AD relevance |
| macos_enumeration_mining_report.md | 32 KB | OSCP:LOW - macOS enumeration |
| macos_filesystem_mining_report.md | 26 KB | OSCP:LOW - macOS filesystem |
| macos_persistence_mining_report.md | 28 KB | OSCP:LOW - macOS persistence |
| macos_privilege_escalation_mining_report.md | 34 KB | OSCP:MEDIUM - Some privesc concepts overlap |
| README.md | - | Category index |

**Archive Reason:** OSCP exam rarely includes macOS targets (as of 2025). Most labs are Windows/Linux. Useful for real-world engagements but not exam-critical.

---

### 3. Mobile Security (2 reports, ~51 KB)

**Directory:** `mobile/`

| Report | Size | OSCP Relevance |
|--------|------|----------------|
| android_mining_report.md | 36 KB | OSCP:NONE - No Android in exam |
| mobile_pentesting_misc_mining_report.md | 15 KB | OSCP:NONE - Mobile-specific techniques |

**Archive Reason:** OSCP exam does not include mobile targets. Android/iOS pentesting is covered in specialized certifications (e.g., OSWE, mobile-specific certs).

**Note:** Uppercase duplicates (ANDROID_MINING_REPORT.md, MOBILE_PENTESTING_MISC_MINING_REPORT.md) were deleted in Phase 1 as superseded versions.

---

### 4. Low-Relevance Binary Exploitation (2 reports, ~39 KB)

**Files in archive root:**

| Report | Size | OSCP Relevance |
|--------|------|----------------|
| arm64_mining_report.md | 12 KB | OSCP:LOW - Exam uses x86/x64 only |
| browser_exploit_mining_report.md | 27 KB | OSCP:NONE - Not on exam |

**Archive Reason:**
- **ARM64:** OSCP exam focuses on x86/x64 buffer overflows (Windows stack-based). ARM64 exploitation is OSED/advanced topic.
- **Browser Exploits:** Client-side browser exploitation is not tested in OSCP exam. Exam focuses on server-side vulnerabilities.

**Retained in Active:** `rop_mining_report.md` (basics relevant), `stack_overflow_mining_report.md` (OSCP:HIGH), `REVERSE_SHELLS_MINING_REPORT.md`

---

### 5. Miscellaneous Low-Priority Topics (7 reports, ~100 KB)

**Files in archive root:**

| Report | Size | OSCP Relevance | Archive Reason |
|--------|------|----------------|----------------|
| ai_security_mining_report.md | 8.9 KB | OSCP:NONE | AI/LLM attacks not in exam scope |
| blockchain_mining_report.md | 17 KB | OSCP:NONE | Blockchain/crypto not in exam |
| blockchain_remine_report.md | 17 KB | OSCP:NONE | Duplicate/enhanced blockchain report |
| llm_attacks_mining_report.md | 8.7 KB | OSCP:NONE | LLM prompt injection not tested |
| radio_hacking_mining_report.md | 9.9 KB | OSCP:NONE | SDR/wireless not in exam |
| hardware_remine_report.md | 17 KB | OSCP:NONE | Hardware pentesting not tested |
| reversing_remine_report.md | 12 KB | OSCP:LOW | Advanced RE beyond OSCP scope |

**Archive Reason:** These are specialized pentesting topics (blockchain, AI/LLM, radio/SDR, hardware) not covered in OSCP exam. Valuable for:
- **CTF competitions** (crypto, reversing, hardware challenges)
- **Advanced certifications** (OSED for reversing)
- **Real-world engagements** (emerging attack vectors)

**Retained in Active:** `cryptography_mining_report.md` (crypto basics have some OSCP relevance for password cracking), `steganography_mining_report.md` (CTF reference)

---

## How to Access Archived Reports

### Option 1: View in Archive Directory

```bash
cd /home/kali/OSCP/crack/track/services/plugin_docs/archive/low_priority

# Browse iOS reports
ls hacktricks_ios/

# Browse macOS reports
ls hacktricks_macos/

# Browse mobile reports
ls mobile/

# Browse individual files
cat arm64_mining_report.md
```

### Option 2: Search Across Archive

```bash
# Search for specific content
grep -r "privilege escalation" track/services/plugin_docs/archive/low_priority/

# Find all mentions of a tool
grep -r "frida" track/services/plugin_docs/archive/low_priority/
```

### Option 3: Restore if Needed

If a report becomes OSCP-relevant (e.g., exam adds mobile targets):

```bash
# Move back to active reports
git mv track/services/plugin_docs/archive/low_priority/hacktricks_ios \
       track/services/plugin_docs/mining_reports/

# Update README to reflect restoration
```

---

## OSCP Relevance Rationale

### Why OSCP:LOW vs OSCP:NONE?

**OSCP:NONE** = Zero exam relevance
- iOS, Android, browser exploits, blockchain, AI/LLM, radio hacking
- These topics will NOT appear in OSCP labs or exam

**OSCP:LOW** = Minimal exam relevance
- macOS (rare in labs, some concepts overlap with Linux)
- ARM64 (exam uses x86/x64 only)
- Advanced reversing (basic RE is OSCP:MEDIUM)

**OSCP:MEDIUM** = Useful but not critical
- macOS AD integration (AD concepts are OSCP:HIGH, but macOS-specific is rare)
- Steganography (CTF technique, occasionally useful)

**OSCP:HIGH** = Exam-critical (retained in active reports)
- Windows privilege escalation
- Linux privilege escalation
- Active Directory attacks
- Web vulnerabilities (SQLi, file upload, SSRF, etc.)
- Network service exploitation
- Buffer overflow basics (x86/x64 stack-based)

---

## Archive Statistics

| Metric | Value |
|--------|-------|
| **Total Reports Archived** | 30 markdown files |
| **Total Size** | 516 KB |
| **iOS Reports** | 7 files (~100 KB) |
| **macOS Reports** | 11 files (~280 KB) |
| **Mobile Reports** | 2 files (~51 KB) |
| **Binary Exploitation (Low)** | 2 files (~39 KB) |
| **Miscellaneous (Low)** | 7 files (~100 KB) |
| **READMEs** | 3 files (category indices) |

**Space Freed from Active Reports:** 516 KB moved to archive

**Combined with Phase 1 Deletions:** 633 KB total reorganization (117 KB deleted + 516 KB archived)

---

## Recommendations for Future Use

### For OSCP Exam Preparation

**Ignore this archive.** Focus on active mining reports:
- `pen300/` - Active Directory, Windows exploitation (17 reports, 850 KB)
- `hacktricks_linux/` - Linux PrivEsc (7 reports, 180 KB)
- `web_attacks/` - Web vulnerabilities (6 reports, 120 KB)
- `network_services/` - Service exploitation (8 reports, 220 KB)
- `binary_exploitation/` - Stack overflows, reverse shells (4 reports, 60 KB)

### For Advanced Certifications

**OSED (Exploit Development):**
- `arm64_mining_report.md` - ARM64 exploitation
- `reversing_remine_report.md` - Advanced reversing

**OSEP (Evasion Techniques):**
- macOS reports for lateral movement in mixed environments

**OSWE (Web Expert):**
- Review active `web_attacks/` instead (more relevant)

**Mobile/Hardware Specialization:**
- `hacktricks_ios/` - iOS pentesting
- `mobile/` - Android pentesting
- `hardware_remine_report.md` - Hardware attacks

### For Real-World Engagements

**All archived reports are valuable** for real-world pentesting:
- macOS is common in corporate environments
- Mobile testing for app security assessments
- Blockchain/crypto for fintech engagements
- AI/LLM for emerging attack vectors

**Recommendation:** Review archived reports AFTER passing OSCP, when preparing for real-world engagements or advanced certifications.

---

## Maintenance Notes

**Archive Created:** 2025-10-10 (Mining Report Consolidation - Phase 3)

**Review Schedule:** Annually or when OSCP exam updates scope

**Restoration Criteria:**
- OSCP exam adds new target types (e.g., iOS, Android)
- User pursuing advanced certifications (OSED, OSEP, OSMR)
- Real-world engagement requires archived topic knowledge

**DO NOT DELETE:** These reports represent valuable research and knowledge extraction. Archive preserves content while keeping active reports OSCP-focused.

---

## Related Documentation

- **Phase 1 Deletions:** See `MINING_REPORT_CONSOLIDATION_REPORT.md` for superseded duplicates removed
- **Active Reports:** See `/track/services/plugin_docs/mining_reports/README.md` for current inventory
- **Superseded Archive:** See `/track/services/plugin_docs/archive/superseded/ARCHIVE_MANIFEST.md` for older reports

---

**Questions or Concerns?**

If a report in this archive should be restored to active status:
1. Review OSCP exam scope (verify if topic is now tested)
2. Check user's certification goals (OSCP vs OSED/OSEP/etc.)
3. Use `git mv` to restore report to appropriate category
4. Update category README with restored file

**Archive Philosophy:** "Low priority for OSCP ≠ Low value overall"

These reports are archived for **OSCP exam focus**, not because they lack value. They're preserved for future use in advanced certifications and real-world pentesting.
