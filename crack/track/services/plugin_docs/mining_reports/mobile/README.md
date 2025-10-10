# Mobile Security Reports

[← Back to Main Index](../../README.md)

---

## Overview

**0 active reports** - All mobile reports archived (OSCP:NONE relevance)

**Archived:** 4 reports moved to `/archive/low_priority/mobile/` (Android, mobile pentesting)

---

## OSCP Exam Notice

**Mobile pentesting is NOT tested in the OSCP exam.** The exam focuses on:
- Windows/Linux privilege escalation
- Active Directory attacks
- Web application vulnerabilities
- Network service exploitation

Mobile security reports have been archived to keep active content OSCP-focused.

---

## Archived Reports (All OSCP:NONE)

**Location:** `/track/services/plugin_docs/archive/low_priority/mobile/`

- `android_mining_report.md` - Android pentesting (no Android targets in OSCP)
- `mobile_pentesting_misc_mining_report.md` - Cross-platform mobile testing

**Deleted (Superseded by Remines):**
- ~~ANDROID_MINING_REPORT.md~~ - Replaced by android_mining_report.md (now archived)
- ~~MOBILE_PENTESTING_MISC_MINING_REPORT.md~~ - Replaced by mobile_pentesting_misc_mining_report.md (now archived)

---

## How to Access Archived Reports

```bash
# View archived mobile reports
cd /home/kali/OSCP/crack/track/services/plugin_docs/archive/low_priority/mobile

# List available reports
ls -lh

# Read a specific report
cat android_mining_report.md
```

**Restoration:** If OSCP exam adds mobile targets (unlikely), use `git mv` to restore reports.

---

## Key Topics Covered (Archived)

- **Android Security:** APK analysis, rooting, exploitation
- **Cross-Platform:** Hybrid app testing (Cordova, Xamarin)
- **Network Attacks:** Mobile network interception
- **Application Testing:** Mobile app vulnerabilities

---

## Usage Notes

### For OSCP Exam Preparation
**Skip this category.** Focus on active mining reports:
- `pen300/` - Active Directory, Windows exploitation
- `hacktricks_linux/` - Linux privilege escalation
- `web_attacks/` - Web vulnerabilities
- `network_services/` - Service exploitation

### For Mobile Pentesting (Post-OSCP)
- Review archived reports for real-world mobile engagements
- Useful for specialized certifications (not OSCP/OSEP/OSED)
- Valuable for Android/iOS app security assessments

### Statistics
- **Active Reports:** 0 (all archived for OSCP focus)
- **Archived Reports:** 2 (OSCP:NONE relevance)
- **Deleted Reports:** 2 (superseded duplicates)
- **Category:** Mobile Security Reports

### Consolidation Notes (2025-10-10)
- Phase 1: Deleted 2 uppercase duplicate originals (48 KB)
- Phase 3: Archived 2 remine reports to `/archive/low_priority/mobile/` (51 KB)
- Result: Category empty (all content preserved in archive)

---

**Last Updated:** 2025-10-10 (Consolidation - All Reports Archived)
**Maintained By:** CRACK Track Team

**See Also:** `/track/services/plugin_docs/archive/low_priority/MANIFEST.md` for archive details
