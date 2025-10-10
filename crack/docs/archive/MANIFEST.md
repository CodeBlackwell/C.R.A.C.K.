# Documentation Archive Manifest

**Archive Created**: 2025-10-10
**Archived By**: Agent 9 (Archive Organizer)
**Backup Location**: `/tmp/crack_docs_backup_20251010.tar.gz`

Files moved during 2025-10-10 documentation cleanup and reorganization.

---

## Root Level Archives

Files archived from project root (`/home/kali/OSCP/crack/`):

### 2025-10-10 Archives (2 files)

**Outdated Checklists & Quick References**:
- `INTEGRATION_CHECKLIST.md` (5.0K) - One-time integration task list (2/11 tasks complete)
- `INPUT_VALIDATOR_QUICKREF.md` (3.1K) - Redundant quick reference (superseded by full docs)

**Reason for Archival**:
- Task lists were incomplete and abandoned
- Quick reference was redundant with full documentation
- No longer actively maintained

### 2025-10-09 Archives (2 files)

**Historical Bug Reports**:
- `HTTP_PLUGIN_FIX_REPORT.md` (11K) - HTTP plugin blockchain confidence scoring fix
- `FREEZE_ANALYSIS.md` (5.7K) - TUI freeze debug analysis (pytest fixture scope issue)

**Reason for Archival**:
- Issues already resolved
- Fixes applied to codebase
- Historical reference only

---

## Restoration Instructions

### View Archived File
```bash
cat docs/archive/2025-10-10/INTEGRATION_CHECKLIST.md
cat docs/archive/2025-10-09/HTTP_PLUGIN_FIX_REPORT.md
```

### Restore to Root (if needed)
```bash
cd /home/kali/OSCP/crack
git mv docs/archive/2025-10-10/FILENAME.md ./
```

### Restore from Backup
```bash
tar -tzf /tmp/crack_docs_backup_20251010.tar.gz | grep FILENAME
tar -xzf /tmp/crack_docs_backup_20251010.tar.gz FILENAME.md
```

---

## Archive Organization

```
docs/archive/
├── MANIFEST.md (this file)
├── 2025-10-10/
│   ├── INTEGRATION_CHECKLIST.md
│   └── INPUT_VALIDATOR_QUICKREF.md
└── 2025-10-09/
    ├── HTTP_PLUGIN_FIX_REPORT.md
    └── FREEZE_ANALYSIS.md
```

**Total Archived**: 4 files (24.8 KB)

---

## Related Archives

For development history archives, see:
- `/home/kali/OSCP/crack/track/docs/archive/README.md` (54 files)

For sessions-related archives, see:
- Development history archives include session implementation reports

---

**Archive Policy**: Files are archived (not deleted) when they are:
1. Historical bug reports (issues resolved)
2. Temporary task tracking documents (abandoned or complete)
3. Redundant documentation (superseded by better docs)
4. One-time planning documents (no longer relevant)

**Retention**: All archived files preserved indefinitely for historical reference.

---

**Last Updated**: 2025-10-10
