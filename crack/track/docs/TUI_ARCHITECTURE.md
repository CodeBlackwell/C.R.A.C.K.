# CRACK Track TUI - Complete Architecture & Design Document

## Table of Contents
1. [Executive Summary](#1-executive-summary)
2. [Panel Inventory](#2-panel-inventory)
3. [Navigation Flow](#3-navigation-flow)
4. [Multi-Stage Task Architecture](#4-multi-stage-task-architecture)
5. [Panel Detailed Specifications](#5-panel-detailed-specifications)
6. [State Machine Diagram](#6-state-machine-diagram)
7. [Sequence Diagrams](#7-sequence-diagrams)
8. [Implementation Phases](#8-implementation-phases)
9. [Data Persistence](#9-data-persistence)
10. [Edge Cases & Error Handling](#10-edge-cases--error-handling)
11. [Visual Mockups](#11-visual-mockups)
12. [Key Design Decisions](#12-key-design-decisions)

---

## 1. Executive Summary

### Purpose
Define complete TUI (Text User Interface) panel structure and user workflow for OSCP enumeration using CRACK Track.

### Workflow Model
**Option A: Hub-and-Spoke Navigation**
- Dashboard as central hub
- Drill-down to specialized panels
- Always return to Dashboard
- Clear navigation breadcrumbs

### Multi-Stage Support
**Dynamic + Batch + Checkpoints:**
1. **Dynamic Generation** - Tasks generate new stages based on results (e.g., gobuster finds /admin → creates "scan /admin" stage)
2. **Batch Execution** - Option to run all stages automatically or manual step-through
3. **Checkpoint Persistence** - Save state after each stage for crash recovery

### Philosophy
- **Clear Navigation** - Always know where you are and how to get back
- **Progressive Disclosure** - Show relevant info when needed, hide complexity
- **Crash-Safe State** - Never lose work, resume from last checkpoint
- **No Terminal Flooding** - Panel updates in-place, no scroll spam

---

## 2. Panel Inventory

### Core Panels (Full-Screen Views)
1. **Config Panel** - Initial setup (LHOST, LPORT, WORDLIST, INTERFACE) ✓ Working
2. **Dashboard Panel** - Main hub (phase, progress, quick actions, recommendations)
3. **Task List Panel** - Browse/filter/search all tasks (primary work screen)
4. **Task Workspace** - **Multi-panel view with task details + live output**
5. **Findings Panel** - Browse discoveries (vulns, creds, directories, notes)

### Overlay Panels (Temporary, Non-State-Changing)
6. **Status Overlay** - Quick stats (shortcut: 's')
7. **Help Overlay** - Shortcuts reference (shortcut: 'h')
8. **Tree Overlay** - Task tree visualization (shortcut: 't')

### Form Panels (Guided Input)
9. **Finding Entry Form** - Document vulnerabilities
10. **Credential Entry Form** - Save creds with source
11. **Import Form** - Upload scan files
12. **Note Form** - Quick notes

---

## 3. Navigation Flow (Option A)

### ⭐ PRIMARY RULE: Config Panel is ALWAYS Screen 1
**Every TUI session MUST start with Config Panel.**
- Validates LHOST, LPORT, WORDLIST, INTERFACE
- User can edit or confirm
- Cannot skip - required for OSCP workflows
- Only shown once per session (unless user resets)

### Primary User Journey
```
[SCREEN 1: Config Panel] → (confirm - REQUIRED)
    ↓
[SCREEN 2: Dashboard Panel] (HUB - always return here)
    │
    ├─→ "Browse Tasks" → [Task List Panel]
    │       │
    │       ├─→ Select Task → [Task Workspace] ← MULTI-PANEL VIEW
    │       │       │           ├─ Left: Task Details
    │       │       │           └─ Right: Command Output (expandable)
    │       │       │
    │       │       ├─→ "Execute" → Output streams live in right panel
    │       │       │       └─→ Stage Complete → Prompt (continue/back/generate)
    │       │       │
    │       │       ├─→ "Expand Output" → Full-screen output mode
    │       │       │       └─→ "Collapse" → Back to split view
    │       │       │
    │       │       └─→ "Back" → [Task List Panel]
    │       │
    │       └─→ "Back" → [Dashboard Panel]
    │
    ├─→ "Document Finding" → [Finding Entry Form] → [Dashboard Panel]
    ├─→ "Import Scan" → [Import Form] → [Dashboard Panel]
    ├─→ "Browse Findings" → [Findings Panel] → [Dashboard Panel]
    │
    └─→ Shortcuts (s/t/h) → [Overlay] → [Dashboard Panel]
```

### Navigation Breadcrumb Examples
```
Dashboard
Dashboard > Task List
Dashboard > Task List > gobuster-80 (Stage 2/3)
Dashboard > Task List > gobuster-80 (Stage 2/3) [Output Expanded]
Dashboard > Findings
Dashboard > Import Scan
```

---

## 4. Multi-Stage Task Architecture

### Design Principles
1. **Dynamic Generation** - Results trigger new stages automatically
2. **Batch Execution** - User can run all stages or step through manually
3. **Checkpoint Persistence** - State saved after each stage (crash recovery)

### Stage Lifecycle
```
[Task Created]
    ↓
[Static Stages Defined] (e.g., gobuster: initial, targeted, deep)
    ↓
[Execute Stage 1] → [Save Checkpoint]
    ↓
[Parse Results] → [Generate New Stages?] (e.g., found /admin → create admin-scan stage)
    ↓                Yes ↓                    No ↓
[Add Dynamic Stages]              [Continue to Stage 2]
    ↓
[User Choice: Continue, Batch, or Back]
    ↓
[Execute Next Stage] → [Save Checkpoint] → [Repeat]
    ↓
[All Stages Complete] → [Mark Task Done]
```

### Task Metadata Structure
```json
{
  "id": "gobuster-80",
  "name": "Port 80 Directory Enumeration",
  "type": "multi-stage",
  "stages": [
    {
      "id": "initial",
      "name": "Initial Directory Scan",
      "status": "completed",
      "checkpoint": "2025-10-09T14:30:00",
      "output_file": "/tmp/gobuster-80-initial.txt",
      "exit_code": 0,
      "generated": false
    },
    {
      "id": "admin-targeted",
      "name": "Targeted Scan on /admin",
      "status": "in-progress",
      "parent_stage": "initial",
      "generated": true,
      "dynamic": true
    },
    {
      "id": "deep-scan",
      "name": "Deep Scan with Large Wordlist",
      "status": "pending",
      "generated": false
    }
  ],
  "current_stage": "admin-targeted",
  "batch_mode": false,
  "total_stages": 3,
  "completed_stages": 1
}
```

### Stage Generation Rules
**Static Stages** (predefined in plugin):
- gobuster: initial, targeted, deep
- hydra: default-creds, small-wordlist, large-wordlist
- SMB: anonymous, authenticated, share-access

**Dynamic Stages** (generated from results):
- gobuster finds `/admin`, `/api`, `/backup` → Creates 3 targeted scan stages
- SMB finds 3 shares → Creates 3 enumeration stages
- SQLi confirms vulnerability → Creates enumeration, exploitation stages

---

## 5. Panel Detailed Specifications

### 5.1 Config Panel ⭐ SCREEN 1 (ALWAYS FIRST)
**Status**: ✓ Working
**Requirement**: MANDATORY - Cannot skip, shown on every new session

**Purpose**:
- Validate attacker machine configuration before enumeration
- Set LHOST, LPORT, WORDLIST, INTERFACE
- Critical for reverse shells, listeners, and automated tasks
- OSCP exam requirement (correct LHOST/LPORT)

**Layout:**
```
╔════════════════════════════════════════════════════════╗
║         Configuration Setup                            ║
╠════════════════════════════════════════════════════════╣
║ LHOST:      192.168.45.200                             ║
║ LPORT:      4444                                       ║
║ WORDLIST:   /usr/share/seclists/common.txt             ║
║ INTERFACE:  tun0                                       ║
║ TARGET:     192.168.45.100 (read-only)                 ║
║                                                        ║
║ 1. Edit LHOST                                          ║
║ 2. Edit LPORT                                          ║
║ 3. Edit WORDLIST                                       ║
║ 4. Edit INTERFACE                                      ║
║                                                        ║
║ 5. Continue to Main Menu                               ║
╚════════════════════════════════════════════════════════╝
```

**Actions:**
- 1-4: Edit variable → Prompt for new value → Save to `~/.crack/config.json`
- 5: Continue → Navigate to [Dashboard Panel]
- q: Quit without saving

---

### 5.2 Dashboard Panel (Main Hub)

**Purpose**: Central hub for all actions, always return here

**Layout:**
```
╔════════════════════════════════════════════════════════╗
║ CRACK Track TUI | Target: 192.168.45.100              ║
║ Phase: Service Detection | Progress: 15/47 (32%)      ║
╠════════════════════════════════════════════════════════╣
║                                                        ║
║ 🎯 NEXT RECOMMENDED TASK                               ║
║ ┌──────────────────────────────────────────────────┐  ║
║ │ gobuster-80 (Port 80 Directory Enumeration)      │  ║
║ │ Stage 1/3: Initial Scan                          │  ║
║ │ Time: ~3 min | Priority: HIGH | Tags: QUICK_WIN  │  ║
║ └──────────────────────────────────────────────────┘  ║
║                                                        ║
║ ACTIONS:                                               ║
║  1. Execute next task                                  ║
║  2. Browse all tasks (47 available)                    ║
║  3. Quick wins (5 available) ⚡                        ║
║  4. Import scan results                                ║
║  5. Document finding                                   ║
║  6. Browse findings (12 total)                         ║
║  7. Full status                                        ║
║  8. Help                                               ║
║  9. Exit                                               ║
║                                                        ║
╠════════════════════════════════════════════════════════╣
║ (s) Status | (t) Tree | (h) Help | (q) Quit           ║
╚════════════════════════════════════════════════════════╝
```

**Content:**
- **Header**: Target, current phase, progress (X/Y tasks, %)
- **Recommended Task Card**: Next high-value task with quick details
- **Action Menu**: Numbered 1-9 for quick access
- **Footer**: Essential shortcuts

**Actions:**
1. Execute next task → Jump to [Task Workspace] with recommended task
2. Browse all tasks → [Task List Panel]
3. Quick wins → [Task List Panel] (filtered for QUICK_WIN tag)
4. Import scan → [Import Form]
5. Document finding → [Finding Entry Form]
6. Browse findings → [Findings Panel]
7. Full status → [Status Overlay]
8. Help → [Help Overlay]
9. Exit → Save and quit

**Shortcuts:**
- `s` → [Status Overlay]
- `t` → [Tree Overlay]
- `h` → [Help Overlay]
- `q` → Quit with save prompt

---

### 5.3 Task List Panel (Primary Work Screen)

**Purpose**: Browse, filter, search, and select tasks

**Layout:**
```
╔════════════════════════════════════════════════════════╗
║ TASK LIST | Filter: Pending | Sort: Priority          ║
║ Breadcrumb: Dashboard > Task List                     ║
╠════════════════════════════════════════════════════════╣
║ # │St│ Task Name               │Port│Pri│Tags│Stage   ║
║───┼──┼─────────────────────────┼────┼───┼────┼────────║
║ 1 │~│ gobuster-80             │ 80 │ H │ QW │ [2/3]  ║
║ 2 │ │ nikto-80                │ 80 │ M │    │        ║
║ 3 │ │ enum4linux-445          │445 │ H │ OS │        ║
║ 4 │ │ hydra-ssh-22            │ 22 │ L │    │ [1/5]  ║
║ 5 │ │ smb-enum-shares-445     │445 │ M │    │        ║
║ 6 │✓│ nmap-version-scan       │All │ H │    │ Done   ║
║ 7 │ │ whatweb-80              │ 80 │ L │    │        ║
║ 8 │ │ mysql-enum-3306         │3306│ M │    │        ║
║ 9 │ │ snmp-enum-161           │161 │ H │ OS │        ║
║10 │ │ ldap-enum-389           │389 │ M │    │        ║
║───┴──┴─────────────────────────┴────┴───┴────┴────────║
║ Page 1/5 | Total: 47 tasks | Showing: 10 per page    ║
║                                                        ║
║ (f) Filter | (s) Sort | (g) Group | (/) Search        ║
║ (Enter #) Select Task | (n) Next Page | (b) Back      ║
╠════════════════════════════════════════════════════════╣
║ Legend: ~ = In-Progress | ✓ = Complete | [2/3] = Stage║
║         QW = Quick Win | OS = OSCP High Priority      ║
╚════════════════════════════════════════════════════════╝
```

**Columns:**
- **#** - Selection number (1-10 per page)
- **St** - Status icon (~ in-progress, ✓ complete, ✗ failed, blank pending)
- **Task Name** - Full task ID
- **Port** - Target port or "All"
- **Pri** - Priority (H/M/L)
- **Tags** - Tag badges (QW, OS, MANUAL, etc.)
- **Stage** - Multi-stage indicator `[current/total]` or "Done"

**Filter Options** (press 'f'):
- By Status: All, Pending, In-Progress, Completed, Failed
- By Port: 80, 443, 22, 445, etc.
- By Service: HTTP, SMB, SSH, MySQL, etc.
- By Priority: HIGH, MEDIUM, LOW
- By Tags: QUICK_WIN, OSCP:HIGH, MANUAL, READ_ONLY
- Multi-Stage: Show only multi-stage, Show with follow-ups available

**Sort Options** (press 's'):
- Priority (HIGH → MEDIUM → LOW) - default
- Name (alphabetical)
- Port (ascending)
- Status (pending first)
- Time estimate (shortest first)

**Group Options** (press 'g'):
- No grouping (flat list) - default
- Group by port
- Group by service
- Group by phase

**Search** (press '/'):
- Search by task name
- Search by command
- Search by description

**Actions:**
- `1-10` - Select task → Navigate to [Task Workspace]
- `f` - Toggle filter menu
- `s` - Change sort order
- `g` - Toggle grouping
- `/` - Search
- `n` - Next page
- `p` - Previous page
- `b` - Back to [Dashboard Panel]

---

### 5.4 Task Workspace (Multi-Panel View) ⭐ NEW

**Purpose**: Unified workspace for task execution with side-by-side details and output

**Layout States:**

#### **State 1: Split View (Default)**
```
╔════════════════════════════════════════════════════════════════════════════════╗
║ TASK WORKSPACE: gobuster-80                                                    ║
║ Breadcrumb: Dashboard > Task List > gobuster-80                               ║
║ Stages: [✓ Initial] → [● Targeted] → [○ Deep Scan]  |  Current: Stage 2/3     ║
╠══════════════════════════════════╦═════════════════════════════════════════════╣
║                                  ║                                             ║
║ TASK DETAILS                     ║ COMMAND OUTPUT                              ║
║                                  ║                                             ║
║ Description:                     ║ [Before Execution]                          ║
║   Targeted scan on /admin path   ║ No output yet.                              ║
║   discovered in initial scan     ║                                             ║
║                                  ║ Press (1) to execute this stage             ║
║ Command:                         ║ Press (2) to batch execute all remaining    ║
║   gobuster dir \                 ║                                             ║
║     -u http://192.168.45.100 \   ║ ──────────────────────────────────────────  ║
║     -w /usr/share/.../common.txt ║                                             ║
║     -t 50 \                      ║ [After Execution Starts]                    ║
║     -o /tmp/gobuster-admin.txt   ║ Executing: gobuster dir ...                 ║
║                                  ║ Status: Running [⣾] 00:00:15                ║
║ Flags:                           ║ ──────────────────────────────────────────  ║
║   -u : Target URL                ║ /admin/backup    (Status: 200) [Size: 1234] ║
║   -w : Wordlist path             ║ /admin/config    (Status: 200) [Size: 567]  ║
║   -t : Thread count (50)         ║ /admin/logs      (Status: 403) [Size: 0]    ║
║   -o : Output file               ║ /admin/users     (Status: 301) [Size: 0]    ║
║                                  ║ ...                                          ║
║ Time: ~2 min                     ║ [Auto-scrolling ↓]                          ║
║ Priority: HIGH                   ║                                             ║
║ Tags: QUICK_WIN                  ║ ──────────────────────────────────────────  ║
║                                  ║                                             ║
║ Manual Alternative:              ║ [After Execution Complete]                  ║
║   for w in $(cat wordlist); do   ║ ✓ Stage 2 Complete                          ║
║     curl -s http://target/$w     ║ Exit Code: 0 (Success)                      ║
║     | grep -q 200 && echo $w     ║                                             ║
║   done                           ║ Auto-Detected Findings:                     ║
║                                  ║   • Directory: /admin/backup (200 OK)       ║
║ Success Indicators:              ║   • Directory: /admin/config (200 OK)       ║
║   • 200/301/302 responses        ║   • Directory: /admin/users (301 Redirect)  ║
║   • New directories found        ║                                             ║
║                                  ║ Next: Continue to Stage 3 or generate       ║
║ (Scroll ↑↓)                      ║       follow-ups for 3 new directories      ║
║                                  ║ (Scroll ↑↓) | (e) Expand Output             ║
╠══════════════════════════════════╩═════════════════════════════════════════════╣
║ ACTIONS:                                                                       ║
║  1. Execute this stage    2. Execute all remaining (batch)                     ║
║  3. Skip to next stage    4. Edit command    5. View alternatives              ║
║  6. Generate follow-ups (3 dirs)    7. Save output    8. Add finding           ║
║  9. Back to task list                                                          ║
║                                                                                ║
║ (e) Expand Output | (c) Collapse Details | (b) Back                           ║
╚════════════════════════════════════════════════════════════════════════════════╝
```

**Panel Breakdown:**

**Left Panel: Task Details (40% width)**
- Task description
- Full command with line breaks
- Flag explanations (educational)
- Time estimate
- Priority and tags
- Manual alternatives (for OSCP exam)
- Success indicators
- Scrollable if content overflows

**Right Panel: Command Output (60% width)**
- **Before Execution**: Placeholder with quick actions
- **During Execution**: Live streaming output with auto-scroll
- **After Execution**: Complete output + exit code + auto-detected findings
- Scrollable independently
- **Expandable to full-screen** (press 'e')

**Header:**
- Task name
- Breadcrumb navigation
- Stage navigator (visual timeline with checkpoints)

**Footer:**
- Numbered actions (1-9)
- Keyboard shortcuts
- Navigation options

#### **State 2: Expanded Output (Full-Screen)**
```
╔════════════════════════════════════════════════════════════════════════════════╗
║ COMMAND OUTPUT (Expanded) - gobuster-80 Stage 2/3                             ║
║ Press (c) to collapse back to split view                                      ║
╠════════════════════════════════════════════════════════════════════════════════╣
║                                                                                ║
║ Executing: gobuster dir -u http://192.168.45.100/admin \                      ║
║   -w /usr/share/seclists/Discovery/Web/common.txt -t 50                       ║
║                                                                                ║
║ Status: Running [⣾] 00:01:45 elapsed                                           ║
║                                                                                ║
║ ──────────────────────────────────────────────────────────────────────────────║
║                                                                                ║
║ /admin/backup           (Status: 200) [Size: 1234]                            ║
║ /admin/config           (Status: 200) [Size: 567]                             ║
║ /admin/logs             (Status: 403) [Size: 0]                               ║
║ /admin/users            (Status: 301) [Size: 0] [Location: /admin/users/]     ║
║ /admin/dashboard        (Status: 200) [Size: 4567]                            ║
║ /admin/settings         (Status: 200) [Size: 890]                             ║
║ /admin/reports          (Status: 403) [Size: 0]                               ║
║ /admin/api              (Status: 200) [Size: 123]                             ║
║ /admin/uploads          (Status: 200) [Size: 0]                               ║
║ /admin/downloads        (Status: 200) [Size: 0]                               ║
║ ...                                                                            ║
║ [More output - auto-scrolling to bottom]                                      ║
║ ...                                                                            ║
║                                                                                ║
║ Progress: 1024/4096 lines (25%)                                               ║
║                                                                                ║
║ (Scroll with ↑↓ | PgUp/PgDn | Home/End)                                       ║
║                                                                                ║
╠════════════════════════════════════════════════════════════════════════════════╣
║ (c) Collapse to split view | (s) Save output | (/) Search output              ║
╚════════════════════════════════════════════════════════════════════════════════╝
```

**Expanded Output Features:**
- Full-screen command output (uses entire terminal)
- Task details hidden temporarily (accessible via 'c' collapse)
- Better for long output (100+ lines)
- Enhanced scrolling (PgUp/PgDn, Home/End)
- Search within output ('/')
- Save to file ('s')

**Output Panel Modes:**
1. **Empty** - Before execution, shows placeholder
2. **Streaming** - During execution, auto-scrolls to bottom, shows progress
3. **Complete** - After execution, shows exit code, findings, next steps
4. **Expanded** - Full-screen mode for detailed review

**Actions:**
1. Execute this stage → Starts command, output streams into right panel
2. Execute all remaining (batch) → Loops through stages automatically
3. Skip to next stage → Mark current skipped, advance
4. Edit command → Inline editor in left panel
5. View alternatives → Show alternative commands overlay
6. Generate follow-ups → Dynamic stage generation (if results found)
7. Save output → Prompt for filename
8. Add finding → Quick finding entry form
9. Back → Navigate to [Task List Panel]

**Shortcuts:**
- `e` - Expand output to full-screen
- `c` - Collapse output back to split view
- `s` - Save output to file
- `/` - Search within output
- `b` - Back to [Task List Panel]

---

### 5.5 Findings Panel

**Purpose**: Browse, filter, and correlate discoveries

**Layout:**
```
╔════════════════════════════════════════════════════════╗
║ FINDINGS BROWSER | Filter: All | Sort: Recent          ║
║ Breadcrumb: Dashboard > Findings                      ║
╠════════════════════════════════════════════════════════╣
║ Type│ Description                │Source     │Time    ║
║─────┼────────────────────────────┼───────────┼────────║
║ 🔓  │ SQLi in /login.php?id=     │ sqlmap    │ 14:30  ║
║ 🔑  │ admin:password123 (MySQL)  │ config.php│ 14:25  ║
║ 📁  │ /admin/backup (200 OK)     │ gobuster  │ 14:20  ║
║ 👤  │ john.doe@victim.com        │ enum4linux│ 14:15  ║
║ 📝  │ Apache 2.4.41 (outdated)   │ whatweb   │ 14:10  ║
║ 🔓  │ Path traversal in download │ manual    │ 14:05  ║
║─────┴────────────────────────────┴───────────┴────────║
║ Total: 12 findings | Vulnerabilities: 3 | Creds: 2   ║
║                                                        ║
║ (f) Filter | (s) Sort | (Enter #) View Details        ║
║ (e) Export | (c) Correlate | (b) Back to Dashboard    ║
╚════════════════════════════════════════════════════════╝
```

**Filters:**
- Type: All, Vulnerabilities, Credentials, Directories, Users, Notes
- Port: 80, 443, 22, etc.
- Service: HTTP, SSH, SMB, etc.
- Date: Today, Last Hour, Custom Range

**Actions:**
- Select finding → View full details + metadata
- Export → Markdown/JSON
- Correlate → Show relationships between findings
- Back → [Dashboard Panel]

---

### 5.6 Overlay Panels

#### Status Overlay (Shortcut: 's')
```
╔════════════════════════════════════════════════════════╗
║ QUICK STATUS                                           ║
╠════════════════════════════════════════════════════════╣
║ Target:    192.168.45.100                              ║
║ Phase:     Service Detection                           ║
║ Progress:  15/47 tasks (32% complete)                  ║
║                                                        ║
║ Ports Discovered: 8                                    ║
║   • 22/tcp   SSH      OpenSSH 8.2p1                    ║
║   • 80/tcp   HTTP     Apache 2.4.41                    ║
║   • 445/tcp  SMB      Samba 4.11.6                     ║
║   ... (5 more)                                         ║
║                                                        ║
║ Findings:     12 total                                 ║
║   • Vulnerabilities: 3                                 ║
║   • Credentials: 2                                     ║
║   • Directories: 7                                     ║
║                                                        ║
║ Time Elapsed: 02:15:30                                 ║
║                                                        ║
║ Press any key to close                                 ║
╚════════════════════════════════════════════════════════╝
```

#### Help Overlay (Shortcut: 'h')
```
╔════════════════════════════════════════════════════════╗
║ KEYBOARD SHORTCUTS                                     ║
╠════════════════════════════════════════════════════════╣
║ Navigation:                                            ║
║   s - Quick status      t - Task tree    h - Help     ║
║   b - Back              q - Quit         n - Next rec ║
║                                                        ║
║ Task Workspace:                                        ║
║   e - Expand output     c - Collapse output            ║
║   / - Search output     s - Save output                ║
║                                                        ║
║ Task List:                                             ║
║   f - Filter tasks      s - Sort tasks   g - Group    ║
║   / - Search tasks      n - Next page    p - Prev     ║
║                                                        ║
║ Advanced:                                              ║
║   alt - Alternative commands    w - Select wordlist   ║
║   qn - Quick note              fc - Finding correlator║
║                                                        ║
║ Press any key to close                                 ║
╚════════════════════════════════════════════════════════╝
```

#### Tree Overlay (Shortcut: 't')
```
╔════════════════════════════════════════════════════════╗
║ TASK TREE                                              ║
╠════════════════════════════════════════════════════════╣
║ ✓ Discovery                                            ║
║   ✓ nmap-initial-scan                                  ║
║   ✓ nmap-full-scan                                     ║
║   ✓ nmap-version-scan                                  ║
║                                                        ║
║ ~ Service Enumeration                                  ║
║   ✓ Port 80 (HTTP)                                     ║
║     ✓ whatweb-80                                       ║
║     ~ gobuster-80 [Stage 2/3]                          ║
║     ○ nikto-80                                         ║
║   ○ Port 445 (SMB)                                     ║
║     ○ enum4linux-445                                   ║
║     ○ smb-enum-shares-445                              ║
║                                                        ║
║ ○ Exploitation                                         ║
║                                                        ║
║ Legend: ✓ Complete | ~ In-Progress | ○ Pending        ║
║                                                        ║
║ Press any key to close                                 ║
╚════════════════════════════════════════════════════════╝
```

---

## 6. State Machine Diagram

### States
```
┌──────────────────────────────────────────────────┐
│                                                  │
│  [INIT] → [CONFIG ⭐ MANDATORY] → [DASHBOARD]    │
│           (Screen 1 - REQUIRED)      (hub)       │
│                           │                      │
│                           ├─→ [TASK_LIST]        │
│                           │      └─→ [TASK_WORKSPACE] (multi-panel)
│                           │             │        │
│                           │             └─→ [EXECUTING] (within workspace)
│                           │                      │
│                           ├─→ [FINDINGS]         │
│                           │                      │
│                           ├─→ [FORM]             │
│                           │                      │
│                           └─→ [OVERLAY]          │
│                                  (non-state)     │
└──────────────────────────────────────────────────┘
```

### State Descriptions

**INIT** - Application startup
- Entry: Load Rich library, check terminal support
- Exit: Navigate to CONFIG

**CONFIG** - Configuration panel ⭐ MANDATORY (Screen 1)
- Entry: Load `~/.crack/config.json`, always shown first
- Actions: Edit LHOST/LPORT/WORDLIST/INTERFACE or confirm
- Exit: Save config, navigate to DASHBOARD (cannot skip)

**DASHBOARD** - Main hub
- Entry: Load profile, get recommendations
- Exit: Navigate to chosen panel, preserve state

**TASK_LIST** - Task browser
- Entry: Load tasks, apply filters/sort
- Exit: Navigate to TASK_WORKSPACE or back to DASHBOARD

**TASK_WORKSPACE** - Multi-panel task view
- Entry: Load task details, initialize output panel (empty)
- During: Output panel updates during execution
- Exit: Save checkpoint, navigate to TASK_LIST or DASHBOARD

**EXECUTING** - Command execution (within workspace)
- Entry: Start command, stream output to right panel
- During: Auto-scroll output, parse results
- Exit: Save checkpoint, show next steps prompt

**FINDINGS** - Findings browser
- Entry: Load findings, apply filters
- Exit: Navigate to DASHBOARD

**FORM** - Input forms (Finding, Cred, Import)
- Entry: Show form fields
- Exit: Validate, save to profile, navigate to DASHBOARD

**OVERLAY** - Temporary overlays (Help, Status, Tree)
- Entry: Render overlay on top of current panel
- Exit: Dismiss, return to previous state (non-state-changing)

### Transitions

| From           | To              | Trigger                    | Condition        |
|----------------|-----------------|----------------------------|------------------|
| INIT           | CONFIG          | Auto                       | Always           |
| CONFIG         | DASHBOARD       | Confirm (press 5)          | Config valid     |
| DASHBOARD      | TASK_LIST       | Browse tasks (press 2)     | Always           |
| TASK_LIST      | TASK_WORKSPACE  | Select task (press 1-10)   | Task exists      |
| TASK_WORKSPACE | EXECUTING       | Execute (press 1)          | Command ready    |
| EXECUTING      | TASK_WORKSPACE  | Complete                   | Always           |
| TASK_WORKSPACE | TASK_LIST       | Back (press b or 9)        | Always           |
| TASK_LIST      | DASHBOARD       | Back (press b)             | Always           |
| DASHBOARD      | FINDINGS        | Browse findings (press 6)  | Always           |
| FINDINGS       | DASHBOARD       | Back (press b)             | Always           |
| DASHBOARD      | FORM            | Document finding (press 5) | Always           |
| FORM           | DASHBOARD       | Save or Cancel             | Always           |
| ANY            | OVERLAY         | Shortcut (s/t/h)           | Always           |
| OVERLAY        | PREVIOUS        | Any key                    | Always           |

---

## 7. Sequence Diagrams

### 7.1 Multi-Stage Task Execution (Full Workflow)

```
User          Dashboard        TaskList       TaskWorkspace      Execution       Profile
 │                │                │                │                │              │
 │  Browse Tasks  │                │                │                │              │
 ├───────────────>│                │                │                │              │
 │                │  Navigate      │                │                │              │
 │                ├───────────────>│                │                │              │
 │                │                │  Show tasks    │                │              │
 │                │                │<───────────────┤                │              │
 │  Select #3     │                │                │                │              │
 ├────────────────┼────────────────>│                │                │              │
 │                │                │  Load task     │                │              │
 │                │                ├───────────────>│                │              │
 │                │                │                │  Get metadata  │              │
 │                │                │                ├───────────────>│              │
 │                │                │                │  Return data   │              │
 │                │                │                │<───────────────┤              │
 │                │                │  Show split    │                │              │
 │                │                │  view (L/R)    │                │              │
 │                │                │<───────────────┤                │              │
 │  Execute (1)   │                │                │                │              │
 ├────────────────┼────────────────┼───────────────>│                │              │
 │                │                │                │  Start cmd     │              │
 │                │                │                ├───────────────>│              │
 │                │                │                │  Stream output │              │
 │                │                │                │  to right panel│              │
 │                │                │                │<───────────────┤              │
 │                │                │                │  [Live updates]│              │
 │                │                │                │<═══════════════╡              │
 │                │                │                │  Complete      │              │
 │                │                │                │<───────────────┤              │
 │                │                │                │  Parse results │              │
 │                │                │                │  Save checkpoint              │
 │                │                │                ├──────────────────────────────>│
 │                │                │                │  Generate stages              │
 │                │                │                │  (dynamic)                    │
 │                │                │                │                │              │
 │                │                │  Show next     │                │              │
 │                │                │  steps prompt  │                │              │
 │                │                │<───────────────┤                │              │
 │  Continue (1)  │                │                │                │              │
 ├────────────────┼────────────────┼───────────────>│                │              │
 │                │                │                │  Load Stage 2  │              │
 │                │                │                │  [Repeat...]   │              │
```

### 7.2 Output Expansion Flow

```
User          TaskWorkspace      OutputPanel
 │                │                │
 │  Viewing split │                │
 │  view (L/R)    │                │
 │                │  Details: 40%  │
 │                │  Output:  60%  │
 │                │<───────────────┤
 │                │                │
 │  Press 'e'     │                │
 │  (Expand)      │                │
 ├───────────────>│                │
 │                │  Hide details  │
 │                │  panel         │
 │                │                │
 │                │  Expand output │
 │                │  to 100% width │
 │                ├───────────────>│
 │                │                │
 │                │  Full-screen   │
 │                │  output        │
 │                │<───────────────┤
 │                │                │
 │  Press 'c'     │                │
 │  (Collapse)    │                │
 ├───────────────>│                │
 │                │  Restore split │
 │                │  view (40/60)  │
 │                ├───────────────>│
 │                │                │
 │                │  Split view    │
 │                │<───────────────┤
```

### 7.3 Dynamic Stage Generation Flow

```
User     TaskWorkspace    Execution    StageGenerator    Profile
 │            │               │              │              │
 │  Execute   │               │              │              │
 │  Stage 1   │               │              │              │
 ├───────────>│               │              │              │
 │            │  Run gobuster │              │              │
 │            ├──────────────>│              │              │
 │            │               │  Output:     │              │
 │            │               │  /admin 200  │              │
 │            │               │  /api 200    │              │
 │            │               │  /backup 403 │              │
 │            │               │              │              │
 │            │               │  Parse dirs  │              │
 │            │               ├─────────────>│              │
 │            │               │              │  Create:     │
 │            │               │              │  admin-scan  │
 │            │               │              │  api-scan    │
 │            │               │              ├─────────────>│
 │            │               │              │  Save stages │
 │            │               │              │<─────────────┤
 │            │  Show:        │              │              │
 │            │  "2 new stages│              │              │
 │            │  generated"   │              │              │
 │            │<──────────────┤              │              │
 │  Continue  │               │              │              │
 │  to Stage 2│               │              │              │
 ├───────────>│               │              │              │
 │            │  Load         │              │              │
 │            │  admin-scan   │              │              │
 │            │  (dynamic)    │              │              │
```

---

## 8. Implementation Phases

### Phase 1: Foundation ✓ DONE
**Goal**: Config panel (SCREEN 1) + basic dashboard shell

**Deliverables:**
- ✓ Config panel working (LHOST, LPORT, WORDLIST, INTERFACE)
- ✓ Config panel ALWAYS shown first (mandatory)
- ✓ Basic dashboard (header, simple menu, footer)
- ✓ Navigation: Config → Dashboard (enforced flow)

**Test Criteria:**
- ✓ Can edit config variables
- ✓ Config persists to `~/.crack/config.json`
- ✓ Cannot skip config panel (required)
- ✓ Dashboard shows target, phase, menu
- ✓ No crashes, clean exit

**Implementation Status:**
- Config panel: ✓ Working in `tui_session.py` (original)
- Dashboard: Needs refactor in v3

---

### Phase 2: Dashboard + Overlays
**Goal**: Complete dashboard with overlay panels

**Deliverables:**
- Dashboard panel with phase, progress, recommendations
- Status overlay (shortcut: 's')
- Help overlay (shortcut: 'h')
- Tree overlay (shortcut: 't')

**Components:**
```python
# dashboard_panel.py
def render_dashboard(profile, recommendations):
    # Phase banner
    # Progress bar
    # Recommended task card
    # Action menu (1-9)
    # Footer shortcuts

# overlay_renderers.py
def render_status_overlay(profile):
    # Target, phase, progress
    # Ports summary
    # Findings count
    # Time elapsed

def render_help_overlay():
    # Keyboard shortcuts
    # Quick reference

def render_tree_overlay(task_tree):
    # Hierarchical task tree
    # Status indicators
```

**Test Criteria:**
- Dashboard shows current phase correctly
- Progress bar accurate (X/Y tasks)
- Next recommended task displays
- All 9 actions selectable
- Overlays appear/dismiss correctly
- Shortcuts work (s, t, h)

---

### Phase 3: Task List Panel
**Goal**: Browsable, filterable, sortable task list

**Deliverables:**
- Task list panel with pagination
- Filter system (status, port, service, tags)
- Sort options (priority, name, port, time)
- Group options (port, service, phase)
- Search functionality

**Components:**
```python
# task_list_panel.py
class TaskListPanel:
    def __init__(self, profile):
        self.tasks = profile.task_tree.get_all_tasks()
        self.filters = FilterState()
        self.sort = SortState()
        self.page = 1
        self.per_page = 10

    def apply_filters(self):
        # Filter by status, port, service, tags

    def apply_sort(self):
        # Sort by priority, name, etc.

    def render(self):
        # Table with columns: #, Status, Name, Port, Pri, Tags, Stage
        # Pagination controls
        # Filter/sort/search bar
```

**Test Criteria:**
- Can browse all tasks (47 total across 5 pages)
- Filters work (pending, port 80, QUICK_WIN tag)
- Sort works (priority, name)
- Pagination works (next/prev page)
- Multi-stage indicator shows `[2/3]`
- Select task → navigates to Task Workspace

---

### Phase 4: Task Workspace (Multi-Panel)
**Goal**: Split-view task details + output panel

**Deliverables:**
- Split-panel layout (40% details / 60% output)
- Stage navigator component
- Task details panel (left)
- Command output panel (right)
- Expand/collapse output ('e'/'c')

**Components:**
```python
# task_workspace.py
class TaskWorkspace:
    def __init__(self, task):
        self.task = task
        self.output_mode = 'split'  # 'split' or 'expanded'
        self.output_lines = []

    def render_split_view(self):
        # Left: Task details (40%)
        # Right: Command output (60%)

    def render_expanded_view(self):
        # Full-screen output (100%)

    def toggle_output(self):
        self.output_mode = 'expanded' if self.output_mode == 'split' else 'split'

# stage_navigator.py
def render_stage_navigator(stages, current_stage):
    # Visual timeline: [✓ S1] → [● S2] → [○ S3]
```

**Test Criteria:**
- Split view shows details + output side-by-side
- Stage navigator displays correctly
- Output panel empty before execution
- Press 'e' → output expands to full-screen
- Press 'c' → output collapses back to split
- Scroll works independently in both panels

---

### Phase 5: Execution + Checkpoints
**Goal**: Live command execution with output streaming

**Deliverables:**
- Command execution in Task Workspace
- Live output streaming to right panel
- Exit code detection
- Auto-parsing for findings
- Checkpoint system (save after each stage)
- Dynamic stage generation
- Post-execution prompt (continue/back/generate)

**Components:**
```python
# execution_manager.py
class ExecutionManager:
    def execute_command(self, command, output_panel):
        # Start subprocess
        # Stream stdout/stderr to output_panel
        # Auto-scroll to bottom
        # Detect completion (exit code)
        # Parse output for findings
        # Return results

    def save_checkpoint(self, task, stage, results):
        # Save to ~/.crack/checkpoints/
        # Include: task_id, stage_id, timestamp, output, findings

    def generate_dynamic_stages(self, results):
        # Parse results (e.g., directories found)
        # Create new stage objects
        # Add to task metadata
```

**Test Criteria:**
- Execute command → output streams live
- Output auto-scrolls during execution
- Exit code shown after completion
- Findings auto-detected (directories, creds)
- Checkpoint saved after stage
- Dynamic stages generated (gobuster finds /admin → creates admin-scan)
- Prompt shows: Continue, Generate, Back

---

### Phase 6: Findings Panel
**Goal**: Browse and filter discoveries

**Deliverables:**
- Findings browser with filters
- Timeline view (chronological)
- Export functionality (Markdown, JSON)
- Correlation view (show relationships)

**Components:**
```python
# findings_panel.py
class FindingsPanel:
    def __init__(self, profile):
        self.findings = profile.findings
        self.filters = FilterState()

    def apply_filters(self):
        # Filter by type, port, service, date

    def render(self):
        # Table: Icon, Description, Source, Timestamp
        # Filter bar
        # Export option
```

**Test Criteria:**
- Shows all findings (12 total)
- Filters work (vulnerabilities only, port 80)
- Sort by timestamp
- Export to Markdown
- Navigate back to Dashboard

---

### Phase 7: Forms
**Goal**: Guided input for findings, creds, imports

**Deliverables:**
- Finding entry form
- Credential entry form
- Import form (scan file upload)
- Note form

**Components:**
```python
# forms.py
class FindingForm:
    def render(self):
        # Type selection menu
        # Description input
        # Source input (required)

    def validate(self):
        # Check required fields

    def save(self, profile):
        # Add to profile.findings

class CredentialForm:
    # Similar structure
```

**Test Criteria:**
- Can add finding with all fields
- Source field required (OSCP requirement)
- Validation works (required fields)
- Saves to profile
- Returns to Dashboard

---

### Phase 8: Polish & Edge Cases
**Goal**: Production-ready UX

**Deliverables:**
- Crash recovery (resume from checkpoint)
- Terminal resize handling
- Better error messages
- Loading indicators
- Keyboard shortcut polish
- Performance optimization (100+ tasks)

**Test Criteria:**
- Ctrl+C during execution → saves checkpoint, allows resume
- Terminal resize → panels redraw correctly
- Invalid input → clear error message
- Long tasks → loading spinner
- 100+ tasks → pagination smooth

---

## 9. Data Persistence (Checkpoint System)

### Checkpoint Directory Structure
```
~/.crack/
├── config.json                           # Global config
├── targets/
│   └── 192.168.45.100.json               # Target profile
├── checkpoints/
│   ├── 192.168.45.100_gobuster-80_initial.json
│   ├── 192.168.45.100_gobuster-80_targeted.json
│   └── 192.168.45.100_current_state.json  # Active state
└── sessions/
    └── 192.168.45.100.json                # Session snapshot
```

### Checkpoint File Format
```json
{
  "task_id": "gobuster-80",
  "stage_id": "initial",
  "status": "completed",
  "timestamp": "2025-10-09T14:30:00",
  "command": "gobuster dir -u http://192.168.45.100 -w /usr/share/seclists/common.txt",
  "output_file": "/tmp/gobuster-80-initial.txt",
  "exit_code": 0,
  "execution_time": 180,
  "findings": [
    {
      "type": "directory",
      "value": "/admin",
      "status": 200,
      "size": 1234
    },
    {
      "type": "directory",
      "value": "/api",
      "status": 200,
      "size": 567
    }
  ],
  "next_stage": "targeted",
  "generated_stages": [
    {
      "id": "admin-scan",
      "name": "Targeted Scan on /admin",
      "parent": "initial",
      "command": "gobuster dir -u http://192.168.45.100/admin -w ...",
      "dynamic": true
    },
    {
      "id": "api-scan",
      "name": "Targeted Scan on /api",
      "parent": "initial",
      "command": "gobuster dir -u http://192.168.45.100/api -w ...",
      "dynamic": true
    }
  ]
}
```

### Crash Recovery Logic
```python
def startup_recovery_check():
    """Check for interrupted tasks on startup"""
    current_state = load_checkpoint("current_state.json")

    if current_state:
        task_id = current_state['task_id']
        stage_id = current_state['stage_id']

        print(f"Found interrupted task: {task_id} (Stage: {stage_id})")
        print("Resume from checkpoint? [Y/n]: ")

        if user_confirms():
            # Load checkpoint
            checkpoint = load_checkpoint(f"{target}_{task_id}_{stage_id}.json")

            # Jump to Task Workspace
            workspace = TaskWorkspace(task_id)
            workspace.load_checkpoint(checkpoint)

            # Resume execution or show results
            if checkpoint['status'] == 'in-progress':
                # Restart stage from beginning
                workspace.execute_current_stage()
            else:
                # Show completed results
                workspace.show_results(checkpoint)
        else:
            # Clear checkpoint
            delete_checkpoint("current_state.json")
```

---

## 10. Edge Cases & Error Handling

### Terminal Issues
**Problem**: Terminal too small (< 80x24)
**Solution**: Show error, fallback to basic mode (non-TUI)
```python
if terminal.width < 80 or terminal.height < 24:
    console.print("[red]Terminal too small for TUI mode[/]")
    console.print("[yellow]Minimum: 80x24 | Current: {terminal.width}x{terminal.height}[/]")
    console.print("[cyan]Falling back to basic mode...[/]")
    return BasicSession(target)
```

**Problem**: Terminal resize during use
**Solution**: Gracefully redraw panels
```python
def on_terminal_resize(new_width, new_height):
    # Recalculate panel dimensions
    # Redraw all panels
    layout_manager.rebuild_layout(new_width, new_height)
    live.refresh()
```

**Problem**: Rich library not available
**Solution**: Fallback to basic mode
```python
try:
    from rich.live import Live
    from rich.panel import Panel
except ImportError:
    console.print("[yellow]Rich library not available[/]")
    console.print("[yellow]Install: pip install rich[/]")
    console.print("[cyan]Falling back to basic mode...[/]")
    return BasicSession(target)
```

### User Input
**Problem**: Invalid input (e.g., press 'x' when 1-9 expected)
**Solution**: Show inline error, don't crash
```python
try:
    choice = int(user_input)
    if 1 <= choice <= len(choices):
        execute_choice(choice)
    else:
        console.print(f"[red]Invalid choice. Enter 1-{len(choices)}[/]")
except ValueError:
    console.print(f"[red]Invalid input: {user_input}[/]")
```

**Problem**: Ctrl+C during execution
**Solution**: Kill command, save partial checkpoint
```python
try:
    result = subprocess.run(command, ...)
except KeyboardInterrupt:
    print("\n[yellow]Execution interrupted by user[/]")
    # Kill subprocess
    process.terminate()
    # Save partial checkpoint
    save_checkpoint(task, stage, status='interrupted', partial_output=True)
    print("[cyan]Checkpoint saved. You can resume later.[/]")
```

**Problem**: EOF (Ctrl+D)
**Solution**: Treat as 'back' or 'quit'
```python
try:
    user_input = input("Choice: ")
except EOFError:
    # Treat as quit
    return 'exit'
```

### Command Execution
**Problem**: Command fails (exit code ≠ 0)
**Solution**: Show error, save checkpoint, allow retry
```python
if exit_code != 0:
    console.print(f"[red]Command failed with exit code {exit_code}[/]")
    console.print(f"[yellow]Check output for errors[/]")
    # Save checkpoint with error status
    save_checkpoint(task, stage, status='failed', exit_code=exit_code)
    # Offer retry
    print("\n1. Retry this stage")
    print("2. Edit command and retry")
    print("3. Skip and continue")
    print("4. Back to task list")
```

**Problem**: Command hangs (timeout)
**Solution**: Show timeout warning, allow kill
```python
try:
    result = subprocess.run(command, timeout=300)  # 5 min timeout
except subprocess.TimeoutExpired:
    print("[yellow]Command timeout (5 minutes)[/]")
    print("1. Wait longer (extend timeout)")
    print("2. Kill command")
    print("3. Run in background")
```

**Problem**: Output parsing fails
**Solution**: Log error, continue without auto-findings
```python
try:
    findings = parse_output(output)
except Exception as e:
    logger.error(f"Output parsing failed: {e}")
    print("[yellow]Could not auto-detect findings[/]")
    print("[cyan]Output saved. You can manually add findings later.[/]")
    findings = []
```

### Multi-Stage Tasks
**Problem**: Stage dependency not met (e.g., Stage 3 requires Stage 2 complete)
**Solution**: Disable stage, show message
```python
if not stage.dependencies_met():
    console.print(f"[yellow]Cannot execute {stage.name}[/]")
    console.print(f"[cyan]Requires: {stage.dependencies} to be completed first[/]")
    # Disable in menu
    stage.selectable = False
```

**Problem**: Dynamic generation fails
**Solution**: Log error, continue with static stages
```python
try:
    new_stages = generate_stages_from_results(results)
except Exception as e:
    logger.error(f"Dynamic stage generation failed: {e}")
    print("[yellow]Could not generate follow-up stages[/]")
    print("[cyan]Continuing with predefined stages...[/]")
    new_stages = []
```

**Problem**: Checkpoint corruption
**Solution**: Warn user, start stage from scratch
```python
try:
    checkpoint = load_checkpoint(checkpoint_file)
    validate_checkpoint(checkpoint)
except (JSONDecodeError, ValidationError) as e:
    print(f"[red]Checkpoint corrupted: {e}[/]")
    print("[yellow]Starting stage from beginning...[/]")
    checkpoint = None
```

### State Management
**Problem**: Navigation stack overflow (user presses 'back' 20 times)
**Solution**: Limit depth to 5, force back to Dashboard
```python
class NavigationStack:
    MAX_DEPTH = 5

    def push(self, state):
        if len(self.stack) >= self.MAX_DEPTH:
            print("[yellow]Navigation limit reached[/]")
            print("[cyan]Returning to Dashboard...[/]")
            self.stack = [DASHBOARD]
        else:
            self.stack.append(state)
```

**Problem**: Profile save fails (disk full, permissions)
**Solution**: Warn user, retry, don't lose data
```python
try:
    profile.save()
except IOError as e:
    print(f"[red]Failed to save profile: {e}[/]")
    print("[yellow]Retrying...[/]")
    time.sleep(1)
    try:
        profile.save()
        print("[green]Saved successfully on retry[/]")
    except IOError:
        print("[red]Save failed. Your work may be lost![/]")
        print("[cyan]Check disk space and permissions[/]")
        # Keep data in memory
```

**Problem**: Config missing on startup
**Solution**: Create default config, prompt user
```python
if not config_exists():
    print("[yellow]No config found. Creating default...[/]")
    config = create_default_config()
    config.save()
    print("[cyan]Please review and update config:[/]")
    # Jump to Config Panel
    return CONFIG_PANEL
```

---

## 11. Visual Mockups

### 11.1 Config Panel (Startup)
```
╔════════════════════════════════════════════════════════╗
║         Configuration Setup                            ║
║  Confirm settings before starting enumeration          ║
╠════════════════════════════════════════════════════════╣
║                                                        ║
║ LHOST:      192.168.45.200                             ║
║ LPORT:      4444                                       ║
║ WORDLIST:   /usr/share/seclists/Discovery/Web/...     ║
║ INTERFACE:  tun0                                       ║
║ TARGET:     192.168.45.100                             ║
║                                                        ║
║ ────────────────────────────────────────────────────   ║
║                                                        ║
║ 1. Edit LHOST                                          ║
║ 2. Edit LPORT                                          ║
║ 3. Edit WORDLIST                                       ║
║ 4. Edit INTERFACE                                      ║
║                                                        ║
║ 5. Continue to Main Menu                               ║
║                                                        ║
╠════════════════════════════════════════════════════════╣
║ (1-4) Edit | (5) Continue | (q) Quit                   ║
╚════════════════════════════════════════════════════════╝
```

### 11.2 Dashboard Panel (Main Hub)
```
╔════════════════════════════════════════════════════════╗
║ CRACK Track TUI | Target: 192.168.45.100              ║
║ Phase: Service Detection | Progress: 15/47 (32%)      ║
╠════════════════════════════════════════════════════════╣
║                                                        ║
║ 🎯 NEXT RECOMMENDED TASK                               ║
║ ┌──────────────────────────────────────────────────┐  ║
║ │ gobuster-80 (Port 80 Directory Enumeration)      │  ║
║ │ Stage 1/3: Initial Scan                          │  ║
║ │ Time: ~3 min | Priority: HIGH | Tags: QUICK_WIN  │  ║
║ │ Command: gobuster dir -u http://192.168.45.100...│  ║
║ └──────────────────────────────────────────────────┘  ║
║                                                        ║
║ QUICK ACTIONS:                                         ║
║  1. Execute next task                                  ║
║  2. Browse all tasks (47 available)                    ║
║  3. Quick wins (5 available) ⚡                        ║
║  4. Import scan results                                ║
║  5. Document finding                                   ║
║  6. Browse findings (12 total)                         ║
║  7. Full status                                        ║
║  8. Help                                               ║
║  9. Exit                                               ║
║                                                        ║
╠════════════════════════════════════════════════════════╣
║ (s) Status | (t) Tree | (h) Help | (q) Quit           ║
╚════════════════════════════════════════════════════════╝
```

### 11.3 Task List Panel
```
╔════════════════════════════════════════════════════════════════════════════════╗
║ TASK LIST | Filter: All | Sort: Priority | Group: None                        ║
║ Breadcrumb: Dashboard > Task List                                             ║
╠════════════════════════════════════════════════════════════════════════════════╣
║ # │St│ Task Name                  │Port│Service│Pri│Tags    │Stage   │Time    ║
║───┼──┼────────────────────────────┼────┼───────┼───┼────────┼────────┼────────║
║ 1 │~│ gobuster-80                │ 80 │ HTTP  │ H │ QW     │ [2/3]  │ ~3m    ║
║ 2 │ │ nikto-80                   │ 80 │ HTTP  │ M │        │        │ ~10m   ║
║ 3 │ │ enum4linux-445             │445 │ SMB   │ H │ OS     │        │ ~2m    ║
║ 4 │ │ hydra-ssh-22               │ 22 │ SSH   │ L │        │ [1/5]  │ ~15m   ║
║ 5 │ │ smb-enum-shares-445        │445 │ SMB   │ M │        │        │ ~1m    ║
║ 6 │✓│ nmap-version-scan          │All │ Multi │ H │        │ Done   │ Done   ║
║ 7 │ │ whatweb-80                 │ 80 │ HTTP  │ L │        │        │ ~30s   ║
║ 8 │ │ mysql-enum-3306            │3306│ MySQL │ M │        │        │ ~2m    ║
║ 9 │ │ snmp-enum-161              │161 │ SNMP  │ H │ OS,QW  │        │ ~1m    ║
║10 │ │ ldap-enum-389              │389 │ LDAP  │ M │        │        │ ~2m    ║
║───┴──┴────────────────────────────┴────┴───────┴───┴────────┴────────┴────────║
║ Page 1/5 (10 per page) | Total: 47 tasks                                      ║
║ Pending: 39 | In-Progress: 2 | Completed: 6                                   ║
║                                                                                ║
║ (f) Filter Menu | (s) Sort Menu | (g) Group Menu | (/) Search                 ║
║ (1-10) Select Task | (n) Next Page | (p) Prev Page | (b) Back to Dashboard    ║
╠════════════════════════════════════════════════════════════════════════════════╣
║ Legend: ~ = In-Progress | ✓ = Complete | [2/3] = Multi-Stage (current/total) ║
║         QW = Quick Win | OS = OSCP High Priority | H/M/L = High/Medium/Low    ║
╚════════════════════════════════════════════════════════════════════════════════╝
```

### 11.4 Task Workspace (Split View - Before Execution)
```
╔════════════════════════════════════════════════════════════════════════════════╗
║ TASK WORKSPACE: gobuster-80 (Port 80 Directory Enumeration)                   ║
║ Breadcrumb: Dashboard > Task List > gobuster-80                               ║
║ Stages: [✓ Initial] → [● Targeted /admin] → [○ Deep Scan]  | Stage 2/3        ║
╠══════════════════════════════════╦═════════════════════════════════════════════╣
║                                  ║                                             ║
║ TASK DETAILS                     ║ COMMAND OUTPUT                              ║
║                                  ║                                             ║
║ Description:                     ║ [No output yet]                             ║
║   Targeted enumeration of /admin ║                                             ║
║   directory discovered in Stage 1║ Press (1) to execute this stage             ║
║   with common directories list   ║ Press (2) to batch execute all remaining    ║
║                                  ║                                             ║
║ Command:                         ║ ─────────────────────────────────────────   ║
║   gobuster dir \                 ║                                             ║
║     -u http://192.168.45.100 \   ║ Output will stream here in real-time        ║
║        /admin \                  ║ during execution.                           ║
║     -w /usr/share/seclists/\     ║                                             ║
║        Discovery/Web/common.txt\ ║ Features:                                   ║
║     -t 50 \                      ║   • Live streaming                          ║
║     -o /tmp/gobuster-admin.txt   ║   • Auto-scroll to bottom                   ║
║                                  ║   • Auto-detect findings                    ║
║ Flags Explained:                 ║   • Expandable to full-screen (press 'e')   ║
║   -u : Target URL                ║                                             ║
║   -w : Wordlist path             ║                                             ║
║   -t : Thread count (50 threads) ║                                             ║
║   -o : Output file               ║                                             ║
║                                  ║                                             ║
║ Estimated Time: ~2 minutes       ║                                             ║
║ Priority: HIGH                   ║                                             ║
║ Tags: QUICK_WIN                  ║                                             ║
║                                  ║                                             ║
║ Manual Alternative (OSCP exam):  ║                                             ║
║   for word in $(cat common.txt)  ║                                             ║
║   do                             ║                                             ║
║     curl -s http://target/$word  ║                                             ║
║       | grep -q 200 && echo $word║                                             ║
║   done                           ║                                             ║
║                                  ║                                             ║
║ Success Indicators:              ║                                             ║
║   • HTTP 200/301/302 responses   ║                                             ║
║   • New directories discovered   ║                                             ║
║   • Output file created          ║                                             ║
║                                  ║                                             ║
║ (Scrollable ↑↓)                  ║ (Scrollable ↑↓) | (e) Expand               ║
╠══════════════════════════════════╩═════════════════════════════════════════════╣
║ ACTIONS:                                                                       ║
║  1. Execute this stage (Stage 2/3)    2. Execute all remaining (batch mode)   ║
║  3. Skip to Stage 3                   4. Edit command                         ║
║  5. View alternative commands         6. Back to task list                    ║
║                                                                                ║
║ (1-6) Action | (e) Expand Output | (b) Back                                   ║
╚════════════════════════════════════════════════════════════════════════════════╝
```

### 11.5 Task Workspace (Split View - During Execution)
```
╔════════════════════════════════════════════════════════════════════════════════╗
║ TASK WORKSPACE: gobuster-80 (Port 80 Directory Enumeration)                   ║
║ Breadcrumb: Dashboard > Task List > gobuster-80                               ║
║ Stages: [✓ Initial] → [● Targeted /admin] → [○ Deep Scan]  | Stage 2/3        ║
╠══════════════════════════════════╦═════════════════════════════════════════════╣
║                                  ║                                             ║
║ TASK DETAILS                     ║ COMMAND OUTPUT [LIVE]                       ║
║                                  ║                                             ║
║ Description:                     ║ Executing: gobuster dir ...                 ║
║   Targeted enumeration of /admin ║ Status: Running [⣾] 00:01:15 elapsed        ║
║   directory discovered in Stage 1║                                             ║
║   with common directories list   ║ ─────────────────────────────────────────   ║
║                                  ║                                             ║
║ Command:                         ║ Gobuster v3.1.0                             ║
║   gobuster dir \                 ║ by OJ Reeves (@TheColonial)                 ║
║     -u http://192.168.45.100 \   ║                                             ║
║        /admin \                  ║ [+] Url:       http://192.168.45.100/admin  ║
║     -w /usr/share/seclists/\     ║ [+] Wordlist:  common.txt                   ║
║        Discovery/Web/common.txt\ ║ [+] Threads:   50                           ║
║     -t 50 \                      ║ [+] Status:    200,204,301,302,307,401,403  ║
║     -o /tmp/gobuster-admin.txt   ║ [+] User Agent: gobuster/3.1.0              ║
║                                  ║                                             ║
║ Flags Explained:                 ║ [+] Starting...                             ║
║   -u : Target URL                ║ ===============================================║
║   -w : Wordlist path             ║ /admin/backup        (Status: 200) [1234]   ║
║   -t : Thread count (50 threads) ║ /admin/config        (Status: 200) [567]    ║
║   -o : Output file               ║ /admin/logs          (Status: 403) [0]      ║
║                                  ║ /admin/users         (Status: 301) [0]      ║
║ Estimated Time: ~2 minutes       ║ /admin/dashboard     (Status: 200) [4567]   ║
║ Priority: HIGH                   ║ /admin/settings      (Status: 200) [890]    ║
║ Tags: QUICK_WIN                  ║ /admin/reports       (Status: 403) [0]      ║
║                                  ║ /admin/api           (Status: 200) [123]    ║
║ Manual Alternative:              ║ /admin/uploads       (Status: 200) [0]      ║
║   [Collapsed during execution]   ║ /admin/downloads     (Status: 200) [0]      ║
║                                  ║ /admin/temp          (Status: 403) [0]      ║
║ Success Indicators:              ║ ...                                          ║
║   • HTTP 200/301/302 responses   ║                                             ║
║   • New directories discovered   ║ [Auto-scrolling to bottom ↓]                ║
║   • Output file created          ║                                             ║
║                                  ║                                             ║
║ (Scrollable ↑↓)                  ║ (Scrollable ↑↓) | (e) Expand               ║
╠══════════════════════════════════╩═════════════════════════════════════════════╣
║ Execution in progress... Press Ctrl+C to interrupt (checkpoint will be saved)  ║
║                                                                                ║
║ (e) Expand Output | (Ctrl+C) Interrupt                                         ║
╚════════════════════════════════════════════════════════════════════════════════╝
```

### 11.6 Task Workspace (Split View - After Execution)
```
╔════════════════════════════════════════════════════════════════════════════════╗
║ TASK WORKSPACE: gobuster-80 (Port 80 Directory Enumeration)                   ║
║ Breadcrumb: Dashboard > Task List > gobuster-80                               ║
║ Stages: [✓ Initial] → [✓ Targeted /admin] → [○ Deep Scan]  | Stage 2/3        ║
╠══════════════════════════════════╦═════════════════════════════════════════════╣
║                                  ║                                             ║
║ TASK DETAILS                     ║ COMMAND OUTPUT [COMPLETE]                   ║
║                                  ║                                             ║
║ Description:                     ║ ...                                          ║
║   Targeted enumeration of /admin ║ /admin/uploads       (Status: 200) [0]      ║
║   directory discovered in Stage 1║ /admin/downloads     (Status: 200) [0]      ║
║   with common directories list   ║ /admin/temp          (Status: 403) [0]      ║
║                                  ║ /admin/cache         (Status: 200) [456]    ║
║ Command:                         ║ /admin/includes      (Status: 403) [0]      ║
║   gobuster dir \                 ║                                             ║
║     -u http://192.168.45.100 \   ║ ===============================================║
║        /admin \                  ║ [+] Finished                                ║
║     -w /usr/share/seclists/\     ║ ===============================================║
║        Discovery/Web/common.txt\ ║                                             ║
║     -t 50 \                      ║ ─────────────────────────────────────────   ║
║     -o /tmp/gobuster-admin.txt   ║ ✓ Stage 2 Complete                          ║
║                                  ║ Exit Code: 0 (Success)                      ║
║ Execution Summary:               ║ Execution Time: 00:02:03                    ║
║   • Exit Code: 0 (Success)       ║                                             ║
║   • Time: 00:02:03               ║ Auto-Detected Findings:                     ║
║   • Directories found: 8         ║   • Directory: /admin/backup (200 OK)       ║
║   • Forbidden: 4                 ║   • Directory: /admin/config (200 OK)       ║
║                                  ║   • Directory: /admin/dashboard (200 OK)    ║
║ Next Steps:                      ║   • Directory: /admin/settings (200 OK)     ║
║   1. Continue to Stage 3         ║   • Directory: /admin/api (200 OK)          ║
║   2. Generate follow-ups (8 dirs)║   • Directory: /admin/uploads (200 OK)      ║
║   3. Mark complete, return       ║   • Directory: /admin/downloads (200 OK)    ║
║                                  ║   • Directory: /admin/cache (200 OK)        ║
║ Success Indicators: ✓ Met        ║                                             ║
║   ✓ HTTP 200/301/302 responses   ║ Recommendations:                            ║
║   ✓ New directories discovered   ║   → Investigate /admin/backup (potential    ║
║   ✓ Output file created          ║     sensitive files)                        ║
║                                  ║   → Check /admin/config (config exposure)   ║
║ (Scrollable ↑↓)                  ║   → Explore /admin/api (API endpoints)      ║
║                                  ║                                             ║
║                                  ║ (Scrollable ↑↓) | (e) Expand               ║
╠══════════════════════════════════╩═════════════════════════════════════════════╣
║ NEXT STEPS:                                                                    ║
║  1. Continue to Stage 3 (Deep Scan)   2. Generate follow-ups for 8 directories║
║  3. Mark complete and return to list  4. Add custom finding                   ║
║  5. Save output to custom location    6. View full output                     ║
║  7. Back to task list                                                          ║
║                                                                                ║
║ (1-7) Action | (e) Expand Output | (b) Back                                   ║
╚════════════════════════════════════════════════════════════════════════════════╝
```

### 11.7 Task Workspace (Expanded Output - Full Screen)
```
╔════════════════════════════════════════════════════════════════════════════════╗
║ COMMAND OUTPUT (Expanded) - gobuster-80 Stage 2/3                             ║
║ Press (c) to collapse back to split view | (/) Search | (s) Save              ║
╠════════════════════════════════════════════════════════════════════════════════╣
║                                                                                ║
║ Executing: gobuster dir -u http://192.168.45.100/admin \                      ║
║   -w /usr/share/seclists/Discovery/Web/common.txt -t 50 \                     ║
║   -o /tmp/gobuster-admin.txt                                                   ║
║                                                                                ║
║ Status: Running [⣾] 00:01:45 elapsed                                           ║
║                                                                                ║
║ ──────────────────────────────────────────────────────────────────────────────║
║                                                                                ║
║ Gobuster v3.1.0                                                                ║
║ by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)                 ║
║                                                                                ║
║ [+] Url:            http://192.168.45.100/admin                                ║
║ [+] Method:         GET                                                        ║
║ [+] Threads:        50                                                         ║
║ [+] Wordlist:       /usr/share/seclists/Discovery/Web/common.txt              ║
║ [+] Negative Status codes:   404                                               ║
║ [+] User Agent:     gobuster/3.1.0                                             ║
║ [+] Extensions:     php,html,txt                                               ║
║ [+] Timeout:        10s                                                        ║
║                                                                                ║
║ [+] Starting gobuster in directory enumeration mode                            ║
║ ===============================================================================║
║                                                                                ║
║ /admin/backup           (Status: 200) [Size: 1234]                            ║
║ /admin/config           (Status: 200) [Size: 567]                             ║
║ /admin/logs             (Status: 403) [Size: 0]                               ║
║ /admin/users            (Status: 301) [Size: 0] → /admin/users/               ║
║ /admin/dashboard        (Status: 200) [Size: 4567]                            ║
║ /admin/settings         (Status: 200) [Size: 890]                             ║
║ /admin/reports          (Status: 403) [Size: 0]                               ║
║ /admin/api              (Status: 200) [Size: 123]                             ║
║ /admin/uploads          (Status: 200) [Size: 0]                               ║
║ /admin/downloads        (Status: 200) [Size: 0]                               ║
║ /admin/temp             (Status: 403) [Size: 0]                               ║
║ /admin/cache            (Status: 200) [Size: 456]                             ║
║ /admin/includes         (Status: 403) [Size: 0]                               ║
║ ...                                                                            ║
║                                                                                ║
║ Progress: 1024/4096 lines (25%)                                               ║
║                                                                                ║
║ (Scroll: ↑↓ PgUp/PgDn Home/End | Search: /)                                   ║
║                                                                                ║
╠════════════════════════════════════════════════════════════════════════════════╣
║ (c) Collapse to split view | (s) Save output | (/) Search | (b) Back          ║
╚════════════════════════════════════════════════════════════════════════════════╝
```

---

## 12. Key Design Decisions Summary

### ✓ Approved Design Choices

1. **Keep Config Panel** - Works perfectly, users need it for LHOST/LPORT/WORDLIST setup

2. **Option A Navigation** - Dashboard hub with drill-down (not task-list-centric)
   - Dashboard = central hub
   - Drill down to specialized panels
   - Always return to Dashboard
   - Clear breadcrumb navigation

3. **Task Workspace = Multi-Panel View** ⭐ NEW
   - Split view: Task details (40%) + Command output (60%)
   - Output panel expandable to full-screen (press 'e')
   - Live output streaming during execution
   - Keep details visible while reviewing output

4. **Multi-Stage Task Architecture**
   - **Dynamic generation** - Results create new stages (gobuster finds /admin → creates admin-scan)
   - **Batch execution option** - Run all stages automatically or manual step-through
   - **Checkpoint persistence** - Crash recovery, resume from any stage

5. **Overlay Pattern** - Help/Status/Tree don't change state, just temporary views

6. **Progressive Enhancement** - Build incrementally, test each phase

7. **Rich Live Context** - Stop for input, resume for display (no terminal flooding)

8. **Checkpoint System** - Save state after every stage for crash recovery

### Navigation Breadcrumb Format
```
Dashboard
Dashboard > Task List
Dashboard > Task List > gobuster-80 (Stage 2/3)
Dashboard > Task List > gobuster-80 (Stage 2/3) [Output Expanded]
Dashboard > Findings
```

### Panel Priority Order (Implementation)
```
Phase 1: Config Panel ✓ + Basic Dashboard
Phase 2: Dashboard + Overlays (Status, Help, Tree)
Phase 3: Task List Panel (browse, filter, sort)
Phase 4: Task Workspace (split view + stage navigator)
Phase 5: Execution + Checkpoints (live streaming, dynamic generation)
Phase 6: Findings Panel (browse discoveries)
Phase 7: Forms (finding, cred, import entry)
Phase 8: Polish + Edge Cases
```

---

## Implementation Notes

### File Structure
```
track/interactive/
├── tui_session_v3.py          # Main TUI controller (refactored)
├── panels/
│   ├── config_panel.py         ✓ Working
│   ├── dashboard_panel.py      # Phase 2
│   ├── task_list_panel.py      # Phase 3
│   ├── task_workspace.py       # Phase 4 (multi-panel)
│   ├── findings_panel.py       # Phase 6
│   └── form_panels.py          # Phase 7
├── overlays/
│   ├── status_overlay.py       # Phase 2
│   ├── help_overlay.py         # Phase 2
│   └── tree_overlay.py         # Phase 2
├── components/
│   ├── stage_navigator.py      # Phase 4
│   ├── output_panel.py         # Phase 4 (expandable)
│   ├── filter_bar.py           # Phase 3
│   └── breadcrumb.py           # Phase 2
└── state/
    ├── navigation_stack.py     # State management
    ├── checkpoint_manager.py   # Phase 5
    └── execution_manager.py    # Phase 5
```

### Next Steps
1. Review this document with user
2. Get approval on multi-panel Task Workspace design
3. Begin Phase 2 implementation (Dashboard + Overlays)
4. Iterative development with testing at each phase

---

**Document Status**: Draft for Review
**Last Updated**: 2025-10-09
**Authors**: Claude Code + User
**Version**: 1.0
