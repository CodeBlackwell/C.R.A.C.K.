# CRACK Video Series - Production Checklist

> Loom video outlines for showcasing individual CRACK toolkit components

---

## Pre-Production Setup

### Environment Checklist
- [ ] Neo4j running (`sudo systemctl start neo4j`)
- [ ] CRACK database populated (`crack reference --stats` shows 795+ commands)
- [ ] Terminal font size: 16-18pt
- [ ] Screen resolution: 1920x1080 minimum
- [ ] Clear desktop/notifications
- [ ] B.R.E.A.C.H. and Crackpedia tested and launching

### Recording Tools
- [ ] Loom installed and logged in
- [ ] Microphone tested
- [ ] Sample recordings checked for audio quality

---

## Video 1: PRISM (Credential Parser)

**Duration:** 8-12 min | **Audience:** Post-exploitation phase

### Prep Materials
- [ ] Sample mimikatz output file (messy, realistic)
- [ ] Sample secretsdump output
- [ ] Sample GPP Groups.xml with cpassword
- [ ] Sample Kerberoast output

### Recording Checklist

#### Hook (30 sec)
- [ ] Show raw mimikatz output (wall of text)
- [ ] Rhetorical: "Where are the actual passwords?"

#### Section 1: The Problem (1 min)
- [ ] Scroll through raw output
- [ ] Highlight how hard it is to find cleartext
- [ ] Mention time wasted during exams

#### Section 2: PRISM in Action (3 min)
- [ ] Run: `crack prism mimikatz.txt`
- [ ] Show color-coded tables appearing
- [ ] Explain: Yellow = cleartext (HIGH VALUE)
- [ ] Explain: Blue = NTLM hashes
- [ ] Point out stats summary at bottom

#### Section 3: Parser Showcase (3 min)
- [ ] Mimikatz: `crack prism mimikatz.txt`
- [ ] Secretsdump: `crack prism secretsdump.txt`
- [ ] GPP: `crack prism Groups.xml` (show auto-decrypt!)
- [ ] Kerberoast: `crack prism spns.txt`

#### Section 4: Output Formats (1 min)
- [ ] JSON: `crack prism dump.txt -f json`
- [ ] Pipe demo: `crack prism dump.txt -f json | jq '.credentials[0]'`
- [ ] Markdown: `crack prism dump.txt -f markdown`

#### Section 5: Neo4j Integration (2 min)
- [ ] Show credentials stored in graph
- [ ] Run query: "Show reused passwords across hosts"
- [ ] Demonstrate target linking

#### Section 6: Multi-System Correlation Demo (2 min)
- [ ] Parse 3 different sources
- [ ] Show Neo4j query finding same hash on multiple machines
- [ ] "Lateral movement targets identified"

### Key Shots to Capture
- [ ] Before/after split screen (raw vs parsed)
- [ ] GPP auto-decryption moment (zoom)
- [ ] Neo4j graph showing credential relationships

### Post-Recording
- [ ] Trim dead air
- [ ] Add chapter markers
- [ ] Export and upload

---

## Video 2: BloodTrail (AD Attack Paths)

**Duration:** 15-20 min | **Audience:** Active Directory pentesting

### Prep Materials
- [ ] Lab AD environment accessible (or recorded outputs)
- [ ] Sample SharpHound ZIP file
- [ ] Pre-populated Neo4j with BloodHound data
- [ ] Known AS-REP roastable user in lab

### Recording Checklist

#### Hook (30 sec)
- [ ] Show BloodHound GUI briefly
- [ ] "Great for visualization, but what command do I actually run?"

#### Section 1: BloodHound Context (1 min)
- [ ] Quick BloodHound recap (what it does)
- [ ] Gap: visualization vs actionable commands
- [ ] BloodTrail bridges the gap

#### Section 2: Anonymous Enumeration (3 min)
- [ ] Run: `crack bloodtrail 10.10.10.161`
- [ ] Show auto-discovery of AS-REP users
- [ ] Show domain info extraction
- [ ] Highlight: No credentials needed!
- [ ] Show output files generated

#### Section 3: Credential Pipeline (4 min)
- [ ] Run: `crack bloodtrail <IP> --creds user:pass`
- [ ] Narrate each stage:
  - [ ] Validates credentials
  - [ ] Collects SharpHound data
  - [ ] Imports to Neo4j
  - [ ] Marks user as pwned
- [ ] Show automation saves 10+ manual steps

#### Section 4: Attack Path Queries (4 min)
- [ ] Run: `crack bloodtrail --list-queries`
- [ ] Show 63+ query templates
- [ ] Run: `crack bloodtrail --run-query quick-asrep-roastable`
- [ ] Show Cypher query + results
- [ ] Explain color-coded attack paths

#### Section 5: Pwned User Tracking (3 min)
- [ ] Run: `crack bloodtrail --pwn 'USER@DOMAIN' --cred-type password --cred-value 'secret'`
- [ ] Show Neo4j storing compromised user
- [ ] Run: `crack bloodtrail --pwned-user 'USER@DOMAIN'`
- [ ] Show access paths: "What can this user touch?"

#### Section 6: Command Generation (2 min)
- [ ] Run: `crack bloodtrail --post-exploit`
- [ ] Show ready-to-run commands:
  - [ ] DCSync commands
  - [ ] Mimikatz commands
  - [ ] Token theft workflows
- [ ] "No more googling syntax"

#### Section 7: Full Chain Demo (3 min)
- [ ] Walk through: Anonymous -> AS-REP -> Crack -> Creds -> DA
- [ ] Show each step tracked in Neo4j
- [ ] Emphasize methodology over memorization

### Key Shots to Capture
- [ ] Anonymous enumeration discovering AS-REP users
- [ ] Credential pipeline automation (all stages)
- [ ] Neo4j graph showing attack path to Domain Admin
- [ ] Post-exploit command generation output

### Post-Recording
- [ ] Trim dead air
- [ ] Add chapter markers
- [ ] Export and upload

---

## Video 3: Crackpedia (Command Encyclopedia)

**Duration:** 10-12 min | **Audience:** Learning/reference

### Prep Materials
- [ ] Neo4j running with full command database
- [ ] Crackpedia launching without errors
- [ ] Test all 4 views work

### Recording Checklist

#### Hook (30 sec)
- [ ] State: "734 commands. Every flag explained. Visual relationships."
- [ ] Show Crackpedia splash/launch

#### Section 1: Launch (30 sec)
- [ ] Run: `crackpedia`
- [ ] Show 3-panel layout loading
- [ ] Point out Neo4j connection badge (green)

#### Section 2: Command Search (2 min)
- [ ] Type "sqli" in search box
- [ ] Show real-time filtering
- [ ] Use arrow keys to navigate results
- [ ] Point out OSCP relevance badges
- [ ] Show category accordion

#### Section 3: Relationship Graph (3 min)
- [ ] Select "nmap" command
- [ ] Explain graph colors:
  - [ ] Yellow = alternatives (masscan, etc.)
  - [ ] Red = prerequisites
  - [ ] Green = next steps
- [ ] Click a yellow node to navigate
- [ ] Show graph updating
- [ ] "If nmap fails, try these alternatives"

#### Section 4: Command Details (2 min)
- [ ] Show right panel details view
- [ ] Full syntax with placeholders
- [ ] Flag explanations (every flag!)
- [ ] Output patterns (success/failure indicators)
- [ ] Tags (LINUX, WINDOWS, OSCP)

#### Section 5: Attack Chains View (2 min)
- [ ] Click Chains tab
- [ ] Search "kerberoast"
- [ ] Show visual DAG of steps
- [ ] Click a step node
- [ ] Show time estimates per step

#### Section 6: Cheatsheets (1 min)
- [ ] Click Cheatsheets tab
- [ ] Browse educational collections
- [ ] Show grouping by topic
- [ ] Click to expand commands

#### Section 7: Keyboard Shortcuts (30 sec)
- [ ] Demo: Arrow key navigation
- [ ] Demo: Ctrl+Shift+C (Commands view)
- [ ] Demo: Ctrl+Shift+X (Chains view)

### Key Shots to Capture
- [ ] 3-panel layout overview (wide shot)
- [ ] Relationship graph expanding as you click
- [ ] Attack chain DAG visualization
- [ ] Flag explanations panel (zoom)

### Post-Recording
- [ ] Trim dead air
- [ ] Add chapter markers
- [ ] Export and upload

---

## Video 4: B.R.E.A.C.H. (Pentesting Workspace)

**Duration:** 12-15 min | **Audience:** Exam/engagement workflow

### Prep Materials
- [ ] Neo4j running
- [ ] Sample engagement with targets pre-populated
- [ ] Sample credentials in vault (or trigger PRISM during recording)
- [ ] Sample loot files

### Recording Checklist

#### Hook (30 sec)
- [ ] "Terminal multiplexer + credential vault + target tracking. One window."
- [ ] Show B.R.E.A.C.H. interface

#### Section 1: Launch & Layout (1 min)
- [ ] Run: `cd breach && ./start.sh`
- [ ] Show three panels:
  - [ ] Left: Targets
  - [ ] Center: Terminals
  - [ ] Right: Context
- [ ] Point out engagement selector in header

#### Section 2: Terminal Multiplexer (3 min)
- [ ] Create new tab (+ button)
- [ ] Create different session types:
  - [ ] Shell session
  - [ ] Scan session
  - [ ] Listener session
- [ ] Show status indicators on tabs
- [ ] Demo: Ctrl+W to close tab
- [ ] Mention session persistence on restart

#### Section 3: Target Sidebar (2 min)
- [ ] Add new target (IP + hostname form)
- [ ] Show status dots (up/down/compromised)
- [ ] Expand target to see services
- [ ] Show nmap quick menu:
  - [ ] Port Scan templates
  - [ ] Service Enum templates
  - [ ] Vuln Scan templates
- [ ] Trigger quick ping

#### Section 4: Credential Vault (3 min)
- [ ] Show credentials panel (right sidebar)
- [ ] Explain: Auto-populated from PRISM
- [ ] Show domain grouping (CORP\admin vs Local)
- [ ] Demo "Use Credential" menu:
  - [ ] SSH Access templates
  - [ ] SMB lateral movement
  - [ ] Kerberos attacks
- [ ] Click template -> New terminal with command

#### Section 5: Loot Tracking (2 min)
- [ ] Show loot panel
- [ ] Browse captured files (flags, keys, configs)
- [ ] Show pattern detection badges
- [ ] Click to preview in modal
- [ ] Demo: Extract hash to credential vault

#### Section 6: Engagement Switching (1 min)
- [ ] Click engagement selector dropdown
- [ ] Show engagement list with status badges
- [ ] Switch to different engagement
- [ ] Show data isolation (different targets/creds)

#### Section 7: Workflow Demo (3 min)
- [ ] End-to-end: Add target -> Nmap -> Discover creds
- [ ] Show creds appearing in vault automatically
- [ ] Use credential -> New shell
- [ ] Emphasize integrated flow

### Key Shots to Capture
- [ ] Terminal tabs with status indicators
- [ ] Credential vault "Use" menu expansion (zoom)
- [ ] Nmap quick menu categories
- [ ] Loot pattern detection badges

### Post-Recording
- [ ] Trim dead air
- [ ] Add chapter markers
- [ ] Export and upload

---

## Video 5: Session Manager (Reverse Shells)

**Duration:** 12-15 min | **Audience:** Shell handling

### Prep Materials
- [ ] Target VM for catching shells
- [ ] Exploit ready to trigger reverse shell
- [ ] HTTP server for beacon demo (optional)
- [ ] SSH access to pivot host (for tunnel demo)

### Recording Checklist

#### Hook (30 sec)
- [ ] "Catch shells. Upgrade to TTY. Pivot through networks. One toolkit."

#### Section 1: Listener Types (2 min)
- [ ] TCP: `crack session start tcp --port 4444`
- [ ] Explain HTTP Beacon (firewall bypass)
- [ ] Mention DNS Tunnel (stealth)
- [ ] Mention ICMP (last resort)

#### Section 2: Catch & List (2 min)
- [ ] Trigger exploit on target
- [ ] Show shell connecting
- [ ] Run: `crack session list`
- [ ] Show: ID, target, status, shell type

#### Section 3: Shell Upgrade (3 min)
- [ ] Run: `crack session upgrade <ID> --method auto`
- [ ] Narrate: Detects Python -> spawns PTY
- [ ] Show before: No arrow keys, janky
- [ ] Show after: Full TTY, arrows work, tab completion
- [ ] Mention fallback methods (script, socat)

#### Section 4: Stabilization (1 min)
- [ ] Run: `crack session stabilize <ID>`
- [ ] Explain: Terminal size, TERM variable
- [ ] Demo: Ctrl+C now works properly

#### Section 5: HTTP Beacon Workflow (3 min)
- [ ] Run: `crack session beacon-gen bash http://LHOST:8080 -o beacon.sh`
- [ ] Show beacon script
- [ ] Simulate: Upload and execute on target
- [ ] Run: `crack session beacon-send <ID> "whoami"`
- [ ] Run: `crack session beacon-poll <ID>`
- [ ] Show command results returning
- [ ] Mention: Upgrade to TCP when ready

#### Section 6: Pivoting (3 min)
- [ ] Run: `crack session tunnel-create <ID> --type ssh-dynamic --socks-port 1080`
- [ ] Show tunnel created
- [ ] Run: `proxychains4 nmap -sT 192.168.1.0/24`
- [ ] Show scanning internal network
- [ ] Run: `crack session tunnel-list`

#### Section 7: OSCP Workflow (2 min)
- [ ] Recap full flow:
  - [ ] Start listener
  - [ ] Exploit target
  - [ ] Upgrade shell
  - [ ] Enumerate
  - [ ] Privesc
- [ ] Emphasize all sessions tracked and persistent

### Key Shots to Capture
- [ ] Shell upgrade transformation (before/after split)
- [ ] Beacon polling showing command results
- [ ] SOCKS tunnel with proxychains scan
- [ ] Session list with status indicators

### Post-Recording
- [ ] Trim dead air
- [ ] Add chapter markers
- [ ] Export and upload

---

## Video 6: Reference System (Command Lookup)

**Duration:** 6-8 min | **Audience:** Quick reference

### Prep Materials
- [ ] CRACK installed and working
- [ ] Config variables set for demo

### Recording Checklist

#### Hook (30 sec)
- [ ] "795 commands. Zero googling. Just `crack reference`."

#### Section 1: Basic Search (2 min)
- [ ] Run: `crack reference nmap`
- [ ] Show ranked results
- [ ] Point out: name, category, OSCP relevance
- [ ] Try: `crack reference sqli`

#### Section 2: Command Details (2 min)
- [ ] Run: `crack reference nmap-service-scan`
- [ ] Show full template with placeholders
- [ ] Show flag explanations
- [ ] Show alternatives + prerequisites
- [ ] Show next steps

#### Section 3: Fill Command (2 min)
- [ ] Run: `crack fill nmap-service-scan`
- [ ] Show interactive prompts
- [ ] Demonstrate config defaults auto-filling
- [ ] Show copy-paste ready output

#### Section 4: Cheatsheets (1 min)
- [ ] Run: `crack cheatsheets linux-privesc`
- [ ] Show scenario-based guidance
- [ ] Show sections with grouped commands

#### Section 5: Config Variables (1 min)
- [ ] Run: `crack config set TARGET 10.10.10.5`
- [ ] Explain auto-fill behavior
- [ ] Run: `crack config auto` (detect LHOST)
- [ ] Show variables now set

### Key Shots to Capture
- [ ] Search results with relevance badges
- [ ] Interactive fill prompts (zoom)
- [ ] Cheatsheet scenario display

### Post-Recording
- [ ] Trim dead air
- [ ] Add chapter markers
- [ ] Export and upload

---

## Video 7: Engagement Tracking

**Duration:** 8-10 min | **Audience:** Organization/documentation

### Prep Materials
- [ ] Neo4j running
- [ ] Clean engagement state (or create fresh)
- [ ] Sample targets to add

### Recording Checklist

#### Hook (30 sec)
- [ ] "Every target, every finding, every credential. All linked in a graph."

#### Section 1: Create Engagement (1 min)
- [ ] Run: `crack engagement create "Lab Pentest"`
- [ ] Run: `crack engagement activate <id>`
- [ ] Run: `crack engagement status`
- [ ] Show engagement info

#### Section 2: Target Management (2 min)
- [ ] Run: `crack target add 10.10.10.5 --hostname dc01`
- [ ] Run: `crack target add 10.10.10.10 --hostname web01`
- [ ] Run: `crack target list`
- [ ] Mention: Auto-populated by port scanner

#### Section 3: Service Discovery (2 min)
- [ ] Run: `crack target services <id>`
- [ ] Run: `crack target service-add <id> 445 --name smb`
- [ ] Show: port, protocol, version
- [ ] Mention: Auto-populated by recon tools

#### Section 4: Finding Tracking (2 min)
- [ ] Run: `crack finding add "SQL Injection" --severity critical`
- [ ] Run: `crack finding link <id> --target <target_id>`
- [ ] Run: `crack finding list`
- [ ] Show vulnerability management

#### Section 5: Neo4j Graph (2 min)
- [ ] Open Neo4j Browser
- [ ] Show graph model:
  - [ ] Engagement -> Targets -> Services
  - [ ] Credentials -> Services
  - [ ] Findings -> Targets
- [ ] Run sample Cypher query

#### Section 6: Tool Integration (1 min)
- [ ] Explain: Port scanner auto-logs services
- [ ] Explain: PRISM auto-logs credentials
- [ ] Explain: Session manager logs shells
- [ ] "All automatic, all linked"

### Key Shots to Capture
- [ ] Engagement status overview
- [ ] Neo4j graph visualization (wide shot)
- [ ] Tool auto-logging demonstration

### Post-Recording
- [ ] Trim dead air
- [ ] Add chapter markers
- [ ] Export and upload

---

## Thumbnail Concepts

| Video | Visual Concept | Text Overlay |
|-------|---------------|--------------|
| PRISM | Raw text -> Clean table (split) | "Parse Everything" |
| BloodTrail | AD graph with red attack path | "Find the Path" |
| Crackpedia | 3-panel GUI with glowing graph | "734 Commands" |
| B.R.E.A.C.H. | Multi-terminal dark workspace | "One Window" |
| Sessions | Shell upgrade animation | "Upgrade Shells" |
| Reference | Search bar -> Results | "Zero Googling" |
| Engagement | Neo4j graph nodes | "Track Everything" |

---

## Publishing Checklist

### Per Video
- [ ] Title optimized for search
- [ ] Description with timestamps
- [ ] Relevant tags added
- [ ] Thumbnail uploaded
- [ ] Links to CRACK repo in description
- [ ] Cross-link to other videos in series

### Series Playlist
- [ ] Create "CRACK Toolkit" playlist
- [ ] Order videos logically
- [ ] Add playlist description

---

## Notes & Ideas

_Space for additional thoughts during production:_

```
-
-
-
```
