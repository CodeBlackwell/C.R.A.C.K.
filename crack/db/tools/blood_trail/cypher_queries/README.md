# BloodHound Cypher Query Library

A curated collection of 63 Cypher queries for Active Directory attack path discovery using BloodHound data in Neo4j.

## Table of Contents

- [Cypher Fundamentals](#cypher-fundamentals)
- [BloodHound Data Model](#bloodhound-data-model)
- [Query Categories](#query-categories)
  - [Quick Wins](#1-quick-wins-10-queries)
  - [Lateral Movement](#2-lateral-movement-12-queries)
  - [Privilege Escalation](#3-privilege-escalation-15-queries)
  - [Attack Chains](#4-attack-chains-8-queries)
  - [Owned Principal](#5-owned-principal-10-queries)
  - [Operational](#6-operational-8-queries)
- [Learning Path](#learning-path)
- [Query Index](#complete-query-index)

---

## Cypher Fundamentals

Cypher is Neo4j's graph query language. Understanding these patterns is essential for BloodHound analysis.

### Basic Syntax

```cypher
-- Nodes are wrapped in parentheses
(u:User)                    -- A node with label "User", aliased as "u"
(c:Computer {name:'DC1'})   -- A node with a property filter

-- Relationships use square brackets and arrows
-[:AdminTo]->               -- Outgoing relationship of type "AdminTo"
<-[:HasSession]-            -- Incoming relationship
-[r:MemberOf*1..5]->        -- Variable-length path (1-5 hops), aliased as "r"

-- Full pattern example
(u:User)-[:AdminTo]->(c:Computer)
-- "Find users with AdminTo relationship to computers"
```

### Key Clauses

| Clause | Purpose | Example |
|--------|---------|---------|
| `MATCH` | Find patterns in graph | `MATCH (u:User)-[:AdminTo]->(c:Computer)` |
| `WHERE` | Filter results | `WHERE u.enabled = true` |
| `RETURN` | Specify output | `RETURN u.name, c.name` |
| `WITH` | Chain operations | `WITH u, count(c) AS cnt WHERE cnt > 5` |
| `ORDER BY` | Sort results | `ORDER BY cnt DESC` |
| `LIMIT` | Restrict rows | `LIMIT 25` |
| `OPTIONAL MATCH` | Left outer join | `OPTIONAL MATCH (u)-[:MemberOf]->(g)` |
| `COLLECT` | Aggregate into list | `collect(c.name) AS computers` |
| `DISTINCT` | Remove duplicates | `RETURN DISTINCT u.name` |

### Common Operators

```cypher
-- Property access
u.name                      -- Get property "name" from node u
u.admincount = true         -- Boolean comparison

-- Pattern matching
u.name =~ '(?i).*ADMIN.*'   -- Case-insensitive regex
u.name STARTS WITH 'SVC_'   -- String prefix match
u.name CONTAINS 'admin'     -- Substring match

-- NULL checks
WHERE u.description IS NOT NULL
WHERE u.lastlogon > 0

-- Multiple relationship types
-[:AdminTo|CanRDP|CanPSRemote]->   -- Match any of these types
```

### Path Functions

```cypher
-- Shortest path between nodes
shortestPath((a)-[*1..10]->(b))

-- All shortest paths
allShortestPaths((a)-[*1..6]->(b))

-- Path introspection
length(p)                   -- Number of hops
nodes(p)                    -- List of nodes in path
relationships(p)            -- List of relationships
[n IN nodes(p) | n.name]    -- Extract property from each node
```

---

## BloodHound Data Model

### Node Types (Labels)

| Label | Description | Key Properties |
|-------|-------------|----------------|
| `User` | AD user account | `name`, `enabled`, `admincount`, `hasspn`, `dontreqpreauth` |
| `Computer` | AD computer | `name`, `operatingsystem`, `enabled`, `unconstraineddelegation` |
| `Group` | AD group | `name`, `admincount`, `description` |
| `Domain` | AD domain | `name`, `functionallevel` |
| `GPO` | Group Policy Object | `name`, `gpcpath` |
| `OU` | Organizational Unit | `name`, `description` |

### Critical User Properties

```cypher
u.enabled           -- Account is active (not disabled)
u.admincount        -- Protected by AdminSDHolder (privileged)
u.hasspn            -- Has Service Principal Name (Kerberoastable)
u.dontreqpreauth    -- Pre-auth disabled (AS-REP roastable)
u.pwdneverexpires   -- Password never expires
u.pwdlastset        -- Epoch timestamp of last password change
u.lastlogon         -- Epoch timestamp of last login
u.owned             -- Marked as compromised in BloodHound
u.highvalue         -- Marked as high-value target
```

### Relationship Types (Edges)

#### Lateral Movement Edges
| Edge | Meaning | Attack |
|------|---------|--------|
| `AdminTo` | Local admin on computer | PSExec, WMI, SMB |
| `CanRDP` | RDP access | Remote Desktop |
| `CanPSRemote` | WinRM access | Evil-WinRM, Enter-PSSession |
| `ExecuteDCOM` | DCOM execution rights | impacket-dcomexec |
| `HasSession` | User logged into computer | Credential harvesting target |

#### ACL Abuse Edges
| Edge | Meaning | Attack |
|------|---------|--------|
| `GenericAll` | Full control | Reset password, modify attributes |
| `GenericWrite` | Write properties | Set SPN for Kerberoasting |
| `WriteDacl` | Modify permissions | Grant yourself GenericAll |
| `WriteOwner` | Change ownership | Take ownership, then WriteDacl |
| `ForceChangePassword` | Reset password | Change without knowing current |
| `AddMember` | Add to group | Add self to privileged group |
| `Owns` | Object owner | Full control rights |
| `AddKeyCredentialLink` | Shadow credentials | Certificate-based auth |
| `AllExtendedRights` | All extended rights | Includes ForceChangePassword |
| `ReadLAPSPassword` | Read LAPS password | Local admin credential access |

#### Privilege Escalation Edges
| Edge | Meaning | Attack |
|------|---------|--------|
| `GetChanges` | Replication rights | DCSync (with GetChangesAll) |
| `GetChangesAll` | Full replication | DCSync |
| `MemberOf` | Group membership | Inherited privileges |
| `TrustedBy` | Domain trust | Cross-domain attacks |

---

## Query Categories

### 1. Quick Wins (10 queries)

**Purpose**: Fast compromise opportunities requiring minimal effort.

**File**: `quick_wins.json`

| ID | Name | What It Finds | Why It Matters |
|----|------|---------------|----------------|
| `quick-asrep-roastable` | AS-REP Roastable Users | Users with pre-auth disabled | Offline password cracking without auth |
| `quick-kerberoastable` | Kerberoastable Service Accounts | Users with SPNs | Request TGS, crack offline |
| `quick-kerberoastable-privileged` | High-Value Kerberoastable | Privileged users with SPNs | Priority cracking targets |
| `quick-unconstrained-delegation` | Unconstrained Delegation | Computers that store TGTs | Capture delegated credentials |
| `quick-constrained-delegation` | Constrained Delegation | S4U2Self/Proxy abuse | Impersonate any user to target |
| `quick-password-in-description` | Passwords in Description | Credentials in AD fields | Free passwords |
| `quick-password-never-expires` | Non-Expiring Passwords | Stale service accounts | Often weak passwords |
| `quick-never-logged-in` | Never Logged In | Unused accounts | May have default credentials |
| `quick-laps-gaps` | Computers Without LAPS | No local admin rotation | Password reuse potential |
| `quick-prewin2000-accounts` | Pre-Win2000 Compatibility | Legacy access groups | Anonymous enumeration |

**Example - AS-REP Roasting Query Explained**:

```cypher
MATCH (u:User)                    -- Find all User nodes
WHERE u.dontreqpreauth = true     -- Pre-authentication disabled
  AND u.enabled = true            -- Account is active
RETURN u.name AS User,            -- Username
       u.admincount AS IsPrivileged,  -- Is this a protected account?
       u.description AS Description   -- May contain password hints
ORDER BY u.admincount DESC        -- Show privileged accounts first
```

**Attack Flow**:
1. Run query to find AS-REP roastable users
2. Use `GetNPUsers.py` to request AS-REP hashes (no auth needed)
3. Crack hashes offline with hashcat/john

---

### 2. Lateral Movement (12 queries)

**Purpose**: Find paths to move between systems.

**File**: `lateral_movement.json`

| ID | Name | What It Finds | Next Step |
|----|------|---------------|-----------|
| `lateral-adminto-nonpriv` | Non-DA Users with Local Admin | Non-privileged users with admin access | Check sessions on those computers |
| `lateral-all-admins-per-computer` | All Local Admins per Computer | Every admin path to each system | Prioritize targets |
| `lateral-psremote-targets` | PSRemote Access | Evil-WinRM targets | WinRM lateral movement |
| `lateral-rdp-targets` | RDP Access Targets | Remote Desktop targets | RDP for interactive access |
| `lateral-dcom-targets` | DCOM Execution Rights | DCOM abuse targets | impacket-dcomexec |
| `lateral-sessions-on-computer` | Sessions on Computer | Who's logged in where | Credential harvesting |
| `lateral-user-access-all` | All Access for User | Complete access map | Plan attack path |
| `lateral-users-to-computer` | Users Who Can Access Computer | All paths to specific target | Alternative routes |
| `lateral-domain-users-admin` | Domain Users as Local Admin | Major misconfiguration | Any user can compromise |
| `lateral-multi-path-computers` | Multiple Admin Paths | Computers with many admins | More options |
| `lateral-da-sessions-workstations` | DA Sessions on Workstations | Privileged sessions to harvest | Mimikatz targets |
| `lateral-cross-trust` | Cross-Trust Lateral Movement | Foreign domain access | Trust abuse |

**Example - Finding Credential Harvest Targets**:

```cypher
MATCH (c:Computer)<-[:HasSession]-(u:User)  -- Computers with user sessions
WHERE NOT c.name STARTS WITH 'DC'           -- Exclude Domain Controllers
  AND u.admincount = true                   -- User is privileged
RETURN c.name AS Workstation,               -- Target computer
       collect(u.name) AS PrivilegedSessions,  -- Who's logged in
       count(u) AS SessionCount             -- How many privileged sessions
ORDER BY SessionCount DESC                  -- Most valuable targets first
```

**Pattern Recognition**:
- `HasSession` edge points FROM computer TO user (direction matters!)
- `admincount = true` indicates protected/privileged accounts
- Workstations (not DCs) are easier to compromise

---

### 3. Privilege Escalation (15 queries)

**Purpose**: Find ACL abuse paths to Domain Admin.

**File**: `privilege_escalation.json`

| ID | Name | Attack Type | MITRE |
|----|------|-------------|-------|
| `privesc-dcsync-rights` | DCSync Rights | Replication abuse | T1003.006 |
| `privesc-genericall-highvalue` | GenericAll on High-Value | Full control abuse | T1222.001 |
| `privesc-shadow-admins` | Shadow Admins | Hidden privilege paths | T1098 |
| `privesc-writedacl` | WriteDacl Abuse | Grant yourself rights | T1222.001 |
| `privesc-writeowner` | WriteOwner Abuse | Take ownership | T1222.001 |
| `privesc-shadow-credentials` | Shadow Credentials | Certificate auth | T1098.001 |
| `privesc-force-change-password` | Password Reset Rights | Credential theft | T1098 |
| `privesc-addmember` | AddMember to Groups | Group manipulation | T1098.002 |
| `privesc-owns` | Ownership Relationships | Owner rights | T1222.001 |
| `privesc-gpo-abuse` | GPO Abuse Paths | Policy manipulation | T1484.001 |
| `privesc-ou-control` | OU Control | Container abuse | - |
| `privesc-all-extended-rights` | AllExtendedRights | Extended ACE abuse | - |
| `privesc-read-laps` | Read LAPS Password | Local admin access | - |
| `privesc-domain-admins` | List Domain Admins | Target identification | - |
| `privesc-genericwrite-users` | GenericWrite on Users | Targeted Kerberoast | T1134 |

**Example - Shadow Admins Query Explained**:

```cypher
-- Find non-privileged users who control privileged accounts
MATCH (attacker)-[r:GenericAll|GenericWrite|ForceChangePassword|
                   WriteDacl|WriteOwner|Owns]->(victim:User)
WHERE victim.admincount = true         -- Victim is privileged
  AND NOT attacker.admincount = true   -- Attacker is NOT privileged
RETURN attacker.name AS ShadowAdmin,   -- The hidden threat
       type(r) AS Permission,          -- How they can attack
       victim.name AS CanControl       -- Who they control
```

**Why This Matters**:
Shadow admins don't appear in privileged groups but have paths to compromise privileged accounts. Security teams often miss these.

---

### 4. Attack Chains (8 queries)

**Purpose**: Multi-hop path reconstruction from owned user to Domain Admin.

**File**: `attack_chains.json`

| ID | Name | Hops | Use Case |
|----|------|------|----------|
| `chain-owned-to-pivot-to-da` | Full Attack Path | Multi | Reconstruct DCSync-style chains |
| `chain-shortest-to-da` | Shortest Path to DA | 1-5 | Fastest route |
| `chain-all-paths-to-da` | All Paths to DA | 1-6 | Alternative routes |
| `chain-credential-harvest` | Credential Harvest | 2 | Mimikatz targets |
| `chain-path-through-computer` | Path Through Computer | 1-5 | Targeted pivot |
| `chain-path-between-users` | Path Between Users | 1-10 | User-to-user escalation |
| `chain-to-high-value` | Path to High-Value | 1-5 | BloodHound marked targets |
| `chain-circular-groups` | Circular Memberships | 1-5 | Misconfigurations |

**Example - Shortest Path Analysis**:

```cypher
MATCH p=shortestPath(
  (u:User {enabled:true})-[*1..5]->(g:Group)  -- Any edge type, 1-5 hops
)
WHERE g.name =~ '(?i).*DOMAIN ADMINS.*'       -- Target: Domain Admins
  AND NOT u.admincount = true                 -- Start: non-privileged
RETURN u.name AS StartUser,
       length(p) AS Hops,                     -- Distance to DA
       [n IN nodes(p) | n.name] AS Path       -- Full path
LIMIT 10
```

**Cypher Pattern Breakdown**:
- `shortestPath()` - Dijkstra's algorithm for minimum hops
- `[*1..5]` - Variable-length path (1 to 5 relationships)
- `[n IN nodes(p) | n.name]` - List comprehension extracting names

---

### 5. Owned Principal (10 queries)

**Purpose**: What can I do from my compromised user?

**File**: `owned_principal.json`

| ID | Name | First Query? | Purpose |
|----|------|--------------|---------|
| `owned-what-can-access` | What Can I Access? | Yes | First query after compromise |
| `owned-quick-wins-context` | Quick Wins from Context | Yes | Combined opportunities |
| `owned-path-to-da` | Path to DA | - | Your specific path |
| `owned-group-memberships` | Group Memberships | - | Inherited privileges |
| `owned-outbound-control` | Objects I Control | - | ACL abuse targets |
| `owned-first-hop` | First Hop Movement | - | Immediate lateral movement |
| `owned-kerberoast-context` | Kerberoast Targets | - | SPNs you can attack |
| `owned-asrep-context` | AS-REP Targets | - | Pre-auth disabled users |
| `owned-session-opportunities` | Session Harvesting | - | Credential theft targets |
| `owned-chained-privesc` | Chained Escalation | - | Multi-step paths |

**Example - First Query After Compromise**:

```cypher
MATCH (u:User {name:'PETE@CORP.COM'})        -- Your owned user
      -[r:AdminTo|CanRDP|CanPSRemote|ExecuteDCOM]->(c:Computer)
RETURN c.name AS Target,                      -- Where can you go?
       type(r) AS AccessType,                 -- How?
       c.operatingsystem AS OS                -- What OS?
ORDER BY AccessType
```

**Workflow**:
1. Mark user as `owned` in BloodHound
2. Run `owned-what-can-access` to see lateral movement options
3. Run `owned-first-hop` to find sessions on accessible computers
4. Run `owned-path-to-da` to see your path to Domain Admin

---

### 6. Operational (8 queries)

**Purpose**: Domain reconnaissance and situational awareness.

**File**: `operational.json`

| ID | Name | Intel Type | OSCP Relevance |
|----|------|------------|----------------|
| `ops-computers-by-os` | OS Distribution | Asset inventory | Find legacy systems |
| `ops-legacy-systems` | Legacy Windows | Vulnerability targets | 2008/2003/XP = exploitable |
| `ops-password-age` | Password Age | Credential targets | Old = weak |
| `ops-inactive-users` | Inactive Accounts | Credential targets | May have defaults |
| `ops-enabled-disabled-ratio` | Account Statistics | Environment size | Planning |
| `ops-trust-relationships` | Domain Trusts | Attack surface | Cross-domain paths |
| `ops-relationship-counts` | Edge Statistics | Data quality | Verify import |
| `ops-high-value-summary` | High-Value Targets | Priority targets | Focus areas |

**Example - Find Legacy Systems**:

```cypher
MATCH (c:Computer {enabled:true})
WHERE c.operatingsystem =~ '(?i).*(2008|2003|Windows 7|Windows XP|Vista).*'
RETURN c.name AS Computer,
       c.operatingsystem AS OS
ORDER BY c.operatingsystem
```

**Why Target Legacy**:
- Missing security patches (EternalBlue, PrintNightmare)
- Weak encryption (NTLMv1, SMBv1)
- No modern security features (Credential Guard, LAPS)

---

## Learning Path

### Week 1: Foundations
1. Study [Cypher Fundamentals](#cypher-fundamentals)
2. Run all `quick_wins.json` queries against test data
3. Understand node types and properties

### Week 2: Lateral Movement
1. Master `AdminTo`, `HasSession`, `CanRDP` edges
2. Practice `lateral_movement.json` queries
3. Build mental model of session-based attacks

### Week 3: ACL Abuse
1. Study ACL edges (GenericAll, WriteDacl, etc.)
2. Run `privilege_escalation.json` queries
3. Understand attack chains (WriteDacl -> GenericAll -> DCSync)

### Week 4: Attack Chains
1. Practice `attack_chains.json` path queries
2. Use `owned_principal.json` for owned-user analysis
3. Build custom queries combining patterns

### Practice Environment
- BloodHound sample databases
- DVAD (Damn Vulnerable Active Directory)
- GOAD (Game of Active Directory)
- PG Practice / HTB Pro Labs

---

## Complete Query Index

### Quick Wins
| ID | File | OSCP |
|----|------|------|
| quick-asrep-roastable | quick_wins.json | HIGH |
| quick-kerberoastable | quick_wins.json | HIGH |
| quick-kerberoastable-privileged | quick_wins.json | HIGH |
| quick-unconstrained-delegation | quick_wins.json | HIGH |
| quick-constrained-delegation | quick_wins.json | HIGH |
| quick-password-in-description | quick_wins.json | HIGH |
| quick-password-never-expires | quick_wins.json | MEDIUM |
| quick-never-logged-in | quick_wins.json | MEDIUM |
| quick-laps-gaps | quick_wins.json | MEDIUM |
| quick-prewin2000-accounts | quick_wins.json | LOW |

### Lateral Movement
| ID | File | OSCP |
|----|------|------|
| lateral-adminto-nonpriv | lateral_movement.json | HIGH |
| lateral-all-admins-per-computer | lateral_movement.json | HIGH |
| lateral-psremote-targets | lateral_movement.json | HIGH |
| lateral-rdp-targets | lateral_movement.json | HIGH |
| lateral-dcom-targets | lateral_movement.json | MEDIUM |
| lateral-sessions-on-computer | lateral_movement.json | HIGH |
| lateral-user-access-all | lateral_movement.json | HIGH |
| lateral-users-to-computer | lateral_movement.json | HIGH |
| lateral-domain-users-admin | lateral_movement.json | HIGH |
| lateral-multi-path-computers | lateral_movement.json | MEDIUM |
| lateral-da-sessions-workstations | lateral_movement.json | HIGH |
| lateral-cross-trust | lateral_movement.json | MEDIUM |

### Privilege Escalation
| ID | File | OSCP |
|----|------|------|
| privesc-dcsync-rights | privilege_escalation.json | HIGH |
| privesc-genericall-highvalue | privilege_escalation.json | HIGH |
| privesc-shadow-admins | privilege_escalation.json | HIGH |
| privesc-writedacl | privilege_escalation.json | HIGH |
| privesc-writeowner | privilege_escalation.json | HIGH |
| privesc-shadow-credentials | privilege_escalation.json | HIGH |
| privesc-force-change-password | privilege_escalation.json | HIGH |
| privesc-addmember | privilege_escalation.json | HIGH |
| privesc-owns | privilege_escalation.json | HIGH |
| privesc-gpo-abuse | privilege_escalation.json | MEDIUM |
| privesc-ou-control | privilege_escalation.json | MEDIUM |
| privesc-all-extended-rights | privilege_escalation.json | HIGH |
| privesc-read-laps | privilege_escalation.json | HIGH |
| privesc-domain-admins | privilege_escalation.json | HIGH |
| privesc-genericwrite-users | privilege_escalation.json | HIGH |

### Attack Chains
| ID | File | OSCP |
|----|------|------|
| chain-owned-to-pivot-to-da | attack_chains.json | HIGH |
| chain-shortest-to-da | attack_chains.json | HIGH |
| chain-all-paths-to-da | attack_chains.json | HIGH |
| chain-credential-harvest | attack_chains.json | HIGH |
| chain-path-through-computer | attack_chains.json | HIGH |
| chain-path-between-users | attack_chains.json | HIGH |
| chain-to-high-value | attack_chains.json | HIGH |
| chain-circular-groups | attack_chains.json | LOW |

### Owned Principal
| ID | File | OSCP |
|----|------|------|
| owned-what-can-access | owned_principal.json | HIGH |
| owned-quick-wins-context | owned_principal.json | HIGH |
| owned-path-to-da | owned_principal.json | HIGH |
| owned-group-memberships | owned_principal.json | HIGH |
| owned-outbound-control | owned_principal.json | HIGH |
| owned-first-hop | owned_principal.json | HIGH |
| owned-kerberoast-context | owned_principal.json | HIGH |
| owned-asrep-context | owned_principal.json | HIGH |
| owned-session-opportunities | owned_principal.json | HIGH |
| owned-chained-privesc | owned_principal.json | HIGH |

### Operational
| ID | File | OSCP |
|----|------|------|
| ops-computers-by-os | operational.json | MEDIUM |
| ops-legacy-systems | operational.json | HIGH |
| ops-password-age | operational.json | MEDIUM |
| ops-inactive-users | operational.json | MEDIUM |
| ops-enabled-disabled-ratio | operational.json | LOW |
| ops-trust-relationships | operational.json | MEDIUM |
| ops-relationship-counts | operational.json | LOW |
| ops-high-value-summary | operational.json | HIGH |

---

## Usage with blood-trail

```bash
# Import BloodHound data and run queries
crack blood-trail /path/to/bloodhound/json/

# Run specific query by ID
crack blood-trail --query lateral-adminto-nonpriv

# Run category
crack blood-trail --category quick_wins

# Verbose output with full query
crack blood-trail --query chain-shortest-to-da -v
```

---

## Validation

All 63 queries have been validated against Neo4j 5.x using `EXPLAIN`:

```
Passed: 63/63
Failed: 0
```

---

## Contributing

When adding new queries:

1. Follow the JSON schema in `schema.json`
2. Use kebab-case for query IDs
3. Include `oscp_relevance` rating
4. Document `edge_types_used` for dependency tracking
5. Provide `example_output` from real environments
6. Link `next_steps` to related query IDs

---

*Part of the CRACK toolkit for OSCP preparation*
