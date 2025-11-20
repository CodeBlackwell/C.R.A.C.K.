// ============================================================================
// WRITEUP SCHEMA - Node Definitions and Constraints
// ============================================================================
// Neo4j schema for OSCP writeup nodes with supporting entities
// Created: 2025-11-19
// Purpose: Enable structured writeup storage with command/chain/technique relationships
// ============================================================================

// ----------------------------------------------------------------------------
// WRITEUP NODE
// ----------------------------------------------------------------------------
// Primary node representing a complete machine writeup

// Create uniqueness constraint on writeup ID
CREATE CONSTRAINT writeup_id_unique IF NOT EXISTS
FOR (w:Writeup) REQUIRE w.id IS UNIQUE;

// Create index on platform for filtering
CREATE INDEX writeup_platform_idx IF NOT EXISTS
FOR (w:Writeup) ON (w.platform);

// Create index on difficulty for searching
CREATE INDEX writeup_difficulty_idx IF NOT EXISTS
FOR (w:Writeup) ON (w.difficulty);

// Create index on OS for filtering
CREATE INDEX writeup_os_idx IF NOT EXISTS
FOR (w:Writeup) ON (w.os);

// Create index on OSCP relevance for prioritization
CREATE INDEX writeup_oscp_relevance_idx IF NOT EXISTS
FOR (w:Writeup) ON (w.oscp_relevance);

// Example Writeup node structure:
// (:Writeup {
//   id: 'htb-usage',
//   name: 'Usage',
//   platform: 'HackTheBox',
//   machine_type: 'retired',
//   difficulty: 'easy',
//   os: 'linux',
//   os_version: 'Ubuntu 22.04.4 LTS',
//   ip_address: '10.10.11.18',
//   oscp_relevance: 'high',
//   exam_applicable: true,
//   synopsis: 'SQL injection to admin access...',
//   total_duration_minutes: 170,
//   release_date: '2024-04-13',
//   retire_date: '2024-08-10',
//   writeup_author: 'C4rm3l0',
//   writeup_date: '2024-08-07',
//   flags_captured: ['user.txt', 'root.txt']
// })

// ----------------------------------------------------------------------------
// CVE NODE
// ----------------------------------------------------------------------------
// Represents CVE vulnerabilities exploited in writeups

// Create uniqueness constraint on CVE ID
CREATE CONSTRAINT cve_id_unique IF NOT EXISTS
FOR (cve:CVE) REQUIRE cve.cve_id IS UNIQUE;

// Create index on severity
CREATE INDEX cve_severity_idx IF NOT EXISTS
FOR (cve:CVE) ON (cve.severity);

// Example CVE node:
// (:CVE {
//   cve_id: 'CVE-2023-24249',
//   name: 'Laravel-admin Arbitrary File Upload',
//   description: 'File upload vulnerability...',
//   severity: 'critical',
//   cvss_score: 9.8,
//   published_date: '2023-01-18',
//   affected_component: 'encore/laravel-admin',
//   affected_versions: ['<= 1.8.18'],
//   references: ['https://nvd.nist.gov/...']
// })

// ----------------------------------------------------------------------------
// TECHNIQUE NODE
// ----------------------------------------------------------------------------
// Represents exploitation/privilege escalation techniques

// Create uniqueness constraint on technique name
CREATE CONSTRAINT technique_name_unique IF NOT EXISTS
FOR (t:Technique) REQUIRE t.name IS UNIQUE;

// Create index on category
CREATE INDEX technique_category_idx IF NOT EXISTS
FOR (t:Technique) ON (t.category);

// Create index on difficulty
CREATE INDEX technique_difficulty_idx IF NOT EXISTS
FOR (t:Technique) ON (t.difficulty);

// Example Technique node:
// (:Technique {
//   name: '7zip Listfile Symlink Arbitrary File Read',
//   category: 'privilege_escalation',
//   difficulty: 'medium',
//   description: 'Exploit 7zip @listfile feature...',
//   detection_difficulty: 'medium',
//   oscp_applicable: true,
//   steps: ['Create @filename marker', 'Create symlink...'],
//   why_this_works: 'Technical explanation...',
//   references: ['https://book.hacktricks.xyz/...']
// })

// ----------------------------------------------------------------------------
// PLATFORM NODE
// ----------------------------------------------------------------------------
// Represents machine source platforms (HTB, PG, THM, etc.)

// Create uniqueness constraint on platform name
CREATE CONSTRAINT platform_name_unique IF NOT EXISTS
FOR (p:Platform) REQUIRE p.name IS UNIQUE;

// Example Platform node:
// (:Platform {
//   name: 'HackTheBox',
//   abbreviation: 'HTB',
//   type: 'commercial',
//   url: 'https://app.hackthebox.com',
//   oscp_similarity: 'high',
//   notes: 'Retired machines similar to OSCP labs'
// })

// ----------------------------------------------------------------------------
// SKILL NODE
// ----------------------------------------------------------------------------
// Represents skills required or taught by machines

// Create uniqueness constraint on skill name
CREATE CONSTRAINT skill_name_unique IF NOT EXISTS
FOR (s:Skill) REQUIRE s.name IS UNIQUE;

// Create index on category
CREATE INDEX skill_category_idx IF NOT EXISTS
FOR (s:Skill) ON (s.category);

// Example Skill node:
// (:Skill {
//   name: 'SQL Injection',
//   category: 'web_exploitation',
//   oscp_importance: 'critical',
//   description: 'Ability to detect and exploit SQL injections',
//   prerequisite_skills: ['Web fundamentals', 'HTTP basics'],
//   resources: ['PortSwigger SQL Injection', 'OWASP Top 10']
// })

// ----------------------------------------------------------------------------
// VULNERABILITY NODE (Alternative to CVE for non-CVE vulns)
// ----------------------------------------------------------------------------
// Represents vulnerabilities without official CVE assignments

// Create index on vulnerability type
CREATE INDEX vulnerability_type_idx IF NOT EXISTS
FOR (v:Vulnerability) ON (v.type);

// Example Vulnerability node:
// (:Vulnerability {
//   name: 'SQL Injection in Password Reset Form',
//   type: 'boolean-based blind',
//   location: '/forget-password',
//   parameter: 'email',
//   severity: 'high',
//   exploitability: 'easy',
//   description: 'Password reset form vulnerable to blind SQLi...'
// })

// ----------------------------------------------------------------------------
// FAILED_ATTEMPT NODE
// ----------------------------------------------------------------------------
// Represents documented failed attempts (critical for learning!)

// Create index on importance for prioritization
CREATE INDEX failed_attempt_importance_idx IF NOT EXISTS
FOR (fa:FailedAttempt) ON (fa.importance);

// Example FailedAttempt node:
// (:FailedAttempt {
//   attempt: 'sqlmap with default settings',
//   command_executed: 'sqlmap -r reset.req -p email --batch',
//   expected: 'Detection of blind SQL injection',
//   actual: 'WARNING: POST parameter email does not seem to be injectable',
//   reason: 'Default sqlmap test level insufficient for blind SQLi',
//   solution: 'Increase test depth with --level 3',
//   lesson_learned: 'Trust manual verification over tool defaults...',
//   time_wasted_minutes: 15,
//   importance: 'critical',
//   phase: 'foothold'
// })

// ----------------------------------------------------------------------------
// PHASE NODE
// ----------------------------------------------------------------------------
// Represents attack phases within writeups

// Create index on phase name
CREATE INDEX phase_name_idx IF NOT EXISTS
FOR (ph:Phase) ON (ph.name);

// Example Phase node:
// (:Phase {
//   writeup_id: 'htb-usage',
//   name: 'foothold',
//   duration_minutes: 90,
//   description: 'SQL injection to admin access...',
//   oscp_notes: 'Standard OSCP web exploitation workflow...'
// })

// ============================================================================
// VERIFICATION QUERIES
// ============================================================================

// Count nodes by type:
// MATCH (w:Writeup) RETURN count(w) as writeups
// MATCH (cve:CVE) RETURN count(cve) as cves
// MATCH (t:Technique) RETURN count(t) as techniques
// MATCH (p:Platform) RETURN count(p) as platforms
// MATCH (s:Skill) RETURN count(s) as skills
// MATCH (fa:FailedAttempt) RETURN count(fa) as failed_attempts

// List all constraints:
// SHOW CONSTRAINTS

// List all indexes:
// SHOW INDEXES

// ============================================================================
