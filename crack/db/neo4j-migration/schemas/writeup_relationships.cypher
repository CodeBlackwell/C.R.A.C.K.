// ============================================================================
// WRITEUP RELATIONSHIPS - Relationship Definitions
// ============================================================================
// Neo4j relationship schema for connecting writeups to commands, chains,
// techniques, CVEs, skills, and other entities
// Created: 2025-11-19
// Purpose: Enable traversal queries for learning paths and command discovery
// ============================================================================

// ----------------------------------------------------------------------------
// DEMONSTRATES RELATIONSHIP
// ----------------------------------------------------------------------------
// Connects Writeup to Command - shows which commands were used

// Pattern: (Writeup)-[:DEMONSTRATES]->(Command)

// Relationship properties:
// - phase: enum[enumeration, foothold, lateral_movement, privilege_escalation, post_exploitation]
// - step_number: integer (sequential order within phase)
// - context: string (why this command was used)
// - command_executed: string (actual command with values filled in)
// - success: boolean (whether command succeeded)
// - duration_seconds: integer (optional - time to execute)
// - notes: string (additional context)

// Example:
// (htb_usage:Writeup {id: 'htb-usage'})
//   -[:DEMONSTRATES {
//       phase: 'foothold',
//       step_number: 4,
//       context: 'Retry sqlmap with increased test depth (--level 3)',
//       command_executed: 'sqlmap -r reset.req -p email --batch --level 3',
//       success: true,
//       notes: 'Success! --level 3 enables more thorough injection tests'
//     }]->
// (cmd:Command {id: 'sqlmap-from-request-level3'})

// Query examples:
// // Find all commands used in a writeup, ordered by execution
// MATCH (w:Writeup {id: 'htb-usage'})-[d:DEMONSTRATES]->(c:Command)
// RETURN c.name, d.phase, d.step_number, d.context
// ORDER BY d.phase, d.step_number

// // Find all writeups that demonstrate a specific command
// MATCH (w:Writeup)-[d:DEMONSTRATES]->(c:Command {id: 'sqlmap-from-request-level3'})
// RETURN w.name, w.difficulty, d.context, d.success

// ----------------------------------------------------------------------------
// FAILED_ATTEMPT RELATIONSHIP
// ----------------------------------------------------------------------------
// Connects Writeup to Command for unsuccessful attempts (CRITICAL FOR LEARNING!)

// Pattern: (Writeup)-[:FAILED_ATTEMPT]->(Command)

// Relationship properties:
// - phase: string (attack phase where failure occurred)
// - attempt: string (what was tried)
// - expected: string (what should have happened)
// - actual: string (what actually happened)
// - reason: string (why it failed)
// - solution: string (how to fix it)
// - lesson_learned: string (what this teaches - REQUIRED, min 30 chars)
// - time_wasted_minutes: integer (time lost to this failure)
// - importance: enum[critical, high, medium, low]
// - step_number: integer

// Example:
// (htb_usage:Writeup)
//   -[:FAILED_ATTEMPT {
//       phase: 'foothold',
//       attempt: 'sqlmap with default settings',
//       expected: 'Detection of blind SQL injection',
//       actual: 'WARNING: POST parameter email does not seem to be injectable',
//       reason: 'Default sqlmap test level (1) insufficient for blind SQLi',
//       solution: 'Increase test depth with --level 3',
//       lesson_learned: 'CRITICAL: Trust manual verification over tool defaults. Sqlmap --level flag often required for blind injections.',
//       time_wasted_minutes: 15,
//       importance: 'critical',
//       step_number: 3
//     }]->
// (cmd:Command {id: 'sqlmap-from-request'})

// Query examples:
// // Find all failed attempts with critical lessons
// MATCH (w:Writeup)-[fa:FAILED_ATTEMPT]->(c:Command)
// WHERE fa.importance = 'critical'
// RETURN w.name, c.name, fa.lesson_learned, fa.time_wasted_minutes
// ORDER BY fa.time_wasted_minutes DESC

// // Find common failure patterns across writeups
// MATCH (w:Writeup)-[fa:FAILED_ATTEMPT]->(c:Command)
// RETURN c.id, c.name, count(w) as failure_count, collect(fa.reason) as reasons
// ORDER BY failure_count DESC

// ----------------------------------------------------------------------------
// APPLIES_CHAIN RELATIONSHIP
// ----------------------------------------------------------------------------
// Connects Writeup to Chain - shows which attack chains were used

// Pattern: (Writeup)-[:APPLIES_CHAIN]->(Chain)

// Relationship properties:
// - phase: string (where chain was applied)
// - effectiveness: enum[high, medium, low]
// - modifications: string (how chain was adapted)
// - notes: string

// Example:
// (htb_usage:Writeup)
//   -[:APPLIES_CHAIN {
//       phase: 'foothold',
//       effectiveness: 'high',
//       modifications: 'Used blind SQLi instead of union-based due to application constraints',
//       notes: 'Chain provided good structure but required adaptation'
//     }]->
// (chain:Chain {id: 'web-sqli-union-dump'})

// Query examples:
// // Find chains used in successful writeups
// MATCH (w:Writeup)-[ac:APPLIES_CHAIN]->(ch:Chain)
// WHERE ac.effectiveness = 'high'
// RETURN ch.name, count(w) as usage_count, collect(w.name) as writeups
// ORDER BY usage_count DESC

// ----------------------------------------------------------------------------
// EXPLOITS_CVE RELATIONSHIP
// ----------------------------------------------------------------------------
// Connects Writeup to CVE vulnerabilities

// Pattern: (Writeup)-[:EXPLOITS_CVE]->(CVE)

// Relationship properties:
// - phase: string (when CVE was exploited)
// - exploitation_method: string (how it was exploited)
// - severity: enum[critical, high, medium, low]
// - impact: string (what access was gained)

// Example:
// (htb_usage:Writeup)
//   -[:EXPLOITS_CVE {
//       phase: 'foothold',
//       exploitation_method: 'Manual file upload with double extension (.jpg.php)',
//       severity: 'critical',
//       impact: 'Remote code execution as dash user'
//     }]->
// (cve:CVE {cve_id: 'CVE-2023-24249'})

// Query examples:
// // Find writeups exploiting specific CVE
// MATCH (w:Writeup)-[e:EXPLOITS_CVE]->(cve:CVE {cve_id: 'CVE-2023-24249'})
// RETURN w.name, w.platform, w.difficulty, e.exploitation_method

// // Find most commonly exploited CVEs in writeups
// MATCH (w:Writeup)-[:EXPLOITS_CVE]->(cve:CVE)
// RETURN cve.cve_id, cve.name, count(w) as writeup_count
// ORDER BY writeup_count DESC

// ----------------------------------------------------------------------------
// TEACHES_TECHNIQUE RELATIONSHIP
// ----------------------------------------------------------------------------
// Connects Writeup to Technique - shows which techniques are demonstrated

// Pattern: (Writeup)-[:TEACHES_TECHNIQUE]->(Technique)

// Relationship properties:
// - phase: string (where technique was used)
// - difficulty: enum[easy, medium, hard]
// - effectiveness: enum[high, medium, low]
// - oscp_applicable: boolean
// - notes: string

// Example:
// (htb_usage:Writeup)
//   -[:TEACHES_TECHNIQUE {
//       phase: 'privilege_escalation',
//       difficulty: 'medium',
//       effectiveness: 'high',
//       oscp_applicable: true,
//       notes: 'Advanced technique but demonstrates important symlink abuse concept'
//     }]->
// (tech:Technique {name: '7zip Listfile Symlink Arbitrary File Read'})

// Query examples:
// // Find all OSCP-applicable techniques from writeups
// MATCH (w:Writeup)-[tt:TEACHES_TECHNIQUE]->(t:Technique)
// WHERE tt.oscp_applicable = true AND w.oscp_relevance = 'high'
// RETURN t.name, t.category, count(w) as writeup_count, collect(w.name) as writeups
// ORDER BY writeup_count DESC

// // Build skill progression path
// MATCH path = (easy:Writeup {difficulty: 'easy'})-[:TEACHES_TECHNIQUE]->(t:Technique)<-[:TEACHES_TECHNIQUE]-(medium:Writeup {difficulty: 'medium'})
// WHERE easy.oscp_relevance = 'high' AND medium.oscp_relevance = 'high'
// RETURN path LIMIT 10

// ----------------------------------------------------------------------------
// REQUIRES_SKILL RELATIONSHIP
// ----------------------------------------------------------------------------
// Connects Writeup to Skill (prerequisite skills needed)

// Pattern: (Writeup)-[:REQUIRES_SKILL]->(Skill)

// Relationship properties:
// - importance: enum[critical, high, medium, low]
// - notes: string

// Example:
// (htb_usage:Writeup)
//   -[:REQUIRES_SKILL {importance: 'critical'}]->
// (skill:Skill {name: 'Web application fundamentals'})

// ----------------------------------------------------------------------------
// TEACHES_SKILL RELATIONSHIP
// ----------------------------------------------------------------------------
// Connects Writeup to Skill (skills learned from machine)

// Pattern: (Writeup)-[:TEACHES_SKILL]->(Skill)

// Relationship properties:
// - proficiency_level: enum[beginner, intermediate, advanced]
// - practice_value: enum[high, medium, low]
// - notes: string

// Example:
// (htb_usage:Writeup)
//   -[:TEACHES_SKILL {
//       proficiency_level: 'intermediate',
//       practice_value: 'high',
//       notes: 'Excellent practice for file upload bypass techniques'
//     }]->
// (skill:Skill {name: 'File upload filter bypass'})

// Query examples:
// // Build learning progression (prerequisite → taught skills)
// MATCH (w:Writeup)-[:REQUIRES_SKILL]->(prereq:Skill)
// MATCH (w)-[:TEACHES_SKILL]->(learned:Skill)
// WHERE w.difficulty = 'easy' AND w.oscp_relevance = 'high'
// RETURN w.name, collect(DISTINCT prereq.name) as prerequisites, collect(DISTINCT learned.name) as skills_learned

// ----------------------------------------------------------------------------
// FROM_PLATFORM RELATIONSHIP
// ----------------------------------------------------------------------------
// Connects Writeup to Platform source

// Pattern: (Writeup)-[:FROM_PLATFORM]->(Platform)

// Relationship properties:
// - machine_type: enum[official, retired, active, practice, custom]
// - release_date: date
// - retire_date: date (optional)

// Example:
// (htb_usage:Writeup)
//   -[:FROM_PLATFORM {
//       machine_type: 'retired',
//       release_date: date('2024-04-13'),
//       retire_date: date('2024-08-10')
//     }]->
// (platform:Platform {name: 'HackTheBox'})

// Query examples:
// // Find writeups by platform
// MATCH (w:Writeup)-[:FROM_PLATFORM]->(p:Platform {name: 'HackTheBox'})
// WHERE w.oscp_relevance = 'high'
// RETURN w.name, w.difficulty, w.total_duration_minutes

// ----------------------------------------------------------------------------
// SIMILAR_TO RELATIONSHIP
// ----------------------------------------------------------------------------
// Connects Writeups that are similar (attack vectors, techniques, skills)

// Pattern: (Writeup)-[:SIMILAR_TO]->(Writeup)

// Relationship properties:
// - similarity_score: float (0.0 to 1.0)
// - common_techniques: array[string]
// - common_skills: array[string]
// - notes: string

// Example:
// (htb_usage:Writeup)
//   -[:SIMILAR_TO {
//       similarity_score: 0.75,
//       common_techniques: ['SQL Injection', 'File Upload Bypass'],
//       common_skills: ['Web exploitation', 'PHP'],
//       notes: 'Both involve web exploitation path to RCE'
//     }]->
// (htb_stocker:Writeup {id: 'htb-stocker'})

// Query examples:
// // Find similar writeups for practice
// MATCH (w:Writeup {id: 'htb-usage'})-[s:SIMILAR_TO]->(similar:Writeup)
// RETURN similar.name, similar.platform, s.similarity_score, s.common_techniques
// ORDER BY s.similarity_score DESC

// ----------------------------------------------------------------------------
// REFERENCES_CHEATSHEET RELATIONSHIP
// ----------------------------------------------------------------------------
// Connects Writeup to Cheatsheet for relevant methodologies

// Pattern: (Writeup)-[:REFERENCES_CHEATSHEET]->(Cheatsheet)

// Relationship properties:
// - relevant_scenario: string (which cheatsheet scenario applies)
// - phase: string
// - notes: string

// Example:
// (htb_usage:Writeup)
//   -[:REFERENCES_CHEATSHEET {
//       relevant_scenario: 'Manual SQL injection methodology',
//       phase: 'foothold',
//       notes: 'Cheatsheet methodology directly applicable to discovery phase'
//     }]->
// (cheatsheet:Cheatsheet {id: 'sqli-methodology'})

// ============================================================================
// COMPLEX QUERY EXAMPLES
// ============================================================================

// Find complete attack path for a writeup:
// MATCH path = (w:Writeup {id: 'htb-usage'})-[d:DEMONSTRATES]->(c:Command)
// OPTIONAL MATCH (w)-[tt:TEACHES_TECHNIQUE]->(t:Technique)
// OPTIONAL MATCH (w)-[ec:EXPLOITS_CVE]->(cve:CVE)
// RETURN w, d, c, tt, t, ec, cve

// Find all failed attempts across all writeups (learning goldmine):
// MATCH (w:Writeup)-[fa:FAILED_ATTEMPT]->(c:Command)
// RETURN w.name, w.difficulty, c.name, fa.lesson_learned, fa.time_wasted_minutes, fa.importance
// ORDER BY fa.time_wasted_minutes DESC

// Find writeups that teach a specific skill progression:
// MATCH (w1:Writeup {difficulty: 'easy'})-[:TEACHES_SKILL]->(s:Skill)<-[:REQUIRES_SKILL]-(w2:Writeup {difficulty: 'medium'})
// WHERE w1.oscp_relevance = 'high' AND w2.oscp_relevance = 'high'
// RETURN w1.name as beginner_machine, s.name as bridging_skill, w2.name as intermediate_machine

// Find most valuable commands (used successfully in multiple writeups):
// MATCH (w:Writeup)-[d:DEMONSTRATES]->(c:Command)
// WHERE d.success = true AND w.oscp_relevance = 'high'
// RETURN c.id, c.name, count(w) as usage_count, collect(w.name) as writeups
// ORDER BY usage_count DESC
// LIMIT 20

// Find common failure patterns for a command:
// MATCH (w:Writeup)-[fa:FAILED_ATTEMPT]->(c:Command {id: 'sqlmap-from-request'})
// RETURN c.name, collect({
//   machine: w.name,
//   reason: fa.reason,
//   solution: fa.solution,
//   lesson: fa.lesson_learned
// }) as failures

// ============================================================================
