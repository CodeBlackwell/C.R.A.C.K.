// ============================================================================
// Writeup Type Definitions
// ============================================================================
// Comprehensive TypeScript interfaces matching the complete writeup JSON schema

// ----------------------------------------------------------------------------
// List Item (for search results)
// ----------------------------------------------------------------------------
export interface WriteupListItem {
  id: string
  name: string
  platform: string
  difficulty: 'easy' | 'medium' | 'hard' | 'insane'
  oscp_relevance: 'high' | 'medium' | 'low'
  machine_type: string
  os: string
  total_duration_minutes: number
}

// ----------------------------------------------------------------------------
// Source Metadata
// ----------------------------------------------------------------------------
export interface WriteupSource {
  platform: string
  type: string // 'retired', 'active', etc.
  release_date?: string
  retire_date?: string
  url?: string
}

// ----------------------------------------------------------------------------
// Machine Metadata
// ----------------------------------------------------------------------------
export interface WriteupMetadata {
  difficulty: 'easy' | 'medium' | 'hard' | 'insane'
  os: string
  os_version?: string
  machine_author?: string
  writeup_author?: string
  writeup_date?: string
  document_number?: string
  ip_address?: string
  points?: number
  user_owns?: number
  system_owns?: number
}

// ----------------------------------------------------------------------------
// OSCP Relevance
// ----------------------------------------------------------------------------
export interface SimilarMachines {
  proving_grounds?: string[]
  hackthebox?: string[]
  oscp_labs?: string[]
}

export interface OSCPRelevance {
  score: 'high' | 'medium' | 'low'
  reasoning: string
  exam_applicable: boolean
  similar_machines?: SimilarMachines
  time_estimate_exam?: string
}

// ----------------------------------------------------------------------------
// Skills
// ----------------------------------------------------------------------------
export interface Skills {
  required: string[]
  learned: string[]
}

// ----------------------------------------------------------------------------
// Attack Phase - Nested Structures
// ----------------------------------------------------------------------------

// Command flags (key-value pairs)
export interface CommandFlags {
  [flag: string]: string
}

// Screenshot reference
export interface ScreenshotReference {
  file: string // Relative path like "images/page05_img01.png"
  caption?: string
  extracted_from_page?: number
  confidence?: 'high' | 'medium' | 'low'
  context?: string
}

// Credentials obtained during a command/phase
export interface CredentialObtained {
  id?: number
  username?: string
  password?: string
  password_hash?: string
  hash_type?: string
  cost_factor?: number
  source?: string
  services?: string[]
  context?: string
}

// Command used in attack phase
export interface CommandUsed {
  command_id: string
  context: string
  step_number: number
  command_executed?: string
  url?: string
  url_visited?: string
  payload?: string
  flags_used?: CommandFlags
  output_snippet?: string
  output?: string
  success: boolean
  notes?: string
  error?: string
  time_taken?: string
  password_cracked?: string
  credentials_used?: string
  credentials_obtained?: CredentialObtained[]
  credentials_found?: CredentialObtained
  request_saved?: string
  location?: string
  findings?: string[]
  files_found?: string[]
  users_found?: string[]
  shell_type?: string
  encoding?: string
  lhost?: string
  lport?: number
  payload_generated?: string
  encoded_payload?: string
  port?: number
  original_filename?: string
  modified_filename?: string
  parameter_modified?: string
  command_tested?: string
  file_created?: string
  proper_format?: string
  cleanup_required?: string
  key_extracted?: boolean
  purpose?: string
  target?: string
  linkname?: string
  option_selected?: string
  hash_file_content?: string
  password_tried?: string
  versions_found?: {
    [key: string]: string
  }
  vulnerability_confirmed?: {
    type: string
    title?: string
    payload_example?: string
  }
  research_source?: string
  technique_discovered?: string
  menu_options?: string[]
  commands_found?: string[]
  critical_finding?: string
  screenshots?: ScreenshotReference[]
}

// Failed attempt in attack phase
export interface FailedAttempt {
  attempt: string
  command_executed?: string
  expected: string
  actual: string
  reason: string
  solution: string
  lesson_learned: string
  time_wasted_minutes?: number
  documentation_importance?: 'high' | 'medium' | 'low'
  notes?: string
}

// Vulnerability discovered in attack phase
export interface Vulnerability {
  name: string
  cve?: string | null
  type: string
  location?: string
  parameter?: string
  method?: string
  component?: string
  version?: string
  command_vulnerable?: string
  flag_exploited?: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  exploitability: 'easy' | 'medium' | 'hard'
  payload_example?: string
  technique?: string
  notes?: string
}

// Technique used in attack phase
export interface Technique {
  name: string
  category: string
  difficulty: 'easy' | 'medium' | 'hard'
  steps: string[]
  why_this_works: string
  detection_difficulty: 'easy' | 'medium' | 'hard'
  references: string[]
}

// ----------------------------------------------------------------------------
// Attack Phase
// ----------------------------------------------------------------------------
export interface AttackPhase {
  phase: string // 'enumeration', 'foothold', 'lateral_movement', 'privilege_escalation'
  duration_minutes: number
  description: string
  commands_used: CommandUsed[]
  failed_attempts: FailedAttempt[]
  vulnerabilities?: Vulnerability[]
  credentials_obtained?: CredentialObtained[]
  techniques?: Technique[]
  chains_applied?: string[] // IDs of attack chains used
  key_findings: string[]
  oscp_notes: string
}

// ----------------------------------------------------------------------------
// Key Learnings
// ----------------------------------------------------------------------------
export interface KeyLearning {
  category: string
  lesson: string
  detail: string
  importance: 'critical' | 'high' | 'medium' | 'low'
  time_impact?: string
  methodology?: string
  notes?: string
}

// ----------------------------------------------------------------------------
// Alternative Approaches
// ----------------------------------------------------------------------------
export interface AlternativeMethod {
  method: string
  description: string
  oscp_applicable: boolean
  reasoning?: string
  notes?: string
}

export interface AlternativeApproaches {
  foothold?: AlternativeMethod[]
  lateral_movement?: AlternativeMethod[]
  privilege_escalation?: AlternativeMethod[]
}

// ----------------------------------------------------------------------------
// Time Breakdown
// ----------------------------------------------------------------------------
export interface TimeBreakdown {
  enumeration?: number
  foothold_sqli?: number
  foothold_file_upload?: number
  foothold?: number
  lateral_movement?: number
  privilege_escalation_analysis?: number
  privilege_escalation_exploitation?: number
  privilege_escalation?: number
  total_minutes: number
  total_hours: number
  flags_captured?: {
    user?: string
    root?: string
    [key: string]: string | undefined
  }
  oscp_time_estimate?: string
}

// ----------------------------------------------------------------------------
// References
// ----------------------------------------------------------------------------
export interface Reference {
  type: string // 'cve', 'blogpost', 'hacktricks', 'tool', 'mitre_attack', etc.
  id?: string
  name?: string
  technique?: string
  url?: string
  description?: string
  author?: string
  documentation?: string
}

// ----------------------------------------------------------------------------
// Files
// ----------------------------------------------------------------------------
export interface WriteupFiles {
  original_writeup?: string
  metadata?: string
  images?: string
}

// ----------------------------------------------------------------------------
// Main Writeup Interface
// ----------------------------------------------------------------------------
export interface Writeup {
  // Core identification
  id: string
  name: string

  // Source and metadata
  source: WriteupSource
  metadata: WriteupMetadata

  // OSCP relevance
  oscp_relevance: OSCPRelevance

  // Content
  synopsis: string
  skills: Skills
  tags: string[]

  // Attack chain
  attack_phases: AttackPhase[]

  // Learning materials
  key_learnings: KeyLearning[]
  alternative_approaches?: AlternativeApproaches

  // Time tracking
  time_breakdown: TimeBreakdown

  // Resources
  references: Reference[]
  files?: WriteupFiles
}

// ============================================================================
// Helper Types
// ============================================================================

// For UI display purposes
export interface PhaseStats {
  phase: string
  duration_minutes: number
  commands_count: number
  failures_count: number
  vulnerabilities_count: number
  credentials_count: number
}

// For command badge display
export interface CommandBadgeInfo {
  command_id: string
  step_number: number
  success: boolean
}

// For timeline visualization
export interface TimelineEvent {
  phase: string
  step_number: number
  timestamp_offset: number // minutes from start
  event_type: 'command' | 'failure' | 'credential' | 'vulnerability'
  description: string
  success?: boolean
}
