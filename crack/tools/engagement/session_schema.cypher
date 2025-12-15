// B.R.E.A.C.H. Terminal Session Schema Extension
// Run after main engagement schema is in place

// ============================================
// Node Constraints
// ============================================

// Terminal Session - unique ID
CREATE CONSTRAINT terminal_session_id IF NOT EXISTS
FOR (s:TerminalSession) REQUIRE s.id IS UNIQUE;

// Command Execution - unique ID
CREATE CONSTRAINT command_execution_id IF NOT EXISTS
FOR (e:CommandExecution) REQUIRE e.id IS UNIQUE;

// Checklist Item - unique ID
CREATE CONSTRAINT checklist_item_id IF NOT EXISTS
FOR (c:ChecklistItem) REQUIRE c.id IS UNIQUE;

// ============================================
// Indexes for Performance
// ============================================

// Sessions by engagement
CREATE INDEX session_engagement IF NOT EXISTS
FOR (s:TerminalSession) ON (s.engagement_id);

// Sessions by target
CREATE INDEX session_target IF NOT EXISTS
FOR (s:TerminalSession) ON (s.target_id);

// Sessions by status (for reconnection queries)
CREATE INDEX session_status IF NOT EXISTS
FOR (s:TerminalSession) ON (s.status);

// Sessions by type
CREATE INDEX session_type IF NOT EXISTS
FOR (s:TerminalSession) ON (s.type);

// Commands by target for history
CREATE INDEX execution_target IF NOT EXISTS
FOR (e:CommandExecution) ON (e.target_id);

// Checklist by target
CREATE INDEX checklist_target IF NOT EXISTS
FOR (c:ChecklistItem) ON (c.target_id);

// ============================================
// Example Data Structure
// ============================================

// TerminalSession Node
// {
//   id: "uuid",
//   type: "shell|listener|tunnel|proxy|scan|server|custom",
//   status: "starting|running|backgrounded|stopped|error|completed|disconnected",
//   command: "nc",
//   args: ["-lvnp", "4444"],
//   working_dir: "/home/kali",
//   pid: 12345,
//   exit_code: null,
//   target_id: "target-uuid",
//   engagement_id: "eng-uuid",
//   label: "NC Listener 4444",
//   persistent: true,
//   interactive: true,
//   started_at: datetime(),
//   stopped_at: null,
//   last_activity_at: datetime()
// }

// Relationships:
// (:Engagement)-[:HAS_TERMINAL_SESSION]->(:TerminalSession)
// (:TerminalSession)-[:ON_TARGET]->(:Target)
// (:TerminalSession)-[:TUNNELS_THROUGH]->(:TerminalSession)
// (:TerminalSession)-[:SPAWNED_FROM]->(:TerminalSession)
// (:TerminalSession)-[:PROXIES_VIA]->(:TerminalSession)
// (:TerminalSession)-[:PROVIDES_ACCESS]->(:TerminalSession)

// CommandExecution Node
// {
//   id: "uuid",
//   command: "nmap -sV 10.10.10.1",
//   target_id: "target-uuid",
//   session_id: "session-uuid",
//   executed_at: datetime(),
//   exit_code: 0,
//   duration_ms: 45000,
//   output_preview: "PORT STATE SERVICE..."
// }

// Relationships:
// (:Target)-[:EXECUTED_COMMAND]->(:CommandExecution)
// (:TerminalSession)-[:RAN]->(:CommandExecution)

// ChecklistItem Node
// {
//   id: "uuid",
//   command_id: "nmap-service-scan",
//   target_id: "target-uuid",
//   status: "pending|in_progress|completed|skipped",
//   notes: "Found 5 open ports",
//   created_at: datetime(),
//   completed_at: datetime()
// }

// Relationships:
// (:Target)-[:HAS_CHECKLIST_ITEM]->(:ChecklistItem)
// (:ChecklistItem)-[:REFERENCES]->(:Command)
// (:ChecklistItem)-[:EXECUTED_BY]->(:CommandExecution)
