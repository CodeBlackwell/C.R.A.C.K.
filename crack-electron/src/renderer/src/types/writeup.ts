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

export interface Writeup {
  id: string
  name: string
  platform: string
  difficulty: 'easy' | 'medium' | 'hard' | 'insane'
  oscp_relevance: 'high' | 'medium' | 'low'
  exam_applicable: boolean
  synopsis: string
  oscp_reasoning: string
  total_duration_minutes: number
  machine_type: string
  os: string
  ip_address?: string
  release_date?: string
  retirement_date?: string
  author?: string
  rating?: number
  user_owns?: number
  root_owns?: number
  tags: string[]
}

export interface WriteupPhase {
  id: string
  name: string
  description: string
  order: number
  duration_minutes?: number
}

export interface WriteupCommand {
  commandId: string
  commandName: string
  phase: string
  stepNumber: number
  context?: string
  commandExecuted?: string
  success: boolean
  notes?: string
}

export interface WriteupFailedAttempt {
  id: string
  description: string
  expectedOutcome: string
  actualOutcome: string
  lessonLearned: string
  phase?: string
}

export interface WriteupCVE {
  cveId: string
  description?: string
}

export interface WriteupTechnique {
  techniqueId: string
  name: string
  category?: string
}
