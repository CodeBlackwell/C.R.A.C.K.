// Attack Chain TypeScript Interfaces

export interface AttackChain {
  id: string;
  name: string;
  description: string;
  version: string;
  category: string;
  platform: string;
  difficulty: 'beginner' | 'intermediate' | 'advanced';
  time_estimate: string;
  oscp_relevant: string | boolean; // Can be string "True"/"False" from DB
  notes: string;
  steps?: ChainStep[];
}

export interface ChainStep {
  id: string;
  name: string;
  objective: string;
  description: string;
  command_ref?: string;
  evidence?: string[];
  dependencies?: string[];
  repeatable?: boolean;
  success_criteria?: string[];
  failure_conditions?: string[];
  next_steps?: string[];
  order?: number;
  command?: ChainStepCommand | null;
}

export interface ChainStepCommand {
  id: string;
  name: string;
  command?: string;
  description?: string;
}

export interface ChainSearchFilters {
  category?: string;
}

export interface ChainGraphData {
  elements: {
    nodes: ChainGraphNode[];
    edges: ChainGraphEdge[];
  };
}

export interface ChainGraphNode {
  data: {
    id: string;
    label: string;
    description: string;
    type: 'step';
    order: number;
    command?: ChainStepCommand | null;
  };
}

export interface ChainGraphEdge {
  data: {
    id: string;
    source: string;
    target: string;
    label: string;
    type: 'next';
  };
}
