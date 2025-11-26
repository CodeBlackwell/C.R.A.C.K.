export interface Command {
  id: string;
  name: string;
  category: string;
  subcategory?: string;
  description: string;
  command: string;
  tags: string[];
  oscp_relevance: boolean;
  notes?: string;
  troubleshooting?: Record<string, string>; // Error message -> solution
  prerequisites?: string | string[];
  alternatives?: string | string[];
  next_steps?: string | string[];
  flag_explanations?: Record<string, string>; // Flag name -> explanation
  flags?: Flag[];
  variables?: Variable[];
  indicators?: Indicator[];
  examples?: Example[];
  educational?: Educational;
  related_commands?: string[];
}

export interface Flag {
  name: string;
  description: string;
  required?: boolean;
  example?: string;
  explanation?: string; // Detailed explanation of what the flag does
}

export interface Variable {
  name: string;
  description: string;
  default_value?: string;
  example?: string;
}

export interface Indicator {
  pattern: string;
  type: string; // 'success' | 'failure'
  description: string;
}

export interface Example {
  command: string;
  description: string;
  context?: string;
}

export interface Educational {
  purpose?: string;
  manual_alternative?: string;
  common_failures?: string[];
  when_to_use?: string[];
  time_estimate?: string;
  technical_notes?: string[];
  exam_relevance?: string;
}

export interface GraphData {
  elements: {
    nodes: CytoscapeNode[];
    edges: CytoscapeEdge[];
  };
}

export interface CytoscapeNode {
  data: {
    id: string;
    label: string;
    type?: string;
    [key: string]: any;
  };
}

export interface CytoscapeEdge {
  data: {
    id: string;
    source: string;
    target: string;
    label: string;
    type: string;
  };
}
