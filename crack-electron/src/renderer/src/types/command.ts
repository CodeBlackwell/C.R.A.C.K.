export interface Command {
  id: string;
  name: string;
  category: string;
  description: string;
  command: string;
  tags: string[];
  oscp_relevance: boolean;
  flags?: Flag[];
  variables?: Variable[];
  indicators?: Indicator[];
}

export interface Flag {
  name: string;
  description: string;
  required?: boolean;
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
