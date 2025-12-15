/**
 * Shared Cytoscape Graph Types
 *
 * Common type definitions for graph visualization across CRACK apps.
 */

/** Cytoscape node data structure */
export interface CytoscapeNode<T = Record<string, unknown>> {
  data: {
    id: string;
    label: string;
    type?: string;
  } & T;
  position?: {
    x: number;
    y: number;
  };
  classes?: string;
}

/** Cytoscape edge data structure */
export interface CytoscapeEdge {
  data: {
    id: string;
    source: string;
    target: string;
    label?: string;
    type?: string;
  };
  classes?: string;
}

/** Complete graph data for Cytoscape */
export interface GraphData<N = Record<string, unknown>> {
  elements: {
    nodes: CytoscapeNode<N>[];
    edges: CytoscapeEdge[];
  };
}

/** Graph layout types */
export type LayoutType = 'dagre' | 'cose' | 'cose-bilkent' | 'elk' | 'grid' | 'circle' | 'concentric';

/** Layout orientation */
export type LayoutOrientation = 'horizontal' | 'vertical';

/** Layout configuration */
export interface LayoutConfig {
  name: LayoutType;
  rankDir?: 'TB' | 'BT' | 'LR' | 'RL';
  nodeSep?: number;
  rankSep?: number;
  padding?: number;
  animate?: boolean;
  animationDuration?: number;
}

/** Node interaction events */
export interface NodeClickEvent {
  nodeId: string;
  nodeData: Record<string, unknown>;
  position: { x: number; y: number };
}

/** Edge interaction events */
export interface EdgeClickEvent {
  edgeId: string;
  sourceId: string;
  targetId: string;
  edgeType: string;
}
