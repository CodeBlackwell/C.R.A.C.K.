/**
 * Actions Panel Type Definitions
 *
 * Hierarchical structure: Category -> Tool -> Command Variants
 * Used by ActionsPanel component to display context-aware actions.
 */

/** Service matching rule for filtering categories */
export interface ServiceMatcher {
  /** Ports that match this service */
  ports?: number[];
  /** Service name patterns (partial match, case-insensitive) */
  serviceNames?: string[];
  /** Protocol filter (tcp/udp) */
  protocols?: ('tcp' | 'udp')[];
}

/** Command variant - a specific command within a tool */
export interface ActionVariant {
  /** Unique identifier */
  id: string;
  /** Display label */
  label: string;
  /** Command template with placeholders */
  command: string;
  /** Short description */
  description?: string;
  /** Flag explanations */
  flagExplanations?: Record<string, string>;
  /** OSCP relevance level */
  oscpRelevance?: 'high' | 'medium' | 'low';
}

/** Tool grouping within a category */
export interface ActionTool {
  /** Tool identifier */
  id: string;
  /** Tool name for display */
  name: string;
  /** Tabler icon name */
  icon?: string;
  /** Command variants for this tool */
  variants: ActionVariant[];
}

/** Top-level action category */
export interface ActionCategory {
  /** Category identifier */
  id: string;
  /** Category name for display */
  name: string;
  /** Tabler icon name */
  icon?: string;
  /** Short description */
  description?: string;
  /** If true, always show regardless of services */
  alwaysShow?: boolean;
  /** Service matcher for conditional display */
  serviceMatcher?: ServiceMatcher;
  /** Tools in this category */
  tools: ActionTool[];
}

/** Context for action execution */
export interface ActionContext {
  /** Target ID in Neo4j */
  targetId: string;
  /** Target IP address */
  ip: string;
  /** Target hostname (optional) */
  hostname?: string;
  /** Specific port (optional) */
  port?: number;
  /** Detected service name (optional) */
  serviceName?: string;
}

/** Service interface (matches Target's services) */
export interface ServiceInfo {
  id: string;
  port: number;
  protocol: string;
  service_name?: string;
  version?: string;
  state?: string;
}
