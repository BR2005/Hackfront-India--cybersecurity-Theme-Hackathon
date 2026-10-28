export type EntityType = 'user' | 'endpoint' | 'server' | 'ip' | 'application' | 'database' | 'vulnerability';

export type Criticality = 'low' | 'medium' | 'high' | 'critical';

export interface GraphNode {
  id: string;
  label: string;
  type: EntityType;
  criticality: Criticality;
  riskScore: number;
  metadata: Record<string, any>;
}

export type RelationshipType = 
  | 'LOGGED_INTO' 
  | 'CONNECTS_TO' 
  | 'HAS_ACCESS_TO' 
  | 'RUNS_PROCESS' 
  | 'HAS_VULNERABILITY' 
  | 'ACCESSES' 
  | 'CONTAINS_DATA'
  | 'MEMBER_OF'
  | 'ADMIN_ON';

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  type: RelationshipType;
  isSuspicious?: boolean;
  metadata: Record<string, any>;
}

export interface GraphData {
  nodes: GraphNode[];
  edges: GraphEdge[];
}
