export type IncidentSeverity = 'low' | 'medium' | 'high' | 'critical';
export type IncidentStatus = 'open' | 'investigating' | 'contained' | 'resolved' | 'closed';

export interface Incident {
  id: string;
  title: string;
  severity: IncidentSeverity;
  status: IncidentStatus;
  firstSeen: string;
  lastSeen: string;
  description: string;
  affectedAssets: string[]; // Node IDs
  relatedEvents: string[]; // Event IDs
  potentialAttackPath?: string[]; // Node IDs
  blastRadiusSummary?: {
    oneHop: number;
    twoHop: number;
    threeHop: number;
    criticalAssets: number;
  };
  recommendations: string[];
}

export interface SecurityEvent {
  id: string;
  type: string;
  severity: IncidentSeverity;
  timestamp: string;
  sourceAsset: string;
  targetAsset?: string;
  details: string;
}
