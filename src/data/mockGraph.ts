import type { GraphData } from '../types/graph';

export const mockGraph: GraphData = {
  nodes: [
    { id: 'u1', label: 'admin_jsmith', type: 'user', criticality: 'high', riskScore: 85, metadata: { department: 'IT' } },
    { id: 'u2', label: 'finance_rdoe', type: 'user', criticality: 'medium', riskScore: 45, metadata: { department: 'Finance' } },
    { id: 'u3', label: 'svc_backup', type: 'user', criticality: 'critical', riskScore: 10, metadata: { type: 'Service Account' } },
    
    { id: 'e1', label: 'WKSTN-442', type: 'endpoint', criticality: 'low', riskScore: 75, metadata: { os: 'Windows 10', ip: '10.0.1.44' } },
    { id: 'e2', label: 'WKSTN-881', type: 'endpoint', criticality: 'low', riskScore: 20, metadata: { os: 'Windows 11', ip: '10.0.1.88' } },
    
    { id: 's1', label: 'SRV-FILE-01', type: 'server', criticality: 'medium', riskScore: 30, metadata: { os: 'Ubuntu 22.04', ip: '10.0.2.10' } },
    { id: 's2', label: 'SRV-AD-01', type: 'server', criticality: 'critical', riskScore: 15, metadata: { os: 'Windows Server 2022', ip: '10.0.2.2' } },
    { id: 's3', label: 'SRV-APP-PROD', type: 'server', criticality: 'high', riskScore: 40, metadata: { os: 'CentOS 7', ip: '10.0.2.50' } },
    
    { id: 'db1', label: 'DB-FINANCE-PROD', type: 'database', criticality: 'critical', riskScore: 12, metadata: { engine: 'PostgreSQL', sensitive: true } },
    { id: 'db2', label: 'DB-USERS-AUTH', type: 'database', criticality: 'critical', riskScore: 5, metadata: { engine: 'Redis', sensitive: true } },
    
    { id: 'v1', label: 'CVE-2021-44228', type: 'vulnerability', criticality: 'critical', riskScore: 100, metadata: { name: 'Log4Shell' } },
    { id: 'v2', label: 'CVE-2023-23397', type: 'vulnerability', criticality: 'high', riskScore: 80, metadata: { name: 'Outlook PrivEsc' } },
  ],
  edges: [
    { id: 'rel1', source: 'u1', target: 'e1', type: 'LOGGED_INTO', metadata: {} },
    { id: 'rel2', source: 'u2', target: 'e2', type: 'LOGGED_INTO', metadata: {} },
    { id: 'rel3', source: 'e1', target: 's1', type: 'CONNECTS_TO', metadata: { protocol: 'SMB' }, isSuspicious: true },
    { id: 'rel4', source: 's1', target: 'db1', type: 'ACCESSES', metadata: { port: 5432 } },
    { id: 'rel5', source: 'u1', target: 's2', type: 'ADMIN_ON', metadata: {} },
    { id: 'rel6', source: 's2', target: 'db2', type: 'CONTAINS_DATA', metadata: {} },
    { id: 'rel7', source: 's3', target: 'v1', type: 'HAS_VULNERABILITY', metadata: {} },
    { id: 'rel8', source: 'e1', target: 's3', type: 'CONNECTS_TO', metadata: { protocol: 'HTTP' } },
    { id: 'rel9', source: 'u3', target: 's2', type: 'LOGGED_INTO', metadata: {} },
    { id: 'rel10', source: 'e2', target: 's1', type: 'CONNECTS_TO', metadata: { protocol: 'SSH' } },
  ]
};
