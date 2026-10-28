import { useEffect, useMemo, useState } from 'react'
import cytoscape from 'cytoscape'
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Line,
  LineChart,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import DashboardLayout from './dashboard-layout'
import {
  DashboardNavigationProvider,
  useDashboardNavigation,
} from './components/capitalio/navigation'

type GraphNode = { id: string; label: string; properties: Record<string, unknown> }
type GraphRelationship = { id: string; type: string; source: string; target: string; properties: Record<string, unknown> }
type GraphData = { mode: string; nodes: GraphNode[]; relationships: GraphRelationship[] }
type BlastAsset = GraphNode & { distance: number; paths: string[][]; supporting_relationships?: string[] }
type Finding = {
  id: string
  title: string
  severity: string
  affected_asset: string | null
  evidence_summary: string
  related_entities: string[]
  potential_impact: string
  next_step: string
  status: string
  classification: string
  risk_score: number
}
type Analytics = {
  metrics: Record<string, number>
  severity_distribution: { severity: string; count: number }[]
  alert_trends: { date: string; count: number }[]
  asset_distribution: { type: string; count: number }[]
  risk_distribution: { risk: string; count: number }[]
  attack_techniques: { id: string; name: unknown; mitre_id?: unknown; related_alerts: string[] }[]
  findings: Finding[]
  scoring: { formula: string; note: string }
}

const apiUrl = import.meta.env.VITE_API_URL ?? 'http://localhost:8000'
const assetLabels = new Set(['Device', 'IPAddress', 'Server', 'Application'])
const chartColors = ['#2563eb', '#7c3aed', '#f97316', '#16a34a', '#dc2626', '#0891b2']

async function fetchApi<T>(path: string): Promise<T> {
  let response: Response
  try {
    response = await fetch(`${apiUrl}${path}`)
  } catch (error) {
    throw new Error(`Unable to reach GraphOps API at ${apiUrl}. ${error instanceof Error ? error.message : 'Network request failed.'}`)
  }
  if (!response.ok) {
    const body = await response.json().catch(() => null)
    throw new Error(body?.detail ?? `API request failed (${response.status})`)
  }
  return response.json() as Promise<T>
}

function MetricCard({ label, value, detail }: { label: string; value: string | number; detail: string }) {
  return <article className="rounded-xl border bg-card p-5 shadow-xs"><p className="text-sm text-muted-foreground">{label}</p><p className="mt-2 text-3xl font-semibold tracking-tight">{value}</p><p className="mt-2 text-xs text-muted-foreground">{detail}</p></article>
}

function Panel({ title, children, className = '' }: { title: string; children: React.ReactNode; className?: string }) {
  return <section className={`rounded-xl border bg-card p-5 shadow-xs ${className}`}><div className="mb-4 flex items-center justify-between gap-3"><h3 className="font-semibold">{title}</h3></div>{children}</section>
}

function AttackGraph({ graph }: { graph: GraphData }) {
  const [host, setHost] = useState<HTMLDivElement | null>(null)
  const [labelFilter, setLabelFilter] = useState('All')
  const [relationshipFilter, setRelationshipFilter] = useState('All')
  const labels = useMemo(() => ['All', ...new Set(graph.nodes.map((node) => node.label))], [graph])
  const relationships = useMemo(() => ['All', ...new Set(graph.relationships.map((relation) => relation.type))], [graph])
  const visibleNodeIds = useMemo(() => new Set(graph.nodes.filter((node) => labelFilter === 'All' || node.label === labelFilter).map((node) => node.id)), [graph, labelFilter])

  useEffect(() => {
    if (!host) return
    const visibleRelationships = graph.relationships.filter((relation) => (relationshipFilter === 'All' || relation.type === relationshipFilter) && visibleNodeIds.has(relation.source) && visibleNodeIds.has(relation.target))
    const instance = cytoscape({
      container: host,
      elements: [
        ...graph.nodes.filter((node) => visibleNodeIds.has(node.id)).map((node) => ({ data: { id: node.id, label: String(node.properties.name ?? node.properties.hostname ?? node.id), kind: node.label } })),
        ...visibleRelationships.map((relation) => ({ data: { id: relation.id, source: relation.source, target: relation.target, label: relation.type } })),
      ],
      layout: { name: 'cose', animate: false },
      style: [
        { selector: 'node', style: { label: 'data(label)', 'background-color': '#2563eb', color: '#1e293b', 'font-size': 9, 'text-valign': 'bottom', 'text-margin-y': 7 } },
        { selector: 'node[kind = "Server"]', style: { 'background-color': '#7c3aed' } },
        { selector: 'node[kind = "Alert"]', style: { 'background-color': '#dc2626' } },
        { selector: 'node[kind = "Vulnerability"]', style: { 'background-color': '#f97316' } },
        { selector: 'edge', style: { width: 1.5, 'line-color': '#cbd5e1', 'target-arrow-color': '#94a3b8', 'target-arrow-shape': 'triangle', label: 'data(label)', color: '#64748b', 'font-size': 7, 'curve-style': 'bezier' } },
      ],
    })
    return () => instance.destroy()
  }, [graph, host, relationshipFilter, visibleNodeIds])

  return <div className="space-y-3"><div className="flex flex-wrap gap-2"><select className="h-9 rounded-md border bg-background px-2 text-sm" value={labelFilter} onChange={(event) => setLabelFilter(event.target.value)}>{labels.map((label) => <option key={label}>{label}</option>)}</select><select className="h-9 rounded-md border bg-background px-2 text-sm" value={relationshipFilter} onChange={(event) => setRelationshipFilter(event.target.value)}>{relationships.map((relation) => <option key={relation}>{relation}</option>)}</select></div><div ref={setHost} className="h-[480px] w-full rounded-lg border bg-slate-50" aria-label="Interactive GraphOps attack graph" /></div>
}

function ChartEmpty({ message }: { message: string }) {
  return <div className="flex h-48 items-center justify-center rounded-lg border border-dashed text-sm text-muted-foreground">{message}</div>
}

function FindingsTable({ findings }: { findings: Finding[] }) {
  const [selected, setSelected] = useState<Finding | null>(null)
  return <><div className="overflow-x-auto"><table className="w-full text-left text-sm"><thead className="text-xs uppercase text-muted-foreground"><tr><th className="px-3 py-2">Finding</th><th className="px-3 py-2">Severity</th><th className="px-3 py-2">Asset</th><th className="px-3 py-2">Risk</th><th className="px-3 py-2">Status</th></tr></thead><tbody className="divide-y">{findings.map((finding) => <tr key={finding.id} className="cursor-pointer hover:bg-muted/50" onClick={() => setSelected(finding)}><td className="px-3 py-3"><p className="font-medium">{finding.title}</p><p className="text-xs text-muted-foreground">{finding.classification}</p></td><td className="px-3 py-3 capitalize">{finding.severity}</td><td className="px-3 py-3 text-xs">{finding.affected_asset ?? 'Unassigned'}</td><td className="px-3 py-3 font-semibold">{finding.risk_score}</td><td className="px-3 py-3 capitalize">{finding.status}</td></tr>)}</tbody></table></div>{selected && <div className="mt-4 rounded-lg border bg-muted/30 p-4 text-sm"><div className="flex justify-between gap-3"><strong>{selected.title}</strong><button className="text-muted-foreground" onClick={() => setSelected(null)}>Close</button></div><p className="mt-3"><b>Evidence:</b> {selected.evidence_summary}</p><p className="mt-2"><b>Potential impact:</b> {selected.potential_impact}</p><p className="mt-2"><b>Next step:</b> {selected.next_step}</p><p className="mt-2 text-xs text-muted-foreground">Related entities: {selected.related_entities.join(', ') || 'None'}</p></div>}</>
}

function Overview({ analytics }: { analytics: Analytics }) {
  const { metrics, severity_distribution, alert_trends, asset_distribution, risk_distribution, findings, scoring } = analytics
  return <div className="space-y-6 p-6 md:p-8"><div><p className="text-sm text-muted-foreground">SOC command center</p><h2 className="mt-1 text-2xl font-semibold tracking-tight">Security overview</h2><p className="mt-2 text-sm text-muted-foreground">Live graph analytics. Reachability is not evidence of confirmed compromise.</p></div><div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3"><MetricCard label="Total graph entities" value={metrics.total_entities} detail="Nodes returned by Neo4j" /><MetricCard label="Active security alerts" value={metrics.active_alerts} detail="Alert nodes in the graph" /><MetricCard label="Critical assets at risk" value={metrics.critical_assets_at_risk} detail="Criticality from asset properties" /><MetricCard label="Potential attack paths" value={metrics.potential_attack_paths} detail="Routes from evidenced compromised assets" /><MetricCard label="Reachable within 1–3 hops" value={metrics.reachable_assets_1_to_3_hops} detail="Unique asset nodes" /><MetricCard label="High-risk identities" value={metrics.high_risk_identities} detail="Admin/service identities" /></div><div className="grid gap-5 lg:grid-cols-2"><Panel title="Alert severity distribution"><ResponsiveContainer width="100%" height={240}><BarChart data={severity_distribution}><CartesianGrid strokeDasharray="3 3" /><XAxis dataKey="severity" /><YAxis allowDecimals={false} /><Tooltip /><Bar dataKey="count" fill="#2563eb" radius={[4, 4, 0, 0]} /></BarChart></ResponsiveContainer></Panel><Panel title="Alert trend"><ResponsiveContainer width="100%" height={240}><LineChart data={alert_trends}><CartesianGrid strokeDasharray="3 3" /><XAxis dataKey="date" /><YAxis allowDecimals={false} /><Tooltip /><Line type="monotone" dataKey="count" stroke="#7c3aed" strokeWidth={3} /></LineChart></ResponsiveContainer></Panel><Panel title="Asset distribution"><ResponsiveContainer width="100%" height={260}><PieChart><Pie data={asset_distribution} dataKey="count" nameKey="type" outerRadius={90} label>{asset_distribution.map((entry, index) => <Cell key={entry.type} fill={chartColors[index % chartColors.length]} />)}</Pie><Tooltip /></PieChart></ResponsiveContainer></Panel><Panel title="Risk distribution"><ResponsiveContainer width="100%" height={260}><BarChart data={risk_distribution}><CartesianGrid strokeDasharray="3 3" /><XAxis dataKey="risk" /><YAxis allowDecimals={false} /><Tooltip /><Bar dataKey="count" fill="#f97316" radius={[4, 4, 0, 0]} /></BarChart></ResponsiveContainer></Panel></div><Panel title="Prioritized threat findings"><FindingsTable findings={findings} /></Panel><Panel title="Risk scoring methodology"><p className="text-sm text-muted-foreground">{scoring.formula}</p><p className="mt-2 text-xs text-muted-foreground">{scoring.note}</p></Panel></div>
}

function GraphOpsPage() {
  const { pathname } = useDashboardNavigation()
  const [graph, setGraph] = useState<GraphData | null>(null)
  const [analytics, setAnalytics] = useState<Analytics | null>(null)
  const [blastAssets, setBlastAssets] = useState<BlastAsset[]>([])
  const [selectedId, setSelectedId] = useState('device:ws-001')
  const [hops, setHops] = useState(1)
  const [error, setError] = useState('')

  useEffect(() => {
    Promise.all([fetchApi<GraphData>('/api/graph'), fetchApi<{ analytics: Analytics }>('/api/analytics')])
      .then(([graphResponse, analyticsResponse]) => { setGraph(graphResponse); setAnalytics(analyticsResponse.analytics) })
      .catch((reason: Error) => setError(reason.message))
  }, [])
  useEffect(() => {
    if (pathname !== '/blast-radius' || !graph) return
    fetchApi<{ assets: BlastAsset[] }>(`/api/blast-radius?asset_id=${encodeURIComponent(selectedId)}&hops=${hops}`)
      .then((response) => setBlastAssets(response.assets))
      .catch((reason: Error) => setError(reason.message))
  }, [graph, hops, pathname, selectedId])

  if (error) return <div className="p-6 md:p-8"><div className="rounded-xl border border-destructive/40 bg-destructive/10 p-5 text-sm text-destructive"><strong>GraphOps API unavailable</strong><p className="mt-1">{error}</p><p className="mt-2 text-xs">No demo data was substituted. Connect Neo4j or use the explicit legacy demo route.</p></div></div>
  if (!graph || !analytics) return <div className="p-8 text-sm text-muted-foreground">Loading security analytics…</div>

  if (pathname === '/attack-graph') return <div className="space-y-6 p-6 md:p-8"><div><p className="text-sm text-muted-foreground">Relationship explorer</p><h2 className="mt-1 text-2xl font-semibold tracking-tight">Interactive attack graph</h2><p className="mt-2 text-sm text-muted-foreground">Directional relationships and evidence-aware entity styling.</p></div><AttackGraph graph={graph} /></div>
  if (pathname === '/blast-radius') {
    const assets = graph.nodes.filter((node) => assetLabels.has(node.label))
    return <div className="space-y-6 p-6 md:p-8"><div><p className="text-sm text-muted-foreground">Evidence-aware analysis</p><h2 className="mt-1 text-2xl font-semibold tracking-tight">Blast radius containment</h2><p className="mt-2 text-sm text-muted-foreground">Reachability and minimum hop distance, not a compromise verdict.</p></div><div className="flex flex-wrap gap-2"><select className="h-10 rounded-md border bg-background px-3 text-sm" value={selectedId} onChange={(event) => setSelectedId(event.target.value)}>{assets.map((asset) => <option key={asset.id} value={asset.id}>{String(asset.properties.hostname ?? asset.properties.name ?? asset.id)}</option>)}</select>{[1, 2, 3].map((value) => <button key={value} className={`h-10 rounded-md border px-4 text-sm ${hops === value ? 'bg-primary text-primary-foreground' : 'bg-background'}`} onClick={() => setHops(value)}>{value} hop{value > 1 ? 's' : ''}</button>)}</div><Panel title={`${blastAssets.length} reachable assets`}><div className="divide-y">{blastAssets.map((asset) => <div className="flex items-center justify-between gap-4 py-3" key={asset.id}><div><p className="font-medium">{String(asset.properties.hostname ?? asset.properties.name ?? asset.id)}</p><p className="text-xs text-muted-foreground">{asset.label} · {asset.id}</p></div><span className="rounded-full bg-primary/10 px-3 py-1 text-xs text-primary">{asset.distance} hop{asset.distance > 1 ? 's' : ''}</span></div>)}{!blastAssets.length && <ChartEmpty message="No reachable assets within the selected hop limit." />}</div></Panel></div>
  }
  if (pathname === '/analytics') return <Overview analytics={analytics} />
  if (pathname === '/alerts') return <div className="space-y-6 p-6 md:p-8"><h2 className="text-2xl font-semibold">Threat findings</h2><Panel title={`${analytics.findings.length} prioritized findings`}><FindingsTable findings={analytics.findings} /></Panel></div>
  if (pathname === '/sources') return <div className="space-y-6 p-6 md:p-8"><h2 className="text-2xl font-semibold">Data sources</h2><Panel title="Neo4j graph"><p className="text-sm text-emerald-600">Connected and queried through FastAPI</p><p className="mt-2 text-xs text-muted-foreground">Mode: {graph.mode}. Metrics and findings are derived from returned graph records.</p></Panel></div>
  return <Overview analytics={analytics} />
}

export default function GraphOpsDashboard() {
  return <DashboardNavigationProvider><DashboardLayout><GraphOpsPage /></DashboardLayout></DashboardNavigationProvider>
}
