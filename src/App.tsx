import { useEffect, useMemo, useRef, useState } from 'react'
import cytoscape, { type Core, type ElementDefinition } from 'cytoscape'
import {
  Activity, AlertTriangle, Boxes, ChevronRight, Database, Gauge, GitBranch,
  Network, RefreshCw, Search, Server, ShieldAlert, ShieldCheck,
} from 'lucide-react'

type Page = 'overview' | 'graph' | 'blast-radius' | 'threat-hunting' | 'incidents' | 'assets' | 'sources'
type Mode = 'api' | 'demo'
type GraphNode = { id: string; label: string; properties: Record<string, unknown> }
type GraphRelationship = { id: string; type: string; source: string; target: string; properties: Record<string, unknown> }
type GraphData = { mode: Mode; nodes: GraphNode[]; relationships: GraphRelationship[] }
type BlastAsset = { id: string; label: string; properties: Record<string, unknown>; distance: number; paths: string[][]; supporting_relationships?: string[][] | string[] }

const apiUrl = import.meta.env.VITE_API_URL ?? 'http://localhost:8000'
const demoGraph: GraphData = {
  mode: 'demo',
  nodes: [
    { id: 'user:alice', label: 'User', properties: { name: 'Alice Chen', role: 'analyst' } },
    { id: 'device:ws-001', label: 'Device', properties: { hostname: 'WS-001', compromised: true } },
    { id: 'device:ws-002', label: 'Device', properties: { hostname: 'WS-002', compromised: false } },
    { id: 'ip:10.0.1.10', label: 'IPAddress', properties: { address: '10.0.1.10' } },
    { id: 'server:ad-01', label: 'Server', properties: { hostname: 'AD-01', criticality: 'critical' } },
    { id: 'server:files-01', label: 'Server', properties: { hostname: 'FILES-01', criticality: 'high' } },
    { id: 'app:portal', label: 'Application', properties: { name: 'Employee Portal' } },
    { id: 'alert:2026-0001', label: 'Alert', properties: { severity: 'high', detected_at: '2026-01-15T08:00:00Z' } },
    { id: 'vuln:cve-2025-0001', label: 'Vulnerability', properties: { cve: 'CVE-2025-0001', severity: 'high' } },
    { id: 'technique:T1078', label: 'AttackTechnique', properties: { name: 'Valid Accounts', mitre_id: 'T1078' } },
  ],
  relationships: [
    { id: 'rel:alice-uses-ws1', type: 'USES', source: 'user:alice', target: 'device:ws-001', properties: {} },
    { id: 'rel:alice-uses-ws2', type: 'USES', source: 'user:alice', target: 'device:ws-002', properties: {} },
    { id: 'rel:ws1-has-ip', type: 'HAS_IP', source: 'device:ws-001', target: 'ip:10.0.1.10', properties: {} },
    { id: 'rel:ws1-connects-ad', type: 'CONNECTS_TO', source: 'device:ws-001', target: 'server:ad-01', properties: { protocol: 'SMB' } },
    { id: 'rel:ws1-connects-files', type: 'CONNECTS_TO', source: 'device:ws-001', target: 'server:files-01', properties: { protocol: 'SMB' } },
    { id: 'rel:files-runs-portal', type: 'RUNS', source: 'server:files-01', target: 'app:portal', properties: {} },
    { id: 'rel:alert-affects-ws1', type: 'AFFECTS', source: 'alert:2026-0001', target: 'device:ws-001', properties: {} },
    { id: 'rel:alert-uses-t1078', type: 'USES_TECHNIQUE', source: 'alert:2026-0001', target: 'technique:T1078', properties: {} },
    { id: 'rel:ws1-has-vuln', type: 'HAS_VULNERABILITY', source: 'device:ws-001', target: 'vuln:cve-2025-0001', properties: {} },
  ],
}

const pages: { id: Page; label: string; icon: typeof Activity }[] = [
  { id: 'overview', label: 'Overview', icon: Gauge },
  { id: 'graph', label: 'Attack graph', icon: Network },
  { id: 'blast-radius', label: 'Blast radius', icon: GitBranch },
  { id: 'threat-hunting', label: 'Threat hunting', icon: Search },
  { id: 'incidents', label: 'Incidents', icon: ShieldAlert },
  { id: 'assets', label: 'Asset inventory', icon: Boxes },
  { id: 'sources', label: 'Data sources', icon: Database },
]

async function apiFetch<T>(path: string): Promise<T> {
  const response = await fetch(`${apiUrl}${path}`)
  if (!response.ok) {
    const detail = await response.json().catch(() => null)
    throw new Error(detail?.detail ?? `API request failed (${response.status})`)
  }
  return response.json() as Promise<T>
}

function ModeBadge({ mode }: { mode: Mode }) {
  return <span className={`mode-badge ${mode}`}><span className="status-dot" />{mode === 'demo' ? 'Demo mode' : 'Neo4j-backed'}</span>
}

function StateCard({ title, message, action }: { title: string; message: string; action?: () => void }) {
  return <div className="state-card" role="status"><AlertTriangle size={20} /><div><strong>{title}</strong><p>{message}</p>{action && <button className="button secondary" onClick={action}>Try again</button>}</div></div>
}

function GraphCanvas({ graph, selectedId, onSelect }: { graph: GraphData; selectedId?: string; onSelect: (id: string) => void }) {
  const container = useRef<HTMLDivElement>(null)
  const instance = useRef<Core | null>(null)
  const elements = useMemo<ElementDefinition[]>(() => [
    ...graph.nodes.map((node) => ({ data: { id: node.id, label: String(node.properties.name ?? node.properties.hostname ?? node.id), kind: node.label.toLowerCase() } })),
    ...graph.relationships.map((edge) => ({ data: { id: edge.id, source: edge.source, target: edge.target, label: edge.type } })),
  ], [graph])
  useEffect(() => {
    if (!container.current) return
    instance.current?.destroy()
    instance.current = cytoscape({
      container: container.current, elements, layout: { name: 'cose', animate: false },
      style: [
        { selector: 'node', style: { label: 'data(label)', 'background-color': '#22d3ee', color: '#e2e8f0', 'font-size': '9px', 'text-wrap': 'wrap', 'text-max-width': '90px', 'text-valign': 'bottom', 'text-margin-y': 7 } },
        { selector: 'node[kind = "alert"]', style: { 'background-color': '#fb7185' } },
        { selector: 'node[kind = "server"]', style: { 'background-color': '#a78bfa' } },
        { selector: 'node[kind = "vulnerability"]', style: { 'background-color': '#f59e0b' } },
        { selector: 'edge', style: { width: 1.5, 'line-color': '#475569', 'target-arrow-color': '#475569', 'target-arrow-shape': 'triangle', label: 'data(label)', color: '#94a3b8', 'font-size': 7, 'curve-style': 'bezier' } },
        { selector: 'node:selected', style: { 'border-width': 3, 'border-color': '#f8fafc' } },
      ],
    })
    instance.current.on('tap', 'node', (event) => onSelect(event.target.id()))
    return () => instance.current?.destroy()
  }, [elements, onSelect])
  useEffect(() => { if (selectedId) instance.current?.getElementById(selectedId).select() }, [selectedId])
  return <div className="graph-canvas" ref={container} aria-label="Interactive security relationship graph" />
}

function App() {
  const [page, setPage] = useState<Page>('overview')
  const [mode, setMode] = useState<Mode>(() => new URLSearchParams(location.search).get('demo') === 'true' ? 'demo' : 'api')
  const [graph, setGraph] = useState<GraphData | null>(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)
  const [selectedId, setSelectedId] = useState('device:ws-001')
  const [hops, setHops] = useState(1)
  const [blastAssets, setBlastAssets] = useState<BlastAsset[]>([])
  const [blastLoading, setBlastLoading] = useState(false)
  const [blastError, setBlastError] = useState('')

  const loadGraph = () => {
    setLoading(true); setError('')
    if (mode === 'demo') { setGraph(demoGraph); setLoading(false); return }
    apiFetch<GraphData>('/api/graph').then(setGraph).catch((err: Error) => { setGraph(null); setError(err.message) }).finally(() => setLoading(false))
  }
  useEffect(loadGraph, [mode])
  useEffect(() => {
    if (!graph || mode === 'demo') {
      if (mode === 'demo' && graph) setBlastAssets(buildDemoBlast(graph, selectedId, hops))
      return
    }
    setBlastLoading(true); setBlastError('')
    apiFetch<{ assets: BlastAsset[] }>(`/api/blast-radius?asset_id=${encodeURIComponent(selectedId)}&hops=${hops}`)
      .then((data) => setBlastAssets(data.assets)).catch((err: Error) => { setBlastAssets([]); setBlastError(err.message) }).finally(() => setBlastLoading(false))
  }, [graph, mode, selectedId, hops])

  const assets = graph?.nodes.filter((node) => ['Device', 'IPAddress', 'Server', 'Application'].includes(node.label)) ?? []
  const title = pages.find((item) => item.id === page)?.label ?? 'Overview'
  return <div className="app-shell">
    <aside className="sidebar">
      <div className="brand"><div className="brand-mark"><Activity size={21} /></div><div><b>GRAPHOPS</b><small>Security graph operations</small></div></div>
      <nav aria-label="Primary navigation">{pages.map(({ id, label, icon: Icon }) => <button key={id} className={page === id ? 'nav-item active' : 'nav-item'} onClick={() => setPage(id)}><Icon size={17} />{label}</button>)}</nav>
      <div className="sidebar-foot"><ModeBadge mode={mode} /><p>API: {apiUrl}</p><button className="button secondary full" onClick={() => setMode(mode === 'demo' ? 'api' : 'demo')}><RefreshCw size={14} />{mode === 'demo' ? 'Use API mode' : 'Enter demo mode'}</button></div>
    </aside>
    <main className="main-content">
      <header className="topbar"><div><span className="eyebrow">SECURITY OPERATIONS / {title.toUpperCase()}</span><h1>{title}</h1></div><div className="topbar-actions"><ModeBadge mode={mode} /><button className="icon-button" title="Reload graph data" onClick={loadGraph}><RefreshCw size={17} /></button></div></header>
      {error && mode === 'api' && <StateCard title="Backend unavailable" message={`${error} No findings are shown. Connect Neo4j or explicitly enter demo mode.`} action={loadGraph} />}
      {loading ? <div className="loading"><span className="spinner" />Loading graph data…</div> : page === 'overview' ? <Overview graph={graph} mode={mode} onNavigate={setPage} /> : page === 'graph' ? <GraphPage graph={graph} selectedId={selectedId} onSelect={setSelectedId} /> : page === 'blast-radius' ? <BlastPage graph={graph} assets={assets} selectedId={selectedId} setSelectedId={setSelectedId} hops={hops} setHops={setHops} blastAssets={blastAssets} loading={blastLoading} error={blastError} /> : <PlaceholderPage page={page} graph={graph} mode={mode} />}
    </main>
  </div>
}

function Overview({ graph, mode, onNavigate }: { graph: GraphData | null; mode: Mode; onNavigate: (page: Page) => void }) {
  const nodes = graph?.nodes ?? []
  const alerts = nodes.filter((node) => node.label === 'Alert')
  const servers = nodes.filter((node) => node.label === 'Server')
  return <div className="page-body"><div className="welcome"><div><span className="eyebrow">COMMAND CENTER</span><h2>Understand your environment before you act.</h2><p>Trace relationships, inspect evidence, and measure potential blast radius without confusing reachability for compromise.</p></div><ModeBadge mode={mode} /></div><div className="metric-grid"><Metric icon={Boxes} label="Graph entities" value={nodes.length} /><Metric icon={AlertTriangle} label="Alerts" value={alerts.length} tone="warning" /><Metric icon={Server} label="Servers" value={servers.length} tone="purple" /><Metric icon={ShieldCheck} label="Evidence posture" value={mode === 'demo' ? 'Sample' : 'Live'} tone="green" /></div><div className="section-grid"><section className="panel"><div className="panel-heading"><div><span className="eyebrow">NEXT INVESTIGATION</span><h3>Attack graph</h3></div><button className="text-button" onClick={() => onNavigate('graph')}>Explore <ChevronRight size={15} /></button></div><p className="muted">Select an entity to inspect supporting relationships and candidate routes to critical assets.</p><button className="button primary" onClick={() => onNavigate('graph')}><Network size={15} />Open interactive graph</button></section><section className="panel"><div className="panel-heading"><div><span className="eyebrow">DATA CONTRACT</span><h3>Connection status</h3></div></div><div className="status-row"><span className={`status-dot ${mode === 'demo' ? 'amber' : 'green'}`} />{mode === 'demo' ? 'Explicit demo data' : graph ? 'Neo4j API connected' : 'API connection failed'}</div><p className="muted">Only data returned by the selected mode is displayed. No findings are synthesized after a failure.</p><button className="text-button" onClick={() => onNavigate('sources')}>View data sources <ChevronRight size={15} /></button></section></div></div>
}

function Metric({ icon: Icon, label, value, tone = '' }: { icon: typeof Activity; label: string; value: string | number; tone?: string }) { return <div className="metric"><div className={`metric-icon ${tone}`}><Icon size={17} /></div><div><span>{label}</span><strong>{value}</strong></div></div> }

function GraphPage({ graph, selectedId, onSelect }: { graph: GraphData | null; selectedId: string; onSelect: (id: string) => void }) {
  const selected = graph?.nodes.find((node) => node.id === selectedId)
  if (!graph) return <div className="page-body"><StateCard title="No graph data" message="Connect the backend or explicitly enter demo mode to inspect relationships." /></div>
  return <div className="page-body"><div className="page-intro"><div><span className="eyebrow">RELATIONSHIP EXPLORER</span><h2>Interactive attack graph</h2><p>Click a node to inspect its identity. Edges show modeled relationships, not proof of compromise.</p></div></div><div className="graph-layout"><section className="panel graph-panel"><GraphCanvas graph={graph} selectedId={selectedId} onSelect={onSelect} /><div className="legend"><span><i className="legend-dot cyan" />Entity</span><span><i className="legend-dot purple" />Server</span><span><i className="legend-dot red" />Alert</span><span><i className="legend-dot amber" />Vulnerability</span></div></section><aside className="panel inspector"><span className="eyebrow">SELECTED ENTITY</span>{selected ? <><h3>{String(selected.properties.name ?? selected.properties.hostname ?? selected.id)}</h3><code>{selected.id}</code><div className="property-list"><div><span>Type</span><b>{selected.label}</b></div>{Object.entries(selected.properties).map(([key, value]) => <div key={key}><span>{key.replace('_', ' ')}</span><b>{String(value)}</b></div>)}</div></> : <p className="muted">Select a node on the graph.</p>}</aside></div></div>
}

function BlastPage({ graph, assets, selectedId, setSelectedId, hops, setHops, blastAssets, loading, error }: { graph: GraphData | null; assets: GraphNode[]; selectedId: string; setSelectedId: (id: string) => void; hops: number; setHops: (hops: number) => void; blastAssets: BlastAsset[]; loading: boolean; error: string }) {
  return <div className="page-body"><div className="page-intro"><div><span className="eyebrow">EVIDENCE-AWARE ANALYSIS</span><h2>Blast-radius analysis</h2><p>Reachable assets are grouped by minimum hop distance. This is topology analysis, not a compromise verdict.</p></div></div><section className="panel controls-panel"><label htmlFor="asset">Starting asset<select id="asset" value={selectedId} onChange={(event) => setSelectedId(event.target.value)} disabled={!assets.length}>{assets.map((asset) => <option key={asset.id} value={asset.id}>{String(asset.properties.hostname ?? asset.properties.name ?? asset.id)} · {asset.label}</option>)}</select></label><fieldset><legend>Hop limit</legend><div className="hop-options">{[1, 2, 3].map((value) => <button key={value} className={hops === value ? 'hop active' : 'hop'} onClick={() => setHops(value)} aria-pressed={hops === value}>{value} hop{value > 1 ? 's' : ''}</button>)}</div></fieldset></section>{error && <StateCard title="Blast-radius request failed" message={error} />}{loading ? <div className="loading"><span className="spinner" />Calculating reachable assets…</div> : graph && !blastAssets.length ? <StateCard title="No reachable assets" message="The API returned no assets within the selected hop limit." /> : <section className="panel results-panel"><div className="panel-heading"><div><span className="eyebrow">RESULTS</span><h3>{blastAssets.length} unique reachable assets</h3></div><span className="result-chip">≤ {hops} hops</span></div><div className="result-list">{blastAssets.map((asset) => <div className="result-item" key={asset.id}><div className="result-main"><span className="distance">{asset.distance}</span><div><strong>{String(asset.properties.hostname ?? asset.properties.name ?? asset.id)}</strong><small>{asset.label} · {asset.id}</small></div></div><div className="result-support"><span>Minimum distance: {asset.distance} hop{asset.distance > 1 ? 's' : ''}</span><span>{asset.paths.length} supporting path{asset.paths.length === 1 ? '' : 's'}</span><span>{Array.isArray(asset.supporting_relationships) ? asset.supporting_relationships.flat().length : 0} supporting relationship{Array.isArray(asset.supporting_relationships) && asset.supporting_relationships.flat().length === 1 ? '' : 's'}</span></div></div>)}</div></section>}</div>
}

function PlaceholderPage({ page, graph, mode }: { page: Page; graph: GraphData | null; mode: Mode }) {
  const copy: Record<Page, [string, string, typeof Activity]> = { 'threat-hunting': ['Threat hunting & alert correlation', 'Review alerts, affected assets, and mapped attack techniques from the connected graph.', Search], incidents: ['Incident investigation', 'Correlate affected assets, evidence, and candidate paths before assigning an incident conclusion.', ShieldAlert], assets: ['Asset inventory', 'Browse devices, IP addresses, servers, and applications represented in the graph.', Boxes], sources: ['Data sources & connection status', 'Understand which source is feeding this view and whether data is live or explicitly synthetic.', Database], overview: ['', '', Activity], graph: ['', '', Activity], 'blast-radius': ['', '', Activity] }
  const [heading, description, Icon] = copy[page]
  const rows = graph?.nodes.filter((node) => page === 'threat-hunting' ? node.label === 'Alert' || node.label === 'AttackTechnique' : page === 'assets' ? ['Device', 'IPAddress', 'Server', 'Application'].includes(node.label) : true) ?? []
  return <div className="page-body"><div className="page-intro"><div><span className="eyebrow">{mode === 'demo' ? 'DEMO DATASET' : 'API DATA'}</span><h2>{heading}</h2><p>{description}</p></div></div>{!graph ? <StateCard title="No data available" message="The API has not returned data. Enter demo mode to explore the deterministic sample dataset." /> : <section className="panel table-panel"><div className="panel-heading"><h3><Icon size={18} /> {rows.length} records</h3><ModeBadge mode={mode} /></div>{rows.length ? <div className="data-table">{rows.map((row) => <div className="table-row" key={row.id}><div><strong>{String(row.properties.name ?? row.properties.hostname ?? row.properties.cve ?? row.id)}</strong><small>{row.id}</small></div><span className="type-pill">{row.label}</span><span className="muted">{Object.entries(row.properties).slice(0, 2).map(([key, value]) => `${key}: ${value}`).join(' · ')}</span></div>)}</div> : <StateCard title="No records returned" message="The connected API returned an empty result for this view." />}</section>}</div>
}

function buildDemoBlast(graph: GraphData, startId: string, maxHops: number): BlastAsset[] {
  const allowedTypes = new Set(['HAS_IP', 'CONNECTS_TO', 'RUNS'])
  const assetLabels = new Set(['Device', 'IPAddress', 'Server', 'Application'])
  const distances = new Map<string, number>([[startId, 0]])
  const queue = [startId]
  while (queue.length) {
    const current = queue.shift()!
    const distance = distances.get(current)!
    if (distance >= maxHops) continue
    graph.relationships.filter((edge) => allowedTypes.has(edge.type) && (edge.source === current || edge.target === current)).forEach((edge) => {
      const next = edge.source === current ? edge.target : edge.source
      if (!distances.has(next)) { distances.set(next, distance + 1); queue.push(next) }
    })
  }
  return [...distances.entries()].filter(([id, distance]) => id !== startId && distance <= maxHops && assetLabels.has(graph.nodes.find((item) => item.id === id)?.label ?? '')).map(([id, distance]) => {
    const node = graph.nodes.find((item) => item.id === id)!
    const path = [startId, id]
    const supporting = graph.relationships
      .filter((edge) => (edge.source === startId && edge.target === id) || (edge.source === id && edge.target === startId))
      .map((edge) => edge.id)
    return { id, label: node.label, properties: node.properties, distance, paths: [path], supporting_relationships: supporting }
  }).sort((a, b) => a.distance - b.distance || a.id.localeCompare(b.id))
}

export default App
