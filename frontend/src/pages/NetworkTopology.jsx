import React, { useEffect, useRef, useState, useMemo, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import axios from 'axios';
import { useCaptureStore } from '../store/captureStore';
import { Card } from '../components/ui/Card';
import { ZoomIn, ZoomOut, RefreshCw, Layers, Maximize2, Filter } from 'lucide-react';

const api = axios.create({ baseURL: '' });

// ── Color palette per protocol ─────────────────────────────────────────────────
const PROTO_COLORS = {
  6:   { stroke: '#3b82f6', fill: '#eff6ff' },   // TCP  – blue
  17:  { stroke: '#8b5cf6', fill: '#f5f3ff' },   // UDP  – purple
  1:   { stroke: '#f59e0b', fill: '#fffbeb' },   // ICMP – amber
  0:   { stroke: '#64748b', fill: '#f8fafc' },   // other
};
const protoName = (p) => ({ 6: 'TCP', 17: 'UDP', 1: 'ICMP' }[p] || 'OTHER');

// ── Very simple spring-force layout (no external library) ─────────────────────
function runForceLayout(nodes, edges, iterations = 200) {
  const n = nodes.length;
  if (n === 0) return nodes;

  const k = Math.sqrt((600 * 500) / Math.max(n, 1));

  // Clone positions
  let pos = nodes.map(nd => ({ ...nd }));

  for (let iter = 0; iter < iterations; iter++) {
    const temp = 30 * (1 - iter / iterations);   // cooling

    // Repulsion between all node pairs
    const disp = pos.map(() => ({ x: 0, y: 0 }));
    for (let i = 0; i < n; i++) {
      for (let j = i + 1; j < n; j++) {
        let dx = pos[i].x - pos[j].x;
        let dy = pos[i].y - pos[j].y;
        const dist = Math.max(1, Math.sqrt(dx * dx + dy * dy));
        const f = (k * k) / dist;
        dx = (dx / dist) * f;
        dy = (dy / dist) * f;
        disp[i].x += dx; disp[i].y += dy;
        disp[j].x -= dx; disp[j].y -= dy;
      }
    }

    // Attraction along edges
    for (const e of edges) {
      const si = pos.findIndex(p => p.id === e.source);
      const ti = pos.findIndex(p => p.id === e.target);
      if (si < 0 || ti < 0) continue;
      let dx = pos[si].x - pos[ti].x;
      let dy = pos[si].y - pos[ti].y;
      const dist = Math.max(1, Math.sqrt(dx * dx + dy * dy));
      const f = (dist * dist) / k;
      dx = (dx / dist) * f;
      dy = (dy / dist) * f;
      disp[si].x -= dx; disp[si].y -= dy;
      disp[ti].x += dx; disp[ti].y += dy;
    }

    // Apply displacements with temp
    for (let i = 0; i < n; i++) {
      const dm = Math.max(1, Math.sqrt(disp[i].x ** 2 + disp[i].y ** 2));
      pos[i].x = Math.max(40, Math.min(560, pos[i].x + (disp[i].x / dm) * Math.min(dm, temp)));
      pos[i].y = Math.max(40, Math.min(460, pos[i].y + (disp[i].y / dm) * Math.min(dm, temp)));
    }
  }

  return pos;
}

// ── Build graph from flows ─────────────────────────────────────────────────────
function buildGraph(flows) {
  const nodeMap = {};
  const edgeMap = {};

  for (const f of flows) {
    const src = f.src_ip;
    const dst = f.dst_ip;
    if (!src || !dst || src === dst) continue;

    // Track nodes
    if (!nodeMap[src]) nodeMap[src] = { id: src, bytes: 0, flows: 0, protocols: new Set() };
    if (!nodeMap[dst]) nodeMap[dst] = { id: dst, bytes: 0, flows: 0, protocols: new Set() };
    nodeMap[src].bytes += f.payload_bytes || 0;
    nodeMap[src].flows++;
    nodeMap[dst].bytes += f.payload_bytes || 0;
    nodeMap[dst].flows++;
    if (f.protocol) {
      nodeMap[src].protocols.add(f.protocol);
      nodeMap[dst].protocols.add(f.protocol);
    }

    // Track edges (bidirectional key, lower IP first)
    const [a, b] = [src, dst].sort();
    const key = `${a}→${b}`;
    if (!edgeMap[key]) {
      edgeMap[key] = { id: key, source: src, target: dst, bytes: 0, flows: 0, protocol: f.protocol };
    }
    edgeMap[key].bytes += f.payload_bytes || 0;
    edgeMap[key].flows++;
  }

  const nodes = Object.values(nodeMap).map(nd => ({
    ...nd,
    protocols: [...nd.protocols],
    x: 80 + Math.random() * 440,
    y: 80 + Math.random() * 340,
  }));
  const edges = Object.values(edgeMap);

  return { nodes, edges };
}

const formatBytes = (b) => {
  if (!b) return '0 B';
  if (b >= 1e9) return (b / 1e9).toFixed(1) + ' GB';
  if (b >= 1e6) return (b / 1e6).toFixed(1) + ' MB';
  if (b >= 1e3) return (b / 1e3).toFixed(1) + ' KB';
  return b + ' B';
};

const EmptySessionState = ({ navigate }) => (
  <div className="flex flex-col items-center justify-center h-96 text-center">
    <Layers className="w-12 h-12 text-slate-300 mb-4" />
    <h2 className="text-lg font-semibold text-slate-700 mb-2">No Session Selected</h2>
    <p className="text-slate-500 text-sm">Select a capture session to view network topology.</p>
    <button onClick={() => navigate('/sessions')} className="mt-4 px-4 py-2 bg-indigo-600 text-white rounded-md text-sm font-medium hover:bg-indigo-700">
      Go to Sessions
    </button>
  </div>
);

// ── SVG Topology component ─────────────────────────────────────────────────────
const TopologyGraph = ({ nodes, edges }) => {
  const svgRef = useRef(null);
  const [positions, setPositions] = useState(null);
  const [dragging, setDragging] = useState(null);
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [hoveredNode, setHoveredNode] = useState(null);
  const [selectedNode, setSelectedNode] = useState(null);

  // Run force layout once on mount or when nodes change
  useEffect(() => {
    if (!nodes.length) return;
    const laid = runForceLayout(nodes, edges, 250);
    setPositions(laid.reduce((m, n) => { m[n.id] = { x: n.x, y: n.y }; return m; }, {}));
  }, [nodes.length]);

  const pos = positions || {};

  // Node radius proportional to bytes (log scale)
  const nodeRadius = useCallback((nd) => {
    if (!nd.bytes) return 12;
    return Math.max(10, Math.min(28, 10 + Math.log2(nd.bytes + 1) * 1.5));
  }, []);

  // Edge stroke width proportional to flow count
  const edgeWidth = (e) => Math.max(1, Math.min(6, 1 + Math.log2(e.flows + 1)));

  // Drag handlers
  const onMouseDownNode = (e, id) => {
    e.stopPropagation();
    setDragging(id);
    setSelectedNode(id);
  };

  const onMouseMove = (e) => {
    if (!dragging) return;
    const rect = svgRef.current.getBoundingClientRect();
    const x = (e.clientX - rect.left - pan.x) / zoom;
    const y = (e.clientY - rect.top - pan.y) / zoom;
    setPositions(prev => ({ ...prev, [dragging]: { x, y } }));
  };

  const onMouseUp = () => setDragging(null);

  const nodesByConnections = useMemo(() => {
    if (!selectedNode) return [];
    return edges
      .filter(e => e.source === selectedNode || e.target === selectedNode)
      .map(e => ({ peer: e.source === selectedNode ? e.target : e.source, bytes: e.bytes, flows: e.flows, protocol: e.protocol }));
  }, [selectedNode, edges]);

  const selectedNodeData = nodes.find(n => n.id === selectedNode);

  return (
    <div className="flex h-full min-h-[520px]">
      {/* Main SVG Canvas */}
      <div className="flex-1 relative bg-slate-50 rounded-l-lg border border-slate-200 overflow-hidden">
        {/* Toolbar */}
        <div className="absolute top-3 right-3 z-10 flex flex-col space-y-1.5">
          <button onClick={() => setZoom(z => Math.min(3, z * 1.2))} className="p-1.5 bg-white border border-slate-200 rounded shadow-sm hover:bg-slate-50">
            <ZoomIn className="w-4 h-4 text-slate-600" />
          </button>
          <button onClick={() => setZoom(z => Math.max(0.3, z / 1.2))} className="p-1.5 bg-white border border-slate-200 rounded shadow-sm hover:bg-slate-50">
            <ZoomOut className="w-4 h-4 text-slate-600" />
          </button>
          <button onClick={() => { setZoom(1); setPan({ x: 0, y: 0 }); }} className="p-1.5 bg-white border border-slate-200 rounded shadow-sm hover:bg-slate-50">
            <Maximize2 className="w-4 h-4 text-slate-600" />
          </button>
        </div>

        {/* Protocol legend */}
        <div className="absolute bottom-3 left-3 z-10 bg-white/90 border border-slate-200 rounded px-3 py-2 text-xs space-y-1">
          {Object.entries({ 6: 'TCP', 17: 'UDP', 1: 'ICMP', 0: 'OTHER' }).map(([p, name]) => (
            <div key={p} className="flex items-center space-x-2">
              <div className="w-3 h-3 rounded-full border-2" style={{ borderColor: PROTO_COLORS[p]?.stroke, backgroundColor: PROTO_COLORS[p]?.fill }} />
              <span className="text-slate-500">{name}</span>
            </div>
          ))}
        </div>

        <svg
          ref={svgRef}
          className="w-full h-full cursor-grab active:cursor-grabbing"
          onMouseMove={onMouseMove}
          onMouseUp={onMouseUp}
          onMouseLeave={onMouseUp}
        >
          <g transform={`translate(${pan.x},${pan.y}) scale(${zoom})`}>
            {/* Edges */}
            <g>
              {edges.map(e => {
                const sp = pos[e.source];
                const tp = pos[e.target];
                if (!sp || !tp) return null;
                const isHighlighted = selectedNode && (e.source === selectedNode || e.target === selectedNode);
                const color = PROTO_COLORS[e.protocol] || PROTO_COLORS[0];
                return (
                  <line
                    key={e.id}
                    x1={sp.x} y1={sp.y} x2={tp.x} y2={tp.y}
                    stroke={isHighlighted ? color.stroke : '#cbd5e1'}
                    strokeWidth={isHighlighted ? edgeWidth(e) + 1 : edgeWidth(e)}
                    strokeOpacity={selectedNode && !isHighlighted ? 0.15 : 0.7}
                    strokeDasharray={e.protocol === 17 ? '4 2' : undefined}
                  />
                );
              })}
            </g>

            {/* Nodes */}
            <g>
              {nodes.map(nd => {
                const p = pos[nd.id];
                if (!p) return null;
                const r = nodeRadius(nd);
                const isSelected = selectedNode === nd.id;
                const isHovered = hoveredNode === nd.id;
                const isPeerOfSelected = selectedNode && nodesByConnections.some(c => c.peer === nd.id);
                const isDimmed = selectedNode && !isSelected && !isPeerOfSelected;
                const mainProto = nd.protocols[0] || 0;
                const color = PROTO_COLORS[mainProto] || PROTO_COLORS[0];

                return (
                  <g
                    key={nd.id}
                    transform={`translate(${p.x},${p.y})`}
                    onMouseDown={(e) => onMouseDownNode(e, nd.id)}
                    onMouseEnter={() => setHoveredNode(nd.id)}
                    onMouseLeave={() => setHoveredNode(null)}
                    style={{ cursor: 'pointer', opacity: isDimmed ? 0.2 : 1 }}
                  >
                    {isSelected && (
                      <circle r={r + 6} fill="none" stroke={color.stroke} strokeWidth={2} strokeDasharray="4 2" />
                    )}
                    <circle
                      r={r}
                      fill={isSelected ? color.stroke : isHovered ? color.fill : 'white'}
                      stroke={color.stroke}
                      strokeWidth={isSelected ? 3 : 1.5}
                      filter={isSelected || isHovered ? 'drop-shadow(0 2px 4px rgba(0,0,0,0.15))' : undefined}
                    />
                    <text
                      textAnchor="middle"
                      dominantBaseline="central"
                      fontSize={9}
                      fontFamily="monospace"
                      fill={isSelected ? 'white' : '#1e293b'}
                      style={{ userSelect: 'none', pointerEvents: 'none' }}
                    >
                      {nd.id.split('.').slice(-2).join('.')}
                    </text>
                    {(isHovered || isSelected) && (
                      <text
                        y={r + 12}
                        textAnchor="middle"
                        fontSize={9}
                        fill="#64748b"
                        style={{ userSelect: 'none', pointerEvents: 'none' }}
                      >
                        {nd.id}
                      </text>
                    )}
                  </g>
                );
              })}
            </g>
          </g>
        </svg>
      </div>

      {/* Node detail panel */}
      <div className="w-64 shrink-0 border border-l-0 border-slate-200 rounded-r-lg bg-white flex flex-col">
        <div className="p-4 border-b border-slate-200">
          <h3 className="text-sm font-semibold text-slate-900">Node Inspector</h3>
          <p className="text-xs text-slate-400 mt-0.5">Click a node to inspect</p>
        </div>

        {!selectedNode ? (
          <div className="flex-1 flex flex-col items-center justify-center p-6 text-center">
            <Filter className="w-8 h-8 text-slate-200 mb-2" />
            <p className="text-sm text-slate-400">Click any node in the graph to see its connections and traffic details.</p>
          </div>
        ) : (
          <div className="flex-1 overflow-auto p-4 space-y-4">
            <div>
              <div className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-2">IP Address</div>
              <div className="text-sm font-mono font-medium text-slate-900 break-all">{selectedNode}</div>
            </div>
            {selectedNodeData && (
              <>
                <div className="grid grid-cols-2 gap-3">
                  <div className="bg-slate-50 rounded p-2.5 text-center">
                    <div className="text-lg font-semibold text-slate-900">{selectedNodeData.flows}</div>
                    <div className="text-xs text-slate-500">Flows</div>
                  </div>
                  <div className="bg-slate-50 rounded p-2.5 text-center">
                    <div className="text-lg font-semibold text-slate-900">{formatBytes(selectedNodeData.bytes)}</div>
                    <div className="text-xs text-slate-500">Traffic</div>
                  </div>
                </div>
                <div>
                  <div className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-2">Protocols</div>
                  <div className="flex flex-wrap gap-1">
                    {selectedNodeData.protocols.map(p => (
                      <span key={p} className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-blue-50 text-blue-700">
                        {protoName(p)}
                      </span>
                    ))}
                  </div>
                </div>
              </>
            )}
            <div>
              <div className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-2">
                Connections ({nodesByConnections.length})
              </div>
              <div className="space-y-1.5 max-h-64 overflow-auto">
                {nodesByConnections.map((c, i) => (
                  <button
                    key={i}
                    onClick={() => setSelectedNode(c.peer)}
                    className="w-full text-left p-2 rounded bg-slate-50 hover:bg-slate-100 transition-colors"
                  >
                    <div className="text-xs font-mono text-slate-800 truncate">{c.peer}</div>
                    <div className="flex items-center justify-between mt-1">
                      <span className="text-xs text-slate-400">{protoName(c.protocol)}</span>
                      <span className="text-xs text-slate-500">{formatBytes(c.bytes)}</span>
                    </div>
                  </button>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

// ── Main Page ──────────────────────────────────────────────────────────────────
const NetworkTopology = () => {
  const { sessionId, isCapturing } = useCaptureStore();
  const navigate = useNavigate();
  const [limit, setLimit] = useState(2000);

  const { data: result, isLoading, refetch } = useQuery({
    queryKey: ['topology-flows', sessionId, limit],
    queryFn: async () => {
      const res = await api.post('/api/search', {
        session_id: sessionId,
        query: '',
        limit,
        offset: 0,
      });
      return res.data;
    },
    enabled: !!sessionId,
    refetchInterval: isCapturing ? 10000 : false,
  });

  const flows = result?.results || [];

  const { nodes, edges } = useMemo(() => buildGraph(flows), [flows]);

  if (!sessionId) return <EmptySessionState navigate={navigate} />;

  return (
    <div className="space-y-4 h-full flex flex-col">
      {/* Header */}
      <div className="flex justify-between items-end shrink-0">
        <div>
          <h1 className="text-2xl font-semibold text-slate-900 tracking-tight">Network Topology</h1>
          <p className="text-slate-500 mt-1">
            Visual map of IP connections for this session
          </p>
        </div>
        <div className="flex items-center space-x-3">
          {isLoading ? (
            <span className="text-sm text-slate-400">Loading flows...</span>
          ) : (
            <span className="text-sm text-slate-500">
              {nodes.length} nodes · {edges.length} edges · from {flows.length} flows
            </span>
          )}
          <select
            value={limit}
            onChange={e => setLimit(Number(e.target.value))}
            className="text-sm border border-slate-200 rounded px-2 py-1.5 bg-white focus:ring-indigo-500 focus:border-indigo-500"
          >
            <option value={500}>Last 500 flows</option>
            <option value={2000}>Last 2k flows</option>
            <option value={5000}>Last 5k flows</option>
          </select>
          <button
            onClick={() => refetch()}
            className="flex items-center px-3 py-1.5 text-sm font-medium text-slate-600 bg-white border border-slate-200 rounded hover:bg-slate-50"
          >
            <RefreshCw className="w-4 h-4 mr-1.5" />
            Refresh
          </button>
        </div>
      </div>

      {/* Summary stat cards */}
      {!isLoading && nodes.length > 0 && (
        <div className="grid grid-cols-4 gap-4 shrink-0">
          <Card className="p-3">
            <div className="text-xs font-medium text-slate-500">Unique IPs</div>
            <div className="text-xl font-semibold text-slate-900 mt-1">{nodes.length}</div>
          </Card>
          <Card className="p-3">
            <div className="text-xs font-medium text-slate-500">Connections</div>
            <div className="text-xl font-semibold text-slate-900 mt-1">{edges.length}</div>
          </Card>
          <Card className="p-3">
            <div className="text-xs font-medium text-slate-500">Total Flows</div>
            <div className="text-xl font-semibold text-slate-900 mt-1">{flows.length}</div>
          </Card>
          <Card className="p-3">
            <div className="text-xs font-medium text-slate-500">Total Traffic</div>
            <div className="text-xl font-semibold text-slate-900 mt-1">
              {formatBytes(flows.reduce((sum, f) => sum + (f.payload_bytes || 0), 0))}
            </div>
          </Card>
        </div>
      )}

      {/* Graph */}
      <div className="flex-1 min-h-0">
        {isLoading ? (
          <div className="h-full flex items-center justify-center text-slate-400">
            <div className="text-center">
              <div className="w-8 h-8 border-2 border-slate-200 border-t-indigo-500 rounded-full animate-spin mx-auto mb-3" />
              <p>Building network graph...</p>
            </div>
          </div>
        ) : nodes.length === 0 ? (
          <div className="h-full flex items-center justify-center">
            <div className="text-center text-slate-400">
              <Layers className="w-12 h-12 mx-auto text-slate-200 mb-4" />
              <p className="font-medium text-slate-500">No flow data found</p>
              <p className="text-sm mt-1">Capture some traffic first, then come back here.</p>
            </div>
          </div>
        ) : (
          <TopologyGraph nodes={nodes} edges={edges} />
        )}
      </div>
    </div>
  );
};

export default NetworkTopology;
