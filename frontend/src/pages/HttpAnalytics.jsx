import React, { useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import axios from 'axios';
import { Card } from '../components/ui/Card';
import { useCaptureStore } from '../store/captureStore';
import { Globe, Zap, AlertTriangle, TrendingUp, Layers, Activity, Lock, Unlock } from 'lucide-react';
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid,
  PieChart, Pie, Cell
} from 'recharts';

const api = axios.create({ baseURL: '' });

const PROTOCOL_COLORS = {
  'HTTPS': '#4f46e5',
  'HTTP':  '#f59e0b',
  'HTTP/2': '#8b5cf6',
  'HTTP/3': '#06b6d4',
};

const StatCard = ({ title, value, unit, icon: Icon, color = 'slate', loading = false }) => (
  <Card className="flex flex-col">
    <div className="flex justify-between items-start mb-3">
      <span className="text-sm font-medium text-slate-500">{title}</span>
      <Icon className={`w-4 h-4 text-${color}-400`} />
    </div>
    <div className="flex items-baseline space-x-1">
      <span className="text-2xl font-semibold text-slate-900">
        {loading ? <span className="inline-block w-12 h-6 bg-slate-100 rounded animate-pulse" /> : (value ?? '—')}
      </span>
      {unit && !loading && <span className="text-sm text-slate-500">{unit}</span>}
    </div>
  </Card>
);

const EmptySessionState = ({ navigate }) => (
  <div className="flex flex-col items-center justify-center h-96 text-center">
    <Layers className="w-12 h-12 text-slate-300 mb-4" />
    <h2 className="text-lg font-semibold text-slate-700 mb-2">No Session Selected</h2>
    <p className="text-slate-500 text-sm">Select a capture session to view web traffic analytics.</p>
    <button onClick={() => navigate('/sessions')} className="mt-4 px-4 py-2 bg-indigo-600 text-white rounded-md text-sm font-medium hover:bg-indigo-700">
      Go to Sessions
    </button>
  </div>
);

// ── AppProtocol enum values (mirror C++ enum) ─────────────────────────────────
const APP_PROTO_NAMES = {
  0: 'Unknown', 1: 'HTTP', 2: 'HTTPS', 3: 'HTTP/2', 4: 'HTTP/3',
  5: 'DNS', 6: 'DNS-TLS', 7: 'SSH', 8: 'FTP', 9: 'SMTP', 10: 'IMAP',
};

// Extract host from a flow (http_host OR tls_sni)
const getFlowHost = (f) => f.http_host || f.tls_sni || null;
const isWebFlow = (f) => !!(f.http_host || f.tls_sni || [1, 2, 3, 4].includes(f.app_protocol));
const isHttpsFlow = (f) => !!(f.tls_sni || f.app_protocol === 2 || f.app_protocol === 3 || f.app_protocol === 4);

// ── Derive web stats from raw flows ──────────────────────────────────────────
function deriveWebStats(flows) {
  const webFlows = flows.filter(isWebFlow);
  if (webFlows.length === 0) return null;

  // Count per host
  const hostCounts = {};
  for (const f of webFlows) {
    const host = getFlowHost(f) || 'unknown';
    hostCounts[host] = (hostCounts[host] || 0) + 1;
  }
  const topHosts = Object.entries(hostCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([host, requests]) => ({ host, requests }));

  // Protocol breakdown (HTTP vs HTTPS vs HTTP2 etc)
  const protoCounts = {};
  for (const f of webFlows) {
    const name = isHttpsFlow(f) ? (f.app_protocol === 3 ? 'HTTP/2' : f.app_protocol === 4 ? 'HTTP/3' : 'HTTPS') : 'HTTP';
    protoCounts[name] = (protoCounts[name] || 0) + 1;
  }
  const protoBreakdown = Object.entries(protoCounts)
    .map(([name, count]) => ({ name, count, fill: PROTOCOL_COLORS[name] || '#94a3b8' }));

  // Duration stats
  const durations = webFlows.filter(f => f.duration_ms > 0).map(f => f.duration_ms);
  const avgMs = durations.length
    ? Math.round(durations.reduce((a, b) => a + b, 0) / durations.length)
    : null;
  const sortedDur = [...durations].sort((a, b) => a - b);
  const p95Ms = sortedDur.length ? sortedDur[Math.floor(sortedDur.length * 0.95)] : null;

  // Bytes per host
  const hostBytes = {};
  for (const f of webFlows) {
    const host = getFlowHost(f) || 'unknown';
    hostBytes[host] = (hostBytes[host] || 0) + (f.payload_bytes || 0);
  }

  // Slowest hosts by avg duration
  const hostDur = {};
  const hostDurCount = {};
  for (const f of webFlows) {
    if (!f.duration_ms) continue;
    const host = getFlowHost(f) || 'unknown';
    hostDur[host] = (hostDur[host] || 0) + f.duration_ms;
    hostDurCount[host] = (hostDurCount[host] || 0) + 1;
  }
  const slowestHosts = Object.entries(hostDur)
    .map(([host, total]) => ({ host, avg_ms: Math.round(total / hostDurCount[host]) }))
    .sort((a, b) => b.avg_ms - a.avg_ms)
    .slice(0, 8);

  const totalBytes = webFlows.reduce((s, f) => s + (f.payload_bytes || 0), 0);
  const httpCount = webFlows.filter(f => !isHttpsFlow(f)).length;
  const httpsCount = webFlows.filter(isHttpsFlow).length;

  return {
    flow_count: webFlows.length,
    http_count: httpCount,
    https_count: httpsCount,
    total_bytes: totalBytes,
    avg_duration_ms: avgMs,
    p95_duration_ms: p95Ms,
    unique_hosts: Object.keys(hostCounts).length,
    topHosts,
    protoBreakdown,
    slowestHosts,
    hostBytes,
    isHistorical: true,
  };
}

const formatBytes = (b) => {
  if (!b) return '0 B';
  if (b >= 1e9) return (b / 1e9).toFixed(1) + ' GB';
  if (b >= 1e6) return (b / 1e6).toFixed(1) + ' MB';
  if (b >= 1e3) return (b / 1e3).toFixed(1) + ' KB';
  return b + ' B';
};

const HttpAnalytics = () => {
  const { sessionId, isCapturing } = useCaptureStore();
  const navigate = useNavigate();

  // Live metrics from engine (for live mode supplementary stats)
  const { data: liveHttp } = useQuery({
    queryKey: ['metrics-http'],
    queryFn: () => api.get('/api/metrics/http?window=300').then(r => r.data),
    refetchInterval: 5000,
    enabled: !!sessionId && isCapturing,
  });

  // Always query flows — both HTTP (http_host) and HTTPS (tls_sni)
  const { data: rawFlows = [], isLoading } = useQuery({
    queryKey: ['web-flows', sessionId],
    queryFn: async () => {
      const res = await api.post('/api/search', {
        session_id: sessionId,
        query: '',
        limit: 5000,
        offset: 0,
      });
      // Keep all flows that have ANY web-related marker
      return (res.data?.results || []).filter(isWebFlow);
    },
    enabled: !!sessionId,
    refetchInterval: isCapturing ? 8000 : false,
  });

  const stats = useMemo(() => {
    if (!rawFlows.length) return null;
    return deriveWebStats(rawFlows);
  }, [rawFlows]);

  // Merge live metrics engine data on top if available
  const topHosts = useMemo(() => {
    if (isCapturing && liveHttp?.top_hosts?.length > 0) {
      return liveHttp.top_hosts.map(h => ({ host: h.host || h.key, requests: h.requests || h.value }));
    }
    return stats?.topHosts || [];
  }, [isCapturing, liveHttp, stats]);

  const slowestHosts = stats?.slowestHosts || [];
  const protoBreakdown = stats?.protoBreakdown || [];

  if (!sessionId) return <EmptySessionState navigate={navigate} />;

  return (
    <div className="space-y-6">
      <div className="flex items-end justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-slate-900 tracking-tight">Web Analytics</h1>
          <p className="text-slate-500 mt-1">
            HTTP &amp; HTTPS traffic — {isCapturing ? 'live session' : 'historical analysis'}
          </p>
        </div>
        {stats && (
          <div className="flex items-center space-x-2">
            <span className="inline-flex items-center space-x-1 px-2 py-1 rounded-full text-xs font-medium bg-amber-50 text-amber-700 border border-amber-200">
              <Unlock className="w-3 h-3" />
              <span>{stats.http_count} HTTP</span>
            </span>
            <span className="inline-flex items-center space-x-1 px-2 py-1 rounded-full text-xs font-medium bg-indigo-50 text-indigo-700 border border-indigo-200">
              <Lock className="w-3 h-3" />
              <span>{stats.https_count} HTTPS</span>
            </span>
          </div>
        )}
      </div>

      {isLoading ? (
        <div className="text-center text-slate-400 py-12">
          <div className="w-8 h-8 border-2 border-slate-200 border-t-indigo-500 rounded-full animate-spin mx-auto mb-3" />
          Loading web traffic data...
        </div>
      ) : !stats ? (
        <div className="text-center text-slate-400 py-16">
          <Globe className="w-12 h-12 mx-auto text-slate-200 mb-4" />
          <p className="font-medium text-slate-500">No web traffic detected yet</p>
          <p className="text-sm mt-2 max-w-sm mx-auto">
            Web flows appear <strong>after connections close</strong>. Try browsing some websites
            while capturing, then wait a few seconds or stop the capture.
            Both HTTP and HTTPS traffic are tracked.
          </p>
          <div className="mt-4 flex justify-center space-x-2 flex-wrap gap-2">
            {['neverssl.com', 'info.cern.ch', 'httpforever.com', 'example.com'].map(site => (
              <code key={site} className="px-2 py-0.5 bg-slate-100 rounded text-xs text-slate-600">
                http://{site}
              </code>
            ))}
          </div>
        </div>
      ) : (
        <>
          {/* Stat cards */}
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
            <StatCard title="Web Flows" value={stats.flow_count.toLocaleString()} icon={Activity} color="blue" />
            <StatCard title="Unique Hosts" value={stats.unique_hosts.toLocaleString()} icon={Globe} color="indigo" />
            <StatCard title="p95 Duration" value={stats.p95_duration_ms != null ? stats.p95_duration_ms.toFixed(0) : '—'} unit="ms" icon={Zap} color="emerald" />
            <StatCard title="Data Transferred" value={formatBytes(stats.total_bytes)} icon={TrendingUp} color="slate" />
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* HTTP vs HTTPS pie */}
            <Card>
              <h3 className="text-sm font-semibold text-slate-900 mb-4">Protocol Breakdown</h3>
              {protoBreakdown.length === 0 ? (
                <div className="h-40 flex items-center justify-center text-slate-400 text-sm">No data</div>
              ) : (
                <div className="h-52">
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={protoBreakdown}
                        dataKey="count"
                        nameKey="name"
                        cx="50%"
                        cy="50%"
                        outerRadius={70}
                        label={({ name, percent }) => percent > 0.05 ? `${name} ${(percent * 100).toFixed(0)}%` : ''}
                      >
                        {protoBreakdown.map((entry, i) => (
                          <Cell key={i} fill={entry.fill} />
                        ))}
                      </Pie>
                      <Tooltip formatter={(v, n) => [v + ' flows', n]} />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
              )}
            </Card>

            {/* Top hosts bar chart */}
            <Card noPadding className="lg:col-span-2">
              <div className="p-4 border-b border-slate-200">
                <h3 className="text-sm font-semibold text-slate-900">Top Hosts by Requests</h3>
              </div>
              {topHosts.length === 0 ? (
                <div className="p-8 text-center text-slate-400 text-sm">No host data yet</div>
              ) : (
                <div className="h-56 p-4">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={topHosts.slice(0, 8)} layout="vertical">
                      <CartesianGrid strokeDasharray="3 3" horizontal={false} stroke="#f1f5f9" />
                      <XAxis type="number" axisLine={false} tickLine={false} tick={{ fontSize: 11, fill: '#94a3b8' }} />
                      <YAxis dataKey="host" type="category" width={150} axisLine={false} tickLine={false} tick={{ fontSize: 10, fill: '#64748b' }} />
                      <Tooltip />
                      <Bar dataKey="requests" fill="#4f46e5" radius={[0, 3, 3, 0]} name="Flows" />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              )}
            </Card>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Top hosts by traffic */}
            <Card noPadding>
              <div className="p-4 border-b border-slate-200">
                <h3 className="text-sm font-semibold text-slate-900">Top Hosts by Traffic</h3>
              </div>
              {topHosts.length === 0 ? (
                <div className="p-8 text-center text-slate-400 text-sm">No data</div>
              ) : (
                <div className="divide-y divide-slate-100">
                  {topHosts.slice(0, 8).map((h, i) => (
                    <div key={i} className="px-4 py-2.5 flex items-center justify-between hover:bg-slate-50">
                      <div className="flex items-center space-x-3 min-w-0">
                        <span className="text-xs text-slate-400 w-5 shrink-0 text-right">{i + 1}</span>
                        <span className="text-sm font-mono text-slate-700 truncate">{h.host}</span>
                      </div>
                      <div className="flex items-center space-x-3 shrink-0 ml-4">
                        <span className="text-xs text-slate-400">{h.requests} flows</span>
                        {stats.hostBytes[h.host] > 0 && (
                          <span className="text-xs text-slate-500 font-medium">{formatBytes(stats.hostBytes[h.host])}</span>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </Card>

            {/* Slowest hosts by duration */}
            <Card noPadding>
              <div className="p-4 border-b border-slate-200">
                <h3 className="text-sm font-semibold text-slate-900">Slowest Connections</h3>
                <p className="text-xs text-slate-400 mt-0.5">Average flow duration per host</p>
              </div>
              {slowestHosts.length === 0 ? (
                <div className="p-8 text-center text-slate-400 text-sm">No duration data</div>
              ) : (
                <div className="divide-y divide-slate-100">
                  {slowestHosts.map((h, i) => (
                    <div key={i} className="px-4 py-2.5 flex items-center justify-between hover:bg-slate-50">
                      <div className="flex items-center space-x-3 min-w-0">
                        <span className="text-xs text-slate-400 w-5 shrink-0 text-right">{i + 1}</span>
                        <span className="text-sm font-mono text-slate-700 truncate">{h.host}</span>
                      </div>
                      <span className={`text-sm font-medium shrink-0 ml-4 ${
                        h.avg_ms > 2000 ? 'text-red-600' :
                        h.avg_ms > 500 ? 'text-orange-500' : 'text-slate-500'
                      }`}>
                        {h.avg_ms?.toFixed(0)} ms
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </Card>
          </div>
        </>
      )}
    </div>
  );
};

export default HttpAnalytics;
