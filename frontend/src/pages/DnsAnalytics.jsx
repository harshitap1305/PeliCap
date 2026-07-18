import React, { useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import axios from 'axios';
import { Card } from '../components/ui/Card';
import { useCaptureStore } from '../store/captureStore';
import { Globe, Zap, AlertTriangle, TrendingUp, Layers } from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from 'recharts';

const api = axios.create({ baseURL: '' });

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
    <p className="text-slate-500 text-sm">Select a capture session to view DNS analytics.</p>
    <button onClick={() => navigate('/sessions')} className="mt-4 px-4 py-2 bg-indigo-600 text-white rounded-md text-sm font-medium hover:bg-indigo-700">
      Go to Sessions
    </button>
  </div>
);

// ── Derive DNS stats from raw flows (historical mode) ─────────────────────────
function deriveDnsStats(flows) {
  const dnsFlows = flows.filter(f => f.dns_query && f.dns_query.length > 0);
  if (dnsFlows.length === 0) return null;

  // Count per domain
  const domainCounts = {};
  for (const f of dnsFlows) {
    const d = f.dns_query;
    domainCounts[d] = (domainCounts[d] || 0) + 1;
  }

  const topDomains = Object.entries(domainCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 15)
    .map(([domain, queries]) => ({ domain, queries }));

  // Durations as resolution time proxy
  const durations = dnsFlows.filter(f => f.duration_ms).map(f => f.duration_ms);
  const avgMs = durations.length
    ? Math.round(durations.reduce((a, b) => a + b, 0) / durations.length)
    : null;
  const sortedDur = [...durations].sort((a, b) => a - b);
  const p95Ms = sortedDur.length ? sortedDur[Math.floor(sortedDur.length * 0.95)] : null;

  // Slowest domains
  const domainDur = {};
  const domainDurCount = {};
  for (const f of dnsFlows) {
    if (!f.duration_ms) continue;
    domainDur[f.dns_query] = (domainDur[f.dns_query] || 0) + f.duration_ms;
    domainDurCount[f.dns_query] = (domainDurCount[f.dns_query] || 0) + 1;
  }
  const slowestDomains = Object.entries(domainDur)
    .map(([domain, total]) => ({ domain, avg_ms: Math.round(total / domainDurCount[domain]) }))
    .sort((a, b) => b.avg_ms - a.avg_ms)
    .slice(0, 10);

  return {
    avg_resolution_ms: avgMs,
    p95_resolution_ms: p95Ms,
    queries_per_sec: null,
    nxdomain_rate_pct: null,
    query_count: dnsFlows.length,
    unique_domains: Object.keys(domainCounts).length,
    top_domains: topDomains,
    slowest_domains: slowestDomains,
    isHistorical: true,
  };
}

const DnsAnalytics = () => {
  const { sessionId, isCapturing } = useCaptureStore();
  const navigate = useNavigate();

  // Live mode: use real-time metrics engine
  const { data: liveDns, isLoading: liveLoading } = useQuery({
    queryKey: ['metrics-dns'],
    queryFn: () => api.get('/api/metrics/dns?window=300').then(r => r.data),
    refetchInterval: 5000,
    enabled: !!sessionId && isCapturing,
  });

  // Always query flows for DNS — filter client-side (wildcards may not be supported)
  const { data: rawFlows, isLoading: flowsLoading } = useQuery({
    queryKey: ['dns-flows', sessionId],
    queryFn: async () => {
      const res = await api.post('/api/search', {
        session_id: sessionId,
        query: '',
        limit: 5000,
        offset: 0,
      });
      const results = res.data?.results || [];
      return results.filter(f => f.dns_query);
    },
    enabled: !!sessionId,
    refetchInterval: isCapturing ? 15000 : false,
  });

  const isLoading = isCapturing ? (liveLoading && flowsLoading) : flowsLoading;

  const dns = useMemo(() => {
    // Prefer live metrics if capturing and engine has data
    if (isCapturing && liveDns && (liveDns.queries_per_sec > 0 || liveDns.top_domains?.length > 0)) {
      return {
        avg_resolution_ms: liveDns.avg_resolution_ms,
        p95_resolution_ms: liveDns.p95_resolution_ms,
        queries_per_sec: liveDns.queries_per_sec,
        nxdomain_rate_pct: liveDns.nxdomain_rate_pct,
        query_count: null,
        unique_domains: null,
        top_domains: liveDns.top_domains || [],
        slowest_domains: liveDns.slowest_domains || [],
        isHistorical: false,
      };
    }
    // Fall back to flow-derived stats
    if (!rawFlows) return null;
    return deriveDnsStats(rawFlows);
  }, [isCapturing, liveDns, rawFlows]);

  if (!sessionId) return <EmptySessionState navigate={navigate} />;

  const topDomains = dns?.top_domains || [];
  const slowestDomains = dns?.slowest_domains || [];

  return (
    <div className="space-y-6">
      <div className="flex items-end justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-slate-900 tracking-tight">DNS Analytics</h1>
          <p className="text-slate-500 mt-1">
            {isCapturing ? 'Live domain resolution performance and query patterns' : 'Historical DNS query analysis from captured session'}
          </p>
        </div>
        {!isCapturing && dns?.isHistorical && (
          <span className="inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium bg-blue-100 text-blue-700 border border-blue-200">
            {dns.query_count} DNS flows · {dns.unique_domains} unique domains
          </span>
        )}
      </div>

      {isLoading ? (
        <div className="text-center text-slate-400 py-12">
          <div className="w-8 h-8 border-2 border-slate-200 border-t-indigo-500 rounded-full animate-spin mx-auto mb-3" />
          Loading DNS analytics...
        </div>
      ) : !dns ? (
        <div className="text-center text-slate-400 py-16">
          <Globe className="w-12 h-12 mx-auto text-slate-200 mb-4" />
          <p className="font-medium text-slate-500">No DNS data found for this session</p>
          <p className="text-sm mt-1">DNS queries will appear here once captured. Make sure UDP port 53 is not filtered by your BPF filter.</p>
        </div>
      ) : (
        <>
          {/* Key metrics */}
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
            {isCapturing ? (
              <>
                <StatCard title="Avg Resolution" value={dns.avg_resolution_ms?.toFixed(1)} unit="ms" icon={Zap} color="blue" loading={isLoading} />
                <StatCard title="p95 Latency" value={dns.p95_resolution_ms?.toFixed(1)} unit="ms" icon={TrendingUp} color="indigo" loading={isLoading} />
                <StatCard title="Queries / sec" value={dns.queries_per_sec?.toFixed(2)} unit="QPS" icon={Globe} color="emerald" loading={isLoading} />
                <StatCard title="NXDOMAIN Rate" value={dns.nxdomain_rate_pct?.toFixed(1)} unit="%" icon={AlertTriangle} color="red" loading={isLoading} />
              </>
            ) : (
              <>
                <StatCard title="DNS Queries" value={dns.query_count?.toLocaleString()} icon={Globe} color="blue" loading={isLoading} />
                <StatCard title="Unique Domains" value={dns.unique_domains?.toLocaleString()} icon={TrendingUp} color="indigo" loading={isLoading} />
                <StatCard title="Avg Duration" value={dns.avg_resolution_ms?.toFixed(0)} unit="ms" icon={Zap} color="emerald" loading={isLoading} />
                <StatCard title="p95 Duration" value={dns.p95_resolution_ms?.toFixed(0)} unit="ms" icon={AlertTriangle} color="slate" loading={isLoading} />
              </>
            )}
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Top queried domains */}
            <Card noPadding>
              <div className="p-4 border-b border-slate-200">
                <h3 className="text-sm font-semibold text-slate-900">Top Queried Domains</h3>
              </div>
              {topDomains.length === 0 ? (
                <div className="p-8 text-center text-slate-400 text-sm">No domain data yet.</div>
              ) : (
                <>
                  <div className="h-52 p-4">
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart data={topDomains.slice(0, 10)} layout="vertical">
                        <CartesianGrid strokeDasharray="3 3" horizontal={false} stroke="#f1f5f9" />
                        <XAxis type="number" axisLine={false} tickLine={false} tick={{ fontSize: 11, fill: '#94a3b8' }} />
                        <YAxis dataKey="domain" type="category" width={130} axisLine={false} tickLine={false} tick={{ fontSize: 10, fill: '#64748b' }} />
                        <Tooltip />
                        <Bar dataKey="queries" fill="#4f46e5" radius={[0, 3, 3, 0]} />
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                  <div className="divide-y divide-slate-100">
                    {topDomains.slice(0, 8).map((d, i) => (
                      <div key={i} className="px-4 py-2 flex justify-between items-center hover:bg-slate-50">
                        <div className="flex items-center space-x-3">
                          <span className="text-xs text-slate-400 w-5 text-right">{i + 1}</span>
                          <span className="text-sm font-mono text-slate-700 truncate max-w-[200px]">{d.domain}</span>
                        </div>
                        <span className="text-sm text-slate-500 shrink-0 ml-4">{d.queries} queries</span>
                      </div>
                    ))}
                  </div>
                </>
              )}
            </Card>

            {/* Slowest domains */}
            <Card noPadding>
              <div className="p-4 border-b border-slate-200">
                <h3 className="text-sm font-semibold text-slate-900">Slowest Domains</h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  {isCapturing ? 'Average resolution latency' : 'Average flow duration'}
                </p>
              </div>
              {slowestDomains.length === 0 ? (
                <div className="p-8 text-center text-slate-400 text-sm">No latency data yet.</div>
              ) : (
                <div className="divide-y divide-slate-100">
                  {slowestDomains.slice(0, 10).map((d, i) => (
                    <div key={i} className="px-4 py-3 flex justify-between items-center hover:bg-slate-50">
                      <div className="flex items-center space-x-3">
                        <span className="text-xs text-slate-400 w-5 text-right">{i + 1}</span>
                        <span className="text-sm font-mono text-slate-700 truncate max-w-[200px]">{d.domain}</span>
                      </div>
                      <span className={`text-sm font-medium shrink-0 ml-4 ${
                        (d.avg_ms || d.avg) > 500 ? 'text-red-600' :
                        (d.avg_ms || d.avg) > 200 ? 'text-orange-500' : 'text-slate-500'
                      }`}>
                        {(d.avg_ms || d.avg)?.toFixed(0)} ms
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

export default DnsAnalytics;
