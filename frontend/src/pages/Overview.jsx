import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Card, CardHeader } from '../components/ui/Card';
import { ProtocolBadge, Badge } from '../components/ui/Badge';
import {
  ArrowUpRight,
  ArrowDownRight,
  Activity,
  ArrowDownToLine,
  ArrowUpFromLine,
  AlertTriangle,
  Zap,
  ArrowRight,
  Server,
  Layers,
  Sparkles,
  Lightbulb
} from 'lucide-react';
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip as RechartsTooltip,
  ResponsiveContainer
} from 'recharts';
import { useQuery } from '@tanstack/react-query';
import axios from 'axios';
import { useCaptureStore } from '../store/captureStore';

const api = axios.create({ baseURL: '' });

const formatNumber = (num) => {
  if (!num && num !== 0) return '—';
  if (num >= 1000000) return (num / 1000000).toFixed(1) + 'M';
  if (num >= 1000) return (num / 1000).toFixed(1) + 'k';
  return num.toString();
};

const formatBytes = (bps) => {
  if (!bps) return '0 bps';
  if (bps >= 1e9) return (bps / 1e9).toFixed(1) + ' Gbps';
  if (bps >= 1e6) return (bps / 1e6).toFixed(1) + ' Mbps';
  if (bps >= 1e3) return (bps / 1e3).toFixed(1) + ' Kbps';
  return bps + ' bps';
};

const getProtocolName = (proto) => {
  switch (proto) { case 6: return 'TCP'; case 17: return 'UDP'; case 1: return 'ICMP'; default: return 'OTHER'; }
};

const StatCard = ({ title, value, unit, icon: Icon, color = 'slate' }) => (
  <Card className="flex flex-col">
    <div className="flex justify-between items-start mb-3">
      <span className="text-sm font-medium text-slate-500">{title}</span>
      <div className={`p-1.5 bg-${color}-50 rounded-md text-${color}-400`}>
        <Icon className="w-4 h-4" />
      </div>
    </div>
    <div className="flex items-baseline space-x-1">
      <span className="text-2xl font-semibold text-slate-900">{value}</span>
      {unit && <span className="text-sm text-slate-500">{unit}</span>}
    </div>
  </Card>
);

const EmptyState = ({ navigate }) => (
  <div className="flex flex-col items-center justify-center h-96 text-center">
    <div className="w-16 h-16 bg-slate-100 rounded-full flex items-center justify-center mb-4">
      <Layers className="w-8 h-8 text-slate-400" />
    </div>
    <h2 className="text-xl font-semibold text-slate-700 mb-2">No Session Selected</h2>
    <p className="text-slate-500 max-w-sm">Select an existing capture session or start a new one to begin analyzing network traffic.</p>
    <button
      onClick={() => navigate('/sessions')}
      className="mt-6 flex items-center px-5 py-2.5 bg-indigo-600 text-white rounded-md hover:bg-indigo-700 font-medium"
    >
      Go to Sessions
      <ArrowRight className="w-4 h-4 ml-2" />
    </button>
  </div>
);

const Overview = () => {
  const { sessionId, isCapturing } = useCaptureStore();
  const navigate = useNavigate();
  const [bwData, setBwData] = useState([]);

  // Live stats (packets, flows) — only poll when actively capturing
  const { data: stats } = useQuery({
    queryKey: ['stats'],
    queryFn: () => api.get('/api/stats').then(r => r.data),
    refetchInterval: isCapturing ? 5000 : false,  // 5s is enough for a dev dashboard
    enabled: isCapturing,
  });

  // Network metrics (bandwidth)
  const { data: netMetrics } = useQuery({
    queryKey: ['metrics-network', sessionId],
    queryFn: () => api.get('/api/metrics/network?window=60').then(r => r.data),
    refetchInterval: isCapturing ? 8000 : false,  // bandwidth chart updates every 8s
    enabled: !!sessionId && isCapturing,           // skip entirely for historical sessions
  });

  // Session info (always fetch fresh — needed for historical stats)
  const { data: sessions = [] } = useQuery({
    queryKey: ['sessions'],
    queryFn: () => api.get('/api/sessions').then(r => Array.isArray(r.data) ? r.data : []),
    refetchInterval: isCapturing ? 10000 : false,
    enabled: !!sessionId,
    refetchOnMount: true,
    staleTime: 0,
  });
  const historicalSession = sessions.find(s => s.session_id === sessionId);

  // Historical mode: get total flow count for this session
  const { data: flowCountData } = useQuery({
    queryKey: ['flow-count', sessionId],
    queryFn: async () => {
      const res = await api.post('/api/search', {
        session_id: sessionId,
        query: '',
        limit: 1,
        offset: 0,
      });
      return res.data?.total ?? res.data?.results?.length ?? null;
    },
    enabled: !!sessionId && !isCapturing,
    staleTime: 30000,
  });

  // Top flows
  const { data: flowsData } = useQuery({
    queryKey: ['top-flows', sessionId],
    queryFn: () => isCapturing
      ? api.get('/api/flows?limit=10').then(r => r.data.flows || [])
      : api.post('/api/search', { session_id: sessionId, query: '', limit: 10, offset: 0 }).then(r => r.data.results || []),
    refetchInterval: isCapturing ? 5000 : false,
    enabled: !!sessionId,
  });
  const topFlows = flowsData || [];

  // Recent alerts
  const { data: alertsData = [] } = useQuery({
    queryKey: ['recent-alerts', sessionId],
    queryFn: () => api.get(`/api/alerts?n=5${sessionId ? `&session_id=${sessionId}` : ''}`).then(r => r.data),
    refetchInterval: isCapturing ? 5000 : false,
    enabled: !!sessionId,
  });

  // AI auto-analysis — only for live sessions (historical data is static, no need to poll)
  const { data: aiAnalysis } = useQuery({
    queryKey: ['ai-auto-analyze', sessionId, isCapturing],
    queryFn: () =>
      axios.post('/ai/auto-analyze', { session_id: sessionId, is_live: isCapturing }).then(r => r.data),
    enabled: !!sessionId && isCapturing,  // historical sessions: no LLM polling
    refetchInterval: 5 * 60 * 1000,
    retry: false,
    staleTime: 4 * 60 * 1000,
  });

  // Historical session aggregate stats from PostgreSQL (packets, alerts, protocol breakdown)
  const { data: historicalStats } = useQuery({
    queryKey: ['hist-session-summary', sessionId],
    queryFn: () =>
      axios.get(`/ai/history/session-summary?session_id=${sessionId}`).then(r => r.data),
    enabled: !!sessionId && !isCapturing,
    staleTime: 60_000,
    retry: false,
  });

  // Historical alerts count from PostgreSQL
  const { data: historicalAlerts = [] } = useQuery({
    queryKey: ['hist-alerts', sessionId],
    queryFn: () =>
      axios.get(`/ai/history/alerts?session_id=${sessionId}&limit=500`).then(r => r.data),
    enabled: !!sessionId && !isCapturing,
    staleTime: 60_000,
    retry: false,
  });

  // WebSocket for live bandwidth chart
  useEffect(() => {
    if (!isCapturing) return;
    const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const ws = new WebSocket(`${wsProtocol}//${window.location.host}/ws/metrics`);

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data.bw_in !== undefined || data.bps_in !== undefined) {
          setBwData(prev => {
            const bwIn = data.bw_in ?? (data.bps_in / 1e6) ?? 0;
            const bwOut = data.bw_out ?? (data.bps_out / 1e6) ?? 0;
            const newData = [...prev, {
              time: new Date().toLocaleTimeString([], { hour12: false }),
              in: bwIn,
              out: bwOut,
            }];
            if (newData.length > 60) newData.shift();
            return newData;
          });
        }
      } catch (e) { }
    };

    return () => ws.close();
  }, [isCapturing]);

  // Derive displayed stats — prefer PostgreSQL data for historical sessions
  const packetsCapt = isCapturing
    ? (stats?.packets_captured ?? 0)
    : (historicalSession?.packets_captured || historicalStats?.total_packets || '—');

  const packetsDropped = isCapturing
    ? (stats?.packets_dropped ?? 0)
    : (historicalSession?.packets_dropped ?? '—');

  const activeFlows = isCapturing
    ? (stats?.active_flows ?? 0)
    : (historicalStats?.total_flows ?? flowCountData ?? topFlows.length ?? '—');

  const bwIn = netMetrics ? (netMetrics.bps_in / 1e6).toFixed(2) : null;
  const bwOut = netMetrics ? (netMetrics.bps_out / 1e6).toFixed(2) : null;

  // Alert count: for historical use PostgreSQL count; for live use in-memory
  const alertCount = !isCapturing && historicalStats
    ? (historicalStats.alerts?.total ?? 0)
    : (Array.isArray(alertsData) ? alertsData.length : 0);

  // For historical alerts panel, use PostgreSQL alerts
  const displayedAlerts = !isCapturing && historicalAlerts.length > 0
    ? historicalAlerts
    : alertsData;

  // Duration for historical session
  const sessionDuration = historicalSession?.start_time && historicalSession?.end_time
    ? (() => {
        const ms = new Date(historicalSession.end_time) - new Date(historicalSession.start_time);
        const s = Math.floor(ms / 1000);
        if (s < 60) return `${s}s`;
        if (s < 3600) return `${Math.floor(s/60)}m ${s%60}s`;
        return `${Math.floor(s/3600)}h ${Math.floor((s%3600)/60)}m`;
      })()
    : null;

  if (!sessionId) {
    return <EmptyState navigate={navigate} />;
  }

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-end">
        <div>
          <h1 className="text-2xl font-semibold text-slate-900 tracking-tight">Overview</h1>
          <p className="text-slate-500 mt-1">
            {isCapturing ? 'Live monitoring of network capture' : 'Historical session analysis'}
          </p>
        </div>
      </div>

      {/* AI Insights card */}
      {aiAnalysis?.summary && (
        <div className="flex items-start gap-3 bg-indigo-50 border border-indigo-100 rounded-xl px-4 py-3">
          <Sparkles className="w-4 h-4 text-indigo-500 mt-0.5 shrink-0" />
          <div>
            <span className="text-xs font-semibold text-indigo-600 uppercase tracking-wide">AI Insight</span>
            <p className="text-sm text-indigo-900 mt-0.5">{aiAnalysis.summary}</p>
          </div>
          <button
            onClick={() => navigate('/copilot')}
            className="ml-auto shrink-0 text-xs text-indigo-600 hover:text-indigo-800 font-medium flex items-center gap-1"
          >
            Ask more <ArrowRight className="w-3 h-3" />
          </button>
        </div>
      )}

      {/* Stat cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-6 gap-4">
        <StatCard title="Packets Captured" value={formatNumber(packetsCapt)} icon={Activity} />
        <StatCard title="Packets Dropped" value={formatNumber(packetsDropped)} icon={AlertTriangle} color="red" />
        <StatCard
          title={isCapturing ? 'Bandwidth In' : 'Total Flows'}
          value={isCapturing ? (bwIn ?? '—') : formatNumber(activeFlows)}
          unit={isCapturing && bwIn ? 'Mbps' : ''}
          icon={isCapturing ? ArrowDownToLine : Zap}
          color="blue"
        />
        <StatCard
          title={isCapturing ? 'Bandwidth Out' : 'Session Duration'}
          value={isCapturing ? (bwOut ?? '—') : (sessionDuration ?? '—')}
          unit={isCapturing && bwOut ? 'Mbps' : ''}
          icon={isCapturing ? ArrowUpFromLine : Server}
          color="slate"
        />
        <StatCard title={isCapturing ? 'Active Flows' : 'Sample Flows'} value={formatNumber(isCapturing ? activeFlows : topFlows.length)} icon={Zap} color="indigo" />
        <StatCard title="Alerts" value={formatNumber(alertCount)} icon={AlertTriangle} color="orange" />
      </div>

      {/* Live Bandwidth Chart — only in live mode */}
      {isCapturing && (
        <Card noPadding className="overflow-hidden">
          <div className="p-6 border-b border-slate-200">
            <h3 className="text-base font-semibold text-slate-900">Live Bandwidth</h3>
          </div>
          <div className="h-[240px] p-4">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={bwData}>
                <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#f1f5f9" />
                <XAxis dataKey="time" axisLine={false} tickLine={false} tick={{ fontSize: 12, fill: '#94a3b8' }} minTickGap={30} />
                <YAxis axisLine={false} tickLine={false} tick={{ fontSize: 12, fill: '#94a3b8' }} tickFormatter={v => v.toFixed(1) + ' M'} />
                <RechartsTooltip contentStyle={{ borderRadius: '8px', border: '1px solid #e2e8f0' }} />
                <Line type="monotone" dataKey="in" stroke="#2563eb" strokeWidth={2} dot={false} isAnimationActive={false} name="In" />
                <Line type="monotone" dataKey="out" stroke="#94a3b8" strokeWidth={2} dot={false} isAnimationActive={false} name="Out" />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </Card>
      )}

      {/* Top Flows + Recent Alerts */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <Card noPadding>
            <div className="p-4 border-b border-slate-200">
              <h3 className="text-sm font-semibold text-slate-900">Top Active Flows</h3>
            </div>
            {topFlows.length === 0 ? (
              <div className="p-8 text-center text-slate-400 text-sm">
                {isCapturing ? 'Waiting for flows...' : 'No flow data for this session.'}
              </div>
            ) : (
              <div className="divide-y divide-slate-100">
                {topFlows.slice(0, 8).map((flow, i) => (
                  <div key={flow.flow_id || i} className="px-4 py-2.5 flex items-center justify-between hover:bg-slate-50">
                    <div className="flex items-center space-x-3 min-w-0">
                      <ProtocolBadge protocol={getProtocolName(flow.protocol)} />
                      <span className="text-xs font-mono text-slate-600 truncate">
                        {flow.src_ip}:{flow.src_port}
                        <ArrowRight className="w-3 h-3 inline mx-1 text-slate-400" />
                        {flow.dst_ip}:{flow.dst_port}
                      </span>
                    </div>
                    <span className="text-xs text-slate-500 shrink-0 ml-2">
                      {flow.payload_bytes
                        ? (flow.payload_bytes >= 1e6
                          ? (flow.payload_bytes / 1e6).toFixed(1) + ' MB'
                          : (flow.payload_bytes / 1e3).toFixed(1) + ' KB')
                        : '—'}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </Card>
        </div>
        <div>
          <Card noPadding>
            <div className="p-4 border-b border-slate-200">
              <h3 className="text-sm font-semibold text-slate-900">Recent Alerts</h3>
            </div>
            {!Array.isArray(displayedAlerts) || displayedAlerts.length === 0 ? (
              <div className="p-8 text-center text-slate-400 text-sm">No alerts for this session.</div>
            ) : (
              <div className="divide-y divide-slate-100">
                {displayedAlerts.slice(0, 6).map((a, i) => {
                  const sev = (a.severity || '').toUpperCase();
                  const color = sev === 'CRITICAL' ? 'text-red-600' : sev === 'WARNING' ? 'text-orange-500' : 'text-slate-400';
                  return (
                    <div key={a.alert_id || i} className="px-4 py-2.5 hover:bg-slate-50">
                      <div className={`text-xs font-semibold ${color}`}>{sev}</div>
                      <div className="text-xs text-slate-700 mt-0.5 truncate">{a.title}</div>
                    </div>
                  );
                })}
              </div>
            )}
          </Card>
        </div>
      </div>
    </div>
  );
};

export default Overview;
