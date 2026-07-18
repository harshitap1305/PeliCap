import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Card } from '../components/ui/Card';
import { Badge } from '../components/ui/Badge';
import { ShieldAlert, CheckCircle2, AlertTriangle, Search, Layers } from 'lucide-react';
import { useCaptureStore } from '../store/captureStore';
import { useQuery } from '@tanstack/react-query';
import axios from 'axios';

const api = axios.create({ baseURL: '' });

// Backend sends severity as string: "INFO", "WARNING", "CRITICAL"
const SEVERITY_CONFIG = {
  CRITICAL: { variant: 'danger', label: 'CRITICAL', color: 'text-red-600' },
  WARNING:  { variant: 'warning', label: 'WARNING',  color: 'text-orange-500' },
  INFO:     { variant: 'neutral', label: 'INFO',      color: 'text-slate-500' },
};

const SeverityBadge = ({ severity }) => {
  const key = (severity || 'INFO').toUpperCase();
  const cfg = SEVERITY_CONFIG[key] || SEVERITY_CONFIG.INFO;
  return <Badge variant={cfg.variant}>{cfg.label}</Badge>;
};

const formatTime = (ns) => {
  if (!ns) return '—';
  const d = new Date(ns / 1_000_000);
  return d.toLocaleTimeString([], { hour12: false });
};

const EmptySessionState = ({ navigate }) => (
  <div className="flex flex-col items-center justify-center h-96 text-center">
    <Layers className="w-12 h-12 text-slate-300 mb-4" />
    <h2 className="text-lg font-semibold text-slate-700 mb-2">No Session Selected</h2>
    <p className="text-slate-500 text-sm">Select a capture session first to view its security alerts.</p>
    <button onClick={() => navigate('/sessions')} className="mt-4 px-4 py-2 bg-indigo-600 text-white rounded-md text-sm font-medium hover:bg-indigo-700">
      Go to Sessions
    </button>
  </div>
);

const Alerts = () => {
  const { sessionId, isCapturing } = useCaptureStore();
  const navigate = useNavigate();
  const [search, setSearch] = useState('');

  const { data: alerts = [], isLoading } = useQuery({
    queryKey: ['alerts', sessionId],
    queryFn: async () => {
      // Pass session_id if available to scope alerts to this session
      const params = new URLSearchParams({ n: '500' });
      if (sessionId) params.set('session_id', sessionId);
      const res = await api.get(`/api/alerts?${params}`);
      return Array.isArray(res.data) ? res.data : [];
    },
    refetchInterval: isCapturing ? 5000 : false,
    enabled: !!sessionId,
  });

  const criticalCount = alerts.filter(a => (a.severity || '').toUpperCase() === 'CRITICAL').length;
  const warningCount = alerts.filter(a => (a.severity || '').toUpperCase() === 'WARNING').length;
  const totalCount = alerts.length;
  const resolvedCount = alerts.filter(a => !a.is_ongoing).length;

  const filtered = search
    ? alerts.filter(a =>
        a.title?.toLowerCase().includes(search.toLowerCase()) ||
        a.description?.toLowerCase().includes(search.toLowerCase()) ||
        a.type?.toLowerCase().includes(search.toLowerCase())
      )
    : alerts;

  if (!sessionId) return <EmptySessionState navigate={navigate} />;

  return (
    <div className="space-y-4 h-full flex flex-col">
      <div className="flex justify-between items-end shrink-0">
        <div>
          <h1 className="text-2xl font-semibold text-slate-900 tracking-tight flex items-center">
            <ShieldAlert className="w-6 h-6 mr-2 text-red-500" />
            Security Alerts
          </h1>
          <p className="text-slate-500 mt-1">Anomalous behavior detected during this capture session</p>
        </div>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-4 gap-4 shrink-0">
        <Card className="p-4 border-l-4 border-red-500">
          <div className="text-sm font-medium text-slate-500">Critical</div>
          <div className="text-2xl font-semibold text-slate-900 mt-1">{criticalCount}</div>
        </Card>
        <Card className="p-4 border-l-4 border-orange-500">
          <div className="text-sm font-medium text-slate-500">Warning</div>
          <div className="text-2xl font-semibold text-slate-900 mt-1">{warningCount}</div>
        </Card>
        <Card className="p-4 border-l-4 border-slate-300">
          <div className="text-sm font-medium text-slate-500">Total</div>
          <div className="text-2xl font-semibold text-slate-900 mt-1">{totalCount}</div>
        </Card>
        <Card className="p-4 border-l-4 border-green-500">
          <div className="text-sm font-medium text-slate-500">Resolved</div>
          <div className="text-2xl font-semibold text-slate-900 mt-1">{resolvedCount}</div>
        </Card>
      </div>

      <Card noPadding className="flex-1 flex flex-col min-h-0">
        {/* Search */}
        <div className="p-4 border-b border-slate-200 bg-slate-50 shrink-0">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
            <input
              type="text"
              placeholder="Filter alerts by title, type, or description..."
              className="w-full pl-9 pr-4 py-2 bg-white border border-slate-200 rounded-md text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
              value={search}
              onChange={e => setSearch(e.target.value)}
            />
          </div>
        </div>

        {/* Alert list */}
        <div className="overflow-auto flex-1">
          {isLoading ? (
            <div className="p-8 text-center text-slate-500">Loading alerts...</div>
          ) : filtered.length === 0 ? (
            <div className="p-12 text-center text-slate-500">
              <CheckCircle2 className="w-10 h-10 mx-auto text-green-400 mb-3" />
              <p className="font-medium text-slate-700">No alerts for this session</p>
              <p className="text-sm mt-1">The detection engine found no anomalies{search ? ' matching your search' : ''}.</p>
            </div>
          ) : (
            <table className="w-full text-left border-collapse">
              <thead className="bg-slate-50/80 sticky top-0 z-10 border-b border-slate-200">
                <tr>
                  <th className="px-4 py-3 text-xs font-semibold text-slate-500 uppercase tracking-wider w-28">Severity</th>
                  <th className="px-4 py-3 text-xs font-semibold text-slate-500 uppercase tracking-wider w-28">Time</th>
                  <th className="px-4 py-3 text-xs font-semibold text-slate-500 uppercase tracking-wider">Title</th>
                  <th className="px-4 py-3 text-xs font-semibold text-slate-500 uppercase tracking-wider w-32">Type</th>
                  <th className="px-4 py-3 text-xs font-semibold text-slate-500 uppercase tracking-wider w-24">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {filtered.map((alert, i) => (
                  <tr key={alert.alert_id || i} className="hover:bg-slate-50 transition-colors">
                    <td className="px-4 py-3 whitespace-nowrap">
                      <SeverityBadge severity={alert.severity} />
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap text-sm font-mono text-slate-500">
                      {formatTime(alert.timestamp_ns)}
                    </td>
                    <td className="px-4 py-3">
                      <div className="text-sm font-medium text-slate-900">{alert.title}</div>
                      {alert.description && (
                        <div className="text-xs text-slate-500 mt-0.5 max-w-xl truncate">{alert.description}</div>
                      )}
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap text-xs text-slate-500">
                      {alert.type || '—'}
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap">
                      <Badge variant={alert.is_ongoing ? 'danger' : 'success'}>
                        {alert.is_ongoing ? 'Active' : 'Resolved'}
                      </Badge>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </Card>
    </div>
  );
};

export default Alerts;
