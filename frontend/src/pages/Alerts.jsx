import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Card } from '../components/ui/Card';
import { Badge } from '../components/ui/Badge';
import {
  ShieldAlert, CheckCircle2, Search, Layers, ChevronDown, ChevronRight,
  Activity, Globe, MonitorCheck, Network, ScanSearch, Wifi, AlertTriangle
} from 'lucide-react';
import { useCaptureStore } from '../store/captureStore';
import { useQuery } from '@tanstack/react-query';
import axios from 'axios';

const api = axios.create({ baseURL: '' });

// ── AlertType integer → display config ────────────────────────────────────────
// Matches core/detection/alert.hpp AlertType enum
const ALERT_TYPE_MAP = {
  100: { label: 'TCP Retransmit Spike',  icon: Activity, group: 'TCP'      },
  101: { label: 'TCP Zero Window',        icon: Activity, group: 'TCP'      },
  102: { label: 'TCP High RTT',           icon: Activity, group: 'TCP'      },
  103: { label: 'Long-Lived Connection',  icon: Activity, group: 'TCP'      },
  200: { label: 'DNS High Latency',       icon: Globe,    group: 'DNS'      },
  201: { label: 'DNS NXDOMAIN Spike',     icon: Globe,    group: 'DNS'      },
  202: { label: 'DNS Query Flood',        icon: Globe,    group: 'DNS'      },
  300: { label: 'HTTP Error Rate Spike',  icon: MonitorCheck, group: 'HTTP' },
  301: { label: 'HTTP Latency Spike',     icon: MonitorCheck, group: 'HTTP' },
  302: { label: 'HTTP Request Flood',     icon: MonitorCheck, group: 'HTTP' },
  400: { label: 'Traffic Spike',          icon: Wifi,     group: 'Traffic'  },
  401: { label: 'Traffic Drop',           icon: Wifi,     group: 'Traffic'  },
  500: { label: 'Port Scan',              icon: ScanSearch, group: 'Behavioral' },
  501: { label: 'Host Scan',              icon: ScanSearch, group: 'Behavioral' },
  600: { label: 'Large Flow',             icon: Network,  group: 'Traffic'  },
};

// Also handle string type names from the API
const ALERT_TYPE_STR_MAP = {
  'TCP_RETRANSMISSION_SPIKE':  ALERT_TYPE_MAP[100],
  'TCP_ZERO_WINDOW':           ALERT_TYPE_MAP[101],
  'TCP_HIGH_RTT':              ALERT_TYPE_MAP[102],
  'TCP_LONG_LIVED_CONNECTION': ALERT_TYPE_MAP[103],
  'DNS_HIGH_LATENCY':          ALERT_TYPE_MAP[200],
  'DNS_NXDOMAIN_SPIKE':        ALERT_TYPE_MAP[201],
  'DNS_QUERY_FLOOD':           ALERT_TYPE_MAP[202],
  'HTTP_ERROR_RATE_SPIKE':     ALERT_TYPE_MAP[300],
  'HTTP_LATENCY_SPIKE':        ALERT_TYPE_MAP[301],
  'HTTP_REQUEST_FLOOD':        ALERT_TYPE_MAP[302],
  'TRAFFIC_SPIKE':             ALERT_TYPE_MAP[400],
  'TRAFFIC_DROP':              ALERT_TYPE_MAP[401],
  'PORT_SCAN':                 ALERT_TYPE_MAP[500],
  'HOST_SCAN':                 ALERT_TYPE_MAP[501],
  'LARGE_FLOW':                ALERT_TYPE_MAP[600],
};

const resolveType = (rawType) => {
  if (!rawType) return null;
  const num = Number(rawType);
  if (!isNaN(num) && ALERT_TYPE_MAP[num]) return ALERT_TYPE_MAP[num];
  if (ALERT_TYPE_STR_MAP[String(rawType).toUpperCase()]) return ALERT_TYPE_STR_MAP[String(rawType).toUpperCase()];
  return { label: String(rawType), icon: AlertTriangle, group: 'Other' };
};

// ── Severity ──────────────────────────────────────────────────────────────────
const SEVERITY_CONFIG = {
  CRITICAL: { variant: 'danger',  label: 'CRITICAL', dot: 'bg-red-500'    },
  WARNING:  { variant: 'warning', label: 'WARNING',  dot: 'bg-orange-400' },
  INFO:     { variant: 'neutral', label: 'INFO',     dot: 'bg-slate-400'  },
};

const SeverityBadge = ({ severity }) => {
  // severity may come as string ("CRITICAL") or integer (2,1,0)
  let key;
  if (typeof severity === 'number') {
    key = severity === 2 ? 'CRITICAL' : severity === 1 ? 'WARNING' : 'INFO';
  } else {
    key = (severity || 'INFO').toString().toUpperCase();
  }
  const cfg = SEVERITY_CONFIG[key] || SEVERITY_CONFIG.INFO;
  return (
    <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs font-semibold
      ${key === 'CRITICAL' ? 'bg-red-50 text-red-700 ring-1 ring-red-200' :
        key === 'WARNING'  ? 'bg-orange-50 text-orange-700 ring-1 ring-orange-200' :
                             'bg-slate-50 text-slate-600 ring-1 ring-slate-200'}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${cfg.dot}`} />
      {cfg.label}
    </span>
  );
};

const formatTime = (ns) => {
  if (!ns) return '—';
  const d = new Date(Number(ns) / 1_000_000);
  return d.toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
};

const formatDate = (ns) => {
  if (!ns) return '';
  const d = new Date(Number(ns) / 1_000_000);
  return d.toLocaleDateString([], { month: 'short', day: 'numeric' });
};

// ── Status badge ──────────────────────────────────────────────────────────────
// For historical sessions (isCapturing=false), is_ongoing=true just means the
// alert was still active when the session ended — show "Session Ended" instead of "Active"
const StatusBadge = ({ isOngoing, isCapturing }) => {
  if (!isOngoing) {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-green-50 text-green-700 ring-1 ring-green-200">
        <CheckCircle2 className="w-3 h-3" /> Resolved
      </span>
    );
  }
  if (!isCapturing) {
    // Historical session — "active" at end of session
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-slate-100 text-slate-600 ring-1 ring-slate-200">
        <span className="w-1.5 h-1.5 rounded-full bg-slate-400" />
        At session end
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-red-50 text-red-700 ring-1 ring-red-200 animate-pulse">
      <span className="w-1.5 h-1.5 rounded-full bg-red-500" />
      Active
    </span>
  );
};

// ── Expandable alert row ──────────────────────────────────────────────────────
const AlertRow = ({ alert, isCapturing }) => {
  const [expanded, setExpanded] = useState(false);
  const typeInfo = resolveType(alert.type);
  const TypeIcon = typeInfo?.icon || AlertTriangle;
  const hasDescription = !!alert.description;

  return (
    <>
      <tr
        className={`transition-colors border-b border-slate-100 ${
          hasDescription ? 'cursor-pointer hover:bg-blue-50/40' : 'hover:bg-slate-50'
        } ${expanded ? 'bg-blue-50/30' : ''}`}
        onClick={() => hasDescription && setExpanded(v => !v)}
        title={hasDescription ? 'Click to expand description' : undefined}
      >
        {/* Severity */}
        <td className="px-4 py-3 whitespace-nowrap">
          <SeverityBadge severity={alert.severity} />
        </td>

        {/* Time */}
        <td className="px-4 py-3 whitespace-nowrap">
          <div className="text-sm font-mono text-slate-700">{formatTime(alert.timestamp_ns)}</div>
          <div className="text-xs text-slate-400">{formatDate(alert.timestamp_ns)}</div>
        </td>

        {/* Title + truncated description */}
        <td className="px-4 py-3">
          <div className="flex items-start gap-2">
            <div className="min-w-0 flex-1">
              <div className="text-sm font-semibold text-slate-900">{alert.title}</div>
              {hasDescription && !expanded && (
                <div className="text-xs text-slate-500 mt-0.5 line-clamp-1 max-w-lg">
                  {alert.description}
                </div>
              )}
              {/* Source IP if present */}
              {alert.src_ip && (
                <div className="text-xs font-mono text-slate-400 mt-0.5">{alert.src_ip}</div>
              )}
            </div>
            {hasDescription && (
              <span className="shrink-0 mt-0.5 text-slate-400">
                {expanded
                  ? <ChevronDown className="w-3.5 h-3.5" />
                  : <ChevronRight className="w-3.5 h-3.5" />
                }
              </span>
            )}
          </div>
        </td>

        {/* Type */}
        <td className="px-4 py-3 whitespace-nowrap">
          {typeInfo ? (
            <span className="inline-flex items-center gap-1.5 text-xs text-slate-600">
              <TypeIcon className="w-3.5 h-3.5 text-slate-400 shrink-0" />
              <span className="font-medium">{typeInfo.label}</span>
            </span>
          ) : (
            <span className="text-xs text-slate-400">{alert.type || '—'}</span>
          )}
          {typeInfo?.group && (
            <div className="text-xs text-slate-400 mt-0.5 pl-5">{typeInfo.group}</div>
          )}
        </td>

        {/* Status */}
        <td className="px-4 py-3 whitespace-nowrap">
          <StatusBadge isOngoing={alert.is_ongoing} isCapturing={isCapturing} />
        </td>
      </tr>

      {/* Expanded description row */}
      {expanded && hasDescription && (
        <tr className="bg-blue-50/30 border-b border-blue-100">
          <td colSpan={5} className="px-4 pt-0 pb-4">
            <div className="ml-0 mt-2 p-3 bg-white rounded-lg border border-blue-100 shadow-sm">
              <div className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-1.5">
                Full Description
              </div>
              <p className="text-sm text-slate-700 leading-relaxed whitespace-pre-wrap">
                {alert.description}
              </p>
              {/* Context details */}
              <div className="mt-3 pt-3 border-t border-slate-100 grid grid-cols-2 sm:grid-cols-4 gap-3">
                {alert.src_ip && (
                  <div>
                    <div className="text-xs text-slate-400">Source IP</div>
                    <div className="text-xs font-mono text-slate-700 mt-0.5">{alert.src_ip}</div>
                  </div>
                )}
                {alert.dst_ip && (
                  <div>
                    <div className="text-xs text-slate-400">Destination IP</div>
                    <div className="text-xs font-mono text-slate-700 mt-0.5">{alert.dst_ip}</div>
                  </div>
                )}
                {alert.alert_id && (
                  <div>
                    <div className="text-xs text-slate-400">Alert ID</div>
                    <div className="text-xs font-mono text-slate-700 mt-0.5">#{alert.alert_id}</div>
                  </div>
                )}
                {typeInfo && (
                  <div>
                    <div className="text-xs text-slate-400">Detector</div>
                    <div className="text-xs text-slate-700 mt-0.5">{typeInfo.label}</div>
                  </div>
                )}
              </div>
            </div>
          </td>
        </tr>
      )}
    </>
  );
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

// ── Main ──────────────────────────────────────────────────────────────────────
const Alerts = () => {
  const { sessionId, isCapturing } = useCaptureStore();
  const navigate = useNavigate();
  const [search, setSearch] = useState('');
  const [filterSeverity, setFilterSeverity] = useState('ALL');

  const { data: alerts = [], isLoading } = useQuery({
    queryKey: ['alerts', sessionId, isCapturing],
    queryFn: async () => {
      if (!sessionId) return [];
      if (isCapturing) {
        const params = new URLSearchParams({ n: '500', session_id: sessionId });
        const res = await api.get(`/api/alerts?${params}`);
        return Array.isArray(res.data) ? res.data : [];
      } else {
        try {
          const res = await axios.get(`/ai/history/alerts?session_id=${sessionId}&limit=500`);
          return Array.isArray(res.data) ? res.data : [];
        } catch {
          const params = new URLSearchParams({ n: '500', session_id: sessionId });
          const res = await api.get(`/api/alerts?${params}`);
          return Array.isArray(res.data) ? res.data : [];
        }
      }
    },
    refetchInterval: isCapturing ? 5000 : false,
    enabled: !!sessionId,
  });

  const criticalCount  = alerts.filter(a => String(a.severity).toUpperCase() === 'CRITICAL' || a.severity === 2).length;
  const warningCount   = alerts.filter(a => String(a.severity).toUpperCase() === 'WARNING'  || a.severity === 1).length;
  const totalCount     = alerts.length;
  const resolvedCount  = alerts.filter(a => !a.is_ongoing).length;

  const filtered = alerts.filter(a => {
    const matchSearch = !search ||
      a.title?.toLowerCase().includes(search.toLowerCase()) ||
      a.description?.toLowerCase().includes(search.toLowerCase());

    const sevKey = typeof a.severity === 'number'
      ? (a.severity === 2 ? 'CRITICAL' : a.severity === 1 ? 'WARNING' : 'INFO')
      : String(a.severity || 'INFO').toUpperCase();
    const matchSev = filterSeverity === 'ALL' || sevKey === filterSeverity;

    return matchSearch && matchSev;
  });

  if (!sessionId) return <EmptySessionState navigate={navigate} />;

  return (
    <div className="space-y-4 h-full flex flex-col">
      {/* Header */}
      <div className="flex justify-between items-end shrink-0">
        <div>
          <h1 className="text-2xl font-semibold text-slate-900 tracking-tight flex items-center">
            <ShieldAlert className="w-6 h-6 mr-2 text-red-500" />
            Security Alerts
          </h1>
          <p className="text-slate-500 mt-1 text-sm">
            {isCapturing
              ? 'Live detection — anomalous behavior detected during this capture session'
              : 'Historical view — alerts recorded during this completed session'}
          </p>
        </div>
        {!isCapturing && (
          <span className="text-xs text-slate-400 bg-slate-100 px-3 py-1 rounded-full">
            Historical session — status shown at time of capture
          </span>
        )}
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
        {/* Toolbar */}
        <div className="p-4 border-b border-slate-200 bg-slate-50/70 shrink-0 flex items-center gap-3">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
            <input
              type="text"
              placeholder="Search by title or description..."
              className="w-full pl-9 pr-4 py-2 bg-white border border-slate-200 rounded-md text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
              value={search}
              onChange={e => setSearch(e.target.value)}
            />
          </div>
          {/* Severity filter */}
          <div className="flex items-center gap-1.5 shrink-0">
            {['ALL', 'CRITICAL', 'WARNING', 'INFO'].map(sev => (
              <button
                key={sev}
                onClick={() => setFilterSeverity(sev)}
                className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
                  filterSeverity === sev
                    ? sev === 'CRITICAL' ? 'bg-red-100 text-red-700'
                      : sev === 'WARNING' ? 'bg-orange-100 text-orange-700'
                      : sev === 'INFO' ? 'bg-slate-200 text-slate-700'
                      : 'bg-blue-100 text-blue-700'
                    : 'bg-white border border-slate-200 text-slate-500 hover:border-slate-300'
                }`}
              >
                {sev}
              </button>
            ))}
          </div>
        </div>

        {/* Table */}
        <div className="overflow-auto flex-1">
          {isLoading ? (
            <div className="p-8 text-center text-slate-500">Loading alerts...</div>
          ) : filtered.length === 0 ? (
            <div className="p-12 text-center text-slate-500">
              <CheckCircle2 className="w-10 h-10 mx-auto text-green-400 mb-3" />
              <p className="font-medium text-slate-700">No alerts found</p>
              <p className="text-sm mt-1">
                {search || filterSeverity !== 'ALL'
                  ? 'Try clearing your search or filter.'
                  : 'The detection engine found no anomalies in this session.'}
              </p>
            </div>
          ) : (
            <table className="w-full text-left border-collapse">
              <thead className="bg-slate-50/80 sticky top-0 z-10 border-b border-slate-200">
                <tr>
                  <th className="px-4 py-3 text-xs font-semibold text-slate-500 uppercase tracking-wider w-28">Severity</th>
                  <th className="px-4 py-3 text-xs font-semibold text-slate-500 uppercase tracking-wider w-28">Time</th>
                  <th className="px-4 py-3 text-xs font-semibold text-slate-500 uppercase tracking-wider">
                    Title &amp; Description
                    <span className="ml-1.5 text-slate-400 font-normal normal-case tracking-normal text-xs">
                      (click to expand)
                    </span>
                  </th>
                  <th className="px-4 py-3 text-xs font-semibold text-slate-500 uppercase tracking-wider w-44">Detector</th>
                  <th className="px-4 py-3 text-xs font-semibold text-slate-500 uppercase tracking-wider w-32">Status</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((alert, i) => (
                  <AlertRow
                    key={alert.alert_id || i}
                    alert={alert}
                    isCapturing={isCapturing}
                  />
                ))}
              </tbody>
            </table>
          )}
        </div>

        {/* Footer */}
        {filtered.length > 0 && (
          <div className="px-4 py-2.5 border-t border-slate-100 bg-slate-50/50 shrink-0">
            <p className="text-xs text-slate-400">
              Showing {filtered.length} of {totalCount} alerts
              {search && ` matching "${search}"`}
              {filterSeverity !== 'ALL' && ` · filtered to ${filterSeverity}`}
              {!isCapturing && ' · click any row to read the full description'}
            </p>
          </div>
        )}
      </Card>
    </div>
  );
};

export default Alerts;
