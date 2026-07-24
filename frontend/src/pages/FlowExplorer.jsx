import React, { useState, useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { Card } from '../components/ui/Card';
import { ProtocolBadge, Badge } from '../components/ui/Badge';
import { Search, Filter, ArrowRight, Download, Server, Layers, Sparkles, X } from 'lucide-react';
import { useCaptureStore } from '../store/captureStore';
import { useQuery } from '@tanstack/react-query';
import axios from 'axios';

const api = axios.create({ baseURL: '' });

const formatBytes = (bytes) => {
  if (!bytes && bytes !== 0) return '—';
  if (bytes >= 1e6) return (bytes / 1e6).toFixed(1) + ' MB';
  if (bytes >= 1e3) return (bytes / 1e3).toFixed(1) + ' KB';
  return bytes + ' B';
};

const getProtocolName = (proto) => {
  switch (proto) { case 6: return 'TCP'; case 17: return 'UDP'; case 1: return 'ICMP'; default: return 'OTHER'; }
};

const StackedByteBar = ({ fwd = 0, rev = 0 }) => {
  const total = fwd + rev;
  const fwdPct = total > 0 ? (fwd / total) * 100 : 0;
  return (
    <div className="w-full">
      <div className="text-xs text-slate-500 mb-1 flex justify-between">
        <span>{formatBytes(total)}</span>
        <span className="text-slate-400">{Math.round(fwdPct)}% out</span>
      </div>
      <div className="flex h-1.5 w-full bg-slate-100 rounded-full overflow-hidden">
        <div style={{ width: `${fwdPct}%` }} className="bg-blue-400" />
        <div style={{ width: `${100 - fwdPct}%` }} className="bg-slate-300" />
      </div>
    </div>
  );
};

const EmptySessionState = ({ navigate }) => (
  <div className="flex flex-col items-center justify-center h-96 text-center">
    <Layers className="w-12 h-12 text-slate-300 mb-4" />
    <h2 className="text-lg font-semibold text-slate-700 mb-2">No Session Selected</h2>
    <p className="text-slate-500 text-sm">Select a capture session first to explore flows.</p>
    <button onClick={() => navigate('/sessions')} className="mt-4 px-4 py-2 bg-indigo-600 text-white rounded-md text-sm font-medium hover:bg-indigo-700">
      Go to Sessions
    </button>
  </div>
);

// Maps human-friendly shorthand to search engine query syntax
const normalizeQuery = (q) => {
  const trimmed = q.trim();
  if (!trimmed) return '';
  const lower = trimmed.toLowerCase();
  // Protocol shorthands → proper field syntax
  if (lower === 'tcp') return 'protocol:TCP';
  if (lower === 'udp') return 'protocol:UDP';
  if (lower === 'dns') return 'protocol:DNS';
  if (lower === 'icmp') return 'protocol:ICMP';
  if (lower === 'http') return 'protocol:HTTP';
  if (lower === 'tls' || lower === 'https') return 'protocol:TLS';
  // Already looks like a field:value query — pass through
  return trimmed;
};

const FlowExplorer = () => {
  const { sessionId, isCapturing } = useCaptureStore();
  const navigate = useNavigate();
  const location = useLocation();
  const [search, setSearch] = useState('');
  const [submittedQuery, setSubmittedQuery] = useState('');
  const [page, setPage] = useState(0);
  const limit = 50;
  const [aiFlow, setAiFlow] = useState(null);
  const [aiExplanation, setAiExplanation] = useState('');
  const [aiLoading, setAiLoading] = useState(false);

  // Pre-fill search from AI Copilot chip navigation
  useEffect(() => {
    if (location.state?.searchQuery) {
      const q = location.state.searchQuery;
      setSearch(q);
      setSubmittedQuery(normalizeQuery(q));
      // Clear state so it doesn't re-trigger on back navigation
      window.history.replaceState({}, '');
    }
  }, [location.state]);

  // Auto-load on mount: query fires immediately with empty string
  const { data: result, isLoading, refetch } = useQuery({
    queryKey: ['flows-search', sessionId, submittedQuery, page],
    queryFn: async () => {
      if (!sessionId) return { results: [] };
      const res = await api.post('/api/search', {
        session_id: sessionId,
        query: submittedQuery,
        limit,
        offset: page * limit,
      });
      return res.data;
    },
    enabled: !!sessionId,
    refetchInterval: isCapturing ? 5000 : false,
  });

  // The backend returns { results: [...], count, latency_ms, query }
  const flows = result?.results || [];

  const handleSearch = (e) => {
    e.preventDefault();
    setPage(0);
    setSubmittedQuery(normalizeQuery(search));
  };

  const handleAiAnalyze = async (flow) => {
    setAiFlow(flow);
    setAiExplanation('');
    setAiLoading(true);
    try {
      const res = await api.post('/ai/explain-flow', { flow, session_id: sessionId });
      setAiExplanation(res.data?.explanation || 'No explanation returned.');
    } catch (e) {
      setAiExplanation('AI analysis failed. Make sure the AI service is running.');
    } finally {
      setAiLoading(false);
    }
  };

  if (!sessionId) return <EmptySessionState navigate={navigate} />;

  return (
    <div className="space-y-4 h-full flex flex-col">
      <div className="flex justify-between items-end shrink-0">
        <div>
          <h1 className="text-2xl font-semibold text-slate-900 tracking-tight">Flow Explorer</h1>
          <p className="text-slate-500 mt-1">Search, filter, and analyze network flows</p>
        </div>
        <div className="flex items-center space-x-3">
          {result?.count !== undefined && (
            <span className="text-sm text-slate-500">{result.count} rows · {result.latency_ms}ms</span>
          )}
          <button className="flex items-center space-x-2 px-3 py-1.5 text-sm font-medium text-slate-600 bg-white border border-slate-200 rounded-md hover:bg-slate-50">
            <Download className="w-4 h-4" />
            <span>Export CSV</span>
          </button>
        </div>
      </div>

      <Card className="p-4 shrink-0 shadow-sm border-slate-200">
        <form onSubmit={handleSearch} className="flex space-x-4">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
            <input
              type="text"
              placeholder='Filter flows e.g. dst_port=443 AND src_ip:10.0.0.0/8'
              className="w-full pl-9 pr-4 py-2 bg-slate-50 border border-slate-200 rounded-md text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:bg-white transition-all font-mono"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>
          <button
            type="submit"
            className="flex items-center space-x-2 px-4 py-2 bg-blue-600 text-white rounded-md text-sm font-medium hover:bg-blue-700"
          >
            <Filter className="w-4 h-4" />
            <span>Search</span>
          </button>
        </form>
      </Card>

      <Card noPadding className="flex-1 flex flex-col min-h-0">
        <div className="overflow-auto flex-1">
          <table className="w-full text-left border-collapse">
            <thead className="bg-slate-50/80 backdrop-blur sticky top-0 z-10 border-b border-slate-200 shadow-sm">
              <tr>
                <th className="px-4 py-3 text-xs font-semibold text-slate-500 uppercase tracking-wider w-24">Protocol</th>
                <th className="px-4 py-3 text-xs font-semibold text-slate-500 uppercase tracking-wider">Source</th>
                <th className="px-4 py-3 text-xs font-semibold text-slate-500 uppercase tracking-wider w-8"></th>
                <th className="px-4 py-3 text-xs font-semibold text-slate-500 uppercase tracking-wider">Destination</th>
                <th className="px-4 py-3 text-xs font-semibold text-slate-500 uppercase tracking-wider">App / SNI</th>
                <th className="px-4 py-3 text-xs font-semibold text-slate-500 uppercase tracking-wider w-36">Bytes</th>
                <th className="px-4 py-3 text-xs font-semibold text-slate-500 uppercase tracking-wider w-24">Duration</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {flows.map((flow, i) => (
                <tr key={flow.flow_id || i} className="hover:bg-slate-50 transition-colors cursor-pointer">
                  <td className="px-4 py-3 whitespace-nowrap">
                    <ProtocolBadge protocol={getProtocolName(flow.protocol)} />
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap text-sm font-mono text-slate-700">
                    {flow.src_ip}:{flow.src_port}
                  </td>
                  <td className="px-1 py-3 text-center text-slate-300">
                    <ArrowRight className="w-4 h-4 inline" />
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap text-sm font-mono text-slate-700">
                    <div className="flex items-center">
                      <Server className="w-3.5 h-3.5 mr-1.5 text-slate-400" />
                      {flow.dst_ip}:{flow.dst_port}
                    </div>
                  </td>
                  <td className="px-4 py-3 text-sm text-slate-500 max-w-[160px] truncate">
                    {flow.tls_sni || flow.http_host || flow.dns_query || '—'}
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap">
                    <span className="text-sm text-slate-500">{formatBytes(flow.payload_bytes)}</span>
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap text-sm text-slate-500">
                    {flow.duration_ms != null ? `${(flow.duration_ms / 1000).toFixed(2)}s` : '—'}
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap">
                    <button
                      onClick={() => handleAiAnalyze(flow)}
                      className="flex items-center gap-1 text-xs text-indigo-600 hover:text-indigo-800
                                 px-2 py-1 rounded hover:bg-indigo-50 transition-colors"
                      title="Analyze with AI"
                    >
                      <Sparkles className="w-3.5 h-3.5" />
                      AI
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {isLoading && (
            <div className="p-8 text-center text-slate-500">Searching flows...</div>
          )}
          {!isLoading && flows.length === 0 && (
            <div className="p-8 text-center text-slate-500">
              {submittedQuery
                ? `No flows matching "${submittedQuery}"`
                : 'No flows found for this session yet. Flows are stored when connections close.'}
            </div>
          )}
        </div>
        <div className="p-4 border-t border-slate-200 bg-slate-50 flex items-center justify-between text-sm text-slate-500 shrink-0">
          <span>{flows.length} flows shown (page {page + 1})</span>
          <div className="flex space-x-1">
            <button
              onClick={() => setPage(Math.max(0, page - 1))}
              disabled={page === 0}
              className="px-3 py-1 bg-white border border-slate-200 rounded text-slate-700 disabled:text-slate-400 disabled:cursor-not-allowed hover:bg-slate-50"
            >
              Previous
            </button>
            <button
              onClick={() => setPage(page + 1)}
              disabled={flows.length < limit}
              className="px-3 py-1 bg-white border border-slate-200 rounded text-slate-700 disabled:text-slate-400 disabled:cursor-not-allowed hover:bg-slate-50"
            >
              Next
            </button>
          </div>
        </div>
      </Card>

      {/* AI Explain Flow Modal */}
      {aiFlow && (
        <div className="fixed inset-0 z-50 flex items-end sm:items-center justify-center p-4 bg-black/40">
          <div className="bg-white rounded-2xl shadow-2xl w-full max-w-lg">
            <div className="flex items-center justify-between px-5 py-4 border-b border-slate-100">
              <div className="flex items-center gap-2">
                <Sparkles className="w-4 h-4 text-indigo-500" />
                <span className="font-semibold text-slate-900">AI Flow Analysis</span>
              </div>
              <button onClick={() => { setAiFlow(null); setAiExplanation(''); }}
                className="text-slate-400 hover:text-slate-600">
                <X className="w-4 h-4" />
              </button>
            </div>
            <div className="px-5 py-4">
              <div className="text-xs font-mono text-slate-500 mb-3">
                {aiFlow.src_ip}:{aiFlow.src_port} → {aiFlow.dst_ip}:{aiFlow.dst_port}
                {(aiFlow.tls_sni || aiFlow.http_host) && <span className="ml-2 text-indigo-600">({aiFlow.tls_sni || aiFlow.http_host})</span>}
              </div>
              {aiLoading
                ? <div className="flex items-center gap-2 text-sm text-slate-500 py-6 justify-center">
                    <div className="w-4 h-4 border-2 border-indigo-400 border-t-transparent rounded-full animate-spin" />
                    Analyzing with Groq...
                  </div>
                : <p className="text-sm text-slate-700 leading-relaxed">{aiExplanation}</p>
              }
            </div>
            <div className="px-5 py-3 border-t border-slate-100 flex justify-end">
              <button
                onClick={() => { setAiFlow(null); setAiExplanation(''); }}
                className="px-4 py-1.5 text-sm bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-lg"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default FlowExplorer;
