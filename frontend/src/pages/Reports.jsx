import React, { useState, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { Card } from '../components/ui/Card';
import { Badge } from '../components/ui/Badge';
import { useCaptureStore } from '../store/captureStore';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import axios from 'axios';
import {
  FileText, Download, Trash2, Loader2, CheckCircle2, XCircle,
  ChevronDown, ChevronUp, Layers, Bot, ShieldAlert, Globe,
  MonitorCheck, Activity, RefreshCw, Eye
} from 'lucide-react';

// AI service runs on port 8001
const aiApi = axios.create({ baseURL: 'http://localhost:8001' });
// C++ backend on 8080 (for session check)
const api = axios.create({ baseURL: '' });

// ── Report type configs ────────────────────────────────────────────────────────
const REPORT_TYPES = [
  {
    id: 'traffic_summary',
    label: 'Traffic Summary',
    description: 'Total traffic volume, protocol distribution, top talkers, bandwidth over time.',
    icon: Activity,
    color: 'text-blue-600 bg-blue-50',
    borderColor: 'border-blue-500',
  },
  {
    id: 'dns',
    label: 'DNS Report',
    description: 'DNS query analysis, top domains, resolution times, NXDOMAIN patterns.',
    icon: Globe,
    color: 'text-amber-600 bg-amber-50',
    borderColor: 'border-amber-500',
  },
  {
    id: 'http_performance',
    label: 'HTTP Performance',
    description: 'Web traffic analysis, top destinations, latency, HTTP host breakdown.',
    icon: MonitorCheck,
    color: 'text-purple-600 bg-purple-50',
    borderColor: 'border-purple-500',
  },
  {
    id: 'security',
    label: 'Security Report',
    description: 'All security alerts, suspicious flows, elevated RTT and retransmit patterns.',
    icon: ShieldAlert,
    color: 'text-red-600 bg-red-50',
    borderColor: 'border-red-500',
  },
  {
    id: 'root_cause_analysis',
    label: 'Root Cause Analysis',
    description: 'AI-driven RCA: incident timeline, probable root cause, recommendations.',
    icon: Bot,
    color: 'text-indigo-600 bg-indigo-50',
    borderColor: 'border-indigo-500',
  },
];

const FORMAT_OPTIONS = [
  { value: 'pdf',      label: 'PDF',      desc: 'Professional PDF with charts' },
  { value: 'docx',     label: 'Word',     desc: 'Editable Word document' },
  { value: 'markdown', label: 'Markdown', desc: 'Plain Markdown with YAML front matter' },
];

// ── Helper utilities ──────────────────────────────────────────────────────────

const formatBytes = (b) => {
  if (!b) return '—';
  if (b >= 1e9) return `${(b / 1e9).toFixed(2)} GB`;
  if (b >= 1e6) return `${(b / 1e6).toFixed(2)} MB`;
  if (b >= 1e3) return `${(b / 1e3).toFixed(1)} KB`;
  return `${b} B`;
};

const formatMs = (ms) => {
  if (!ms) return '—';
  if (ms >= 60000) return `${(ms / 60000).toFixed(1)}m`;
  if (ms >= 1000) return `${(ms / 1000).toFixed(1)}s`;
  return `${ms}ms`;
};

const statusIcon = (status) => {
  if (status === 'completed') return <CheckCircle2 className="w-4 h-4 text-green-600" />;
  if (status === 'failed') return <XCircle className="w-4 h-4 text-red-600" />;
  if (status === 'running') return <Loader2 className="w-4 h-4 text-blue-600 animate-spin" />;
  return <Loader2 className="w-4 h-4 text-slate-400 animate-spin" />;
};

const statusBadgeVariant = { completed: 'success', failed: 'critical', running: 'info', queued: 'neutral' };

// ── Report type card ──────────────────────────────────────────────────────────
const ReportTypeCard = ({ type, selected, onSelect }) => {
  const Icon = type.icon;
  return (
    <button
      onClick={() => onSelect(type.id)}
      className={`w-full text-left p-4 rounded-xl border-2 transition-all duration-150 ${
        selected
          ? `${type.borderColor} bg-white shadow-md`
          : 'border-slate-200 bg-white hover:border-slate-300 hover:shadow-sm'
      }`}
    >
      <div className="flex items-start gap-3">
        <div className={`p-2 rounded-lg ${type.color}`}>
          <Icon className="w-5 h-5" />
        </div>
        <div className="min-w-0 flex-1">
          <div className="font-semibold text-sm text-slate-900">{type.label}</div>
          <div className="text-xs text-slate-500 mt-0.5 leading-relaxed">{type.description}</div>
        </div>
      </div>
    </button>
  );
};

// ── Progress bar ──────────────────────────────────────────────────────────────
const ProgressBar = ({ pct, step }) => (
  <div className="mt-4">
    <div className="flex justify-between text-xs text-slate-500 mb-1.5">
      <span>{step}</span>
      <span>{pct}%</span>
    </div>
    <div className="w-full bg-slate-100 rounded-full h-2">
      <div
        className="bg-blue-600 h-2 rounded-full transition-all duration-500"
        style={{ width: `${pct}%` }}
      />
    </div>
  </div>
);

// ── No session state ──────────────────────────────────────────────────────────
const NoSession = ({ navigate }) => (
  <div className="flex flex-col items-center justify-center h-96 text-center">
    <Layers className="w-12 h-12 text-slate-300 mb-4" />
    <h2 className="text-lg font-semibold text-slate-700 mb-2">No Session Selected</h2>
    <p className="text-slate-500 text-sm">Select a capture session first to generate reports.</p>
    <button
      onClick={() => navigate('/sessions')}
      className="mt-4 px-4 py-2 bg-blue-600 text-white rounded-md text-sm font-medium hover:bg-blue-700"
    >
      Go to Sessions
    </button>
  </div>
);

// ── Main component ────────────────────────────────────────────────────────────
const Reports = () => {
  const { sessionId } = useCaptureStore();
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  // Generator state
  const [selectedType, setSelectedType] = useState('traffic_summary');
  const [selectedFormat, setSelectedFormat] = useState('pdf');
  const [includeAi, setIncludeAi] = useState(true);
  const [topN, setTopN] = useState(20);
  const [activeJobId, setActiveJobId] = useState(null);
  const [previewReportId, setPreviewReportId] = useState(null);

  // Poll active job
  const { data: jobData } = useQuery({
    queryKey: ['report-job', activeJobId],
    queryFn: () => aiApi.get(`/api/reports/jobs/${activeJobId}`).then(r => r.data),
    enabled: !!activeJobId,
    refetchInterval: (data) => {
      if (!data) return 2000;
      return ['completed', 'failed'].includes(data.status) ? false : 2000;
    },
    onSuccess: (data) => {
      if (data.status === 'completed') {
        setActiveJobId(null);
        queryClient.invalidateQueries(['reports-list']);
      } else if (data.status === 'failed') {
        setActiveJobId(null);
      }
    }
  });

  // List reports
  const { data: reports = [], isLoading: reportsLoading, refetch: refetchReports } = useQuery({
    queryKey: ['reports-list', sessionId],
    queryFn: () =>
      aiApi.get('/api/reports', { params: { session_id: sessionId, limit: 50 } })
        .then(r => r.data),
    enabled: !!sessionId,
  });

  // Generate mutation
  const generateMutation = useMutation({
    mutationFn: (payload) => aiApi.post('/api/reports/generate', payload).then(r => r.data),
    onSuccess: (data) => {
      setActiveJobId(data.job_id);
    },
  });

  // Delete mutation
  const deleteMutation = useMutation({
    mutationFn: (reportId) => aiApi.delete(`/api/reports/${reportId}`),
    onSuccess: () => queryClient.invalidateQueries(['reports-list']),
  });

  const handleGenerate = () => {
    if (!sessionId) return;
    generateMutation.mutate({
      report_type: selectedType,
      session_id: sessionId,
      format: selectedFormat,
      include_ai: includeAi,
      top_n: topN,
    });
  };

  const handleDownload = async (reportId) => {
    const url = `http://localhost:8001/api/reports/${reportId}/download`;
    const link = document.createElement('a');
    link.href = url;
    link.target = '_blank';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const isGenerating = !!activeJobId && jobData?.status === 'running';
  const jobComplete = jobData?.status === 'completed';
  const jobFailed = jobData?.status === 'failed';

  if (!sessionId) return <NoSession navigate={navigate} />;

  return (
    <div className="space-y-6">

      {/* Page header */}
      <div>
        <h1 className="text-2xl font-bold text-slate-900 tracking-tight">Reports</h1>
        <p className="text-slate-500 text-sm mt-1">
          Generate professional PDF, Word, or Markdown reports from captured session data.
        </p>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">

        {/* ── Left: Report Generator ─────────────────────────────────────── */}
        <div className="xl:col-span-1 space-y-4">
          <Card className="p-5">
            <h2 className="text-sm font-semibold text-slate-700 uppercase tracking-wider mb-4">
              1 — Choose Report Type
            </h2>
            <div className="space-y-2">
              {REPORT_TYPES.map(type => (
                <ReportTypeCard
                  key={type.id}
                  type={type}
                  selected={selectedType === type.id}
                  onSelect={setSelectedType}
                />
              ))}
            </div>
          </Card>

          <Card className="p-5">
            <h2 className="text-sm font-semibold text-slate-700 uppercase tracking-wider mb-4">
              2 — Configure
            </h2>

            {/* Format */}
            <div className="mb-4">
              <label className="text-xs font-medium text-slate-600 mb-2 block">Export Format</label>
              <div className="grid grid-cols-3 gap-2">
                {FORMAT_OPTIONS.map(fmt => (
                  <button
                    key={fmt.value}
                    onClick={() => setSelectedFormat(fmt.value)}
                    className={`text-center p-2.5 rounded-lg border text-xs font-medium transition-all ${
                      selectedFormat === fmt.value
                        ? 'border-blue-500 bg-blue-50 text-blue-700'
                        : 'border-slate-200 text-slate-600 hover:border-slate-300'
                    }`}
                  >
                    <div className="font-bold text-sm">{fmt.label}</div>
                    <div className="text-slate-400 font-normal mt-0.5">{fmt.desc}</div>
                  </button>
                ))}
              </div>
            </div>

            {/* AI Narrative toggle */}
            <div className="flex items-center justify-between mb-4">
              <div>
                <div className="text-xs font-medium text-slate-700">AI Narrative</div>
                <div className="text-xs text-slate-400">Adds AI-generated analysis paragraphs</div>
              </div>
              <button
                onClick={() => setIncludeAi(v => !v)}
                className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors ${
                  includeAi ? 'bg-blue-600' : 'bg-slate-200'
                }`}
              >
                <span className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white shadow transition-transform ${
                  includeAi ? 'translate-x-4' : 'translate-x-1'
                }`} />
              </button>
            </div>

            {/* Top N */}
            <div className="mb-5">
              <label className="text-xs font-medium text-slate-600 mb-1 block">
                Top N Items — {topN}
              </label>
              <input
                type="range"
                min={10} max={100} step={10}
                value={topN}
                onChange={(e) => setTopN(Number(e.target.value))}
                className="w-full accent-blue-600"
              />
              <div className="flex justify-between text-xs text-slate-400 mt-0.5">
                <span>10</span><span>100</span>
              </div>
            </div>

            {/* Generate button */}
            <button
              onClick={handleGenerate}
              disabled={isGenerating || !!activeJobId}
              className="w-full py-2.5 bg-blue-600 hover:bg-blue-700 disabled:opacity-60
                         text-white font-semibold rounded-lg transition-colors flex items-center
                         justify-center gap-2 text-sm"
            >
              {isGenerating
                ? <><Loader2 className="w-4 h-4 animate-spin" /> Generating…</>
                : <><FileText className="w-4 h-4" /> Generate Report</>
              }
            </button>

            {/* Progress */}
            {activeJobId && jobData && (
              <ProgressBar
                pct={jobData.progress_pct || 0}
                step={jobData.current_step || 'Processing…'}
              />
            )}
            {jobFailed && (
              <div className="mt-3 p-3 bg-red-50 border border-red-200 rounded-lg text-xs text-red-700">
                <strong>Failed:</strong> {jobData?.error_message || 'Unknown error'}
              </div>
            )}
            {jobComplete && (
              <div className="mt-3 p-3 bg-green-50 border border-green-200 rounded-lg text-xs text-green-700 flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4" />
                Report generated successfully!
              </div>
            )}
          </Card>
        </div>

        {/* ── Right: Recent Reports ──────────────────────────────────────── */}
        <div className="xl:col-span-2 space-y-4">
          <Card>
            <div className="flex items-center justify-between px-5 py-4 border-b border-slate-100">
              <h2 className="font-semibold text-slate-900">Generated Reports</h2>
              <button
                onClick={() => refetchReports()}
                className="p-1.5 hover:bg-slate-100 rounded text-slate-500 transition-colors"
                title="Refresh"
              >
                <RefreshCw className="w-4 h-4" />
              </button>
            </div>

            {reportsLoading && (
              <div className="p-8 text-center text-slate-500 text-sm">Loading reports…</div>
            )}

            {!reportsLoading && reports.length === 0 && (
              <div className="p-12 text-center">
                <FileText className="w-10 h-10 text-slate-200 mx-auto mb-3" />
                <p className="text-slate-500 text-sm">No reports generated yet.</p>
                <p className="text-slate-400 text-xs mt-1">Use the generator on the left to create your first report.</p>
              </div>
            )}

            {reports.length > 0 && (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-slate-100 bg-slate-50/70">
                      <th className="px-5 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wider">Type</th>
                      <th className="px-4 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wider">Format</th>
                      <th className="px-4 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wider">Size</th>
                      <th className="px-4 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wider">Gen Time</th>
                      <th className="px-4 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wider">Created</th>
                      <th className="px-4 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wider">AI</th>
                      <th className="px-4 py-3 text-right text-xs font-semibold text-slate-500 uppercase tracking-wider">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {reports.map(r => (
                      <tr key={r.report_id} className="border-b border-slate-50 hover:bg-slate-50/60 transition-colors">
                        <td className="px-5 py-3">
                          <div className="font-medium text-slate-800 text-sm">{r.title}</div>
                          {r.created_by === 'auto' && (
                            <span className="text-xs text-amber-600">Auto-generated</span>
                          )}
                        </td>
                        <td className="px-4 py-3">
                          <span className="px-2 py-0.5 bg-slate-100 text-slate-600 rounded text-xs font-mono uppercase">
                            {r.format}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-slate-500 font-mono text-xs">
                          {formatBytes(r.file_size_bytes)}
                        </td>
                        <td className="px-4 py-3 text-slate-500 text-xs">
                          {formatMs(r.generation_time_ms)}
                        </td>
                        <td className="px-4 py-3 text-slate-500 text-xs">
                          {r.created_at ? new Date(r.created_at).toLocaleString([], {
                            month: 'short', day: 'numeric',
                            hour: '2-digit', minute: '2-digit'
                          }) : '—'}
                        </td>
                        <td className="px-4 py-3">
                          {r.ai_narrative_included
                            ? <span className="text-indigo-600 text-xs font-medium">✦ AI</span>
                            : <span className="text-slate-300 text-xs">—</span>
                          }
                        </td>
                        <td className="px-4 py-3">
                          <div className="flex items-center justify-end gap-1.5">
                            {r.format === 'pdf' && (
                              <button
                                onClick={() => setPreviewReportId(
                                  previewReportId === r.report_id ? null : r.report_id
                                )}
                                className="p-1.5 hover:bg-blue-50 text-slate-400 hover:text-blue-600 rounded transition-colors"
                                title="Preview"
                              >
                                <Eye className="w-4 h-4" />
                              </button>
                            )}
                            <button
                              onClick={() => handleDownload(r.report_id)}
                              className="p-1.5 hover:bg-green-50 text-slate-400 hover:text-green-600 rounded transition-colors"
                              title="Download"
                            >
                              <Download className="w-4 h-4" />
                            </button>
                            <button
                              onClick={() => deleteMutation.mutate(r.report_id)}
                              className="p-1.5 hover:bg-red-50 text-slate-400 hover:text-red-600 rounded transition-colors"
                              title="Delete"
                            >
                              <Trash2 className="w-4 h-4" />
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Card>

          {/* PDF Preview */}
          {previewReportId && (
            <Card className="overflow-hidden">
              <div className="flex items-center justify-between px-5 py-3 border-b border-slate-100">
                <h2 className="font-semibold text-slate-900 text-sm">Report Preview</h2>
                <button
                  onClick={() => setPreviewReportId(null)}
                  className="text-slate-400 hover:text-slate-600 text-xs"
                >
                  Close
                </button>
              </div>
              <iframe
                src={`http://localhost:8001/api/reports/${previewReportId}/download`}
                className="w-full"
                style={{ height: '700px', border: 'none' }}
                title="Report Preview"
              />
            </Card>
          )}
        </div>
      </div>
    </div>
  );
};

export default Reports;
