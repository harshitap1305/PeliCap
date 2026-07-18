import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import axios from 'axios';
import { Play, Plus, Activity, StopCircle, Clock, Database, ChevronRight, AlertCircle, X } from 'lucide-react';
import { format } from 'date-fns';
import { Card } from '../components/ui/Card';
import { useCaptureStore } from '../store/captureStore';

const api = axios.create({ baseURL: '' });

const Sessions = () => {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { sessionId, isCapturing, setCapturing, setSession, clearSession } = useCaptureStore();
  const [showModal, setShowModal] = useState(false);
  const [formData, setFormData] = useState({ name: '', description: '', interface: '', bpf_filter: '' });

  // Fetch all sessions
  const { data: sessions = [], isLoading } = useQuery({
    queryKey: ['sessions'],
    queryFn: async () => {
      const res = await api.get('/api/sessions');
      if (!Array.isArray(res.data)) {
        console.error('Expected array of sessions but got:', res.data);
        return [];
      }
      return res.data;
    },
    refetchInterval: isCapturing ? 3000 : 10000,
  });

  // Fetch available interfaces for the modal
  const { data: interfaces = [] } = useQuery({
    queryKey: ['interfaces'],
    queryFn: async () => {
      const res = await api.get('/api/interfaces');
      return Array.isArray(res.data) ? res.data : [];
    },
  });

  // Start Capture Mutation
  const startMutation = useMutation({
    mutationFn: async (data) => {
      const res = await api.post('/api/capture/start', data);
      return res.data;
    },
    onSuccess: (data) => {
      // Set session identity first, then mark as capturing
      setSession(data.session_id, formData.name || 'Unnamed Session', formData.interface);
      setCapturing(true);
      setShowModal(false);
      setFormData({ name: '', description: '', interface: '', bpf_filter: '' });
      queryClient.invalidateQueries(['sessions']);
      navigate('/overview');
    },
  });

  // Stop Capture Mutation
  const stopMutation = useMutation({
    mutationFn: async () => {
      const res = await api.post('/api/capture/stop');
      return res.data;
    },
    onSuccess: () => {
      setCapturing(false);
      queryClient.invalidateQueries(['sessions']);
    },
  });

  const handleStartCapture = (e) => {
    e.preventDefault();
    if (!formData.interface) return;
    startMutation.mutate({
      interface: formData.interface,
      name: formData.name || 'Unnamed Session',
      description: formData.description,
      bpf_filter: formData.bpf_filter,
      promiscuous: true,
    });
  };

  const selectSession = (session) => {
    // Set session data for historical browse mode
    setSession(session.session_id, session.name || 'Unnamed Session', session.interface_name);
    // Mark as NOT live capturing (historical mode)
    setCapturing(false);
    navigate('/overview');
  };

  // Detect active session: either from store (immediately after start) or from DB
  const activeSessionFromDb = Array.isArray(sessions) ? sessions.find(s => s.end_time === null) : null;
  const isLive = isCapturing;

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-semibold text-slate-900 tracking-tight">Capture Sessions</h1>
          <p className="text-slate-500 mt-1">Manage active captures and review historical network data</p>
        </div>
        <div className="flex space-x-3">
          {isLive ? (
            <button
              onClick={() => stopMutation.mutate()}
              disabled={stopMutation.isPending}
              className="flex items-center px-4 py-2 bg-red-600 text-white rounded-md hover:bg-red-700 font-medium transition-colors shadow-sm disabled:opacity-60"
            >
              <StopCircle className="w-4 h-4 mr-2" />
              {stopMutation.isPending ? 'Stopping...' : 'Stop Active Capture'}
            </button>
          ) : (
            <button
              onClick={() => setShowModal(true)}
              className="flex items-center px-4 py-2 bg-indigo-600 text-white rounded-md hover:bg-indigo-700 font-medium transition-colors shadow-sm"
            >
              <Plus className="w-4 h-4 mr-2" />
              Start New Capture
            </button>
          )}
        </div>
      </div>

      {/* Active session banner */}
      {(isLive || activeSessionFromDb) && (
        <Card className="border-indigo-200 bg-indigo-50/50">
          <div className="flex justify-between items-center">
            <div className="flex items-center space-x-4">
              <div className="w-10 h-10 bg-indigo-100 rounded-full flex items-center justify-center">
                <div className="relative flex h-3 w-3">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-indigo-400 opacity-75"></span>
                  <span className="relative inline-flex rounded-full h-3 w-3 bg-indigo-600"></span>
                </div>
              </div>
              <div>
                <h3 className="font-semibold text-indigo-900 text-lg">
                  {activeSessionFromDb?.name || 'Active Capture'}
                  <span className="ml-3 inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-indigo-100 text-indigo-800">
                    Live
                  </span>
                </h3>
                <p className="text-indigo-700 text-sm mt-0.5">
                  Capturing on {activeSessionFromDb?.interface_name || '...'}
                </p>
              </div>
            </div>
            <button
              onClick={() => activeSessionFromDb ? selectSession(activeSessionFromDb) : navigate('/overview')}
              className="flex items-center px-4 py-2 bg-white border border-indigo-200 text-indigo-700 rounded-md hover:bg-indigo-50 font-medium transition-colors"
            >
              View Live Dashboard
              <ChevronRight className="w-4 h-4 ml-2" />
            </button>
          </div>
        </Card>
      )}

      {/* Historical sessions list */}
      <Card title="Historical Sessions" noPadding>
        {isLoading ? (
          <div className="p-8 text-center text-slate-500">Loading sessions...</div>
        ) : sessions.filter(s => s.end_time !== null).length === 0 ? (
          <div className="p-12 text-center text-slate-500">
            <Database className="w-12 h-12 mx-auto text-slate-300 mb-4" />
            <p className="text-lg font-medium text-slate-900">No completed sessions yet</p>
            <p className="mt-1">Start and stop a capture to create a session you can analyze.</p>
          </div>
        ) : (
          <div className="divide-y divide-slate-200">
            {sessions.filter(s => s.end_time !== null).map((session) => (
              <div
                key={session.session_id}
                onClick={() => selectSession(session)}
                className="p-4 hover:bg-slate-50 cursor-pointer transition-colors flex items-center justify-between group"
              >
                <div className="flex items-start space-x-4">
                  <div className="w-10 h-10 rounded bg-slate-100 flex items-center justify-center shrink-0 mt-1">
                    <Activity className="w-5 h-5 text-slate-500" />
                  </div>
                  <div>
                    <h4 className="font-medium text-slate-900">{session.name || 'Unnamed Session'}</h4>
                    {session.description && (
                      <p className="text-sm text-slate-500 mt-0.5">{session.description}</p>
                    )}
                    <div className="flex items-center space-x-4 mt-2 text-xs text-slate-500 font-medium">
                      <span className="flex items-center">
                        <Clock className="w-3.5 h-3.5 mr-1" />
                        {session.start_time ? format(new Date(session.start_time), 'MMM d, yyyy HH:mm:ss') : '—'}
                      </span>
                      <span className="flex items-center bg-slate-100 px-2 py-0.5 rounded">
                        {session.interface_name}
                      </span>
                      <span>
                        {(session.packets_captured || 0).toLocaleString()} packets
                      </span>
                    </div>
                  </div>
                </div>
                <div className="opacity-0 group-hover:opacity-100 transition-opacity">
                  <ChevronRight className="w-5 h-5 text-slate-400" />
                </div>
              </div>
            ))}
          </div>
        )}
      </Card>

      {/* Start Capture Modal */}
      {showModal && (
        <div className="fixed inset-0 bg-slate-900/50 z-50 flex items-center justify-center p-4">
          <div className="bg-white rounded-lg shadow-xl w-full max-w-md overflow-hidden">
            <div className="px-6 py-4 border-b border-slate-200 flex justify-between items-center">
              <h3 className="text-lg font-semibold text-slate-900">Start New Capture</h3>
              <button onClick={() => { setShowModal(false); startMutation.reset(); }} className="text-slate-400 hover:text-slate-600">
                <X className="w-5 h-5" />
              </button>
            </div>

            {startMutation.isError && (
              <div className="mx-6 mt-4 p-3 bg-red-50 border border-red-200 rounded-md flex items-start space-x-2">
                <AlertCircle className="w-4 h-4 text-red-500 mt-0.5 shrink-0" />
                <p className="text-sm text-red-700">
                  {startMutation.error?.response?.data?.error || 'Failed to start capture. Check the interface name.'}
                </p>
              </div>
            )}

            <form onSubmit={handleStartCapture} className="p-6 space-y-4">
              <div>
                <label className="block text-sm font-medium text-slate-700 mb-1">
                  Session Name <span className="text-slate-400">(optional)</span>
                </label>
                <input
                  type="text"
                  className="w-full px-3 py-2 border border-slate-300 rounded-md text-sm focus:ring-indigo-500 focus:border-indigo-500"
                  placeholder="e.g. Debugging HTTP spikes"
                  value={formData.name}
                  onChange={e => setFormData({ ...formData, name: e.target.value })}
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-slate-700 mb-1">
                  Interface <span className="text-red-500">*</span>
                </label>
                <select
                  required
                  className="w-full px-3 py-2 border border-slate-300 rounded-md text-sm bg-white focus:ring-indigo-500 focus:border-indigo-500"
                  value={formData.interface}
                  onChange={e => setFormData({ ...formData, interface: e.target.value })}
                >
                  <option value="">Select an interface...</option>
                  {interfaces.map(iface => (
                    <option key={iface.name} value={iface.name}>
                      {iface.name}{iface.ip_address ? ` (${iface.ip_address})` : ''}
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-sm font-medium text-slate-700 mb-1">
                  Description <span className="text-slate-400">(optional)</span>
                </label>
                <textarea
                  className="w-full px-3 py-2 border border-slate-300 rounded-md text-sm"
                  rows={2}
                  placeholder="What are you capturing?"
                  value={formData.description}
                  onChange={e => setFormData({ ...formData, description: e.target.value })}
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-slate-700 mb-1">
                  BPF Filter <span className="text-slate-400">(optional)</span>
                </label>
                <input
                  type="text"
                  className="w-full px-3 py-2 border border-slate-300 rounded-md text-sm font-mono focus:ring-indigo-500 focus:border-indigo-500"
                  placeholder="tcp port 80"
                  value={formData.bpf_filter}
                  onChange={e => setFormData({ ...formData, bpf_filter: e.target.value })}
                />
              </div>

              <div className="pt-2 flex justify-end space-x-3">
                <button
                  type="button"
                  onClick={() => { setShowModal(false); startMutation.reset(); }}
                  className="px-4 py-2 border border-slate-300 text-sm font-medium rounded-md text-slate-700 bg-white hover:bg-slate-50"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={!formData.interface || startMutation.isPending}
                  className="inline-flex items-center px-4 py-2 text-sm font-medium rounded-md text-white bg-indigo-600 hover:bg-indigo-700 disabled:opacity-50"
                >
                  <Play className="w-4 h-4 mr-2" />
                  {startMutation.isPending ? 'Starting...' : 'Start Capture'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};

export default Sessions;
