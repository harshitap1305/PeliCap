import React from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import axios from 'axios';
import { useCaptureStore } from '../../store/captureStore';
import { StopCircle, ArrowLeftRight, Radio, History, AlertCircle } from 'lucide-react';

const api = axios.create({ baseURL: '' });

const SessionBanner = () => {
  // ALL hooks must be called unconditionally at the top
  const { sessionId, sessionName, sessionInterface, isCapturing, setCapturing, clearSession } = useCaptureStore();
  const navigate = useNavigate();
  const location = useLocation();
  const queryClient = useQueryClient();

  const stopMutation = useMutation({
    mutationFn: () => api.post('/api/capture/stop'),
    onSuccess: () => {
      setCapturing(false);
      queryClient.invalidateQueries(['sessions']);
    },
  });

  // Conditional renders happen AFTER all hooks
  if (location.pathname === '/sessions') return null;

  // No session selected
  if (!sessionId) {
    return (
      <div className="shrink-0 bg-amber-50 border-b border-amber-200 px-6 py-2.5 flex items-center justify-between">
        <div className="flex items-center space-x-2 text-amber-800 text-sm">
          <AlertCircle className="w-4 h-4 text-amber-500" />
          <span>No session selected — data cannot be shown without a capture session.</span>
        </div>
        <button
          onClick={() => navigate('/sessions')}
          className="flex items-center text-sm font-medium text-amber-700 hover:text-amber-900 underline"
        >
          Go to Sessions →
        </button>
      </div>
    );
  }

  // Live capture active
  if (isCapturing) {
    return (
      <div className="shrink-0 bg-emerald-50 border-b border-emerald-200 px-6 py-2 flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <div className="relative flex h-2.5 w-2.5">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
            <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-emerald-500"></span>
          </div>
          <Radio className="w-4 h-4 text-emerald-600" />
          <span className="text-sm font-semibold text-emerald-800">LIVE</span>
          <span className="text-sm text-emerald-700">
            {sessionName || 'Active Capture'}
            {sessionInterface && <span className="ml-1 opacity-70">on {sessionInterface}</span>}
          </span>
        </div>
        <div className="flex items-center space-x-3">
          <button
            onClick={() => { clearSession(); navigate('/sessions'); }}
            className="flex items-center text-xs font-medium text-emerald-700 hover:text-emerald-900 border border-emerald-300 rounded px-2 py-1 hover:bg-emerald-100"
          >
            <ArrowLeftRight className="w-3.5 h-3.5 mr-1" />
            Switch Session
          </button>
          <button
            onClick={() => stopMutation.mutate()}
            disabled={stopMutation.isPending}
            className="flex items-center text-xs font-medium text-red-600 hover:text-red-800 border border-red-200 rounded px-2 py-1 hover:bg-red-50 disabled:opacity-50"
          >
            <StopCircle className="w-3.5 h-3.5 mr-1" />
            {stopMutation.isPending ? 'Stopping...' : 'Stop Capture'}
          </button>
        </div>
      </div>
    );
  }

  // Historical session selected
  return (
    <div className="shrink-0 bg-blue-50 border-b border-blue-200 px-6 py-2 flex items-center justify-between">
      <div className="flex items-center space-x-3">
        <History className="w-4 h-4 text-blue-500" />
        <span className="text-sm font-medium text-blue-800">Browsing:</span>
        <span className="text-sm text-blue-700">
          {sessionName || 'Unnamed Session'}
          {sessionInterface && <span className="ml-1 opacity-70">on {sessionInterface}</span>}
        </span>
        <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-blue-100 text-blue-700">
          Historical
        </span>
      </div>
      <button
        onClick={() => { clearSession(); navigate('/sessions'); }}
        className="flex items-center text-xs font-medium text-blue-600 hover:text-blue-800 border border-blue-200 rounded px-2 py-1 hover:bg-blue-100"
      >
        <ArrowLeftRight className="w-3.5 h-3.5 mr-1" />
        Switch Session
      </button>
    </div>
  );
};

export default SessionBanner;
