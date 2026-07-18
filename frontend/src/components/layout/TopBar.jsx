import React, { useEffect, useRef, useState } from 'react';
import { Bell, Wifi, WifiOff } from 'lucide-react';
import { useCaptureStore } from '../../store/captureStore';
import { useQuery } from '@tanstack/react-query';
import axios from 'axios';

const api = axios.create({ baseURL: '' });

const TopBar = () => {
  const { isCapturing, sessionId } = useCaptureStore();
  const [wsConnected, setWsConnected] = useState(false);
  const wsRef = useRef(null);

  // Live packet/flow counters
  const { data: stats } = useQuery({
    queryKey: ['stats'],
    queryFn: async () => {
      const res = await api.get('/api/stats');
      return res.data;
    },
    refetchInterval: 2000,
    enabled: isCapturing,
  });

  // Alert count for the bell badge (session-scoped)
  const { data: alertsData = [] } = useQuery({
    queryKey: ['alerts-count', sessionId],
    queryFn: () =>
      api.get(`/api/alerts?n=100${sessionId ? `&session_id=${sessionId}` : ''}`).then(r =>
        Array.isArray(r.data) ? r.data : []
      ),
    refetchInterval: isCapturing ? 10000 : false,
    enabled: !!sessionId,
  });

  const alertCount = Array.isArray(alertsData) ? alertsData.length : 0;

  // WebSocket health check — try to connect to WS endpoint; track open/close
  useEffect(() => {
    if (!isCapturing) {
      setWsConnected(false);
      return;
    }

    const connect = () => {
      const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const ws = new WebSocket(`${wsProtocol}//${window.location.host}/ws/metrics`);
      wsRef.current = ws;
      ws.onopen = () => setWsConnected(true);
      ws.onclose = () => setWsConnected(false);
      ws.onerror = () => setWsConnected(false);
    };

    connect();
    return () => {
      if (wsRef.current) wsRef.current.close();
    };
  }, [isCapturing]);

  return (
    <header className="h-14 bg-white border-b border-slate-200 flex items-center justify-between px-6 shrink-0 z-10">
      <div className="flex items-center">
        {/* Capture Status */}
        <div className="flex items-center space-x-2 px-3 py-1.5 bg-slate-50 rounded-md border border-slate-200">
          <div className="relative flex h-2.5 w-2.5">
            {isCapturing && (
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75" />
            )}
            <span className={`relative inline-flex rounded-full h-2.5 w-2.5 ${isCapturing ? 'bg-green-500' : 'bg-slate-400'}`} />
          </div>
          <span className="text-sm font-medium text-slate-700">
            {isCapturing ? 'Capturing' : sessionId ? 'Historical Mode' : 'Not Capturing'}
          </span>
          {isCapturing && stats && (
            <>
              <span className="text-sm text-slate-400 mx-1">•</span>
              <span className="text-sm font-medium text-slate-600">{(stats.packets_captured || 0).toLocaleString()} pkts</span>
            </>
          )}
        </div>
      </div>

      <div className="flex items-center space-x-4">
        {/* Alert Bell — only shows badge if there are real alerts */}
        <div className="relative">
          <button
            className="relative p-2 text-slate-500 hover:text-slate-700 hover:bg-slate-100 rounded-full transition-colors"
            title={alertCount > 0 ? `${alertCount} alerts` : 'No alerts'}
          >
            <Bell className="w-5 h-5" />
            {alertCount > 0 && (
              <span className="absolute top-1 right-1 min-w-[16px] h-4 px-0.5 bg-red-500 rounded-full ring-2 ring-white text-white text-[9px] font-bold flex items-center justify-center">
                {alertCount > 99 ? '99+' : alertCount}
              </span>
            )}
          </button>
        </div>

        {/* WebSocket Status — only shown during live capture */}
        {isCapturing && (
          <div
            className={`flex items-center space-x-1.5 text-xs font-medium ${wsConnected ? 'text-green-600' : 'text-slate-400'}`}
            title={wsConnected ? 'WebSocket connected' : 'WebSocket disconnected'}
          >
            {wsConnected ? <Wifi className="w-4 h-4" /> : <WifiOff className="w-4 h-4" />}
            <span className="hidden sm:inline">{wsConnected ? 'Live' : 'Connecting...'}</span>
          </div>
        )}
      </div>
    </header>
  );
};

export default TopBar;
