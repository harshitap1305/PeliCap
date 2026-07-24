import React, { useState, useRef, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { Card } from '../components/ui/Card';
import { ProtocolBadge } from '../components/ui/Badge';
import { Search, Filter, Download, X, Layers } from 'lucide-react';
import { useVirtualizer } from '@tanstack/react-virtual';
import { useQuery } from '@tanstack/react-query';
import { useCaptureStore } from '../store/captureStore';
import axios from 'axios';

const api = axios.create({ baseURL: '' });

const formatTime = (ns) => {
  if (!ns) return '-';
  const d = new Date(ns / 1000000);
  return `${d.getHours().toString().padStart(2, '0')}:${d.getMinutes().toString().padStart(2, '0')}:${d.getSeconds().toString().padStart(2, '0')}.${d.getMilliseconds().toString().padStart(3, '0')}`;
};

const getProto = (pkt) => {
  if (pkt.app_protocol) return pkt.app_protocol;
  if (pkt.http) return 'HTTP';
  if (pkt.dns) return 'DNS';
  if (pkt.tls) return 'TLS';
  if (pkt.tcp) return 'TCP';
  if (pkt.udp) return 'UDP';
  if (pkt.arp) return 'ARP';
  if (pkt.icmp) return 'ICMP';
  return 'OTHER';
};

const getInfo = (pkt) => {
  if (pkt.http) {
    return pkt.http.method
      ? `${pkt.http.method} ${pkt.http.url || ''}`
      : `HTTP ${pkt.http.status || ''} ${pkt.http.message || ''}`;
  }
  if (pkt.dns) return `DNS ${pkt.dns.is_response ? 'Response' : 'Query'}: ${pkt.dns.query || ''}`;
  if (pkt.tls) return `TLS ${pkt.tls.version || ''} ${pkt.tls.sni ? `SNI: ${pkt.tls.sni}` : ''}`;
  if (pkt.tcp) return `TCP ${pkt.tcp.src_port} → ${pkt.tcp.dst_port}`;
  if (pkt.udp) return `UDP ${pkt.udp.src_port} → ${pkt.udp.dst_port}`;
  return 'Application Data';
};

// Simple client-side filter: matches against a BPF-like text filter
// Supports: ip, src/dst ip fragments, port numbers, protocol names, free text
const matchesFilter = (pkt, filter) => {
  if (!filter.trim()) return true;
  const f = filter.toLowerCase().trim();

  // Protocol shortcuts
  if (f === 'tcp') return !!(pkt.tcp);
  if (f === 'udp') return !!(pkt.udp);
  if (f === 'icmp') return !!(pkt.icmp);
  if (f === 'dns') return !!(pkt.dns);
  if (f === 'http') return !!(pkt.http);
  if (f === 'tls' || f === 'ssl') return !!(pkt.tls);
  if (f === 'arp') return !!(pkt.arp);

  // Port filter: "port 443" or "port=443"
  const portMatch = f.match(/^(?:port\s*[=:]?\s*)(\d+)$/);
  if (portMatch) {
    const port = parseInt(portMatch[1]);
    return pkt.tcp?.src_port === port || pkt.tcp?.dst_port === port
      || pkt.udp?.src_port === port || pkt.udp?.dst_port === port;
  }

  // src_port / dst_port
  const srcPortMatch = f.match(/^src\s+port\s+(\d+)$/);
  if (srcPortMatch) {
    const port = parseInt(srcPortMatch[1]);
    return pkt.tcp?.src_port === port || pkt.udp?.src_port === port;
  }
  const dstPortMatch = f.match(/^dst\s+port\s+(\d+)$/);
  if (dstPortMatch) {
    const port = parseInt(dstPortMatch[1]);
    return pkt.tcp?.dst_port === port || pkt.udp?.dst_port === port;
  }

  // IP filter: "host 1.2.3.4" or free IP text
  const hostMatch = f.match(/^(?:host\s+)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.[\d*]+)$/);
  if (hostMatch) {
    const ip = hostMatch[1];
    const src = pkt.ip?.src || pkt.ip6?.src || '';
    const dst = pkt.ip?.dst || pkt.ip6?.dst || '';
    return src.includes(ip) || dst.includes(ip);
  }

  // src / dst host
  const srcHostMatch = f.match(/^src\s+(?:host\s+)?(.+)$/);
  if (srcHostMatch) {
    const ip = srcHostMatch[1];
    const src = pkt.ip?.src || pkt.ip6?.src || '';
    return src.includes(ip);
  }
  const dstHostMatch = f.match(/^dst\s+(?:host\s+)?(.+)$/);
  if (dstHostMatch) {
    const ip = dstHostMatch[1];
    const dst = pkt.ip?.dst || pkt.ip6?.dst || '';
    return dst.includes(ip);
  }

  // Free-text fallback: search across all string representations
  const pktStr = JSON.stringify(pkt).toLowerCase();
  return pktStr.includes(f);
};

const EmptySessionState = ({ navigate }) => (
  <div className="flex flex-col items-center justify-center h-96 text-center">
    <Layers className="w-12 h-12 text-slate-300 mb-4" />
    <h2 className="text-lg font-semibold text-slate-700 mb-2">No Session Selected</h2>
    <p className="text-slate-500 text-sm">Select a capture session first to explore packets.</p>
    <button onClick={() => navigate('/sessions')} className="mt-4 px-4 py-2 bg-indigo-600 text-white rounded-md text-sm font-medium hover:bg-indigo-700">
      Go to Sessions
    </button>
  </div>
);

const PacketExplorer = () => {
  const { sessionId, isCapturing } = useCaptureStore();
  const navigate = useNavigate();
  const [selectedPacket, setSelectedPacket] = useState(null);
  const [filterInput, setFilterInput] = useState('');
  const [activeFilter, setActiveFilter] = useState('');
  const parentRef = useRef(null);

  const { data, isLoading } = useQuery({
    queryKey: ['packets', sessionId, isCapturing],
    queryFn: async () => {
      if (!sessionId) return { packets: [] };
      if (isCapturing) {
        // Live: use in-memory packet ring buffer
        const res = await api.get('/api/packets?limit=5000');
        return res.data;
      } else {
        // Historical: /api/packets is empty (in-memory only).
        // Fall back to searching stored flows from PostgreSQL.
        const res = await api.post('/api/search', {
          session_id: sessionId,
          query: '',
          limit: 2000,
          offset: 0,
        });
        // Convert flow records to a packet-like structure the rest of the
        // component can render (the filter and detail panel will still work).
        const flows = res.data?.results || [];
        const packets = flows.map(f => ({
          timestamp_ns: f.start_time ? new Date(f.start_time).getTime() * 1_000_000 : 0,
          length: (f.fwd_bytes || 0) + (f.rev_bytes || 0),
          payload_bytes: f.payload_bytes,
          ip: { src: f.src_ip, dst: f.dst_ip },
          // Synthesise protocol fields so matchesFilter works
          tcp: f.protocol === 6 ? { src_port: f.src_port, dst_port: f.dst_port } : undefined,
          udp: f.protocol === 17 ? { src_port: f.src_port, dst_port: f.dst_port } : undefined,
          dns: f.app_protocol === 'DNS' ? { query: f.dns_query, is_response: false } : undefined,
          tls: f.tls_sni ? { sni: f.tls_sni } : undefined,
          http: f.http_host ? { method: 'GET', url: f.http_host } : undefined,
          app_protocol: f.app_protocol,
          // Keep original flow data for detail panel
          _flow: f,
          _isFlow: true,
        }));
        return { packets, _isHistorical: true };
      }
    },
    refetchInterval: isCapturing ? 2000 : false,
    enabled: !!sessionId,
  });

  const allPackets = data?.packets || [];
  const isHistorical = !!data?._isHistorical;

  // Client-side filter applied only when user clicks "Apply Filter"
  const packets = useMemo(() => {
    if (!activeFilter.trim()) return allPackets;
    return allPackets.filter(pkt => matchesFilter(pkt, activeFilter));
  }, [allPackets, activeFilter]);

  const handleApplyFilter = (e) => {
    e.preventDefault();
    setActiveFilter(filterInput);
    setSelectedPacket(null);
  };

  const handleClearFilter = () => {
    setFilterInput('');
    setActiveFilter('');
  };

  if (!sessionId) return <EmptySessionState navigate={navigate} />;

  const rowVirtualizer = useVirtualizer({
    count: packets.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => 36,
    overscan: 20,
  });

  return (
    <div className="flex flex-col h-full space-y-4">
      {/* Header */}
      <div className="flex justify-between items-end shrink-0">
        <div>
          <h1 className="text-2xl font-semibold text-slate-900 tracking-tight">Packet Explorer</h1>
          <p className="text-slate-500 mt-1">
            {isCapturing
              ? 'Deep inspection of raw packets'
              : isHistorical
                ? 'Historical mode — showing stored flows (raw packets not persisted)'
                : 'Deep inspection of raw packets'}
            {activeFilter && (
              <span className="ml-2 text-indigo-600">
                · {packets.length} of {allPackets.length} records match
              </span>
            )}
          </p>
        </div>
        <button className="flex items-center space-x-2 px-3 py-1.5 text-sm font-medium text-slate-600 bg-white border border-slate-200 rounded-md hover:bg-slate-50">
          <Download className="w-4 h-4" />
          <span>Export PCAP</span>
        </button>
      </div>

      {/* Filter Bar */}
      <Card className="p-4 shrink-0 shadow-sm border-slate-200">
        <form onSubmit={handleApplyFilter} className="flex space-x-3">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
            <input
              type="text"
              placeholder='Filter: tcp · udp · dns · http · port 443 · host 1.2.3.4 · src port 80'
              className="w-full pl-9 pr-4 py-2 bg-slate-50 border border-slate-200 rounded-md text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:bg-white transition-all font-mono"
              value={filterInput}
              onChange={(e) => setFilterInput(e.target.value)}
            />
          </div>
          <button
            type="submit"
            className="flex items-center space-x-2 px-4 py-2 bg-blue-600 text-white rounded-md text-sm font-medium hover:bg-blue-700 transition-colors"
          >
            <Filter className="w-4 h-4" />
            <span>Apply</span>
          </button>
          {activeFilter && (
            <button
              type="button"
              onClick={handleClearFilter}
              className="flex items-center space-x-2 px-3 py-2 bg-white border border-slate-200 text-slate-600 rounded-md text-sm font-medium hover:bg-slate-50 transition-colors"
            >
              <X className="w-4 h-4" />
              <span>Clear</span>
            </button>
          )}
        </form>
        {activeFilter && (
          <p className="text-xs text-indigo-600 mt-2 font-mono">
            Active filter: <strong>{activeFilter}</strong>
          </p>
        )}
      </Card>

      {/* Split Pane Layout */}
      <div className="flex-1 flex min-h-0 space-x-4">
        {/* Virtualized Packet List */}
        <Card noPadding className={`flex flex-col flex-1 min-w-0 transition-all ${selectedPacket ? 'w-2/3' : 'w-full'}`}>
          {/* Table Header */}
          <div className="bg-slate-50 border-b border-slate-200 flex text-xs font-semibold text-slate-500 uppercase tracking-wider pr-4 shrink-0">
            <div className="px-4 py-2 w-16 shrink-0 border-r border-slate-200">No.</div>
            <div className="px-4 py-2 w-44 shrink-0 border-r border-slate-200">Time</div>
            <div className="px-4 py-2 w-36 shrink-0 border-r border-slate-200">Source</div>
            <div className="px-4 py-2 w-36 shrink-0 border-r border-slate-200">Destination</div>
            <div className="px-4 py-2 w-24 shrink-0 border-r border-slate-200">Protocol</div>
            <div className="px-4 py-2 w-20 shrink-0 border-r border-slate-200 text-right">Length</div>
            <div className="px-4 py-2 flex-1">Info</div>
          </div>

          {isLoading ? (
            <div className="flex-1 flex items-center justify-center text-slate-400 text-sm">
              <div className="w-6 h-6 border-2 border-slate-200 border-t-indigo-500 rounded-full animate-spin mr-3" />
              Loading packets...
            </div>
          ) : packets.length === 0 ? (
            <div className="flex-1 flex items-center justify-center text-slate-400 text-sm flex-col space-y-2">
              <p>{activeFilter ? `No packets match "${activeFilter}"` : 'No packets captured yet.'}</p>
              {activeFilter && (
                <button onClick={handleClearFilter} className="text-indigo-600 text-xs hover:underline">
                  Clear filter
                </button>
              )}
            </div>
          ) : (
            /* Virtualized Body */
            <div ref={parentRef} className="flex-1 overflow-auto bg-white">
              <div style={{ height: `${rowVirtualizer.getTotalSize()}px`, width: '100%', position: 'relative' }}>
                {rowVirtualizer.getVirtualItems().map((virtualRow) => {
                  const packet = packets[virtualRow.index];
                  const isSelected = selectedPacket?.id === packet.id;
                  const proto = getProto(packet);
                  return (
                    <div
                      key={virtualRow.index}
                      onClick={() => setSelectedPacket(packet)}
                      className={`absolute top-0 left-0 w-full flex text-sm border-b border-slate-100 cursor-pointer hover:bg-blue-50/50 transition-colors ${isSelected ? 'bg-blue-50 text-blue-900 font-medium' : 'text-slate-600'}`}
                      style={{ height: `${virtualRow.size}px`, transform: `translateY(${virtualRow.start}px)` }}
                    >
                      <div className="px-4 py-1.5 w-16 shrink-0 border-r border-slate-100 font-mono text-xs text-slate-400">{packet.id}</div>
                      <div className="px-4 py-1.5 w-44 shrink-0 border-r border-slate-100 font-mono text-xs">{formatTime(packet.timestamp_ns)}</div>
                      <div className="px-4 py-1.5 w-36 shrink-0 border-r border-slate-100 truncate text-xs font-mono">{packet.ip?.src || packet.ip6?.src || packet.eth?.src || 'N/A'}</div>
                      <div className="px-4 py-1.5 w-36 shrink-0 border-r border-slate-100 truncate text-xs font-mono">{packet.ip?.dst || packet.ip6?.dst || packet.eth?.dst || 'N/A'}</div>
                      <div className="px-4 py-1 w-24 shrink-0 border-r border-slate-100">
                        <ProtocolBadge protocol={proto} />
                      </div>
                      <div className="px-4 py-1.5 w-20 shrink-0 border-r border-slate-100 text-right font-mono text-xs">{packet.captured_len}</div>
                      <div className="px-4 py-1.5 flex-1 truncate font-mono text-xs text-slate-500">{getInfo(packet)}</div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* Footer */}
          <div className="px-4 py-2 border-t border-slate-200 bg-slate-50 text-xs text-slate-400 shrink-0">
            {isLoading ? 'Loading...' : `${packets.length} packets${activeFilter ? ` (filtered from ${allPackets.length})` : ''}`}
            {isCapturing && <span className="ml-2 text-green-500">● Live</span>}
          </div>
        </Card>

        {/* Packet Detail Pane */}
        {selectedPacket && (
          <Card noPadding className="w-1/3 flex flex-col shrink-0">
            <div className="flex justify-between items-center p-3 border-b border-slate-200 bg-slate-50 shrink-0">
              <h3 className="font-semibold text-slate-900 text-sm">Packet #{selectedPacket.id}</h3>
              <button onClick={() => setSelectedPacket(null)} className="p-1 hover:bg-slate-200 rounded text-slate-500 transition-colors">
                <X className="w-4 h-4" />
              </button>
            </div>
            <div className="flex-1 overflow-auto p-4">
              <div className="space-y-3 text-sm">
                {/* Frame */}
                <DetailSection title={`Frame: ${selectedPacket.captured_len} bytes`}>
                  <Field label="Arrival Time" value={formatTime(selectedPacket.timestamp_ns)} />
                  <Field label="Frame Length" value={`${selectedPacket.original_len} bytes`} />
                  <Field label="Capture Length" value={`${selectedPacket.captured_len} bytes`} />
                  <Field label="Interface" value={selectedPacket.interface_name || selectedPacket.interface} />
                </DetailSection>

                {selectedPacket.eth && (
                  <DetailSection title={`Ethernet II, ${selectedPacket.eth.src} → ${selectedPacket.eth.dst}`}>
                    <Field label="Src" value={selectedPacket.eth.src} mono />
                    <Field label="Dst" value={selectedPacket.eth.dst} mono />
                    <Field label="EtherType" value={`0x${(selectedPacket.eth.ethertype || 0).toString(16).padStart(4, '0')}`} mono />
                  </DetailSection>
                )}

                {selectedPacket.ip && (
                  <DetailSection title={`IPv4, ${selectedPacket.ip.src} → ${selectedPacket.ip.dst}`}>
                    <Field label="Source" value={selectedPacket.ip.src} mono />
                    <Field label="Destination" value={selectedPacket.ip.dst} mono />
                    <Field label="TTL" value={selectedPacket.ip.ttl} />
                    <Field label="Protocol" value={selectedPacket.ip.protocol} />
                  </DetailSection>
                )}

                {selectedPacket.ip6 && (
                  <DetailSection title={`IPv6, ${selectedPacket.ip6.src} → ${selectedPacket.ip6.dst}`}>
                    <Field label="Source" value={selectedPacket.ip6.src} mono />
                    <Field label="Destination" value={selectedPacket.ip6.dst} mono />
                  </DetailSection>
                )}

                {selectedPacket.tcp && (
                  <DetailSection title={`TCP ${selectedPacket.tcp.src_port} → ${selectedPacket.tcp.dst_port}`}>
                    <Field label="Src Port" value={selectedPacket.tcp.src_port} />
                    <Field label="Dst Port" value={selectedPacket.tcp.dst_port} />
                    <Field label="Seq" value={selectedPacket.tcp.seq} mono />
                    <Field label="Ack" value={selectedPacket.tcp.ack} mono />
                    <Field label="Flags" value={selectedPacket.tcp.flags} mono />
                    <Field label="Window" value={selectedPacket.tcp.window_size} />
                  </DetailSection>
                )}

                {selectedPacket.udp && (
                  <DetailSection title={`UDP ${selectedPacket.udp.src_port} → ${selectedPacket.udp.dst_port}`}>
                    <Field label="Src Port" value={selectedPacket.udp.src_port} />
                    <Field label="Dst Port" value={selectedPacket.udp.dst_port} />
                    <Field label="Length" value={selectedPacket.udp.length} />
                  </DetailSection>
                )}

                {selectedPacket.dns && (
                  <DetailSection title={`DNS ${selectedPacket.dns.is_response ? 'Response' : 'Query'}`}>
                    <Field label="Query" value={selectedPacket.dns.query} mono />
                    <Field label="Transaction ID" value={selectedPacket.dns.transaction_id} mono />
                    <Field label="Is Response" value={selectedPacket.dns.is_response ? 'Yes' : 'No'} />
                  </DetailSection>
                )}

                {selectedPacket.http && (
                  <DetailSection title={`HTTP ${selectedPacket.http.method || `${selectedPacket.http.status}`}`}>
                    <Field label="Method" value={selectedPacket.http.method} />
                    <Field label="URL" value={selectedPacket.http.url} mono />
                    <Field label="Status" value={selectedPacket.http.status} />
                    <Field label="Host" value={selectedPacket.http.host} mono />
                  </DetailSection>
                )}

                {selectedPacket.tls && (
                  <DetailSection title={`TLS ${selectedPacket.tls.version || ''}`}>
                    <Field label="SNI" value={selectedPacket.tls.sni} mono />
                    <Field label="Version" value={selectedPacket.tls.version} />
                    <Field label="Record Type" value={selectedPacket.tls.record_type} />
                  </DetailSection>
                )}
              </div>
            </div>
          </Card>
        )}
      </div>
    </div>
  );
};

// ── Helper components for detail pane ─────────────────────────────────────────
const DetailSection = ({ title, children }) => (
  <div>
    <div className="font-medium text-slate-700 bg-slate-100 px-2 py-1.5 rounded text-xs flex items-center">
      <span className="w-3 inline-block text-center mr-1 text-slate-400">▼</span>
      {title}
    </div>
    <div className="pl-5 mt-1.5 space-y-1">{children}</div>
  </div>
);

const Field = ({ label, value, mono = false }) => {
  if (value == null || value === '') return null;
  return (
    <div className="flex text-xs">
      <span className="text-slate-400 w-28 shrink-0">{label}:</span>
      <span className={`text-slate-700 ${mono ? 'font-mono' : ''} break-all`}>{String(value)}</span>
    </div>
  );
};

export default PacketExplorer;
