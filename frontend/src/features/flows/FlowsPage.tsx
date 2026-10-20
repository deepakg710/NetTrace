import React, { useState, useEffect } from 'react';
import { useCapture } from '../../context/CaptureContext';
import { api } from '../../lib/api';
import { FlowItem } from '../../types';
import { StatusBadge } from '../../components/StatusBadge';
import { EmptyState } from '../../components/EmptyState';
import { LoadingSpinner } from '../../components/LoadingSpinner';
import { EvidenceModal } from '../../components/EvidenceModal';
import {
  ArrowRight,
  ChevronLeft,
  ChevronRight,
  ArrowUpRight,
  ArrowDownLeft,
  ExternalLink,
  X
} from 'lucide-react';
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid
} from 'recharts';
import { useNavigate, useSearchParams } from 'react-router-dom';

export const FlowsPage: React.FC = () => {
  const { activeCapture } = useCapture();
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();

  const [flows, setFlows] = useState<FlowItem[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);
  const [protocolFilter, setProtocolFilter] = useState('');
  const [stateFilter, setStateFilter] = useState('');
  const [ipFilter, setIpFilter] = useState(() => searchParams.get('ip') || '');
  const [loading, setLoading] = useState(false);

  // Selected flow for bottom detail split
  const [selectedFlow, setSelectedFlow] = useState<FlowItem | null>(null);
  const [selectedPacketNumber, setSelectedPacketNumber] = useState<number | null>(null);

  useEffect(() => {
    const qIp = searchParams.get('ip');
    if (qIp !== null) {
      setIpFilter(qIp);
    }
  }, [searchParams]);

  const fetchFlows = async () => {
    if (!activeCapture) return;
    setLoading(true);
    try {
      const res = await api.getFlows(activeCapture.id, {
        page,
        page_size: pageSize,
        protocol: protocolFilter || undefined,
        state: stateFilter || undefined,
        ip: ipFilter || undefined,
      });
      setFlows(res.items);
      setTotal(res.total);
      if (res.items.length > 0 && (!selectedFlow || !res.items.some(f => f.id === selectedFlow.id))) {
        setSelectedFlow(res.items[0]);
      } else if (res.items.length === 0) {
        setSelectedFlow(null);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchFlows();
  }, [activeCapture, page, pageSize, protocolFilter, stateFilter, ipFilter]);

  if (!activeCapture) {
    return (
      <EmptyState
        title="No Capture Selected"
        description="Select or upload a capture to explore network flows and conversation timelines."
        actionText="Go to Captures"
        onAction={() => navigate('/captures')}
      />
    );
  }

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`;
  };

  // Use actual per-packet timeline stored during flow analysis
  const flowTimelineData: Array<{ offset: number; sent: number; recv: number; packet_number?: number; bytes?: number }> =
    selectedFlow && Array.isArray(selectedFlow.details?.timeline)
      ? selectedFlow.details.timeline
      : [];

  return (
    <div className="space-y-6 animate-in fade-in duration-200">
      {/* Title */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-800">
        <div>
          <h1 className="text-2xl font-bold text-slate-100">Flow Explorer</h1>
          <p className="text-xs text-slate-400 font-mono mt-1">
            Tracking <strong className="text-slate-200">{total.toLocaleString()}</strong> bidirectional conversations in {activeCapture.original_filename}
          </p>
        </div>
      </div>

      {/* Filter Bar */}
      <div className="p-3.5 bg-slate-900/60 border border-slate-800 rounded-xl flex flex-wrap items-center gap-3">
        <select
          value={protocolFilter}
          onChange={(e) => {
            setProtocolFilter(e.target.value);
            setPage(1);
          }}
          className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-300 font-mono focus:outline-none focus:border-cyan-500"
        >
          <option value="">All Protocols</option>
          <option value="TCP">TCP</option>
          <option value="UDP">UDP</option>
        </select>

        <select
          value={stateFilter}
          onChange={(e) => {
            setStateFilter(e.target.value);
            setPage(1);
          }}
          className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-300 font-mono focus:outline-none focus:border-cyan-500"
        >
          <option value="">All TCP States</option>
          <option value="ESTABLISHED">ESTABLISHED</option>
          <option value="INCOMPLETE_HANDSHAKE">INCOMPLETE_HANDSHAKE</option>
          <option value="RESET">RESET</option>
          <option value="CLOSED_CLEAN">CLOSED_CLEAN</option>
          <option value="ONGOING_OR_MIDSTREAM">ONGOING_OR_MIDSTREAM</option>
        </select>

        {ipFilter && (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-cyan-950/70 border border-cyan-700/70 text-cyan-300 text-xs font-mono">
            <span>IP: {ipFilter}</span>
            <button
              type="button"
              aria-label="Remove IP filter"
              onClick={() => {
                setIpFilter('');
                setSearchParams({});
                setPage(1);
              }}
              className="hover:text-white transition-colors"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          </span>
        )}

        {(protocolFilter || stateFilter || ipFilter) && (
          <button
            onClick={() => {
              setProtocolFilter('');
              setStateFilter('');
              setIpFilter('');
              setSearchParams({});
              setPage(1);
            }}
            className="text-xs text-slate-400 hover:text-slate-200 underline font-mono ml-auto"
          >
            Clear Filters
          </button>
        )}
      </div>

      {/* Flow Table */}
      <div className="p-4 bg-slate-900/60 border border-slate-800 rounded-xl space-y-3">
        {loading ? (
          <LoadingSpinner message="Aggregating flow telemetry..." />
        ) : flows.length === 0 ? (
          <div className="py-12 text-center text-xs text-slate-500 font-mono">
            No active conversation flows match current filters.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 font-mono text-[11px] select-none">
                  <th className="pb-2.5 px-2.5 w-16">Proto</th>
                  <th className="pb-2.5 px-2.5">Conversation (Initiator &rarr; Responder)</th>
                  <th className="pb-2.5 px-2.5 w-32">State</th>
                  <th className="pb-2.5 px-2.5 text-right w-20">Packets</th>
                  <th className="pb-2.5 px-2.5 text-right w-24">Bytes</th>
                  <th className="pb-2.5 px-2.5 text-right w-20">Duration</th>
                  <th className="pb-2.5 px-2.5 text-right w-24">Handshake RTT</th>
                  <th className="pb-2.5 px-2.5 text-right w-24">Evidence</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono text-[11px]">
                {flows.map((fl) => {
                  const isSelected = selectedFlow?.id === fl.id;
                  return (
                    <tr
                      key={fl.id}
                      onClick={() => setSelectedFlow(fl)}
                      className={`cursor-pointer transition-colors ${
                        isSelected
                          ? 'bg-cyan-950/40 border-l-2 border-l-cyan-400 text-slate-100'
                          : 'hover:bg-slate-800/40 text-slate-300'
                      }`}
                    >
                      <td className="py-2.5 px-2.5">
                        <span className="px-1.5 py-0.5 rounded bg-slate-800 text-cyan-300 text-[10px]">
                          {fl.protocol}
                        </span>
                      </td>
                      <td className="py-2.5 px-2.5">
                        <div className="flex items-center gap-1.5">
                          <span className="text-slate-200 font-semibold">{fl.src_ip}:{fl.src_port ?? '-'}</span>
                          <ArrowRight className="w-3 h-3 text-slate-500" />
                          <span className="text-slate-200 font-semibold">{fl.dst_ip}:{fl.dst_port ?? '-'}</span>
                        </div>
                        <div className="text-[10px] text-slate-500 mt-0.5">
                          &uarr; {fl.src_to_dst_packets} pkts ({formatBytes(fl.src_to_dst_bytes)}) • &darr; {fl.dst_to_src_packets} pkts ({formatBytes(fl.dst_to_src_bytes)})
                        </div>
                      </td>
                      <td className="py-2.5 px-2.5">
                        <StatusBadge status={fl.state} type="state" />
                      </td>
                      <td className="py-2.5 px-2.5 text-right text-slate-200">{fl.packet_count.toLocaleString()}</td>
                      <td className="py-2.5 px-2.5 text-right text-slate-300 font-semibold">{formatBytes(fl.byte_count)}</td>
                      <td className="py-2.5 px-2.5 text-right text-slate-400">{fl.duration.toFixed(2)}s</td>
                      <td className="py-2.5 px-2.5 text-right text-cyan-400">
                        {fl.handshake_latency_ms !== null ? `${fl.handshake_latency_ms}ms` : '-'}
                      </td>
                      <td className="py-2.5 px-2.5 text-right">
                        {fl.details?.syn_packet ? (
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              setSelectedPacketNumber(fl.details.syn_packet);
                            }}
                            className="px-2 py-0.5 bg-cyan-950 hover:bg-cyan-900 text-cyan-400 border border-cyan-800/80 text-[10px] rounded transition-colors"
                          >
                            SYN #{fl.details.syn_packet}
                          </button>
                        ) : (
                          <span className="text-slate-600">-</span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination */}
        <div className="flex flex-col sm:flex-row items-center justify-between gap-3 pt-3 border-t border-slate-800 text-xs font-mono text-slate-400">
          <div>Total: {total.toLocaleString()} conversations</div>
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-1.5">
              <span>Rows:</span>
              <select
                value={pageSize}
                onChange={(e) => {
                  setPageSize(parseInt(e.target.value));
                  setPage(1);
                }}
                className="bg-slate-950 border border-slate-800 rounded px-2 py-0.5 text-slate-300 focus:outline-none"
              >
                <option value="25">25</option>
                <option value="50">50</option>
                <option value="100">100</option>
              </select>
            </div>
            <div className="flex items-center gap-2">
              <button
                disabled={page <= 1}
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                className="p-1.5 bg-slate-950 border border-slate-800 rounded hover:bg-slate-800 disabled:opacity-40"
              >
                <ChevronLeft className="w-3.5 h-3.5" />
              </button>
              <span>Page {page}</span>
              <button
                disabled={flows.length < pageSize}
                onClick={() => setPage((p) => p + 1)}
                className="p-1.5 bg-slate-950 border border-slate-800 rounded hover:bg-slate-800 disabled:opacity-40"
              >
                <ChevronRight className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Bottom Split: Flow Timeline on Left, Flow Details Panel on Right */}
      {selectedFlow && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
          {/* Flow Timeline Chart */}
          <div className="lg:col-span-7 p-4 bg-slate-900/60 border border-slate-800 rounded-xl flex flex-col justify-between">
            <div className="flex items-center justify-between mb-3">
              <div>
                <h3 className="text-sm font-semibold text-slate-200">Packet-Based Conversation Timeline</h3>
                <p className="text-[11px] text-slate-400 font-mono">
                  {selectedFlow.src_ip}:{selectedFlow.src_port} &harr; {selectedFlow.dst_ip}:{selectedFlow.dst_port} (observed packet sequence, not payload TCP stream reassembly)
                </p>
              </div>
              <div className="flex items-center gap-2 text-[10px] font-mono">
                <span className="flex items-center gap-1 text-cyan-400">
                  <span className="w-2 h-2 rounded-full bg-cyan-400" /> Outbound
                </span>
                <span className="flex items-center gap-1 text-blue-400">
                  <span className="w-2 h-2 rounded-full bg-blue-500" /> Inbound
                </span>
              </div>
            </div>

            <div className="h-48 w-full my-1">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={flowTimelineData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                  <defs>
                    <linearGradient id="flowSent" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.4} />
                      <stop offset="95%" stopColor="#06b6d4" stopOpacity={0.0} />
                    </linearGradient>
                    <linearGradient id="flowRecv" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3} />
                      <stop offset="95%" stopColor="#3b82f6" stopOpacity={0.0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                  <XAxis dataKey="offset" stroke="#64748b" fontSize={10} unit="s" />
                  <YAxis stroke="#64748b" fontSize={10} />
                  <Tooltip contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px', fontSize: '12px' }} />
                  <Area type="monotone" dataKey="sent" name="Outbound Pkts" stroke="#06b6d4" fillOpacity={1} fill="url(#flowSent)" />
                  <Area type="monotone" dataKey="recv" name="Inbound Pkts" stroke="#3b82f6" fillOpacity={1} fill="url(#flowRecv)" />
                </AreaChart>
              </ResponsiveContainer>
            </div>

            <div className="flex items-center justify-between text-xs text-slate-400 font-mono pt-2 border-t border-slate-800">
              <span>Duration: {selectedFlow.duration.toFixed(3)}s</span>
              <span>Total Volume: {formatBytes(selectedFlow.byte_count)}</span>
            </div>
          </div>

          {/* Flow Details Panel */}
          <div className="lg:col-span-5 p-4 bg-slate-900/60 border border-slate-800 rounded-xl space-y-3.5">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-sm font-semibold text-slate-200">Conversation Details</h3>
                <span className="text-[10px] font-mono text-slate-400">Flow ID: {selectedFlow.flow_id}</span>
              </div>
              <StatusBadge status={selectedFlow.state} type="state" />
            </div>

            {/* Cross-Navigation Actions */}
            <div className="flex flex-wrap gap-2">
              <button
                onClick={() => {
                  const parts = [
                    `ip.addr == ${selectedFlow.src_ip}`,
                    `ip.addr == ${selectedFlow.dst_ip}`,
                  ];
                  if (selectedFlow.protocol === 'TCP' && selectedFlow.dst_port !== null) {
                    parts.push(`tcp.port == ${selectedFlow.dst_port}`);
                  } else if (selectedFlow.protocol === 'UDP' && selectedFlow.dst_port !== null) {
                    parts.push(`udp.port == ${selectedFlow.dst_port}`);
                  }
                  const expr = parts.join(' && ');
                  navigate(`/packets?display_filter=${encodeURIComponent(expr)}`);
                }}
                className="flex-1 px-2.5 py-1.5 bg-cyan-600/20 hover:bg-cyan-600/30 border border-cyan-500/40 rounded-lg text-[11px] font-mono text-cyan-300 flex items-center justify-center gap-1.5 transition-colors"
              >
                <span>Filter Flow in Packet Explorer</span>
                <ExternalLink className="w-3 h-3" />
              </button>
              <button
                onClick={() => navigate(`/topology?ip=${encodeURIComponent(selectedFlow.src_ip)}`)}
                className="px-2.5 py-1.5 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-lg text-[11px] font-mono text-slate-200 flex items-center justify-center gap-1.5 transition-colors"
              >
                <span>View in Topology</span>
                <ExternalLink className="w-3 h-3" />
              </button>
            </div>

            {/* Metrics Grid */}
            <div className="grid grid-cols-2 gap-2 text-xs font-mono">
              <div className="p-2.5 bg-slate-950/60 rounded-lg border border-slate-800">
                <span className="text-slate-500 block text-[10px] uppercase">Handshake Latency</span>
                <span className="text-cyan-400 font-semibold">
                  {selectedFlow.handshake_latency_ms !== null ? `${selectedFlow.handshake_latency_ms} ms` : 'Incomplete / N/A'}
                </span>
              </div>
              <div className="p-2.5 bg-slate-950/60 rounded-lg border border-slate-800">
                <span className="text-slate-500 block text-[10px] uppercase">Retransmissions</span>
                <span className="text-amber-400 font-semibold">{selectedFlow.retransmissions_count} packets</span>
              </div>
            </div>

            {/* Directional Breakdown */}
            <div className="p-3 bg-slate-950/60 rounded-lg border border-slate-800 space-y-2 text-xs font-mono">
              <div className="text-[10px] uppercase tracking-wider text-slate-500">Directional Traffic Breakdown</div>
              <div className="flex items-center justify-between text-slate-300">
                <span className="flex items-center gap-1 text-cyan-400">
                  <ArrowUpRight className="w-3.5 h-3.5" /> Client &rarr; Server
                </span>
                <span>{selectedFlow.src_to_dst_packets} pkts • {formatBytes(selectedFlow.src_to_dst_bytes)}</span>
              </div>
              <div className="flex items-center justify-between text-slate-300">
                <span className="flex items-center gap-1 text-blue-400">
                  <ArrowDownLeft className="w-3.5 h-3.5" /> Server &rarr; Client
                </span>
                <span>{selectedFlow.dst_to_src_packets} pkts • {formatBytes(selectedFlow.dst_to_src_bytes)}</span>
              </div>
            </div>

            {/* Evidence Links */}
            <div className="p-3 bg-slate-950/60 rounded-lg border border-slate-800 space-y-1.5 text-xs font-mono">
              <div className="text-[10px] uppercase tracking-wider text-slate-500">Supporting Frame Evidence</div>
              <div className="flex flex-wrap gap-1.5 pt-1">
                {selectedFlow.details?.syn_packet && (
                  <button
                    onClick={() => setSelectedPacketNumber(selectedFlow.details.syn_packet)}
                    className="px-2 py-0.5 bg-cyan-950 hover:bg-cyan-900 text-cyan-300 border border-cyan-800 rounded flex items-center gap-1 transition-colors"
                  >
                    <span>SYN Frame #{selectedFlow.details.syn_packet}</span>
                    <ExternalLink className="w-2.5 h-2.5" />
                  </button>
                )}
                {selectedFlow.details?.syn_ack_packet && (
                  <button
                    onClick={() => setSelectedPacketNumber(selectedFlow.details.syn_ack_packet)}
                    className="px-2 py-0.5 bg-cyan-950 hover:bg-cyan-900 text-cyan-300 border border-cyan-800 rounded flex items-center gap-1 transition-colors"
                  >
                    <span>SYN-ACK #{selectedFlow.details.syn_ack_packet}</span>
                    <ExternalLink className="w-2.5 h-2.5" />
                  </button>
                )}
                {selectedFlow.details?.rst_packet && (
                  <button
                    onClick={() => setSelectedPacketNumber(selectedFlow.details.rst_packet)}
                    className="px-2 py-0.5 bg-rose-950 hover:bg-rose-900 text-rose-300 border border-rose-800 rounded flex items-center gap-1 transition-colors"
                  >
                    <span>RST Frame #{selectedFlow.details.rst_packet}</span>
                    <ExternalLink className="w-2.5 h-2.5" />
                  </button>
                )}
                {!selectedFlow.details?.syn_packet && !selectedFlow.details?.rst_packet && (
                  <span className="text-slate-500 italic text-[11px]">Mid-stream flow or captured without initial handshake frames.</span>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Packet Evidence Modal */}
      {selectedPacketNumber && (
        <EvidenceModal
          captureId={activeCapture.id}
          packetNumber={selectedPacketNumber}
          onClose={() => setSelectedPacketNumber(null)}
        />
      )}
    </div>
  );
};
