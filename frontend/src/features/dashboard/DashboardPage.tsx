import React, { useState } from 'react';
import { useCapture } from '../../context/CaptureContext';
import { MetricCard } from '../../components/MetricCard';
import { EmptyState } from '../../components/EmptyState';
import { EvidenceModal } from '../../components/EvidenceModal';
import {
  FileCode2,
  HardDrive,
  GitCompare,
  ShieldAlert,
  ArrowRight,
  Globe2,
  Activity
} from 'lucide-react';
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  PieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid
} from 'recharts';
import { useNavigate } from 'react-router-dom';

const PROTO_COLORS: Record<string, string> = {
  TCP: '#06b6d4',
  UDP: '#3b82f6',
  DNS: '#8b5cf6',
  ICMP: '#f59e0b',
  ARP: '#10b981',
  IPv6: '#ec4899',
  HTTP: '#0ea5e9',
  TLS: '#6366f1',
};

const SEV_COLORS: Record<string, string> = {
  Critical: '#ef4444',
  High: '#f43f5e',
  Medium: '#f59e0b',
  Low: '#06b6d4',
  Informational: '#3b82f6',
};

export const DashboardPage: React.FC = () => {
  const { activeCapture } = useCapture();
  const navigate = useNavigate();
  const [selectedPacketNumber, setSelectedPacketNumber] = useState<number | null>(null);

  if (!activeCapture) {
    return (
      <EmptyState
        title="No Packet Capture Loaded"
        description="Upload a .pcap or .pcapng file or select a deterministic sample to begin protocol analysis and diagnostics."
        actionText="Go to Captures & Upload"
        onAction={() => navigate('/captures')}
      />
    );
  }

  const meta = activeCapture.metadata || {};
  const totalPackets = activeCapture.packet_count || 0;
  const totalBytes = meta.total_bytes || 0;
  const protoCounts = meta.protocol_counts || {};
  const topEndpoints = meta.top_endpoints || [];
  const topFlows = meta.top_flows || [];
  const trafficTime = meta.traffic_over_time || [];
  const tcpStats = meta.tcp_stats || {
    total_tcp_flows: 0,
    established_flows: 0,
    completed_handshakes: 0,
    incomplete_handshakes: 0,
    resets_observed: 0,
    clean_closes: 0
  };
  const dnsStats = meta.dns_stats || {
    total_dns_records: 0,
    answered_queries: 0,
    unanswered_queries: 0,
    nxdomain_count: 0,
    servfail_count: 0
  };
  const findingsBySev = meta.findings_by_severity || {};
  const recentFindings = meta.recent_findings || [];
  const totalFindings = Object.values(findingsBySev).reduce((a, b) => a + b, 0);
  const dnsFailures = dnsStats.nxdomain_count + dnsStats.servfail_count + dnsStats.unanswered_queries;

  // Format data for Protocol Donut
  const protoChartData = Object.entries(protoCounts).map(([name, count], index) => {
    const fallbackPalette = ['#06b6d4', '#3b82f6', '#8b5cf6', '#10b981', '#f59e0b', '#ec4899', '#14b8a6'];
    return {
      name,
      value: count,
      color: PROTO_COLORS[name.toUpperCase()] || fallbackPalette[index % fallbackPalette.length],
      percent: totalPackets > 0 ? ((count / totalPackets) * 100).toFixed(1) : '0'
    };
  });

  // Format data for Severity Donut
  const sevChartData = ['Critical', 'High', 'Medium', 'Low', 'Informational']
    .filter(sev => (findingsBySev[sev] || 0) > 0)
    .map(sev => ({
      name: sev,
      value: findingsBySev[sev],
      color: SEV_COLORS[sev] || '#94a3b8',
      percent: totalFindings > 0 ? (((findingsBySev[sev] || 0) / totalFindings) * 100).toFixed(1) : '0'
    }));

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`;
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-200">
      {/* Page Title & Status Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-800/80">
        <div>
          <div className="flex items-center gap-2 mb-1.5">
            <span className="text-[11px] font-mono uppercase tracking-wider text-cyan-400 bg-cyan-950/70 border border-cyan-800/70 px-2 py-0.5 rounded font-medium">
              Active Session
            </span>
            <span className="text-[11px] font-mono text-slate-400 bg-slate-900 border border-slate-800 px-2 py-0.5 rounded uppercase">
              {activeCapture.format}
            </span>
            <span className="text-[11px] font-mono text-emerald-400 bg-emerald-950/60 border border-emerald-800/60 px-2 py-0.5 rounded">
              Status: {activeCapture.status}
            </span>
          </div>
          <h1 className="text-2xl font-bold text-slate-100 tracking-tight truncate" title={activeCapture.original_filename}>
            {activeCapture.original_filename}
          </h1>
          <p className="text-xs font-mono text-slate-400 mt-1 flex items-center gap-3">
            <span>Duration: <strong className="text-slate-200">{activeCapture.duration_seconds.toFixed(2)}s</strong></span>
            <span>•</span>
            <span>Capture Size: <strong className="text-slate-200">{formatBytes(activeCapture.file_size_bytes)}</strong></span>
            <span>•</span>
            <span>Analyzed: <strong className="text-slate-300">{new Date(activeCapture.upload_time).toLocaleString()}</strong></span>
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <button
            onClick={() => navigate('/reports')}
            className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded-lg text-xs font-mono transition-colors flex items-center gap-1.5"
          >
            <span>Export Reports</span>
          </button>
          <button
            onClick={() => navigate('/packets')}
            className="px-3.5 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-semibold rounded-lg text-xs font-mono transition-all flex items-center gap-1.5 shadow-sm shadow-cyan-950"
          >
            <span>Packet Explorer</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Top 6 KPI Metric Cards */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3.5">
        <MetricCard
          title="Total Packets"
          value={totalPackets.toLocaleString()}
          subtext="Captured wire frames"
          icon={FileCode2}
          color="cyan"
          onClick={() => navigate('/packets')}
        />
        <MetricCard
          title="Total Volume"
          value={formatBytes(totalBytes)}
          subtext="Wire byte payload"
          icon={HardDrive}
          color="emerald"
        />
        <MetricCard
          title="Endpoints"
          value={(meta.total_endpoints ?? topEndpoints.length).toString()}
          subtext="Distinct IP addresses"
          icon={Globe2}
          color="blue"
          onClick={() => navigate('/endpoints')}
        />
        <MetricCard
          title="Conversations"
          value={tcpStats.total_tcp_flows.toString()}
          subtext={`${tcpStats.completed_handshakes || 0} completed`}
          icon={GitCompare}
          color="indigo"
          onClick={() => navigate('/flows')}
        />
        <MetricCard
          title="DNS Failures"
          value={dnsFailures.toString()}
          subtext={dnsFailures === 0 ? "All queries answered" : `${dnsStats.unanswered_queries} unanswered`}
          icon={Activity}
          color={dnsFailures > 0 ? "rose" : "cyan"}
          onClick={() => navigate('/dns')}
        />
        <MetricCard
          title="Findings"
          value={totalFindings.toString()}
          subtext={totalFindings === 0 ? "Clean baseline" : `${findingsBySev['High'] || 0} High • ${findingsBySev['Medium'] || 0} Med`}
          icon={ShieldAlert}
          color={totalFindings > 0 ? (findingsBySev['Critical'] || findingsBySev['High'] ? "rose" : "amber") : "emerald"}
          onClick={() => navigate('/findings')}
        />
      </div>

      {/* Middle 3 Chart Cards */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {/* 1. Protocol Breakdown Donut */}
        <div className="p-4 bg-slate-900/60 border border-slate-800 rounded-xl flex flex-col justify-between">
          <div className="flex items-center justify-between mb-2">
            <div>
              <h3 className="text-sm font-semibold text-slate-200">Protocol Breakdown</h3>
              <p className="text-[11px] text-slate-400 font-mono">Distribution across layers</p>
            </div>
            <span className="text-[10px] font-mono text-cyan-400 bg-cyan-950/60 border border-cyan-800/50 px-2 py-0.5 rounded">
              {protoChartData.length} Protocols
            </span>
          </div>

          <div className="relative flex items-center justify-center my-2">
            <div className="h-44 w-full">
              {protoChartData.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={protoChartData}
                      cx="50%"
                      cy="50%"
                      innerRadius={50}
                      outerRadius={70}
                      paddingAngle={2}
                      dataKey="value"
                    >
                      {protoChartData.map((entry, index) => (
                        <Cell key={`proto-cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip
                      contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px', fontSize: '12px' }}
                      itemStyle={{ color: '#06b6d4' }}
                    />
                  </PieChart>
                </ResponsiveContainer>
              ) : (
                <div className="flex items-center justify-center h-full text-xs text-slate-500">
                  No protocol frames
                </div>
              )}
            </div>
            {protoChartData.length > 0 && (
              <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
                <span className="text-lg font-bold font-mono text-slate-100">{totalPackets.toLocaleString()}</span>
                <span className="text-[10px] uppercase font-mono text-slate-400 tracking-wider">Frames</span>
              </div>
            )}
          </div>

          <div className="grid grid-cols-2 gap-2 pt-2 border-t border-slate-800/80">
            {protoChartData.slice(0, 4).map((item) => (
              <div key={item.name} className="flex items-center justify-between text-xs font-mono">
                <span className="flex items-center gap-1.5 text-slate-300">
                  <span className="w-2 h-2 rounded-full" style={{ backgroundColor: item.color }} />
                  {item.name}
                </span>
                <span className="text-slate-400">{item.percent}%</span>
              </div>
            ))}
          </div>
        </div>

        {/* 2. Traffic Throughput Over Time (Dual Wave) */}
        <div className="p-4 bg-slate-900/60 border border-slate-800 rounded-xl flex flex-col justify-between">
          <div className="flex items-center justify-between mb-2">
            <div>
              <h3 className="text-sm font-semibold text-slate-200">Traffic Over Time</h3>
              <p className="text-[11px] text-slate-400 font-mono">Packet throughput timeline</p>
            </div>
            <div className="flex items-center gap-2 text-[10px] font-mono">
              <span className="flex items-center gap-1 text-cyan-400">
                <span className="w-2 h-2 rounded-full bg-cyan-400" /> Sent
              </span>
              <span className="flex items-center gap-1 text-blue-400">
                <span className="w-2 h-2 rounded-full bg-blue-500" /> Received
              </span>
            </div>
          </div>

          <div className="h-44 w-full my-2">
            {trafficTime.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={trafficTime} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                  <defs>
                    <linearGradient id="sentGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.4} />
                      <stop offset="95%" stopColor="#06b6d4" stopOpacity={0.0} />
                    </linearGradient>
                    <linearGradient id="recvGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3} />
                      <stop offset="95%" stopColor="#3b82f6" stopOpacity={0.0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                  <XAxis dataKey="time_offset" stroke="#64748b" fontSize={10} unit="s" />
                  <YAxis stroke="#64748b" fontSize={10} />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px', fontSize: '12px' }}
                  />
                  <Area type="monotone" dataKey="sent" name="Sent Packets" stroke="#06b6d4" fillOpacity={1} fill="url(#sentGrad)" />
                  <Area type="monotone" dataKey="received" name="Recv Packets" stroke="#3b82f6" fillOpacity={1} fill="url(#recvGrad)" />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex items-center justify-center h-full text-xs text-slate-500">
                Single instant capture or insufficient timestamp frames
              </div>
            )}
          </div>

          <div className="flex items-center justify-between text-xs text-slate-400 font-mono pt-2 border-t border-slate-800/80">
            <span>Peak Rate: ~{Math.max(...trafficTime.map(t => t.packets), 1)} pkt/bin</span>
            <span className="text-cyan-400">Window: {activeCapture.duration_seconds.toFixed(1)}s</span>
          </div>
        </div>

        {/* 3. Findings Severity Distribution Donut */}
        <div className="p-4 bg-slate-900/60 border border-slate-800 rounded-xl flex flex-col justify-between">
          <div className="flex items-center justify-between mb-2">
            <div>
              <h3 className="text-sm font-semibold text-slate-200">Findings by Severity</h3>
              <p className="text-[11px] text-slate-400 font-mono">Heuristic diagnostic alerts</p>
            </div>
            <button
              onClick={() => navigate('/findings')}
              className="text-[11px] text-cyan-400 hover:text-cyan-300 font-mono flex items-center gap-1"
            >
              <span>Inspect</span>
              <ArrowRight className="w-3 h-3" />
            </button>
          </div>

          <div className="relative flex items-center justify-center my-2">
            <div className="h-44 w-full">
              {totalFindings > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={sevChartData}
                      cx="50%"
                      cy="50%"
                      innerRadius={50}
                      outerRadius={70}
                      paddingAngle={2}
                      dataKey="value"
                    >
                      {sevChartData.map((entry, index) => (
                        <Cell key={`sev-cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip
                      contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px', fontSize: '12px' }}
                    />
                  </PieChart>
                </ResponsiveContainer>
              ) : (
                <div className="flex flex-col items-center justify-center h-full text-center px-4">
                  <span className="text-emerald-400 text-sm font-semibold mb-1">Clean Baseline</span>
                  <p className="text-[11px] text-slate-400">No anomalous or suspicious indicators detected.</p>
                </div>
              )}
            </div>
            {totalFindings > 0 && (
              <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
                <span className="text-lg font-bold font-mono text-slate-100">{totalFindings}</span>
                <span className="text-[10px] uppercase font-mono text-slate-400 tracking-wider">Findings</span>
              </div>
            )}
          </div>

          <div className="flex items-center justify-between pt-2 border-t border-slate-800/80 text-xs font-mono">
            <span className="text-rose-400">High: {findingsBySev['High'] || 0}</span>
            <span className="text-amber-400">Med: {findingsBySev['Medium'] || 0}</span>
            <span className="text-cyan-400">Low: {findingsBySev['Low'] || 0}</span>
            <span className="text-blue-400">Info: {findingsBySev['Informational'] || 0}</span>
          </div>
        </div>
      </div>

      {/* Bottom 3 Detailed Panels */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {/* Panel 1: Top Communicating Endpoints */}
        <div className="p-4 bg-slate-900/60 border border-slate-800 rounded-xl flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-3">
              <div>
                <h3 className="text-sm font-semibold text-slate-200">Top Endpoints</h3>
                <p className="text-[11px] text-slate-400 font-mono">By observed traffic volume</p>
              </div>
              <button
                onClick={() => navigate('/endpoints')}
                className="text-[11px] text-cyan-400 hover:text-cyan-300 font-mono flex items-center gap-1"
              >
                <span>View all</span>
                <ArrowRight className="w-3 h-3" />
              </button>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400 font-mono text-[11px]">
                    <th className="pb-2 font-normal">IP Address</th>
                    <th className="pb-2 text-right font-normal">Packets</th>
                    <th className="pb-2 text-right font-normal">Volume</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {topEndpoints.slice(0, 5).map((ep) => (
                    <tr
                      key={ep.ip}
                      onClick={() => navigate(`/endpoints`)}
                      className="hover:bg-slate-800/40 cursor-pointer transition-colors"
                    >
                      <td className="py-2.5 font-mono text-cyan-400 hover:underline">{ep.ip}</td>
                      <td className="py-2.5 text-right font-mono text-slate-300">{ep.packets.toLocaleString()}</td>
                      <td className="py-2.5 text-right font-mono text-slate-400">{formatBytes(ep.bytes)}</td>
                    </tr>
                  ))}
                  {topEndpoints.length === 0 && (
                    <tr>
                      <td colSpan={3} className="py-4 text-center text-xs text-slate-500">
                        No endpoints detected
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
          <div className="pt-2 text-[11px] font-mono text-slate-500">
            Total active hosts: {topEndpoints.length}
          </div>
        </div>

        {/* Panel 2: Top Conversations / Flows */}
        <div className="p-4 bg-slate-900/60 border border-slate-800 rounded-xl flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-3">
              <div>
                <h3 className="text-sm font-semibold text-slate-200">Top Conversations</h3>
                <p className="text-[11px] text-slate-400 font-mono">Dominant bidirectional flows</p>
              </div>
              <button
                onClick={() => navigate('/flows')}
                className="text-[11px] text-cyan-400 hover:text-cyan-300 font-mono flex items-center gap-1"
              >
                <span>View all</span>
                <ArrowRight className="w-3 h-3" />
              </button>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400 font-mono text-[11px]">
                    <th className="pb-2 font-normal">Conversation</th>
                    <th className="pb-2 text-center font-normal">Protocol</th>
                    <th className="pb-2 text-right font-normal">State</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {topFlows.slice(0, 5).map((f) => (
                    <tr
                      key={f.flow_id}
                      onClick={() => navigate('/flows')}
                      className="hover:bg-slate-800/40 cursor-pointer transition-colors"
                    >
                      <td className="py-2 font-mono text-[11px] text-slate-200">
                        <div className="truncate max-w-[140px]" title={`${f.src || ''} ↔ ${f.dst || ''}`}>
                          {f.src || f.flow_id}
                        </div>
                      </td>
                      <td className="py-2 text-center font-mono">
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 border border-slate-700 text-cyan-400">
                          {f.protocol}
                        </span>
                      </td>
                      <td className="py-2 text-right font-mono">
                        <span className={`text-[10px] px-1.5 py-0.5 rounded font-medium ${
                          f.state === 'ESTABLISHED' ? 'bg-emerald-950/60 text-emerald-400 border border-emerald-800/50' :
                          f.state === 'RESET' ? 'bg-rose-950/60 text-rose-400 border border-rose-800/50' :
                          'bg-amber-950/60 text-amber-400 border border-amber-800/50'
                        }`}>
                          {f.state}
                        </span>
                      </td>
                    </tr>
                  ))}
                  {topFlows.length === 0 && (
                    <tr>
                      <td colSpan={3} className="py-4 text-center text-xs text-slate-500">
                        No conversations recorded
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
          <div className="pt-2 text-[11px] font-mono text-slate-500">
            Active flows: {tcpStats.total_tcp_flows}
          </div>
        </div>

        {/* Panel 3: Recent Findings */}
        <div className="p-4 bg-slate-900/60 border border-slate-800 rounded-xl flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-3">
              <div>
                <h3 className="text-sm font-semibold text-slate-200">Recent Findings</h3>
                <p className="text-[11px] text-slate-400 font-mono">Evidence-backed anomalies</p>
              </div>
              <button
                onClick={() => navigate('/findings')}
                className="text-[11px] text-cyan-400 hover:text-cyan-300 font-mono flex items-center gap-1"
              >
                <span>View all</span>
                <ArrowRight className="w-3 h-3" />
              </button>
            </div>

            <div className="space-y-2">
              {recentFindings.length > 0 ? (
                recentFindings.slice(0, 4).map((f) => (
                  <div
                    key={f.id}
                    onClick={() => navigate('/findings')}
                    className="p-2 bg-slate-950/40 hover:bg-slate-800/50 border border-slate-800/80 rounded-lg cursor-pointer transition-colors"
                  >
                    <div className="flex items-center justify-between gap-1 mb-1">
                      <span className={`text-[10px] font-mono px-1.5 py-0.2 rounded font-semibold ${
                        f.severity === 'Critical' ? 'bg-rose-950 text-rose-400 border border-rose-800' :
                        f.severity === 'High' ? 'bg-rose-950/70 text-rose-400 border border-rose-800/60' :
                        f.severity === 'Medium' ? 'bg-amber-950/70 text-amber-400 border border-amber-800/60' :
                        'bg-cyan-950/70 text-cyan-400 border border-cyan-800/60'
                      }`}>
                        {f.severity}
                      </span>
                      <span className="text-[10px] font-mono text-slate-500">{f.category}</span>
                    </div>
                    <div className="text-xs font-medium text-slate-200 truncate" title={f.title}>
                      {f.title}
                    </div>
                    {f.packet_numbers && f.packet_numbers.length > 0 && (
                      <div className="mt-1 flex items-center gap-1">
                        <span className="text-[10px] font-mono text-slate-400">Evidence frames:</span>
                        {f.packet_numbers.slice(0, 3).map((pNum) => (
                          <button
                            key={pNum}
                            onClick={(e) => {
                              e.stopPropagation();
                              setSelectedPacketNumber(pNum);
                            }}
                            className="text-[10px] font-mono text-cyan-400 bg-cyan-950/60 hover:bg-cyan-900 border border-cyan-800/70 px-1 rounded transition-colors"
                          >
                            #{pNum}
                          </button>
                        ))}
                      </div>
                    )}
                  </div>
                ))
              ) : (
                <div className="py-6 text-center text-xs text-slate-500 italic bg-slate-950/30 rounded border border-slate-800/50">
                  No findings detected in this capture.
                </div>
              )}
            </div>
          </div>
          <div className="pt-2 text-[11px] font-mono text-slate-500">
            Total diagnostic alerts: {totalFindings}
          </div>
        </div>
      </div>

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
