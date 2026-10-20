import React, { useState, useEffect } from 'react';
import { useCapture } from '../../context/CaptureContext';
import { api } from '../../lib/api';
import { DNSItem } from '../../types';
import { EmptyState } from '../../components/EmptyState';
import { LoadingSpinner } from '../../components/LoadingSpinner';
import { EvidenceModal } from '../../components/EvidenceModal';
import {
  Search,
  ChevronLeft,
  ChevronRight,
  Activity,
  CheckCircle2,
  AlertCircle,
  HelpCircle,
  XCircle,
  Filter,
  RotateCcw
} from 'lucide-react';
import {
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Tooltip
} from 'recharts';
import { useNavigate } from 'react-router-dom';

const RCODE_COLORS: Record<string, string> = {
  NOERROR: '#10b981',
  NXDOMAIN: '#f59e0b',
  SERVFAIL: '#f43f5e',
  UNANSWERED: '#64748b',
  REFUSED: '#ec4899',
  FORMERR: '#8b5cf6',
};

export const DNSPage: React.FC = () => {
  const { activeCapture } = useCapture();
  const navigate = useNavigate();

  const [records, setRecords] = useState<DNSItem[]>([]);
  const [total, setTotal] = useState(0);
  const [totalAns, setTotalAns] = useState(0);
  const [totalUnans, setTotalUnans] = useState(0);
  const [rcodes, setRcodes] = useState<Record<string, number>>({});
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);
  const [rcodeFilter, setRcodeFilter] = useState('');
  const [search, setSearch] = useState('');
  const [loading, setLoading] = useState(false);
  const [selectedPacketNumber, setSelectedPacketNumber] = useState<number | null>(null);

  const fetchDNS = async () => {
    if (!activeCapture) return;
    setLoading(true);
    try {
      const res = await api.getDNS(activeCapture.id, {
        page,
        page_size: pageSize,
        rcode: rcodeFilter || undefined,
        query_name: search || undefined,
      });
      setRecords(res.items);
      setTotal(res.total);
      setTotalAns(res.total_answered);
      setTotalUnans(res.total_unanswered);
      setRcodes(res.rcode_counts);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDNS();
  }, [activeCapture, page, pageSize, rcodeFilter]);

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    setPage(1);
    fetchDNS();
  };

  const handleReset = () => {
    setRcodeFilter('');
    setSearch('');
    setPage(1);
  };

  if (!activeCapture) {
    return (
      <EmptyState
        title="No Capture Selected"
        description="Select or upload a capture to inspect DNS transaction resolution and error codes."
        actionText="Go to Captures"
        onAction={() => navigate('/captures')}
      />
    );
  }

  // Calculate stats
  const nxdomainCount = rcodes['NXDOMAIN'] || 0;
  const servfailCount = rcodes['SERVFAIL'] || 0;
  const successRate = total > 0 ? (((rcodes['NOERROR'] || 0) / total) * 100).toFixed(1) : '0';

  // Format chart data for RCODE Donut
  const rcodeChartData = Object.entries(rcodes)
    .filter(([_, count]) => count > 0)
    .map(([rcode, count]) => ({
      name: rcode,
      value: count,
      color: RCODE_COLORS[rcode] || '#94a3b8',
      percent: total > 0 ? ((count / total) * 100).toFixed(1) : '0',
    }));

  return (
    <div className="space-y-6 animate-in fade-in duration-200">
      {/* Title */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-800">
        <div>
          <h1 className="text-2xl font-bold text-slate-100">DNS Analysis</h1>
          <p className="text-xs text-slate-400 font-mono mt-1">
            Transaction correlation engine for <strong className="text-slate-200">{activeCapture.original_filename}</strong>
          </p>
        </div>
      </div>

      {/* 5 Top KPI Cards */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3.5">
        <div className="p-3.5 bg-slate-900/60 border border-slate-800 rounded-xl">
          <div className="flex items-center justify-between text-slate-500 mb-1">
            <span className="text-[10px] font-mono uppercase">Total Queries</span>
            <Activity className="w-3.5 h-3.5 text-cyan-400" />
          </div>
          <span className="font-mono text-xl font-bold text-slate-200">{total.toLocaleString()}</span>
          <span className="text-[10px] font-mono text-slate-500 block mt-0.5">Wire transactions</span>
        </div>

        <div className="p-3.5 bg-slate-900/60 border border-slate-800 rounded-xl">
          <div className="flex items-center justify-between text-slate-500 mb-1">
            <span className="text-[10px] font-mono uppercase">Answered</span>
            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
          </div>
          <span className="font-mono text-xl font-bold text-emerald-400">{totalAns.toLocaleString()}</span>
          <span className="text-[10px] font-mono text-slate-500 block mt-0.5">{successRate}% success rate</span>
        </div>

        <div className="p-3.5 bg-slate-900/60 border border-slate-800 rounded-xl">
          <div className="flex items-center justify-between text-slate-500 mb-1">
            <span className="text-[10px] font-mono uppercase">Unanswered</span>
            <HelpCircle className="w-3.5 h-3.5 text-amber-400" />
          </div>
          <span className="font-mono text-xl font-bold text-amber-400">{totalUnans.toLocaleString()}</span>
          <span className="text-[10px] font-mono text-slate-500 block mt-0.5">Missing replies</span>
        </div>

        <div className="p-3.5 bg-slate-900/60 border border-slate-800 rounded-xl">
          <div className="flex items-center justify-between text-slate-500 mb-1">
            <span className="text-[10px] font-mono uppercase">NXDOMAIN</span>
            <AlertCircle className="w-3.5 h-3.5 text-rose-400" />
          </div>
          <span className="font-mono text-xl font-bold text-rose-400">{nxdomainCount.toLocaleString()}</span>
          <span className="text-[10px] font-mono text-slate-500 block mt-0.5">Domain not found</span>
        </div>

        <div className="p-3.5 bg-slate-900/60 border border-slate-800 rounded-xl">
          <div className="flex items-center justify-between text-slate-500 mb-1">
            <span className="text-[10px] font-mono uppercase">SERVFAIL</span>
            <XCircle className="w-3.5 h-3.5 text-rose-500" />
          </div>
          <span className="font-mono text-xl font-bold text-rose-500">{servfailCount.toLocaleString()}</span>
          <span className="text-[10px] font-mono text-slate-500 block mt-0.5">Server errors</span>
        </div>
      </div>

      {/* Filters Toolbar */}
      <div className="p-3.5 bg-slate-900/60 border border-slate-800 rounded-xl flex flex-wrap items-center justify-between gap-3">
        <form onSubmit={handleSearch} className="flex items-center gap-2.5 flex-1 min-w-[240px]">
          <div className="relative flex-1">
            <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
            <input
              type="text"
              placeholder="Search domain name (e.g. example.com)..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-8 pr-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 font-mono placeholder:text-slate-600"
            />
          </div>
          <button
            type="submit"
            className="px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-semibold text-xs font-mono rounded-lg transition-colors flex items-center gap-1"
          >
            <Filter className="w-3 h-3" />
            <span>Filter</span>
          </button>
        </form>

        <div className="flex items-center gap-2">
          <select
            value={rcodeFilter}
            onChange={(e) => {
              setRcodeFilter(e.target.value);
              setPage(1);
            }}
            className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-300 font-mono focus:outline-none focus:border-cyan-500"
          >
            <option value="">All Response Codes</option>
            <option value="NOERROR">NOERROR (0)</option>
            <option value="NXDOMAIN">NXDOMAIN (3)</option>
            <option value="SERVFAIL">SERVFAIL (2)</option>
            <option value="UNANSWERED">UNANSWERED</option>
          </select>

          {(rcodeFilter || search) && (
            <button
              onClick={handleReset}
              className="text-xs text-slate-400 hover:text-slate-200 font-mono flex items-center gap-1 bg-slate-950 border border-slate-800 px-2.5 py-1.5 rounded-lg transition-colors"
            >
              <RotateCcw className="w-3 h-3" />
              <span>Reset</span>
            </button>
          )}
        </div>
      </div>

      {/* Split: Left DNS Queries Table, Right RCODE Donut */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-start">
        {/* Left: DNS Queries Table */}
        <div className="lg:col-span-8 p-4 bg-slate-900/60 border border-slate-800 rounded-xl space-y-4">
          {loading ? (
            <LoadingSpinner message="Correlating DNS transaction IDs..." />
          ) : records.length === 0 ? (
            <div className="py-12 text-center text-xs text-slate-500 font-mono">
              No DNS records matching the selected filter criteria.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400 font-mono text-[11px] select-none">
                    <th className="pb-2.5 px-2.5 w-16">Tx ID</th>
                    <th className="pb-2.5 px-2.5">Query Name</th>
                    <th className="pb-2.5 px-2.5 w-14">Type</th>
                    <th className="pb-2.5 px-2.5 w-28">Status / RCODE</th>
                    <th className="pb-2.5 px-2.5">Endpoints</th>
                    <th className="pb-2.5 px-2.5 text-right w-16">RTT</th>
                    <th className="pb-2.5 px-2.5">Resolved Answers</th>
                    <th className="pb-2.5 px-2.5 text-right w-20">Evidence</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-mono text-[11px]">
                  {records.map((d) => {
                    let rcodeColor = 'text-emerald-400 bg-emerald-950/60 border-emerald-800/60';
                    if (d.rcode === 'NXDOMAIN') rcodeColor = 'text-amber-400 bg-amber-950/60 border-amber-800/60';
                    if (d.rcode === 'SERVFAIL') rcodeColor = 'text-rose-400 bg-rose-950/60 border-rose-800/60';
                    if (d.rcode === 'UNANSWERED') rcodeColor = 'text-slate-400 bg-slate-900 border-slate-800';

                    return (
                      <tr key={d.id} className="hover:bg-slate-800/40 transition-colors">
                        <td className="py-2.5 px-2.5 text-cyan-400">{d.transaction_id}</td>
                        <td className="py-2.5 px-2.5 font-semibold text-slate-200 max-w-[180px] truncate" title={d.query_name}>
                          {d.query_name}
                        </td>
                        <td className="py-2.5 px-2.5 text-slate-300">
                          <span className="px-1 py-0.5 rounded bg-slate-800 text-slate-300 text-[10px]">
                            {d.query_type}
                          </span>
                        </td>
                        <td className="py-2.5 px-2.5">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-semibold border ${rcodeColor}`}>
                            {d.rcode}
                          </span>
                        </td>
                        <td className="py-2.5 px-2.5 text-slate-400 truncate max-w-[140px]" title={`${d.client_ip} → ${d.server_ip}`}>
                          {d.client_ip} &rarr; {d.server_ip}
                        </td>
                        <td className="py-2.5 px-2.5 text-right text-slate-300">
                          {d.latency_ms !== null ? `${d.latency_ms}ms` : '-'}
                        </td>
                        <td className="py-2.5 px-2.5 text-slate-400 max-w-[160px] truncate" title={d.answers.join(', ')}>
                          {d.answers.length > 0 ? d.answers.join(' | ') : <span className="text-slate-600">None</span>}
                        </td>
                        <td className="py-2.5 px-2.5 text-right">
                          <div className="flex items-center justify-end gap-1">
                            <button
                              onClick={() => setSelectedPacketNumber(d.query_packet_number)}
                              className="px-1.5 py-0.5 bg-cyan-950 hover:bg-cyan-900 text-cyan-300 border border-cyan-800/80 text-[10px] rounded transition-colors"
                              title="Inspect DNS query packet"
                            >
                              #{d.query_packet_number}Q
                            </button>
                            {d.response_packet_number && (
                              <button
                                onClick={() => setSelectedPacketNumber(d.response_packet_number!)}
                                className="px-1.5 py-0.5 bg-emerald-950 hover:bg-emerald-900 text-emerald-300 border border-emerald-800/80 text-[10px] rounded transition-colors"
                                title="Inspect DNS response packet"
                              >
                                #{d.response_packet_number}R
                              </button>
                            )}
                          </div>
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
            <div>Total: {total.toLocaleString()} DNS records</div>
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
                  disabled={records.length < pageSize}
                  onClick={() => setPage((p) => p + 1)}
                  className="p-1.5 bg-slate-950 border border-slate-800 rounded hover:bg-slate-800 disabled:opacity-40"
                >
                  <ChevronRight className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          </div>
        </div>

        {/* Right: DNS Response Codes Donut */}
        <div className="lg:col-span-4 p-4 bg-slate-900/60 border border-slate-800 rounded-xl flex flex-col justify-between space-y-4">
          <div>
            <h3 className="text-sm font-semibold text-slate-200">DNS Response Codes</h3>
            <p className="text-[11px] text-slate-400 font-mono">Distribution of RCODE returns</p>
          </div>

          <div className="relative flex items-center justify-center my-2">
            <div className="h-48 w-full">
              {rcodeChartData.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={rcodeChartData}
                      cx="50%"
                      cy="50%"
                      innerRadius={55}
                      outerRadius={75}
                      paddingAngle={2}
                      dataKey="value"
                    >
                      {rcodeChartData.map((entry, index) => (
                        <Cell key={`rcode-cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip
                      contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px', fontSize: '12px' }}
                    />
                  </PieChart>
                </ResponsiveContainer>
              ) : (
                <div className="flex items-center justify-center h-full text-xs text-slate-500">
                  No DNS records found
                </div>
              )}
            </div>
            {rcodeChartData.length > 0 && (
              <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
                <span className="text-xl font-bold font-mono text-emerald-400">{successRate}%</span>
                <span className="text-[10px] uppercase font-mono text-slate-400 tracking-wider">Success</span>
              </div>
            )}
          </div>

          <div className="space-y-2 pt-2 border-t border-slate-800 text-xs font-mono">
            {rcodeChartData.map((item) => (
              <div key={item.name} className="flex items-center justify-between">
                <span className="flex items-center gap-1.5 text-slate-300">
                  <span className="w-2 h-2 rounded-full" style={{ backgroundColor: item.color }} />
                  {item.name}
                </span>
                <span className="text-slate-400">{item.value} ({item.percent}%)</span>
              </div>
            ))}
          </div>

          <div className="p-3 bg-slate-950/60 rounded-lg border border-slate-800/80 text-[11px] text-slate-400 leading-relaxed font-mono">
            Unanswered queries and NXDOMAIN results reflect real network resolution status within the capture boundary.
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
