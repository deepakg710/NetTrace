import React, { useState, useEffect } from 'react';
import { useCapture } from '../../context/CaptureContext';
import { api } from '../../lib/api';
import { EndpointItem } from '../../types';
import { EmptyState } from '../../components/EmptyState';
import { LoadingSpinner } from '../../components/LoadingSpinner';
import { Network, ArrowUpRight, ArrowDownLeft, Search } from 'lucide-react';
import { useNavigate } from 'react-router-dom';

export const EndpointsPage: React.FC = () => {
  const { activeCapture } = useCapture();
  const navigate = useNavigate();

  const [endpoints, setEndpoints] = useState<EndpointItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [search, setSearch] = useState('');

  useEffect(() => {
    if (!activeCapture) return;
    setLoading(true);
    api.getEndpoints(activeCapture.id)
      .then(setEndpoints)
      .catch(console.error)
      .finally(() => setLoading(false));
  }, [activeCapture]);

  if (!activeCapture) {
    return (
      <EmptyState
        title="No Capture Selected"
        description="Select or upload a capture to explore communicating host endpoints."
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

  const filtered = endpoints.filter((ep) =>
    ep.ip_address.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="space-y-6 animate-in fade-in duration-200">
      {/* Title */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-slate-100">Endpoints</h1>
          <p className="text-xs text-slate-400 font-mono mt-1">
            {endpoints.length} observed IP hosts communicating in {activeCapture.original_filename}
          </p>
        </div>
      </div>

      {/* Search Bar */}
      <div className="p-4 bg-slate-900/60 border border-slate-800 rounded-xl">
        <div className="relative max-w-md">
          <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
          <input
            type="text"
            placeholder="Search IP address..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 font-mono placeholder:text-slate-600"
          />
        </div>
      </div>

      {/* Table */}
      <div className="p-5 bg-slate-900/60 border border-slate-800 rounded-xl">
        {loading ? (
          <LoadingSpinner message="Calculating endpoint conversation statistics..." />
        ) : filtered.length === 0 ? (
          <div className="py-12 text-center text-xs text-slate-500 font-mono">
            No communicating endpoints found.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 font-mono">
                  <th className="pb-3 px-3">IP Address</th>
                  <th className="pb-3 px-3 text-right">Total Packets</th>
                  <th className="pb-3 px-3 text-right">Total Bytes</th>
                  <th className="pb-3 px-3 text-right">Transmitted</th>
                  <th className="pb-3 px-3 text-right">Received</th>
                  <th className="pb-3 px-3">Protocols</th>
                  <th className="pb-3 px-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono">
                {filtered.map((ep) => (
                  <tr key={ep.id} className="hover:bg-slate-800/40 transition-colors">
                    <td className="py-3 px-3 font-semibold text-cyan-400 flex items-center gap-2">
                      <Network className="w-3.5 h-3.5 text-slate-500" />
                      <span>{ep.ip_address}</span>
                    </td>
                    <td className="py-3 px-3 text-right text-slate-200">{ep.packet_count.toLocaleString()}</td>
                    <td className="py-3 px-3 text-right text-slate-300 font-semibold">{formatBytes(ep.byte_count)}</td>
                    <td className="py-3 px-3 text-right text-slate-400">
                      <span className="flex items-center justify-end gap-1 text-emerald-400">
                        <ArrowUpRight className="w-3 h-3" />
                        {formatBytes(ep.sent_bytes)} ({ep.sent_packets})
                      </span>
                    </td>
                    <td className="py-3 px-3 text-right text-slate-400">
                      <span className="flex items-center justify-end gap-1 text-blue-400">
                        <ArrowDownLeft className="w-3 h-3" />
                        {formatBytes(ep.recv_bytes)} ({ep.recv_packets})
                      </span>
                    </td>
                    <td className="py-3 px-3">
                      <div className="flex flex-wrap gap-1">
                        {ep.protocols.map((p) => (
                          <span key={p} className="px-1.5 py-0.5 rounded bg-slate-800 text-[10px] text-slate-300">
                            {p}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className="py-3 px-3 text-right">
                      <button
                        onClick={() => navigate(`/packets?ip=${ep.ip_address}`)}
                        className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-cyan-400 text-xs rounded transition-colors"
                      >
                        Inspect Packets
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
