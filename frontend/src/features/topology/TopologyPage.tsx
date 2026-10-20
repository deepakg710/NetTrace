import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import {
  Activity,
  AlertTriangle,
  ArrowLeft,
  ArrowRight,
  Calendar,
  Check,
  ChevronRight,
  Clock,
  Copy,
  ExternalLink,
  Filter,
  Globe2,
  HardDrive,
  Info,
  Maximize2,
  Monitor,
  Network,
  RefreshCw,
  RotateCcw,
  Search,
  Server,
  Share2,
  ShieldAlert,
  Users,
  X,
} from 'lucide-react';
import { useCapture } from '../../context/CaptureContext';
import { api } from '../../lib/api';
import {
  FindingItem,
  FlowItem,
  TopologyEdge,
  TopologyNode,
  TopologyResponse,
} from '../../types';
import { EmptyState } from '../../components/EmptyState';
import { LoadingSpinner } from '../../components/LoadingSpinner';
import { StatusBadge } from '../../components/StatusBadge';
import { EvidenceModal } from '../../components/EvidenceModal';
import { TopologyGraph } from './TopologyGraph';

const formatBytes = (bytes: number): string => {
  if (bytes <= 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.min(sizes.length - 1, Math.floor(Math.log(bytes) / Math.log(k)));
  return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`;
};

const formatDurationHMS = (seconds?: number | null): string => {
  if (seconds === undefined || seconds === null || Number.isNaN(seconds) || seconds < 0) {
    return '00:00:00';
  }
  if (seconds > 0 && seconds < 1) {
    return `${seconds.toFixed(2)}s`;
  }
  const totalSec = Math.round(seconds);
  const hrs = Math.floor(totalSec / 3600);
  const mins = Math.floor((totalSec % 3600) / 60);
  const secs = totalSec % 60;
  return [hrs, mins, secs].map((v) => String(v).padStart(2, '0')).join(':');
};

const formatCaptureTimestamp = (ts?: number | null): string => {
  if (ts === undefined || ts === null || Number.isNaN(ts) || ts <= 0) return 'N/A';
  try {
    const d = new Date(ts * 1000);
    return d.toISOString().replace('T', ' ').slice(0, 19);
  } catch {
    return `${ts.toFixed(2)}s`;
  }
};

const formatPacketRange = (nums: number[]): string => {
  if (!nums || nums.length === 0) return 'N/A';
  const sorted = [...nums].sort((a, b) => a - b);
  if (sorted.length === 1) return `#${sorted[0]}`;
  return `${sorted[0]}–${sorted[sorted.length - 1]}`;
};

const PROTO_COLORS: Record<string, string> = {
  TCP: '#3b82f6',
  DNS: '#10b981',
  UDP: '#a855f7',
  HTTP: '#06b6d4',
  TLS: '#6366f1',
  ICMP: '#f43f5e',
  ARP: '#f59e0b',
  Other: '#64748b',
};

export const TopologyPage: React.FC = () => {
  const { activeCapture, selectCapture } = useCapture();
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();

  const [topology, setTopology] = useState<TopologyResponse | null>(null);
  const [findings, setFindings] = useState<FindingItem[]>([]);
  const [flows, setFlows] = useState<FlowItem[]>([]);
  const [loading, setLoading] = useState<boolean>(false);
  const [reanalyzing, setReanalyzing] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  // Toolbar controls
  const [layoutMode, setLayoutMode] = useState<'force' | 'grouped'>('force');
  const [protocolFilter, setProtocolFilter] = useState<string>('');
  const [findingsOnly, setFindingsOnly] = useState<boolean>(false);
  const [maxNodes, setMaxNodes] = useState<number>(150);
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [resetSignal, setResetSignal] = useState<number>(0);
  const [fitViewSignal, setFitViewSignal] = useState<number>(0);

  // Traffic breakdown metric toggle ('bytes' | 'packets')
  const [trafficMetric, setTrafficMetric] = useState<'bytes' | 'packets'>('bytes');

  // Selection & Highlighting state
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(() =>
    searchParams.get('ip')
  );
  const [selectedEdgeId, setSelectedEdgeId] = useState<string | null>(null);
  const [highlightedFindingId, setHighlightedFindingId] = useState<string | null>(null);
  const [evidencePacketNumber, setEvidencePacketNumber] = useState<number | null>(null);
  const [copiedIp, setCopiedIp] = useState<boolean>(false);

  useEffect(() => {
    const urlIp = searchParams.get('ip');
    if (urlIp) {
      setSelectedNodeId(urlIp);
      setSelectedEdgeId(null);
    }
  }, [searchParams]);

  const fetchTopology = useCallback(async () => {
    if (!activeCapture) return;
    setLoading(true);
    setError(null);
    try {
      const [topoRes, findingsRes, flowsRes] = await Promise.all([
        api.getTopology(activeCapture.id, {
          maxNodes,
          protocol: protocolFilter || undefined,
          findingsOnly,
        }),
        api.getFindings(activeCapture.id).catch(() => [] as FindingItem[]),
        api
          .getFlows(activeCapture.id, { page: 1, page_size: 100 })
          .then((r) => r.items || [])
          .catch(() => [] as FlowItem[]),
      ]);
      setTopology(topoRes);
      setFindings(findingsRes);
      setFlows(flowsRes);

      if (selectedNodeId && !topoRes.nodes.some((n) => n.id === selectedNodeId)) {
        setSelectedNodeId(null);
      }
      if (selectedEdgeId && !topoRes.edges.some((e) => e.id === selectedEdgeId)) {
        setSelectedEdgeId(null);
      }
    } catch (err: unknown) {
      const message =
        err instanceof Error ? err.message : 'Failed to load communication topology.';
      setError(message);
    } finally {
      setLoading(false);
    }
  }, [activeCapture, maxNodes, protocolFilter, findingsOnly, selectedNodeId, selectedEdgeId]);

  useEffect(() => {
    fetchTopology();
  }, [activeCapture, maxNodes, protocolFilter, findingsOnly]);

  const handleReanalyze = async () => {
    if (!activeCapture) return;
    setReanalyzing(true);
    setError(null);
    try {
      await api.reanalyzeCapture(activeCapture.id);
      await selectCapture(activeCapture.id);
      await fetchTopology();
    } catch (err: unknown) {
      const message =
        err instanceof Error ? err.message : 'Failed to re-analyze capture.';
      setError(message);
    } finally {
      setReanalyzing(false);
    }
  };

  const findingsMap = useMemo(() => {
    const map = new Map<string, FindingItem>();
    for (const f of findings) {
      map.set(f.id, f);
    }
    return map;
  }, [findings]);

  const nodesById = useMemo(() => {
    const map = new Map<string, TopologyNode>();
    if (!topology) return map;
    for (const n of topology.nodes) {
      map.set(n.id, n);
    }
    return map;
  }, [topology]);

  const selectedNode: TopologyNode | null = useMemo(() => {
    if (!topology || !selectedNodeId) return null;
    return topology.nodes.find((n) => n.id === selectedNodeId) || null;
  }, [topology, selectedNodeId]);

  const selectedEdge: TopologyEdge | null = useMemo(() => {
    if (!topology || !selectedEdgeId) return null;
    return topology.edges.find((e) => e.id === selectedEdgeId) || null;
  }, [topology, selectedEdgeId]);

  // Summary statistics for Topology Summary Card
  const summaryStats = useMemo(() => {
    if (!topology) {
      return {
        totalEndpoints: 0,
        activeEndpoints: 0,
        isolatedEndpoints: 0,
        totalConnections: 0,
        observedConnections: 0,
        inferredConnections: 0,
      };
    }
    const connectedIds = new Set<string>();
    let observedEdges = 0;
    let inferredEdges = 0;
    for (const e of topology.edges) {
      connectedIds.add(e.source);
      connectedIds.add(e.target);
      if (e.kind === 'inferred_l2' || e.inferred) {
        inferredEdges++;
      } else {
        observedEdges++;
      }
    }
    const activeCount = topology.nodes.filter((n) => connectedIds.has(n.id)).length;
    const isolatedCount = Math.max(0, topology.nodes.length - activeCount);
    return {
      totalEndpoints: topology.nodes.length,
      activeEndpoints: activeCount,
      isolatedEndpoints: isolatedCount,
      totalConnections: topology.edges.length,
      observedConnections: observedEdges,
      inferredConnections: inferredEdges,
    };
  }, [topology]);

  // Traffic Breakdown computed from actual protocol bytes/packets
  const trafficBreakdown = useMemo(() => {
    if (!topology) return { total: 0, items: [] as Array<{ proto: string; value: number; pct: number; color: string }> };

    const rawMap: Record<string, number> = {};
    const sourceRecord =
      trafficMetric === 'bytes' ? topology.protocol_bytes : topology.protocol_packets;

    if (sourceRecord && Object.keys(sourceRecord).length > 0) {
      for (const [k, v] of Object.entries(sourceRecord)) {
        if (v > 0) rawMap[k.toUpperCase()] = (rawMap[k.toUpperCase()] || 0) + v;
      }
    } else {
      // Fallback: aggregate from observed edges
      for (const e of topology.edges) {
        if (e.kind === 'inferred_l2' || e.inferred) continue;
        const p = (e.protocols[0] || 'Other').toUpperCase();
        const val = trafficMetric === 'bytes' ? e.bytes : e.packets;
        if (val > 0) rawMap[p] = (rawMap[p] || 0) + val;
      }
    }

    const total = Object.values(rawMap).reduce((acc, v) => acc + v, 0);
    if (total <= 0) return { total: 0, items: [] };

    const sorted = Object.entries(rawMap).sort((a, b) => b[1] - a[1]);
    const topSlice = sorted.slice(0, 5);
    const restSum = sorted.slice(5).reduce((acc, [, v]) => acc + v, 0);
    if (restSum > 0) {
      topSlice.push(['Other', restSum]);
    }

    const items = topSlice.map(([proto, value]) => ({
      proto,
      value,
      pct: Math.max(0.1, Number(((value / total) * 100).toFixed(1))),
      color: PROTO_COLORS[proto] || PROTO_COLORS.Other,
    }));

    return { total, items };
  }, [topology, trafficMetric]);

  // Highlighted nodes and edges when a finding is clicked
  const { highlightedNodeIds, highlightedEdgeIds } = useMemo(() => {
    const nSet = new Set<string>();
    const eSet = new Set<string>();
    if (!highlightedFindingId || !topology) {
      return { highlightedNodeIds: nSet, highlightedEdgeIds: eSet };
    }
    for (const n of topology.nodes) {
      if (n.finding_ids.includes(highlightedFindingId)) {
        nSet.add(n.id);
      }
    }
    for (const e of topology.edges) {
      if (
        e.finding_ids.includes(highlightedFindingId) ||
        (nSet.has(e.source) && nSet.has(e.target))
      ) {
        eSet.add(e.id);
      }
    }
    return { highlightedNodeIds: nSet, highlightedEdgeIds: eSet };
  }, [highlightedFindingId, topology]);

  // Compute top peers for the selected node from observed edges
  const selectedNodePeers = useMemo(() => {
    if (!selectedNode || !topology) return [];
    const list: Array<{
      peerId: string;
      peerClassification: string;
      packets: number;
      bytes: number;
      flowCount: number;
      protocols: string[];
      inferred: boolean;
    }> = [];

    for (const e of topology.edges) {
      if (e.source === selectedNode.id || e.target === selectedNode.id) {
        const peerId = e.source === selectedNode.id ? e.target : e.source;
        const peerNode = nodesById.get(peerId);
        list.push({
          peerId,
          peerClassification:
            peerNode?.classification ||
            (peerNode?.scope === 'local' ? 'Private Host' : 'Remote Host'),
          packets: e.packets,
          bytes: e.bytes,
          flowCount: e.flow_count,
          protocols: e.protocols,
          inferred: e.kind === 'inferred_l2' || Boolean(e.inferred),
        });
      }
    }
    return list.sort((a, b) => b.packets - a.packets || b.bytes - a.bytes);
  }, [selectedNode, topology, nodesById]);

  const totalSelectedNodePeerPackets = useMemo(
    () => selectedNodePeers.reduce((acc, p) => acc + p.packets, 0) || 1,
    [selectedNodePeers]
  );

  // Related flows for the selected node or edge
  const selectedEntityFlows = useMemo(() => {
    if (selectedNode) {
      return flows
        .filter((f) => f.src_ip === selectedNode.id || f.dst_ip === selectedNode.id)
        .slice(0, 6);
    }
    if (selectedEdge) {
      return flows
        .filter(
          (f) =>
            (f.src_ip === selectedEdge.source && f.dst_ip === selectedEdge.target) ||
            (f.src_ip === selectedEdge.target && f.dst_ip === selectedEdge.source)
        )
        .slice(0, 6);
    }
    return [];
  }, [flows, selectedNode, selectedEdge]);

  // Related findings for the Related Findings card
  const displayedFindings = useMemo(() => {
    if (selectedNode) {
      return selectedNode.finding_ids
        .map((fid) => findingsMap.get(fid))
        .filter((f): f is FindingItem => Boolean(f));
    }
    if (selectedEdge) {
      return selectedEdge.finding_ids
        .map((fid) => findingsMap.get(fid))
        .filter((f): f is FindingItem => Boolean(f));
    }
    return findings.slice(0, 5);
  }, [selectedNode, selectedEdge, findingsMap, findings]);

  const handleSearchKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter' && topology && searchQuery.trim()) {
      const q = searchQuery.trim().toLowerCase();
      const match = topology.nodes.find(
        (n) =>
          n.id.toLowerCase().includes(q) ||
          (n.classification || '').toLowerCase().includes(q) ||
          n.roles.some((r) => r.role.toLowerCase().includes(q))
      );
      if (match) {
        setSelectedEdgeId(null);
        setSelectedNodeId(match.id);
      }
    }
  };

  const handleCopyIp = (ip: string) => {
    if (navigator?.clipboard?.writeText) {
      navigator.clipboard.writeText(ip).catch(() => {});
    }
    setCopiedIp(true);
    setTimeout(() => setCopiedIp(false), 1500);
  };

  if (!activeCapture) {
    return (
      <EmptyState
        title="No Capture Selected"
        description="Select or upload a capture to inspect observed communication topology and endpoint relationships."
        actionText="Go to Captures"
        onAction={() => navigate('/captures')}
      />
    );
  }

  const totalCapturePackets =
    topology?.total_packets || activeCapture.packet_count || 0;
  const totalCaptureBytes =
    topology?.total_bytes ||
    activeCapture.metadata?.total_bytes ||
    activeCapture.file_size_bytes ||
    0;

  return (
    <div className="space-y-3 animate-in fade-in duration-200">
      {/* Compact Current-Capture Status Strip & Header matching Reference Image */}
      <div className="p-3 bg-slate-900/70 border border-slate-800/90 rounded-xl flex flex-col lg:flex-row lg:items-center justify-between gap-3">
        <div className="flex items-start gap-3">
          <div className="w-9 h-9 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 flex-shrink-0 mt-0.5">
            <Share2 className="w-5 h-5" />
          </div>
          <div>
            <div className="flex flex-wrap items-center gap-2.5">
              <h1 className="text-lg sm:text-xl font-bold text-slate-100 tracking-tight">
                Communication Topology
              </h1>
              <span className="px-2 py-0.5 rounded-full bg-emerald-950/70 border border-emerald-700/60 text-[11px] font-mono text-emerald-400 flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                Analysis {activeCapture.status === 'completed' ? 'Complete' : activeCapture.status}
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Visualize how endpoints in this capture communicate with each other.
            </p>
          </div>
        </div>

        {/* Capture Telemetry Pill Strip */}
        <div className="flex flex-wrap items-center gap-x-4 gap-y-1.5 text-xs font-mono text-slate-300 bg-slate-950/80 border border-slate-800/90 px-3 py-2 rounded-lg">
          <span className="flex items-center gap-1.5 text-cyan-300 font-semibold">
            <HardDrive className="w-3.5 h-3.5 text-cyan-400" />
            {activeCapture.original_filename}
          </span>
          <span className="text-slate-700">|</span>
          <span className="flex items-center gap-1 text-slate-300" title="Total observed packets">
            <Activity className="w-3.5 h-3.5 text-slate-400" />
            <span>{totalCapturePackets.toLocaleString()} pkts</span>
          </span>
          <span className="text-slate-700 hidden sm:inline">|</span>
          <span className="flex items-center gap-1 text-slate-300" title="Capture byte volume">
            <span>Size {formatBytes(totalCaptureBytes)}</span>
          </span>
          <span className="text-slate-700 hidden md:inline">|</span>
          <span className="hidden md:flex items-center gap-1 text-slate-300" title="Capture duration">
            <Clock className="w-3.5 h-3.5 text-slate-400" />
            <span>Duration {formatDurationHMS(activeCapture.duration_seconds)}</span>
          </span>
          {activeCapture.start_time && (
            <>
              <span className="text-slate-700 hidden xl:inline">|</span>
              <span className="hidden xl:flex items-center gap-1 text-slate-400">
                <Calendar className="w-3.5 h-3.5 text-slate-500" />
                <span>Captured {formatCaptureTimestamp(activeCapture.start_time)}</span>
              </span>
            </>
          )}
        </div>
      </div>

      {/* Unified Toolbar matching Reference Image */}
      <div className="p-2.5 bg-slate-900/70 border border-slate-800 rounded-xl flex flex-wrap items-center gap-2">
        {/* Force Layout / Grouped Toggle */}
        <div
          className="inline-flex rounded-lg bg-slate-950 border border-slate-800 p-0.5 text-xs font-mono"
          role="group"
          aria-label="Layout toggle"
        >
          <button
            type="button"
            onClick={() => setLayoutMode('force')}
            className={`px-3 py-1.5 rounded-md transition-colors flex items-center gap-1.5 ${
              layoutMode === 'force'
                ? 'bg-blue-600 text-white font-semibold shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Share2 className="w-3.5 h-3.5" />
            <span>Force Layout</span>
          </button>
          <button
            type="button"
            onClick={() => setLayoutMode('grouped')}
            className={`px-3 py-1.5 rounded-md transition-colors flex items-center gap-1.5 ${
              layoutMode === 'grouped'
                ? 'bg-blue-600 text-white font-semibold shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Network className="w-3.5 h-3.5" />
            <span>Grouped</span>
          </button>
        </div>

        {/* Protocol Filter */}
        <select
          aria-label="Protocol filter"
          value={protocolFilter}
          onChange={(e) => setProtocolFilter(e.target.value)}
          className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 font-mono focus:outline-none focus:border-cyan-500"
        >
          <option value="">All Protocols</option>
          <option value="TCP">TCP</option>
          <option value="UDP">UDP</option>
          <option value="DNS">DNS</option>
          <option value="ICMP">ICMP</option>
          <option value="ARP">ARP</option>
          <option value="HTTP">HTTP</option>
          <option value="TLS">TLS</option>
          <option value="IPv6">IPv6</option>
        </select>

        {/* Findings Only Pill Switch */}
        <label className="flex items-center gap-2 px-3 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 font-mono cursor-pointer select-none hover:border-slate-700 transition-colors">
          <input
            type="checkbox"
            checked={findingsOnly}
            onChange={(e) => setFindingsOnly(e.target.checked)}
            className="rounded border-slate-700 bg-slate-900 text-cyan-500 focus:ring-cyan-500"
          />
          <span>Findings only</span>
        </label>

        {/* Max Nodes Select */}
        <div className="flex items-center gap-1.5 bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs font-mono text-slate-400">
          <span>Max nodes:</span>
          <select
            aria-label="Max nodes"
            value={maxNodes}
            onChange={(e) => setMaxNodes(parseInt(e.target.value, 10))}
            className="bg-transparent text-slate-200 font-semibold focus:outline-none"
          >
            <option value={25} className="bg-slate-950">25</option>
            <option value={50} className="bg-slate-950">50</option>
            <option value={150} className="bg-slate-950">150</option>
            <option value={500} className="bg-slate-950">500</option>
          </select>
        </div>

        {/* Endpoint Search Input */}
        <div className="relative flex-1 min-w-[200px] max-w-xs">
          <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            aria-label="Search endpoint"
            placeholder="Search endpoint (IP or name)..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            onKeyDown={handleSearchKeyDown}
            className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-8 pr-7 py-1.5 text-xs text-slate-200 font-mono placeholder:text-slate-500 focus:outline-none focus:border-cyan-500"
          />
          {searchQuery && (
            <button
              type="button"
              aria-label="Clear search"
              onClick={() => setSearchQuery('')}
              className="absolute right-2 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-200"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          )}
        </div>

        {/* Clear Filters + Fit View + Reset Layout Controls */}
        <div className="flex items-center gap-1.5 ml-auto">
          {(protocolFilter || findingsOnly || searchQuery || highlightedFindingId) && (
            <button
              type="button"
              onClick={() => {
                setProtocolFilter('');
                setFindingsOnly(false);
                setSearchQuery('');
                setHighlightedFindingId(null);
              }}
              className="px-2.5 py-1.5 bg-cyan-950/50 hover:bg-cyan-900/60 text-cyan-300 border border-cyan-700/60 rounded-lg text-xs font-mono flex items-center gap-1 transition-colors"
            >
              <span>Clear Filters</span>
              <X className="w-3 h-3" />
            </button>
          )}
          <button
            type="button"
            onClick={() => setFitViewSignal((s) => s + 1)}
            className="px-2.5 py-1.5 bg-slate-950 hover:bg-slate-800 text-slate-300 border border-slate-800 rounded-lg text-xs font-mono flex items-center gap-1.5 transition-colors"
            title="Fit all visible nodes in canvas"
          >
            <Maximize2 className="w-3.5 h-3.5" />
            <span>Fit View</span>
          </button>
          <button
            type="button"
            onClick={() => {
              setSelectedNodeId(null);
              setSelectedEdgeId(null);
              setHighlightedFindingId(null);
              setSearchQuery('');
              setResetSignal((s) => s + 1);
            }}
            className="px-3 py-1.5 bg-slate-950 hover:bg-slate-800 text-slate-200 border border-slate-800 rounded-lg text-xs font-mono flex items-center gap-1.5 transition-colors"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            <span>Reset Layout</span>
          </button>
        </div>
      </div>

      {/* Error Banner */}
      {error && (
        <div className="p-3 bg-rose-950/50 border border-rose-800/80 rounded-xl flex items-center gap-2.5 text-xs text-rose-200 font-mono">
          <AlertTriangle className="w-4 h-4 text-rose-400 flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Notes / Truncation / Missing Hints Banner */}
      {topology && (topology.notes.length > 0 || !topology.hints_available || topology.truncated) && (
        <div className="px-3.5 py-2.5 bg-amber-950/25 border border-amber-800/50 rounded-xl flex flex-col sm:flex-row sm:items-center justify-between gap-2.5 text-xs text-amber-200/90 font-mono">
          <div className="space-y-1">
            {topology.notes.map((note, idx) => (
              <div key={idx} className="flex items-start gap-2">
                <Info className="w-3.5 h-3.5 text-amber-400 flex-shrink-0 mt-0.5" />
                <span>{note}</span>
              </div>
            ))}
          </div>
          {!topology.hints_available && (
            <button
              type="button"
              onClick={handleReanalyze}
              disabled={reanalyzing}
              className="px-3 py-1.5 bg-amber-500/20 hover:bg-amber-500/30 text-amber-200 border border-amber-500/40 rounded-lg text-xs font-mono font-semibold flex items-center gap-1.5 self-start sm:self-center whitespace-nowrap transition-colors disabled:opacity-50"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${reanalyzing ? 'animate-spin' : ''}`} />
              <span>{reanalyzing ? 'Re-analyzing...' : 'Re-analyze'}</span>
            </button>
          )}
        </div>
      )}

      {/* Main Content Area: Left Graph Canvas + Legend | Right Multi-Card Sidebar */}
      {loading ? (
        <div className="p-12 bg-slate-900/60 border border-slate-800 rounded-xl">
          <LoadingSpinner message="Building communication topology..." />
        </div>
      ) : topology && topology.nodes.length === 0 ? (
        <EmptyState
          title="No IP conversations in this capture"
          description="No matching endpoints or IP conversations were observed for the selected filters."
          actionText="Reset Filters"
          onAction={() => {
            setProtocolFilter('');
            setFindingsOnly(false);
            setSearchQuery('');
          }}
        />
      ) : topology ? (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-3.5 items-start">
          {/* Left Column (8 cols): Central Topology Canvas + 5-Column Graph Legend */}
          <div className="lg:col-span-8 flex flex-col gap-3 min-w-0">
            <div className="h-[490px] xl:h-[550px] w-full">
              <TopologyGraph
                nodes={topology.nodes}
                edges={topology.edges}
                layoutMode={layoutMode}
                selectedNodeId={selectedNodeId}
                selectedEdgeId={selectedEdgeId}
                highlightedNodeIds={highlightedNodeIds}
                highlightedEdgeIds={highlightedEdgeIds}
                searchQuery={searchQuery}
                captureFilename={activeCapture.original_filename}
                totalFlowsCount={topology.total_flows}
                onSelectNode={(n) => {
                  setHighlightedFindingId(null);
                  setSelectedEdgeId(null);
                  setSelectedNodeId(n ? n.id : null);
                }}
                onSelectEdge={(e) => {
                  setHighlightedFindingId(null);
                  setSelectedNodeId(null);
                  setSelectedEdgeId(e ? e.id : null);
                }}
                resetSignal={resetSignal}
                fitViewSignal={fitViewSignal}
              />
            </div>

            {/* Compact 5-Column Graph Legend Bar matching Reference Image */}
            <div className="p-3 bg-slate-900/75 border border-slate-800/90 rounded-xl grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-5 gap-3 text-[11px] font-mono text-slate-300">
              {/* Col 1: Graph Legend (Endpoint Icons) */}
              <div className="space-y-1.5 xl:border-r xl:border-slate-800/80 xl:pr-2.5">
                <div className="text-[10px] text-slate-400 font-semibold uppercase tracking-wider">
                  Graph Legend
                </div>
                <div className="grid grid-cols-2 gap-1.5 pt-0.5 text-[10px]">
                  <span className="flex items-center gap-1.5 text-slate-300">
                    <span className="w-4 h-4 rounded-full border border-cyan-400 bg-cyan-500/10 flex items-center justify-center text-cyan-400">
                      <Monitor className="w-2.5 h-2.5" />
                    </span>
                    <span className="truncate">Client / Host</span>
                  </span>
                  <span className="flex items-center gap-1.5 text-slate-300">
                    <span className="w-4 h-4 rounded-full border border-purple-400 bg-purple-500/10 flex items-center justify-center text-purple-400">
                      <Server className="w-2.5 h-2.5" />
                    </span>
                    <span className="truncate">Server</span>
                  </span>
                  <span className="flex items-center gap-1.5 text-slate-300">
                    <span className="w-4 h-4 rounded-full border border-emerald-400 bg-emerald-500/10 flex items-center justify-center text-emerald-400">
                      <Server className="w-2.5 h-2.5" />
                    </span>
                    <span className="truncate">DNS Server</span>
                  </span>
                  <span className="flex items-center gap-1.5 text-slate-300">
                    <span className="w-4 h-4 rounded-full border border-dashed border-slate-400 bg-slate-800/60" />
                    <span className="truncate">Isolated</span>
                  </span>
                </div>
              </div>

              {/* Col 2: Connections */}
              <div className="space-y-1.5 xl:border-r xl:border-slate-800/80 xl:pr-2.5">
                <div className="text-[10px] text-slate-400 font-semibold uppercase tracking-wider">
                  Connections
                </div>
                <div className="space-y-1.5 pt-0.5 text-[10px]">
                  <div className="flex items-center gap-2 text-slate-300">
                    <span className="w-7 h-0.5 bg-blue-400 relative inline-block">
                      <span className="absolute -right-0.5 -top-1 border-y-4 border-y-transparent border-l-4 border-l-blue-400" />
                    </span>
                    <span>Observed (traffic volume)</span>
                  </div>
                  <div className="flex items-center gap-2 text-slate-300">
                    <span className="w-7 border-t border-dashed border-emerald-400 relative inline-block">
                      <span className="absolute -right-0.5 -top-1 border-y-4 border-y-transparent border-l-4 border-l-emerald-400" />
                    </span>
                    <span>Inferred (L2 / heuristic)</span>
                  </div>
                </div>
              </div>

              {/* Col 3: Edge / Node Size */}
              <div className="space-y-1.5 xl:border-r xl:border-slate-800/80 xl:pr-2.5">
                <div className="text-[10px] text-slate-400 font-semibold uppercase tracking-wider">
                  Edge / Node Size
                </div>
                <div className="space-y-1.5 pt-0.5 text-[10px] text-slate-300">
                  <div className="flex items-center gap-2">
                    <span className="w-5 h-[1.5px] bg-blue-400 rounded" />
                    <span>Larger node = more bytes</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="w-5 h-[4px] bg-cyan-400 rounded" />
                    <span>Thicker edge = more bytes</span>
                  </div>
                </div>
              </div>

              {/* Col 4: Protocol Colors */}
              <div className="space-y-1.5 xl:border-r xl:border-slate-800/80 xl:pr-2.5">
                <div className="text-[10px] text-slate-400 font-semibold uppercase tracking-wider">
                  Protocol Colors
                </div>
                <div className="grid grid-cols-2 gap-x-2 gap-y-1 pt-0.5 text-[10px]">
                  <span className="flex items-center gap-1.5 text-slate-300">
                    <span className="w-2 h-2 rounded-full bg-[#3b82f6]" /> TCP
                  </span>
                  <span className="flex items-center gap-1.5 text-slate-300">
                    <span className="w-2 h-2 rounded-full bg-[#a855f7]" /> UDP
                  </span>
                  <span className="flex items-center gap-1.5 text-slate-300">
                    <span className="w-2 h-2 rounded-full bg-[#10b981]" /> DNS
                  </span>
                  <span className="flex items-center gap-1.5 text-slate-300">
                    <span className="w-2 h-2 rounded-full bg-[#f43f5e]" /> Reset/Finding
                  </span>
                </div>
              </div>

              {/* Col 5: Quick Actions */}
              <div className="space-y-1">
                <div className="text-[10px] text-slate-400 font-semibold uppercase tracking-wider">
                  Quick Actions
                </div>
                <div className="flex flex-col gap-1 pt-0.5 text-[10px]">
                  <button
                    type="button"
                    onClick={() => {
                      if (selectedNode && selectedNode.kind === 'host') {
                        navigate(`/packets?ip=${encodeURIComponent(selectedNode.id)}`);
                      } else if (selectedEdge && !selectedEdge.source.startsWith('gw:')) {
                        navigate(
                          `/packets?display_filter=${encodeURIComponent(
                            `ip.addr == ${selectedEdge.source} && ip.addr == ${selectedEdge.target}`
                          )}`
                        );
                      } else {
                        navigate('/packets');
                      }
                    }}
                    className="text-left text-slate-300 hover:text-cyan-300 flex items-center gap-1.5 transition-colors"
                  >
                    <Search className="w-3 h-3 text-cyan-400" />
                    <span>Locate in Packet Explorer</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      if (selectedNode && selectedNode.kind === 'host') {
                        navigate(`/flows?ip=${encodeURIComponent(selectedNode.id)}`);
                      } else if (selectedEdge && !selectedEdge.source.startsWith('gw:')) {
                        navigate(`/flows?ip=${encodeURIComponent(selectedEdge.source)}`);
                      } else {
                        navigate('/flows');
                      }
                    }}
                    className="text-left text-slate-300 hover:text-cyan-300 flex items-center gap-1.5 transition-colors"
                  >
                    <Activity className="w-3 h-3 text-blue-400" />
                    <span>View Flows</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      if (selectedNode && selectedNode.kind === 'host') {
                        navigate(
                          `/packets?display_filter=${encodeURIComponent(
                            `ip.addr == ${selectedNode.id}`
                          )}`
                        );
                      } else {
                        navigate('/packets');
                      }
                    }}
                    className="text-left text-slate-300 hover:text-cyan-300 flex items-center gap-1.5 transition-colors"
                  >
                    <Filter className="w-3 h-3 text-emerald-400" />
                    <span>Add Filter</span>
                  </button>
                </div>
              </div>
            </div>
          </div>

          {/* Right Column (4 cols): Stacked Sidebar Cards matching Reference Image */}
          <div className="lg:col-span-4 min-w-0 space-y-3 max-h-[675px] overflow-y-auto pr-0.5">
            {/* CARD 1: Topology Summary & Traffic Breakdown */}
            <div
              className="p-3.5 bg-slate-900/75 border border-slate-800/90 rounded-xl space-y-3"
              data-testid="topology-summary-details"
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Share2 className="w-4 h-4 text-cyan-400" />
                  <h2 className="text-xs font-bold uppercase tracking-wider text-slate-200 font-mono">
                    Topology Summary
                  </h2>
                </div>
                {topology.truncated && (
                  <span className="px-2 py-0.5 rounded bg-amber-950/80 border border-amber-700/70 text-[10px] font-mono text-amber-300">
                    Truncated ({topology.omitted_nodes} omitted)
                  </span>
                )}
              </div>

              {/* 2 KPI Boxes: Total Endpoints & Total Connections */}
              <div className="grid grid-cols-2 gap-2.5 text-xs font-mono">
                <div className="p-2.5 bg-slate-950/75 border border-slate-800/90 rounded-lg">
                  <div className="flex items-center gap-1.5 text-[10px] text-slate-400">
                    <Users className="w-3.5 h-3.5 text-cyan-400" />
                    <span>Total Endpoints</span>
                  </div>
                  <div className="text-xl font-bold text-slate-100 mt-0.5">
                    {summaryStats.totalEndpoints}
                    {topology.truncated && (
                      <span className="text-xs font-normal text-slate-400 ml-1">
                        / {topology.total_nodes}
                      </span>
                    )}
                  </div>
                  <div className="text-[10px] text-slate-400 mt-0.5">
                    ({summaryStats.activeEndpoints} active, {summaryStats.isolatedEndpoints} isolated)
                  </div>
                </div>

                <div className="p-2.5 bg-slate-950/75 border border-slate-800/90 rounded-lg">
                  <div className="flex items-center gap-1.5 text-[10px] text-slate-400">
                    <Network className="w-3.5 h-3.5 text-blue-400" />
                    <span>Total Connections</span>
                  </div>
                  <div className="text-xl font-bold text-slate-100 mt-0.5">
                    {summaryStats.totalConnections}
                  </div>
                  <div className="text-[10px] text-slate-400 mt-0.5">
                    ({summaryStats.observedConnections} observed, {summaryStats.inferredConnections}{' '}
                    inferred)
                  </div>
                </div>
              </div>

              {/* Traffic Breakdown Sub-Section */}
              <div className="pt-2 border-t border-slate-800/80 space-y-2 text-xs font-mono">
                <div className="flex items-center justify-between">
                  <span className="text-[11px] font-semibold text-slate-200">
                    Traffic Breakdown
                  </span>
                  <div className="inline-flex rounded bg-slate-950 border border-slate-800 p-0.5 text-[10px]">
                    <button
                      type="button"
                      onClick={() => setTrafficMetric('bytes')}
                      className={`px-1.5 py-0.5 rounded transition-colors ${
                        trafficMetric === 'bytes'
                          ? 'bg-cyan-500/20 text-cyan-300 font-semibold'
                          : 'text-slate-500 hover:text-slate-300'
                      }`}
                    >
                      Bytes
                    </button>
                    <button
                      type="button"
                      onClick={() => setTrafficMetric('packets')}
                      className={`px-1.5 py-0.5 rounded transition-colors ${
                        trafficMetric === 'packets'
                          ? 'bg-cyan-500/20 text-cyan-300 font-semibold'
                          : 'text-slate-500 hover:text-slate-300'
                      }`}
                    >
                      Packets
                    </button>
                  </div>
                </div>

                {trafficBreakdown.items.length > 0 ? (
                  <>
                    {/* Stacked Multi-Segment Progress Bar */}
                    <div className="w-full h-2.5 bg-slate-950 rounded-full overflow-hidden flex border border-slate-800/80">
                      {trafficBreakdown.items.map((item) => (
                        <div
                          key={item.proto}
                          style={{
                            width: `${Math.max(3, item.pct)}%`,
                            backgroundColor: item.color,
                          }}
                          title={`${item.proto}: ${
                            trafficMetric === 'bytes'
                              ? formatBytes(item.value)
                              : `${item.value.toLocaleString()} pkts`
                          } (${item.pct}%)`}
                          className="h-full first:rounded-l-full last:rounded-r-full"
                        />
                      ))}
                    </div>

                    {/* Protocol Legend & Percentages */}
                    <div className="grid grid-cols-2 gap-x-3 gap-y-1 pt-0.5 text-[11px]">
                      {trafficBreakdown.items.map((item) => (
                        <div
                          key={item.proto}
                          className="flex items-center justify-between text-slate-300"
                        >
                          <span className="flex items-center gap-1.5 truncate">
                            <span
                              className="w-2 h-2 rounded-full flex-shrink-0"
                              style={{ backgroundColor: item.color }}
                            />
                            <span className="truncate">{item.proto}</span>
                          </span>
                          <span className="text-slate-400 font-semibold">{item.pct}%</span>
                        </div>
                      ))}
                    </div>
                  </>
                ) : (
                  <div className="text-[11px] text-slate-500 italic">
                    No protocol volume data available.
                  </div>
                )}
              </div>
            </div>

            {/* CARD 2: Selected Endpoint OR Selected Connection Inspector */}
            {selectedEdge ? (
              <div
                className="p-3.5 bg-slate-900/75 border border-slate-800/90 rounded-xl space-y-3.5"
                data-testid="topology-edge-details"
              >
                <div className="flex items-center justify-between pb-2 border-b border-slate-800">
                  <button
                    type="button"
                    onClick={() => setSelectedEdgeId(null)}
                    className="text-xs font-mono text-slate-300 hover:text-white flex items-center gap-1.5 transition-colors font-semibold"
                  >
                    <ArrowLeft className="w-3.5 h-3.5 text-cyan-400" />
                    <span>Selected connection</span>
                  </button>
                  <div className="flex items-center gap-1.5">
                    <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-200 border border-slate-700 text-[10px] font-mono uppercase">
                      {selectedEdge.status}
                    </span>
                    {(selectedEdge.kind === 'inferred_l2' || selectedEdge.inferred) && (
                      <span
                        title={selectedEdge.basis || ''}
                        className="px-2 py-0.5 rounded bg-amber-950/80 text-amber-300 border border-dashed border-amber-600 text-[10px] font-mono"
                      >
                        inferred
                      </span>
                    )}
                  </div>
                </div>

                <div>
                  <span className="text-[10px] font-mono uppercase tracking-wider text-cyan-400 block">
                    {selectedEdge.bidirectional
                      ? 'Bidirectional Conversation'
                      : 'Directional Communication'}
                  </span>
                  <h3 className="text-sm font-bold font-mono text-slate-100 break-all mt-0.5">
                    {selectedEdge.initiator || selectedEdge.source}{' '}
                    {selectedEdge.bidirectional ? '↔' : '→'}{' '}
                    {selectedEdge.responder || selectedEdge.target}
                  </h3>
                </div>

                {(selectedEdge.kind === 'inferred_l2' || selectedEdge.inferred) &&
                  selectedEdge.basis && (
                    <div className="p-2.5 bg-amber-950/30 border border-dashed border-amber-700/60 rounded-lg text-[11px] font-mono text-amber-200">
                      {selectedEdge.basis}
                    </div>
                  )}

                <div className="grid grid-cols-3 gap-2 text-xs font-mono">
                  <div className="p-2 bg-slate-950/70 border border-slate-800 rounded-lg">
                    <span className="text-[10px] text-slate-500 uppercase block">Flows</span>
                    <span className="text-slate-200 font-semibold">
                      {selectedEdge.flow_count.toLocaleString()}
                    </span>
                  </div>
                  <div className="p-2 bg-slate-950/70 border border-slate-800 rounded-lg">
                    <span className="text-[10px] text-slate-500 uppercase block">Packets</span>
                    <span className="text-slate-200 font-semibold">
                      {selectedEdge.packets.toLocaleString()}
                    </span>
                  </div>
                  <div className="p-2 bg-slate-950/70 border border-slate-800 rounded-lg">
                    <span className="text-[10px] text-slate-500 uppercase block">Bytes</span>
                    <span className="text-cyan-400 font-semibold">
                      {formatBytes(selectedEdge.bytes)}
                    </span>
                  </div>
                </div>

                {/* Protocols & Ports */}
                <div className="space-y-2 text-xs font-mono">
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] uppercase text-slate-500">Protocols</span>
                    <div className="flex flex-wrap gap-1">
                      {selectedEdge.protocols.length > 0 ? (
                        selectedEdge.protocols.map((p) => (
                          <span
                            key={p}
                            className="px-2 py-0.5 bg-slate-800 text-cyan-300 rounded text-[10px]"
                          >
                            {p}
                          </span>
                        ))
                      ) : (
                        <span className="text-slate-500 italic text-[11px]">L2 / Inferred</span>
                      )}
                    </div>
                  </div>
                  {selectedEdge.ports.length > 0 && (
                    <div>
                      <span className="text-[10px] uppercase text-slate-500 block mb-1">
                        Destination Ports
                      </span>
                      <div className="flex flex-wrap gap-1">
                        {selectedEdge.ports.map((port) => (
                          <span
                            key={port}
                            className="px-1.5 py-0.5 bg-slate-950 border border-slate-800 text-slate-300 rounded text-[10px]"
                          >
                            {port}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>

                {/* Flow State Breakdown */}
                <div className="space-y-1.5 text-xs font-mono">
                  <span className="text-[10px] uppercase text-slate-500 block">
                    Flow State Breakdown
                  </span>
                  {Object.keys(selectedEdge.states).length > 0 ? (
                    <div className="border border-slate-800 rounded-lg overflow-hidden">
                      <table className="w-full text-left text-[11px] font-mono">
                        <tbody className="divide-y divide-slate-800/60">
                          {Object.entries(selectedEdge.states).map(([st, cnt]) => (
                            <tr key={st} className="bg-slate-950/40">
                              <td className="py-1.5 px-2.5">
                                <StatusBadge status={st} type="state" />
                              </td>
                              <td className="py-1.5 px-2.5 text-right text-slate-200 font-semibold">
                                {cnt}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  ) : (
                    <span className="text-slate-500 italic text-[11px]">
                      No transport state records (inferred L2 link)
                    </span>
                  )}
                </div>

                {/* Sample Packet Evidence */}
                {selectedEdge.sample_packet_numbers &&
                  selectedEdge.sample_packet_numbers.length > 0 && (
                    <div className="space-y-1.5 text-xs font-mono">
                      <span className="text-[10px] uppercase text-slate-500 block">
                        Packet Evidence Frames
                      </span>
                      <div className="flex flex-wrap gap-1.5">
                        {selectedEdge.sample_packet_numbers.map((pnum) => (
                          <button
                            key={pnum}
                            type="button"
                            onClick={() => setEvidencePacketNumber(pnum)}
                            className="px-2 py-0.5 bg-cyan-950 hover:bg-cyan-900 text-cyan-300 border border-cyan-800 rounded text-[10px] flex items-center gap-1 transition-colors"
                          >
                            <span>Frame #{pnum}</span>
                            <ExternalLink className="w-2.5 h-2.5" />
                          </button>
                        ))}
                      </div>
                    </div>
                  )}

                {/* Edge Action Buttons */}
                <div className="grid grid-cols-2 gap-2 pt-1">
                  <button
                    type="button"
                    onClick={() => {
                      const targetIp = selectedEdge.source.startsWith('gw:')
                        ? selectedEdge.target
                        : selectedEdge.source;
                      navigate(`/flows?ip=${encodeURIComponent(targetIp)}`);
                    }}
                    className="px-2.5 py-2 bg-blue-600 hover:bg-blue-500 text-white font-semibold rounded-lg text-xs font-mono flex items-center justify-center gap-1.5 transition-colors"
                  >
                    <span>View Related Flows</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      if (!selectedEdge.source.startsWith('gw:') && !selectedEdge.target.startsWith('gw:')) {
                        navigate(
                          `/packets?display_filter=${encodeURIComponent(
                            `ip.addr == ${selectedEdge.source} && ip.addr == ${selectedEdge.target}`
                          )}`
                        );
                      } else {
                        const hostIp = selectedEdge.source.startsWith('gw:')
                          ? selectedEdge.target
                          : selectedEdge.source;
                        navigate(`/packets?ip=${encodeURIComponent(hostIp)}`);
                      }
                    }}
                    className="px-2.5 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded-lg text-xs font-mono flex items-center justify-center gap-1.5 transition-colors"
                  >
                    <span>View Packets</span>
                  </button>
                </div>
              </div>
            ) : selectedNode ? (
              <div
                className="p-3.5 bg-slate-900/75 border border-slate-800/90 rounded-xl space-y-3.5"
                data-testid="topology-node-details"
              >
                {/* Card Header */}
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Monitor className="w-4 h-4 text-cyan-400" />
                    <h2 className="text-xs font-bold uppercase tracking-wider text-slate-200 font-mono">
                      Selected Endpoint
                    </h2>
                  </div>
                  <div className="flex items-center gap-1.5">
                    {selectedNode.kind === 'inferred_gateway' && (
                      <span
                        title={selectedNode.roles[0]?.basis || 'Inferred gateway node'}
                        className="px-2 py-0.5 rounded bg-amber-950/80 text-amber-300 border border-dashed border-amber-600 text-[10px] font-mono"
                      >
                        inferred
                      </span>
                    )}
                    <button
                      type="button"
                      aria-label="Clear selected endpoint"
                      onClick={() => setSelectedNodeId(null)}
                      className="text-slate-500 hover:text-slate-200 transition-colors"
                    >
                      <X className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>

                {/* Endpoint Identity Box matching Reference Image */}
                <div className="p-2.5 bg-slate-950/80 border border-slate-800/90 rounded-xl flex items-center gap-3">
                  <div className="w-10 h-10 rounded-full bg-blue-500/10 border-2 border-cyan-400 flex items-center justify-center text-cyan-400 flex-shrink-0">
                    {selectedNode.scope === 'remote' ? (
                      <Globe2 className="w-5 h-5" />
                    ) : selectedNode.roles.some(
                        (r) => r.role === 'dns_server' || r.role === 'scan_target'
                      ) ? (
                      <Server className="w-5 h-5" />
                    ) : (
                      <Monitor className="w-5 h-5" />
                    )}
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-1.5">
                      <h3 className="text-sm font-bold font-mono text-slate-100 truncate">
                        {selectedNode.id}
                      </h3>
                      <button
                        type="button"
                        title="Copy IP address"
                        onClick={() => handleCopyIp(selectedNode.id)}
                        className="text-slate-500 hover:text-slate-200 transition-colors"
                      >
                        {copiedIp ? (
                          <Check className="w-3 h-3 text-emerald-400" />
                        ) : (
                          <Copy className="w-3 h-3" />
                        )}
                      </button>
                    </div>
                    <div className="text-[11px] text-slate-400 truncate">
                      ({selectedNode.classification || 'Observed Endpoint'})
                    </div>
                  </div>
                  <span className="px-2 py-0.5 rounded bg-slate-800 border border-slate-700 text-cyan-300 text-[10px] font-mono flex-shrink-0">
                    {selectedNode.scope === 'local'
                      ? 'Client / Local'
                      : selectedNode.scope === 'remote'
                      ? 'Remote'
                      : selectedNode.scope}
                  </span>
                </div>

                {/* Key-Value Telemetry List matching Reference Image */}
                <div className="space-y-1.5 text-xs font-mono px-0.5">
                  <div className="flex items-center justify-between py-1 border-b border-slate-800/60">
                    <span className="text-slate-400 flex items-center gap-1.5">
                      <Activity className="w-3.5 h-3.5 text-slate-500" /> Packets
                    </span>
                    <span className="text-slate-100 font-bold">
                      {selectedNode.packets.toLocaleString()}
                    </span>
                  </div>
                  <div className="flex items-center justify-between py-1 border-b border-slate-800/60">
                    <span className="text-slate-400 flex items-center gap-1.5">
                      <HardDrive className="w-3.5 h-3.5 text-slate-500" /> Bytes
                    </span>
                    <span className="text-cyan-400 font-bold">
                      {formatBytes(selectedNode.bytes)}
                    </span>
                  </div>
                  <div className="flex items-center justify-between py-1 border-b border-slate-800/60">
                    <span className="text-slate-400 flex items-center gap-1.5">
                      <Users className="w-3.5 h-3.5 text-slate-500" /> Distinct peers
                    </span>
                    <span className="text-slate-100 font-bold">
                      {selectedNode.distinct_peers ?? selectedNodePeers.length}
                    </span>
                  </div>
                  <div className="flex items-center justify-between py-1 border-b border-slate-800/60">
                    <span className="text-slate-400 flex items-center gap-1.5">
                      <Clock className="w-3.5 h-3.5 text-slate-500" /> First Seen
                    </span>
                    <span className="text-slate-300 text-[11px]">
                      {formatCaptureTimestamp(selectedNode.first_seen)}
                    </span>
                  </div>
                  <div className="flex items-center justify-between py-1 border-b border-slate-800/60">
                    <span className="text-slate-400 flex items-center gap-1.5">
                      <Calendar className="w-3.5 h-3.5 text-slate-500" /> Last Seen
                    </span>
                    <span className="text-slate-300 text-[11px]">
                      {formatCaptureTimestamp(selectedNode.last_seen)}
                    </span>
                  </div>
                </div>

                {/* MAC & TTL Hop Metadata (when present) */}
                {(selectedNode.macs.length > 0 || selectedNode.hop_estimate) && (
                  <div className="p-2 bg-slate-950/60 border border-slate-800/80 rounded-lg space-y-1 text-[11px] font-mono">
                    {selectedNode.macs.length > 0 && (
                      <div className="flex items-center justify-between gap-2">
                        <span className="text-slate-500">MAC:</span>
                        <span className="text-slate-300 truncate">
                          {selectedNode.macs.join(', ')}
                        </span>
                      </div>
                    )}
                    {selectedNode.hop_estimate && (
                      <div
                        title={selectedNode.hop_estimate.basis}
                        className="flex items-center justify-between gap-2"
                      >
                        <span className="text-slate-500">TTL Hops:</span>
                        <span className="text-amber-300">
                          ~{selectedNode.hop_estimate.hops} hops (TTL{' '}
                          {selectedNode.hop_estimate.observed_ttl}/
                          {selectedNode.hop_estimate.assumed_initial_ttl} • inferred)
                        </span>
                      </div>
                    )}
                  </div>
                )}

                {/* Observed & Inferred Roles */}
                {selectedNode.roles.length > 0 && (
                  <div className="space-y-1.5 text-xs font-mono">
                    <span className="text-[10px] uppercase text-slate-500 block">
                      Endpoint Roles &amp; Basis
                    </span>
                    <div className="space-y-1.5">
                      {selectedNode.roles.map((r, idx) => (
                        <div
                          key={`${r.role}-${idx}`}
                          title={r.basis}
                          className="p-2 bg-slate-950/60 border border-slate-800 rounded-lg flex flex-col gap-0.5"
                        >
                          <div className="flex items-center justify-between gap-2">
                            <span className="text-slate-200 font-semibold">{r.role}</span>
                            {r.inferred ? (
                              <span
                                title={r.basis}
                                className="px-1.5 py-0.5 rounded bg-amber-950/80 text-amber-300 border border-dashed border-amber-600 text-[10px]"
                              >
                                inferred
                              </span>
                            ) : (
                              <span
                                title={r.basis}
                                className="px-1.5 py-0.5 rounded bg-emerald-950/60 text-emerald-300 border border-emerald-800/60 text-[10px]"
                              >
                                observed
                              </span>
                            )}
                          </div>
                          <span className="text-[11px] text-slate-400">{r.basis}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Top Peers with Counts & Percentages matching Reference Image */}
                <div className="space-y-2 text-xs font-mono pt-1 border-t border-slate-800/80">
                  <div className="flex items-center justify-between">
                    <span className="text-[11px] font-semibold text-cyan-400">Top peers</span>
                    <span className="text-[10px] text-slate-500">Packets / Share</span>
                  </div>
                  {selectedNodePeers.length > 0 ? (
                    <div className="space-y-1.5">
                      {selectedNodePeers.slice(0, 5).map((peer, idx) => {
                        const pct = ((peer.packets / totalSelectedNodePeerPackets) * 100).toFixed(
                          1
                        );
                        const dotColors = ['#0ea5e9', '#a855f7', '#10b981', '#f59e0b', '#3b82f6'];
                        return (
                          <button
                            key={peer.peerId}
                            type="button"
                            onClick={() => setSelectedNodeId(peer.peerId)}
                            className="w-full text-left py-1 px-1.5 rounded hover:bg-slate-800/50 transition-colors flex items-center justify-between gap-2 group"
                          >
                            <span className="flex items-center gap-1.5 min-w-0 truncate">
                              <span
                                className="w-2 h-2 rounded-full flex-shrink-0"
                                style={{ backgroundColor: dotColors[idx % dotColors.length] }}
                              />
                              <strong className="text-slate-200 group-hover:text-cyan-300 font-semibold">
                                {peer.peerId}
                              </strong>
                              <span className="text-slate-500 text-[10px] truncate">
                                ({peer.peerClassification})
                              </span>
                            </span>
                            <span className="flex items-center gap-2.5 flex-shrink-0 text-[11px]">
                              <span className="text-slate-200 font-semibold">
                                {peer.packets.toLocaleString()}
                              </span>
                              <span className="text-slate-400 w-11 text-right">{pct}%</span>
                            </span>
                          </button>
                        );
                      })}
                    </div>
                  ) : (
                    <span className="text-slate-500 italic text-[11px] block">
                      Isolated endpoint (no observed peer edges)
                    </span>
                  )}
                </div>

                {/* Related Flows Preview */}
                {selectedEntityFlows.length > 0 && (
                  <div className="space-y-1.5 text-xs font-mono pt-1 border-t border-slate-800/80">
                    <div className="flex items-center justify-between">
                      <span className="text-[11px] font-semibold text-slate-300">
                        Related flows ({selectedEntityFlows.length})
                      </span>
                      <button
                        type="button"
                        onClick={() =>
                          navigate(`/flows?ip=${encodeURIComponent(selectedNode.id)}`)
                        }
                        className="text-[10px] text-cyan-400 hover:underline"
                      >
                        Open all &rarr;
                      </button>
                    </div>
                    <div className="space-y-1 max-h-28 overflow-y-auto pr-1">
                      {selectedEntityFlows.slice(0, 3).map((fl) => (
                        <div
                          key={fl.id}
                          className="p-1.5 bg-slate-950/70 border border-slate-800/80 rounded-lg flex items-center justify-between gap-2 text-[10px]"
                        >
                          <div className="truncate">
                            <span className="text-cyan-300 font-semibold mr-1.5">
                              {fl.protocol}
                            </span>
                            <span className="text-slate-300">
                              {fl.src_ip}:{fl.src_port ?? '*'} &rarr; {fl.dst_ip}:
                              {fl.dst_port ?? '*'}
                            </span>
                          </div>
                          <StatusBadge status={fl.state} type="state" />
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Action Buttons matching Reference Image: View Related Flows & Locate in Packet Explorer */}
                {selectedNode.kind === 'host' && (
                  <div className="grid grid-cols-2 gap-2 pt-1">
                    <button
                      type="button"
                      onClick={() =>
                        navigate(`/flows?ip=${encodeURIComponent(selectedNode.id)}`)
                      }
                      className="px-2.5 py-2 bg-blue-600 hover:bg-blue-500 text-white font-semibold rounded-lg text-xs font-mono flex items-center justify-center gap-1.5 transition-colors shadow-sm"
                    >
                      <span>View Related Flows</span>
                    </button>
                    <button
                      type="button"
                      onClick={() =>
                        navigate(`/packets?ip=${encodeURIComponent(selectedNode.id)}`)
                      }
                      className="px-2.5 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded-lg text-xs font-mono flex items-center justify-center gap-1.5 transition-colors"
                    >
                      <span>View Packets ({selectedNode.packets})</span>
                    </button>
                  </div>
                )}
              </div>
            ) : (
              /* Unselected State for Card 2: Quick Endpoint Selector */
              <div className="p-3.5 bg-slate-900/75 border border-slate-800/90 rounded-xl space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Monitor className="w-4 h-4 text-cyan-400" />
                    <h2 className="text-xs font-bold uppercase tracking-wider text-slate-200 font-mono">
                      Selected Endpoint
                    </h2>
                  </div>
                  <span className="text-[10px] font-mono text-slate-500">Click node on graph</span>
                </div>
                <p className="text-xs text-slate-400 leading-relaxed">
                  Select any endpoint node or connection edge in the topology canvas to inspect its traffic metrics, peers, flows, and packet evidence.
                </p>
                <div className="space-y-1.5 text-xs font-mono max-h-40 overflow-y-auto pr-1">
                  {topology.nodes.slice(0, 6).map((n) => (
                    <button
                      key={n.id}
                      type="button"
                      onClick={() => setSelectedNodeId(n.id)}
                      className="w-full text-left p-2 bg-slate-950/70 hover:bg-slate-800/70 border border-slate-800 rounded-lg flex items-center justify-between gap-2 transition-colors"
                    >
                      <div className="truncate">
                        <span className="text-slate-200 font-semibold">{n.id}</span>
                        <span className="text-[10px] text-slate-500 ml-1.5">
                          ({n.classification || n.scope})
                        </span>
                      </div>
                      <span className="text-cyan-400 text-[11px] font-semibold flex-shrink-0">
                        {formatBytes(n.bytes)}
                      </span>
                    </button>
                  ))}
                </div>
              </div>
            )}

            {/* CARD 3: Related Findings Card matching Reference Image */}
            <div className="p-3.5 bg-slate-900/75 border border-slate-800/90 rounded-xl space-y-2.5 text-xs font-mono">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <ShieldAlert className="w-4 h-4 text-rose-400" />
                  <h2 className="text-xs font-bold uppercase tracking-wider text-slate-200">
                    Related Findings
                  </h2>
                </div>
                {findings.length > 0 && (
                  <button
                    type="button"
                    onClick={() => navigate('/findings')}
                    className="text-[10px] text-cyan-400 hover:underline flex items-center gap-0.5"
                  >
                    <span>All ({findings.length})</span>
                    <ArrowRight className="w-2.5 h-2.5" />
                  </button>
                )}
              </div>

              {displayedFindings.length > 0 ? (
                <div className="space-y-2">
                  {displayedFindings.map((f) => {
                    const isHighlighted = highlightedFindingId === f.id;
                    const firstTs =
                      f.timestamps && f.timestamps.length > 0
                        ? formatCaptureTimestamp(f.timestamps[0]).slice(11)
                        : null;
                    const lastTs =
                      f.timestamps && f.timestamps.length > 1
                        ? formatCaptureTimestamp(f.timestamps[f.timestamps.length - 1]).slice(11)
                        : null;

                    return (
                      <div
                        key={f.id}
                        onClick={() => setHighlightedFindingId(isHighlighted ? null : f.id)}
                        className={`p-2.5 rounded-lg border cursor-pointer transition-colors space-y-1.5 ${
                          isHighlighted
                            ? 'bg-cyan-950/40 border-cyan-500/70'
                            : 'bg-slate-950/80 hover:bg-slate-900 border-slate-800/90'
                        }`}
                      >
                        <div className="flex items-start justify-between gap-2">
                          <div className="flex items-center gap-2 min-w-0">
                            <StatusBadge status={f.severity} type="severity" />
                            <span className="text-slate-100 font-semibold text-xs truncate">
                              {f.title}
                            </span>
                          </div>
                          <button
                            type="button"
                            title="View full diagnostic finding"
                            onClick={(ev) => {
                              ev.stopPropagation();
                              navigate('/findings');
                            }}
                            className="text-slate-500 hover:text-slate-200 p-0.5 flex-shrink-0"
                          >
                            <ChevronRight className="w-3.5 h-3.5" />
                          </button>
                        </div>

                        <p className="text-[11px] text-slate-400 line-clamp-2 font-sans pl-0.5">
                          {f.observed_facts}
                        </p>

                        <div className="flex items-center justify-between text-[10px] text-slate-400 pt-0.5">
                          <span>
                            Packets: {formatPacketRange(f.supporting_packet_numbers)}
                            {firstTs ? ` • ${firstTs}${lastTs ? `–${lastTs}` : ''}` : ''}
                          </span>
                          {f.supporting_packet_numbers.length > 0 && (
                            <button
                              type="button"
                              onClick={(ev) => {
                                ev.stopPropagation();
                                setEvidencePacketNumber(f.supporting_packet_numbers[0]);
                              }}
                              className="text-cyan-400 hover:underline flex items-center gap-0.5"
                            >
                              <span>Frame #{f.supporting_packet_numbers[0]}</span>
                              <ExternalLink className="w-2.5 h-2.5" />
                            </button>
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>
              ) : (
                <div className="p-3 bg-slate-950/60 border border-slate-800/80 rounded-lg text-[11px] text-slate-500 italic">
                  {selectedNode || selectedEdge
                    ? 'No diagnostic findings linked to the selected element.'
                    : 'No diagnostic findings triggered in this capture.'}
                </div>
              )}
            </div>
          </div>
        </div>
      ) : null}

      {/* Packet Evidence Modal */}
      {evidencePacketNumber !== null && (
        <EvidenceModal
          captureId={activeCapture.id}
          packetNumber={evidencePacketNumber}
          onClose={() => setEvidencePacketNumber(null)}
        />
      )}
    </div>
  );
};

export default TopologyPage;
