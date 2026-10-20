import React, { useEffect, useState, useCallback, useMemo } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import { useCapture } from '../../context/CaptureContext';
import { api } from '../../lib/api';
import { PacketItem, PacketListResponse, PacketFacetsResponse } from '../../types';
import { PacketInspector, QuickFilterField } from '../../components/PacketInspector';
import { EmptyState } from '../../components/EmptyState';
import {
  validateDisplayFilter,
  getDisplayFilterSuggestions,
  loadSavedFilters,
  saveFilterItem,
  removeSavedFilter,
  loadRecentFilters,
  pushRecentFilter,
  SavedFilterItem,
} from '../../lib/displayFilter';
import {
  ListFilter,
  Search,
  ChevronLeft,
  ChevronRight,
  ChevronUp,
  ChevronDown,
  RotateCcw,
  UploadCloud,
  Sparkles,
  Plus,
  X,
  Copy,
  Check,
  ArrowLeftRight,
  Palette,
  Terminal,
  SlidersHorizontal,
  Bookmark,
  History,
  Download,
  AlertTriangle,
  CheckCircle2,
  Columns,
  Clock,
  ShieldAlert,
  Lightbulb
} from 'lucide-react';

type BuilderFieldType =
  | 'ip'
  | 'src_ip'
  | 'dst_ip'
  | 'exclude_ip'
  | 'port'
  | 'src_port'
  | 'dst_port'
  | 'protocol'
  | 'tcp_flag'
  | 'min_length'
  | 'max_length'
  | 'packet_number'
  | 'search';

interface PresetFilter {
  id: string;
  label: string;
  expression: string;
  description: string;
  badgeColor: string;
  apply: () => {
    protocol?: string;
    tcpFlag?: string;
    port?: string;
    minLength?: string;
    maxLength?: string;
    displayFilter?: string;
  };
}

const PRESET_FILTERS: PresetFilter[] = [
  {
    id: 'tcp',
    label: 'TCP',
    expression: 'tcp',
    description: 'All TCP segments (tcp)',
    badgeColor: 'border-blue-700/60 bg-blue-950/40 text-blue-300 hover:bg-blue-900/50',
    apply: () => ({ protocol: 'TCP', displayFilter: 'tcp' }),
  },
  {
    id: 'udp',
    label: 'UDP',
    expression: 'udp',
    description: 'All UDP datagrams (udp)',
    badgeColor: 'border-cyan-700/60 bg-cyan-950/40 text-cyan-300 hover:bg-cyan-900/50',
    apply: () => ({ protocol: 'UDP', displayFilter: 'udp' }),
  },
  {
    id: 'dns',
    label: 'DNS Queries & Replies',
    expression: 'dns',
    description: 'Domain name resolution traffic (dns)',
    badgeColor: 'border-purple-700/60 bg-purple-950/40 text-purple-300 hover:bg-purple-900/50',
    apply: () => ({ protocol: 'DNS', displayFilter: 'dns' }),
  },
  {
    id: 'icmp',
    label: 'ICMP / Ping',
    expression: 'icmp',
    description: 'ICMP diagnostic and control messages (icmp)',
    badgeColor: 'border-amber-700/60 bg-amber-950/40 text-amber-300 hover:bg-amber-900/50',
    apply: () => ({ protocol: 'ICMP', displayFilter: 'icmp' }),
  },
  {
    id: 'http',
    label: 'HTTP',
    expression: 'http || tcp.port == 80',
    description: 'HTTP web traffic (http || tcp.port == 80)',
    badgeColor: 'border-teal-700/60 bg-teal-950/40 text-teal-300 hover:bg-teal-900/50',
    apply: () => ({ displayFilter: 'http || tcp.port == 80' }),
  },
  {
    id: 'tls',
    label: 'TLS',
    expression: 'tls || tcp.port == 443',
    description: 'TLS / HTTPS encrypted sessions (tls || tcp.port == 443)',
    badgeColor: 'border-indigo-700/60 bg-indigo-950/40 text-indigo-300 hover:bg-indigo-900/50',
    apply: () => ({ displayFilter: 'tls || tcp.port == 443' }),
  },
  {
    id: 'syn',
    label: 'TCP Handshakes (SYN)',
    expression: 'tcp.flags.syn == 1',
    description: 'Connection initiation packets (tcp.flags.syn == 1)',
    badgeColor: 'border-emerald-700/60 bg-emerald-950/40 text-emerald-300 hover:bg-emerald-900/50',
    apply: () => ({ protocol: 'TCP', tcpFlag: 'SYN', displayFilter: 'tcp.flags.syn == 1' }),
  },
  {
    id: 'rst',
    label: 'TCP Resets (RST)',
    expression: 'tcp.flags.reset == 1',
    description: 'Abrupt connection resets or refused ports (tcp.flags.reset == 1)',
    badgeColor: 'border-rose-700/60 bg-rose-950/40 text-rose-300 hover:bg-rose-900/50',
    apply: () => ({ protocol: 'TCP', tcpFlag: 'RST', displayFilter: 'tcp.flags.reset == 1' }),
  },
];

function getPacketRowTint(pkt: PacketItem, colorize: boolean, isSelected: boolean): string {
  if (isSelected) {
    return 'bg-cyan-950/60 text-cyan-100 border-l-2 border-l-cyan-400';
  }
  if (!colorize) {
    return 'hover:bg-slate-800/60 text-slate-300 border-l-2 border-l-transparent';
  }
  const flags = (pkt.tcp_flags || '').toUpperCase();
  const proto = (pkt.protocol || '').toUpperCase();
  if (flags.includes('RST')) {
    return 'bg-rose-950/25 hover:bg-rose-950/45 text-rose-100 border-l-2 border-l-rose-500/80';
  }
  if (flags.includes('SYN')) {
    return 'bg-emerald-950/20 hover:bg-emerald-950/40 text-emerald-100 border-l-2 border-l-emerald-500/80';
  }
  if (flags.includes('FIN')) {
    return 'bg-amber-950/20 hover:bg-amber-950/35 text-amber-100 border-l-2 border-l-amber-500/70';
  }
  if (proto === 'DNS') {
    return 'bg-purple-950/20 hover:bg-purple-950/40 text-purple-100 border-l-2 border-l-purple-500/70';
  }
  if (proto === 'HTTP') {
    return 'bg-teal-950/25 hover:bg-teal-950/45 text-teal-100 border-l-2 border-l-teal-500/70';
  }
  if (proto === 'ICMP' || proto === 'ARP') {
    return 'bg-amber-950/15 hover:bg-amber-950/35 text-amber-100 border-l-2 border-l-amber-400/70';
  }
  return 'hover:bg-slate-800/60 text-slate-300 border-l-2 border-l-transparent';
}

function formatFlagBadges(tcpFlags: string | null | undefined) {
  if (!tcpFlags) return <span className="text-slate-600">-</span>;
  const parts = tcpFlags
    .split(',')
    .map((f) => f.trim().toUpperCase())
    .filter(Boolean);
  if (parts.length === 0) return <span className="text-slate-600">-</span>;

  return (
    <div className="inline-flex items-center gap-0.5">
      {parts.map((f) => {
        const short = f[0];
        const cls =
          f === 'RST'
            ? 'bg-rose-600/30 text-rose-300 border-rose-500/60'
            : f === 'SYN'
            ? 'bg-blue-600/30 text-blue-300 border-blue-500/60'
            : f === 'ACK'
            ? 'bg-emerald-600/30 text-emerald-300 border-emerald-500/60'
            : f === 'FIN'
            ? 'bg-amber-600/30 text-amber-300 border-amber-500/60'
            : 'bg-purple-600/30 text-purple-300 border-purple-500/60';
        return (
          <span
            key={f}
            title={f}
            className={`px-1 py-0.2 rounded text-[9px] font-bold border ${cls}`}
          >
            {short}
          </span>
        );
      })}
    </div>
  );
}

export const PacketsPage: React.FC = () => {
  const { activeCapture } = useCapture();
  const [searchParams, setSearchParams] = useSearchParams();
  const navigate = useNavigate();

  const [data, setData] = useState<PacketListResponse | null>(null);
  const [facets, setFacets] = useState<PacketFacetsResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [selectedPacket, setSelectedPacket] = useState<PacketItem | null>(null);
  const [selectedPacketNumbers, setSelectedPacketNumbers] = useState<Set<number>>(new Set());
  const [colorizeRows, setColorizeRows] = useState(true);
  const [timeMode, setTimeMode] = useState<'relative' | 'absolute'>('relative');
  const [copiedWireshark, setCopiedWireshark] = useState(false);

  // Pagination & Sorting
  const [page, setPage] = useState<number>(Number(searchParams.get('page')) || 1);
  const [pageSize, setPageSize] = useState<number>(50);
  const [sortBy, setSortBy] = useState<string>('packet_number');
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('asc');

  // Column visibility
  const [showColumnsMenu, setShowColumnsMenu] = useState(false);
  const [visibleCols, setVisibleCols] = useState({
    time: true,
    source: true,
    destination: true,
    protocol: true,
    length: true,
    flags: true,
    info: true,
  });

  // Display Filter Bar state
  const [displayFilterInput, setDisplayFilterInput] = useState<string>(
    searchParams.get('display_filter') || ''
  );
  const [appliedDisplayFilter, setAppliedDisplayFilter] = useState<string>(
    searchParams.get('display_filter') || ''
  );
  const [filterError, setFilterError] = useState<string | null>(null);
  const [showAutocomplete, setShowAutocomplete] = useState(false);
  const [showSavedMenu, setShowSavedMenu] = useState(false);
  const [showRecentMenu, setShowRecentMenu] = useState(false);
  const [savedFilters, setSavedFilters] = useState<SavedFilterItem[]>(() => loadSavedFilters());
  const [recentFilters, setRecentFilters] = useState<string[]>(() => loadRecentFilters());
  const [newSavedName, setNewSavedName] = useState('');

  // Structured filter state (initialized from URL params if deep-linked)
  const [protocolFilter, setProtocolFilter] = useState<string>(searchParams.get('protocol') || '');
  const [ipFilter, setIpFilter] = useState<string>(searchParams.get('ip') || '');
  const [srcIpFilter, setSrcIpFilter] = useState<string>(searchParams.get('src_ip') || '');
  const [dstIpFilter, setDstIpFilter] = useState<string>(searchParams.get('dst_ip') || '');
  const [excludeIpFilter, setExcludeIpFilter] = useState<string>(searchParams.get('exclude_ip') || '');
  const [portFilter, setPortFilter] = useState<string>(searchParams.get('port') || '');
  const [srcPortFilter, setSrcPortFilter] = useState<string>(searchParams.get('src_port') || '');
  const [dstPortFilter, setDstPortFilter] = useState<string>(searchParams.get('dst_port') || '');
  const [flagFilter, setFlagFilter] = useState<string>(searchParams.get('flag') || '');
  const [minLengthFilter, setMinLengthFilter] = useState<string>(searchParams.get('min_length') || '');
  const [maxLengthFilter, setMaxLengthFilter] = useState<string>(searchParams.get('max_length') || '');
  const [packetNumberFilter, setPacketNumberFilter] = useState<string>(
    searchParams.get('packet_number') || ''
  );
  const [peerAFilter, setPeerAFilter] = useState<string>(searchParams.get('peer_a') || '');
  const [peerBFilter, setPeerBFilter] = useState<string>(searchParams.get('peer_b') || '');
  const [search, setSearch] = useState<string>(searchParams.get('search') || '');
  const [searchInput, setSearchInput] = useState<string>(searchParams.get('search') || '');

  // Guided Visual Filter Builder state
  const [builderField, setBuilderField] = useState<BuilderFieldType>('ip');
  const [builderValue, setBuilderValue] = useState<string>('');
  const [showBuilderRow, setShowBuilderRow] = useState<boolean>(false);

  // Live validation of the current displayFilterInput
  const liveValidation = useMemo(
    () => validateDisplayFilter(displayFilterInput),
    [displayFilterInput]
  );

  const autocompleteSuggestions = useMemo(
    () => getDisplayFilterSuggestions(displayFilterInput, facets),
    [displayFilterInput, facets]
  );

  // Sync URL query params when navigated from Overview / Topology / Findings / Global Search
  useEffect(() => {
    const qIp = searchParams.get('ip');
    const qPort = searchParams.get('port');
    const qProto = searchParams.get('protocol');
    const qFlag = searchParams.get('flag');
    const qPkt = searchParams.get('packet_number');
    const qSearch = searchParams.get('search');
    const qDisplay = searchParams.get('display_filter');

    if (qIp !== null) setIpFilter(qIp);
    if (qPort !== null) setPortFilter(qPort);
    if (qProto !== null) setProtocolFilter(qProto);
    if (qFlag !== null) setFlagFilter(qFlag);
    if (qPkt !== null) setPacketNumberFilter(qPkt);
    if (qSearch !== null) {
      setSearch(qSearch);
      setSearchInput(qSearch);
    }
    if (qDisplay !== null) {
      setDisplayFilterInput(qDisplay);
      const v = validateDisplayFilter(qDisplay);
      if (v.valid) {
        setAppliedDisplayFilter(qDisplay);
        setFilterError(null);
      } else {
        setFilterError(v.error || 'Invalid display filter.');
      }
    }
  }, [searchParams]);

  // Fetch capture-level packet facets (protocols, IPs, ports, finding_packets, guided_suggestions)
  useEffect(() => {
    if (!activeCapture || activeCapture.status !== 'completed') {
      setFacets(null);
      return;
    }
    api
      .getPacketFacets(activeCapture.id)
      .then((res) => setFacets(res))
      .catch(() => setFacets(null));
  }, [activeCapture]);

  const fetchPackets = useCallback(async () => {
    if (!activeCapture || activeCapture.status !== 'completed') return;
    setLoading(true);
    try {
      const res = await api.getPackets(activeCapture.id, {
        page,
        page_size: pageSize,
        display_filter: appliedDisplayFilter || undefined,
        protocol: protocolFilter || undefined,
        ip: ipFilter || undefined,
        src_ip: srcIpFilter || undefined,
        dst_ip: dstIpFilter || undefined,
        exclude_ip: excludeIpFilter || undefined,
        port: portFilter ? Number(portFilter) : undefined,
        src_port: srcPortFilter ? Number(srcPortFilter) : undefined,
        dst_port: dstPortFilter ? Number(dstPortFilter) : undefined,
        packet_number: packetNumberFilter ? Number(packetNumberFilter) : undefined,
        tcp_flag: flagFilter || undefined,
        min_length: minLengthFilter ? Number(minLengthFilter) : undefined,
        max_length: maxLengthFilter ? Number(maxLengthFilter) : undefined,
        peer_a: peerAFilter || undefined,
        peer_b: peerBFilter || undefined,
        search: search || undefined,
        sort_by: sortBy,
        sort_dir: sortDir,
      });
      setData(res);
      setFilterError(null);
      if (res.items.length > 0) {
        setSelectedPacket((prev) => {
          if (prev && res.items.some((i) => i.packet_number === prev.packet_number)) {
            return prev;
          }
          return res.items[0];
        });
      } else {
        setSelectedPacket(null);
      }
    } catch (err: any) {
      setFilterError(err?.message || 'Failed to apply packet filter.');
    } finally {
      setLoading(false);
    }
  }, [
    activeCapture,
    page,
    pageSize,
    appliedDisplayFilter,
    protocolFilter,
    ipFilter,
    srcIpFilter,
    dstIpFilter,
    excludeIpFilter,
    portFilter,
    srcPortFilter,
    dstPortFilter,
    packetNumberFilter,
    flagFilter,
    minLengthFilter,
    maxLengthFilter,
    peerAFilter,
    peerBFilter,
    search,
    sortBy,
    sortDir,
  ]);

  useEffect(() => {
    fetchPackets();
  }, [fetchPackets]);

  // Step to previous / next packet in table
  const stepSelectedPacket = useCallback(
    (delta: -1 | 1) => {
      if (!data?.items?.length) return;
      const idx = selectedPacket
        ? data.items.findIndex((p) => p.packet_number === selectedPacket.packet_number)
        : -1;
      const nextIdx = Math.max(0, Math.min(data.items.length - 1, idx + delta));
      setSelectedPacket(data.items[nextIdx]);
    },
    [data, selectedPacket]
  );

  // Keyboard Up / Down arrow navigation across packet table
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      const tag = (e.target as HTMLElement)?.tagName;
      if (tag === 'INPUT' || tag === 'SELECT' || tag === 'TEXTAREA') return;
      if (e.key === 'ArrowDown') {
        e.preventDefault();
        stepSelectedPacket(1);
      } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        stepSelectedPacket(-1);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [stepSelectedPacket]);

  const applyDisplayFilterExpression = (expr: string) => {
    const trimmed = expr.trim();
    setDisplayFilterInput(trimmed);
    setShowAutocomplete(false);
    if (!trimmed) {
      setFilterError(null);
      setAppliedDisplayFilter('');
      setPage(1);
      return;
    }
    const validation = validateDisplayFilter(trimmed);
    if (!validation.valid) {
      setFilterError(validation.error || 'Invalid display filter expression.');
      return;
    }
    setFilterError(null);
    setAppliedDisplayFilter(trimmed);
    setRecentFilters(pushRecentFilter(trimmed));
    setPage(1);
  };

  const handleDisplayFilterSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    applyDisplayFilterExpression(displayFilterInput);
  };

  const handleApplySearch = (e: React.FormEvent) => {
    e.preventDefault();
    setPage(1);
    setSearch(searchInput.trim());
  };

  const handleAddBuilderRule = (e: React.FormEvent) => {
    e.preventDefault();
    const val = builderValue.trim();
    if (!val) return;
    setPage(1);
    switch (builderField) {
      case 'ip':
        setIpFilter(val);
        break;
      case 'src_ip':
        setSrcIpFilter(val);
        break;
      case 'dst_ip':
        setDstIpFilter(val);
        break;
      case 'exclude_ip':
        setExcludeIpFilter(val);
        break;
      case 'port':
        setPortFilter(val.replace(/\D/g, ''));
        break;
      case 'src_port':
        setSrcPortFilter(val.replace(/\D/g, ''));
        break;
      case 'dst_port':
        setDstPortFilter(val.replace(/\D/g, ''));
        break;
      case 'protocol':
        setProtocolFilter(val.toUpperCase());
        break;
      case 'tcp_flag':
        setFlagFilter(val.toUpperCase());
        break;
      case 'min_length':
        setMinLengthFilter(val.replace(/\D/g, ''));
        break;
      case 'max_length':
        setMaxLengthFilter(val.replace(/\D/g, ''));
        break;
      case 'packet_number':
        setPacketNumberFilter(val.replace(/\D/g, ''));
        break;
      case 'search':
        setSearch(val);
        setSearchInput(val);
        break;
    }
    setBuilderValue('');
  };

  const handleQuickFilterFromChild = (field: QuickFilterField, value: string | number) => {
    setPage(1);
    const strVal = String(value);
    if (field === 'display_filter') {
      applyDisplayFilterExpression(strVal);
    } else if (field === 'ip') setIpFilter(strVal);
    else if (field === 'src_ip') setSrcIpFilter(strVal);
    else if (field === 'dst_ip') setDstIpFilter(strVal);
    else if (field === 'exclude_ip') setExcludeIpFilter(strVal);
    else if (field === 'port') setPortFilter(strVal);
    else if (field === 'src_port') setSrcPortFilter(strVal);
    else if (field === 'dst_port') setDstPortFilter(strVal);
    else if (field === 'protocol') setProtocolFilter(strVal);
    else if (field === 'tcp_flag') setFlagFilter(strVal);
    else if (field === 'search') {
      setSearch(strVal);
      setSearchInput(strVal);
    }
  };

  const handleFollowConversation = (peerA: string, peerB: string) => {
    setPage(1);
    setPeerAFilter(peerA);
    setPeerBFilter(peerB);
    const expr = `ip.addr == ${peerA} && ip.addr == ${peerB}`;
    setDisplayFilterInput(expr);
    setAppliedDisplayFilter(expr);
    setFilterError(null);
  };

  const handleApplyPreset = (preset: PresetFilter) => {
    setPage(1);
    setProtocolFilter('');
    setFlagFilter('');
    setPortFilter('');
    setMinLengthFilter('');
    setMaxLengthFilter('');
    const next = preset.apply();
    if (next.protocol) setProtocolFilter(next.protocol);
    if (next.tcpFlag) setFlagFilter(next.tcpFlag);
    if (next.port) setPortFilter(next.port);
    if (next.minLength) setMinLengthFilter(next.minLength);
    if (next.maxLength) setMaxLengthFilter(next.maxLength);
    if (next.displayFilter) {
      setDisplayFilterInput(next.displayFilter);
      setAppliedDisplayFilter(next.displayFilter);
      setFilterError(null);
      setRecentFilters(pushRecentFilter(next.displayFilter));
    }
  };

  const handleResetFilters = () => {
    setDisplayFilterInput('');
    setAppliedDisplayFilter('');
    setFilterError(null);
    setProtocolFilter('');
    setIpFilter('');
    setSrcIpFilter('');
    setDstIpFilter('');
    setExcludeIpFilter('');
    setPortFilter('');
    setSrcPortFilter('');
    setDstPortFilter('');
    setFlagFilter('');
    setMinLengthFilter('');
    setMaxLengthFilter('');
    setPacketNumberFilter('');
    setPeerAFilter('');
    setPeerBFilter('');
    setSearch('');
    setSearchInput('');
    setPage(1);
    setSearchParams({});
  };

  const handleSortColumn = (col: string) => {
    if (sortBy === col) {
      setSortDir((prev) => (prev === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortBy(col);
      setSortDir('asc');
    }
    setPage(1);
  };

  const toggleSelectPacketCheckbox = (pktNum: number) => {
    setSelectedPacketNumbers((prev) => {
      const next = new Set(prev);
      if (next.has(pktNum)) next.delete(pktNum);
      else next.add(pktNum);
      return next;
    });
  };

  const toggleSelectAllOnPage = () => {
    if (!data?.items?.length) return;
    const allNums = data.items.map((p) => p.packet_number);
    const allSelected = allNums.every((n) => selectedPacketNumbers.has(n));
    setSelectedPacketNumbers((prev) => {
      const next = new Set(prev);
      if (allSelected) {
        allNums.forEach((n) => next.delete(n));
      } else {
        allNums.forEach((n) => next.add(n));
      }
      return next;
    });
  };

  // Compute live Wireshark Display Filter equivalent combining display_filter + structured filters
  const wiresharkExpression = useMemo(() => {
    const parts: string[] = [];
    if (appliedDisplayFilter) parts.push(appliedDisplayFilter);
    if (protocolFilter && !appliedDisplayFilter.toLowerCase().includes(protocolFilter.toLowerCase())) {
      parts.push(protocolFilter.toLowerCase());
    }
    if (ipFilter) parts.push(`ip.addr == ${ipFilter}`);
    if (srcIpFilter) parts.push(`ip.src == ${srcIpFilter}`);
    if (dstIpFilter) parts.push(`ip.dst == ${dstIpFilter}`);
    if (excludeIpFilter) parts.push(`ip.addr != ${excludeIpFilter}`);
    if (peerAFilter && peerBFilter && !appliedDisplayFilter.includes(peerAFilter)) {
      parts.push(`(ip.addr == ${peerAFilter} && ip.addr == ${peerBFilter})`);
    }
    if (portFilter) parts.push(`tcp.port == ${portFilter} || udp.port == ${portFilter}`);
    if (srcPortFilter) parts.push(`tcp.srcport == ${srcPortFilter}`);
    if (dstPortFilter) parts.push(`tcp.dstport == ${dstPortFilter}`);
    if (flagFilter && !appliedDisplayFilter.includes('tcp.flags')) {
      const fMap: Record<string, string> = {
        SYN: 'tcp.flags.syn == 1',
        RST: 'tcp.flags.reset == 1',
        ACK: 'tcp.flags.ack == 1',
        FIN: 'tcp.flags.fin == 1',
        PSH: 'tcp.flags.push == 1',
      };
      parts.push(fMap[flagFilter.toUpperCase()] || `tcp.flags contains "${flagFilter}"`);
    }
    if (minLengthFilter) parts.push(`frame.len >= ${minLengthFilter}`);
    if (maxLengthFilter) parts.push(`frame.len <= ${maxLengthFilter}`);
    if (packetNumberFilter) parts.push(`frame.number == ${packetNumberFilter}`);
    if (search) parts.push(`frame contains "${search}"`);
    return parts.join(' && ');
  }, [
    appliedDisplayFilter,
    protocolFilter,
    ipFilter,
    srcIpFilter,
    dstIpFilter,
    excludeIpFilter,
    peerAFilter,
    peerBFilter,
    portFilter,
    srcPortFilter,
    dstPortFilter,
    flagFilter,
    minLengthFilter,
    maxLengthFilter,
    packetNumberFilter,
    search,
  ]);

  // Active visual filter chips
  const activeChips = useMemo(() => {
    const chips: Array<{ id: string; label: string; value: string; onClear: () => void }> = [];
    if (appliedDisplayFilter) {
      chips.push({
        id: 'display_filter',
        label: 'Display Filter',
        value: appliedDisplayFilter,
        onClear: () => {
          setDisplayFilterInput('');
          setAppliedDisplayFilter('');
          setFilterError(null);
        },
      });
    }
    if (protocolFilter) {
      chips.push({
        id: 'proto',
        label: 'Protocol',
        value: protocolFilter,
        onClear: () => setProtocolFilter(''),
      });
    }
    if (ipFilter) {
      chips.push({
        id: 'ip',
        label: 'Any IP',
        value: ipFilter,
        onClear: () => setIpFilter(''),
      });
    }
    if (srcIpFilter) {
      chips.push({
        id: 'src_ip',
        label: 'Source IP',
        value: srcIpFilter,
        onClear: () => setSrcIpFilter(''),
      });
    }
    if (dstIpFilter) {
      chips.push({
        id: 'dst_ip',
        label: 'Dest IP',
        value: dstIpFilter,
        onClear: () => setDstIpFilter(''),
      });
    }
    if (excludeIpFilter) {
      chips.push({
        id: 'exclude_ip',
        label: 'Exclude IP',
        value: `!= ${excludeIpFilter}`,
        onClear: () => setExcludeIpFilter(''),
      });
    }
    if (peerAFilter && peerBFilter) {
      chips.push({
        id: 'stream',
        label: 'Conversation Stream',
        value: `${peerAFilter} ⇄ ${peerBFilter}`,
        onClear: () => {
          setPeerAFilter('');
          setPeerBFilter('');
        },
      });
    }
    if (portFilter) {
      chips.push({
        id: 'port',
        label: 'Any Port',
        value: portFilter,
        onClear: () => setPortFilter(''),
      });
    }
    if (srcPortFilter) {
      chips.push({
        id: 'src_port',
        label: 'Source Port',
        value: srcPortFilter,
        onClear: () => setSrcPortFilter(''),
      });
    }
    if (dstPortFilter) {
      chips.push({
        id: 'dst_port',
        label: 'Dest Port',
        value: dstPortFilter,
        onClear: () => setDstPortFilter(''),
      });
    }
    if (flagFilter) {
      chips.push({
        id: 'flag',
        label: 'TCP Flag',
        value: flagFilter,
        onClear: () => setFlagFilter(''),
      });
    }
    if (minLengthFilter) {
      chips.push({
        id: 'min_len',
        label: 'Min Size',
        value: `≥ ${minLengthFilter} B`,
        onClear: () => setMinLengthFilter(''),
      });
    }
    if (maxLengthFilter) {
      chips.push({
        id: 'max_len',
        label: 'Max Size',
        value: `≤ ${maxLengthFilter} B`,
        onClear: () => setMaxLengthFilter(''),
      });
    }
    if (packetNumberFilter) {
      chips.push({
        id: 'pkt_num',
        label: 'Frame #',
        value: `#${packetNumberFilter}`,
        onClear: () => setPacketNumberFilter(''),
      });
    }
    if (search) {
      chips.push({
        id: 'search',
        label: 'Text Search',
        value: `"${search}"`,
        onClear: () => {
          setSearch('');
          setSearchInput('');
        },
      });
    }
    return chips;
  }, [
    appliedDisplayFilter,
    protocolFilter,
    ipFilter,
    srcIpFilter,
    dstIpFilter,
    excludeIpFilter,
    peerAFilter,
    peerBFilter,
    portFilter,
    srcPortFilter,
    dstPortFilter,
    flagFilter,
    minLengthFilter,
    maxLengthFilter,
    packetNumberFilter,
    search,
  ]);

  const handleCopyWireshark = () => {
    if (!wiresharkExpression) return;
    navigator.clipboard.writeText(wiresharkExpression);
    setCopiedWireshark(true);
    setTimeout(() => setCopiedWireshark(false), 2000);
  };

  const handleSaveCurrentFilter = (e: React.FormEvent) => {
    e.preventDefault();
    const exprToSave = displayFilterInput.trim() || wiresharkExpression;
    if (!exprToSave) return;
    const name = newSavedName.trim() || exprToSave.slice(0, 28);
    setSavedFilters(saveFilterItem(name, exprToSave));
    setNewSavedName('');
  };

  if (!activeCapture) {
    return (
      <div className="p-8 max-w-4xl mx-auto">
        <EmptyState
          title="No Capture Selected"
          description="Select or upload a packet capture to inspect individual frames and protocol headers."
          icon={UploadCloud}
          actionText="Go to Captures"
          onAction={() => navigate('/captures')}
        />
      </div>
    );
  }

  const selectedArray = Array.from(selectedPacketNumbers);
  const csvExportUrl = api.getPacketsExportUrl(activeCapture.id, {
    format: 'csv',
    display_filter: appliedDisplayFilter || undefined,
    protocol: protocolFilter || undefined,
    ip: ipFilter || undefined,
    src_ip: srcIpFilter || undefined,
    dst_ip: dstIpFilter || undefined,
    exclude_ip: excludeIpFilter || undefined,
    port: portFilter ? Number(portFilter) : undefined,
    tcp_flag: flagFilter || undefined,
    search: search || undefined,
    packet_numbers: selectedArray.length > 0 ? selectedArray : undefined,
  });
  const jsonExportUrl = api.getPacketsExportUrl(activeCapture.id, {
    format: 'json',
    display_filter: appliedDisplayFilter || undefined,
    protocol: protocolFilter || undefined,
    ip: ipFilter || undefined,
    src_ip: srcIpFilter || undefined,
    dst_ip: dstIpFilter || undefined,
    exclude_ip: excludeIpFilter || undefined,
    port: portFilter ? Number(portFilter) : undefined,
    tcp_flag: flagFilter || undefined,
    search: search || undefined,
    packet_numbers: selectedArray.length > 0 ? selectedArray : undefined,
  });

  const selectedPacketFindings =
    (selectedPacket && facets?.finding_packets?.[String(selectedPacket.packet_number)]) || [];

  return (
    <div className="p-4 lg:p-5 h-[calc(100vh-4rem)] flex flex-col gap-3 max-w-[1800px] mx-auto overflow-hidden">
      {/* Top Filter & Investigation Toolbar */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-3 shadow-md space-y-2.5 flex-shrink-0">
        {/* Row 1: Title + Live Match Count + Prev/Next Match + Export & View Controls */}
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2.5">
            <ListFilter className="w-5 h-5 text-cyan-400 flex-shrink-0" />
            <div className="flex items-center gap-2 flex-wrap">
              <h1 className="text-base font-bold text-slate-100">Packet Explorer</h1>
              <span className="text-xs font-mono text-slate-400">
                {activeCapture.original_filename}
              </span>
              <span
                data-testid="packet-match-count"
                className={`text-[11px] font-mono px-2 py-0.5 rounded border ${
                  filterError
                    ? 'bg-rose-950/60 text-rose-300 border-rose-700/70'
                    : 'bg-slate-800 text-cyan-400 border-slate-700'
                }`}
              >
                {filterError
                  ? 'Invalid Filter'
                  : data
                  ? `${data.total.toLocaleString()} / ${activeCapture.packet_count.toLocaleString()} packets`
                  : 'Loading...'}
              </span>
            </div>
          </div>

          {/* Right Toolbar Actions: Prev/Next Match, Time Format, Columns, Colors, Export */}
          <div className="flex items-center gap-1.5 flex-wrap">
            {/* Prev / Next Matching Packet */}
            <div className="flex items-center bg-slate-950 border border-slate-800 rounded-lg overflow-hidden text-[11px] font-mono">
              <button
                type="button"
                onClick={() => stepSelectedPacket(-1)}
                disabled={!data?.items?.length}
                className="px-2 py-1 text-slate-300 hover:bg-slate-800 disabled:opacity-40 flex items-center gap-1"
                title="Previous matching packet (ArrowUp)"
              >
                <ChevronUp className="w-3.5 h-3.5" />
                <span className="hidden sm:inline">Prev</span>
              </button>
              <button
                type="button"
                onClick={() => stepSelectedPacket(1)}
                disabled={!data?.items?.length}
                className="px-2 py-1 text-slate-300 hover:bg-slate-800 border-l border-slate-800 disabled:opacity-40 flex items-center gap-1"
                title="Next matching packet (ArrowDown)"
              >
                <ChevronDown className="w-3.5 h-3.5" />
                <span className="hidden sm:inline">Next</span>
              </button>
            </div>

            {/* Relative vs Absolute Time Toggle */}
            <button
              type="button"
              onClick={() => setTimeMode((m) => (m === 'relative' ? 'absolute' : 'relative'))}
              className="px-2 py-1 bg-slate-950 hover:bg-slate-800 border border-slate-800 rounded-lg text-[11px] font-mono text-slate-300 flex items-center gap-1"
              title="Toggle Relative (+0.000s) vs Absolute (HH:MM:SS.mmm) timestamp column"
            >
              <Clock className="w-3.5 h-3.5 text-cyan-400" />
              <span>{timeMode === 'relative' ? 'Rel Time' : 'UTC Time'}</span>
            </button>

            {/* Column Visibility Menu */}
            <div className="relative">
              <button
                type="button"
                onClick={() => setShowColumnsMenu((v) => !v)}
                className="px-2 py-1 bg-slate-950 hover:bg-slate-800 border border-slate-800 rounded-lg text-[11px] font-mono text-slate-300 flex items-center gap-1"
                title="Configure visible packet columns"
              >
                <Columns className="w-3.5 h-3.5 text-cyan-400" />
                <span className="hidden sm:inline">Columns</span>
              </button>
              {showColumnsMenu && (
                <div className="absolute right-0 mt-1 w-44 bg-slate-950 border border-slate-700 rounded-lg shadow-xl p-2 z-30 space-y-1 text-xs font-mono">
                  {Object.entries(visibleCols).map(([colKey, isVis]) => (
                    <label
                      key={colKey}
                      className="flex items-center justify-between px-2 py-1 hover:bg-slate-900 rounded cursor-pointer text-slate-200"
                    >
                      <span className="capitalize">{colKey}</span>
                      <input
                        type="checkbox"
                        checked={isVis}
                        onChange={() =>
                          setVisibleCols((prev) => ({
                            ...prev,
                            [colKey]: !prev[colKey as keyof typeof prev],
                          }))
                        }
                        className="accent-cyan-500"
                      />
                    </label>
                  ))}
                </div>
              )}
            </div>

            {/* Colorize Rows Toggle */}
            <button
              type="button"
              onClick={() => setColorizeRows((prev) => !prev)}
              className={`px-2 py-1 border rounded-lg text-[11px] font-mono flex items-center gap-1 transition-colors ${
                colorizeRows
                  ? 'bg-cyan-950/60 border-cyan-700/70 text-cyan-300'
                  : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-slate-200'
              }`}
              title="Toggle Wireshark-style packet row color coding"
            >
              <Palette className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">Colors</span>
            </button>

            {/* Export CSV / JSON */}
            <a
              href={csvExportUrl}
              download
              className="px-2 py-1 bg-slate-950 hover:bg-slate-800 border border-slate-800 rounded-lg text-[11px] font-mono text-slate-200 flex items-center gap-1"
              title={
                selectedArray.length > 0
                  ? `Export ${selectedArray.length} selected packet(s) to CSV`
                  : 'Export filtered packets to CSV'
              }
            >
              <Download className="w-3 h-3 text-cyan-400" />
              <span>{selectedArray.length > 0 ? `CSV (${selectedArray.length})` : 'CSV'}</span>
            </a>
            <a
              href={jsonExportUrl}
              download
              className="px-2 py-1 bg-slate-950 hover:bg-slate-800 border border-slate-800 rounded-lg text-[11px] font-mono text-slate-200 flex items-center gap-1"
              title={
                selectedArray.length > 0
                  ? `Export ${selectedArray.length} selected packet(s) to JSON`
                  : 'Export filtered packets to JSON'
              }
            >
              <Download className="w-3 h-3 text-emerald-400" />
              <span>JSON</span>
            </a>
          </div>
        </div>

        {/* Row 2: Display-Filter Engine Bar (with Syntax Validation, Autocomplete, Saved & Recent Filters) */}
        <div className="flex flex-col lg:flex-row items-stretch lg:items-center gap-2">
          <form onSubmit={handleDisplayFilterSubmit} className="relative flex-1 flex items-center gap-1.5">
            <div className="relative flex-1">
              <Terminal
                className={`w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 ${
                  !displayFilterInput.trim()
                    ? 'text-slate-500'
                    : liveValidation.valid
                    ? 'text-emerald-400'
                    : 'text-rose-400'
                }`}
              />
              <input
                type="text"
                aria-label="Display Filter Expression"
                placeholder="Display filter (e.g. ip.addr == 192.168.1.10 && tcp, dns || tcp.port == 443, !(arp), frame.len > 100)..."
                value={displayFilterInput}
                onFocus={() => setShowAutocomplete(true)}
                onBlur={() => setTimeout(() => setShowAutocomplete(false), 180)}
                onChange={(e) => {
                  setDisplayFilterInput(e.target.value);
                  setShowAutocomplete(true);
                }}
                className={`w-full pl-8 pr-20 py-1.5 bg-slate-950 border rounded-lg text-xs font-mono text-slate-100 placeholder-slate-500 focus:outline-none transition-colors ${
                  !displayFilterInput.trim()
                    ? 'border-slate-800 focus:border-cyan-500'
                    : liveValidation.valid
                    ? 'border-emerald-700/80 focus:border-emerald-500'
                    : 'border-rose-600/80 focus:border-rose-500'
                }`}
              />
              {displayFilterInput && (
                <div className="absolute right-2.5 top-1/2 -translate-y-1/2 flex items-center gap-1">
                  {liveValidation.valid ? (
                    <span className="text-[10px] font-mono text-emerald-400 flex items-center gap-0.5">
                      <CheckCircle2 className="w-3 h-3" /> Valid
                    </span>
                  ) : (
                    <span className="text-[10px] font-mono text-rose-400 flex items-center gap-0.5">
                      <AlertTriangle className="w-3 h-3" /> Syntax
                    </span>
                  )}
                  <button
                    type="button"
                    onClick={() => applyDisplayFilterExpression('')}
                    className="text-slate-500 hover:text-slate-200 ml-1"
                    title="Clear display filter"
                  >
                    <X className="w-3.5 h-3.5" />
                  </button>
                </div>
              )}

              {/* Autocomplete Suggestions Popover */}
              {showAutocomplete && autocompleteSuggestions.length > 0 && (
                <div className="absolute left-0 right-0 mt-1 bg-slate-950 border border-slate-700 rounded-lg shadow-2xl z-30 max-h-56 overflow-y-auto divide-y divide-slate-800/60">
                  {autocompleteSuggestions.map((sug) => (
                    <button
                      key={`${sug.category}-${sug.label}`}
                      type="button"
                      onMouseDown={(e) => {
                        e.preventDefault();
                        setDisplayFilterInput(sug.insertText);
                      }}
                      className="w-full px-3 py-1.5 text-left hover:bg-slate-900 flex items-center justify-between gap-2 text-xs font-mono"
                    >
                      <div className="flex items-center gap-2">
                        <span className="px-1.5 py-0.2 rounded bg-slate-800 text-cyan-300 text-[9px] uppercase">
                          {sug.category}
                        </span>
                        <span className="text-slate-100 font-semibold">{sug.label}</span>
                      </div>
                      <span className="text-[11px] text-slate-400 truncate">{sug.description}</span>
                    </button>
                  ))}
                </div>
              )}
            </div>

            <button
              type="submit"
              className="px-3 py-1.5 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold rounded-lg text-xs font-mono transition-colors flex-shrink-0"
            >
              Apply Filter
            </button>

            {/* Saved Filters Dropdown */}
            <div className="relative">
              <button
                type="button"
                onClick={() => {
                  setShowSavedMenu((v) => !v);
                  setShowRecentMenu(false);
                }}
                className="px-2.5 py-1.5 bg-slate-950 hover:bg-slate-800 border border-slate-800 rounded-lg text-xs font-mono text-slate-300 flex items-center gap-1"
                title="Saved Display Filters"
              >
                <Bookmark className="w-3.5 h-3.5 text-cyan-400" />
                <span className="hidden sm:inline">Saved</span>
              </button>
              {showSavedMenu && (
                <div className="absolute right-0 mt-1 w-80 bg-slate-950 border border-slate-700 rounded-xl shadow-2xl p-3 z-30 space-y-2.5 text-xs font-mono">
                  <div className="text-[10px] uppercase tracking-wider text-slate-400 font-semibold">
                    Saved Display Filters
                  </div>
                  <div className="max-h-44 overflow-y-auto space-y-1">
                    {savedFilters.map((sf) => (
                      <div
                        key={sf.name}
                        className="flex items-center justify-between gap-2 px-2 py-1.5 rounded bg-slate-900/80 hover:bg-slate-800 border border-slate-800"
                      >
                        <button
                          type="button"
                          onClick={() => {
                            applyDisplayFilterExpression(sf.expression);
                            setShowSavedMenu(false);
                          }}
                          className="text-left flex-1 truncate"
                        >
                          <div className="text-slate-200 font-semibold truncate">{sf.name}</div>
                          <div className="text-[10px] text-cyan-400 truncate">{sf.expression}</div>
                        </button>
                        <button
                          type="button"
                          onClick={() => setSavedFilters(removeSavedFilter(sf.name))}
                          className="text-slate-500 hover:text-rose-400 p-1"
                          title="Delete saved filter"
                        >
                          <X className="w-3 h-3" />
                        </button>
                      </div>
                    ))}
                  </div>
                  <div className="pt-2 border-t border-slate-800 flex items-center gap-1.5">
                    <input
                      type="text"
                      value={newSavedName}
                      onChange={(e) => setNewSavedName(e.target.value)}
                      placeholder="Filter name..."
                      className="flex-1 px-2 py-1 bg-slate-900 border border-slate-700 rounded text-[11px] text-slate-200"
                    />
                    <button
                      type="button"
                      onClick={handleSaveCurrentFilter}
                      className="px-2 py-1 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-semibold rounded text-[11px]"
                    >
                      Save Current
                    </button>
                  </div>
                </div>
              )}
            </div>

            {/* Recent Filters Dropdown */}
            <div className="relative">
              <button
                type="button"
                onClick={() => {
                  setShowRecentMenu((v) => !v);
                  setShowSavedMenu(false);
                }}
                className="px-2.5 py-1.5 bg-slate-950 hover:bg-slate-800 border border-slate-800 rounded-lg text-xs font-mono text-slate-300 flex items-center gap-1"
                title="Recent Display Filters"
              >
                <History className="w-3.5 h-3.5 text-cyan-400" />
              </button>
              {showRecentMenu && (
                <div className="absolute right-0 mt-1 w-72 bg-slate-950 border border-slate-700 rounded-xl shadow-2xl p-2.5 z-30 space-y-1.5 text-xs font-mono">
                  <div className="text-[10px] uppercase tracking-wider text-slate-400 px-1">
                    Recent Filter History
                  </div>
                  {recentFilters.length === 0 ? (
                    <div className="text-slate-500 px-2 py-2 text-[11px]">No recent filters yet.</div>
                  ) : (
                    recentFilters.map((rf) => (
                      <button
                        key={rf}
                        type="button"
                        onClick={() => {
                          applyDisplayFilterExpression(rf);
                          setShowRecentMenu(false);
                        }}
                        className="w-full text-left px-2 py-1.5 rounded hover:bg-slate-900 text-cyan-300 truncate block"
                      >
                        {rf}
                      </button>
                    ))
                  )}
                </div>
              )}
            </div>
          </form>

          {/* Separate Free-Text Search + Structured Inputs */}
          <form onSubmit={handleApplySearch} className="flex flex-wrap items-center gap-1.5">
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                placeholder="Text search (info, domain)..."
                value={searchInput}
                onChange={(e) => setSearchInput(e.target.value)}
                className="pl-8 pr-2.5 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 w-44 font-mono"
              />
            </div>

            <select
              aria-label="Protocol Filter"
              value={protocolFilter}
              onChange={(e) => {
                setProtocolFilter(e.target.value);
                setPage(1);
              }}
              className="px-2 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
            >
              <option value="">All Protocols</option>
              {facets?.protocols && facets.protocols.length > 0 ? (
                facets.protocols.map((p) => (
                  <option key={p.value} value={p.value}>
                    {p.value} ({p.count})
                  </option>
                ))
              ) : (
                <>
                  <option value="TCP">TCP</option>
                  <option value="UDP">UDP</option>
                  <option value="DNS">DNS</option>
                  <option value="HTTP">HTTP</option>
                  <option value="ICMP">ICMP</option>
                  <option value="ARP">ARP</option>
                </>
              )}
            </select>

            <input
              type="text"
              list="capture-ips-datalist"
              placeholder="IP (e.g. 192.168.1.1)"
              value={ipFilter}
              onChange={(e) => {
                setIpFilter(e.target.value);
                setPage(1);
              }}
              className="px-2.5 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 w-36"
            />
            <datalist id="capture-ips-datalist">
              {facets?.ips?.map((ipItem) => (
                <option key={ipItem.value} value={ipItem.value}>
                  {ipItem.value} ({ipItem.count} pkts)
                </option>
              ))}
            </datalist>

            <input
              type="number"
              list="capture-ports-datalist"
              placeholder="Port (e.g. 80)"
              value={portFilter}
              onChange={(e) => {
                setPortFilter(e.target.value);
                setPage(1);
              }}
              className="px-2 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 w-24"
            />
            <datalist id="capture-ports-datalist">
              {facets?.ports?.map((pItem) => (
                <option key={pItem.port} value={pItem.port}>
                  Port {pItem.port} — {pItem.service} ({pItem.count} pkts)
                </option>
              ))}
            </datalist>

            <button
              type="button"
              onClick={() => setShowBuilderRow((v) => !v)}
              className={`px-2 py-1.5 border rounded-lg text-xs font-mono flex items-center gap-1 transition-colors ${
                showBuilderRow
                  ? 'bg-cyan-950/60 border-cyan-700 text-cyan-300'
                  : 'bg-slate-950 border-slate-800 text-slate-300 hover:text-slate-100'
              }`}
              title="Toggle Visual Filter Builder & Guided Suggestions"
            >
              <SlidersHorizontal className="w-3.5 h-3.5 text-cyan-400" />
              <span>Builder</span>
            </button>

            {activeChips.length > 0 && (
              <button
                type="button"
                onClick={handleResetFilters}
                className="p-1.5 text-slate-400 hover:text-slate-100 bg-slate-800 hover:bg-slate-700 rounded-lg transition-colors"
                title="Clear all filters"
              >
                <RotateCcw className="w-4 h-4" />
              </button>
            )}
          </form>
        </div>

        {/* Display Filter Error Banner (never silently ignore an invalid filter!) */}
        {filterError && (
          <div
            role="alert"
            className="px-3 py-2 rounded-lg bg-rose-950/50 border border-rose-700/80 text-rose-200 text-xs font-mono flex items-center justify-between gap-2"
          >
            <div className="flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-rose-400 flex-shrink-0" />
              <span>{filterError}</span>
            </div>
            <button
              type="button"
              onClick={() => setFilterError(null)}
              className="text-rose-300 hover:text-white"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
        )}

        {/* Row 3: Quick Filters + Selected Endpoint Quick Filter + Guided Troubleshooting Suggestions */}
        <div className="pt-2 border-t border-slate-800/80 flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-1.5 flex-wrap">
            <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400 flex items-center gap-1 mr-1">
              <Sparkles className="w-3 h-3 text-cyan-400" />
              Quick Filters:
            </span>
            {PRESET_FILTERS.map((preset) => (
              <button
                key={preset.id}
                type="button"
                onClick={() => handleApplyPreset(preset)}
                title={preset.description}
                className={`px-2 py-0.5 rounded-md border text-[11px] font-mono transition-colors ${preset.badgeColor}`}
              >
                {preset.label}
              </button>
            ))}
            {selectedPacket?.src_ip && selectedPacket.src_ip !== 'unknown' && (
              <button
                type="button"
                onClick={() => applyDisplayFilterExpression(`ip.addr == ${selectedPacket.src_ip}`)}
                className="px-2 py-0.5 rounded-md border border-cyan-700/70 bg-cyan-950/40 text-cyan-300 hover:bg-cyan-900/50 text-[11px] font-mono"
                title={`Filter traffic involving selected host ${selectedPacket.src_ip}`}
              >
                Host: {selectedPacket.src_ip}
              </button>
            )}
          </div>

          {/* Evidence-Backed Guided Troubleshooting Suggestions */}
          {facets?.guided_suggestions && facets.guided_suggestions.length > 0 && (
            <div className="flex items-center gap-1.5 flex-wrap">
              <span className="text-[10px] font-mono uppercase tracking-wider text-amber-400/90 flex items-center gap-1">
                <Lightbulb className="w-3 h-3" />
                Guided Next Steps:
              </span>
              {facets.guided_suggestions.slice(0, 3).map((sug, idx) => (
                <button
                  key={idx}
                  type="button"
                  onClick={() => applyDisplayFilterExpression(sug.filter)}
                  title={`${sug.reason} (${sug.filter})`}
                  className="px-2 py-0.5 rounded bg-amber-950/30 hover:bg-amber-900/40 border border-amber-700/50 text-[10px] font-mono text-amber-200 transition-colors"
                >
                  {sug.label}
                </button>
              ))}
            </div>
          )}
        </div>

        {/* Optional Expandable Visual Rule Builder Row */}
        {showBuilderRow && (
          <form
            onSubmit={handleAddBuilderRule}
            className="pt-2 border-t border-slate-800/80 flex items-center gap-2 flex-wrap"
          >
            <span className="text-[10px] font-mono uppercase tracking-wider text-cyan-400 flex items-center gap-1">
              <SlidersHorizontal className="w-3 h-3" />
              Visual Filter Builder:
            </span>
            <select
              aria-label="Filter Builder Field"
              value={builderField}
              onChange={(e) => {
                setBuilderField(e.target.value as BuilderFieldType);
                setBuilderValue('');
              }}
              className="px-2 py-1 bg-slate-950 border border-slate-800 rounded text-[11px] font-mono text-cyan-300"
            >
              <option value="ip">Any IP (Src or Dst)</option>
              <option value="src_ip">Source IP Only (ip.src)</option>
              <option value="dst_ip">Destination IP Only (ip.dst)</option>
              <option value="exclude_ip">Exclude IP (ip.addr !=)</option>
              <option value="port">Any Port (Src or Dst)</option>
              <option value="src_port">Source Port Only</option>
              <option value="dst_port">Destination Port Only</option>
              <option value="protocol">Protocol</option>
              <option value="tcp_flag">TCP Flag</option>
              <option value="min_length">Min Packet Size (Bytes)</option>
              <option value="max_length">Max Packet Size (Bytes)</option>
              <option value="packet_number">Frame Number (#)</option>
              <option value="search">Payload / Info Text</option>
            </select>

            <input
              type="text"
              list={
                builderField.includes('ip')
                  ? 'capture-ips-datalist'
                  : builderField.includes('port')
                  ? 'capture-ports-datalist'
                  : undefined
              }
              value={builderValue}
              onChange={(e) => setBuilderValue(e.target.value)}
              placeholder="Enter or pick observed value..."
              className="px-2.5 py-1 bg-slate-950 border border-slate-800 rounded text-[11px] font-mono text-slate-200 w-48"
            />

            <button
              type="submit"
              className="px-2.5 py-1 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-semibold rounded text-[11px] font-mono flex items-center gap-1"
            >
              <Plus className="w-3 h-3" />
              <span>Add Condition</span>
            </button>
          </form>
        )}

        {/* Active Filter Chips + Equivalent Display Filter Preview */}
        {activeChips.length > 0 && (
          <div className="pt-2 border-t border-slate-800/80 flex flex-col md:flex-row md:items-center justify-between gap-2">
            <div className="flex items-center gap-1.5 flex-wrap">
              <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400 mr-1">
                Active Filters:
              </span>
              {activeChips.map((chip) => (
                <span
                  key={chip.id}
                  className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md bg-cyan-950/60 border border-cyan-800/80 text-[11px] font-mono text-cyan-200"
                >
                  <span className="text-slate-400">{chip.label}:</span>
                  <span className="font-semibold text-cyan-300">{chip.value}</span>
                  <button
                    type="button"
                    onClick={chip.onClear}
                    className="text-slate-400 hover:text-rose-400 transition-colors"
                    title={`Remove ${chip.label} filter`}
                  >
                    <X className="w-3 h-3" />
                  </button>
                </span>
              ))}
              <button
                type="button"
                onClick={handleResetFilters}
                className="text-[11px] font-mono text-rose-400 hover:text-rose-300 underline ml-1"
              >
                Clear All
              </button>
            </div>

            {wiresharkExpression && (
              <div className="flex items-center gap-2 bg-slate-950/90 border border-slate-800 px-2.5 py-1 rounded-lg">
                <Terminal className="w-3.5 h-3.5 text-emerald-400 flex-shrink-0" />
                <span className="text-[10px] font-mono uppercase text-slate-500">Wireshark syntax:</span>
                <code
                  data-testid="wireshark-filter-preview"
                  className="text-[11px] font-mono text-emerald-300 select-all"
                >
                  {wiresharkExpression}
                </code>
                <button
                  type="button"
                  onClick={handleCopyWireshark}
                  className="p-1 text-slate-400 hover:text-slate-200 rounded transition-colors"
                  title="Copy equivalent Wireshark display filter"
                >
                  {copiedWireshark ? (
                    <Check className="w-3 h-3 text-emerald-400" />
                  ) : (
                    <Copy className="w-3 h-3" />
                  )}
                </button>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Vertical Split: Top Packet Table (52%) + Bottom 3-Pane Packet Inspector (48%) */}
      <div className="flex-1 flex flex-col gap-3 min-h-0">
        {/* Top Pane: High-Density Packet Table */}
        <div className="h-[52%] min-h-[200px] bg-slate-900 border border-slate-800 rounded-xl flex flex-col overflow-hidden shadow-md">
          <div className="flex-1 overflow-auto">
            <table className="w-full text-left border-collapse">
              <thead className="sticky top-0 bg-slate-950 border-b border-slate-800 text-[11px] font-mono uppercase text-slate-400 z-10 select-none">
                <tr>
                  <th className="py-2 px-2.5 w-8 text-center">
                    <input
                      type="checkbox"
                      aria-label="Select all packets on page"
                      checked={
                        Boolean(data?.items?.length) &&
                        data!.items.every((p) => selectedPacketNumbers.has(p.packet_number))
                      }
                      onChange={toggleSelectAllOnPage}
                      className="accent-cyan-500"
                    />
                  </th>
                  <th
                    onClick={() => handleSortColumn('packet_number')}
                    className="py-2 px-2.5 w-16 cursor-pointer hover:text-cyan-300"
                  >
                    No. {sortBy === 'packet_number' ? (sortDir === 'asc' ? '↑' : '↓') : ''}
                  </th>
                  {visibleCols.time && (
                    <th
                      onClick={() => handleSortColumn('timestamp')}
                      className="py-2 px-2.5 w-28 cursor-pointer hover:text-cyan-300"
                    >
                      Time {sortBy === 'timestamp' ? (sortDir === 'asc' ? '↑' : '↓') : ''}
                    </th>
                  )}
                  {visibleCols.source && (
                    <th
                      onClick={() => handleSortColumn('src_ip')}
                      className="py-2 px-2.5 cursor-pointer hover:text-cyan-300"
                    >
                      Source {sortBy === 'src_ip' ? (sortDir === 'asc' ? '↑' : '↓') : ''}
                    </th>
                  )}
                  {visibleCols.destination && (
                    <th
                      onClick={() => handleSortColumn('dst_ip')}
                      className="py-2 px-2.5 cursor-pointer hover:text-cyan-300"
                    >
                      Destination {sortBy === 'dst_ip' ? (sortDir === 'asc' ? '↑' : '↓') : ''}
                    </th>
                  )}
                  {visibleCols.protocol && (
                    <th
                      onClick={() => handleSortColumn('protocol')}
                      className="py-2 px-2.5 w-20 cursor-pointer hover:text-cyan-300"
                    >
                      Protocol {sortBy === 'protocol' ? (sortDir === 'asc' ? '↑' : '↓') : ''}
                    </th>
                  )}
                  {visibleCols.length && (
                    <th
                      onClick={() => handleSortColumn('length')}
                      className="py-2 px-2.5 w-16 cursor-pointer hover:text-cyan-300"
                    >
                      Length {sortBy === 'length' ? (sortDir === 'asc' ? '↑' : '↓') : ''}
                    </th>
                  )}
                  {visibleCols.info && <th className="py-2 px-2.5">Info</th>}
                  {visibleCols.flags && <th className="py-2 px-2.5 w-20">TCP Flags</th>}
                  <th className="py-2 px-2 w-14 text-center" title="Follow Stream">
                    Stream
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/50 text-xs font-mono">
                {loading ? (
                  <tr>
                    <td colSpan={10} className="py-10 text-center text-slate-500">
                      Loading packets...
                    </td>
                  </tr>
                ) : !data || data.items.length === 0 ? (
                  <tr>
                    <td colSpan={10} className="py-10 text-center text-slate-500">
                      <div className="space-y-2">
                        <p>No packets match the current filter criteria.</p>
                        {activeChips.length > 0 && (
                          <button
                            type="button"
                            onClick={handleResetFilters}
                            className="px-3 py-1 rounded bg-slate-800 hover:bg-slate-700 text-cyan-300 text-xs font-mono"
                          >
                            Reset Filters
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ) : (
                  data.items.map((pkt) => {
                    const isSelected = selectedPacket?.packet_number === pkt.packet_number;
                    const isChecked = selectedPacketNumbers.has(pkt.packet_number);
                    const rowTint = getPacketRowTint(pkt, colorizeRows, isSelected);
                    const pktFindings = facets?.finding_packets?.[String(pkt.packet_number)];

                    const formattedTime =
                      timeMode === 'relative'
                        ? pkt.rel_time.toFixed(4)
                        : new Date(pkt.timestamp * 1000).toISOString().split('T')[1].slice(0, 12);

                    return (
                      <tr
                        key={pkt.packet_number}
                        onClick={() => setSelectedPacket(pkt)}
                        className={`cursor-pointer transition-colors group ${rowTint}`}
                      >
                        <td
                          className="py-1.5 px-2.5 text-center"
                          onClick={(e) => e.stopPropagation()}
                        >
                          <input
                            type="checkbox"
                            aria-label={`Select packet ${pkt.packet_number}`}
                            checked={isChecked}
                            onChange={() => toggleSelectPacketCheckbox(pkt.packet_number)}
                            className="accent-cyan-500"
                          />
                        </td>
                        <td className="py-1.5 px-2.5 text-slate-400">
                          <div className="flex items-center gap-1">
                            <span>{pkt.packet_number}</span>
                            {pktFindings && pktFindings.length > 0 && (
                              <span
                                title={`Evidence in finding: ${pktFindings.map((f) => f.title).join(', ')}`}
                                className="text-rose-400"
                              >
                                <ShieldAlert className="w-3 h-3" />
                              </span>
                            )}
                          </div>
                        </td>
                        {visibleCols.time && (
                          <td className="py-1.5 px-2.5 text-slate-400">{formattedTime}</td>
                        )}
                        {visibleCols.source && (
                          <td className="py-1.5 px-2.5 truncate max-w-[170px]">
                            <div className="flex items-center gap-0.5">
                              {pkt.src_ip ? (
                                <button
                                  type="button"
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    applyDisplayFilterExpression(`ip.src == ${pkt.src_ip}`);
                                  }}
                                  className="hover:underline hover:text-cyan-300 text-left truncate"
                                  title={`Click to filter ip.src == ${pkt.src_ip}`}
                                >
                                  {pkt.src_ip}
                                </button>
                              ) : (
                                <span>—</span>
                              )}
                              {pkt.src_port != null && (
                                <button
                                  type="button"
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    setPortFilter(String(pkt.src_port));
                                    setPage(1);
                                  }}
                                  className="text-slate-500 hover:text-cyan-300 hover:underline"
                                  title={`Click to filter Port ${pkt.src_port}`}
                                >
                                  :{pkt.src_port}
                                </button>
                              )}
                            </div>
                          </td>
                        )}
                        {visibleCols.destination && (
                          <td className="py-1.5 px-2.5 truncate max-w-[170px]">
                            <div className="flex items-center gap-0.5">
                              {pkt.dst_ip ? (
                                <button
                                  type="button"
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    applyDisplayFilterExpression(`ip.dst == ${pkt.dst_ip}`);
                                  }}
                                  className="hover:underline hover:text-cyan-300 text-left truncate"
                                  title={`Click to filter ip.dst == ${pkt.dst_ip}`}
                                >
                                  {pkt.dst_ip}
                                </button>
                              ) : (
                                <span>—</span>
                              )}
                              {pkt.dst_port != null && (
                                <button
                                  type="button"
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    setPortFilter(String(pkt.dst_port));
                                    setPage(1);
                                  }}
                                  className="text-slate-500 hover:text-cyan-300 hover:underline"
                                  title={`Click to filter Port ${pkt.dst_port}`}
                                >
                                  :{pkt.dst_port}
                                </button>
                              )}
                            </div>
                          </td>
                        )}
                        {visibleCols.protocol && (
                          <td className="py-1.5 px-2.5">
                            <button
                              type="button"
                              onClick={(e) => {
                                e.stopPropagation();
                                applyDisplayFilterExpression(pkt.protocol.toLowerCase());
                              }}
                              className={`px-1.5 py-0.5 rounded text-[10px] font-semibold border transition-colors ${
                                pkt.protocol === 'TCP'
                                  ? 'bg-blue-950/80 text-blue-300 border-blue-800/60 hover:border-blue-500'
                                  : pkt.protocol === 'DNS'
                                  ? 'bg-purple-950/80 text-purple-300 border-purple-800/60 hover:border-purple-500'
                                  : pkt.protocol === 'HTTP'
                                  ? 'bg-amber-950/80 text-amber-300 border-amber-700/60 hover:border-amber-500'
                                  : pkt.protocol === 'UDP'
                                  ? 'bg-cyan-950/80 text-cyan-300 border-cyan-800/60 hover:border-cyan-500'
                                  : pkt.protocol === 'ICMP'
                                  ? 'bg-amber-950/80 text-amber-300 border-amber-800/60 hover:border-amber-500'
                                  : 'bg-slate-800 text-slate-300 border-slate-700'
                              }`}
                              title={`Filter protocol: ${pkt.protocol.toLowerCase()}`}
                            >
                              {pkt.protocol}
                            </button>
                          </td>
                        )}
                        {visibleCols.length && (
                          <td className="py-1.5 px-2.5 text-slate-400">{pkt.length}</td>
                        )}
                        {visibleCols.info && (
                          <td className="py-1.5 px-2.5 text-slate-300 truncate max-w-[360px]">
                            <span title={pkt.info}>{pkt.info}</span>
                          </td>
                        )}
                        {visibleCols.flags && (
                          <td className="py-1.5 px-2.5">{formatFlagBadges(pkt.tcp_flags)}</td>
                        )}
                        <td className="py-1.5 px-2 text-center">
                          {pkt.src_ip && pkt.dst_ip && pkt.src_ip !== 'unknown' && (
                            <button
                              type="button"
                              onClick={(e) => {
                                e.stopPropagation();
                                handleFollowConversation(pkt.src_ip!, pkt.dst_ip!);
                              }}
                              className="p-1 rounded bg-slate-800/80 hover:bg-cyan-950 text-slate-400 hover:text-cyan-300 border border-slate-700/70 hover:border-cyan-700 transition-colors"
                              title={`Follow conversation: ${pkt.src_ip} ⇄ ${pkt.dst_ip}`}
                            >
                              <ArrowLeftRight className="w-3 h-3" />
                            </button>
                          )}
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>

          {/* Table Footer: Page Size + Color Key + Pagination */}
          <div className="px-4 py-1.5 bg-slate-950 border-t border-slate-800 flex flex-wrap items-center justify-between gap-2 text-xs font-mono text-slate-400">
            <div className="flex items-center gap-3 flex-wrap">
              <span>
                Page <strong className="text-slate-200">{data?.page || 1}</strong> of{' '}
                <strong className="text-slate-200">{data?.total_pages || 1}</strong>
              </span>
              <div className="flex items-center gap-1.5">
                <span className="text-[11px]">Rows:</span>
                <select
                  aria-label="Page Size"
                  value={pageSize}
                  onChange={(e) => {
                    setPageSize(Number(e.target.value));
                    setPage(1);
                  }}
                  className="bg-slate-900 border border-slate-800 rounded px-1.5 py-0.5 text-[11px] text-slate-200"
                >
                  <option value={25}>25</option>
                  <option value={50}>50</option>
                  <option value={100}>100</option>
                  <option value={200}>200</option>
                </select>
              </div>
              {colorizeRows && (
                <div className="hidden md:flex items-center gap-2 text-[10px] text-slate-400 border-l border-slate-800 pl-3">
                  <span className="inline-flex items-center gap-1">
                    <span className="w-2 h-2 rounded-full bg-emerald-400" /> SYN
                  </span>
                  <span className="inline-flex items-center gap-1">
                    <span className="w-2 h-2 rounded-full bg-rose-400" /> RST
                  </span>
                  <span className="inline-flex items-center gap-1">
                    <span className="w-2 h-2 rounded-full bg-purple-400" /> DNS
                  </span>
                  <span className="inline-flex items-center gap-1">
                    <span className="w-2 h-2 rounded-full bg-teal-400" /> HTTP
                  </span>
                  <span className="inline-flex items-center gap-1">
                    <span className="w-2 h-2 rounded-full bg-amber-400" /> ICMP/ARP
                  </span>
                </div>
              )}
            </div>
            <div className="flex items-center gap-1.5">
              <button
                disabled={!data || page <= 1}
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                className="p-1 rounded bg-slate-900 border border-slate-800 text-slate-300 hover:bg-slate-800 disabled:opacity-40"
              >
                <ChevronLeft className="w-4 h-4" />
              </button>
              <button
                disabled={!data || page >= (data.total_pages || 1)}
                onClick={() => setPage((p) => p + 1)}
                className="p-1 rounded bg-slate-900 border border-slate-800 text-slate-300 hover:bg-slate-800 disabled:opacity-40"
              >
                <ChevronRight className="w-4 h-4" />
              </button>
            </div>
          </div>
        </div>

        {/* Bottom Pane: 3-Column Detailed Packet Inspector (Layers | Hex+ASCII | Summary & Context) */}
        <div className="flex-1 min-h-[210px]">
          <PacketInspector
            packet={selectedPacket}
            layout="split"
            relatedFindings={selectedPacketFindings}
            onApplyFilter={handleQuickFilterFromChild}
            onFollowConversation={handleFollowConversation}
            onNavigate={(path) => navigate(path)}
          />
        </div>
      </div>
    </div>
  );
};
