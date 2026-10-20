import React, { useState, useMemo, useEffect } from 'react';
import { PacketItem } from '../types';
import {
  Layers,
  ChevronDown,
  ChevronRight,
  Copy,
  Check,
  FileCode,
  Info,
  X,
  Filter,
  ArrowLeftRight,
  Search,
  ChevronsUpDown,
  ExternalLink,
  ShieldAlert,
  Network,
  Activity
} from 'lucide-react';

export type QuickFilterField =
  | 'ip'
  | 'src_ip'
  | 'dst_ip'
  | 'exclude_ip'
  | 'port'
  | 'src_port'
  | 'dst_port'
  | 'protocol'
  | 'tcp_flag'
  | 'display_filter'
  | 'search';

interface FindingRef {
  id: string;
  title: string;
  severity: string;
  category: string;
}

interface Props {
  packet: PacketItem | null;
  loading?: boolean;
  layout?: 'split' | 'tabbed';
  relatedFindings?: FindingRef[];
  onClose?: () => void;
  onApplyFilter?: (field: QuickFilterField, value: string | number) => void;
  onFollowConversation?: (peerA: string, peerB: string) => void;
  onNavigate?: (path: string) => void;
}

const TCP_FLAG_DESCRIPTIONS: Record<string, { label: string; color: string }> = {
  SYN: { label: 'Synchronize (Handshake Start)', color: 'bg-emerald-950/80 text-emerald-300 border-emerald-700/60' },
  ACK: { label: 'Acknowledgment', color: 'bg-cyan-950/80 text-cyan-300 border-cyan-800/60' },
  RST: { label: 'Reset (Abrupt Abort / Refused)', color: 'bg-rose-950/80 text-rose-300 border-rose-700/60' },
  FIN: { label: 'Finish (Graceful Teardown)', color: 'bg-amber-950/80 text-amber-300 border-amber-700/60' },
  PSH: { label: 'Push Data Immediately', color: 'bg-purple-950/80 text-purple-300 border-purple-700/60' },
  URG: { label: 'Urgent Pointer Significant', color: 'bg-orange-950/80 text-orange-300 border-orange-700/60' },
};

function parseRawBytesFromPacket(packet: PacketItem): number[] {
  if (packet.details?.raw_hex) {
    const clean = String(packet.details.raw_hex).replace(/[^0-9a-fA-F]/g, '');
    const out: number[] = [];
    for (let i = 0; i < clean.length; i += 2) {
      const b = parseInt(clean.slice(i, i + 2), 16);
      if (!Number.isNaN(b)) out.push(b);
    }
    if (out.length > 0) return out;
  }

  const dump = packet.details?.hex_dump || packet.details?.payload_hex || '';
  if (!dump) return [];

  // Parse formatted lines like "0000  45 00 00 3c ...  |E..<...|"
  const lines = String(dump).split('\n');
  const bytes: number[] = [];
  for (const line of lines) {
    if (line.startsWith('...')) continue;
    const match = line.match(/^[0-9a-fA-F]{4}\s+((?:[0-9a-fA-F]{2}\s*)+)/);
    if (match) {
      const hexPart = match[1].trim().split(/\s+/);
      for (const h of hexPart) {
        const b = parseInt(h, 16);
        if (!Number.isNaN(b)) bytes.push(b);
      }
    }
  }
  return bytes;
}

function buildDisplayFilterForField(
  layerName: string,
  fieldKey: string,
  fieldVal: any,
  packet: PacketItem
): { field: QuickFilterField; value: string } | null {
  const k = fieldKey.toLowerCase();
  const strVal = String(fieldVal ?? '').trim();
  if (!strVal) return null;

  if (k === 'source ip') return { field: 'display_filter', value: `ip.src == ${strVal}` };
  if (k === 'destination ip') return { field: 'display_filter', value: `ip.dst == ${strVal}` };
  if (k === 'source port') {
    const p = packet.protocol === 'UDP' || packet.protocol === 'DNS' ? 'udp.srcport' : 'tcp.srcport';
    return { field: 'display_filter', value: `${p} == ${strVal}` };
  }
  if (k === 'destination port') {
    const p = packet.protocol === 'UDP' || packet.protocol === 'DNS' ? 'udp.dstport' : 'tcp.dstport';
    return { field: 'display_filter', value: `${p} == ${strVal}` };
  }
  if (k.includes('time to live') || k === 'ttl') {
    return { field: 'display_filter', value: `ip.ttl == ${strVal}` };
  }
  if (k === 'sequence number') {
    return { field: 'display_filter', value: `tcp.seq == ${strVal}` };
  }
  if (k === 'acknowledgment number') {
    return { field: 'display_filter', value: `tcp.ack == ${strVal}` };
  }
  if (k === 'window size') {
    return { field: 'display_filter', value: `tcp.window == ${strVal}` };
  }
  if (k === 'frame number') {
    return { field: 'display_filter', value: `frame.number == ${strVal}` };
  }
  if (k === 'response code' && layerName.toLowerCase().includes('domain')) {
    return { field: 'display_filter', value: `dns.rcode == "${strVal}"` };
  }
  if (strVal.length < 48) {
    return { field: 'search', value: strVal };
  }
  return null;
}

export const PacketInspector: React.FC<Props> = ({
  packet,
  loading,
  layout = 'split',
  relatedFindings = [],
  onClose,
  onApplyFilter,
  onFollowConversation,
  onNavigate,
}) => {
  const [activeTab, setActiveTab] = useState<'layers' | 'hex' | 'summary'>('layers');
  const [expandedLayers, setExpandedLayers] = useState<Record<string, boolean>>({});
  const [layerSearch, setLayerSearch] = useState('');
  const [highlightedRange, setHighlightedRange] = useState<{
    start: number;
    end: number;
    label: string;
  } | null>(null);
  const [copiedHex, setCopiedHex] = useState(false);
  const [copiedSummary, setCopiedSummary] = useState(false);

  // Reset highlighted byte range when selected packet changes
  useEffect(() => {
    setHighlightedRange(null);
  }, [packet?.packet_number]);

  const layersTree = packet?.details?.layers_tree || [];

  const filteredLayersTree = useMemo(() => {
    if (!layerSearch.trim()) return layersTree;
    const term = layerSearch.trim().toLowerCase();
    return layersTree
      .map((layer) => {
        const layerMatch =
          layer.name.toLowerCase().includes(term) ||
          (layer.summary && layer.summary.toLowerCase().includes(term));
        const matchingFields: Record<string, any> = {};
        Object.entries(layer.fields || {}).forEach(([k, v]) => {
          const valStr = typeof v === 'object' && v !== null ? JSON.stringify(v) : String(v);
          if (k.toLowerCase().includes(term) || valStr.toLowerCase().includes(term) || layerMatch) {
            matchingFields[k] = v;
          }
        });
        if (layerMatch || Object.keys(matchingFields).length > 0) {
          return { ...layer, fields: matchingFields };
        }
        return null;
      })
      .filter(Boolean) as typeof layersTree;
  }, [layersTree, layerSearch]);

  const rawBytes = useMemo(() => (packet ? parseRawBytesFromPacket(packet) : []), [packet]);

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center h-full p-8 text-slate-400 bg-slate-900 border border-slate-800 rounded-xl">
        <span className="animate-spin text-xl text-cyan-400 mb-2">&#9696;</span>
        <span className="text-xs font-mono">Decoding packet layers...</span>
      </div>
    );
  }

  if (!packet) {
    return (
      <div className="flex flex-col items-center justify-center h-full p-6 text-center text-slate-500 bg-slate-900 border border-slate-800 rounded-xl">
        <Layers className="w-8 h-8 text-slate-700 mb-2" />
        <h4 className="text-sm font-semibold text-slate-300 mb-1">No Packet Selected</h4>
        <p className="text-xs text-slate-500 max-w-md">
          Select any packet frame from the table (or use ↑/↓ arrow keys) to inspect decoded protocol layers, synchronized hex + ASCII byte offsets, and related flows/findings.
        </p>
      </div>
    );
  }

  const toggleLayer = (layerName: string, byteStart?: number, byteEnd?: number) => {
    setExpandedLayers((prev) => ({
      ...prev,
      [layerName]: !(prev[layerName] ?? true),
    }));
    if (byteStart !== undefined && byteEnd !== undefined && byteEnd > byteStart) {
      setHighlightedRange({ start: byteStart, end: byteEnd, label: layerName });
    }
  };

  const toggleAllLayers = (expand: boolean) => {
    const next: Record<string, boolean> = {};
    layersTree.forEach((l) => {
      next[l.name] = expand;
    });
    setExpandedLayers(next);
  };

  const handleCopyHex = () => {
    const hex = packet.details?.raw_hex || packet.details?.hex_dump || '';
    if (!hex) return;
    navigator.clipboard.writeText(hex);
    setCopiedHex(true);
    setTimeout(() => setCopiedHex(false), 2000);
  };

  const handleCopySummary = () => {
    const summaryText = `Frame #${packet.packet_number} | ${packet.protocol} | ${packet.src_ip || '-'}:${packet.src_port ?? '-'} -> ${packet.dst_ip || '-'}:${packet.dst_port ?? '-'} | Len=${packet.length}B | ${packet.info}`;
    navigator.clipboard.writeText(summaryText);
    setCopiedSummary(true);
    setTimeout(() => setCopiedSummary(false), 2000);
  };

  const parsedFlags = (packet.tcp_flags || '')
    .split(',')
    .map((f) => f.trim().toUpperCase())
    .filter(Boolean);

  // Build 16-byte rows for synchronized Hex + ASCII view
  const hexRows: Array<{ offset: number; bytes: Array<{ idx: number; val: number }> }> = [];
  for (let offset = 0; offset < rawBytes.length; offset += 16) {
    const chunk = rawBytes.slice(offset, offset + 16).map((val, i) => ({
      idx: offset + i,
      val,
    }));
    hexRows.push({ offset, bytes: chunk });
  }

  // Render Pane 1: Decoded Layer Tree
  const renderLayersPane = () => (
    <div className="flex flex-col h-full min-h-0">
      <div className="flex items-center gap-1.5 pb-2 mb-2 border-b border-slate-800/80">
        <div className="relative flex-1">
          <Search className="w-3 h-3 text-slate-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={layerSearch}
            onChange={(e) => setLayerSearch(e.target.value)}
            placeholder="Search decoded fields (ttl, seq, mac, host)..."
            className="w-full pl-7 pr-2 py-1 bg-slate-950 border border-slate-800 rounded text-[11px] font-mono text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
          />
        </div>
        <button
          type="button"
          onClick={() => toggleAllLayers(true)}
          className="px-1.5 py-1 bg-slate-950 hover:bg-slate-800 border border-slate-800 rounded text-[10px] font-mono text-slate-400 hover:text-slate-200 flex items-center gap-1"
          title="Expand all protocol layers"
        >
          <ChevronsUpDown className="w-3 h-3" />
          <span>Expand</span>
        </button>
        <button
          type="button"
          onClick={() => toggleAllLayers(false)}
          className="px-1.5 py-1 bg-slate-950 hover:bg-slate-800 border border-slate-800 rounded text-[10px] font-mono text-slate-400 hover:text-slate-200"
          title="Collapse all protocol layers"
        >
          Collapse
        </button>
      </div>

      <div className="flex-1 overflow-y-auto space-y-1.5 pr-1">
        {filteredLayersTree.length > 0 ? (
          filteredLayersTree.map((layer) => {
            const isExpanded = expandedLayers[layer.name] ?? true;
            const isLayerHighlighted =
              highlightedRange &&
              layer.byte_start !== undefined &&
              highlightedRange.start === layer.byte_start &&
              highlightedRange.end === layer.byte_end;

            return (
              <div
                key={layer.name}
                className={`border rounded-lg overflow-hidden transition-colors ${
                  isLayerHighlighted
                    ? 'border-cyan-500/70 bg-cyan-950/20'
                    : 'border-slate-800/80 bg-slate-950/50'
                }`}
              >
                <button
                  type="button"
                  onClick={() => toggleLayer(layer.name, layer.byte_start, layer.byte_end)}
                  className="w-full flex items-center justify-between px-2.5 py-1.5 bg-slate-900/90 hover:bg-slate-800/70 text-left text-xs font-mono font-semibold text-slate-200 transition-colors"
                >
                  <div className="flex items-center gap-1.5 truncate">
                    {isExpanded ? (
                      <ChevronDown className="w-3.5 h-3.5 text-cyan-400 flex-shrink-0" />
                    ) : (
                      <ChevronRight className="w-3.5 h-3.5 text-slate-500 flex-shrink-0" />
                    )}
                    <span className="text-cyan-300 truncate">{layer.name}</span>
                    {layer.summary && (
                      <span className="text-[11px] font-normal text-slate-400 ml-1 truncate">
                        — {layer.summary}
                      </span>
                    )}
                  </div>
                  {layer.byte_start !== undefined && layer.byte_end !== undefined && (
                    <span className="text-[9px] font-mono text-slate-500 ml-2 flex-shrink-0">
                      [{layer.byte_start}..{layer.byte_end}]
                    </span>
                  )}
                </button>

                {isExpanded && (
                  <div className="px-3 py-1.5 border-t border-slate-800/60 bg-slate-950/40 text-[11px] font-mono divide-y divide-slate-800/40">
                    {Object.entries(layer.fields).map(([k, v]) => {
                      const strVal =
                        Array.isArray(v)
                          ? v.join(', ')
                          : typeof v === 'object' && v !== null
                          ? JSON.stringify(v)
                          : String(v);
                      const fieldRange = layer.field_offsets?.[k];
                      const isFieldSelected =
                        fieldRange &&
                        highlightedRange &&
                        highlightedRange.start === fieldRange[0] &&
                        highlightedRange.end === fieldRange[1];
                      const filterAction = buildDisplayFilterForField(layer.name, k, strVal, packet);

                      return (
                        <div
                          key={k}
                          onClick={() => {
                            if (fieldRange) {
                              setHighlightedRange({
                                start: fieldRange[0],
                                end: fieldRange[1],
                                label: `${layer.name} · ${k}`,
                              });
                            } else if (layer.byte_start !== undefined && layer.byte_end !== undefined) {
                              setHighlightedRange({
                                start: layer.byte_start,
                                end: layer.byte_end,
                                label: layer.name,
                              });
                            }
                          }}
                          className={`py-1 px-1.5 -mx-1.5 rounded flex items-start justify-between gap-2 cursor-pointer group transition-colors ${
                            isFieldSelected ? 'bg-cyan-950/60 text-cyan-200' : 'hover:bg-slate-900/70'
                          }`}
                        >
                          <span className="text-slate-400 font-normal">{k.replace(/_/g, ' ')}:</span>
                          <div className="flex items-center gap-1.5">
                            <span className="text-slate-200 text-right break-all">{strVal || '—'}</span>
                            {onApplyFilter && filterAction && (
                              <button
                                type="button"
                                onClick={(e) => {
                                  e.stopPropagation();
                                  onApplyFilter(filterAction.field, filterAction.value);
                                }}
                                className="opacity-0 group-hover:opacity-100 px-1.5 py-0.5 rounded bg-cyan-950 hover:bg-cyan-900 text-[9px] text-cyan-300 border border-cyan-700/70 transition-opacity flex-shrink-0"
                                title={`Apply filter: ${filterAction.value}`}
                              >
                                Filter
                              </button>
                            )}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            );
          })
        ) : (
          <div className="bg-slate-950/80 rounded-lg border border-slate-800/80 p-3 font-mono text-xs overflow-x-auto text-slate-300">
            <pre>{JSON.stringify(packet.details, null, 2)}</pre>
          </div>
        )}
      </div>
    </div>
  );

  // Render Pane 2: Synchronized Hex + ASCII Byte View
  const renderHexPane = () => (
    <div className="flex flex-col h-full min-h-0">
      <div className="flex items-center justify-between pb-2 mb-2 border-b border-slate-800/80">
        <div className="flex items-center gap-2 truncate">
          <span className="text-[11px] font-mono text-slate-400">
            Hex & ASCII ({rawBytes.length || packet.length} B)
          </span>
          {highlightedRange && (
            <span className="px-1.5 py-0.5 rounded bg-cyan-950/80 border border-cyan-700/70 text-[10px] font-mono text-cyan-300 truncate">
              Bytes {highlightedRange.start}–{highlightedRange.end} ({highlightedRange.label})
            </span>
          )}
        </div>
        <button
          type="button"
          onClick={handleCopyHex}
          className="flex items-center gap-1 px-2 py-0.5 text-[10px] font-mono text-slate-300 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded transition-colors flex-shrink-0"
        >
          {copiedHex ? (
            <>
              <Check className="w-3 h-3 text-emerald-400" />
              <span className="text-emerald-400">Copied</span>
            </>
          ) : (
            <>
              <Copy className="w-3 h-3 text-slate-400" />
              <span>Copy Hex</span>
            </>
          )}
        </button>
      </div>

      <div className="flex-1 overflow-auto bg-slate-950 border border-slate-800/90 rounded-lg p-2.5 font-mono text-[11px] leading-relaxed">
        {hexRows.length > 0 ? (
          <>
            <div className="grid grid-cols-[42px_1fr_118px] gap-2 pb-1 mb-1 border-b border-slate-800/80 text-[9px] uppercase text-slate-500 select-none">
              <span>Offset</span>
              <span>00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F</span>
              <span>ASCII</span>
            </div>
            {hexRows.map((row) => (
              <div
                key={row.offset}
                className="grid grid-cols-[42px_1fr_118px] gap-2 hover:bg-slate-900/60 px-1 rounded items-center"
              >
                <span className="text-slate-500 select-none">
                  {row.offset.toString(16).padStart(4, '0')}
                </span>
                <div className="flex items-center flex-wrap gap-x-1">
                  {row.bytes.map((b, i) => {
                    const isHighlighted =
                      highlightedRange !== null &&
                      b.idx >= highlightedRange.start &&
                      b.idx < highlightedRange.end;
                    return (
                      <span
                        key={b.idx}
                        className={`px-0.5 rounded transition-colors ${
                          i === 7 ? 'mr-1.5' : ''
                        } ${
                          isHighlighted
                            ? 'bg-cyan-500 text-slate-950 font-bold'
                            : 'text-cyan-300/90'
                        }`}
                      >
                        {b.val.toString(16).padStart(2, '0')}
                      </span>
                    );
                  })}
                </div>
                <div className="border-l border-slate-800 pl-2 flex items-center">
                  {row.bytes.map((b) => {
                    const isHighlighted =
                      highlightedRange !== null &&
                      b.idx >= highlightedRange.start &&
                      b.idx < highlightedRange.end;
                    const ch = b.val >= 32 && b.val <= 126 ? String.fromCharCode(b.val) : '.';
                    return (
                      <span
                        key={b.idx}
                        className={
                          isHighlighted
                            ? 'bg-cyan-500 text-slate-950 font-bold'
                            : 'text-amber-200/80'
                        }
                      >
                        {ch}
                      </span>
                    );
                  })}
                </div>
              </div>
            ))}
          </>
        ) : (
          <pre className="whitespace-pre text-slate-300">
            {packet.details?.hex_dump || 'No hex dump available for this frame.'}
          </pre>
        )}
      </div>
    </div>
  );

  // Render Pane 3: Packet Metadata, Context, Findings & Quick Actions
  const renderSummaryPane = () => (
    <div className="flex flex-col h-full min-h-0 overflow-y-auto space-y-2.5 pr-1">
      {/* Packet Information Table */}
      <div className="p-2.5 bg-slate-950/70 rounded-lg border border-slate-800/80 space-y-1.5 text-[11px] font-mono">
        <div className="flex items-center justify-between pb-1 border-b border-slate-800">
          <span className="text-[10px] uppercase tracking-wider text-slate-400 font-semibold">
            Packet Information
          </span>
          <button
            type="button"
            onClick={handleCopySummary}
            className="text-[10px] text-cyan-400 hover:text-cyan-300 flex items-center gap-1"
            title="Copy packet summary line"
          >
            {copiedSummary ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
            <span>{copiedSummary ? 'Copied' : 'Copy'}</span>
          </button>
        </div>
        <div className="flex justify-between">
          <span className="text-slate-500">Packet Number</span>
          <span className="text-slate-200 font-semibold">#{packet.packet_number}</span>
        </div>
        <div className="flex justify-between">
          <span className="text-slate-500">Timestamp</span>
          <span className="text-slate-300">
            {new Date(packet.timestamp * 1000).toISOString().replace('T', ' ').replace('Z', '')}
          </span>
        </div>
        <div className="flex justify-between">
          <span className="text-slate-500">Captured / Wire</span>
          <span className="text-slate-200">
            {packet.length} B / {packet.original_length} B
          </span>
        </div>
        <div className="flex justify-between items-center">
          <span className="text-slate-500">Source</span>
          <div className="flex items-center gap-1">
            <span className="text-cyan-400 font-semibold">
              {packet.src_ip || 'L2'}{packet.src_port != null ? `:${packet.src_port}` : ''}
            </span>
            {onApplyFilter && packet.src_ip && (
              <button
                type="button"
                onClick={() => onApplyFilter('display_filter', `ip.src == ${packet.src_ip}`)}
                className="px-1 py-0.2 bg-slate-800 hover:bg-cyan-950 text-[9px] text-cyan-300 rounded border border-slate-700"
                title={`Filter ip.src == ${packet.src_ip}`}
              >
                Filter
              </button>
            )}
          </div>
        </div>
        <div className="flex justify-between items-center">
          <span className="text-slate-500">Destination</span>
          <div className="flex items-center gap-1">
            <span className="text-cyan-400 font-semibold">
              {packet.dst_ip || 'L2'}{packet.dst_port != null ? `:${packet.dst_port}` : ''}
            </span>
            {onApplyFilter && packet.dst_ip && (
              <button
                type="button"
                onClick={() => onApplyFilter('display_filter', `ip.dst == ${packet.dst_ip}`)}
                className="px-1 py-0.2 bg-slate-800 hover:bg-cyan-950 text-[9px] text-cyan-300 rounded border border-slate-700"
                title={`Filter ip.dst == ${packet.dst_ip}`}
              >
                Filter
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Decoded TCP Flags */}
      {parsedFlags.length > 0 && (
        <div className="p-2.5 bg-slate-950/70 rounded-lg border border-slate-800/80 space-y-1.5">
          <span className="text-[10px] uppercase tracking-wider text-slate-400 font-mono block">
            TCP Control Flags
          </span>
          <div className="flex flex-wrap gap-1">
            {parsedFlags.map((flag) => {
              const meta = TCP_FLAG_DESCRIPTIONS[flag] || {
                label: flag,
                color: 'bg-slate-800 text-slate-300 border-slate-700',
              };
              const flagField =
                flag === 'RST'
                  ? 'tcp.flags.reset == 1'
                  : flag === 'PSH'
                  ? 'tcp.flags.push == 1'
                  : `tcp.flags.${flag.toLowerCase()} == 1`;
              return (
                <button
                  key={flag}
                  type="button"
                  onClick={() => onApplyFilter?.('display_filter', flagField)}
                  className={`px-2 py-0.5 rounded border text-[10px] font-mono flex items-center gap-1 ${meta.color}`}
                  title={`Filter ${flagField}`}
                >
                  <span className="font-bold">{flag}</span>
                  <span className="opacity-80 text-[9px]">{meta.label}</span>
                </button>
              );
            })}
          </div>
        </div>
      )}

      {/* Related Findings for this Packet */}
      {relatedFindings.length > 0 && (
        <div className="p-2.5 bg-rose-950/25 rounded-lg border border-rose-800/60 space-y-1.5">
          <div className="flex items-center gap-1.5 text-[10px] uppercase tracking-wider text-rose-300 font-mono font-semibold">
            <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
            <span>Evidence in {relatedFindings.length} Finding(s)</span>
          </div>
          {relatedFindings.map((fd) => (
            <div
              key={fd.id}
              className="flex items-center justify-between gap-2 text-[11px] font-mono bg-slate-950/70 px-2 py-1 rounded border border-rose-900/50"
            >
              <span className="text-slate-200 truncate" title={fd.title}>
                [{fd.severity}] {fd.title}
              </span>
              {onNavigate && (
                <button
                  type="button"
                  onClick={() => onNavigate('/findings')}
                  className="text-cyan-400 hover:underline text-[10px] flex-shrink-0"
                >
                  Inspect &rarr;
                </button>
              )}
            </div>
          ))}
        </div>
      )}

      {/* Related Views & Cross-Navigation */}
      {onNavigate && packet.src_ip && (
        <div className="p-2.5 bg-slate-950/70 rounded-lg border border-slate-800/80 space-y-1.5 text-[11px] font-mono">
          <span className="text-[10px] uppercase tracking-wider text-slate-400 block">
            Related Investigation Views
          </span>
          <div className="grid grid-cols-2 gap-1.5">
            <button
              type="button"
              onClick={() => onNavigate(`/flows?ip=${encodeURIComponent(packet.src_ip!)}`)}
              className="px-2 py-1.5 bg-slate-900 hover:bg-slate-800 border border-slate-800 rounded text-slate-200 flex items-center justify-between transition-colors"
            >
              <span className="flex items-center gap-1.5">
                <Activity className="w-3 h-3 text-cyan-400" />
                View in Flows
              </span>
              <ExternalLink className="w-3 h-3 text-slate-500" />
            </button>
            <button
              type="button"
              onClick={() => onNavigate(`/topology?ip=${encodeURIComponent(packet.src_ip!)}`)}
              className="px-2 py-1.5 bg-slate-900 hover:bg-slate-800 border border-slate-800 rounded text-slate-200 flex items-center justify-between transition-colors"
            >
              <span className="flex items-center gap-1.5">
                <Network className="w-3 h-3 text-cyan-400" />
                In Topology
              </span>
              <ExternalLink className="w-3 h-3 text-slate-500" />
            </button>
          </div>
        </div>
      )}
    </div>
  );

  return (
    <div className="flex flex-col h-full bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-lg">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-2 border-b border-slate-800 bg-slate-950/80">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="px-2 py-0.5 rounded bg-cyan-950 text-cyan-400 font-mono text-xs font-semibold border border-cyan-800/80">
            Frame #{packet.packet_number}
          </span>
          <span className="text-xs font-mono text-slate-300">
            +{packet.rel_time.toFixed(4)}s
          </span>
          <button
            type="button"
            onClick={() => onApplyFilter?.('display_filter', packet.protocol.toLowerCase())}
            className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 hover:bg-cyan-950 text-cyan-300 border border-slate-700 hover:border-cyan-700 transition-colors flex items-center gap-1"
            title={`Click to filter by protocol ${packet.protocol}`}
          >
            <span>{packet.protocol}</span>
            {onApplyFilter && <Filter className="w-2.5 h-2.5 opacity-70" />}
          </button>
          <span className="text-[11px] font-mono text-slate-400 hidden sm:inline truncate max-w-md">
            {packet.info}
          </span>
        </div>

        <div className="flex items-center gap-1.5">
          {packet.src_ip && packet.dst_ip && onFollowConversation && (
            <button
              type="button"
              onClick={() => onFollowConversation(packet.src_ip!, packet.dst_ip!)}
              className="flex items-center gap-1 px-2 py-1 rounded bg-cyan-950/70 hover:bg-cyan-900/80 text-cyan-300 border border-cyan-800/60 text-[11px] font-mono transition-colors"
              title="Isolate bidirectional conversation between these two endpoints"
            >
              <ArrowLeftRight className="w-3 h-3" />
              <span>Follow Stream</span>
            </button>
          )}
          {onClose && (
            <button
              onClick={onClose}
              className="p-1 text-slate-400 hover:text-slate-100 hover:bg-slate-800 rounded transition-colors"
              title="Close inspector"
            >
              <X className="w-4 h-4" />
            </button>
          )}
        </div>
      </div>

      {/* In 'split' mode on desktop: show all 3 panes side by side (Layers | Hex+ASCII | Summary & Context) */}
      {layout === 'split' ? (
        <>
          {/* Mobile/Tablet Tabs fallback */}
          <div className="flex lg:hidden items-center border-b border-slate-800 bg-slate-950/40 text-xs font-mono">
            <button
              onClick={() => setActiveTab('layers')}
              className={`flex items-center gap-1.5 px-3 py-1.5 border-b-2 ${
                activeTab === 'layers' ? 'border-cyan-400 text-cyan-400' : 'border-transparent text-slate-400'
              }`}
            >
              <Layers className="w-3.5 h-3.5" />
              <span>Packet Details ({layersTree.length})</span>
            </button>
            <button
              onClick={() => setActiveTab('hex')}
              className={`flex items-center gap-1.5 px-3 py-1.5 border-b-2 ${
                activeTab === 'hex' ? 'border-cyan-400 text-cyan-400' : 'border-transparent text-slate-400'
              }`}
            >
              <FileCode className="w-3.5 h-3.5" />
              <span>Hex View</span>
            </button>
            <button
              onClick={() => setActiveTab('summary')}
              className={`flex items-center gap-1.5 px-3 py-1.5 border-b-2 ${
                activeTab === 'summary' ? 'border-cyan-400 text-cyan-400' : 'border-transparent text-slate-400'
              }`}
            >
              <Info className="w-3.5 h-3.5" />
              <span>Packet Info</span>
            </button>
          </div>

          <div className="flex-1 min-h-0 p-3 lg:hidden overflow-y-auto">
            {activeTab === 'layers' && renderLayersPane()}
            {activeTab === 'hex' && renderHexPane()}
            {activeTab === 'summary' && renderSummaryPane()}
          </div>

          <div className="hidden lg:grid lg:grid-cols-12 gap-3 flex-1 min-h-0 p-3">
            <div className="lg:col-span-5 min-h-0 h-full">{renderLayersPane()}</div>
            <div className="lg:col-span-4 min-h-0 h-full">{renderHexPane()}</div>
            <div className="lg:col-span-3 min-h-0 h-full">{renderSummaryPane()}</div>
          </div>
        </>
      ) : (
        <>
          <div className="flex items-center border-b border-slate-800 bg-slate-950/40 text-xs font-mono">
            <button
              onClick={() => setActiveTab('summary')}
              className={`flex items-center gap-1.5 px-3 py-2 border-b-2 ${
                activeTab === 'summary' ? 'border-cyan-400 text-cyan-400' : 'border-transparent text-slate-400'
              }`}
            >
              <Info className="w-3.5 h-3.5" />
              <span>Summary</span>
            </button>
            <button
              onClick={() => setActiveTab('layers')}
              className={`flex items-center gap-1.5 px-3 py-2 border-b-2 ${
                activeTab === 'layers' ? 'border-cyan-400 text-cyan-400' : 'border-transparent text-slate-400'
              }`}
            >
              <Layers className="w-3.5 h-3.5" />
              <span>Layers ({layersTree.length})</span>
            </button>
            <button
              onClick={() => setActiveTab('hex')}
              className={`flex items-center gap-1.5 px-3 py-2 border-b-2 ${
                activeTab === 'hex' ? 'border-cyan-400 text-cyan-400' : 'border-transparent text-slate-400'
              }`}
            >
              <FileCode className="w-3.5 h-3.5" />
              <span>Hex / ASCII</span>
            </button>
          </div>
          <div className="flex-1 overflow-y-auto p-3 min-h-0">
            {activeTab === 'summary' && renderSummaryPane()}
            {activeTab === 'layers' && renderLayersPane()}
            {activeTab === 'hex' && renderHexPane()}
          </div>
        </>
      )}
    </div>
  );
};
