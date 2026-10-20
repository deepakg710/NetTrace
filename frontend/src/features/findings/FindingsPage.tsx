import React, { useState, useEffect } from 'react';
import { useCapture } from '../../context/CaptureContext';
import { api } from '../../lib/api';
import { FindingItem } from '../../types';
import { StatusBadge } from '../../components/StatusBadge';
import { EmptyState } from '../../components/EmptyState';
import { LoadingSpinner } from '../../components/LoadingSpinner';
import { EvidenceModal } from '../../components/EvidenceModal';
import {
  HelpCircle,
  CheckCircle2,
  AlertTriangle,
  Lightbulb,
  ExternalLink,
  ChevronRight,
  RotateCcw
} from 'lucide-react';
import { useNavigate } from 'react-router-dom';

export const FindingsPage: React.FC = () => {
  const { activeCapture } = useCapture();
  const navigate = useNavigate();

  const [findings, setFindings] = useState<FindingItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [severityFilter, setSeverityFilter] = useState<string>('');
  const [categoryFilter, setCategoryFilter] = useState<string>('');
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(null);
  const [selectedPacketNumber, setSelectedPacketNumber] = useState<number | null>(null);

  const fetchFindings = async () => {
    if (!activeCapture) return;
    setLoading(true);
    try {
      const res = await api.getFindings(activeCapture.id, {
        severity: severityFilter || undefined,
        category: categoryFilter || undefined,
      });
      setFindings(res);
      if (res.length > 0 && (!selectedFindingId || !res.some(f => f.id === selectedFindingId))) {
        setSelectedFindingId(res[0].id);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchFindings();
  }, [activeCapture, severityFilter, categoryFilter]);

  if (!activeCapture) {
    return (
      <EmptyState
        title="No Capture Selected"
        description="Select or upload a capture to view diagnostic protocol findings and anomalies."
        actionText="Go to Captures"
        onAction={() => navigate('/captures')}
      />
    );
  }

  const selectedFinding = findings.find(f => f.id === selectedFindingId) || findings[0] || null;

  return (
    <div className="space-y-6 animate-in fade-in duration-200">
      {/* Title */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-800">
        <div>
          <h1 className="text-2xl font-bold text-slate-100">Findings & Evidence</h1>
          <p className="text-xs text-slate-400 font-mono mt-1">
            Evidence-backed protocol diagnostic findings for <strong className="text-slate-200">{activeCapture.original_filename}</strong>
          </p>
        </div>
      </div>

      {/* Filter Bar */}
      <div className="p-3.5 bg-slate-900/60 border border-slate-800 rounded-xl flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-2.5">
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-300 font-mono focus:outline-none focus:border-cyan-500"
          >
            <option value="">All Severities</option>
            <option value="Critical">Critical</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
            <option value="Informational">Informational</option>
          </select>

          <select
            value={categoryFilter}
            onChange={(e) => setCategoryFilter(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-300 font-mono focus:outline-none focus:border-cyan-500"
          >
            <option value="">All Categories</option>
            <option value="TCP">TCP Diagnostics</option>
            <option value="DNS">DNS Diagnostics</option>
            <option value="SCAN">Scan Patterns</option>
            <option value="ANOMALY">Traffic Anomalies</option>
          </select>

          {(severityFilter || categoryFilter) && (
            <button
              onClick={() => {
                setSeverityFilter('');
                setCategoryFilter('');
              }}
              className="text-xs text-slate-400 hover:text-slate-200 font-mono flex items-center gap-1 bg-slate-950 border border-slate-800 px-2.5 py-1.5 rounded-lg transition-colors"
            >
              <RotateCcw className="w-3 h-3" />
              <span>Reset</span>
            </button>
          )}
        </div>

        <div className="text-xs font-mono text-slate-400">
          Showing <span className="text-cyan-400 font-semibold">{findings.length}</span> finding{findings.length === 1 ? '' : 's'}
        </div>
      </div>

      {/* Main Content: Master-Detail Split */}
      {loading ? (
        <LoadingSpinner message="Correlating findings and packet evidence..." />
      ) : findings.length === 0 ? (
        <div className="p-12 text-center border border-slate-800 rounded-2xl bg-slate-900/30 space-y-3">
          <div className="p-3 rounded-full bg-emerald-500/10 text-emerald-400 inline-block">
            <CheckCircle2 className="w-8 h-8" />
          </div>
          <h3 className="text-base font-semibold text-slate-200">No Diagnostic Anomalies Triggered</h3>
          <p className="text-xs text-slate-400 max-w-md mx-auto">
            The active capture contains clean protocol exchanges. All observed TCP handshakes, resets, DNS queries, and port access patterns remain within standard baseline thresholds.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-start">
          {/* Left Column: Findings Master List */}
          <div className="lg:col-span-5 space-y-2.5">
            {findings.map((f) => {
              const isSelected = selectedFinding?.id === f.id;
              return (
                <div
                  key={f.id}
                  onClick={() => setSelectedFindingId(f.id)}
                  className={`p-3.5 rounded-xl border transition-all cursor-pointer ${
                    isSelected
                      ? 'bg-slate-900 border-cyan-500/60 shadow-md shadow-cyan-950/40 ring-1 ring-cyan-500/30'
                      : 'bg-slate-900/50 hover:bg-slate-900/80 border-slate-800/80'
                  }`}
                >
                  <div className="flex items-center justify-between gap-2 mb-2">
                    <div className="flex items-center gap-2">
                      <StatusBadge status={f.severity} type="severity" />
                      <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-300">
                        {f.category}
                      </span>
                    </div>
                    <span className="text-[10px] font-mono text-cyan-400 bg-cyan-950/60 border border-cyan-800/60 px-1.5 py-0.5 rounded">
                      {f.confidence} Confidence
                    </span>
                  </div>

                  <h3 className="text-xs font-semibold text-slate-100 line-clamp-2 leading-snug">
                    {f.title}
                  </h3>

                  <div className="flex items-center justify-between mt-2 pt-2 border-t border-slate-800/60 text-[10px] font-mono text-slate-400">
                    <span>{f.supporting_packet_numbers.length} evidence frames</span>
                    <span className="text-cyan-400 flex items-center gap-0.5">
                      <span>Inspect</span>
                      <ChevronRight className="w-3 h-3" />
                    </span>
                  </div>
                </div>
              );
            })}
          </div>

          {/* Right Column: Finding Detail Inspector */}
          {selectedFinding && (
            <div className="lg:col-span-7 p-5 bg-slate-900/80 border border-slate-800 rounded-xl space-y-5 sticky top-4 shadow-xl">
              {/* Header */}
              <div className="border-b border-slate-800 pb-4 space-y-2">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <StatusBadge status={selectedFinding.severity} type="severity" />
                    <span className="text-xs font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                      {selectedFinding.category}
                    </span>
                    <span className="text-xs font-mono text-slate-500">
                      Rule: {selectedFinding.rule_name}
                    </span>
                  </div>
                  <span className="text-xs font-mono text-cyan-400 bg-cyan-950/60 border border-cyan-800/70 px-2 py-0.5 rounded">
                    Confidence: <strong>{selectedFinding.confidence}</strong>
                  </span>
                </div>

                <h2 className="text-base font-bold text-slate-100 pt-1">
                  {selectedFinding.title}
                </h2>
              </div>

              {/* Observed Facts */}
              <div className="space-y-1.5">
                <div className="text-[10px] uppercase font-mono tracking-wider text-slate-400 font-semibold">
                  Observed Wire Facts
                </div>
                <div className="p-3 bg-slate-950/70 rounded-lg border border-slate-800 text-xs font-mono text-slate-200 leading-relaxed">
                  {selectedFinding.observed_facts}
                </div>
              </div>

              {/* Threshold Rule */}
              <div className="space-y-1.5">
                <div className="text-[10px] uppercase font-mono tracking-wider text-slate-400 font-semibold">
                  Detection Threshold
                </div>
                <div className="p-2.5 bg-slate-950/70 rounded-lg border border-slate-800 text-xs font-mono text-cyan-400">
                  {selectedFinding.threshold_val}
                </div>
              </div>

              {/* Supporting Packet Evidence */}
              {selectedFinding.supporting_packet_numbers.length > 0 && (
                <div className="space-y-2">
                  <div className="text-[10px] uppercase font-mono tracking-wider text-slate-400 font-semibold flex items-center justify-between">
                    <span>Supporting Packet Evidence</span>
                    <span className="text-slate-500 lowercase font-normal">Click any frame to inspect decoded layers</span>
                  </div>
                  <div className="flex flex-wrap gap-1.5 p-3 bg-slate-950/70 rounded-lg border border-slate-800">
                    {selectedFinding.supporting_packet_numbers.slice(0, 16).map((pktNum) => (
                      <button
                        key={pktNum}
                        onClick={() => setSelectedPacketNumber(pktNum)}
                        className="px-2.5 py-1 bg-cyan-950/80 hover:bg-cyan-900 text-cyan-300 border border-cyan-800/80 rounded text-xs font-mono flex items-center gap-1 transition-colors"
                        title={`Inspect packet #${pktNum}`}
                      >
                        <span>#{pktNum}</span>
                        <ExternalLink className="w-2.5 h-2.5 opacity-70" />
                      </button>
                    ))}
                    {selectedFinding.supporting_packet_numbers.length > 16 && (
                      <span className="text-xs text-slate-500 font-mono self-center px-1">
                        +{selectedFinding.supporting_packet_numbers.length - 16} more frames
                      </span>
                    )}
                  </div>
                </div>
              )}

              {/* Explanations & Recommendations Split */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5 text-xs">
                <div className="p-3.5 bg-slate-950/70 rounded-lg border border-slate-800 space-y-1.5">
                  <div className="flex items-center gap-1.5 font-semibold text-amber-400">
                    <HelpCircle className="w-3.5 h-3.5" />
                    <span>Possible Explanations</span>
                  </div>
                  <p className="text-slate-400 leading-relaxed">
                    {selectedFinding.explanations}
                  </p>
                </div>

                <div className="p-3.5 bg-slate-950/70 rounded-lg border border-slate-800 space-y-1.5">
                  <div className="flex items-center gap-1.5 font-semibold text-cyan-400">
                    <Lightbulb className="w-3.5 h-3.5" />
                    <span>Recommended Next Steps</span>
                  </div>
                  <p className="text-slate-400 leading-relaxed">
                    {selectedFinding.recommendations}
                  </p>
                </div>
              </div>

              {/* Observation Limitations */}
              <div className="flex items-start gap-2 p-3 bg-slate-950/40 rounded-lg border border-slate-800/80 text-[11px] text-slate-400 font-mono italic">
                <AlertTriangle className="w-3.5 h-3.5 text-slate-500 flex-shrink-0 mt-0.5" />
                <span><strong>Observation Limitations:</strong> {selectedFinding.limitations}</span>
              </div>
            </div>
          )}
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
