import React, { useState, useEffect } from 'react';
import { api } from '../../lib/api';
import { DetectorSettings } from '../../types';
import {
  Save,
  CheckCircle2,
  AlertCircle,
  Shield,
  Sliders
} from 'lucide-react';

export const SettingsPage: React.FC = () => {
  const [settings, setSettings] = useState<DetectorSettings>({
    port_scan_threshold: 15,
    host_scan_threshold: 10,
    connection_burst_threshold: 20,
    burst_window_seconds: 2.0,
    repeated_dns_query_threshold: 5,
    periodic_connection_min_count: 4,
    periodic_cv_threshold: 0.2,
    traffic_rate_spike_pps: 100.0,
  });

  const [saving, setSaving] = useState(false);
  const [saveSuccess, setSaveSuccess] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.getSettings()
      .then(setSettings)
      .catch((err) => setError(err.message));
  }, []);

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    setError(null);
    setSaveSuccess(false);
    try {
      const updated = await api.updateSettings(settings);
      setSettings(updated);
      setSaveSuccess(true);
      setTimeout(() => setSaveSuccess(false), 3000);
    } catch (err: any) {
      setError(err.message || 'Failed to save settings.');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="space-y-8 max-w-4xl mx-auto animate-in fade-in duration-200">
      {/* Title */}
      <div>
        <h1 className="text-2xl font-bold text-slate-100">Settings & Methodology</h1>
        <p className="text-xs text-slate-400 font-mono mt-1">
          Configure diagnostic heuristic thresholds, threat model boundaries, and application defaults.
        </p>
      </div>

      {/* Notifications */}
      {error && (
        <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-400 text-xs flex items-center gap-2">
          <AlertCircle className="w-4 h-4 flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}
      {saveSuccess && (
        <div className="p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-xs flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 flex-shrink-0" />
          <span>Heuristic thresholds updated and persisted to SQLite successfully.</span>
        </div>
      )}

      {/* Threshold Configuration Form */}
      <form onSubmit={handleSave} className="p-6 bg-slate-900/60 border border-slate-800 rounded-xl space-y-6">
        <div className="flex items-center gap-2 border-b border-slate-800 pb-3">
          <Sliders className="w-5 h-5 text-cyan-400" />
          <h2 className="text-base font-semibold text-slate-100">Detection Heuristic Thresholds</h2>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
          {/* Port Scan */}
          <div className="space-y-1.5">
            <label className="text-xs font-semibold text-slate-300 block">
              Port-Scan Threshold (Distinct Ports)
            </label>
            <input
              type="number"
              min="2"
              max="500"
              value={settings.port_scan_threshold}
              onChange={(e) => setSettings({ ...settings, port_scan_threshold: parseInt(e.target.value) || 15 })}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
            />
            <p className="text-[11px] text-slate-500">
              Flags single source IP contacting &ge; N distinct destination ports on a host. Default: 15.
            </p>
          </div>

          {/* Host Scan */}
          <div className="space-y-1.5">
            <label className="text-xs font-semibold text-slate-300 block">
              Host-Scan Threshold (Distinct Target IPs)
            </label>
            <input
              type="number"
              min="2"
              max="500"
              value={settings.host_scan_threshold}
              onChange={(e) => setSettings({ ...settings, host_scan_threshold: parseInt(e.target.value) || 10 })}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
            />
            <p className="text-[11px] text-slate-500">
              Flags single source IP contacting &ge; N distinct destination IP addresses. Default: 10.
            </p>
          </div>

          {/* Connection Burst */}
          <div className="space-y-1.5">
            <label className="text-xs font-semibold text-slate-300 block">
              Connection Burst Packet Count
            </label>
            <input
              type="number"
              min="2"
              max="1000"
              value={settings.connection_burst_threshold}
              onChange={(e) => setSettings({ ...settings, connection_burst_threshold: parseInt(e.target.value) || 20 })}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
            />
            <p className="text-[11px] text-slate-500">
              Number of packets required to trigger a high-rate connection burst finding. Default: 20.
            </p>
          </div>

          {/* Burst Window */}
          <div className="space-y-1.5">
            <label className="text-xs font-semibold text-slate-300 block">
              Burst Window Interval (Seconds)
            </label>
            <input
              type="number"
              step="0.5"
              min="0.1"
              max="60"
              value={settings.burst_window_seconds}
              onChange={(e) => setSettings({ ...settings, burst_window_seconds: parseFloat(e.target.value) || 2.0 })}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
            />
            <p className="text-[11px] text-slate-500">
              Sliding observation window duration for burst detection. Default: 2.0s.
            </p>
          </div>

          {/* Repeated DNS Query */}
          <div className="space-y-1.5">
            <label className="text-xs font-semibold text-slate-300 block">
              Repeated DNS Query Threshold
            </label>
            <input
              type="number"
              min="2"
              max="200"
              value={settings.repeated_dns_query_threshold}
              onChange={(e) => setSettings({ ...settings, repeated_dns_query_threshold: parseInt(e.target.value) || 5 })}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
            />
            <p className="text-[11px] text-slate-500">
              Flags domain queried &ge; N times in the capture session. Default: 5.
            </p>
          </div>

          {/* Periodic Connections Min Count */}
          <div className="space-y-1.5">
            <label className="text-xs font-semibold text-slate-300 block">
              Periodic Connection Minimum Count
            </label>
            <input
              type="number"
              min="3"
              max="50"
              value={settings.periodic_connection_min_count}
              onChange={(e) => setSettings({ ...settings, periodic_connection_min_count: parseInt(e.target.value) || 4 })}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
            />
            <p className="text-[11px] text-slate-500">
              Minimum connection count to compute interval coefficient of variation. Default: 4.
            </p>
          </div>
        </div>

        <div className="pt-4 border-t border-slate-800 flex justify-end">
          <button
            type="submit"
            disabled={saving}
            className="px-5 py-2 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold text-xs rounded-lg transition-colors flex items-center gap-2 disabled:opacity-50 shadow-md shadow-cyan-600/20"
          >
            <Save className="w-4 h-4" />
            <span>{saving ? 'Saving...' : 'Save Detector Settings'}</span>
          </button>
        </div>
      </form>

      {/* System Information & Threat Model */}
      <div className="p-6 bg-slate-900/60 border border-slate-800 rounded-xl space-y-4">
        <div className="flex items-center gap-2 border-b border-slate-800 pb-3">
          <Shield className="w-5 h-5 text-cyan-400" />
          <h2 className="text-base font-semibold text-slate-100">Architecture & Threat Model</h2>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
          <div className="p-3 bg-slate-950/60 rounded-lg border border-slate-800/80 space-y-1">
            <span className="font-semibold text-slate-300 block">Offline Local Execution</span>
            <p className="text-slate-400 leading-relaxed">
              NetTrace runs strictly on localhost. No network packets or captured payload content are transmitted to external servers, cloud AI providers, or telemetry sinks.
            </p>
          </div>

          <div className="p-3 bg-slate-950/60 rounded-lg border border-slate-800/80 space-y-1">
            <span className="font-semibold text-slate-300 block">Input Sanitization & Storage</span>
            <p className="text-slate-400 leading-relaxed">
              Uploaded files are stored with random UUID identifiers in dedicated data folders to prevent path traversal. Header magic bytes are validated before Scapy parser initialization.
            </p>
          </div>

          <div className="p-3 bg-slate-950/60 rounded-lg border border-slate-800/80 space-y-1">
            <span className="font-semibold text-slate-300 block">No Live Sniffing Privileges</span>
            <p className="text-slate-400 leading-relaxed">
              The application explicitly operates in offline PCAP parsing mode and does not require administrative or promiscuous interface capture privileges.
            </p>
          </div>

          <div className="p-3 bg-slate-950/60 rounded-lg border border-slate-800/80 space-y-1">
            <span className="font-semibold text-slate-300 block">Explainable Heuristics</span>
            <p className="text-slate-400 leading-relaxed">
              Every finding traces back to verifiable packet indices, timestamps, and explicit detection rules. Findings clearly state observation limitations and avoid unsubstantiated accusations.
            </p>
          </div>
        </div>

        <div className="pt-3 border-t border-slate-800 flex items-center justify-between text-xs text-slate-500 font-mono">
          <span>NetTrace Engine v1.0.0</span>
          <span>FastAPI • Scapy • SQLite • ReportLab • React</span>
        </div>
      </div>
    </div>
  );
};
