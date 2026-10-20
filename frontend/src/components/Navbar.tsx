import React, { useEffect, useRef, useState } from 'react';
import { useCapture } from '../context/CaptureContext';
import { RefreshCw, CheckCircle2, AlertCircle, HardDrive, UploadCloud, Search } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { api } from '../lib/api';
import { validateDisplayFilter } from '../lib/displayFilter';

export const Navbar: React.FC = () => {
  const { captures, activeCaptureId, selectCapture, refreshCaptures } = useCapture();
  const [healthy, setHealthy] = useState<boolean | null>(null);
  const [reanalyzing, setReanalyzing] = useState(false);
  const [globalQuery, setGlobalQuery] = useState('');
  const searchInputRef = useRef<HTMLInputElement>(null);
  const navigate = useNavigate();

  useEffect(() => {
    api.getHealth()
      .then((h) => setHealthy(h.database_ok))
      .catch(() => setHealthy(false));
  }, []);

  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        searchInputRef.current?.focus();
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, []);

  const handleGlobalSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const q = globalQuery.trim();
    if (!q) return;

    // Check if it's a valid display filter expression
    const v = validateDisplayFilter(q);
    if (v.valid && (q.includes('==') || q.includes('!=') || q.includes('&&') || q.includes('||') || q.includes('.') || ['tcp', 'udp', 'dns', 'icmp', 'arp', 'http', 'tls'].includes(q.toLowerCase()))) {
      navigate(`/packets?display_filter=${encodeURIComponent(q)}`);
      return;
    }

    // Check if it looks like an IPv4 address
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(q)) {
      navigate(`/packets?display_filter=${encodeURIComponent(`ip.addr == ${q}`)}`);
      return;
    }

    // Check if it looks like a numeric port
    if (/^\d{1,5}$/.test(q) && Number(q) >= 1 && Number(q) <= 65535) {
      navigate(`/packets?display_filter=${encodeURIComponent(`port == ${q}`)}`);
      return;
    }

    // Otherwise run as text search in Packet Explorer
    navigate(`/packets?search=${encodeURIComponent(q)}`);
  };

  const handleReanalyze = async () => {
    if (!activeCaptureId) return;
    try {
      setReanalyzing(true);
      await api.reanalyzeCapture(activeCaptureId);
      await refreshCaptures();
    } catch (err) {
      console.error(err);
    } finally {
      setReanalyzing(false);
    }
  };

  return (
    <header className="h-16 px-6 bg-slate-900/80 backdrop-blur-md border-b border-slate-800 flex items-center justify-between gap-4 z-10">
      {/* Active Capture Selector */}
      <div className="flex items-center gap-3">
        <HardDrive className="w-4 h-4 text-slate-400" />
        <span className="text-xs text-slate-400 font-mono hidden sm:inline">Capture:</span>
        <select
          value={activeCaptureId || ''}
          onChange={(e) => {
            if (e.target.value) selectCapture(e.target.value);
          }}
          className="bg-slate-950 border border-slate-700/80 text-slate-200 text-xs font-mono rounded-lg px-3 py-1.5 focus:outline-none focus:border-cyan-500 max-w-xs truncate"
        >
          {captures.length === 0 ? (
            <option value="">No captures available</option>
          ) : (
            captures.map((c) => (
              <option key={c.id} value={c.id}>
                {c.original_filename} ({c.packet_count} pkts)
              </option>
            ))
          )}
        </select>

        {activeCaptureId && (
          <button
            onClick={handleReanalyze}
            disabled={reanalyzing}
            title="Re-run analysis algorithms"
            className="p-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-xs flex items-center gap-1.5 transition-colors disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${reanalyzing ? 'animate-spin text-cyan-400' : ''}`} />
            <span className="hidden md:inline text-[11px]">Re-analyze</span>
          </button>
        )}
      </div>

      {/* Global Search Bar (Ctrl+K) */}
      <form onSubmit={handleGlobalSearchSubmit} className="hidden lg:flex items-center flex-1 max-w-md relative">
        <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 pointer-events-none" />
        <input
          ref={searchInputRef}
          type="text"
          value={globalQuery}
          onChange={(e) => setGlobalQuery(e.target.value)}
          placeholder="Quick search IP, port, display filter, or domain (Ctrl+K)..."
          aria-label="Global packet and endpoint search"
          className="w-full bg-slate-950/90 border border-slate-800 focus:border-cyan-500/70 rounded-lg pl-8 pr-14 py-1.5 text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none transition-colors"
        />
        <kbd className="absolute right-2.5 px-1.5 py-0.5 text-[10px] font-mono text-slate-400 bg-slate-900 border border-slate-700 rounded">
          Ctrl+K
        </kbd>
      </form>

      {/* Right actions: Backend status & Upload CTA */}
      <div className="flex items-center gap-4">
        <div className="flex items-center gap-1.5 text-xs font-mono text-slate-400">
          {healthy === true ? (
            <span className="flex items-center gap-1 text-emerald-400">
              <CheckCircle2 className="w-3.5 h-3.5" /> Engine Active
            </span>
          ) : healthy === false ? (
            <span className="flex items-center gap-1 text-rose-400">
              <AlertCircle className="w-3.5 h-3.5" /> Engine Offline
            </span>
          ) : (
            <span className="text-slate-500">Connecting...</span>
          )}
        </div>

        <button
          onClick={() => navigate('/captures')}
          className="flex items-center gap-1.5 px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-semibold text-xs rounded-lg transition-all shadow-md shadow-cyan-600/20"
        >
          <UploadCloud className="w-3.5 h-3.5" />
          <span>Upload PCAP</span>
        </button>
      </div>
    </header>
  );
};

