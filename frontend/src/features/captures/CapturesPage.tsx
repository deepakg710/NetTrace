import React, { useState, useRef } from 'react';
import { useCapture } from '../../context/CaptureContext';
import { StatusBadge } from '../../components/StatusBadge';
import { api } from '../../lib/api';
import {
  UploadCloud,
  FileCheck,
  Trash2,
  RefreshCw,
  FolderOpen,
  AlertCircle,
  FileCode,
  Sparkles
} from 'lucide-react';
import { useNavigate } from 'react-router-dom';

export const CapturesPage: React.FC = () => {
  const { captures, activeCaptureId, selectCapture, refreshCaptures, deleteCapture } = useCapture();
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const navigate = useNavigate();

  const handleUpload = async (file: File) => {
    const ext = file.name.substring(file.name.lastIndexOf('.')).toLowerCase();
    if (ext !== '.pcap' && ext !== '.pcapng') {
      setError(`Invalid file type "${ext}". Only .pcap and .pcapng files are supported.`);
      return;
    }

    if (file.size > 100 * 1024 * 1024) {
      setError('File exceeds the maximum upload limit of 100 MB.');
      return;
    }

    try {
      setUploading(true);
      setError(null);
      setSuccessMsg(null);
      const newCapture = await api.uploadCapture(file);
      await refreshCaptures();
      await selectCapture(newCapture.id);
      setSuccessMsg(`Capture "${file.name}" uploaded and analyzed successfully.`);
    } catch (err: any) {
      setError(err.message || 'Upload failed.');
    } finally {
      setUploading(false);
    }
  };

  const onDrop = (e: React.DragEvent) => {
    e.preventDefault();
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      handleUpload(e.dataTransfer.files[0]);
    }
  };



  return (
    <div className="space-y-8 max-w-6xl mx-auto animate-in fade-in duration-200">
      {/* Title */}
      <div>
        <h1 className="text-2xl font-bold text-slate-100">Packet Captures & Ingestion</h1>
        <p className="text-xs text-slate-400 font-mono mt-1">
          Upload PCAP/PCAPNG captures for offline protocol parsing and diagnostic correlation.
        </p>
      </div>

      {/* Messages */}
      {error && (
        <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-400 text-xs flex items-center gap-2">
          <AlertCircle className="w-4 h-4 flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}
      {successMsg && (
        <div className="p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-xs flex items-center gap-2">
          <FileCheck className="w-4 h-4 flex-shrink-0" />
          <span>{successMsg}</span>
        </div>
      )}

      {/* Drag & Drop Upload Zone */}
      <div
        onDragOver={(e) => e.preventDefault()}
        onDrop={onDrop}
        onClick={() => fileInputRef.current?.click()}
        className={`p-10 border-2 border-dashed rounded-2xl flex flex-col items-center justify-center cursor-pointer transition-all ${
          uploading
            ? 'border-cyan-500/50 bg-cyan-950/20'
            : 'border-slate-800 hover:border-cyan-500/40 bg-slate-900/40 hover:bg-slate-900/60'
        }`}
      >
        <input
          ref={fileInputRef}
          type="file"
          accept=".pcap,.pcapng"
          className="hidden"
          onChange={(e) => {
            if (e.target.files && e.target.files.length > 0) {
              handleUpload(e.target.files[0]);
            }
          }}
        />

        <div className="p-4 rounded-full bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 mb-4">
          <UploadCloud className="w-8 h-8" />
        </div>

        {uploading ? (
          <div className="text-center space-y-2">
            <p className="text-sm font-semibold text-cyan-300">Uploading and Analyzing Capture...</p>
            <p className="text-xs text-slate-400 font-mono">Parsing frames and correlating TCP/DNS streams</p>
          </div>
        ) : (
          <div className="text-center space-y-2">
            <p className="text-sm font-semibold text-slate-200">
              Click to select or drag and drop PCAP / PCAPNG file here
            </p>
            <p className="text-xs text-slate-500 font-mono">
              Accepted extensions: <span className="text-cyan-400">.pcap</span>, <span className="text-cyan-400">.pcapng</span> • Maximum size: 100 MB
            </p>
          </div>
        )}
      </div>

      {/* Sample Capture Quick-Load */}
      <div className="p-5 bg-slate-900/60 border border-slate-800 rounded-xl space-y-3">
        <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-slate-300">
          <Sparkles className="w-4 h-4 text-cyan-400" />
          <span>Deterministic Demo & Verification Samples</span>
        </div>
        <p className="text-xs text-slate-400">
          Need a sample to test without live sniffing? Choose a pre-generated synthetic capture:
        </p>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-2">
          <div className="p-3 bg-slate-950/60 border border-slate-800 rounded-lg flex items-center justify-between">
            <div>
              <div className="text-xs font-semibold text-slate-200">Normal Baseline Traffic</div>
              <div className="text-[11px] font-mono text-slate-500">10 pkts • Clean DNS & HTTP Handshake</div>
            </div>
            <button
              onClick={async () => {
                try {
                  setUploading(true);
                  setError(null);
                  const res = await fetch('/samples/normal_traffic.pcap');
                  const blob = await res.blob();
                  const file = new File([blob], 'normal_traffic.pcap', { type: 'application/vnd.tcpdump.pcap' });
                  await handleUpload(file);
                  navigate('/');
                } catch (e: any) {
                  setError(e.message);
                } finally {
                  setUploading(false);
                }
              }}
              className="px-3 py-1 bg-slate-800 hover:bg-slate-700 text-cyan-400 text-xs font-mono rounded transition-colors"
            >
              1-Click Load
            </button>
          </div>

          <div className="p-3 bg-slate-950/60 border border-slate-800 rounded-lg flex items-center justify-between">
            <div>
              <div className="text-xs font-semibold text-slate-200">Incident Troubleshooting</div>
              <div className="text-[11px] font-mono text-slate-500">42 pkts • Resets, Scans, Incomplete Handshakes</div>
            </div>
            <button
              onClick={async () => {
                try {
                  setUploading(true);
                  setError(null);
                  const res = await fetch('/samples/incident_troubleshooting.pcap');
                  const blob = await res.blob();
                  const file = new File([blob], 'incident_troubleshooting.pcap', { type: 'application/vnd.tcpdump.pcap' });
                  await handleUpload(file);
                  navigate('/');
                } catch (e: any) {
                  setError(e.message);
                } finally {
                  setUploading(false);
                }
              }}
              className="px-3 py-1 bg-cyan-600 hover:bg-cyan-500 text-slate-950 text-xs font-mono font-semibold rounded transition-colors"
            >
              1-Click Load
            </button>
          </div>
        </div>
      </div>

      {/* Capture History Table */}
      <div className="p-5 bg-slate-900/60 border border-slate-800 rounded-xl space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-sm font-semibold text-slate-200">Capture History & Saved Analyses</h3>
            <p className="text-xs text-slate-500 font-mono">Locally persisted SQLite capture records</p>
          </div>
          <button
            onClick={() => refreshCaptures()}
            className="p-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-xs transition-colors"
            title="Refresh history"
          >
            <RefreshCw className="w-3.5 h-3.5" />
          </button>
        </div>

        {captures.length === 0 ? (
          <div className="text-center py-8 text-xs text-slate-500 font-mono italic">
            No captures stored in database yet.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 font-mono">
                  <th className="pb-3 px-3">Filename</th>
                  <th className="pb-3 px-3">Format</th>
                  <th className="pb-3 px-3">Status</th>
                  <th className="pb-3 px-3 text-right">Packets</th>
                  <th className="pb-3 px-3 text-right">Duration</th>
                  <th className="pb-3 px-3">Uploaded</th>
                  <th className="pb-3 px-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono">
                {captures.map((c) => {
                  const isActive = c.id === activeCaptureId;
                  return (
                    <tr
                      key={c.id}
                      className={`hover:bg-slate-800/40 transition-colors ${
                        isActive ? 'bg-cyan-500/5 border-l-2 border-cyan-400' : ''
                      }`}
                    >
                      <td className="py-3 px-3 font-medium text-slate-200 flex items-center gap-2">
                        <FileCode className="w-4 h-4 text-cyan-400 flex-shrink-0" />
                        <span className="truncate max-w-xs">{c.original_filename}</span>
                        {isActive && (
                          <span className="text-[10px] bg-cyan-500/20 text-cyan-300 px-1.5 py-0.2 rounded font-sans">
                            Active
                          </span>
                        )}
                      </td>
                      <td className="py-3 px-3 text-slate-400">{c.format.toUpperCase()}</td>
                      <td className="py-3 px-3">
                        <StatusBadge status={c.status} type="state" />
                      </td>
                      <td className="py-3 px-3 text-right text-slate-300">{c.packet_count.toLocaleString()}</td>
                      <td className="py-3 px-3 text-right text-slate-400">{c.duration_seconds.toFixed(2)}s</td>
                      <td className="py-3 px-3 text-slate-400 text-[11px]">
                        {new Date(c.upload_time).toLocaleString()}
                      </td>
                      <td className="py-3 px-3 text-right">
                        <div className="flex items-center justify-end gap-2">
                          <button
                            onClick={() => {
                              selectCapture(c.id);
                              navigate('/');
                            }}
                            className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-cyan-300 rounded text-xs transition-colors flex items-center gap-1"
                            title="Open capture in dashboard"
                          >
                            <FolderOpen className="w-3.5 h-3.5" />
                            <span>Open</span>
                          </button>
                          <button
                            onClick={() => {
                              if (confirm(`Delete capture "${c.original_filename}" and its database records?`)) {
                                deleteCapture(c.id);
                              }
                            }}
                            className="p-1 hover:bg-rose-500/10 text-slate-500 hover:text-rose-400 rounded transition-colors"
                            title="Delete capture"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
