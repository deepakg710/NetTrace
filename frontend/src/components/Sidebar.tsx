import React from 'react';
import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard,
  UploadCloud,
  FileCode2,
  Network,
  GitCompare,
  Share2,
  Globe2,
  ShieldAlert,
  FileText,
  Settings,
  Activity
} from 'lucide-react';
import { useCapture } from '../context/CaptureContext';

const navItems = [
  { to: '/', label: 'Overview', icon: LayoutDashboard },
  { to: '/captures', label: 'Captures & Upload', icon: UploadCloud },
  { to: '/packets', label: 'Packet Explorer', icon: FileCode2 },
  { to: '/endpoints', label: 'Endpoints', icon: Network },
  { to: '/flows', label: 'Flow Explorer', icon: GitCompare },
  { to: '/topology', label: 'Topology', icon: Share2 },
  { to: '/dns', label: 'DNS Analysis', icon: Globe2 },
  { to: '/findings', label: 'Findings & Diagnostics', icon: ShieldAlert },
  { to: '/reports', label: 'Reports & Export', icon: FileText },
  { to: '/settings', label: 'Settings & About', icon: Settings },
];

export const Sidebar: React.FC = () => {
  const { activeCapture } = useCapture();

  return (
    <aside className="w-64 bg-slate-900 border-r border-slate-800 flex flex-col h-screen select-none">
      {/* Brand */}
      <div className="h-16 px-6 flex items-center gap-3 border-b border-slate-800">
        <div className="w-9 h-9 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
          <Activity className="w-5 h-5 animate-pulse" />
        </div>
        <div>
          <span className="font-bold text-base tracking-wide text-slate-100 flex items-center gap-1.5">
            NET<span className="text-cyan-400">TRACE</span>
          </span>
          <span className="text-[10px] font-mono text-slate-500 uppercase tracking-wider block">Packet Toolkit</span>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
        {navItems.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            className={({ isActive }) =>
              `flex items-center gap-3 px-3 py-2.5 rounded-lg text-xs font-medium transition-all ${
                isActive
                  ? 'bg-cyan-500/10 text-cyan-300 border border-cyan-500/30 font-semibold'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`
            }
          >
            <item.icon className="w-4 h-4 flex-shrink-0" />
            <span>{item.label}</span>
          </NavLink>
        ))}
      </nav>

      {/* Active Capture Footer Status */}
      <div className="p-4 border-t border-slate-800 bg-slate-950/60">
        <div className="text-[10px] font-mono text-slate-500 uppercase tracking-wider mb-1">
          Active Workspace
        </div>
        {activeCapture ? (
          <div className="truncate">
            <div className="text-xs font-mono font-medium text-slate-200 truncate" title={activeCapture.original_filename}>
              {activeCapture.original_filename}
            </div>
            <div className="text-[11px] text-cyan-400 font-mono mt-0.5">
              {activeCapture.packet_count.toLocaleString()} pkts • {activeCapture.duration_seconds.toFixed(2)}s
            </div>
          </div>
        ) : (
          <div className="text-xs text-slate-500 italic">No capture loaded</div>
        )}
      </div>
    </aside>
  );
};
