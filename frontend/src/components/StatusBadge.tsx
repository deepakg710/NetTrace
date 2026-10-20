import React from 'react';

interface Props {
  status: string;
  type?: 'severity' | 'state' | 'format';
}

export const StatusBadge: React.FC<Props> = ({ status, type = 'severity' }) => {
  let colorClasses = 'bg-slate-800 text-slate-300 border-slate-700';

  if (type === 'severity') {
    switch (status) {
      case 'Critical':
        colorClasses = 'bg-red-500/10 text-red-400 border-red-500/30';
        break;
      case 'High':
        colorClasses = 'bg-rose-500/10 text-rose-400 border-rose-500/30';
        break;
      case 'Medium':
        colorClasses = 'bg-amber-500/10 text-amber-400 border-amber-500/30';
        break;
      case 'Low':
        colorClasses = 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30';
        break;
      case 'Informational':
        colorClasses = 'bg-blue-500/10 text-blue-400 border-blue-500/30';
        break;
    }
  } else if (type === 'state') {
    switch (status) {
      case 'ESTABLISHED':
      case 'CLOSED_CLEAN':
      case 'completed':
        colorClasses = 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30';
        break;
      case 'INCOMPLETE_HANDSHAKE':
      case 'RESET':
      case 'failed':
        colorClasses = 'bg-rose-500/10 text-rose-400 border-rose-500/30';
        break;
      case 'analyzing':
      case 'uploaded':
        colorClasses = 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30 animate-pulse';
        break;
      case 'partial':
        colorClasses = 'bg-amber-500/10 text-amber-400 border-amber-500/30';
        break;
      default:
        colorClasses = 'bg-slate-800 text-slate-300 border-slate-700';
    }
  }

  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border font-mono ${colorClasses}`}>
      {status}
    </span>
  );
};
