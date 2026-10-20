import React from 'react';
import { LucideIcon } from 'lucide-react';

interface MetricCardProps {
  title: string;
  value: string | number;
  subtext?: string;
  icon: LucideIcon;
  color?: 'cyan' | 'blue' | 'amber' | 'rose' | 'emerald' | 'purple' | 'indigo';
  onClick?: () => void;
}

const colorMap = {
  cyan: {
    border: 'border-cyan-500/20',
    bg: 'bg-cyan-500/5',
    iconBg: 'bg-cyan-500/10 text-cyan-400',
    val: 'text-cyan-400',
  },
  blue: {
    border: 'border-blue-500/20',
    bg: 'bg-blue-500/5',
    iconBg: 'bg-blue-500/10 text-blue-400',
    val: 'text-blue-400',
  },
  amber: {
    border: 'border-amber-500/20',
    bg: 'bg-amber-500/5',
    iconBg: 'bg-amber-500/10 text-amber-400',
    val: 'text-amber-400',
  },
  rose: {
    border: 'border-rose-500/20',
    bg: 'bg-rose-500/5',
    iconBg: 'bg-rose-500/10 text-rose-400',
    val: 'text-rose-400',
  },
  emerald: {
    border: 'border-emerald-500/20',
    bg: 'bg-emerald-500/5',
    iconBg: 'bg-emerald-500/10 text-emerald-400',
    val: 'text-emerald-400',
  },
  purple: {
    border: 'border-purple-500/20',
    bg: 'bg-purple-500/5',
    iconBg: 'bg-purple-500/10 text-purple-400',
    val: 'text-purple-400',
  },
  indigo: {
    border: 'border-indigo-500/20',
    bg: 'bg-indigo-500/5',
    iconBg: 'bg-indigo-500/10 text-indigo-400',
    val: 'text-indigo-400',
  },
};

export const MetricCard: React.FC<MetricCardProps> = ({
  title,
  value,
  subtext,
  icon: Icon,
  color = 'cyan',
  onClick,
}) => {
  const scheme = colorMap[color] || colorMap.cyan;

  return (
    <div
      onClick={onClick}
      className={`p-4 rounded-xl border ${scheme.border} ${scheme.bg} bg-slate-900/60 backdrop-blur-sm relative overflow-hidden transition-all ${
        onClick ? 'cursor-pointer hover:border-cyan-500/50 hover:bg-slate-900/90' : 'hover:border-slate-700'
      }`}
    >
      <div className="flex items-center justify-between">
        <div>
          <p className="text-xs font-medium text-slate-400 uppercase tracking-wider">{title}</p>
          <p className={`text-2xl font-bold font-mono mt-1 ${scheme.val}`}>
            {value}
          </p>
          {subtext && <p className="text-xs text-slate-500 mt-1">{subtext}</p>}
        </div>
        <div className={`p-3 rounded-lg ${scheme.iconBg}`}>
          <Icon className="w-5 h-5" />
        </div>
      </div>
    </div>
  );
};
