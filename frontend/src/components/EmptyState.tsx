import React from 'react';
import { LucideIcon, Inbox } from 'lucide-react';

interface Props {
  title: string;
  description: string;
  icon?: LucideIcon;
  actionText?: string;
  onAction?: () => void;
}

export const EmptyState: React.FC<Props> = ({
  title,
  description,
  icon: Icon = Inbox,
  actionText,
  onAction,
}) => {
  return (
    <div className="flex flex-col items-center justify-center p-12 text-center border border-dashed border-slate-800 rounded-2xl bg-slate-900/30">
      <div className="p-4 rounded-full bg-slate-800/60 text-slate-400 mb-4 border border-slate-700/50">
        <Icon className="w-8 h-8 text-cyan-400" />
      </div>
      <h3 className="text-lg font-semibold text-slate-200 mb-1">{title}</h3>
      <p className="text-sm text-slate-400 max-w-md mb-6">{description}</p>
      {actionText && onAction && (
        <button
          onClick={onAction}
          className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-semibold text-xs rounded-lg transition-all shadow-lg shadow-cyan-600/20"
        >
          {actionText}
        </button>
      )}
    </div>
  );
};
