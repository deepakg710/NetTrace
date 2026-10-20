import React from 'react';

export const LoadingSpinner: React.FC<{ message?: string }> = ({ message = 'Loading capture data...' }) => {
  return (
    <div className="flex flex-col items-center justify-center p-16 space-y-4">
      <div className="relative w-12 h-12">
        <div className="absolute inset-0 rounded-full border-2 border-slate-800"></div>
        <div className="absolute inset-0 rounded-full border-2 border-cyan-400 border-t-transparent animate-spin"></div>
      </div>
      <p className="text-sm font-mono text-slate-400">{message}</p>
    </div>
  );
};
