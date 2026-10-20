import React, { useEffect, useState } from 'react';
import { api } from '../lib/api';
import { PacketItem } from '../types';
import { PacketInspector } from './PacketInspector';

interface Props {
  captureId: string;
  packetNumber: number | null;
  onClose: () => void;
}

export const EvidenceModal: React.FC<Props> = ({ captureId, packetNumber, onClose }) => {
  const [packet, setPacket] = useState<PacketItem | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!packetNumber) return;
    setLoading(true);
    setError(null);
    api.getPacket(captureId, packetNumber)
      .then(setPacket)
      .catch((err) => setError(err.message || 'Failed to load packet details.'))
      .finally(() => setLoading(false));
  }, [captureId, packetNumber]);

  if (!packetNumber) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-in fade-in duration-150">
      <div className="relative w-full max-w-4xl h-[85vh] flex flex-col bg-slate-900 border border-slate-800 rounded-xl shadow-2xl overflow-hidden">
        {error ? (
          <div className="p-6 text-rose-400 bg-rose-950/20 border border-rose-800 rounded m-4">
            {error}
          </div>
        ) : (
          <PacketInspector packet={packet} loading={loading} onClose={onClose} />
        )}
      </div>
    </div>
  );
};
