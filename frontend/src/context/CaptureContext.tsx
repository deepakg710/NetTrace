import React, { createContext, useContext, useState, useEffect } from 'react';
import { CaptureItem, CaptureDetail } from '../types';
import { api } from '../lib/api';

interface CaptureContextType {
  captures: CaptureItem[];
  activeCapture: CaptureDetail | null;
  activeCaptureId: string | null;
  loading: boolean;
  error: string | null;
  selectCapture: (id: string) => Promise<void>;
  refreshCaptures: () => Promise<void>;
  deleteCapture: (id: string) => Promise<void>;
}

const CaptureContext = createContext<CaptureContextType | undefined>(undefined);

export const CaptureProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [captures, setCaptures] = useState<CaptureItem[]>([]);
  const [activeCapture, setActiveCapture] = useState<CaptureDetail | null>(null);
  const [activeCaptureId, setActiveCaptureId] = useState<string | null>(() => {
    return localStorage.getItem('nettrace_active_capture_id');
  });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const refreshCaptures = async () => {
    try {
      setLoading(true);
      setError(null);
      const list = await api.getCaptures();
      setCaptures(list);

      if (list.length > 0) {
        // If current active is still in list, keep it, otherwise pick the first
        const exists = list.find((c) => c.id === activeCaptureId);
        const targetId = exists ? exists.id : list[0].id;
        setActiveCaptureId(targetId);
        localStorage.setItem('nettrace_active_capture_id', targetId);
        const detail = await api.getCapture(targetId);
        setActiveCapture(detail);
      } else {
        setActiveCaptureId(null);
        setActiveCapture(null);
        localStorage.removeItem('nettrace_active_capture_id');
      }
    } catch (err: any) {
      setError(err.message || 'Failed to fetch captures.');
    } finally {
      setLoading(false);
    }
  };

  const selectCapture = async (id: string) => {
    try {
      setLoading(true);
      const detail = await api.getCapture(id);
      setActiveCapture(detail);
      setActiveCaptureId(id);
      localStorage.setItem('nettrace_active_capture_id', id);
    } catch (err: any) {
      setError(err.message || 'Failed to select capture.');
    } finally {
      setLoading(false);
    }
  };

  const deleteCapture = async (id: string) => {
    try {
      await api.deleteCapture(id);
      await refreshCaptures();
    } catch (err: any) {
      setError(err.message || 'Failed to delete capture.');
    }
  };

  useEffect(() => {
    refreshCaptures();
  }, []);

  return (
    <CaptureContext.Provider
      value={{
        captures,
        activeCapture,
        activeCaptureId,
        loading,
        error,
        selectCapture,
        refreshCaptures,
        deleteCapture,
      }}
    >
      {children}
    </CaptureContext.Provider>
  );
};

export const useCapture = () => {
  const context = useContext(CaptureContext);
  if (!context) {
    throw new Error('useCapture must be used within a CaptureProvider');
  }
  return context;
};
