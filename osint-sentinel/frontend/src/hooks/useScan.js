import { useState, useCallback } from 'react';
import { runScan, checkHealth } from '../utils/api';

export function useScan() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [scanHistory, setScanHistory] = useState([]);

  const scan = useCallback(async (target) => {
    setLoading(true);
    setError(null);
    setData(null);
    try {
      const result = await runScan(target);
      setData(result);
      setScanHistory(prev => {
        // Deduplicate by target, keep newest, cap at 10
        const filtered = prev.filter(h => h.target !== result.target);
        return [result, ...filtered].slice(0, 10);
      });
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }, []);

  const reset = useCallback(() => {
    setData(null);
    setError(null);
  }, []);

  const clearHistory = useCallback(() => {
    setScanHistory([]);
  }, []);

  return { data, loading, error, scan, reset, scanHistory, clearHistory };
}

export function useHealth() {
  const [health, setHealth] = useState(null);

  const check = useCallback(async () => {
    try {
      const result = await checkHealth();
      setHealth(result);
    } catch (e) {
      setHealth({ status: 'error', error: e.message });
    }
  }, []);

  return { health, check };
}
