import { useState, useEffect } from 'react';
import { Scan, Vulnerability } from '@/shared/types';
import { getApiUrl, getAuthHeaders } from '@/react-app/lib/api';

export function useScans() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchScans = async () => {
    try {
      const headers = await getAuthHeaders();

      // Don't set loading to true on subsequent fetches to avoid flickering
      const response = await fetch(getApiUrl('/api/scans'), { headers });

      // Check if response is JSON (avoid HTML fallback issues)
      const contentType = response.headers.get('content-type');
      if (!contentType || !contentType.includes('application/json')) {
        throw new Error('Received non-JSON response from API');
      }

      if (!response.ok) throw new Error('Failed to fetch scans');
      const data = await response.json();
      setScans(data);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch scans');
      console.error('Fetch scans error:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchScans();

    const interval = setInterval(() => {
      fetchScans();
    }, 2000); // Poll every 2 seconds to catch status changes quickly

    return () => clearInterval(interval);
  }, []);

  return { scans, loading, error, refetch: fetchScans };
}

export function useScan(id: string | undefined) {
  const [scan, setScan] = useState<Scan | null>(null);
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchScan = async () => {
    if (!id) return;

    try {
      setLoading(true);
      const headers = await getAuthHeaders();

      const [scanRes, vulnRes] = await Promise.all([
        fetch(getApiUrl(`/api/scans/${id}`), { headers }),
        fetch(getApiUrl(`/api/scans/${id}/vulnerabilities`), { headers }),
      ]);

      if (!scanRes.ok || !vulnRes.ok) throw new Error('Failed to fetch scan details');

      const scanData = await scanRes.json();
      const vulnData = await vulnRes.json();

      setScan(scanData);
      setVulnerabilities(vulnData);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch scan');
      console.error('Fetch scan error:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchScan();
    const interval = setInterval(() => {
      fetchScan();
    }, scan?.status === 'running' ? 2000 : 5000); // Poll every 2s if running, 5s if completed
    return () => clearInterval(interval);
  }, [id, scan?.status]);

  return { scan, vulnerabilities, loading, error, refetch: fetchScan };
}
