import { useState, useEffect } from 'react';
import { Scan, Vulnerability } from '@/shared/types';
import { supabase } from '@/react-app/lib/supabase';
import { getApiUrl } from '@/react-app/lib/api';

export function useScans() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchScans = async () => {
    try {
      // Get auth token for user-specific data
      const { data: { session } } = await supabase.auth.getSession();
      const headers: HeadersInit = {};
      if (session?.access_token) {
        headers['Authorization'] = `Bearer ${session.access_token}`;
      }

      // Don't set loading to true on subsequent fetches to avoid flickering
      const response = await fetch(getApiUrl('/api/scans'), { headers });

      // Check if response is JSON (avoid HTML fallback issues)
      const contentType = response.headers.get("content-type");
      if (!contentType || !contentType.includes("application/json")) {
        throw new Error("Received non-JSON response from API");
      }

      if (!response.ok) throw new Error('Failed to fetch scans');
      const data = await response.json();
      setScans(data);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch scans');
      console.error("Fetch scans error:", err);
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

      // Get auth token for user-specific data
      const { data: { session } } = await supabase.auth.getSession();
      const headers: HeadersInit = {};
      if (session?.access_token) {
        headers['Authorization'] = `Bearer ${session.access_token}`;
      }

      const [scanRes, vulnRes] = await Promise.all([
        fetch(getApiUrl(`/api/scans/${id}`), { headers }),
        fetch(getApiUrl(`/api/scans/${id}/vulnerabilities`), { headers })
      ]);

      if (!scanRes.ok || !vulnRes.ok) throw new Error('Failed to fetch scan details');

      const scanData = await scanRes.json();
      const vulnData = await vulnRes.json();

      setScan(scanData);
      setVulnerabilities(vulnData);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch scan');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchScan();
    // Poll more frequently when scan is running, less frequently when completed
    const interval = setInterval(() => {
      fetchScan();
    }, scan?.status === 'running' ? 2000 : 5000); // Poll every 2s if running, 5s if completed
    return () => clearInterval(interval);
  }, [id, scan?.status]);

  return { scan, vulnerabilities, loading, error, refetch: fetchScan };
}

export function useDashboardStats() {
  const [stats, setStats] = useState({
    totalScans: 0,
    completedScans: 0,
    runningScans: 0,
    totalVulnerabilities: 0,
    criticalVulnerabilities: 0,
  });
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchStats = async () => {
      try {
        // Get auth token for user-specific data
        const { data: { session } } = await supabase.auth.getSession();
        const headers: HeadersInit = {};
        if (session?.access_token) {
          headers['Authorization'] = `Bearer ${session.access_token}`;
        }

        const response = await fetch(getApiUrl('/api/dashboard/stats'), { headers });
        if (response.ok) {
          // Check content type before parsing
          const contentType = response.headers.get("content-type");
          if (contentType && contentType.includes("application/json")) {
            const data = await response.json();
            setStats(data);
          }
        }
      } catch (err) {
        console.error('Failed to fetch stats:', err);
      } finally {
        setLoading(false);
      }
    };

    fetchStats();
    const interval = setInterval(fetchStats, 5000);
    return () => clearInterval(interval);
  }, []);

  return { stats, loading };
}

