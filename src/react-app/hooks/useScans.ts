import { useState, useEffect } from 'react';
import { Scan, Vulnerability } from '@/shared/types';

export function useScans() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchScans = async () => {
    try {
      setLoading(true);
      const response = await fetch('/api/scans');
      if (!response.ok) throw new Error('Failed to fetch scans');
      const data = await response.json();
      setScans(data);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch scans');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchScans();
    const interval = setInterval(fetchScans, 5000); // Poll every 5 seconds
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
      const [scanRes, vulnRes] = await Promise.all([
        fetch(`/api/scans/${id}`),
        fetch(`/api/scans/${id}/vulnerabilities`)
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
    const interval = setInterval(fetchScan, 3000); // Poll every 3 seconds
    return () => clearInterval(interval);
  }, [id]);

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
        const response = await fetch('/api/dashboard/stats');
        if (response.ok) {
          const data = await response.json();
          setStats(data);
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
