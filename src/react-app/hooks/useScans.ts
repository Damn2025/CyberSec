import { useState, useEffect, useCallback, useRef } from 'react';
import { Scan, Vulnerability } from '@/shared/types';

export function useScans() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchScans = async () => {
    try {
      // Add cache-busting to ensure we get fresh data
      const response = await fetch(`/api/scans?t=${Date.now()}`, {
        cache: 'no-store',
        headers: {
          'Cache-Control': 'no-cache',
        },
      });
      if (!response.ok) {
        throw new Error(`Failed to fetch scans: ${response.status} ${response.statusText}`);
      }
      const data = await response.json();
      // Force state update by creating new array reference
      setScans(prevScans => {
        // Check if status changed for any scan
        const statusChanged = prevScans.some((prev, idx) => 
          data[idx] && prev.status !== data[idx].status
        );
        if (statusChanged) {
          console.log('Scan status changed detected:', data.find((s: Scan, idx: number) => 
            prevScans[idx] && prevScans[idx].status !== s.status
          ));
        }
        return [...data];
      });
      setError(null);
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to fetch scans';
      setError(errorMessage);
      // Only log network errors, don't throw
      if (err instanceof TypeError && err.message.includes('fetch')) {
        console.warn('Network error fetching scans - API may not be available:', errorMessage);
      } else {
        console.error('Error fetching scans:', errorMessage);
      }
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
  const isInitialMount = useRef(true);

  const fetchScan = useCallback(async () => {
    if (!id) return;
    
    try {
      // Only set loading on initial fetch, not on subsequent polls
      if (isInitialMount.current) {
        setLoading(true);
        isInitialMount.current = false;
      }
      
      // Add cache-busting to ensure we get fresh data
      const timestamp = Date.now();
      const [scanRes, vulnRes] = await Promise.all([
        fetch(`/api/scans/${id}?t=${timestamp}`, {
          cache: 'no-store',
          headers: { 'Cache-Control': 'no-cache' },
        }),
        fetch(`/api/scans/${id}/vulnerabilities?t=${timestamp}`, {
          cache: 'no-store',
          headers: { 'Cache-Control': 'no-cache' },
        })
      ]);
      
      if (!scanRes.ok || !vulnRes.ok) {
        throw new Error(`Failed to fetch scan details: ${scanRes.status || vulnRes.status}`);
      }
      
      const scanData = await scanRes.json();
      const vulnData = await vulnRes.json();
      
      // Force state update by creating new object references
      setScan(prevScan => {
        // Check if status changed
        if (prevScan && prevScan.status !== scanData.status) {
          console.log(`Scan ${id} status changed from ${prevScan.status} to ${scanData.status}`);
        }
        return { ...scanData };
      });
      setVulnerabilities([...vulnData]);
      setError(null);
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to fetch scan';
      setError(errorMessage);
      // Only log network errors, don't throw
      if (err instanceof TypeError && err.message.includes('fetch')) {
        console.warn('Network error fetching scan details - API may not be available:', errorMessage);
      } else {
        console.error('Error fetching scan details:', errorMessage);
      }
    } finally {
      setLoading(false);
    }
  }, [id]);

  useEffect(() => {
    isInitialMount.current = true;
    fetchScan();
    
    // Poll every 2 seconds to catch status changes quickly
    const interval = setInterval(() => {
      fetchScan();
    }, 2000);
    
    return () => clearInterval(interval);
  }, [fetchScan]);

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
        } else {
          console.warn(`Failed to fetch stats: ${response.status} ${response.statusText}`);
        }
      } catch (err) {
        // Only log network errors, don't crash
        if (err instanceof TypeError && err.message.includes('fetch')) {
          console.warn('Network error fetching stats - API may not be available');
        } else {
          console.error('Failed to fetch stats:', err);
        }
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
