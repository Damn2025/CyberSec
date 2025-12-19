import { useState, useEffect } from 'react';
import { MobileScan, MobileVulnerability } from '@/shared/types';
import { supabase } from '@/react-app/lib/supabase';

export function useMobileScans() {
  const [scans, setScans] = useState<MobileScan[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchScans = async () => {
    try {
      // Get auth token for user-specific data
      const { data: { session } } = await supabase.auth.getSession();
      const headers: HeadersInit = {};
      if (session?.access_token) {
        headers['Authorization'] = `Bearer ${session.access_token}`;
      }

      const response = await fetch('/api/mobile-scans', { headers });
      const data = await response.json();
      setScans(data);
    } catch (error) {
      console.error('Failed to fetch mobile scans:', error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchScans();
    const interval = setInterval(fetchScans, 5000);
    return () => clearInterval(interval);
  }, []);

  return { scans, loading, refetch: fetchScans };
}

export function useMobileScan(id: string | undefined) {
  const [scan, setScan] = useState<MobileScan | null>(null);
  const [vulnerabilities, setVulnerabilities] = useState<MobileVulnerability[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!id) return;

    const fetchScanData = async () => {
      try {
        // Get auth token for user-specific data
        const { data: { session } } = await supabase.auth.getSession();
        const headers: HeadersInit = {};
        if (session?.access_token) {
          headers['Authorization'] = `Bearer ${session.access_token}`;
        }

        const [scanRes, vulnRes] = await Promise.all([
          fetch(`/api/mobile-scans/${id}`, { headers }),
          fetch(`/api/mobile-scans/${id}/vulnerabilities`, { headers }),
        ]);

        const scanData = await scanRes.json();
        const vulnData = await vulnRes.json();

        setScan(scanData);
        setVulnerabilities(vulnData);
      } catch (error) {
        console.error('Failed to fetch mobile scan:', error);
      } finally {
        setLoading(false);
      }
    };

    fetchScanData();
    const interval = setInterval(fetchScanData, 5000);
    return () => clearInterval(interval);
  }, [id]);

  return { scan, vulnerabilities, loading };
}
