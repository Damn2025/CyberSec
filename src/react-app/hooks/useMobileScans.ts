import { useState, useEffect } from 'react';
import { MobileScan, MobileVulnerability } from '@/shared/types';
import { supabase } from '@/react-app/lib/supabase';
import { getApiUrl } from '@/react-app/lib/api';

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

      const response = await fetch(getApiUrl('/api/mobile-scans'), { headers });

      // Check for JSON content type
      const contentType = response.headers.get("content-type");
      if (contentType && contentType.includes("application/json")) {
        const data = await response.json();
        setScans(data);
      } else {
        throw new Error("Received non-JSON response from API");
      }
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
          fetch(getApiUrl(`/api/mobile-scans/${id}`), { headers }),
          fetch(getApiUrl(`/api/mobile-scans/${id}/vulnerabilities`), { headers }),
        ]);

        // Helper to safely parse JSON
        const safeJson = async (res: Response) => {
          const contentType = res.headers.get("content-type");
          if (contentType && contentType.includes("application/json")) {
            return await res.json();
          }
          throw new Error("Received non-JSON response");
        };

        const scanData = await safeJson(scanRes);
        const vulnData = await safeJson(vulnRes);

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
