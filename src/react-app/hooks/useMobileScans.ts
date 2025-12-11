import { useState, useEffect } from 'react';
import { MobileScan, MobileVulnerability } from '@/shared/types';

export function useMobileScans() {
  const [scans, setScans] = useState<MobileScan[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchScans = async () => {
    try {
      const response = await fetch('/api/mobile-scans');
      if (!response.ok) {
        throw new Error(`Failed to fetch mobile scans: ${response.status} ${response.statusText}`);
      }
      const data = await response.json();
      setScans(data);
    } catch (error) {
      // Only log network errors, don't crash
      if (error instanceof TypeError && error.message.includes('fetch')) {
        console.warn('Network error fetching mobile scans - API may not be available:', error);
      } else {
        console.error('Failed to fetch mobile scans:', error);
      }
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
        const [scanRes, vulnRes] = await Promise.all([
          fetch(`/api/mobile-scans/${id}`),
          fetch(`/api/mobile-scans/${id}/vulnerabilities`),
        ]);

        if (!scanRes.ok || !vulnRes.ok) {
          throw new Error(`Failed to fetch mobile scan details: ${scanRes.status || vulnRes.status}`);
        }

        const scanData = await scanRes.json();
        const vulnData = await vulnRes.json();

        setScan(scanData);
        setVulnerabilities(vulnData);
      } catch (error) {
        // Only log network errors, don't crash
        if (error instanceof TypeError && error.message.includes('fetch')) {
          console.warn('Network error fetching mobile scan details - API may not be available:', error);
        } else {
          console.error('Failed to fetch mobile scan:', error);
        }
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
