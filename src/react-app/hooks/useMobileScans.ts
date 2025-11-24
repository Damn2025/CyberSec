import { useState, useEffect } from 'react';
import { MobileScan, MobileVulnerability } from '@/shared/types';

export function useMobileScans() {
  const [scans, setScans] = useState<MobileScan[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchScans = async () => {
    try {
      const response = await fetch('/api/mobile-scans');
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
        const [scanRes, vulnRes] = await Promise.all([
          fetch(`/api/mobile-scans/${id}`),
          fetch(`/api/mobile-scans/${id}/vulnerabilities`),
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
