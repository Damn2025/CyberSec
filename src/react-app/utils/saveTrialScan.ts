import { supabase } from '@/react-app/lib/supabase';
import { getApiUrl } from '@/react-app/lib/api';

export async function saveTrialScan(): Promise<boolean> {
  try {
    // Check for pending trial scan in localStorage
    const pendingTrialScan = localStorage.getItem('pendingTrialScan');
    if (!pendingTrialScan) {
      return false;
    }

    const trialScanData = JSON.parse(pendingTrialScan);
    
    // Get current session
    const { data: { session } } = await supabase.auth.getSession();
    if (!session?.access_token) {
      return false;
    }

    const headers: HeadersInit = {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${session.access_token}`,
    };

    let response: Response;

    if (trialScanData.scanType === 'web') {
      // Save web trial scan
      response = await fetch(getApiUrl('/api/scans/save-trial'), {
        method: 'POST',
        headers,
        body: JSON.stringify({
          scan: trialScanData.scan,
          vulnerabilities: trialScanData.vulnerabilities,
        }),
      });
    } else if (trialScanData.scanType === 'mobile') {
      // Save mobile trial scan
      response = await fetch(getApiUrl('/api/mobile-scans/save-trial'), {
        method: 'POST',
        headers,
        body: JSON.stringify({
          scan: trialScanData.scan,
          vulnerabilities: trialScanData.vulnerabilities,
        }),
      });
    } else {
      return false;
    }

    if (response.ok) {
      localStorage.removeItem('pendingTrialScan');
      return true;
    }

    return false;
  } catch (err) {
    console.error('Failed to save trial scan:', err);
    return false;
  }
}

