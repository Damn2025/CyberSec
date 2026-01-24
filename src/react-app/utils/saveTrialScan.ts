import { getApiUrl, getAuthHeaders } from '@/react-app/lib/api';

export async function saveTrialScan(): Promise<boolean> {
  try {
    // Check for pending trial scan in localStorage
    const pendingTrialScan = localStorage.getItem('pendingTrialScan');
    if (!pendingTrialScan) {
      return false;
    }

    const trialScanData = JSON.parse(pendingTrialScan);

    // Get auth headers (includes Authorization if session exists)
    const headers = await getAuthHeaders('application/json');
    const headersObj: Record<string, string> = typeof headers === 'object' && !Array.isArray(headers) && !(headers instanceof Headers) 
      ? headers as Record<string, string>
      : {};

    // If Authorization is required and missing, we bail out
    // (original behaviour required session.access_token)
    if (!headersObj.Authorization) return false;

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
