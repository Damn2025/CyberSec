const VIRUSTOTAL_API_KEY = "1db101d5de7ea9691551fa5690031ce72b09883494e3d4b30f6000edf0b30db9";
const VIRUSTOTAL_BASE_URL = "https://www.virustotal.com/vtapi/v2";

export interface VirusTotalUrlResult {
  scan_id: string;
  url: string;
  permalink: string;
  response_code: number;
  scan_date: string;
  positives: number;
  total: number;
  scans: Record<string, {
    detected: boolean;
    result: string;
  }>;
}

export interface VirusTotalFileResult {
  scan_id: string;
  sha1: string;
  resource: string;
  response_code: number;
  scan_date: string;
  permalink: string;
  positives: number;
  total: number;
  scans: Record<string, {
    detected: boolean;
    version: string;
    result: string;
    update: string;
  }>;
}

/**
 * Scan a URL using VirusTotal API
 */
export async function scanUrl(url: string): Promise<VirusTotalUrlResult | null> {
  try {
    // Submit URL for scanning
    const scanFormData = new FormData();
    scanFormData.append("apikey", VIRUSTOTAL_API_KEY);
    scanFormData.append("url", url);

    // Create abort controller for timeout
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 30000); // 30 second timeout
    
    const scanResponse = await fetch(`${VIRUSTOTAL_BASE_URL}/url/scan`, {
      method: "POST",
      body: scanFormData,
      signal: controller.signal,
    });
    
    clearTimeout(timeoutId);

    if (!scanResponse.ok) {
      console.error(`VirusTotal URL scan submission failed: ${scanResponse.status} ${scanResponse.statusText}`);
      return null;
    }

    const scanData = await scanResponse.json() as { response_code: number; scan_id?: string; verbose_msg?: string };
    
    if (scanData.response_code !== 1) {
      console.warn(`VirusTotal URL scan submission error: ${scanData.verbose_msg || "Unknown error"}`);
      return null;
    }

    if (!scanData.scan_id) {
      console.warn("VirusTotal URL scan: No scan_id returned");
      return null;
    }

    // Wait a bit for the scan to process
    await new Promise(resolve => setTimeout(resolve, 2000));

    // Get scan report
    const reportFormData = new FormData();
    reportFormData.append("apikey", VIRUSTOTAL_API_KEY);
    reportFormData.append("resource", scanData.scan_id);

    // Create abort controller for timeout
    const reportController = new AbortController();
    const reportTimeoutId = setTimeout(() => reportController.abort(), 30000); // 30 second timeout
    
    const reportResponse = await fetch(`${VIRUSTOTAL_BASE_URL}/url/report`, {
      method: "POST",
      body: reportFormData,
      signal: reportController.signal,
    });
    
    clearTimeout(reportTimeoutId);

    if (!reportResponse.ok) {
      console.error(`VirusTotal URL report fetch failed: ${reportResponse.status} ${reportResponse.statusText}`);
      return null;
    }

    const reportData = await reportResponse.json() as VirusTotalUrlResult | { response_code: number; verbose_msg?: string };
    
    if (reportData.response_code !== 1) {
      console.warn(`VirusTotal URL report error: ${('verbose_msg' in reportData) ? reportData.verbose_msg : "Unknown error"}`);
      return null;
    }

    return reportData as VirusTotalUrlResult;
  } catch (error) {
    // Handle AbortError and other fetch errors gracefully
    if (error instanceof Error) {
      if (error.name === 'AbortError' || error.name === 'TimeoutError') {
        console.warn("VirusTotal URL scan timeout - this is normal in dev environment");
      } else {
        console.error("VirusTotal URL scan error:", error.message);
      }
    } else {
      console.error("VirusTotal URL scan error:", error);
    }
    return null;
  }
}

/**
 * Scan a file using VirusTotal API
 */
export async function scanFile(fileBuffer: ArrayBuffer, fileName: string): Promise<VirusTotalFileResult | null> {
  try {
    // Submit file for scanning
    const scanFormData = new FormData();
    scanFormData.append("apikey", VIRUSTOTAL_API_KEY);
    scanFormData.append("file", new Blob([fileBuffer], { type: "application/octet-stream" }), fileName);

    // Create abort controller for timeout
    const fileController = new AbortController();
    const fileTimeoutId = setTimeout(() => fileController.abort(), 60000); // 60 second timeout for file uploads
    
    const scanResponse = await fetch(`${VIRUSTOTAL_BASE_URL}/file/scan`, {
      method: "POST",
      body: scanFormData,
      signal: fileController.signal,
    });
    
    clearTimeout(fileTimeoutId);

    if (!scanResponse.ok) {
      console.error(`VirusTotal file scan submission failed: ${scanResponse.status} ${scanResponse.statusText}`);
      return null;
    }

    const scanData = await scanResponse.json() as { response_code: number; sha256?: string; scan_id?: string; verbose_msg?: string };
    
    if (scanData.response_code !== 1) {
      console.warn(`VirusTotal file scan submission error: ${scanData.verbose_msg || "Unknown error"}`);
      return null;
    }

    if (!scanData.sha256 && !scanData.scan_id) {
      console.warn("VirusTotal file scan: No sha256 or scan_id returned");
      return null;
    }

    // Wait a bit for the scan to process
    await new Promise(resolve => setTimeout(resolve, 3000));

    // Get scan report using SHA256 hash
    const reportFormData = new FormData();
    reportFormData.append("apikey", VIRUSTOTAL_API_KEY);
    reportFormData.append("resource", scanData.sha256 || scanData.scan_id || "");

    // Create abort controller for timeout
    const fileReportController = new AbortController();
    const fileReportTimeoutId = setTimeout(() => fileReportController.abort(), 30000); // 30 second timeout
    
    const reportResponse = await fetch(`${VIRUSTOTAL_BASE_URL}/file/report`, {
      method: "POST",
      body: reportFormData,
      signal: fileReportController.signal,
    });
    
    clearTimeout(fileReportTimeoutId);

    if (!reportResponse.ok) {
      console.error(`VirusTotal file report fetch failed: ${reportResponse.status} ${reportResponse.statusText}`);
      return null;
    }

    const reportData = await reportResponse.json() as VirusTotalFileResult | { response_code: number; verbose_msg?: string };
    
    if (reportData.response_code !== 1) {
      console.warn(`VirusTotal file report error: ${('verbose_msg' in reportData) ? reportData.verbose_msg : "Unknown error"}`);
      return null;
    }

    return reportData as VirusTotalFileResult;
  } catch (error) {
    // Handle AbortError and other fetch errors gracefully
    if (error instanceof Error) {
      if (error.name === 'AbortError' || error.name === 'TimeoutError') {
        console.warn("VirusTotal file scan timeout - this is normal in dev environment");
      } else {
        console.error("VirusTotal file scan error:", error.message);
      }
    } else {
      console.error("VirusTotal file scan error:", error);
    }
    return null;
  }
}

