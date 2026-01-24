import { useState } from 'react';
import { Download, FileDown, FileJson, FileSpreadsheet, Loader2 } from 'lucide-react';
import { Scan, Vulnerability, MobileScan, MobileVulnerability } from '@/shared/types';
import { getApiUrl, getAuthHeaders } from '@/react-app/lib/api';

interface ExportReportButtonProps {
  scan: Scan | MobileScan;
  vulnerabilities?: Vulnerability[] | MobileVulnerability[];
  isMobile?: boolean;
}

type ExportFormat = 'pdf' | 'json' | 'csv' | 'html';

export default function ExportReportButton({ scan, isMobile = false }: ExportReportButtonProps) {
  const [isOpen, setIsOpen] = useState(false);
  const [exporting, setExporting] = useState<ExportFormat | null>(null);

  const handleExport = async (format: ExportFormat) => {
    setExporting(format);
    try {
      const endpointPath = isMobile ? `/api/mobile-scans/${scan.id}/export` : `/api/scans/${scan.id}/export`;
      const url = `${getApiUrl(endpointPath)}?format=${format}`;

      // For binary downloads we don't set Content-Type here (browser will handle)
      const headers = await getAuthHeaders(null);

      const response = await fetch(url, { headers });
      if (!response.ok) throw new Error('Export failed');

      const blob = await response.blob();
      const blobUrl = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = blobUrl;

      const prefix = isMobile ? 'mobile-security-report' : 'cybersec-report';
      const filename = `${prefix}-${scan.id}-${Date.now()}`;
      const extensions: Record<ExportFormat, string> = { pdf: 'pdf', json: 'json', csv: 'csv', html: 'html' };
      a.download = `${filename}.${extensions[format]}`;

      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(blobUrl);

      setIsOpen(false);
    } catch (error) {
      console.error('Export failed:', error);
      // Consider showing a nicer UI error instead of alert in production
      alert('Failed to export report. Check console for details.');
    } finally {
      setExporting(null);
    }
  };

  const formatButtons = [
    { format: 'pdf' as ExportFormat, label: 'PDF Report', icon: FileDown, description: 'Full report with charts' },
    { format: 'json' as ExportFormat, label: 'JSON Data', icon: FileJson, description: 'Structured data format' },
    { format: 'csv' as ExportFormat, label: 'CSV Export', icon: FileSpreadsheet, description: 'Spreadsheet compatible' },
    { format: 'html' as ExportFormat, label: 'HTML Report', icon: FileDown, description: 'Interactive web report' },
  ];

  return (
    <div className="relative">
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="flex items-center gap-2 px-4 py-2 rounded-lg bg-gradient-to-r from-green-500 to-emerald-600 text-white font-medium hover:from-green-600 hover:to-emerald-700 transition-all shadow-lg shadow-green-500/20"
      >
        <Download className="w-4 h-4" />
        Export Report
      </button>

      {isOpen && (
        <>
          <div
            className="fixed inset-0 z-40"
            onClick={() => setIsOpen(false)}
          />
          <div className="absolute right-0 top-full mt-2 w-72 bg-gray-900 border border-gray-800 rounded-xl shadow-2xl z-50 overflow-hidden">
            <div className="p-3 border-b border-gray-800">
              <div className="text-sm text-gray-300">Choose export format</div>
            </div>

            <div className="p-3 space-y-2">
              {formatButtons.map((btn) => {
                const Icon = btn.icon;
                return (
                  <button
                    key={btn.format}
                    onClick={() => handleExport(btn.format)}
                    className="w-full flex items-center justify-between gap-3 p-2 rounded-lg hover:bg-gray-800 transition-colors"
                  >
                    <div className="flex items-center gap-3">
                      <Icon className="w-4 h-4 text-gray-300" />
                      <div className="text-left">
                        <div className="text-sm text-white">{btn.label}</div>
                        <div className="text-xs text-gray-400">{btn.description}</div>
                      </div>
                    </div>

                    <div>
                      {exporting === btn.format ? (
                        <Loader2 className="w-4 h-4 animate-spin text-blue-400" />
                      ) : (
                        <span className="text-xs text-gray-400">{btn.format.toUpperCase()}</span>
                      )}
                    </div>
                  </button>
                );
              })}
            </div>
          </div>
        </>
      )}
    </div>
  );
}
