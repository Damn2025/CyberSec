import { useState } from 'react';
import { Download, FileDown, FileJson, FileSpreadsheet, Loader2 } from 'lucide-react';
import { Scan, Vulnerability, MobileScan, MobileVulnerability } from '@/shared/types';

interface ExportReportButtonProps {
  scan: Scan | MobileScan;
  vulnerabilities: Vulnerability[] | MobileVulnerability[];
  isMobile?: boolean;
}

// vulnerabilities prop used for type checking only - actual data fetched from API

type ExportFormat = 'pdf' | 'json' | 'csv' | 'html';

export default function ExportReportButton({ scan, isMobile = false }: ExportReportButtonProps) {
  const [isOpen, setIsOpen] = useState(false);
  const [exporting, setExporting] = useState<ExportFormat | null>(null);

  const handleExport = async (format: ExportFormat) => {
    setExporting(format);
    try {
      const endpoint = isMobile ? `/api/mobile-scans/${scan.id}/export` : `/api/scans/${scan.id}/export`;
      const response = await fetch(`${endpoint}?format=${format}`);
      if (!response.ok) throw new Error('Export failed');

      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      
      const prefix = isMobile ? 'mobile-security-report' : 'cybersec-report';
      const filename = `${prefix}-${scan.id}-${Date.now()}`;
      const extensions = { pdf: 'pdf', json: 'json', csv: 'csv', html: 'html' };
      a.download = `${filename}.${extensions[format]}`;
      
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(url);
      
      setIsOpen(false);
    } catch (error) {
      console.error('Export failed:', error);
      alert('Failed to export report');
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
              <h3 className="text-sm font-semibold text-white">Export Format</h3>
            </div>
            <div className="p-2">
              {formatButtons.map(({ format, label, icon: Icon, description }) => (
                <button
                  key={format}
                  onClick={() => handleExport(format)}
                  disabled={exporting !== null}
                  className="w-full flex items-center gap-3 p-3 rounded-lg hover:bg-gray-800 transition-colors text-left disabled:opacity-50"
                >
                  <div className="p-2 rounded-lg bg-gray-800 border border-gray-700">
                    {exporting === format ? (
                      <Loader2 className="w-4 h-4 text-green-400 animate-spin" />
                    ) : (
                      <Icon className="w-4 h-4 text-gray-400" />
                    )}
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="text-sm font-medium text-white">{label}</div>
                    <div className="text-xs text-gray-400">{description}</div>
                  </div>
                </button>
              ))}
            </div>
          </div>
        </>
      )}
    </div>
  );
}
