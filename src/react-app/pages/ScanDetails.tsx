import { useParams, useNavigate } from 'react-router';
import { ArrowLeft, CheckCircle, AlertCircle, Clock, Loader2, Trash2 } from 'lucide-react';
import { useScan } from '@/react-app/hooks/useScans';
import VulnerabilityCard from '@/react-app/components/VulnerabilityCard';
import CWETop25Card from '@/react-app/components/CWETop25Card';
import ExportReportButton from '@/react-app/components/ExportReportButton';
import { useState } from 'react';
import { getApiUrl, getAuthHeaders } from '@/react-app/lib/api';

export default function ScanDetails() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { scan, vulnerabilities, loading } = useScan(id);
  const [deleting, setDeleting] = useState(false);

  const handleDelete = async () => {
    if (!id || !confirm('Are you sure you want to delete this scan?')) return;

    setDeleting(true);
    try {
      const headers = await getAuthHeaders();
      const response = await fetch(getApiUrl(`/api/scans/${id}`), { method: 'DELETE', headers });
      if (response.ok) {
        navigate('/');
      } else {
        // Optionally parse JSON to show error message
        const text = await response.text();
        console.error('Delete failed', response.status, text);
      }
    } catch (error) {
      console.error('Failed to delete scan:', error);
    } finally {
      setDeleting(false);
    }
  };

  if (loading && !scan) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-gray-950 via-gray-900 to-black flex items-center justify-center">
        <div className="text-center">
          <Loader2 className="w-12 h-12 text-blue-500 mx-auto mb-4 animate-spin" />
          <p className="text-gray-400">Loading scan details...</p>
        </div>
      </div>
    );
  }

  if (!scan) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-gray-950 via-gray-900 to-black flex items-center justify-center">
        <div className="text-center">
          <AlertCircle className="w-12 h-12 text-red-500 mx-auto mb-4" />
          <p className="text-gray-400">Scan not found</p>
        </div>
      </div>
    );
  }

  const statusConfig = {
    pending: { icon: Clock, color: 'text-gray-400' },
    running: { icon: Loader2, color: 'text-blue-400' },
    completed: { icon: CheckCircle, color: 'text-green-400' },
    failed: { icon: AlertCircle, color: 'text-red-400' },
  };

  const config = statusConfig[scan.status as keyof typeof statusConfig] || statusConfig.pending;
  const StatusIcon = config.icon;

  const totalVulnerabilities = (vulnerabilities || []).length;
  const severityCounts = {
    critical: scan.severity_critical,
    high: scan.severity_high,
    medium: scan.severity_medium,
    low: scan.severity_low,
    info: scan.severity_info,
  };

  // Find CWE Top 25 vulnerabilities
  const cweTop25Vulns = (vulnerabilities || []).filter(
    (v) => v.category?.includes("CWE Top 25") || v.title.includes("CWE Top 25")
  );

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-950 via-gray-900 to-black p-8">
      <div className="max-w-5xl mx-auto">
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-4">
            <button onClick={() => navigate(-1)} className="p-2 rounded-lg hover:bg-gray-800">
              <ArrowLeft className="w-5 h-5 text-gray-300" />
            </button>
            <div>
              <div className="flex items-center gap-3">
                <StatusIcon className={`w-8 h-8 ${config.color}`} />
                <div>
                  <h1 className="text-2xl font-bold text-white">{scan.target_url || 'Scan'}</h1>
                  <div className="text-sm text-gray-400">{scan.scan_type} • {scan.status}</div>
                </div>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <ExportReportButton scan={scan} vulnerabilities={vulnerabilities || []} />
            <button
              onClick={handleDelete}
              disabled={deleting}
              className="flex items-center gap-2 px-3 py-2 rounded-lg bg-red-600 text-white hover:bg-red-700"
            >
              {deleting ? <Loader2 className="w-4 h-4 animate-spin" /> : <Trash2 className="w-4 h-4" />}
              Delete
            </button>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="md:col-span-2 space-y-4">
            {vulnerabilities && vulnerabilities.length > 0 ? (
              vulnerabilities.map((v) => (
                <VulnerabilityCard key={v.id} vulnerability={v} />
              ))
            ) : (
              <div className="p-6 bg-gray-900 border border-gray-800 rounded-lg text-gray-400">
                No vulnerabilities found for this scan.
              </div>
            )}
          </div>

          <aside className="space-y-4">
            <div className="p-4 bg-gray-900 border border-gray-800 rounded-lg">
              <h3 className="text-sm text-gray-300 mb-2">Summary</h3>
              <div className="flex flex-col gap-2">
                <div className="flex items-center justify-between text-sm text-gray-300">
                  <span>Total vulnerabilities</span>
                  <span>{totalVulnerabilities}</span>
                </div>
                {Object.entries(severityCounts).map(([k, v]) => (
                  <div key={k} className="flex items-center justify-between text-sm text-gray-300">
                    <span className="capitalize">{k}</span>
                    <span>{v}</span>
                  </div>
                ))}
              </div>
            </div>

            {cweTop25Vulns.length > 0 && (
              <div className="space-y-4">
                <h3 className="text-sm font-semibold text-gray-300 mb-2">CWE Top 25 Vulnerabilities</h3>
                {cweTop25Vulns.map((v) => (
                  <CWETop25Card key={v.id} vulnerability={v} />
                ))}
              </div>
            )}
          </aside>
        </div>
      </div>
    </div>
  );
}
