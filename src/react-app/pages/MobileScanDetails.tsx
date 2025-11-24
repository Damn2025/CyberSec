import { useParams, useNavigate } from 'react-router';
import { ArrowLeft, Activity, CheckCircle, AlertCircle, Clock, Loader2, Trash2, Smartphone } from 'lucide-react';
import { useMobileScan } from '@/react-app/hooks/useMobileScans';
import VulnerabilityCard from '@/react-app/components/VulnerabilityCard';
import SeverityBadge from '@/react-app/components/SeverityBadge';
import ExportReportButton from '@/react-app/components/ExportReportButton';
import { formatDistanceToNow } from 'date-fns';
import { useState } from 'react';

export default function MobileScanDetails() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { scan, vulnerabilities, loading } = useMobileScan(id);
  const [deleting, setDeleting] = useState(false);

  const handleDelete = async () => {
    if (!id || !confirm('Are you sure you want to delete this mobile scan?')) return;
    
    setDeleting(true);
    try {
      const response = await fetch(`/api/mobile-scans/${id}`, { method: 'DELETE' });
      if (response.ok) {
        navigate('/');
      }
    } catch (error) {
      console.error('Failed to delete mobile scan:', error);
    } finally {
      setDeleting(false);
    }
  };

  if (loading && !scan) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-gray-950 via-gray-900 to-black flex items-center justify-center">
        <div className="text-center">
          <Loader2 className="w-12 h-12 text-purple-500 mx-auto mb-4 animate-spin" />
          <p className="text-gray-400">Loading mobile scan details...</p>
        </div>
      </div>
    );
  }

  if (!scan) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-gray-950 via-gray-900 to-black flex items-center justify-center">
        <div className="text-center">
          <AlertCircle className="w-12 h-12 text-red-500 mx-auto mb-4" />
          <p className="text-gray-400">Mobile scan not found</p>
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

  const totalVulnerabilities = vulnerabilities.length;
  const severityCounts = {
    critical: scan.severity_critical,
    high: scan.severity_high,
    medium: scan.severity_medium,
    low: scan.severity_low,
    info: scan.severity_info,
  };

  // Group vulnerabilities by OWASP category
  const owaspCategories = new Map<string, number>();
  vulnerabilities.forEach(v => {
    const count = owaspCategories.get(v.owasp_category) || 0;
    owaspCategories.set(v.owasp_category, count + 1);
  });

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-950 via-gray-900 to-black">
      {/* Header */}
      <div className="border-b border-gray-800 bg-gray-950/50 backdrop-blur-xl sticky top-0 z-10">
        <div className="max-w-7xl mx-auto px-6 py-6">
          <div className="flex items-center justify-between mb-4">
            <button
              onClick={() => navigate('/')}
              className="flex items-center gap-2 px-4 py-2 rounded-lg hover:bg-gray-800 transition-colors text-gray-400 hover:text-white"
            >
              <ArrowLeft className="w-5 h-5" />
              Back to Dashboard
            </button>
            <div className="flex items-center gap-3">
              {scan.status === 'completed' && (
                <ExportReportButton 
                  scan={scan as any} 
                  vulnerabilities={vulnerabilities as any}
                  isMobile={true}
                />
              )}
              <button
                onClick={handleDelete}
                disabled={deleting}
                className="flex items-center gap-2 px-4 py-2 rounded-lg bg-red-500/10 hover:bg-red-500/20 transition-colors text-red-400 border border-red-500/20 disabled:opacity-50"
              >
                <Trash2 className="w-4 h-4" />
                {deleting ? 'Deleting...' : 'Delete Scan'}
              </button>
            </div>
          </div>
          
          <div className="flex items-start justify-between gap-6">
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-3 mb-3">
                <div className="p-2 rounded-lg bg-purple-500/10 border border-purple-500/20">
                  <Smartphone className="w-6 h-6 text-purple-400" />
                </div>
                <div className="flex-1 min-w-0">
                  <h1 className="text-2xl font-bold text-white truncate">{scan.app_name}</h1>
                  {scan.package_name && (
                    <p className="text-sm text-gray-500 truncate">{scan.package_name}</p>
                  )}
                </div>
              </div>
              <div className="flex items-center gap-4 text-sm text-gray-400">
                <span className="capitalize">Platform: {scan.platform}</span>
                {scan.version && (
                  <>
                    <span>•</span>
                    <span>Version: {scan.version}</span>
                  </>
                )}
                <span>•</span>
                <span>
                  {scan.completed_at 
                    ? `Completed ${formatDistanceToNow(new Date(scan.completed_at), { addSuffix: true })}`
                    : `Started ${formatDistanceToNow(new Date(scan.started_at || scan.created_at), { addSuffix: true })}`
                  }
                </span>
              </div>
            </div>
            <div className="flex items-center gap-3 px-4 py-2 rounded-lg bg-gray-800/50 border border-gray-700">
              <StatusIcon className={`w-5 h-5 ${config.color} ${scan.status === 'running' ? 'animate-spin' : ''}`} />
              <span className={`text-sm font-medium ${config.color} capitalize`}>{scan.status}</span>
            </div>
          </div>
        </div>
      </div>

      <div className="max-w-7xl mx-auto px-6 py-8">
        {/* Summary Stats */}
        {scan.status === 'completed' && (
          <>
            <div className="mb-8 p-6 rounded-xl border border-gray-800 bg-gradient-to-br from-gray-900 to-gray-950">
              <h2 className="text-lg font-semibold text-white mb-4">Scan Summary</h2>
              <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
                <div className="text-center">
                  <div className="text-3xl font-bold text-white mb-1">{totalVulnerabilities}</div>
                  <div className="text-sm text-gray-400">Total Issues</div>
                </div>
                {Object.entries(severityCounts).map(([severity, count]) => (
                  <div key={severity} className="text-center">
                    <div className="text-3xl font-bold text-white mb-1">{count}</div>
                    <SeverityBadge severity={severity} />
                  </div>
                ))}
              </div>
            </div>

            {/* OWASP Mobile Top 10 Summary */}
            {owaspCategories.size > 0 && (
              <div className="mb-8 p-6 rounded-xl border border-purple-800/50 bg-gradient-to-br from-purple-900/20 to-pink-900/20">
                <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
                  <span className="text-2xl">🛡️</span>
                  OWASP Mobile Top 10 Findings
                </h2>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  {Array.from(owaspCategories.entries())
                    .sort((a, b) => b[1] - a[1])
                    .map(([category, count]) => (
                      <div
                        key={category}
                        className="p-4 rounded-lg bg-gray-900/50 border border-gray-800 hover:border-purple-500/30 transition-colors"
                      >
                        <div className="flex items-center justify-between">
                          <span className="text-sm text-gray-300 font-medium">{category}</span>
                          <span className="px-2 py-1 rounded-full bg-purple-500/20 text-purple-400 text-xs font-semibold">
                            {count} issue{count !== 1 ? 's' : ''}
                          </span>
                        </div>
                      </div>
                    ))}
                </div>
              </div>
            )}
          </>
        )}

        {/* Vulnerabilities List */}
        <div>
          <h2 className="text-2xl font-bold text-white mb-6">
            {scan.status === 'running' ? 'Scanning...' : 'Vulnerabilities Found'}
          </h2>

          {scan.status === 'running' ? (
            <div className="flex flex-col items-center justify-center py-20">
              <div className="p-6 rounded-2xl bg-gradient-to-br from-purple-500/10 to-pink-500/10 border border-purple-500/20 mb-6">
                <Activity className="w-16 h-16 text-purple-400 mx-auto animate-pulse" />
              </div>
              <h3 className="text-xl font-semibold text-white mb-2">Scan in Progress</h3>
              <p className="text-gray-400">Analyzing {scan.app_name} for security vulnerabilities...</p>
              <p className="text-sm text-gray-500 mt-2">This may take a few minutes</p>
            </div>
          ) : vulnerabilities.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-20">
              <div className="p-6 rounded-2xl bg-gradient-to-br from-green-500/10 to-emerald-500/10 border border-green-500/20 mb-6">
                <CheckCircle className="w-16 h-16 text-green-400 mx-auto" />
              </div>
              <h3 className="text-xl font-semibold text-white mb-2">No Vulnerabilities Found</h3>
              <p className="text-gray-400">This mobile app scan didn't detect any security issues.</p>
            </div>
          ) : (
            <div className="space-y-4">
              {vulnerabilities.map((vuln) => (
                <VulnerabilityCard key={vuln.id} vulnerability={vuln as any} isMobile={true} />
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
