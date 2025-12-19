import { useParams, useNavigate } from 'react-router';
import { ArrowLeft, CheckCircle, AlertCircle, Clock, Loader2, ExternalLink, Trash2, Award, Shield } from 'lucide-react';
import { useScan } from '@/react-app/hooks/useScans';
import VulnerabilityCard from '@/react-app/components/VulnerabilityCard';
import CWETop25Card from '@/react-app/components/CWETop25Card';
import SeverityBadge from '@/react-app/components/SeverityBadge';
import ExportReportButton from '@/react-app/components/ExportReportButton';
import { formatDistanceToNow } from 'date-fns';
import { useState } from 'react';

export default function ScanDetails() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { scan, vulnerabilities, loading } = useScan(id);
  const [deleting, setDeleting] = useState(false);

  const handleDelete = async () => {
    if (!id || !confirm('Are you sure you want to delete this scan?')) return;
    
    setDeleting(true);
    try {
      const response = await fetch(`/api/scans/${id}`, { method: 'DELETE' });
      if (response.ok) {
        navigate('/');
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

  const totalVulnerabilities = vulnerabilities.length;
  const severityCounts = {
    critical: scan.severity_critical,
    high: scan.severity_high,
    medium: scan.severity_medium,
    low: scan.severity_low,
    info: scan.severity_info,
  };

  // Determine scanner type for each vulnerability (Standard, CWE_TOP_25, NIST_SP_800_171)
  const getScannerType = (v: { category?: string | null; title: string }) => {
    if (v.category?.includes("CWE Top 25") || v.title.includes("CWE Top 25")) {
      return "CWE_TOP_25" as const;
    }
    if (
      v.category?.includes("NIST SP 800-171") ||
      v.title.toLowerCase().includes("nist")
    ) {
      return "NIST_SP_800_171" as const;
    }
    return "STANDARD" as const;
  };

  const cweTop25Vulns = vulnerabilities.filter(
    (v) => getScannerType(v) === "CWE_TOP_25",
  );
  const nistVulns = vulnerabilities.filter(
    (v) => getScannerType(v) === "NIST_SP_800_171",
  );
  const standardVulns = vulnerabilities.filter(
    (v) => getScannerType(v) === "STANDARD",
  );

  // Extract rank for sorting CWE Top 25 vulnerabilities
  const extractRank = (title: string): number => {
    const match = title.match(/CWE Top 25 #(\d+)/);
    return match ? parseInt(match[1], 10) : 999;
  };

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
                <ExportReportButton scan={scan} vulnerabilities={vulnerabilities} />
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
                <h1 className="text-2xl font-bold text-white truncate">{scan.target_url}</h1>
                <a
                  href={scan.target_url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="p-1.5 rounded-lg hover:bg-gray-800 transition-colors"
                >
                  <ExternalLink className="w-4 h-4 text-gray-500" />
                </a>
              </div>
              <div className="flex items-center gap-4 text-sm text-gray-400">
                <span className="capitalize">Scan Type: {scan.scan_type}</span>
                <span>•</span>
                <span>
                  {scan.completed_at 
                    ? `Completed ${formatDistanceToNow(new Date(scan.completed_at), { addSuffix: true })}`
                    : `Started ${formatDistanceToNow(new Date(scan.started_at || scan.created_at), { addSuffix: true })}`
                  }
                </span>
              </div>
            </div>
            <div className="flex items-center gap-3 px-4 py-2 rounded-lg bg-black/50 border border-red-900/30">
              <StatusIcon className={`w-5 h-5 ${config.color} ${scan.status === 'running' ? 'animate-spin' : ''}`} />
              <span className={`text-sm font-medium ${config.color} capitalize`}>{scan.status}</span>
            </div>
          </div>
        </div>
      </div>

      <div className="max-w-7xl mx-auto px-6 py-8">
        {/* Summary Stats */}
        {scan.status === 'completed' && (
          <div className="mb-8 space-y-4">
            <div className="p-6 rounded-xl border border-red-900/30 bg-black/50">
              <h2 className="text-lg font-semibold text-white mb-4">Scan Summary</h2>
              <div className="grid grid-cols-2 md:grid-cols-6 gap-4">
                <div className="text-center">
                  <div className="text-3xl font-bold text-white mb-1">{totalVulnerabilities}</div>
                  <div className="text-sm text-gray-400">Total Issues</div>
                </div>
                {/* {cweTop25Vulns.length > 0 && (
                  <div className="text-center">
                    <div className="text-3xl font-bold text-purple-400 mb-1">{cweTop25Vulns.length}</div>
                    <div className="text-sm text-gray-400 flex items-center justify-center gap-1">
                      <Award className="w-3 h-3" />
                      CWE Top 25
                    </div>
                  </div>
                )} */}
                {Object.entries(severityCounts).map(([severity, count]) => (
                  <div key={severity} className="text-center">
                    <div className="text-3xl font-bold text-white mb-1">{count}</div>
                    <SeverityBadge severity={severity} />
                  </div>
                ))}
              </div>

              {/* Scanner-type breakdown */}
              <div className="mt-4 flex flex-wrap gap-3 text-xs md:text-sm text-gray-300">
                <span className="px-3 py-1 rounded-full bg-gray-800 border border-gray-700 font-mono">
                  Standard: {standardVulns.length}
                </span>
                <span className="px-3 py-1 rounded-full bg-gray-800 border border-gray-700 font-mono">
                  CWE Top 25: {cweTop25Vulns.length}
                </span>
                <span className="px-3 py-1 rounded-full bg-gray-800 border border-gray-700 font-mono">
                  NIST SP 800-171: {nistVulns.length}
                </span>
              </div>
            </div>
            
            {cweTop25Vulns.length > 0 && (
              <div className="p-4 rounded-xl border border-red-500/20 bg-gradient-to-br from-red-500/5 to-red-900/5">
                <div className="flex items-center gap-2 text-red-400">
                  <Award className="w-5 h-5" />
                  <span className="text-sm font-semibold">
                    {cweTop25Vulns.length} CWE Top 25 {cweTop25Vulns.length === 1 ? 'vulnerability' : 'vulnerabilities'} detected
                  </span>
                </div>
                <p className="text-xs text-gray-400 mt-1 ml-7">
                  These are from the 2024 CWE Top 25 Most Dangerous Software Weaknesses list
                </p>
              </div>
            )}
          </div>
        )}

        {/* NIST SP 800-171 Vulnerabilities Section */}
        {scan.status === "completed" && nistVulns.length > 0 && (
          <div className="mb-8">
            <div className="flex items-center gap-3 mb-6">
              <div className="p-2 rounded-lg bg-gradient-to-br from-blue-500/10 to-blue-900/10 border border-blue-500/20">
                <Shield className="w-6 h-6 text-blue-400" />
              </div>
              <div>
                <h2 className="text-2xl font-bold text-white">
                  NIST SP 800-171 Controls 
                </h2>
                <p className="text-sm text-gray-400">
                  Findings mapped to NIST SP 800-171 security controls
                </p>
              </div>
              <span className="ml-auto px-3 py-1 rounded-full text-sm font-medium bg-blue-500/10 text-blue-400 border border-blue-500/20">
                {nistVulns.length} detected
              </span>
            </div>

            <div className="space-y-4">
              {nistVulns
                .sort((a, b) => {
                  // sort by severity then CVSS
                  const severityOrder: Record<string, number> = {
                    critical: 5,
                    high: 4,
                    medium: 3,
                    low: 2,
                    info: 1,
                  };
                  const aOrder = severityOrder[a.severity] || 0;
                  const bOrder = severityOrder[b.severity] || 0;
                  if (bOrder !== aOrder) return bOrder - aOrder;
                  return (b.cvss_score || 0) - (a.cvss_score || 0);
                })
                .map((vuln) => (
                  <VulnerabilityCard key={vuln.id} vulnerability={vuln} />
                ))}
            </div>
          </div>
        )}

        {/* CWE Top 25 Vulnerabilities Section */}
        {scan.status === 'completed' && cweTop25Vulns.length > 0 && (
          <div className="mb-8">
            <div className="flex items-center gap-3 mb-6">
              <div className="p-2 rounded-lg bg-gradient-to-br from-red-500/10 to-red-900/10 border border-red-500/20">
                <Award className="w-6 h-6 text-red-400" />
              </div>
              <div>
                <h2 className="text-2xl font-bold text-white">CWE Top 25 Vulnerabilities</h2>
                <p className="text-sm text-gray-400">Most dangerous software weaknesses (2024)</p>
              </div>
              <span className="ml-auto px-3 py-1 rounded-full text-sm font-medium bg-red-500/10 text-red-400 border border-red-500/20">
                {cweTop25Vulns.length} detected
              </span>
            </div>
            
            <div className="space-y-4">
              {cweTop25Vulns
                .sort((a, b) => {
                  // Sort by rank (lower rank = higher priority)
                  const aRank = extractRank(a.title);
                  const bRank = extractRank(b.title);
                  return aRank - bRank;
                })
                .map((vuln) => (
                  <CWETop25Card key={vuln.id} vulnerability={vuln} />
                ))}
            </div>
          </div>
        )}

        {/* OSWAP TOP_25 Vulnerabilities List */}
        <div>
          <div className="flex items-center justify-between mb-6">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-gradient-to-br from-red-500/10 to-red-900/10 border border-red-500/20">
                <Shield className="w-6 h-6 text-red-400" />
              </div>
              <div>
                <h2 className="text-2xl font-bold text-white">
                  {scan.status === 'running' ? 'Scanning...' : 'Standard Security Vulnerabilities'}
                </h2>
                {scan.status === 'completed' && standardVulns.length > 0 && (
                  <p className="text-sm text-gray-400">
                    {standardVulns.length} {standardVulns.length === 1 ? 'vulnerability' : 'vulnerabilities'} found
                  </p>
                )}
              </div>
            </div>
            {scan.status === 'completed' && vulnerabilities.length > 0 && (
               <span className="ml-auto px-3 py-1 rounded-full text-sm font-medium bg-red-500/10 text-red-400 border border-red-500/20">
                {standardVulns.length} detected
              </span>
            )}
          </div>
          {standardVulns.length === 0 && cweTop25Vulns.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-20">
              <div className="p-6 rounded-2xl bg-gradient-to-br from-green-500/10 to-emerald-500/10 border border-green-500/20 mb-6">
                <CheckCircle className="w-16 h-16 text-green-400 mx-auto" />
              </div>
              <h3 className="text-xl font-semibold text-white mb-2">No Vulnerabilities Found</h3>
              <p className="text-gray-400">Great news! This scan didn't detect any security issues.</p>
            </div>
          ) : standardVulns.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-12">
              <div className="p-4 rounded-xl bg-gradient-to-br from-red-500/10 to-red-900/10 border border-red-500/20 mb-4">
                <Shield className="w-12 h-12 text-red-400 mx-auto" />
              </div>
              <h3 className="text-lg font-semibold text-white mb-2">No Standard Vulnerabilities</h3>
              <p className="text-gray-400 text-sm">All detected vulnerabilities are from CWE Top 25 list above.</p>
            </div>
          ) : (
            <div className="space-y-4">
              {standardVulns
                .sort((a, b) => {
                  // Sort by severity: critical > high > medium > low > info
                  const severityOrder: Record<string, number> = {
                    critical: 5,
                    high: 4,
                    medium: 3,
                    low: 2,
                    info: 1,
                  };
                  const aOrder = severityOrder[a.severity] || 0;
                  const bOrder = severityOrder[b.severity] || 0;
                  if (bOrder !== aOrder) return bOrder - aOrder;
                  // If same severity, sort by CVSS score (higher first)
                  return (b.cvss_score || 0) - (a.cvss_score || 0);
                })
                .map((vuln) => (
                  <VulnerabilityCard key={vuln.id} vulnerability={vuln} />
                ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
