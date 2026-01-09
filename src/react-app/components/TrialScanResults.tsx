import { X, Lock, AlertTriangle, Shield, CheckCircle, Globe, Smartphone } from 'lucide-react';
import SeverityBadge from '@/react-app/components/SeverityBadge';

interface TrialScanResultsProps {
  scanType: 'web' | 'mobile';
  scan: any;
  vulnerabilities: any[];
  onClose: () => void;
  onOpenLogin: () => void;
  onOpenSignup: () => void;
}

export default function TrialScanResults({
  scanType,
  scan,
  vulnerabilities,
  onClose,
  onOpenLogin,
  onOpenSignup,
}: TrialScanResultsProps) {
  const severityCounts = {
    critical: scan.severity_critical || 0,
    high: scan.severity_high || 0,
    medium: scan.severity_medium || 0,
    low: scan.severity_low || 0,
    info: scan.severity_info || 0,
  };

  const totalVulnerabilities = vulnerabilities.length;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm">
      <div className="relative w-full max-w-4xl bg-gradient-to-br from-gray-900 to-gray-950 rounded-2xl border border-gray-800 shadow-2xl max-h-[90vh] overflow-y-auto">
        {/* Header */}
        <div className="p-6 border-b border-gray-800 sticky top-0 bg-gray-950 z-10">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-3">
              <div className={`p-2 rounded-lg ${scanType === 'web' ? 'bg-blue-500/10 border border-blue-500/20' : 'bg-purple-500/10 border border-purple-500/20'}`}>
                {scanType === 'web' ? (
                  <Globe className="w-5 h-5 text-blue-400" />
                ) : (
                  <Smartphone className="w-5 h-5 text-purple-400" />
                )}
              </div>
              <div>
                <h2 className="text-xl font-bold text-white">
                  {scanType === 'web' ? 'Web Scan Results' : 'Mobile Scan Results'}
                </h2>
                <p className="text-sm text-gray-400">
                  {scanType === 'web' ? scan.target_url : scan.app_name}
                </p>
              </div>
            </div>
            <button
              onClick={onClose}
              className="p-2 rounded-lg hover:bg-gray-800 transition-colors"
            >
              <X className="w-5 h-5 text-gray-400" />
            </button>
          </div>

          {/* Summary Stats */}
          <div className="grid grid-cols-2 md:grid-cols-6 gap-4 mt-4">
            <div className="text-center p-3 rounded-lg bg-gray-900/50 border border-gray-800">
              <div className="text-2xl font-bold text-white mb-1">{totalVulnerabilities}</div>
              <div className="text-xs text-gray-400">Total Issues</div>
            </div>
            {Object.entries(severityCounts).map(([severity, count]) => (
              <div key={severity} className="text-center p-3 rounded-lg bg-gray-900/50 border border-gray-800">
                <div className="text-2xl font-bold text-white mb-1">{count}</div>
                <SeverityBadge severity={severity} />
              </div>
            ))}
          </div>
        </div>

        {/* Blurred Results Section */}
        <div className="p-6 relative">
          {/* Blur Overlay */}
          <div className="absolute inset-0 bg-gray-950/95 backdrop-blur-md z-20 flex items-center justify-center rounded-b-2xl">
            <div className="text-center p-8 max-w-md">
              <div className="p-4 rounded-full bg-red-500/10 border border-red-500/20 inline-block mb-4">
                <Lock className="w-8 h-8 text-red-400" />
              </div>
              <h3 className="text-2xl font-bold text-white mb-2">Sign Up to View Full Results</h3>
              <p className="text-gray-400 mb-6">
                Your trial scan has completed! Sign up or log in to view detailed vulnerability information, 
                recommendations, and save your scan results.
              </p>
              <div className="flex flex-col sm:flex-row gap-3 justify-center">
                <button
                  onClick={() => {
                    onClose();
                    onOpenSignup();
                  }}
                  className="px-6 py-3 bg-gradient-to-r from-red-600 to-red-700 text-white font-medium rounded-lg hover:from-red-700 hover:to-red-800 transition-all shadow-lg shadow-red-500/20"
                >
                  Sign Up Free
                </button>
                <button
                  onClick={() => {
                    onClose();
                    onOpenLogin();
                  }}
                  className="px-6 py-3 border border-gray-700 text-gray-300 font-medium rounded-lg hover:bg-gray-800 transition-all"
                >
                  Log In
                </button>
              </div>
            </div>
          </div>

          {/* Blurred Content Preview */}
          <div className="blur-sm pointer-events-none opacity-50">
            <div className="mb-6">
              <h3 className="text-lg font-semibold text-white mb-4">Vulnerabilities Found</h3>
              <div className="space-y-4">
                {vulnerabilities.slice(0, 3).map((vuln, idx) => (
                  <div
                    key={idx}
                    className="p-4 rounded-lg border border-gray-800 bg-gray-900/50"
                  >
                    <div className="flex items-start justify-between mb-2">
                      <div className="flex items-center gap-3">
                        <AlertTriangle className={`w-5 h-5 ${
                          vuln.severity === 'critical' ? 'text-red-400' :
                          vuln.severity === 'high' ? 'text-orange-400' :
                          vuln.severity === 'medium' ? 'text-yellow-400' :
                          'text-blue-400'
                        }`} />
                        <h4 className="font-semibold text-white">{vuln.title}</h4>
                      </div>
                      <SeverityBadge severity={vuln.severity} />
                    </div>
                    <p className="text-sm text-gray-400 mb-2 line-clamp-2">
                      {vuln.description}
                    </p>
                    {vuln.cvss_score && (
                      <div className="text-xs text-gray-500">
                        CVSS Score: {vuln.cvss_score}
                      </div>
                    )}
                  </div>
                ))}
                {vulnerabilities.length > 3 && (
                  <div className="text-center text-gray-500 text-sm py-4">
                    +{vulnerabilities.length - 3} more vulnerabilities...
                  </div>
                )}
              </div>
            </div>

            {/* Additional Preview Sections */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
              <div className="p-4 rounded-lg border border-gray-800 bg-gray-900/50">
                <div className="flex items-center gap-2 mb-2">
                  <Shield className="w-5 h-5 text-blue-400" />
                  <h4 className="font-semibold text-white">Security Recommendations</h4>
                </div>
                <p className="text-sm text-gray-400 line-clamp-3">
                  Detailed remediation steps and best practices to fix identified vulnerabilities...
                </p>
              </div>
              <div className="p-4 rounded-lg border border-gray-800 bg-gray-900/50">
                <div className="flex items-center gap-2 mb-2">
                  <CheckCircle className="w-5 h-5 text-green-400" />
                  <h4 className="font-semibold text-white">Compliance Status</h4>
                </div>
                <p className="text-sm text-gray-400 line-clamp-3">
                  View compliance status against industry standards and frameworks...
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}


