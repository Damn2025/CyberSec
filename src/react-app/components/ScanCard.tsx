import { Scan } from '@/shared/types';
import { Clock, CheckCircle, AlertCircle, Loader2, ExternalLink } from 'lucide-react';
import { formatDistanceToNow } from 'date-fns';
import SeverityBadge from './SeverityBadge';
import { useNavigate } from 'react-router';

interface ScanCardProps {
  scan: Scan;
}

export default function ScanCard({ scan }: ScanCardProps) {
  const navigate = useNavigate();
  const totalVulnerabilities = 
    scan.severity_critical + 
    scan.severity_high + 
    scan.severity_medium + 
    scan.severity_low + 
    scan.severity_info;

  const statusConfig = {
    pending: {
      icon: Clock,
      color: 'text-gray-400',
      bg: 'bg-gray-500/10',
      border: 'border-gray-500/30',
    },
    running: {
      icon: Loader2,
      color: 'text-blue-400',
      bg: 'bg-blue-500/10',
      border: 'border-blue-500/30',
    },
    completed: {
      icon: CheckCircle,
      color: 'text-green-400',
      bg: 'bg-green-500/10',
      border: 'border-green-500/30',
    },
    failed: {
      icon: AlertCircle,
      color: 'text-red-400',
      bg: 'bg-red-500/10',
      border: 'border-red-500/30',
    },
  };

  const config = statusConfig[scan.status as keyof typeof statusConfig] || statusConfig.pending;
  const StatusIcon = config.icon;

  return (
    <div 
      onClick={() => navigate(`/scans/${scan.id}`)}
      className="group cursor-pointer relative overflow-hidden rounded-xl border border-gray-800 bg-gradient-to-br from-gray-900 to-gray-950 backdrop-blur-sm transition-all duration-300 hover:scale-[1.01] hover:shadow-xl hover:border-gray-700"
    >
      <div className="p-6">
        <div className="flex items-start justify-between mb-4">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-2">
              <h3 className="text-lg font-semibold text-white truncate">{scan.target_url}</h3>
              <ExternalLink className="w-4 h-4 text-gray-500 flex-shrink-0 opacity-0 group-hover:opacity-100 transition-opacity" />
            </div>
            <p className="text-sm text-gray-400">
              Scan Type: <span className="text-gray-300 capitalize">{scan.scan_type}</span>
            </p>
          </div>
          <div className={`flex items-center gap-2 px-3 py-1.5 rounded-lg ${config.bg} ${config.border} border`}>
            <StatusIcon className={`w-4 h-4 ${config.color} ${scan.status === 'running' ? 'animate-spin' : ''}`} />
            <span className={`text-sm font-medium ${config.color} capitalize`}>{scan.status}</span>
          </div>
        </div>

        {scan.status === 'completed' && totalVulnerabilities > 0 && (
          <div className="flex flex-wrap gap-2 mb-4">
            {scan.severity_critical > 0 && <SeverityBadge severity="critical" count={scan.severity_critical} />}
            {scan.severity_high > 0 && <SeverityBadge severity="high" count={scan.severity_high} />}
            {scan.severity_medium > 0 && <SeverityBadge severity="medium" count={scan.severity_medium} />}
            {scan.severity_low > 0 && <SeverityBadge severity="low" count={scan.severity_low} />}
            {scan.severity_info > 0 && <SeverityBadge severity="info" count={scan.severity_info} />}
          </div>
        )}

        <div className="flex items-center justify-between text-xs text-gray-500">
          <span>
            {scan.completed_at 
              ? `Completed ${formatDistanceToNow(new Date(scan.completed_at), { addSuffix: true })}`
              : `Started ${formatDistanceToNow(new Date(scan.started_at || scan.created_at), { addSuffix: true })}`
            }
          </span>
          {scan.status === 'completed' && (
            <span className="text-gray-400 font-medium">
              {totalVulnerabilities} {totalVulnerabilities === 1 ? 'issue' : 'issues'} found
            </span>
          )}
        </div>
      </div>
      <div className="absolute inset-0 bg-gradient-to-br from-blue-500/5 to-purple-500/5 opacity-0 group-hover:opacity-100 transition-opacity duration-300" />
    </div>
  );
}
