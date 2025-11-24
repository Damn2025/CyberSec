import { useNavigate } from 'react-router';
import { Smartphone, Clock, CheckCircle, AlertCircle, Loader2, ChevronRight } from 'lucide-react';
import { MobileScan } from '@/shared/types';
import SeverityBadge from './SeverityBadge';
import { formatDistanceToNow } from 'date-fns';

interface MobileScanCardProps {
  scan: MobileScan;
}

export default function MobileScanCard({ scan }: MobileScanCardProps) {
  const navigate = useNavigate();

  const statusConfig = {
    pending: { icon: Clock, color: 'text-gray-400', bg: 'bg-gray-500/10' },
    running: { icon: Loader2, color: 'text-blue-400', bg: 'bg-blue-500/10' },
    completed: { icon: CheckCircle, color: 'text-green-400', bg: 'bg-green-500/10' },
    failed: { icon: AlertCircle, color: 'text-red-400', bg: 'bg-red-500/10' },
  };

  const config = statusConfig[scan.status as keyof typeof statusConfig] || statusConfig.pending;
  const StatusIcon = config.icon;

  const totalVulnerabilities = scan.severity_critical + scan.severity_high + scan.severity_medium + scan.severity_low + scan.severity_info;

  return (
    <div
      onClick={() => navigate(`/mobile-scans/${scan.id}`)}
      className="group relative bg-gradient-to-br from-gray-900 to-gray-950 rounded-xl border border-gray-800 p-6 hover:border-purple-500/50 transition-all cursor-pointer hover:shadow-lg hover:shadow-purple-500/10"
    >
      <div className="flex items-start justify-between mb-4">
        <div className="flex items-center gap-3 flex-1 min-w-0">
          <div className="p-2 rounded-lg bg-purple-500/10 border border-purple-500/20">
            <Smartphone className="w-5 h-5 text-purple-400" />
          </div>
          <div className="flex-1 min-w-0">
            <h3 className="text-lg font-semibold text-white truncate group-hover:text-purple-400 transition-colors">
              {scan.app_name}
            </h3>
            {scan.package_name && (
              <p className="text-sm text-gray-500 truncate">{scan.package_name}</p>
            )}
          </div>
        </div>
        <ChevronRight className="w-5 h-5 text-gray-600 group-hover:text-purple-400 transition-colors flex-shrink-0" />
      </div>

      <div className="flex items-center gap-2 mb-4">
        <span className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-medium ${config.bg} ${config.color} border border-current/20`}>
          <StatusIcon className={`w-3 h-3 ${scan.status === 'running' ? 'animate-spin' : ''}`} />
          {scan.status}
        </span>
        <span className="px-3 py-1 rounded-full text-xs font-medium bg-gray-800 text-gray-400 border border-gray-700 capitalize">
          {scan.platform}
        </span>
        {scan.version && (
          <span className="px-3 py-1 rounded-full text-xs font-medium bg-gray-800 text-gray-400 border border-gray-700">
            v{scan.version}
          </span>
        )}
      </div>

      {scan.status === 'completed' && (
        <div className="grid grid-cols-5 gap-2 mb-4">
          <div className="text-center">
            <div className="text-lg font-bold text-red-400">{scan.severity_critical}</div>
            <SeverityBadge severity="critical" />
          </div>
          <div className="text-center">
            <div className="text-lg font-bold text-orange-400">{scan.severity_high}</div>
            <SeverityBadge severity="high" />
          </div>
          <div className="text-center">
            <div className="text-lg font-bold text-yellow-400">{scan.severity_medium}</div>
            <SeverityBadge severity="medium" />
          </div>
          <div className="text-center">
            <div className="text-lg font-bold text-blue-400">{scan.severity_low}</div>
            <SeverityBadge severity="low" />
          </div>
          <div className="text-center">
            <div className="text-lg font-bold text-gray-400">{scan.severity_info}</div>
            <SeverityBadge severity="info" />
          </div>
        </div>
      )}

      <div className="flex items-center justify-between text-sm text-gray-500">
        <span>
          {scan.completed_at
            ? `Completed ${formatDistanceToNow(new Date(scan.completed_at), { addSuffix: true })}`
            : `Started ${formatDistanceToNow(new Date(scan.started_at || scan.created_at), { addSuffix: true })}`
          }
        </span>
        {scan.status === 'completed' && (
          <span className="text-purple-400 font-medium">{totalVulnerabilities} issues</span>
        )}
      </div>
    </div>
  );
}
