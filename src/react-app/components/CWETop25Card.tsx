import { useState } from 'react';
import { Vulnerability } from '@/shared/types';
import { ChevronDown, ChevronUp, Shield, Info, Award, TrendingUp, Globe } from 'lucide-react';
import SeverityBadge from './SeverityBadge';

interface CWETop25CardProps {
  vulnerability: Vulnerability;
}

// Extract rank from title if it contains "CWE Top 25 #"
const extractRank = (title: string): number | null => {
  const match = title.match(/CWE Top 25 #(\d+)/);
  return match ? parseInt(match[1], 10) : null;
};

// Extract CWE name from title
const extractCWEName = (title: string): string => {
  const match = title.match(/^(.+?)\s*\(CWE Top 25/);
  return match ? match[1].trim() : title;
};

export default function CWETop25Card({ vulnerability }: CWETop25CardProps) {
  const [expanded, setExpanded] = useState(false);
  
  const rank = extractRank(vulnerability.title);
  const cweName = extractCWEName(vulnerability.title);

  // Get rank badge color based on rank
  const getRankColor = (rank: number | null) => {
    if (!rank) return 'bg-gray-500/10 text-gray-400 border-gray-500/20';
    if (rank <= 5) return 'bg-red-500/10 text-red-400 border-red-500/20';
    if (rank <= 10) return 'bg-orange-500/10 text-orange-400 border-orange-500/20';
    if (rank <= 15) return 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20';
    return 'bg-blue-500/10 text-blue-400 border-blue-500/20';
  };

  return (
    <div className="group rounded-xl border border-gray-800 bg-gradient-to-br from-gray-900 to-gray-950 backdrop-blur-sm transition-all duration-300 hover:border-gray-700 overflow-hidden">
      <div
        onClick={() => setExpanded(!expanded)}
        className="p-5 cursor-pointer"
      >
        <div className="flex items-start justify-between gap-4 mb-3">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-3 mb-2">
              {rank && (
                <div className={`flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold ${getRankColor(rank)} border`}>
                  <Award className="w-3.5 h-3.5" />
                  <span>#{rank}</span>
                </div>
              )}
              <h3 className="text-lg font-semibold text-white">{cweName}</h3>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <SeverityBadge severity={vulnerability.severity} />
              {vulnerability.cwe_id && (
                <span className="px-2.5 py-1 rounded-full text-xs font-medium bg-blue-500/10 text-blue-400 border border-blue-500/20 flex items-center gap-1">
                  <Shield className="w-3 h-3" />
                  {vulnerability.cwe_id}
                </span>
              )}
              {vulnerability.cvss_score && (
                <span className="px-2.5 py-1 rounded-full text-xs font-medium bg-purple-500/10 text-purple-400 border border-purple-500/20 flex items-center gap-1">
                  <TrendingUp className="w-3 h-3" />
                  Score: {vulnerability.cvss_score.toFixed(1)}
                </span>
              )}
              {vulnerability.category && (
                <span className="px-2.5 py-1 rounded-full text-xs font-medium bg-gray-800 text-gray-300 border border-gray-700">
                  {vulnerability.category}
                </span>
              )}
            </div>
          </div>
          <button className="p-2 rounded-lg hover:bg-gray-800 transition-colors flex-shrink-0">
            {expanded ? (
              <ChevronUp className="w-5 h-5 text-gray-400" />
            ) : (
              <ChevronDown className="w-5 h-5 text-gray-400" />
            )}
          </button>
        </div>

        <p className="text-sm text-gray-400 leading-relaxed">
          {vulnerability.description}
        </p>
      </div>

      {expanded && (
        <div className="border-t border-gray-800 bg-gray-950/50 p-5 space-y-4">
          {/* CWE Information */}
          {vulnerability.cwe_id && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="p-3 rounded-lg bg-blue-500/5 border border-blue-500/20">
                <div className="flex items-center gap-2 mb-1">
                  <Shield className="w-4 h-4 text-blue-400" />
                  <h4 className="text-sm font-semibold text-white">CWE ID</h4>
                </div>
                <p className="text-sm text-gray-300 font-mono">{vulnerability.cwe_id}</p>
              </div>
              {rank && (
                <div className="p-3 rounded-lg bg-purple-500/5 border border-purple-500/20">
                  <div className="flex items-center gap-2 mb-1">
                    <Award className="w-4 h-4 text-purple-400" />
                    <h4 className="text-sm font-semibold text-white">CWE Top 25 Rank</h4>
                  </div>
                  <p className="text-sm text-gray-300">#{rank} of 25</p>
                </div>
              )}
              {vulnerability.cvss_score && (
                <div className="p-3 rounded-lg bg-orange-500/5 border border-orange-500/20">
                  <div className="flex items-center gap-2 mb-1">
                    <TrendingUp className="w-4 h-4 text-orange-400" />
                    <h4 className="text-sm font-semibold text-white">CWE Score</h4>
                  </div>
                  <p className="text-sm text-gray-300">{vulnerability.cvss_score.toFixed(2)}</p>
                </div>
              )}
              <div className="p-3 rounded-lg bg-green-500/5 border border-green-500/20">
                <div className="flex items-center gap-2 mb-1">
                  <Globe className="w-4 h-4 text-green-400" />
                  <h4 className="text-sm font-semibold text-white">Severity</h4>
                </div>
                <SeverityBadge severity={vulnerability.severity} />
              </div>
            </div>
          )}

          {vulnerability.evidence && (
            <div>
              <div className="flex items-center gap-2 mb-2">
                <Info className="w-4 h-4 text-blue-400" />
                <h4 className="text-sm font-semibold text-white">Detection Evidence</h4>
              </div>
              <pre className="p-3 bg-gray-900 rounded-lg text-xs text-gray-300 overflow-x-auto border border-gray-800 whitespace-pre-wrap">
                {vulnerability.evidence}
              </pre>
            </div>
          )}

          {vulnerability.recommendation && (
            <div>
              <div className="flex items-center gap-2 mb-2">
                <Shield className="w-4 h-4 text-green-400" />
                <h4 className="text-sm font-semibold text-white">Mitigation Recommendation</h4>
              </div>
              <p className="text-sm text-gray-300 leading-relaxed p-3 bg-green-500/5 rounded-lg border border-green-500/20">
                {vulnerability.recommendation}
              </p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

