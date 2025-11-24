import { Severity } from '@/shared/types';

interface SeverityBadgeProps {
  severity: Severity | string;
  count?: number;
}

export default function SeverityBadge({ severity, count }: SeverityBadgeProps) {
  const configs = {
    critical: {
      bg: 'bg-red-500/10',
      text: 'text-red-500',
      border: 'border-red-500/20',
      glow: 'shadow-red-500/20',
    },
    high: {
      bg: 'bg-orange-500/10',
      text: 'text-orange-500',
      border: 'border-orange-500/20',
      glow: 'shadow-orange-500/20',
    },
    medium: {
      bg: 'bg-yellow-500/10',
      text: 'text-yellow-500',
      border: 'border-yellow-500/20',
      glow: 'shadow-yellow-500/20',
    },
    low: {
      bg: 'bg-blue-500/10',
      text: 'text-blue-500',
      border: 'border-blue-500/20',
      glow: 'shadow-blue-500/20',
    },
    info: {
      bg: 'bg-gray-500/10',
      text: 'text-gray-500',
      border: 'border-gray-500/20',
      glow: 'shadow-gray-500/20',
    },
  };

  const config = configs[severity as keyof typeof configs] || configs.info;

  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium border ${config.bg} ${config.text} ${config.border} ${config.glow} shadow-sm`}
    >
      <span className={`w-1.5 h-1.5 rounded-full ${config.text.replace('text-', 'bg-')}`} />
      {severity.charAt(0).toUpperCase() + severity.slice(1)}
      {count !== undefined && <span className="ml-1 opacity-75">({count})</span>}
    </span>
  );
}
