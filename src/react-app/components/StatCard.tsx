import { LucideIcon } from 'lucide-react';

interface StatCardProps {
  title: string;
  value: number | string;
  icon: LucideIcon;
  trend?: string;
  color?: 'blue' | 'green' | 'red' | 'purple' | 'yellow';
}

export default function StatCard({ title, value, icon: Icon, trend, color = 'blue' }: StatCardProps) {
  const colorStyles = {
    blue: 'from-blue-500/20 to-blue-600/20 border-blue-500/30 text-blue-400',
    green: 'from-green-500/20 to-green-600/20 border-green-500/30 text-green-400',
    red: 'from-red-500/20 to-red-600/20 border-red-500/30 text-red-400',
    purple: 'from-purple-500/20 to-purple-600/20 border-purple-500/30 text-purple-400',
    yellow: 'from-yellow-500/20 to-yellow-600/20 border-yellow-500/30 text-yellow-400',
  };

  return (
    <div className={`relative group overflow-hidden rounded-xl border bg-gradient-to-br backdrop-blur-sm ${colorStyles[color]} transition-all duration-300 hover:scale-[1.02] hover:shadow-lg`}>
      <div className="p-6">
        <div className="flex items-start justify-between">
          <div className="flex-1">
            <p className="text-sm font-medium text-gray-400 mb-1">{title}</p>
            <p className="text-3xl font-bold text-white mb-1">{value}</p>
            {trend && (
              <p className="text-xs text-gray-400">{trend}</p>
            )}
          </div>
          <div className={`p-3 rounded-lg bg-gradient-to-br ${colorStyles[color]} shadow-lg`}>
            <Icon className="w-6 h-6" />
          </div>
        </div>
      </div>
      <div className={`absolute inset-0 bg-gradient-to-br ${colorStyles[color]} opacity-0 group-hover:opacity-10 transition-opacity duration-300`} />
    </div>
  );
}
