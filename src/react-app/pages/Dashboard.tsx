import { useState } from 'react';
import { Shield, Activity, AlertTriangle, FileSearch, Plus, Globe, Smartphone } from 'lucide-react';
import StatCard from '@/react-app/components/StatCard';
import ScanCard from '@/react-app/components/ScanCard';
import MobileScanCard from '@/react-app/components/MobileScanCard';
import NewScanModal from '@/react-app/components/NewScanModal';
import NewMobileScanModal from '@/react-app/components/NewMobileScanModal';
import { useScans, useDashboardStats } from '@/react-app/hooks/useScans';
import { useMobileScans } from '@/react-app/hooks/useMobileScans';

export default function Dashboard() {
  const [modalOpen, setModalOpen] = useState(false);
  const [mobileModalOpen, setMobileModalOpen] = useState(false);
  const [activeTab, setActiveTab] = useState<'web' | 'mobile'>('web');
  const { scans, loading, refetch } = useScans();
  const { scans: mobileScans, loading: mobileLoading, refetch: refetchMobile } = useMobileScans();
  const { stats } = useDashboardStats();

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-950 via-gray-900 to-black">
      {/* Header */}
      <div className="border-b border-gray-800 bg-gray-950/50 backdrop-blur-xl sticky top-0 z-10">
        <div className="max-w-7xl mx-auto px-6 py-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <div className="p-3 rounded-xl bg-gradient-to-br from-blue-500 to-purple-600 shadow-lg shadow-blue-500/20">
                <Shield className="w-8 h-8 text-white" />
              </div>
              <div>
                <h1 className="text-3xl font-bold bg-gradient-to-r from-white to-gray-400 bg-clip-text text-transparent">
                  CyberSec
                </h1>
                <p className="text-sm text-gray-400">Advanced Security Vulnerability Scanner</p>
              </div>
            </div>
            <div className="flex items-center gap-3">
              <button
                onClick={() => setModalOpen(true)}
                className="flex items-center gap-2 px-6 py-3 rounded-xl bg-gradient-to-r from-blue-500 to-purple-600 text-white font-medium hover:from-blue-600 hover:to-purple-700 transition-all shadow-lg shadow-blue-500/20 hover:shadow-blue-500/30 hover:scale-105"
              >
                <Globe className="w-5 h-5" />
                Web Scan
              </button>
              <button
                onClick={() => setMobileModalOpen(true)}
                className="flex items-center gap-2 px-6 py-3 rounded-xl bg-gradient-to-r from-purple-500 to-pink-600 text-white font-medium hover:from-purple-600 hover:to-pink-700 transition-all shadow-lg shadow-purple-500/20 hover:shadow-purple-500/30 hover:scale-105"
              >
                <Smartphone className="w-5 h-5" />
                Mobile Scan
              </button>
            </div>
          </div>
        </div>
      </div>

      <div className="max-w-7xl mx-auto px-6 py-8">
        {/* Stats Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
          <StatCard
            title="Total Scans"
            value={stats.totalScans}
            icon={FileSearch}
            color="blue"
          />
          <StatCard
            title="Completed"
            value={stats.completedScans}
            icon={Shield}
            color="green"
          />
          <StatCard
            title="Active Scans"
            value={stats.runningScans}
            icon={Activity}
            color="purple"
          />
          <StatCard
            title="Critical Issues"
            value={stats.criticalVulnerabilities}
            icon={AlertTriangle}
            color="red"
          />
        </div>

        {/* Scans Section */}
        <div>
          <div className="flex items-center justify-between mb-6">
            <h2 className="text-2xl font-bold text-white">Recent Scans</h2>
            <div className="flex items-center gap-4">
              <div className="flex items-center gap-2 text-sm text-gray-400">
                <Activity className="w-4 h-4" />
                <span>Auto-refreshing</span>
              </div>
              <div className="flex items-center gap-2 bg-gray-900 rounded-lg p-1 border border-gray-800">
                <button
                  onClick={() => setActiveTab('web')}
                  className={`flex items-center gap-2 px-4 py-2 rounded-md text-sm font-medium transition-all ${
                    activeTab === 'web'
                      ? 'bg-blue-500 text-white'
                      : 'text-gray-400 hover:text-white'
                  }`}
                >
                  <Globe className="w-4 h-4" />
                  Web
                </button>
                <button
                  onClick={() => setActiveTab('mobile')}
                  className={`flex items-center gap-2 px-4 py-2 rounded-md text-sm font-medium transition-all ${
                    activeTab === 'mobile'
                      ? 'bg-purple-500 text-white'
                      : 'text-gray-400 hover:text-white'
                  }`}
                >
                  <Smartphone className="w-4 h-4" />
                  Mobile
                </button>
              </div>
            </div>
          </div>

          {activeTab === 'web' ? (
            loading && scans.length === 0 ? (
              <div className="flex items-center justify-center py-20">
                <div className="text-center">
                  <Activity className="w-12 h-12 text-gray-600 mx-auto mb-4 animate-pulse" />
                  <p className="text-gray-400">Loading scans...</p>
                </div>
              </div>
            ) : scans.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-20 px-6 text-center">
              <div className="p-6 rounded-2xl bg-gradient-to-br from-gray-800 to-gray-900 border border-gray-700 mb-6">
                <FileSearch className="w-16 h-16 text-gray-600 mx-auto" />
              </div>
              <h3 className="text-xl font-semibold text-white mb-2">No scans yet</h3>
              <p className="text-gray-400 mb-6 max-w-md">
                Get started by creating your first security scan. We'll analyze your application for vulnerabilities.
              </p>
              <button
                  onClick={() => setModalOpen(true)}
                  className="flex items-center gap-2 px-6 py-3 rounded-xl bg-gradient-to-r from-blue-500 to-purple-600 text-white font-medium hover:from-blue-600 hover:to-purple-700 transition-all shadow-lg shadow-blue-500/20"
                >
                  <Plus className="w-5 h-5" />
                  Create First Web Scan
                </button>
              </div>
            ) : (
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {scans.map((scan) => (
                  <ScanCard key={scan.id} scan={scan} />
                ))}
              </div>
            )
          ) : (
            mobileLoading && mobileScans.length === 0 ? (
              <div className="flex items-center justify-center py-20">
                <div className="text-center">
                  <Activity className="w-12 h-12 text-gray-600 mx-auto mb-4 animate-pulse" />
                  <p className="text-gray-400">Loading mobile scans...</p>
                </div>
              </div>
            ) : mobileScans.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-20 px-6 text-center">
                <div className="p-6 rounded-2xl bg-gradient-to-br from-gray-800 to-gray-900 border border-gray-700 mb-6">
                  <Smartphone className="w-16 h-16 text-gray-600 mx-auto" />
                </div>
                <h3 className="text-xl font-semibold text-white mb-2">No mobile scans yet</h3>
                <p className="text-gray-400 mb-6 max-w-md">
                  Upload an Android APK or iOS IPA file to analyze your mobile application for security vulnerabilities.
                </p>
                <button
                  onClick={() => setMobileModalOpen(true)}
                  className="flex items-center gap-2 px-6 py-3 rounded-xl bg-gradient-to-r from-purple-500 to-pink-600 text-white font-medium hover:from-purple-600 hover:to-pink-700 transition-all shadow-lg shadow-purple-500/20"
                >
                  <Plus className="w-5 h-5" />
                  Create First Mobile Scan
                </button>
              </div>
            ) : (
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {mobileScans.map((scan) => (
                  <MobileScanCard key={scan.id} scan={scan} />
                ))}
              </div>
            )
          )}
        </div>
      </div>

      <NewScanModal
        isOpen={modalOpen}
        onClose={() => setModalOpen(false)}
        onSuccess={refetch}
      />

      <NewMobileScanModal
        isOpen={mobileModalOpen}
        onClose={() => setMobileModalOpen(false)}
        onSuccess={refetchMobile}
      />
    </div>
  );
}
