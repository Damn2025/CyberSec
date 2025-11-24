import { useState } from 'react';
import { X, Target, Loader2 } from 'lucide-react';
import { CreateScan, ScanType } from '@/shared/types';

interface NewScanModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess: () => void;
}

export default function NewScanModal({ isOpen, onClose, onSuccess }: NewScanModalProps) {
  const [targetUrl, setTargetUrl] = useState('');
  const [scanType, setScanType] = useState<ScanType>('standard');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      const data: CreateScan = {
        target_url: targetUrl,
        scan_type: scanType,
      };

      const response = await fetch('/api/scans', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
      });

      if (!response.ok) {
        throw new Error('Failed to create scan');
      }

      setTargetUrl('');
      setScanType('standard');
      onSuccess();
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create scan');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm">
      <div className="relative w-full max-w-lg bg-gradient-to-br from-gray-900 to-gray-950 rounded-2xl border border-gray-800 shadow-2xl">
        <div className="p-6 border-b border-gray-800">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-blue-500/10 border border-blue-500/20">
                <Target className="w-5 h-5 text-blue-400" />
              </div>
              <h2 className="text-xl font-bold text-white">New Security Scan</h2>
            </div>
            <button
              onClick={onClose}
              className="p-2 rounded-lg hover:bg-gray-800 transition-colors"
            >
              <X className="w-5 h-5 text-gray-400" />
            </button>
          </div>
        </div>

        <form onSubmit={handleSubmit} className="p-6 space-y-6">
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              Target URL
            </label>
            <input
              type="url"
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              placeholder="https://example.com"
              required
              className="w-full px-4 py-3 bg-gray-900/50 border border-gray-700 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500/50 focus:border-blue-500 transition-all"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              Scan Type
            </label>
            <div className="grid grid-cols-2 gap-3">
              {(['quick', 'standard', 'comprehensive', 'api', 'mobile'] as ScanType[]).map((type) => (
                <button
                  key={type}
                  type="button"
                  onClick={() => setScanType(type)}
                  className={`p-4 rounded-lg border text-left transition-all ${
                    scanType === type
                      ? 'bg-blue-500/10 border-blue-500/50 shadow-lg shadow-blue-500/20'
                      : 'bg-gray-900/50 border-gray-700 hover:border-gray-600'
                  }`}
                >
                  <div className="font-medium text-white capitalize mb-1">{type}</div>
                  <div className="text-xs text-gray-400">
                    {type === 'quick' && 'Fast basic checks'}
                    {type === 'standard' && 'Recommended depth'}
                    {type === 'comprehensive' && 'Deep analysis'}
                    {type === 'api' && 'API security scan'}
                    {type === 'mobile' && 'Mobile app scan'}
                  </div>
                </button>
              ))}
            </div>
          </div>

          {error && (
            <div className="p-4 bg-red-500/10 border border-red-500/20 rounded-lg text-red-400 text-sm">
              {error}
            </div>
          )}

          <div className="flex gap-3">
            <button
              type="button"
              onClick={onClose}
              className="flex-1 px-4 py-3 rounded-lg border border-gray-700 text-gray-300 font-medium hover:bg-gray-800 transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={loading}
              className="flex-1 px-4 py-3 rounded-lg bg-gradient-to-r from-blue-500 to-purple-500 text-white font-medium hover:from-blue-600 hover:to-purple-600 disabled:opacity-50 disabled:cursor-not-allowed transition-all shadow-lg shadow-blue-500/20 flex items-center justify-center gap-2"
            >
              {loading ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  Starting Scan...
                </>
              ) : (
                'Start Scan'
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
