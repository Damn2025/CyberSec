import { useState } from 'react';
import { X, Target, Loader2, Globe, Zap, Shield, Code } from 'lucide-react';
import { CreateScan, ScanType } from '@/shared/types';
import { getApiUrl, getAuthHeaders } from '@/react-app/lib/api';

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

      const headers = await getAuthHeaders('application/json');
      const headersObj: Record<string, string> = typeof headers === 'object' && !Array.isArray(headers) && !(headers instanceof Headers) 
        ? headers as Record<string, string>
        : {};
      if (!headersObj.Authorization) throw new Error('Not authenticated');

      const response = await fetch(getApiUrl('/api/scans'), {
        method: 'POST',
        headers,
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
              className="w-full px-4 py-3 rounded-lg bg-gray-900 border border-gray-800 text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-300 mb-3">
              Select Scanner Type
            </label>
            <div className="grid grid-cols-2 gap-3">
              <button
                type="button"
                onClick={() => setScanType('quick')}
                className={`flex items-center gap-2 px-4 py-3 rounded-lg border transition-all ${
                  scanType === 'quick'
                    ? 'bg-blue-600/20 border-blue-500 text-blue-400'
                    : 'bg-gray-900 border-gray-800 text-gray-300 hover:border-gray-700'
                }`}
              >
                <Zap className="w-4 h-4" />
                <span className="font-medium">Quick</span>
              </button>
              <button
                type="button"
                onClick={() => setScanType('standard')}
                className={`flex items-center gap-2 px-4 py-3 rounded-lg border transition-all ${
                  scanType === 'standard'
                    ? 'bg-blue-600/20 border-blue-500 text-blue-400'
                    : 'bg-gray-900 border-gray-800 text-gray-300 hover:border-gray-700'
                }`}
              >
                <Shield className="w-4 h-4" />
                <span className="font-medium">Standard</span>
              </button>
              <button
                type="button"
                onClick={() => setScanType('comprehensive')}
                className={`flex items-center gap-2 px-4 py-3 rounded-lg border transition-all ${
                  scanType === 'comprehensive'
                    ? 'bg-blue-600/20 border-blue-500 text-blue-400'
                    : 'bg-gray-900 border-gray-800 text-gray-300 hover:border-gray-700'
                }`}
              >
                <Globe className="w-4 h-4" />
                <span className="font-medium">Comprehensive</span>
              </button>
              <button
                type="button"
                onClick={() => setScanType('api')}
                className={`flex items-center gap-2 px-4 py-3 rounded-lg border transition-all ${
                  scanType === 'api'
                    ? 'bg-blue-600/20 border-blue-500 text-blue-400'
                    : 'bg-gray-900 border-gray-800 text-gray-300 hover:border-gray-700'
                }`}
              >
                <Code className="w-4 h-4" />
                <span className="font-medium">API</span>
              </button>
            </div>
          </div>

          <div className="flex justify-end gap-3 pt-4 border-t border-gray-800">
            <button
              type="button"
              onClick={() => { onClose(); }}
              className="px-6 py-3 rounded-lg bg-gray-800 text-white hover:bg-gray-700 transition-colors font-medium"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={loading || !targetUrl}
              className="px-6 py-3 rounded-lg bg-gradient-to-r from-blue-600 to-purple-600 text-white hover:from-blue-700 hover:to-purple-700 transition-all font-medium shadow-lg shadow-blue-500/20 disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
            >
              {loading ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  <span>Creating...</span>
                </>
              ) : (
                <>
                  <Target className="w-4 h-4" />
                  <span>Start Scan</span>
                </>
              )}
            </button>
          </div>

          {error && <div className="text-red-400 text-sm">{error}</div>}
        </form>
      </div>
    </div>
  );
}
