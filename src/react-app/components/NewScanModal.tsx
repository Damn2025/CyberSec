import { useState } from 'react';
import { X, Target, Loader2 } from 'lucide-react';
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
      const headersObj = headers as Record<string, string>;
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
              className="w-full px-3 py-2 rounded-lg bg-gray-900 border border-gray-800 text-white"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              Scan type
            </label>
            <select
              value={scanType}
              onChange={(e) => setScanType(e.target.value as ScanType)}
              className="w-full px-3 py-2 rounded-lg bg-gray-900 border border-gray-800 text-white"
            >
              <option value="quick">Quick</option>
              <option value="standard">Standard</option>
              <option value="comprehensive">Comprehensive</option>
              <option value="api">API</option>
              <option value="mobile">Mobile</option>
            </select>
          </div>

          <div className="flex justify-end gap-3">
            <button
              type="button"
              onClick={() => { onClose(); }}
              className="px-4 py-2 rounded-lg bg-gray-800 text-white"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={loading}
              className="px-4 py-2 rounded-lg bg-green-600 text-white"
            >
              {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : 'Create Scan'}
            </button>
          </div>

          {error && <div className="text-red-400 text-sm">{error}</div>}
        </form>
      </div>
    </div>
  );
}
