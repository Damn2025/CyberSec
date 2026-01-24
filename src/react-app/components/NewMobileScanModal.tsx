import { useState } from 'react';
import { X, Loader2, Smartphone } from 'lucide-react';
import { getApiUrl, getAuthHeaders } from '@/react-app/lib/api';

interface NewMobileScanModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess: () => void;
}

export default function NewMobileScanModal({ isOpen, onClose, onSuccess }: NewMobileScanModalProps) {
  const [file, setFile] = useState<File | null>(null);
  const [platform, setPlatform] = useState<'android' | 'ios'>('android');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      setFile(e.target.files[0]);
      setError(null);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!file) {
      setError('Please select a file');
      return;
    }

    setError(null);
    setLoading(true);

    try {
      const formData = new FormData();
      formData.append('file', file);
      formData.append('platform', platform);

      // Attach Authorization if available; don't set Content-Type for FormData
      const headers = await getAuthHeaders(null);
      if (!headers['Authorization']) throw new Error('Not authenticated');

      const response = await fetch(getApiUrl('/api/mobile-scans'), {
        method: 'POST',
        headers,
        body: formData,
      });

      if (!response.ok) {
        const data = await response.json();
        throw new Error(data.error || 'Failed to upload file');
      }

      setFile(null);
      setPlatform('android');
      onSuccess();
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create mobile scan');
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
              <div className="p-2 rounded-lg bg-purple-500/10 border border-purple-500/20">
                <Smartphone className="w-5 h-5 text-purple-400" />
              </div>
              <h2 className="text-xl font-bold text-white">New Mobile App Scan</h2>
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
              Platform
            </label>
            <select
              value={platform}
              onChange={(e) => setPlatform(e.target.value as 'android' | 'ios')}
              className="w-full px-3 py-2 rounded-lg bg-gray-900 border border-gray-800 text-white"
            >
              <option value="android">Android (APK)</option>
              <option value="ios">iOS (IPA/ZIP)</option>
            </select>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              File
            </label>
            <input type="file" accept={platform === 'android' ? '.apk' : '.ipa,.zip'} onChange={handleFileChange} />
          </div>

          <div className="flex justify-end gap-3">
            <button type="button" onClick={() => { onClose(); }} className="px-4 py-2 rounded-lg bg-gray-800 text-white">
              Cancel
            </button>
            <button type="submit" disabled={loading} className="px-4 py-2 rounded-lg bg-green-600 text-white">
              {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : 'Upload & Scan'}
            </button>
          </div>

          {error && <div className="text-red-400 text-sm">{error}</div>}
        </form>
      </div>
    </div>
  );
}
