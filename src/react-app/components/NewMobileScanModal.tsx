import { useState } from 'react';
import { X, Loader2, Smartphone, Upload } from 'lucide-react';
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
  const [dragActive, setDragActive] = useState(false);

  if (!isOpen) return null;

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      setFile(e.dataTransfer.files[0]);
      setError(null);
    }
  };

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
      const headersObj: Record<string, string> = typeof headers === 'object' && !Array.isArray(headers) && !(headers instanceof Headers) 
        ? headers as Record<string, string>
        : {};
      if (!headersObj.Authorization) throw new Error('Not authenticated');

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

  const acceptedFormats = platform === 'android' ? '.apk' : '.ipa,.zip';

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
            <label className="block text-sm font-medium text-gray-300 mb-3">
              Select Platform
            </label>
            <div className="grid grid-cols-2 gap-3">
              <button
                type="button"
                onClick={() => setPlatform('android')}
                className={`flex items-center gap-2 px-4 py-3 rounded-lg border transition-all ${
                  platform === 'android'
                    ? 'bg-green-600/20 border-green-500 text-green-400'
                    : 'bg-gray-900 border-gray-800 text-gray-300 hover:border-gray-700'
                }`}
              >
                <Smartphone className="w-4 h-4" />
                <span className="font-medium">Android (APK)</span>
              </button>
              <button
                type="button"
                onClick={() => setPlatform('ios')}
                className={`flex items-center gap-2 px-4 py-3 rounded-lg border transition-all ${
                  platform === 'ios'
                    ? 'bg-blue-600/20 border-blue-500 text-blue-400'
                    : 'bg-gray-900 border-gray-800 text-gray-300 hover:border-gray-700'
                }`}
              >
                <Smartphone className="w-4 h-4" />
                <span className="font-medium">iOS (IPA/ZIP)</span>
              </button>
            </div>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              Upload File
            </label>
            <div
              onDragEnter={handleDrag}
              onDragOver={handleDrag}
              onDragLeave={handleDrag}
              onDrop={handleDrop}
              className={`p-6 border-2 border-dashed rounded-lg transition-all text-center ${
                dragActive 
                  ? 'border-purple-400 bg-purple-500/10' 
                  : 'border-gray-700 bg-gray-900/50 hover:border-gray-600'
              }`}
            >
              {file ? (
                <div className="space-y-2">
                  <div className="flex items-center justify-center gap-2 text-purple-400">
                    <Smartphone className="w-5 h-5" />
                    <span className="font-medium">{file.name}</span>
                  </div>
                  <button
                    type="button"
                    onClick={() => setFile(null)}
                    className="text-xs text-gray-400 hover:text-gray-300"
                  >
                    Remove file
                  </button>
                </div>
              ) : (
                <>
                  <input 
                    type="file" 
                    accept={acceptedFormats} 
                    onChange={handleFileChange}
                    className="hidden"
                    id="mobile-file-upload"
                  />
                  <label 
                    htmlFor="mobile-file-upload"
                    className="cursor-pointer"
                  >
                    <div className="space-y-2">
                      <Upload className="w-8 h-8 text-gray-500 mx-auto" />
                      <div className="text-sm text-gray-400">
                        Click to upload or drag and drop
                      </div>
                      <div className="text-xs text-gray-500">
                        {platform === 'android' ? 'APK files only' : 'IPA or ZIP files'}
                      </div>
                    </div>
                  </label>
                </>
              )}
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
              disabled={loading || !file}
              className="px-6 py-3 rounded-lg bg-gradient-to-r from-purple-600 to-pink-600 text-white hover:from-purple-700 hover:to-pink-700 transition-all font-medium shadow-lg shadow-purple-500/20 disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
            >
              {loading ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  <span>Uploading...</span>
                </>
              ) : (
                <>
                  <Upload className="w-4 h-4" />
                  <span>Upload & Scan</span>
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
