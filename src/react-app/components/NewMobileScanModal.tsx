import { useState } from 'react';
import { X, Smartphone, Upload, Loader2 } from 'lucide-react';
import { MobilePlatform } from '@/shared/types';

interface NewMobileScanModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess: () => void;
}

export default function NewMobileScanModal({ isOpen, onClose, onSuccess }: NewMobileScanModalProps) {
  const [platform, setPlatform] = useState<MobilePlatform>('android');
  const [file, setFile] = useState<File | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [dragActive, setDragActive] = useState(false);

  if (!isOpen) return null;

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") {
      setDragActive(true);
    } else if (e.type === "dragleave") {
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

      const response = await fetch('/api/mobile-scans', {
        method: 'POST',
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
  const fileExtension = platform === 'android' ? 'APK' : 'IPA';

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
            <div className="grid grid-cols-2 gap-3">
              <button
                type="button"
                onClick={() => {
                  setPlatform('android');
                  setFile(null);
                }}
                className={`p-4 rounded-lg border text-left transition-all ${
                  platform === 'android'
                    ? 'bg-purple-500/10 border-purple-500/50 shadow-lg shadow-purple-500/20'
                    : 'bg-gray-900/50 border-gray-700 hover:border-gray-600'
                }`}
              >
                <div className="font-medium text-white mb-1">Android</div>
                <div className="text-xs text-gray-400">APK files</div>
              </button>
              <button
                type="button"
                onClick={() => {
                  setPlatform('ios');
                  setFile(null);
                }}
                className={`p-4 rounded-lg border text-left transition-all ${
                  platform === 'ios'
                    ? 'bg-purple-500/10 border-purple-500/50 shadow-lg shadow-purple-500/20'
                    : 'bg-gray-900/50 border-gray-700 hover:border-gray-600'
                }`}
              >
                <div className="font-medium text-white mb-1">iOS</div>
                <div className="text-xs text-gray-400">IPA files</div>
              </button>
            </div>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              Upload {fileExtension} File
            </label>
            <div
              onDragEnter={handleDrag}
              onDragLeave={handleDrag}
              onDragOver={handleDrag}
              onDrop={handleDrop}
              className={`relative border-2 border-dashed rounded-lg p-8 text-center transition-all ${
                dragActive
                  ? 'border-purple-500 bg-purple-500/10'
                  : 'border-gray-700 bg-gray-900/30 hover:border-gray-600'
              }`}
            >
              <input
                type="file"
                onChange={handleFileChange}
                accept={acceptedFormats}
                className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
              />
              <Upload className="w-12 h-12 text-gray-600 mx-auto mb-4" />
              {file ? (
                <div>
                  <p className="text-white font-medium mb-1">{file.name}</p>
                  <p className="text-sm text-gray-400">
                    {(file.size / 1024 / 1024).toFixed(2)} MB
                  </p>
                </div>
              ) : (
                <div>
                  <p className="text-gray-300 mb-1">
                    Drop your {fileExtension} file here or click to browse
                  </p>
                  <p className="text-sm text-gray-500">
                    Maximum file size: 100MB
                  </p>
                </div>
              )}
            </div>
          </div>

          <div className="bg-blue-500/10 border border-blue-500/20 rounded-lg p-4">
            <h4 className="text-sm font-semibold text-blue-400 mb-2">What we'll analyze:</h4>
            <ul className="text-xs text-gray-300 space-y-1">
              <li>• OWASP Mobile Top 10 vulnerabilities</li>
              <li>• Insecure data storage and communication</li>
              <li>• Code quality and reverse engineering risks</li>
              <li>• Authentication and authorization flaws</li>
              <li>• Cryptography implementation issues</li>
              <li>• Platform-specific security misconfigurations</li>
            </ul>
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
              disabled={loading || !file}
              className="flex-1 px-4 py-3 rounded-lg bg-gradient-to-r from-purple-500 to-pink-500 text-white font-medium hover:from-purple-600 hover:to-pink-600 disabled:opacity-50 disabled:cursor-not-allowed transition-all shadow-lg shadow-purple-500/20 flex items-center justify-center gap-2"
            >
              {loading ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  Uploading...
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
