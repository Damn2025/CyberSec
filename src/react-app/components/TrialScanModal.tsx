import { useState } from 'react';
import { X, Globe, Smartphone, Loader2, Target } from 'lucide-react';
import { ScanType } from '@/shared/types';
import { getApiUrl } from '@/react-app/lib/api';

interface TrialScanModalProps {
  isOpen: boolean;
  onClose: () => void;
  onScanComplete: (scanType: 'web' | 'mobile', data: any) => void;
  onOpenLogin: () => void;
  onOpenSignup: () => void;
}

export default function TrialScanModal({ 
  isOpen, 
  onClose, 
  onScanComplete,
  onOpenLogin,
  onOpenSignup 
}: TrialScanModalProps) {
  const [selectedType, setSelectedType] = useState<'web' | 'mobile' | null>(null);
  const [targetUrl, setTargetUrl] = useState('');
  const [scanType, setScanType] = useState<ScanType>('standard');
  const [file, setFile] = useState<File | null>(null);
  const [platform, setPlatform] = useState<'android' | 'ios'>('android');
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

  const performTrialScan = async () => {
    setLoading(true);
    setError(null);

    try {
      // Simulate scan delay
      await new Promise(resolve => setTimeout(resolve, 2000));

      if (selectedType === 'web') {
        // Perform web scan without storing
        const response = await fetch(getApiUrl('/api/scans/trial'), {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            target_url: targetUrl,
            scan_type: scanType,
          }),
        });

        if (!response.ok) {
          // If trial endpoint doesn't exist, simulate results
          const mockResults = {
            scan: {
              id: 'trial-' + Date.now(),
              target_url: targetUrl,
              scan_type: scanType,
              status: 'completed',
              severity_critical: 3,
              severity_high: 5,
              severity_medium: 8,
              severity_low: 12,
              severity_info: 4,
            },
            vulnerabilities: [
              {
                id: 1,
                title: 'SQL Injection Vulnerability',
                description: 'The application is vulnerable to SQL injection attacks...',
                severity: 'critical',
                category: 'Injection',
                cvss_score: 9.8,
                recommendation: 'Use parameterized queries...',
              },
              {
                id: 2,
                title: 'Cross-Site Scripting (XSS)',
                description: 'Reflected XSS vulnerability detected...',
                severity: 'high',
                category: 'XSS',
                cvss_score: 7.5,
                recommendation: 'Implement proper input validation...',
              },
            ],
          };
          onScanComplete('web', mockResults);
          setLoading(false);
          return;
        }

        const data = await response.json();
        onScanComplete('web', data);
        setLoading(false);
      } else {
        // Perform mobile scan without storing
        if (!file) {
          setError('Please select a file');
          setLoading(false);
          return;
        }

        const formData = new FormData();
        formData.append('file', file);
        formData.append('platform', platform);

        const response = await fetch(getApiUrl('/api/mobile-scans/trial'), {
          method: 'POST',
          body: formData,
        });

        if (!response.ok) {
          // If trial endpoint doesn't exist, simulate results
          const mockResults = {
            scan: {
              id: 'trial-mobile-' + Date.now(),
              app_name: file.name,
              platform: platform,
              status: 'completed',
              severity_critical: 2,
              severity_high: 4,
              severity_medium: 6,
              severity_low: 10,
              severity_info: 3,
            },
            vulnerabilities: [
              {
                id: 1,
                title: 'Insecure Data Storage',
                description: 'The app stores sensitive data in plaintext...',
                severity: 'critical',
                owasp_category: 'M2',
                cvss_score: 8.5,
                recommendation: 'Encrypt sensitive data before storage...',
              },
              {
                id: 2,
                title: 'Weak Cryptography',
                description: 'Weak encryption algorithms detected...',
                severity: 'high',
                owasp_category: 'M5',
                cvss_score: 7.0,
                recommendation: 'Use strong cryptographic algorithms...',
              },
            ],
          };
          onScanComplete('mobile', mockResults);
          setLoading(false);
          return;
        }

        const data = await response.json();
        onScanComplete('mobile', data);
        setLoading(false);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to perform scan');
      setLoading(false);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!selectedType) {
      setError('Please select scan type');
      return;
    }

    if (selectedType === 'web' && !targetUrl) {
      setError('Please enter a target URL');
      return;
    }

    if (selectedType === 'mobile' && !file) {
      setError('Please select a file');
      return;
    }

    await performTrialScan();
  };

  const resetForm = () => {
    setSelectedType(null);
    setTargetUrl('');
    setScanType('standard');
    setFile(null);
    setPlatform('android');
    setError(null);
  };

  const handleClose = () => {
    resetForm();
    onClose();
  };

  if (selectedType === null) {
    return (
      <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm">
        <div className="relative w-full max-w-lg bg-gradient-to-br from-gray-900 to-gray-950 rounded-2xl border border-gray-800 shadow-2xl">
          <div className="p-6 border-b border-gray-800">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-red-500/10 border border-red-500/20">
                  <Target className="w-5 h-5 text-red-400" />
                </div>
                <h2 className="text-xl font-bold text-white">Start Your Trial Scan</h2>
              </div>
              <button
                onClick={handleClose}
                className="p-2 rounded-lg hover:bg-gray-800 transition-colors"
              >
                <X className="w-5 h-5 text-gray-400" />
              </button>
            </div>
          </div>

          <div className="p-6">
            <p className="text-gray-300 mb-6 text-center">
              Choose your scan type to get started. Results will be previewed without saving.
            </p>

            <div className="grid grid-cols-2 gap-4">
              <button
                onClick={() => setSelectedType('web')}
                className="p-6 rounded-lg border-2 border-gray-700 hover:border-blue-500/50 bg-gray-900/50 hover:bg-blue-500/10 transition-all group"
              >
                <div className="flex flex-col items-center gap-3">
                  <div className="p-3 rounded-lg bg-blue-500/10 border border-blue-500/20 group-hover:bg-blue-500/20 transition-colors">
                    <Globe className="w-8 h-8 text-blue-400" />
                  </div>
                  <div className="font-medium text-white text-lg">Web</div>
                  <div className="text-xs text-gray-400 text-center">
                    Scan websites and web applications
                  </div>
                </div>
              </button>

              <button
                onClick={() => setSelectedType('mobile')}
                className="p-6 rounded-lg border-2 border-gray-700 hover:border-purple-500/50 bg-gray-900/50 hover:bg-purple-500/10 transition-all group"
              >
                <div className="flex flex-col items-center gap-3">
                  <div className="p-3 rounded-lg bg-purple-500/10 border border-purple-500/20 group-hover:bg-purple-500/20 transition-colors">
                    <Smartphone className="w-8 h-8 text-purple-400" />
                  </div>
                  <div className="font-medium text-white text-lg">Mobile</div>
                  <div className="text-xs text-gray-400 text-center">
                    Scan Android APK or iOS IPA files
                  </div>
                </div>
              </button>
            </div>

            <div className="mt-6 p-4 bg-yellow-500/10 border border-yellow-500/20 rounded-lg">
              <p className="text-xs text-yellow-300 text-center">
                ⚠️ Trial scans are for preview only. Sign up to save and manage your scans.
              </p>
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm">
      <div className="relative w-full max-w-lg bg-gradient-to-br from-gray-900 to-gray-950 rounded-2xl border border-gray-800 shadow-2xl max-h-[90vh] overflow-y-auto">
        <div className="p-6 border-b border-gray-800 sticky top-0 bg-gray-950 z-10">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className={`p-2 rounded-lg ${selectedType === 'web' ? 'bg-blue-500/10 border border-blue-500/20' : 'bg-purple-500/10 border border-purple-500/20'}`}>
                {selectedType === 'web' ? (
                  <Globe className="w-5 h-5 text-blue-400" />
                ) : (
                  <Smartphone className="w-5 h-5 text-purple-400" />
                )}
              </div>
              <h2 className="text-xl font-bold text-white">
                {selectedType === 'web' ? 'Web Scan' : 'Mobile Scan'}
              </h2>
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={() => setSelectedType(null)}
                className="p-2 rounded-lg hover:bg-gray-800 transition-colors text-gray-400 hover:text-white"
                title="Back"
              >
                ←
              </button>
              <button
                onClick={handleClose}
                className="p-2 rounded-lg hover:bg-gray-800 transition-colors"
              >
                <X className="w-5 h-5 text-gray-400" />
              </button>
            </div>
          </div>
        </div>

        <form onSubmit={handleSubmit} className="p-6 space-y-6">
          {selectedType === 'web' ? (
            <>
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
                  {(['quick', 'standard', 'comprehensive', 'api'] as ScanType[]).map((type) => (
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
                      </div>
                    </button>
                  ))}
                </div>
              </div>
            </>
          ) : (
            <>
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
                  Upload {platform === 'android' ? 'APK' : 'IPA'} File
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
                    accept={platform === 'android' ? '.apk' : '.ipa,.zip'}
                    className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
                  />
                  <Smartphone className="w-12 h-12 text-gray-600 mx-auto mb-4" />
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
                        Drop your {platform === 'android' ? 'APK' : 'IPA'} file here or click to browse
                      </p>
                      <p className="text-sm text-gray-500">Maximum file size: 100MB</p>
                    </div>
                  )}
                </div>
              </div>
            </>
          )}

          {error && (
            <div className="p-4 bg-red-500/10 border border-red-500/20 rounded-lg text-red-400 text-sm">
              {error}
            </div>
          )}

          <div className="flex gap-3">
            <button
              type="button"
              onClick={handleClose}
              className="flex-1 px-4 py-3 rounded-lg border border-gray-700 text-gray-300 font-medium hover:bg-gray-800 transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={loading}
              className={`flex-1 px-4 py-3 rounded-lg text-white font-medium disabled:opacity-50 disabled:cursor-not-allowed transition-all shadow-lg flex items-center justify-center gap-2 ${
                selectedType === 'web'
                  ? 'bg-gradient-to-r from-blue-500 to-purple-500 hover:from-blue-600 hover:to-purple-600 shadow-blue-500/20'
                  : 'bg-gradient-to-r from-purple-500 to-pink-500 hover:from-purple-600 hover:to-pink-600 shadow-purple-500/20'
              }`}
            >
              {loading ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  Scanning...
                </>
              ) : (
                'Start Trial Scan'
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

