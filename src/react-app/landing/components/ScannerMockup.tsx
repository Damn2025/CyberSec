import { useState, useEffect } from 'react';
import { AlertTriangle, CheckCircle, Activity, ChevronRight } from 'lucide-react';

type LogType = "info" | "success" | "warning" | "error";
type LogEntry = { id: number; text: string; type: LogType };

const ScannerMockup = () => {
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [progress, setProgress] = useState(0);
  const [scanning, setScanning] = useState(true);

  useEffect(() => {
    if (!scanning) return;
    
    const possibleLogs = [
      { text: "Initializing deep packet inspection...", type: "info" },
      { text: "Connecting to secure gateway...", type: "info" },
      { text: "Port 443 open. Verifying certificate...", type: "success" },
      { text: "WARNING: Anomalous traffic detected on Port 8080", type: "warning" },
      { text: "Scanning endpoint 192.168.1.105...", type: "info" },
      { text: "CRITICAL: SQL Injection vulnerability found", type: "error" },
      { text: "Patching suggestions generated.", type: "success" },
      { text: "Analyzing heuristic patterns...", type: "info" },
      { text: "Firewall integrity check passed.", type: "success" },
    ];

    const interval = setInterval(() => {
      setProgress(p => {
        if (p >= 100) {
          setScanning(false);
          return 100;
        }
        return p + Math.random() * 2;
      });

      if (Math.random() > 0.6) {
        const newLog = possibleLogs[Math.floor(Math.random() * possibleLogs.length)];
        setLogs(prev => [...prev.slice(-6), { ...newLog, id: Date.now() } as LogEntry]);
      }
    }, 200);

    return () => clearInterval(interval);
  }, [scanning]);

  return (
    <div className="relative w-full max-w-2xl mx-auto rounded-xl overflow-hidden border border-red-900/50 bg-black/80 backdrop-blur-xl shadow-[0_0_50px_rgba(220,38,38,0.15)] group" id="scanner">
      {/* Window Header */}
      <div className="flex items-center justify-between px-4 py-3 bg-red-950/20 border-b border-red-900/30">
        <div className="flex items-center gap-2">
          <div className="w-3 h-3 rounded-full bg-red-600/50"></div>
          <div className="w-3 h-3 rounded-full bg-yellow-600/50"></div>
          <div className="w-3 h-3 rounded-full bg-green-600/50"></div>
        </div>
        <div className="text-xs font-mono text-red-400 uppercase tracking-widest">CyberSec_Core_v4.2.exe</div>
      </div>

      {/* Main Scanner UI */}
      <div className="p-6 font-mono text-sm relative min-h-[300px]">
        {/* Grid Background Overlay */}
        <div className="absolute inset-0 cyber-grid opacity-10 pointer-events-none"></div>
        
        {/* Scanning Animation Line */}
        {scanning && (
          <div className="absolute top-0 left-0 w-full h-1 bg-red-500/50 shadow-[0_0_20px_#ef4444] animate-scanline pointer-events-none z-10"></div>
        )}

        {/* Stats Row */}
        <div className="flex justify-between mb-6 text-xs uppercase tracking-widest">
          <div className="flex flex-col gap-1">
            <span className="text-gray-500">Status</span>
            <span className={`font-bold ${scanning ? 'text-red-500 animate-pulse' : 'text-green-500'}`}>
              {scanning ? 'System Scanning...' : 'Scan Complete'}
            </span>
          </div>
          <div className="flex flex-col gap-1 text-right">
            <span className="text-gray-500">Threat Level</span>
            <span className="text-red-500 font-bold">High</span>
          </div>
        </div>

        {/* Central Graphic */}
        <div className="flex justify-center my-8 relative">
           <div className="relative w-32 h-32 border border-red-900/50 rounded-full flex items-center justify-center">
             <div className="absolute inset-0 rounded-full border border-red-600/20 animate-ping"></div>
             <div className="absolute inset-2 rounded-full border border-dashed border-red-600/40 animate-spin duration-[10s]"></div>
             <span className="text-2xl font-bold text-white">{Math.floor(progress)}%</span>
           </div>
        </div>

        {/* Logs */}
        <div className="space-y-2 mt-4">
          {logs.map((log) => (
            <div key={log.id} className="flex items-center gap-3 animate-fadeIn">
              {log.type === 'error' && <AlertTriangle className="w-4 h-4 text-red-500 shrink-0" />}
              {log.type === 'success' && <CheckCircle className="w-4 h-4 text-green-500 shrink-0" />}
              {log.type === 'warning' && <Activity className="w-4 h-4 text-yellow-500 shrink-0" />}
              {log.type === 'info' && <ChevronRight className="w-4 h-4 text-gray-500 shrink-0" />}
              <span className={`
                ${log.type === 'error' ? 'text-red-400' : ''}
                ${log.type === 'success' ? 'text-green-400' : ''}
                ${log.type === 'warning' ? 'text-yellow-400' : ''}
                ${log.type === 'info' ? 'text-gray-400' : ''}
              `}>{log.text}</span>
            </div>
          ))}
          <div className="h-4 w-2 bg-red-500 animate-pulse inline-block align-middle ml-1"></div>
        </div>
      </div>
    </div>
  );
};

export default ScannerMockup;





