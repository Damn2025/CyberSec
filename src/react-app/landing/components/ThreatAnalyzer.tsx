import { useState } from 'react';
import { Sparkles, FileCode, Activity, HelpCircle } from 'lucide-react';

// const ThreatAnalyzer = () => {
//   const [isOpen, setIsOpen] = useState(false);
//   const [messages, setMessages] = useState([{ role: 'system', text: 'Secure connection established. CyberSec Assistant online. How can I protect you today?' }]);
//   const [input, setInput] = useState('');
//   const [loading, setLoading] = useState(false);
//   const messagesEndRef = useRef(null);

//   const scrollToBottom = () => {
//     messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
//   };

//   useEffect(() => {
//     scrollToBottom();
//   }, [messages]);

//   const handleSend = async () => {
//     if (!input.trim()) return;
    
//     const userMsg = { role: 'user', text: input };
//     setMessages(prev => [...prev, userMsg]);
//     setInput('');
//     setLoading(true);
//     const apiKey = "fb6e430cc2977b74b81fb4964a9d28cf";
//     const prompt = `You are "CyberLink", an advanced AI assistant for the CyberSec website. 

//     Your tone is professional, slightly robotic/futuristic but helpful.

//     Answer questions about cybersecurity, the CyberSec product features (Scanner, AI Analysis, Consultation), or general security advice.

//     Keep answers concise and conversational.

    

//     User Query: ${input}`;

//     try {
//       const response = await fetch(
//         `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-preview-09-2025:generateContent?key=${apiKey}`,
//         {
//           method: 'POST',
//           headers: { 'Content-Type': 'application/json' },
//           body: JSON.stringify({ contents: [{ parts: [{ text: prompt }] }] }),
//         }
//       );
//       const data = await response.json();
//       const aiText = data.candidates?.[0]?.content?.parts?.[0]?.text || "Connection interrupted. Re-establishing link...";
      
//       setMessages(prev => [...prev, { role: 'ai', text: aiText }]);
//     } catch (error) {
//       setMessages(prev => [...prev, { role: 'ai', text: "Error: Uplink failed. Please try again." }]);
//     } finally {
//       setLoading(false);
//     }
//   };

//   return (
//     <div className="fixed bottom-6 right-6 z-[60] flex flex-col items-end" >
//       {isOpen && (
//         <div className="mb-4 w-80 md:w-96 h-96 bg-black/90 backdrop-blur-md border border-red-500/50 rounded-lg flex flex-col shadow-[0_0_40px_rgba(220,38,38,0.3)] animate-fadeIn overflow-hidden">
//            <div className="p-3 bg-red-900/20 border-b border-red-500/30 flex justify-between items-center">
//              <div className="flex items-center gap-2">
//                <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
//                <span className="font-mono text-xs font-bold text-red-400 tracking-widest">CYBERLINK_V1.0</span>
//              </div>
//              <button onClick={() => setIsOpen(false)} className="text-gray-400 hover:text-white"><X className="w-4 h-4"/></button>
//            </div>
           
//            <div className="flex-1 overflow-y-auto p-4 space-y-4 scrollbar-hide">
//              {messages.map((m, i) => (
//                <div key={i} className={`flex ${m.role === 'user' ? 'justify-end' : 'justify-start'}`}>
//                  <div className={`max-w-[85%] p-3 rounded text-sm font-mono ${m.role === 'user' ? 'bg-red-600/20 border border-red-500/30 text-white' : 'bg-gray-800/50 border border-gray-700 text-gray-300'}`}>
//                    {m.text}
//                  </div>
//                </div>
//              ))}
//              {loading && (
//                <div className="flex justify-start">
//                  <div className="bg-gray-800/50 border border-gray-700 p-3 rounded flex gap-1">
//                    <div className="w-1.5 h-1.5 bg-red-500 rounded-full animate-bounce"></div>
//                    <div className="w-1.5 h-1.5 bg-red-500 rounded-full animate-bounce delay-100"></div>
//                    <div className="w-1.5 h-1.5 bg-red-500 rounded-full animate-bounce delay-200"></div>
//                  </div>
//                </div>
//              )}
//              <div ref={messagesEndRef} />
//            </div>
//            <div className="p-3 border-t border-white/10 bg-black/50 flex gap-2">
//              <input 
//                type="text" 
//                className="flex-1 bg-transparent border-none outline-none text-sm font-mono text-white placeholder-gray-600"
//                placeholder="Enter command..."
//                value={input}
//                onChange={(e) => setInput(e.target.value)}
//                onKeyPress={(e) => e.key === 'Enter' && handleSend()}
//              />
//              <button onClick={handleSend} disabled={loading} className="text-red-500 hover:text-white transition-colors">
//                <Send className="w-4 h-4" />
//              </button>
//            </div>
//         </div>
//       )}
      
//       <button 
//         onClick={() => setIsOpen(!isOpen)}
//         className="group relative flex items-center justify-center w-14 h-14 rounded-full bg-red-600 text-white shadow-[0_0_20px_rgba(220,38,38,0.5)] hover:bg-red-700 transition-all hover:scale-110"
//       >
//         <span className="absolute -top-1 -right-1 flex h-3 w-3">
//           <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-red-400 opacity-75"></span>
//           <span className="relative inline-flex rounded-full h-3 w-3 bg-red-500"></span>
//         </span>
//         {isOpen ? <ChevronDown className="w-6 h-6" /> : <MessageSquare className="w-6 h-6" />}
//       </button>
//     </div>
//   );
// };

const ThreatAnalyzer = () => {
  const [input, setInput] = useState('');
  const [result, setResult] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isSimpleMode, setIsSimpleMode] = useState(false);

  const analyzeThreat = async () => {
    if (!input.trim()) return;
    setLoading(true);
    setError(null);
    setResult(null);
    const apiKey = "AIzaSyCBpLsBoZeutiV7TY44O9eJvIJ_y3K_ZDA";
    const systemPrompt = isSimpleMode 
      ? `You are a helpful cybersecurity assistant for non-technical users. 
         Explain the risk in simple, plain English (no jargon). 
         1. Is it safe? (Yes/No)
         2. What is it? (Simple explanation)
         3. What should I do? (Clear advice, e.g., "Delete this email")`
      : `You are CyberSec AI, an advanced cybersecurity AI. Analyze for zero-day threats.
    Be concise, technical, and authoritative. 
         1. THREAT LEVEL (Low/Medium/High/Critical)
         2. ANALYSIS (Technical details)
         3. REMEDIATION (Specific actions)`;
    const prompt = `${systemPrompt}\n\nInput to analyze:\n${input}`;
    try {
      const response = await fetch(
        `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-preview-09-2025:generateContent?key=${apiKey}`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ contents: [{ parts: [{ text: prompt }] }] }),
        }
      );
      if (!response.ok) throw new Error('Analysis Protocol Failed');
      const data = await response.json();
      setResult(data.candidates?.[0]?.content?.parts?.[0]?.text ?? null);
    } catch (err) {
      setError("CONNECTION_REFUSED: AI Core unreachable. Check network credentials.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <section id="threat-analyzer" className="py-24 bg-black relative border-t border-red-900/20">
       <div className="absolute top-0 left-0 w-full h-px bg-gradient-to-r from-transparent via-red-900 to-transparent"></div>
      <div className="container mx-auto px-6">
        <div className="flex flex-col items-center mb-16 text-center">
           <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-red-500/30 bg-red-950/20 text-red-400 text-xs font-mono mb-6 tracking-widest uppercase">
              <Sparkles className="w-3 h-3 text-red-400" />
              <span>Powered by CyberSec</span>
           </div>
           <h2 className="text-2xl md:text-3xl lg:text-4xl font-bold text-white mb-2 md:mb-3 lg:mb-4"> <span className='text-transparent bg-clip-text bg-gradient-to-r from-red-500 to-red-800 text-shadow-glow'>AI</span> Threat Intelligence</h2>
           <p className="text-gray-400 max-w-2xl mb-4 md:mb-6 lg:mb-8 text-sm md:text-base">
             Paste suspicious logs, headers, or code snippets below. CyberSec AI will analyze them for zero-day vulnerabilities and anomalies instantly.
           </p>
           <div className="flex items-center gap-2 md:gap-3 lg:gap-4 bg-white/5 p-1 rounded-full border border-white/10">
             <button onClick={() => setIsSimpleMode(false)} className={`px-3 md:px-4 py-1.5 md:py-2 rounded-full text-[10px] md:text-xs lg:text-sm font-bold transition-all ${!isSimpleMode ? 'bg-red-600 text-white shadow-lg' : 'text-gray-400 hover:text-white'}`}>Tech</button>
             <button onClick={() => setIsSimpleMode(true)} className={`px-3 md:px-4 py-1.5 md:py-2 rounded-full text-[10px] md:text-xs lg:text-sm font-bold transition-all ${isSimpleMode ? 'bg-green-600 text-white shadow-lg' : 'text-gray-400 hover:text-white'}`}>Simple</button>
           </div>
        </div>
        <div className="max-w-4xl mx-auto rounded-xl overflow-hidden border border-red-900/50 bg-black/80 shadow-[0_0_60px_rgba(220,38,38,0.1)]">
           <div className="flex items-center justify-between px-4 py-2 bg-gray-900 border-b border-gray-800">
             <div className="flex gap-2">
               <div className="w-3 h-3 rounded-full bg-red-500"></div>
               <div className="w-3 h-3 rounded-full bg-yellow-500"></div>
               <div className="w-3 h-3 rounded-full bg-green-500"></div>
             </div>
             <div className="text-xs font-mono text-gray-500">root@cybersec-ai:~</div>
           </div>
           <div className="p-3 md:p-6 lg:p-8 grid grid-cols-2 gap-2 md:gap-4 lg:gap-8">
              <div className="flex flex-col h-full">
                 <div className={`bg-gray-900/50 border ${isSimpleMode ? 'border-green-500/30' : 'border-white/10'} rounded p-2 md:p-3 lg:p-4 mb-2 md:mb-4 lg:mb-6 text-[10px] md:text-xs lg:text-sm font-mono transition-colors duration-300 hidden md:block`}>
                   <h4 className={`${isSimpleMode ? 'text-green-400' : 'text-white'} font-bold mb-1 md:mb-2 flex items-center gap-1 md:gap-2 text-[10px] md:text-xs`}>
                     <HelpCircle className={`w-3 h-3 md:w-4 md:h-4 ${isSimpleMode ? 'text-green-500' : 'text-red-500'}`} />
                     <span className="hidden lg:inline">{isSimpleMode ? "BEGINNER'S GUIDE (SAFE MODE):" : "OPERATIONAL MANUAL:"}</span>
                     <span className="lg:hidden">{isSimpleMode ? "GUIDE:" : "MANUAL:"}</span>
                   </h4>
                   {isSimpleMode ? (
                     <div className="space-y-1.5 md:space-y-2 lg:space-y-3 text-[9px] md:text-[10px] lg:text-xs text-gray-300">
                       <div className="flex items-start gap-1.5 md:gap-2 lg:gap-3">
                         <div className="bg-green-900/40 text-green-400 w-4 h-4 md:w-4 md:h-4 lg:w-5 lg:h-5 flex items-center justify-center rounded shrink-0 font-bold text-[9px] md:text-[10px]">1</div>
                         <div className="text-[9px] md:text-[10px] lg:text-xs"><strong className="text-green-300 block mb-0.5 text-[10px] md:text-xs">Copy</strong><span className="hidden md:inline">Go to the email or text message that looks weird or scary. Highlight it and copy it.</span></div>
                       </div>
                       <div className="flex items-start gap-1.5 md:gap-2 lg:gap-3">
                         <div className="bg-green-900/40 text-green-400 w-4 h-4 md:w-4 md:h-4 lg:w-5 lg:h-5 flex items-center justify-center rounded shrink-0 font-bold text-[9px] md:text-[10px]">2</div>
                         <div className="text-[9px] md:text-[10px] lg:text-xs"><strong className="text-green-300 block mb-0.5 text-[10px] md:text-xs">Paste</strong><span className="hidden md:inline">Click in the big box below called "Input Artifact" and paste the text there.</span></div>
                       </div>
                       <div className="flex items-start gap-1.5 md:gap-2 lg:gap-3">
                         <div className="bg-green-900/40 text-green-400 w-4 h-4 md:w-4 md:h-4 lg:w-5 lg:h-5 flex items-center justify-center rounded shrink-0 font-bold text-[9px] md:text-[10px]">3</div>
                         <div className="text-[9px] md:text-[10px] lg:text-xs"><strong className="text-green-300 block mb-0.5 text-[10px] md:text-xs">Analyze</strong><span className="hidden md:inline">Press the button. We will clearly tell you if it is <span className="text-green-400 font-bold">SAFE</span> or <span className="text-red-400 font-bold">DANGEROUS</span>.</span></div>
                       </div>
                     </div>
                   ) : (
                     <ul className="space-y-0.5 md:space-y-1 list-disc list-inside text-[9px] md:text-[10px] lg:text-xs text-gray-400">
                       <li className="text-[9px] md:text-[10px] lg:text-xs"><strong className="text-gray-300">Step 1:</strong> Select <span className="text-white">Mode</span>.</li>
                       <li className="text-[9px] md:text-[10px] lg:text-xs"><strong className="text-gray-300">Step 2:</strong> Paste artifact.</li>
                       <li className="text-[9px] md:text-[10px] lg:text-xs"><strong className="text-gray-300">Step 3:</strong> Execute <span className="text-red-400">ANALYZE</span>.</li>
                       <li className="text-[9px] md:text-[10px] lg:text-xs hidden md:list-item"><strong className="text-gray-300">Step 4:</strong> Review report.</li>
                     </ul>
                   )}
                 </div>
                 <label className="text-[9px] md:text-[10px] lg:text-xs font-mono text-red-500 mb-1 md:mb-2 uppercase tracking-widest flex items-center gap-1 md:gap-2">
                   <FileCode className="w-3 h-3 md:w-3.5 md:h-3.5 lg:w-4 lg:h-4" /> <span className="hidden md:inline">Input Artifact</span><span className="md:hidden">Input</span>
                 </label>
                 <textarea className="flex-1 bg-gray-950/50 border border-red-900/30 rounded p-2 md:p-3 lg:p-4 text-[10px] md:text-xs lg:text-sm font-mono text-gray-300 focus:outline-none focus:border-red-500 focus:ring-1 focus:ring-red-500 resize-none min-h-[120px] md:min-h-[150px] lg:min-h-[200px]" placeholder={isSimpleMode ? "Paste text..." : "// Paste code..."} value={input} onChange={(e) => setInput(e.target.value)}></textarea>
                 <button onClick={analyzeThreat} disabled={loading || !input} className="mt-2 md:mt-3 lg:mt-4 w-full py-2 md:py-2.5 lg:py-3 bg-red-600 text-white font-mono font-bold hover:bg-red-700 disabled:opacity-50 disabled:cursor-not-allowed transition-all flex items-center justify-center gap-1 md:gap-2 group text-[10px] md:text-xs lg:text-sm">
                   {loading ? (
                     <><div className="w-3 h-3 md:w-3.5 md:h-3.5 lg:w-4 lg:h-4 border-2 border-white/30 border-t-white rounded-full animate-spin"></div> <span className="hidden md:inline">ANALYZING...</span><span className="md:hidden">...</span></>
                   ) : (
                     <><Sparkles className="w-3 h-3 md:w-3.5 md:h-3.5 lg:w-4 lg:h-4" /> <span className="hidden md:inline">ANALYZE {isSimpleMode ? 'TEXT' : 'THREAT'}</span><span className="md:hidden">GO</span></>
                   )}
                 </button>
              </div>
              <div className="flex flex-col h-full bg-black border border-gray-800 rounded p-2 md:p-3 lg:p-4 relative overflow-hidden min-h-[120px] md:min-h-[150px] lg:min-h-[200px]">
                 <div className="absolute inset-0 cyber-grid opacity-10 pointer-events-none"></div>
                 <label className={`text-[9px] md:text-[10px] lg:text-xs font-mono mb-2 md:mb-3 lg:mb-4 uppercase tracking-widest flex items-center gap-1 md:gap-2 relative z-10 ${isSimpleMode ? 'text-green-500' : 'text-red-500'}`}>
                   <Activity className="w-3 h-3 md:w-3.5 md:h-3.5 lg:w-4 lg:h-4" /> <span className="hidden md:inline">Analysis Output</span><span className="md:hidden">Output</span>
                 </label>
                 <div className="flex-1 font-mono text-[10px] md:text-xs lg:text-sm relative z-10 overflow-y-auto scrollbar-hide">
                    {!result && !loading && !error && (
                      <div className="text-gray-600 italic mt-4 md:mt-6 lg:mt-10 text-center text-[9px] md:text-[10px] lg:text-xs">Waiting...<br/><span className="text-[8px] md:text-[9px] lg:text-xs opacity-50">System ready.</span></div>
                    )}
                    {loading && (
                      <div className="space-y-1 md:space-y-1.5 lg:space-y-2">
                         <div className="h-1.5 md:h-2 bg-red-900/30 rounded w-3/4 animate-pulse"></div>
                         <div className="h-1.5 md:h-2 bg-red-900/20 rounded w-1/2 animate-pulse"></div>
                         <div className="text-red-500 text-[9px] md:text-[10px] lg:text-xs mt-2 md:mt-3 lg:mt-4 animate-pulse">Running...</div>
                      </div>
                    )}
                    {error && <div className="text-red-500 font-bold text-[10px] md:text-xs lg:text-sm">{error}</div>}
                    {result && (
                      <div className="whitespace-pre-wrap text-gray-300 animate-fadeIn leading-relaxed text-[10px] md:text-xs lg:text-sm">
                        <span className={`${isSimpleMode ? "text-green-500" : "text-red-500"} font-bold text-[10px] md:text-xs lg:text-sm`}>
                          {'>'} {isSimpleMode ? 'REPORT:' : 'REPORT:'}
                        </span>
                        <br /><br />
                        {result}
                      </div>
                    )}
                 </div>
              </div>
           </div>
        </div>
      </div>
     
    </section>
  );
};
export default ThreatAnalyzer;

// const ThreatAnalyzer = () => {
//   const [input, setInput] = useState('');
//   const [result, setResult] = useState(null);
//   const [loading, setLoading] = useState(false);
//   const [error, setError] = useState(null);

//   const analyzeThreat = async () => {
//     if (!input.trim()) return;
//     setLoading(true);
//     setError(null);
//     setResult(null);

//     const apiKey = "AIzaSyCBpLsBoZeutiV7TY44O9eJvIJ_y3K_ZDA"; // Runtime provided
//     const prompt = `You are CyberSec AI, an advanced cybersecurity AI. Analyze the following log entry, code snippet, or text for potential security threats. 
//     Be concise, technical, and authoritative. 
//     Structure your response with: 
//     1. THREAT LEVEL (Low, Medium, High, Critical)
//     2. ANALYSIS (Brief explanation of what this is)
//     3. REMEDIATION (One specific action to take)
    
//     If the input is safe, say so.
    
//     Input to analyze:
//     ${input}`;

//     try {
//       const response = await fetch(
//         `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-preview-09-2025:generateContent?key=${apiKey}`,
//         {
//           method: 'POST',
//           headers: {
//             'Content-Type': 'application/json',
//           },
//           body: JSON.stringify({
//             contents: [{ parts: [{ text: prompt }] }],
//           }),
//         }
//       );

//       if (!response.ok) throw new Error('Analysis Protocol Failed');
      
//       const data = await response.json();
//       const text = data.candidates?.[0]?.content?.parts?.[0]?.text;
//       setResult(text);
//     } catch (err) {
//       setError("CONNECTION_REFUSED: AI Core unreachable. Check network credentials.");
//     } finally {
//       setLoading(false);
//     }
//   };

//   return (
//     <section id="threat-analyzer" className="py-24 bg-black relative border-t border-red-900/20">
//       <div className="container mx-auto px-6">
//         <div className="flex flex-col items-center mb-16 text-center">
//            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-red-500/30 bg-red-950/20 text-red-400 text-xs font-mono mb-6 tracking-widest uppercase">
//               <Sparkles className="w-3 h-3 text-red-400" />
//               <span>Powered by Gemini 2.0 Flash</span>
//            </div>
//            <h2 className="text-4xl font-bold text-white mb-4">AI Threat Intelligence</h2>
//            <p className="text-gray-400 max-w-2xl">
//              Paste suspicious logs, headers, or code snippets below. CyberSec AI will analyze them for zero-day vulnerabilities and anomalies instantly.
//            </p>
//         </div>

//         <div className="max-w-4xl mx-auto rounded-xl overflow-hidden border border-red-900/50 bg-black/80 shadow-[0_0_60px_rgba(220,38,38,0.1)]">
//            {/* Terminal Header */}
//            <div className="flex items-center justify-between px-4 py-2 bg-gray-900 border-b border-gray-800">
//              <div className="flex gap-2">
//                <div className="w-3 h-3 rounded-full bg-red-500"></div>
//                <div className="w-3 h-3 rounded-full bg-yellow-500"></div>
//                <div className="w-3 h-3 rounded-full bg-green-500"></div>
//              </div>
//              <div className="text-xs font-mono text-gray-500">root@cybersec-ai:~</div>
//            </div>

//            <div className="p-6 md:p-8 grid md:grid-cols-2 gap-8">
//               {/* Input Side */}
//               <div className="flex flex-col h-full">
//                  <label className="text-xs font-mono text-red-500 mb-2 uppercase tracking-widest flex items-center gap-2">
//                    <FileCode className="w-4 h-4" />
//                    Input Artifact
//                  </label>
//                  <textarea
//                    className="flex-1 bg-gray-950/50 border border-red-900/30 rounded p-4 text-sm font-mono text-gray-300 focus:outline-none focus:border-red-500 focus:ring-1 focus:ring-red-500 resize-none min-h-[200px]"
//                    placeholder="// Paste suspicious code or logs here..."
//                    value={input}
//                    onChange={(e) => setInput(e.target.value)}
//                  ></textarea>
//                  <button 
//                    onClick={analyzeThreat}
//                    disabled={loading || !input}
//                    className="mt-4 w-full py-3 bg-red-600 text-white font-mono font-bold hover:bg-red-700 disabled:opacity-50 disabled:cursor-not-allowed transition-all flex items-center justify-center gap-2 group"
//                  >
//                    {loading ? (
//                      <>
//                        <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin"></div>
//                        ANALYZING...
//                      </>
//                    ) : (
//                      <>
//                        <Sparkles className="w-4 h-4" />
//                        ANALYZE THREAT ✨
//                      </>
//                    )}
//                  </button>
//               </div>

//               {/* Output Side */}
//               <div className="flex flex-col h-full bg-black border border-gray-800 rounded p-4 relative overflow-hidden min-h-[200px]">
//                  <div className="absolute inset-0 cyber-grid opacity-10 pointer-events-none"></div>
//                  <label className="text-xs font-mono text-green-500 mb-4 uppercase tracking-widest flex items-center gap-2 relative z-10">
//                    <Activity className="w-4 h-4" />
//                    Analysis Output
//                  </label>
                 
//                  <div className="flex-1 font-mono text-sm relative z-10 overflow-y-auto scrollbar-hide">
//                     {!result && !loading && !error && (
//                       <div className="text-gray-600 italic mt-10 text-center">
//                         Waiting for input stream...<br/>
//                         <span className="text-xs opacity-50">System ready.</span>
//                       </div>
//                     )}
                    
//                     {loading && (
//                       <div className="space-y-2">
//                          <div className="h-2 bg-red-900/30 rounded w-3/4 animate-pulse"></div>
//                          <div className="h-2 bg-red-900/20 rounded w-1/2 animate-pulse"></div>
//                          <div className="h-2 bg-red-900/10 rounded w-5/6 animate-pulse"></div>
//                          <div className="text-red-500 text-xs mt-4 animate-pulse">Processing heuristics...</div>
//                       </div>
//                     )}

//                     {error && (
//                       <div className="text-red-500 border-l-2 border-red-500 pl-3">
//                          <div className="font-bold">ERROR</div>
//                          {error}
//                       </div>
//                     )}

//                     {result && (
//                       <div className="whitespace-pre-wrap text-gray-300 animate-fadeIn leading-relaxed">
//                         <span className="text-red-500 font-bold">{'>'} ACCESS GRANTED. REPORT FOLLOWS:</span>
//                         <br /><br />
//                         {result}
//                       </div>
//                     )}
//                  </div>
//               </div>
//            </div>
//         </div>
//       </div>
//       <ChatWidget />
//     </section>
//   );
// };




