import { useState, useEffect, useRef } from 'react';
import { X, Send, MessageSquare, ChevronDown } from 'lucide-react';

type ChatMessage = {
  role: "system" | "user" | "ai";
  text: string;
};

const ChatWidget = () => {
  const [isOpen, setIsOpen] = useState(false);
  const [messages, setMessages] = useState<ChatMessage[]>([
    { role: 'system', text: 'CYBERSEC Assistant online. How can I protect you today?' },
  ]);
    const [input, setInput] = useState('');
    const [loading, setLoading] = useState(false);
    const messagesEndRef = useRef<HTMLDivElement | null>(null);
  
    const scrollToBottom = () => {
      messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
    };
  
    useEffect(scrollToBottom, [messages]);
  
    const handleSend = async () => {
      if (!input.trim()) return;
      
      const userMsg: ChatMessage = { role: 'user', text: input };
      setMessages(prev => [...prev, userMsg]);
      setInput('');
      setLoading(true);
  
      const apiKey = "AIzaSyCBpLsBoZeutiV7TY44O9eJvIJ_y3K_ZDA";
      const prompt = `You are "CyberLink", an advanced AI assistant for the CyberSec website. 
      Your tone is professional, slightly robotic/futuristic but helpful.
      Answer questions about cybersecurity, the CyberSec product features (Scanner, AI Analysis, Consultation), or general security advice.
      Keep answers concise and conversational.
      
      User Query: ${input}`;
  
      try {
        const response = await fetch(
          `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-preview-09-2025:generateContent?key=${apiKey}`,
          {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ contents: [{ parts: [{ text: prompt }] }] }),
          }
        );
        const data = await response.json();
        const aiText = data.candidates?.[0]?.content?.parts?.[0]?.text || "Connection interrupted. Re-establishing link...";
        
        setMessages(prev => [...prev, { role: 'ai', text: aiText }]);
      } catch (error) {
        setMessages(prev => [...prev, { role: 'ai', text: "Error: Uplink failed. Please try again." }]);
      } finally {
        setLoading(false);
      }
    };
  
    return (
      <div className="fixed bottom-6 right-6 z-[60] flex flex-col items-end">
        {isOpen && (
          <div className="mb-4 w-80 md:w-96 h-96 bg-black/90 backdrop-blur-md border border-red-500/50 rounded-lg flex flex-col shadow-[0_0_40px_rgba(220,38,38,0.3)] animate-fadeIn overflow-hidden">
             <div className="p-3 bg-red-900/20 border-b border-red-500/30 flex justify-between items-center">
               <div className="flex items-center gap-2">
                 <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
                 <span className="text-shadow-glow text-xs font-bold tracking-widest text-white">CYBER<span className="text-red-600">SEC</span></span>
               </div>
               <button onClick={() => setIsOpen(false)} className="text-gray-400 hover:text-white"><X className="w-4 h-4"/></button>
             </div>
             
             <div className="flex-1 overflow-y-auto p-4 space-y-4 scrollbar-hide">
               {messages.map((m, i) => (
                 <div key={i} className={`flex ${m.role === 'user' ? 'justify-end' : 'justify-start'}`}>
                   <div className={`max-w-[85%] p-3 rounded text-sm font-mono ${m.role === 'user' ? 'bg-red-600/20 border border-red-500/30 text-white' : 'bg-gray-800/50 border border-gray-700 text-gray-300'}`}>
                     {m.text}
                   </div>
                 </div>
               ))}
               {loading && (
                 <div className="flex justify-start">
                   <div className="bg-gray-800/50 border border-gray-700 p-3 rounded flex gap-1">
                     <div className="w-1.5 h-1.5 bg-red-500 rounded-full animate-bounce"></div>
                     <div className="w-1.5 h-1.5 bg-red-500 rounded-full animate-bounce delay-100"></div>
                     <div className="w-1.5 h-1.5 bg-red-500 rounded-full animate-bounce delay-200"></div>
                   </div>
                 </div>
               )}
               <div ref={messagesEndRef} />
             </div>
  
             <div className="p-3 border-t border-white/10 bg-black/50 flex gap-2">
               <input 
                 type="text" 
                 className="flex-1 bg-transparent border-none outline-none text-sm font-mono text-white placeholder-gray-600"
                 placeholder="Enter command..."
                 value={input}
                 onChange={(e) => setInput(e.target.value)}
                 onKeyPress={(e) => e.key === 'Enter' && handleSend()}
               />
               <button onClick={handleSend} disabled={loading} className="text-red-500 hover:text-white transition-colors">
                 <Send className="w-4 h-4" />
               </button>
             </div>
          </div>
        )}
        
        <button 
          onClick={() => setIsOpen(!isOpen)}
          className="group relative flex items-center justify-center w-14 h-14 rounded-full bg-red-600 text-white shadow-[0_0_20px_rgba(220,38,38,0.5)] hover:bg-red-700 transition-all hover:scale-110"
        >
          <span className="absolute -top-1 -right-1 flex h-3 w-3">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-red-400 opacity-75"></span>
            <span className="relative inline-flex rounded-full h-3 w-3 bg-red-500"></span>
          </span>
          {isOpen ? <ChevronDown className="w-6 h-6" /> : <MessageSquare className="w-6 h-6" />}
        </button>
      </div>
    );
  };

export default ChatWidget ;