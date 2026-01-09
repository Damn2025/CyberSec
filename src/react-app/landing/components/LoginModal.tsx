import type { FormEvent } from "react";
import { useState } from 'react';
import { X, Lock, Mail, Eye, EyeOff, Shield, Phone } from 'lucide-react';
import { supabase } from "@/react-app/lib/supabase";
import { saveTrialScan } from "@/react-app/utils/saveTrialScan";

type LoginModalProps = {
  isOpen: boolean;
  onClose: () => void;
  onSwitchToSignup: () => void;
  onAuthenticated: () => void;
};

const LoginModal = ({ isOpen, onClose, onSwitchToSignup, onAuthenticated }: LoginModalProps) => {
  const [email, setEmail] = useState('');
  const [phone, setPhone] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  if (!isOpen) return null;

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      if (!email) {
        if (phone) {
          setError("Phone login isn't enabled yet. Please log in with email + password.");
        } else {
          setError('Please enter your email address.');
        }
        return;
      }
      if (!password) {
        setError('Please enter your password.');
        return;
      }

      const { error: signInError } = await supabase.auth.signInWithPassword({ email, password });
      if (signInError) {
        setError(signInError.message);
        return;
      }

      // Save trial scan if exists (after successful login)
      try {
        await saveTrialScan();
      } catch (err) {
        console.error('Failed to save trial scan after login:', err);
        // Don't block login if saving trial scan fails
      }

      setEmail('');
      setPhone('');
      setPassword('');
      onAuthenticated();
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/80 backdrop-blur-sm animate-fadeIn">
      <div className="relative w-full max-w-md mx-4 py-4">
        <div className="bg-black border border-red-500/50 rounded-lg shadow-[0_0_40px_rgba(220,38,38,0.3)] overflow-hidden">
        <button onClick={onClose} className="absolute top-4 right-4 text-gray-500 hover:text-white transition-colors">
            <X className="w-6 h-6" />
          </button>
          {/* Header */}
          <div className="text-center mb-8 py-4">
            <div className="relative w-16 h-16 mx-auto mb-4 flex items-center justify-center bg-red-900/10 rounded-full border border-red-500/30">
               <Shield className="w-8 h-8 text-red-600" />
               <div className="absolute inset-0 border border-red-500/20 rounded-full animate-ping"></div>
            </div>
            <h2 className="text-2xl font-bold text-white mb-2 tracking-wide">ACCESS TERMINAL</h2>
            <p className="text-gray-400 text-sm font-mono">Enter credentials to initiate Level 5 Scan.</p>
          
          </div>

          {/* Form */}
          <form onSubmit={handleSubmit} className="p-6 space-y-6">
            {error && (
              <div className="p-3 bg-red-900/30 border border-red-500/50 rounded text-sm text-red-400 font-mono">
                {error}
              </div>
            )}

            {/* Email Field */}
            <div>
              <label className="block text-xs font-mono text-gray-400 mb-2 uppercase tracking-wider">
                Email Address
              </label>
              <div className="relative">
                <Mail className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-500" />
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="w-full pl-10 pr-4 py-3 bg-gray-950/50 border border-gray-800 rounded text-white placeholder-gray-600 font-mono text-sm focus:outline-none focus:border-red-500 focus:ring-1 focus:ring-red-500"
                  placeholder="user@example.com"
                />
              </div>
            </div>

            {/* Phone Field */}
            <div>
              <label className="block text-xs font-mono text-gray-400 mb-2 uppercase tracking-wider">
                Phone Number
              </label>
              <div className="relative">
                <Phone className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-500" />
                <input
                  type="tel"
                  value={phone}
                  onChange={(e) => setPhone(e.target.value)}
                  className="w-full pl-10 pr-4 py-3 bg-gray-950/50 border border-gray-800 rounded text-white placeholder-gray-600 font-mono text-sm focus:outline-none focus:border-red-500 focus:ring-1 focus:ring-red-500"
                  placeholder="+1 234 567 890"
                />
              </div>
              <p className="mt-2 text-[10px] text-gray-500 font-mono">
                Use email or phone to log in.
              </p>
            </div>

            {/* Password Field */}
            <div>
              <label className="block text-xs font-mono text-gray-400 mb-2 uppercase tracking-wider">
                Password
              </label>
              <div className="relative">
                <Lock className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-500" />
                <input
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full pl-10 pr-12 py-3 bg-gray-950/50 border border-gray-800 rounded text-white placeholder-gray-600 font-mono text-sm focus:outline-none focus:border-red-500 focus:ring-1 focus:ring-red-500"
                  placeholder="••••••••"
                  required
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-500 hover:text-white transition-colors"
                >
                  {showPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                </button>
              </div>
            </div>

     

            {/* Submit Button */}
            <button
              type="submit"
              disabled={loading}
              className="w-full py-3 bg-red-600 text-white font-mono font-bold hover:bg-red-700 disabled:opacity-50 disabled:cursor-not-allowed transition-all flex items-center justify-center gap-2 shadow-[0_0_20px_rgba(220,38,38,0.3)]"
            >
              {loading ? (
                <>
                  <div className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin"></div>
                  AUTHENTICATING...
                </>
              ) : (
                <>
                  <Lock className="w-4 h-4" />
                  LOGIN
                </>
              )}
            </button>

            {/* Switch to Signup */}
            <div className="text-center pt-4 border-t border-gray-800">
              <p className="text-sm text-gray-400 font-mono">
                Don't have an account?{' '}
                <button
                  type="button"
                  onClick={onSwitchToSignup}
                  className="text-red-500 hover:text-red-400 transition-colors font-bold"
                >
                  SIGN UP
                </button>
              </p>
            </div>
          </form>
        </div>
      </div>
    </div>
    
  );

};

export default LoginModal;

