import type { ChangeEvent, FormEvent } from "react";
import { useEffect, useState } from 'react';
import { X, Lock, Mail, Eye, EyeOff, Shield, User, Phone } from 'lucide-react';
import { supabase } from "@/react-app/lib/supabase";

type SignupModalProps = {
  isOpen: boolean;
  onClose: () => void;
  onSwitchToLogin: () => void;
  onAuthenticated: () => void;
};

const SignupModal = ({ isOpen, onClose, onSwitchToLogin, onAuthenticated }: SignupModalProps) => {
  const [formData, setFormData] = useState({
    name: '',
    email: '',
    phone: '',
    password: '',
    confirmPassword: ''
  });
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [confirmationNotice, setConfirmationNotice] = useState<string | null>(null);

  useEffect(() => {
    // Reset transient UI when the modal opens.
    if (!isOpen) return;
    setError('');
    setConfirmationNotice(null);
    setLoading(false);
  }, [isOpen]);

  const handleChange = (e: ChangeEvent<HTMLInputElement>) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    });
  };

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError('');
    setConfirmationNotice(null);

    // Validation
    if (formData.password !== formData.confirmPassword) {
      setError('Passwords do not match');
      return;
    }

    if (formData.password.length < 8) {
      setError('Password must be at least 8 characters');
      return;
    }

    setLoading(true);

    try {
      const emailRedirectTo =
        typeof window !== "undefined"
          ? `${window.location.origin}${window.location.hostname === "evoke.ai" ? "" : "/cyber"
          }/dashboard`
          : undefined;

      const { data, error: signUpError } = await supabase.auth.signUp({
        email: formData.email,
        password: formData.password,
        options: {
          ...(emailRedirectTo ? { emailRedirectTo } : {}),
          data: {
            full_name: formData.name,
            phone: formData.phone,
          },
        },
      });

      if (signUpError) {
        setError(signUpError.message);
        return;
      }

      // Create profile entry in profiles table after signup
      console.log(data.user)
      if (data.user) {
        try {
          // Use upsert to handle cases where profile might already exist
          // This works if there's a session (email confirmations disabled)
          // If there's no session (email confirmations enabled), RLS will block this,
          // but the database trigger will create the profile when email is confirmed
          const { error: profileError } = await supabase
            .from("profiles")
            .upsert(
              {
                id: data.user.id,
                full_name: formData.name.trim() || "UNKNOWN",
                phone: formData.phone.trim() || "UNKNOWN",
                email: formData.email.trim() || "UNKNOWN",
              },
              {
                onConflict: "id",
                ignoreDuplicates: false, // Update if exists
              }
            );

          if (profileError) {
            // Check for conflict 409 or duplicate key value violates unique constraint
            const isConflict = profileError.code === '23505' || profileError.message.includes('409');

            if (isConflict) {
              console.log("Profile already exists, skipping creation.");
            } else if (!profileError.message.includes("permission") && !profileError.message.includes("RLS")) {
              // If profile creation fails due to RLS (no session), that's okay
              // The database trigger or AuthProvider will create it later
              // Only log if it's not an RLS/permission error
              console.error("Failed to create profile:", profileError);
            }
          }
        } catch (profileErr) {
          // Handle any unexpected errors during profile creation
          console.error("Unexpected error creating profile:", profileErr);
        }
      }

      // If email confirmations are enabled, Supabase returns no session until the user clicks the email link.
      if (!data.session) {
        setConfirmationNotice(
          `Account created! Please check ${formData.email} for a confirmation email, then log in to continue.`,
        );
        return;
      }

      setFormData({
        name: '',
        email: '',
        phone: '',
        password: '',
        confirmPassword: ''
      });
      onClose();
      onAuthenticated();
    } finally {
      setLoading(false);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/80 backdrop-blur-sm animate-fadeIn">
      <div className="relative w-full max-w-md mx-4">
        <div className="bg-black border border-red-500/50 rounded-lg shadow-[0_0_40px_rgba(220,38,38,0.3)] overflow-hidden">
          {/* Header */}
          <div className="p-6 bg-red-900/20 border-b border-red-500/30 flex justify-between items-center">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-full bg-red-600/20 flex items-center justify-center border border-red-500/30">
                <Shield className="w-5 h-5 text-red-500" />
              </div>
              <div>
                <h2 className="text-xl font-bold text-white font-mono tracking-wider">CREATE ACCOUNT</h2>
                <p className="text-xs text-gray-400 font-mono">Join the CyberSec network</p>
              </div>
            </div>
            <button
              onClick={onClose}
              className="text-gray-400 hover:text-white transition-colors"
            >
              <X className="w-5 h-5" />
            </button>
          </div>

          {/* Form */}
          <form onSubmit={handleSubmit} className="p-6 space-y-5">
            {confirmationNotice && (
              <div className="p-3 bg-green-900/20 border border-green-500/30 rounded text-sm text-green-300 font-mono">
                {confirmationNotice}
                <div className="mt-3 flex gap-3">
                  <button
                    type="button"
                    onClick={onSwitchToLogin}
                    className="px-4 py-2 bg-green-600/20 border border-green-500/30 text-green-200 hover:bg-green-600/30 rounded font-mono text-xs transition-colors"
                  >
                    GO TO LOGIN
                  </button>
                  <button
                    type="button"
                    onClick={onClose}
                    className="px-4 py-2 bg-white/5 border border-white/10 text-gray-300 hover:bg-white/10 rounded font-mono text-xs transition-colors"
                  >
                    CLOSE
                  </button>
                </div>
              </div>
            )}
            {error && (
              <div className="p-3 bg-red-900/30 border border-red-500/50 rounded text-sm text-red-400 font-mono">
                {error}
              </div>
            )}

            {/* Name Field */}
            <div>
              <label className="block text-xs font-mono text-gray-400 mb-2 uppercase tracking-wider">
                Full Name
              </label>
              <div className="relative">
                <User className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-500" />
                <input
                  type="text"
                  name="name"
                  value={formData.name}
                  onChange={handleChange}
                  className="w-full pl-10 pr-4 py-3 bg-gray-950/50 border border-gray-800 rounded text-white placeholder-gray-600 font-mono text-sm focus:outline-none focus:border-red-500 focus:ring-1 focus:ring-red-500"
                  placeholder="John Doe"
                  required
                />
              </div>
            </div>

            {/* Email Field */}
            <div>
              <label className="block text-xs font-mono text-gray-400 mb-2 uppercase tracking-wider">
                Email Address
              </label>
              <div className="relative">
                <Mail className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-500" />
                <input
                  type="email"
                  name="email"
                  value={formData.email}
                  onChange={handleChange}
                  className="w-full pl-10 pr-4 py-3 bg-gray-950/50 border border-gray-800 rounded text-white placeholder-gray-600 font-mono text-sm focus:outline-none focus:border-red-500 focus:ring-1 focus:ring-red-500"
                  placeholder="user@example.com"
                  required
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
                  name="phone"
                  value={formData.phone}
                  onChange={handleChange}
                  className="w-full pl-10 pr-4 py-3 bg-gray-950/50 border border-gray-800 rounded text-white placeholder-gray-600 font-mono text-sm focus:outline-none focus:border-red-500 focus:ring-1 focus:ring-red-500"
                  placeholder="+1 234 567 890"
                  required
                />
              </div>
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
                  name="password"
                  value={formData.password}
                  onChange={handleChange}
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

            {/* Confirm Password Field */}
            <div>
              <label className="block text-xs font-mono text-gray-400 mb-2 uppercase tracking-wider">
                Confirm Password
              </label>
              <div className="relative">
                <Lock className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-500" />
                <input
                  type={showConfirmPassword ? 'text' : 'password'}
                  name="confirmPassword"
                  value={formData.confirmPassword}
                  onChange={handleChange}
                  className="w-full pl-10 pr-12 py-3 bg-gray-950/50 border border-gray-800 rounded text-white placeholder-gray-600 font-mono text-sm focus:outline-none focus:border-red-500 focus:ring-1 focus:ring-red-500"
                  placeholder="••••••••"
                  required
                />
                <button
                  type="button"
                  onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                  className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-500 hover:text-white transition-colors"
                >
                  {showConfirmPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                </button>
              </div>
            </div>

            {/* Terms and Conditions */}
            <label className="flex items-start gap-2 text-sm text-gray-400 font-mono cursor-pointer">
              <input type="checkbox" className="w-4 h-4 mt-0.5 bg-gray-950 border-gray-700 rounded text-red-600 focus:ring-red-500" required />
              <span>I agree to the <span className="text-red-500 hover:text-red-400">Terms of Service</span> and <span className="text-red-500 hover:text-red-400">Privacy Policy</span></span>
            </label>

            {/* Submit Button */}
            <button
              type="submit"
              disabled={loading}
              className="w-full py-3 bg-red-600 text-white font-mono font-bold hover:bg-red-700 disabled:opacity-50 disabled:cursor-not-allowed transition-all flex items-center justify-center gap-2 shadow-[0_0_20px_rgba(220,38,38,0.3)]"
            >
              {loading ? (
                <>
                  <div className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin"></div>
                  CREATING ACCOUNT...
                </>
              ) : (
                <>
                  <Shield className="w-4 h-4" />
                  CREATE ACCOUNT
                </>
              )}
            </button>

            {/* Switch to Login */}
            <div className="text-center pt-4 border-t border-gray-800">
              <p className="text-sm text-gray-400 font-mono">
                Already have an account?{' '}
                <button
                  type="button"
                  onClick={onSwitchToLogin}
                  className="text-red-500 hover:text-red-400 transition-colors font-bold"
                >
                  LOGIN
                </button>
              </p>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
};

export default SignupModal;



