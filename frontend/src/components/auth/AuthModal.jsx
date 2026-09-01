import React, { useState } from 'react';
import {
  Shield,
  Lock,
  Mail,
  User,
  Building2,
  Eye,
  EyeOff,
  AlertTriangle,
  Loader2,
  ArrowRight,
  X,
  CheckCircle2,
} from 'lucide-react';
import { useAuth } from '../../context/AuthContext';

export default function AuthModal({ isOpen, onClose, onSuccess, pendingDomain = '' }) {
  const { login } = useAuth();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');

  if (!isOpen) return null;

  const handleSubmit = async (e) => {
    e.preventDefault();
    setErrorMsg('');

    if (!email.trim() || !password) {
      setErrorMsg('Please enter both your work email and password.');
      return;
    }

    setLoading(true);
    try {
      const result = await login(email.trim(), password);
      if (onSuccess) {
        onSuccess(result);
      }
      onClose();
    } catch (err) {
      setErrorMsg(err.message || 'Authentication failed. Please verify credentials.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md animate-fade-in">
      <div className="w-full max-w-md rounded-2xl panel-glass border border-border-dim shadow-2xl overflow-hidden relative bg-panel">
        {/* Header */}
        <div className="p-6 border-b border-border-dim bg-panel-elevated flex items-center justify-between">
          <div className="flex items-center gap-3">
            <img
              src="/logo.png"
              alt="Recon7 Logo"
              className="w-10 h-10 rounded-lg object-contain bg-void p-1 border border-cyan-signal/60 shadow-glow-cyan-sm"
              onError={(e) => {
                e.target.style.display = 'none';
              }}
            />
            <div>
              <div className="flex items-center gap-2">
                <span className="font-display font-bold text-sm tracking-wider text-text-primary uppercase">
                  OPERATOR SIGN IN
                </span>
                <span className="text-[9px] px-1.5 py-0.5 rounded bg-cyan-signal/10 border border-cyan-signal/40 text-cyan-signal font-mono font-bold">
                  AUTH
                </span>
              </div>
              <p className="text-[11px] font-mono text-text-dim">
                {pendingDomain ? `Authorize access to scan ${pendingDomain}` : 'Enter credentials to access console'}
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1 rounded-md text-text-dim hover:text-text-primary hover:bg-void transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Form Body */}
        <form onSubmit={handleSubmit} className="p-6 space-y-4">
          {errorMsg && (
            <div className="p-3 rounded-lg bg-magenta-alert/15 border border-magenta-alert/40 text-magenta-alert text-xs font-mono flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 shrink-0" />
              <span>{errorMsg}</span>
            </div>
          )}

          {/* Email */}
          <div className="space-y-1">
            <label className="block text-[11px] font-mono text-text-dim uppercase tracking-wider">
              Email Address <span className="text-cyan-signal">*</span>
            </label>
            <div className="relative">
              <Mail className="w-4 h-4 text-text-dim absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="email"
                required
                placeholder="user@example.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full pl-9 pr-3 py-2 rounded-lg bg-void border border-border-dim focus:border-cyan-signal text-xs font-mono text-text-primary placeholder:text-text-dim/60 focus:outline-none transition-all"
              />
            </div>
          </div>

          {/* Password */}
          <div className="space-y-1">
            <div className="flex items-center justify-between">
              <label className="block text-[11px] font-mono text-text-dim uppercase tracking-wider">
                Password <span className="text-cyan-signal">*</span>
              </label>
            </div>
            <div className="relative">
              <Lock className="w-4 h-4 text-text-dim absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type={showPassword ? 'text' : 'password'}
                required
                placeholder="••••••••••••"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full pl-9 pr-10 py-2 rounded-lg bg-void border border-border-dim focus:border-cyan-signal text-xs font-mono text-text-primary placeholder:text-text-dim/60 focus:outline-none transition-all"
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-text-dim hover:text-text-primary"
              >
                {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>
          </div>

          {/* Submit Button */}
          <div className="pt-2">
            <button
              type="submit"
              disabled={loading}
              className="w-full py-2.5 rounded-lg bg-cyan-signal hover:brightness-110 text-black font-mono font-bold text-xs tracking-wider transition-all flex items-center justify-center gap-2 shadow-glow-cyan-sm hover:scale-[1.01] active:scale-95 disabled:opacity-50"
            >
              {loading ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  <span>SIGNING IN...</span>
                </>
              ) : (
                <>
                  <span>SIGN IN</span>
                  <ArrowRight className="w-4 h-4" />
                </>
              )}
            </button>
          </div>

          {/* Access Policy Advisory */}
          <div className="text-center pt-3 border-t border-border-dim/60">
            <p className="text-[10px] font-mono text-text-dim leading-relaxed">
              Access Policy: Public registration is closed. Accounts are provisioned by your system administrator.
            </p>
          </div>
        </form>
      </div>
    </div>
  );
}
