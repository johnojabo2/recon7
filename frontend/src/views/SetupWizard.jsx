import React, { useState } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  Lock,
  Mail,
  User,
  Building,
  KeyRound,
  ArrowRight,
  Terminal,
  AlertOctagon,
  CheckCircle2,
} from 'lucide-react';
import { apiRequest } from '../api/client';
import { useAuth } from '../context/AuthContext';

export default function SetupWizard({ onSetupComplete }) {
  const { login } = useAuth();
  const [fullName, setFullName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [orgName, setOrgName] = useState('');
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(null);

    if (!fullName.trim() || !email.trim() || !password.trim()) {
      setError('Please provide your name, master email, and password.');
      return;
    }

    if (password.length < 8) {
      setError('Master security password must be at least 8 characters long.');
      return;
    }

    if (password !== confirmPassword) {
      setError('Passwords do not match. Please re-enter.');
      return;
    }

    setLoading(true);
    try {
      const data = await apiRequest('/setup/initialize', {
        method: 'POST',
        body: {
          full_name: fullName.trim(),
          email: email.trim(),
          password,
          organization_name: orgName.trim() || undefined,
        },
      });

      if (data && data.access_token) {
        localStorage.setItem('r7_auth_token', data.access_token);
        if (data.tenant?.id) {
          localStorage.setItem('r7_tenant_id', data.tenant.id);
        }
        if (onSetupComplete) {
          onSetupComplete(data);
        } else {
          window.location.href = '/dashboard';
        }
      }
    } catch (err) {
      setError(err.message || 'Failed to initialize root administrator account.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-void flex flex-col items-center justify-center p-4 sm:p-6 font-sans text-text-primary selection:bg-cyan-signal selection:text-black">
      {/* High-Tech Background Glow */}
      <div className="fixed inset-0 pointer-events-none overflow-hidden flex items-center justify-center">
        <div className="w-[650px] h-[650px] bg-cyan-signal/5 rounded-full blur-[140px]" />
        <div className="w-[450px] h-[450px] bg-magenta-alert/5 rounded-full blur-[120px] translate-x-32 -translate-y-24" />
      </div>

      <div className="relative w-full max-w-xl z-10">
        {/* Logo & Terminal Header Badge */}
        <div className="text-center mb-6 space-y-3">
          <div className="flex justify-center mb-1">
            <div className="relative group">
              <div className="absolute -inset-1.5 bg-gradient-to-r from-cyan-signal via-cyan-bright to-cyan-signal rounded-2xl blur-md opacity-60 group-hover:opacity-100 transition duration-500"></div>
              <img
                src="/logo.png"
                alt="Recon7 Logo"
                className="relative w-16 h-16 rounded-xl object-contain bg-void p-1.5 border border-cyan-signal/80 shadow-glow-cyan"
                onError={(e) => {
                  e.target.style.display = 'none';
                }}
              />
            </div>
          </div>
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-signal/10 border border-cyan-signal/30 text-cyan-signal font-mono text-xs tracking-wider">
            <Terminal className="w-3.5 h-3.5" />
            <span>RECON7 ENTERPRISE INITIALIZATION</span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-display font-bold tracking-tight text-text-primary">
            Root Administrator Setup
          </h1>
          <p className="text-xs sm:text-sm text-text-dim max-w-md mx-auto leading-relaxed">
            Welcome to Recon7. No security administrator has been configured yet.
            Please establish the master root credentials to initialize the platform.
          </p>
        </div>

        {/* Security Alert Callout */}
        <div className="mb-6 p-4 rounded-lg bg-panel-elevated border border-border-dim shadow-panel flex items-start gap-3">
          <ShieldAlert className="w-5 h-5 text-cyan-signal mt-0.5 shrink-0" />
          <div className="text-xs space-y-1">
            <div className="font-bold text-text-primary uppercase tracking-wider font-mono">
              Master Access Lockdown
            </div>
            <p className="text-text-dim leading-relaxed">
              Once created, open registration will be permanently closed. This account will have global authority to provision operators, manage organizations, and configure attack surface reconnaissance.
            </p>
          </div>
        </div>

        {/* Setup Card */}
        <div className="panel-glass rounded-xl border border-border-dim p-6 sm:p-8 shadow-2xl space-y-6 bg-panel">
          {error && (
            <div className="p-3.5 rounded-md bg-magenta-alert/15 border border-magenta-alert/40 text-magenta-alert text-xs flex items-start gap-2.5 animate-shake">
              <AlertOctagon className="w-4 h-4 shrink-0 mt-0.5" />
              <span className="font-mono">{error}</span>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-xs font-mono font-bold uppercase text-text-dim mb-1.5">
                Administrator Full Name
              </label>
              <div className="relative">
                <User className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-text-dim" />
                <input
                  type="text"
                  required
                  value={fullName}
                  onChange={(e) => setFullName(e.target.value)}
                  placeholder="e.g. Lead Security Officer"
                  className="w-full pl-9 pr-3 py-2.5 rounded-md bg-void border border-border-dim focus:border-cyan-signal text-text-primary text-xs font-mono outline-none transition-all placeholder:text-text-dim/40 shadow-inner"
                />
              </div>
            </div>

            <div>
              <label className="block text-xs font-mono font-bold uppercase text-text-dim mb-1.5">
                Master Work Email
              </label>
              <div className="relative">
                <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-text-dim" />
                <input
                  type="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="admin@enterprise.local"
                  className="w-full pl-9 pr-3 py-2.5 rounded-md bg-void border border-border-dim focus:border-cyan-signal text-text-primary text-xs font-mono outline-none transition-all placeholder:text-text-dim/40 shadow-inner"
                />
              </div>
            </div>

            <div>
              <label className="block text-xs font-mono font-bold uppercase text-text-dim mb-1.5">
                Primary Organization / Workspace Name
              </label>
              <div className="relative">
                <Building className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-text-dim" />
                <input
                  type="text"
                  value={orgName}
                  onChange={(e) => setOrgName(e.target.value)}
                  placeholder="e.g. Cyber Defense Command"
                  className="w-full pl-9 pr-3 py-2.5 rounded-md bg-void border border-border-dim focus:border-cyan-signal text-text-primary text-xs font-mono outline-none transition-all placeholder:text-text-dim/40 shadow-inner"
                />
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className="block text-xs font-mono font-bold uppercase text-text-dim mb-1.5">
                  Master Password
                </label>
                <div className="relative">
                  <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-text-dim" />
                  <input
                    type="password"
                    required
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="Min 8 characters"
                    className="w-full pl-9 pr-3 py-2.5 rounded-md bg-void border border-border-dim focus:border-cyan-signal text-text-primary text-xs font-mono outline-none transition-all placeholder:text-text-dim/40 shadow-inner"
                  />
                </div>
              </div>

              <div>
                <label className="block text-xs font-mono font-bold uppercase text-text-dim mb-1.5">
                  Confirm Password
                </label>
                <div className="relative">
                  <KeyRound className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-text-dim" />
                  <input
                    type="password"
                    required
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    placeholder="Repeat password"
                    className="w-full pl-9 pr-3 py-2.5 rounded-md bg-void border border-border-dim focus:border-cyan-signal text-text-primary text-xs font-mono outline-none transition-all placeholder:text-text-dim/40 shadow-inner"
                  />
                </div>
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full mt-4 flex items-center justify-center gap-2 py-3 rounded-md bg-cyan-signal text-black font-semibold text-xs tracking-wider uppercase font-mono shadow-glow-cyan-sm hover:brightness-110 active:scale-[0.99] transition-all disabled:opacity-50"
            >
              {loading ? (
                <span>INITIALIZING SYSTEM...</span>
              ) : (
                <>
                  <ShieldCheck className="w-4 h-4" />
                  <span>INITIALIZE MASTER ACCOUNT & UNLOCK</span>
                  <ArrowRight className="w-4 h-4 ml-1" />
                </>
              )}
            </button>
          </form>
        </div>

        {/* Footer info */}
        <div className="text-center mt-6 text-[11px] font-mono text-text-dim">
          <span>Recon7 Attack Surface Intelligence • Enterprise IAM Edition</span>
        </div>
      </div>
    </div>
  );
}
