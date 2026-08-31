import React, { useState } from 'react';
import { Navigate } from 'react-router-dom';
import { Shield, Lock, LogIn, ArrowRight, Radio } from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import AuthModal from './AuthModal';

export default function ProtectedRoute({ children }) {
  const { isAuthenticated, loading } = useAuth();
  const [authModalOpen, setAuthModalOpen] = useState(false);

  if (loading) {
    return (
      <div className="min-h-screen bg-void flex items-center justify-center font-mono text-xs text-text-dim gap-3">
        <span className="w-3 h-3 rounded-full bg-cyan-signal animate-ping" />
        <span className="text-cyan-signal font-bold uppercase tracking-wider">
          VERIFYING OPERATOR CREDENTIALS...
        </span>
      </div>
    );
  }

  if (!isAuthenticated) {
    return (
      <div className="min-h-screen bg-[#020408] flex flex-col items-center justify-center p-6 font-sans text-text-primary cyber-grid relative overflow-hidden">
        {/* Ambient Glow */}
        <div className="absolute w-96 h-96 bg-magenta-alert/10 rounded-full blur-3xl pointer-events-none" />

        <div className="max-w-md w-full rounded-2xl bg-panel border border-border-bright p-8 text-center space-y-6 shadow-panel relative z-10">
          <div className="flex justify-center">
            <div className="relative group">
              <div className="absolute -inset-1 bg-gradient-to-r from-cyan-signal to-cyan-bright rounded-2xl blur-md opacity-70 group-hover:opacity-100 transition duration-300"></div>
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

          <div className="space-y-2">
            <div className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full bg-magenta-alert/10 border border-magenta-alert/40 text-magenta-alert font-mono text-[10px] font-bold uppercase tracking-wider">
              <Radio className="w-3 h-3 animate-pulse" />
              <span>ACCESS RESTRICTED // AUTH REQUIRED</span>
            </div>
            <h1 className="text-xl font-display font-black tracking-tight uppercase text-text-primary">
              OPERATOR AUTHENTICATION REQUIRED
            </h1>
            <p className="text-xs font-mono text-text-dim leading-relaxed">
              This operational console and its target asset telemetry are strictly restricted to authenticated red team operators.
            </p>
          </div>

          <div className="pt-2 space-y-3 font-mono text-xs">
            <button
              onClick={() => setAuthModalOpen(true)}
              className="w-full py-3 rounded-xl bg-cyan-signal text-black font-bold tracking-wider hover:brightness-110 active:scale-[0.98] shadow-glow-cyan-sm transition-all flex items-center justify-center gap-2"
            >
              <LogIn className="w-4 h-4" />
              <span>AUTHENTICATE OPERATOR</span>
            </button>

            <a
              href="/portal"
              className="inline-block text-[11px] text-text-dim hover:text-cyan-signal transition-colors"
            >
              ← Return to Public Intelligence Portal
            </a>
          </div>
        </div>

        <AuthModal
          isOpen={authModalOpen}
          onClose={() => setAuthModalOpen(false)}
          onSuccess={() => setAuthModalOpen(false)}
        />
      </div>
    );
  }

  return children;
}
