import React, { useState } from 'react';
import {
  Shield,
  Search,
  Globe,
  Users,
  Server,
  Terminal,
  Activity,
  ArrowRight,
  Lock,
  Cpu,
  Layers,
  FileText,
  AlertTriangle,
  CheckCircle2,
  ChevronRight,
  ExternalLink,
  Radar,
  Crosshair,
  Radio,
  Fingerprint,
  LogOut,
  User as UserIcon,
} from 'lucide-react';
import ParticleBackground from '../components/landing/ParticleBackground';
import PipelineFlow from '../components/landing/PipelineFlow';
import AuthModal from '../components/auth/AuthModal';
import { useAuth } from '../context/AuthContext';

export default function LandingPageView({ onEnterConsole, onInitiateScan }) {
  const { isAuthenticated, user, logout } = useAuth();
  const [targetInput, setTargetInput] = useState('');
  const [errorMsg, setErrorMsg] = useState('');
  const [authModalOpen, setAuthModalOpen] = useState(false);
  const [pendingDomain, setPendingDomain] = useState('');

  const handleSubmit = (e) => {
    e.preventDefault();
    const cleanDomain = targetInput.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
    if (!cleanDomain || !cleanDomain.includes('.')) {
      setErrorMsg('Please enter a valid domain name (e.g., example.com)');
      return;
    }
    setErrorMsg('');

    // If not authenticated, require login / onboarding before scanning
    if (!isAuthenticated) {
      setPendingDomain(cleanDomain);
      setAuthModalOpen(true);
      return;
    }

    if (onInitiateScan) {
      onInitiateScan(cleanDomain);
    } else if (onEnterConsole) {
      onEnterConsole();
    }
  };

  return (
    <div className="min-h-screen bg-[#020408] text-text-primary flex flex-col font-sans selection:bg-cyan-signal selection:text-void relative overflow-x-hidden">
      {/* Delicate Faint Background Particles */}
      <ParticleBackground className="z-0" />

      {/* 1. CLASSIFICATION TOP HEADER */}
      <header className="h-16 border-b border-[#0e1626] bg-[#020408]/90 backdrop-blur-md px-6 flex items-center justify-between sticky top-0 z-50">
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-3">
            <img
              src="/logo.png"
              alt="Recon7 Logo"
              className="w-8 h-8 rounded object-contain border border-cyan-signal/40 shadow-glow-cyan-sm"
              onError={(e) => {
                e.target.style.display = 'none';
              }}
            />
            <div className="flex items-center gap-2">
              <span className="font-display font-black text-xl tracking-wider text-text-primary">
                RECON<span className="text-cyan-signal">7</span>
              </span>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <div className="hidden md:flex items-center gap-2 text-[11px] font-mono text-text-dim px-3 py-1 rounded bg-[#050811] border border-[#0e1626]">
            <span className="w-2 h-2 rounded-full bg-success-green animate-pulse shadow-glow-green" />
            <span>GLOBAL SENSOR GRID ONLINE</span>
          </div>

          {isAuthenticated ? (
            <>
              <div className="hidden sm:flex items-center gap-2 px-3 py-1.5 rounded bg-[#050811] border border-[#142033] text-xs font-mono">
                <UserIcon className="w-3.5 h-3.5 text-cyan-signal" />
                <span className="text-text-primary font-medium">{user?.full_name || user?.email}</span>
              </div>

              <button
                onClick={onEnterConsole}
                className="px-4 py-2 rounded-md bg-cyan-signal/15 hover:bg-cyan-signal/25 border border-cyan-signal/50 text-cyan-signal font-mono text-xs font-bold transition-all flex items-center gap-1.5 shadow-glow-cyan-sm hover:shadow-glow-cyan"
              >
                <span>OPERATIONS CONSOLE</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>

              <button
                onClick={logout}
                className="p-2 rounded-md text-text-dim hover:text-magenta-alert hover:bg-[#142033] transition-colors"
                title="Sign Out"
              >
                <LogOut className="w-4 h-4" />
              </button>
            </>
          ) : (
            <button
              onClick={() => setAuthModalOpen(true)}
              className="px-4 py-2 rounded-md bg-cyan-signal hover:bg-cyan-bright text-void font-mono text-xs font-bold transition-all flex items-center gap-1.5 shadow-glow-cyan hover:scale-[1.02] active:scale-95"
            >
              <span>SIGN IN / ONBOARD</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          )}
        </div>
      </header>

      {/* 2. HERO SECTION WITH OFFICIAL RECON7 EMBLEM */}
      <section className="relative min-h-[640px] lg:min-h-[700px] flex items-center border-b border-[#0e1626] px-6 lg:px-16 py-16 z-10">
        <div className="max-w-7xl mx-auto w-full grid grid-cols-1 lg:grid-cols-12 gap-12 lg:gap-8 items-center">
          
          {/* Hero Left */}
          <div className="lg:col-span-7 space-y-6">
            <div className="space-y-2">
              <div className="text-xs font-mono tracking-widest text-cyan-signal font-bold uppercase">
                RECON7
              </div>
              <h1 className="text-3xl sm:text-4xl lg:text-5xl font-display font-black tracking-tight leading-tight text-text-primary">
                Map what's exposed. <br />
                <span className="text-cyan-signal">Before someone else does.</span>
              </h1>
            </div>

            <p className="text-text-dim text-sm sm:text-base leading-relaxed max-w-xl font-mono">
              Recon7 is an autonomous reconnaissance engine for authorized red team operations — subdomain discovery,
              deep service scanning, and AI-prioritized findings, from one input.
            </p>

            {/* Quick Target Launchpad Form */}
            <form onSubmit={handleSubmit} className="space-y-2 pt-2 max-w-lg">
              <div className="flex flex-col sm:flex-row gap-2">
                <div className="relative flex-1">
                  <Globe className="w-4 h-4 text-cyan-signal absolute left-3.5 top-1/2 -translate-y-1/2" />
                  <input
                    type="text"
                    placeholder="Enter target domain (e.g. example.com)"
                    value={targetInput}
                    onChange={(e) => setTargetInput(e.target.value)}
                    className="w-full pl-10 pr-4 py-3 bg-[#050811]/90 border border-[#142033] focus:border-cyan-signal rounded-md text-xs font-mono text-text-primary placeholder:text-text-dim/60 focus:outline-none transition-all shadow-inner"
                  />
                </div>

                <button
                  type="submit"
                  className="px-6 py-3 rounded-md bg-cyan-signal hover:bg-cyan-bright text-void font-mono font-bold text-xs tracking-wider transition-all flex items-center justify-center gap-2 shadow-glow-cyan hover:scale-[1.02] active:scale-95 shrink-0"
                >
                  <span>Start a scan</span>
                  <Crosshair className="w-4 h-4" />
                </button>
              </div>

              {errorMsg && (
                <p className="text-xs font-mono text-magenta-alert">{errorMsg}</p>
              )}

              <p className="text-[11px] font-mono text-text-dim flex items-center gap-1.5 pt-0.5">
                <Lock className="w-3 h-3 text-cyan-signal" />
                <span>
                  {isAuthenticated
                    ? 'Authorization required before any active scan runs.'
                    : 'Sign in / account onboarding required prior to scan execution.'}
                </span>
              </p>
            </form>

            {/* Plain Stat Strip */}
            <div className="grid grid-cols-3 gap-4 pt-6 border-t border-[#0e1626] max-w-lg">
              <div>
                <div className="text-xl font-display font-black text-cyan-signal">8-stage</div>
                <div className="text-[11px] font-mono text-text-dim">pipeline</div>
              </div>
              <div>
                <div className="text-xl font-display font-black text-emerald-400">Free-tool</div>
                <div className="text-[11px] font-mono text-text-dim">backbone</div>
              </div>
              <div>
                <div className="text-xl font-display font-black text-text-primary">AI-triaged</div>
                <div className="text-[11px] font-mono text-text-dim">output</div>
              </div>
            </div>
          </div>

          {/* Hero Right: Official Logo Centerpiece */}
          <div className="lg:col-span-5 flex items-center justify-center">
            <div className="relative w-full max-w-md p-8 rounded-2xl bg-[#050811]/85 border border-[#142033] backdrop-blur-xl shadow-2xl flex flex-col items-center text-center space-y-6 group hover:border-cyan-signal/40 transition-all duration-300">
              
              {/* Subtle Atmospheric Glow Aura */}
              <div className="absolute inset-0 rounded-2xl bg-cyan-signal/5 blur-2xl pointer-events-none" />

              {/* Agency Radar Reticle Ring */}
              <div className="relative w-48 h-48 sm:w-56 sm:h-56 flex items-center justify-center">
                {/* Slow Rotating Thin Outer Compass Ring */}
                <div
                  className="absolute inset-0 rounded-full border border-dashed border-cyan-signal/30 animate-spin"
                  style={{ animationDuration: '40s' }}
                />
                <div className="absolute inset-2 rounded-full border border-[#142033]" />
                <div className="absolute inset-5 rounded-full border border-cyan-signal/20" />

                {/* Official Recon7 Logo */}
                <img
                  src="/logo.png"
                  alt="Recon7 Emblem"
                  className="w-36 h-36 sm:w-44 sm:h-44 object-contain rounded-xl relative z-10 drop-shadow-[0_0_35px_rgba(6,182,212,0.3)] transition-transform duration-300 group-hover:scale-105"
                  onError={(e) => {
                    e.target.style.display = 'none';
                  }}
                />
              </div>

              {/* Emblem Badge */}
              <div className="space-y-1.5 relative z-10">
                <div className="flex items-center justify-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse shadow-glow-green" />
                  <span className="text-sm font-mono font-bold tracking-wider text-cyan-signal">
                    Recon7
                  </span>
                </div>
                <p className="text-[11px] font-mono text-text-dim tracking-wide uppercase">
                  RECONNAISSANCE MADE EASIER FOR RED TEAM OPS
                </p>
              </div>
            </div>
          </div>

        </div>
      </section>

      {/* 3. CAPABILITIES — SIX CARDS */}
      <section className="px-6 lg:px-16 py-20 border-b border-[#0e1626] bg-[#03060c]/60 z-10">
        <div className="max-w-7xl mx-auto space-y-10">
          <div>
            <span className="text-xs font-mono text-cyan-signal uppercase tracking-widest font-bold">
              CAPABILITIES
            </span>
            <h2 className="text-2xl md:text-3xl font-display font-black text-text-primary mt-1">
              SURFACE & EXPOSURE ANALYSIS
            </h2>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {/* Card 01 */}
            <div className="p-6 rounded-lg bg-[#050811]/90 border border-[#0e1626] hover:border-cyan-signal/50 transition-all group space-y-3 shadow-panel">
              <div className="w-10 h-10 rounded-md bg-[#020408] border border-[#142033] flex items-center justify-center text-cyan-signal group-hover:shadow-glow-cyan-sm transition-all">
                <Server className="w-5 h-5" />
              </div>
              <h3 className="text-sm font-mono font-bold text-text-primary">01 — Attack surface</h3>
              <p className="text-xs text-text-dim leading-relaxed font-mono">
                Subdomains, IPs, and origin hosts mapped from public DNS, cert transparency, and passive sources.
              </p>
            </div>

            {/* Card 02 */}
            <div className="p-6 rounded-lg bg-[#050811]/90 border border-[#0e1626] hover:border-emerald-400/50 transition-all group space-y-3 shadow-panel">
              <div className="w-10 h-10 rounded-md bg-[#020408] border border-[#142033] flex items-center justify-center text-emerald-400 group-hover:shadow-glow-green-sm transition-all">
                <Cpu className="w-5 h-5" />
              </div>
              <h3 className="text-sm font-mono font-bold text-text-primary">02 — Deep scan</h3>
              <p className="text-xs text-text-dim leading-relaxed font-mono">
                Two-stage port sweep and service/version fingerprinting across every discovered host.
              </p>
            </div>

            {/* Card 03 */}
            <div className="p-6 rounded-lg bg-[#050811]/90 border border-[#0e1626] hover:border-magenta-alert/50 transition-all group space-y-3 shadow-panel">
              <div className="w-10 h-10 rounded-md bg-[#020408] border border-[#142033] flex items-center justify-center text-magenta-alert group-hover:shadow-glow-magenta-sm transition-all">
                <AlertTriangle className="w-5 h-5" />
              </div>
              <h3 className="text-sm font-mono font-bold text-text-primary">03 — Vulnerability correlation</h3>
              <p className="text-xs text-text-dim leading-relaxed font-mono">
                Fingerprinted services matched against CVE and OWASP Top 10, scored by severity.
              </p>
            </div>

            {/* Card 04 */}
            <div className="p-6 rounded-lg bg-[#050811]/90 border border-[#0e1626] hover:border-cyan-signal/50 transition-all group space-y-3 shadow-panel">
              <div className="w-10 h-10 rounded-md bg-[#020408] border border-[#142033] flex items-center justify-center text-cyan-signal group-hover:shadow-glow-cyan-sm transition-all">
                <Users className="w-5 h-5" />
              </div>
              <h3 className="text-sm font-mono font-bold text-text-primary">04 — Org exposure</h3>
              <p className="text-xs text-text-dim leading-relaxed font-mono">
                Public employee names and inferred email patterns, sourced from company pages, documents, and commit history.
              </p>
            </div>

            {/* Card 05 */}
            <div className="p-6 rounded-lg bg-[#050811]/90 border border-[#0e1626] hover:border-amber-400/50 transition-all group space-y-3 shadow-panel">
              <div className="w-10 h-10 rounded-md bg-[#020408] border border-[#142033] flex items-center justify-center text-amber-400 transition-all">
                <FileText className="w-5 h-5" />
              </div>
              <h3 className="text-sm font-mono font-bold text-text-primary">05 — Document metadata</h3>
              <p className="text-xs text-text-dim leading-relaxed font-mono">
                Author names and internal usernames pulled from public PDFs and Office docs published by the target.
              </p>
            </div>

            {/* Card 06 */}
            <div className="p-6 rounded-lg bg-[#050811]/90 border border-[#0e1626] hover:border-cyan-signal/50 transition-all group space-y-3 shadow-panel">
              <div className="w-10 h-10 rounded-md bg-[#020408] border border-[#142033] flex items-center justify-center text-cyan-signal group-hover:shadow-glow-cyan-sm transition-all">
                <Lock className="w-5 h-5" />
              </div>
              <h3 className="text-sm font-mono font-bold text-text-primary">06 — Scope enforcement</h3>
              <p className="text-xs text-text-dim leading-relaxed font-mono">
                Every scan runs against an attested, authorized target. No exceptions.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* 4. PIPELINE SECTION WITH CONNECTED ANIMATED LINES */}
      <section className="px-6 lg:px-16 py-20 border-b border-[#0e1626] z-10">
        <div className="max-w-5xl mx-auto space-y-6">
          <div className="text-center space-y-2 pb-2">
            <span className="text-xs font-mono text-cyan-signal uppercase tracking-widest font-bold">
              PIPELINE
            </span>
            <h2 className="text-2xl md:text-3xl font-display font-black text-text-primary">
              THE 8-STAGE RECONNAISSANCE ENGINE
            </h2>
          </div>

          {/* Connected Pipeline Flow Circuit with Animated Lines */}
          <PipelineFlow />

          <div className="rounded-lg bg-[#020408] border border-[#142033] shadow-2xl p-4 font-mono text-xs overflow-hidden mt-6">
            <div className="flex items-center justify-between border-b border-[#0e1626] pb-3 mb-3 text-text-dim">
              <div className="flex items-center gap-2">
                <Terminal className="w-4 h-4 text-cyan-signal" />
                <span className="text-text-primary font-bold">recon7-core // worker.py (TELEMETRY FEED)</span>
              </div>
              <span className="text-[10px] text-success-green">STATUS: HEALTHY</span>
            </div>

            <div className="space-y-2 text-text-dim leading-relaxed">
              <p className="text-cyan-signal">
                [01.INIT] Checking scope authorization attestation for target... <span className="text-success-green">VERIFIED</span>
              </p>
              <p>
                [02.DNS] Enumerating subdomains via Certificate Transparency & Sublist3r... <span className="text-text-primary">184 hosts identified</span>
              </p>
              <p className="text-amber-400">
                [03.CDN_BYPASS] Cloudflare Anycast edge detected (104.18.20.14) &rarr; Probing TLS SAN & historical DNS records...
              </p>
              <p className="text-cyan-signal font-bold">
                [03.CDN_BYPASS] Possible origin identified, unconfirmed: 162.0.233.40
              </p>
              <p>
                [04.PORTS] Executing concurrent port probes on 162.0.233.40... <span className="text-cyan-signal">21/ftp, 80/http, 443/https OPEN</span>
              </p>
              <p>
                [05.TECH] Fingerprinting web technology stack... <span className="text-text-primary">Nginx 1.24, PHP 8.2, OpenSSL 3.0</span>
              </p>
              <p className="text-magenta-alert">
                [06.VULNS] Triaged 41 security advisories across exposed ports & application endpoints
              </p>
              <p>
                [07.WHOIS] Parsing registrar, nameserver authority, and autonomous system number... <span className="text-text-primary">ASN 37075</span>
              </p>
              <p className="text-emerald-400 font-bold">
                [08.PEOPLE_OSINT] Resolved 40+ human personnel with LinkedIn profile links & corporate hierarchy
              </p>
              <p className="text-cyan-signal pt-2 border-t border-[#0e1626]">
                [+] SCAN COMPLETE // Synthesis recorded to Investigation Graph.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* 5. FOOTER CTA */}
      <footer className="px-6 lg:px-16 py-12 bg-[#020408] border-t border-[#0e1626] flex flex-col md:flex-row items-center justify-between gap-6 text-xs font-mono text-text-dim z-10">
        <div className="flex items-center gap-3">
          <img
            src="/logo.png"
            alt="Recon7 Logo"
            className="w-6 h-6 rounded object-contain"
            onError={(e) => {
              e.target.style.display = 'none';
            }}
          />
          <div>
            <span className="font-bold text-text-primary text-sm sm:text-base">
              Recon7. Built for people who already know what they're looking for.
            </span>
          </div>
        </div>

        <div className="flex items-center gap-4 shrink-0">
          {isAuthenticated ? (
            <button
              onClick={onEnterConsole}
              className="px-5 py-2.5 rounded bg-cyan-signal text-void font-bold hover:bg-cyan-bright transition-all flex items-center gap-1.5 shadow-glow-cyan-sm"
            >
              <span>Launch console</span>
              <ChevronRight className="w-3.5 h-3.5" />
            </button>
          ) : (
            <button
              onClick={() => setAuthModalOpen(true)}
              className="px-5 py-2.5 rounded bg-cyan-signal/20 hover:bg-cyan-signal/30 text-cyan-signal border border-cyan-signal/40 font-bold transition-all flex items-center gap-1.5 shadow-glow-cyan-sm"
            >
              <span>Sign in to launch console</span>
              <ChevronRight className="w-3.5 h-3.5" />
            </button>
          )}
        </div>
      </footer>

      {/* Security Access Gate Auth Modal */}
      <AuthModal
        isOpen={authModalOpen}
        onClose={() => setAuthModalOpen(false)}
        pendingDomain={pendingDomain}
        onSuccess={() => {
          if (pendingDomain) {
            onInitiateScan(pendingDomain);
            setPendingDomain('');
          } else {
            onEnterConsole();
          }
        }}
      />
    </div>
  );
}
