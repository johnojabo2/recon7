import React, { useState, useEffect, useRef } from 'react';
import {
  Shield,
  Plus,
  ChevronDown,
  Check,
  Building2,
  Radio,
  Globe,
  LogOut,
  LogIn,
  User as UserIcon,
  KeyRound,
  ShieldCheck,
  Settings,
  BookOpen,
  Sun,
  Moon,
} from 'lucide-react';
import { useTenant } from '../context/TenantContext';
import { useTenants } from '../api/hooks';
import { useAuth } from '../context/AuthContext';
import { useTheme } from '../context/ThemeContext';
import AuthModal from './auth/AuthModal';

export default function TopBar({ onOpenNewScan, activeTab, onSelectTab }) {
  const { tenantId, setTenantId, activeTarget } = useTenant();
  const { user, logout, isAuthenticated } = useAuth();
  const { theme, toggleTheme, isDark } = useTheme();
  const { data: tenants = [] } = useTenants();
  const [dropdownOpen, setDropdownOpen] = useState(false);
  const [userMenuOpen, setUserMenuOpen] = useState(false);
  const [authModalOpen, setAuthModalOpen] = useState(false);

  const userMenuRef = useRef(null);

  // Close user dropdown on outside click
  useEffect(() => {
    function handleClickOutside(event) {
      if (userMenuRef.current && !userMenuRef.current.contains(event.target)) {
        setUserMenuOpen(false);
      }
    }
    if (userMenuOpen) {
      document.addEventListener('mousedown', handleClickOutside);
    }
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, [userMenuOpen]);

  const handleSignOut = () => {
    logout();
    onSelectTab('landing');
  };

  const currentTenant = tenants.find((t) => t.id === tenantId) || {
    id: tenantId,
    name: tenantId === 'dev-default-tenant' ? 'Development Org' : `Tenant ${tenantId.slice(0, 8)}`,
  };

  return (
    <header className="h-16 border-b border-border-dim bg-panel px-6 flex items-center justify-between sticky top-0 z-40">
      {/* Brand & Active Target */}
      <div className="flex items-center gap-6">
        <div className="flex items-center gap-3 cursor-pointer group" onClick={() => onSelectTab('dashboard')} title="Recon7 Operational Console">
          <img
            src="/logo.png"
            alt="Recon7 Logo"
            className="w-9 h-9 rounded object-contain border border-cyan-signal/60 group-hover:border-cyan-signal shadow-glow-cyan-sm transition-all"
            onError={(e) => {
              e.target.style.display = 'none';
            }}
          />
          <div>
            <div className="flex items-center gap-2">
              <span className="font-display font-bold text-lg tracking-wider text-text-primary group-hover:text-cyan-signal transition-colors">RECON7</span>
              <span className="text-[10px] px-1.5 py-0.5 rounded bg-cyan-signal/10 border border-cyan-signal/40 text-cyan-signal font-mono font-bold">
                ENTERPRISE
              </span>
            </div>
            <p className="text-[10px] text-text-dim tracking-wider font-mono">GLOBAL OSINT PLATFORM</p>
          </div>
        </div>

        <div className="h-6 w-[1px] bg-border-dim hidden md:block" />

        {/* Active Target Banner */}
        <div className="hidden md:flex items-center gap-2 text-xs">
          <span className="text-text-dim">TARGET:</span>
          {activeTarget ? (
            <span className="font-mono text-cyan-signal font-medium bg-cyan-signal/10 px-2.5 py-1 rounded border border-cyan-signal/30">
              {activeTarget}
            </span>
          ) : (
            <span className="font-mono text-text-dim italic">No active target</span>
          )}
        </div>
      </div>

      {/* Right Controls: Tenant Switcher & Quick Scan */}
      <div className="flex items-center gap-3">
        {/* Documentation Hub Button */}
        <button
          onClick={() => onSelectTab('docs')}
          className={`hidden sm:flex items-center gap-1.5 px-3 py-1.5 rounded-md border font-mono text-xs transition-colors ${
            activeTab === 'docs'
              ? 'bg-cyan-signal/15 text-cyan-signal border-cyan-signal/50 shadow-glow-cyan-sm'
              : 'bg-void border-border-dim hover:border-cyan-signal/40 text-text-dim hover:text-cyan-signal'
          }`}
          title="Open Documentation & Deployment Hub"
        >
          <BookOpen className="w-3.5 h-3.5" />
          <span>DOCS</span>
        </button>

        {/* Global Light / Dark Theme Switcher */}
        <button
          onClick={toggleTheme}
          className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-md bg-void border border-border-dim hover:border-cyan-signal/50 text-text-primary text-xs font-mono transition-all"
          title={`Switch to ${isDark ? 'Light' : 'Dark'} Mode`}
        >
          {isDark ? (
            <>
              <Sun className="w-3.5 h-3.5 text-amber-400" />
              <span className="hidden sm:inline text-text-dim hover:text-text-primary">LIGHT</span>
            </>
          ) : (
            <>
              <Moon className="w-3.5 h-3.5 text-cyan-600" />
              <span className="hidden sm:inline text-text-dim hover:text-text-primary">DARK</span>
            </>
          )}
        </button>

        {/* Live System Beacon */}
        <div className="hidden lg:flex items-center gap-2 px-3 py-1 rounded-full bg-void border border-border-dim text-xs">
          <span className="w-2 h-2 rounded-full bg-success-green shadow-glow-green animate-pulse" />
          <span className="font-mono text-text-dim text-[11px]">CORE ONLINE</span>
        </div>

        {/* Tenant Selector Dropdown */}
        <div className="relative">
          <button
            onClick={() => setDropdownOpen(!dropdownOpen)}
            className="flex items-center gap-2.5 px-3 py-1.5 rounded-md bg-void border border-border-dim hover:border-border-bright text-xs text-text-primary transition-colors"
          >
            <Building2 className="w-3.5 h-3.5 text-cyan-signal" />
            <span className="max-w-[140px] truncate font-medium">{currentTenant.name}</span>
            <ChevronDown className="w-3.5 h-3.5 text-text-dim" />
          </button>

          {dropdownOpen && (
            <div className="absolute right-0 mt-2 w-64 rounded-md bg-panel-elevated border border-border-bright shadow-panel z-50 p-1.5">
              <div className="px-2.5 py-1.5 text-[11px] font-mono text-text-dim uppercase tracking-wider border-b border-border-dim mb-1">
                Select Tenant Organization
              </div>
              <div className="max-h-56 overflow-y-auto">
                {tenants.map((t) => (
                  <button
                    key={t.id}
                    onClick={() => {
                      setTenantId(t.id);
                      setDropdownOpen(false);
                    }}
                    className={`w-full flex items-center justify-between px-2.5 py-2 rounded text-xs text-left transition-colors ${
                      t.id === tenantId
                        ? 'bg-cyan-signal/10 text-cyan-signal font-medium'
                        : 'text-text-primary hover:bg-void'
                    }`}
                  >
                    <span className="truncate">{t.name}</span>
                    {t.id === tenantId && <Check className="w-3.5 h-3.5 text-cyan-signal" />}
                  </button>
                ))}
              </div>
              <div className="border-t border-border-dim mt-1 pt-1">
                <button
                  onClick={() => {
                    onSelectTab('settings');
                    setDropdownOpen(false);
                  }}
                  className="w-full text-left px-2.5 py-1.5 text-xs text-text-dim hover:text-cyan-signal transition-colors flex items-center gap-1.5"
                >
                  <Plus className="w-3.5 h-3.5" />
                  <span>Manage / Add Tenant</span>
                </button>
              </div>
            </div>
          )}
        </div>

        {/* New Scan Action Button */}
        <button
          onClick={onOpenNewScan}
          className="flex items-center gap-2 px-4 py-1.5 rounded-md bg-cyan-signal text-black font-semibold text-xs tracking-wide shadow-glow-cyan-sm hover:brightness-110 active:scale-[0.98] transition-all font-mono"
        >
          <Plus className="w-4 h-4" />
          <span>NEW SCAN</span>
        </button>

        {/* User Account Icon & Options Dropdown */}
        <div className="relative pl-2 border-l border-border-dim flex items-center gap-2" ref={userMenuRef}>
          {!isAuthenticated && (
            <button
              onClick={() => setAuthModalOpen(true)}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-cyan-signal/15 border border-cyan-signal/50 text-cyan-signal hover:bg-cyan-signal hover:text-black transition-all font-mono text-xs font-bold shadow-glow-cyan-sm"
              title="Sign In / Authenticate Operator"
            >
              <LogIn className="w-3.5 h-3.5" />
              <span>SIGN IN</span>
            </button>
          )}

          <button
            onClick={() => setUserMenuOpen(!userMenuOpen)}
            className="flex items-center gap-2.5 p-1.5 pr-2.5 rounded-lg bg-void border border-border-dim hover:border-cyan-signal/40 text-text-primary transition-all group"
            title="Operator Profile & Options"
          >
            <div className="w-7 h-7 rounded-md bg-cyan-signal/15 border border-cyan-signal/50 flex items-center justify-center text-cyan-signal font-mono font-bold text-xs shadow-glow-cyan-sm group-hover:scale-105 transition-transform">
              {user?.full_name ? user.full_name.charAt(0).toUpperCase() : <UserIcon className="w-3.5 h-3.5" />}
            </div>

            <div className="hidden xl:flex flex-col text-left">
              <span className="text-xs font-mono font-bold text-text-primary leading-none">
                {user?.full_name || user?.email || (isAuthenticated ? 'Operator' : 'Guest Operator')}
              </span>
              <span className="text-[9px] font-mono text-cyan-signal uppercase tracking-wider mt-0.5 font-semibold">
                {user?.role || (isAuthenticated ? 'ADMIN' : 'UNAUTHENTICATED')}
              </span>
            </div>

            <ChevronDown className={`w-3.5 h-3.5 text-text-dim group-hover:text-text-primary transition-transform ${userMenuOpen ? 'rotate-180 text-cyan-signal' : ''}`} />
          </button>

          {/* Dropdown Card */}
          {userMenuOpen && (
            <div className="absolute right-0 top-full mt-2 w-72 rounded-xl bg-panel-elevated border border-border-bright shadow-2xl z-50 overflow-hidden animate-fade-in font-sans">
              {/* Header User Card */}
              <div className="p-4 bg-void/80 border-b border-border-dim space-y-2">
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 rounded-lg bg-cyan-signal/20 border border-cyan-signal/60 flex items-center justify-center text-cyan-signal font-mono font-black text-sm shadow-glow-cyan-sm">
                    {user?.full_name ? user.full_name.charAt(0).toUpperCase() : <UserIcon className="w-5 h-5" />}
                  </div>
                  <div className="overflow-hidden">
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-mono font-bold text-text-primary truncate">
                        {user?.full_name || (isAuthenticated ? 'Operator' : 'Guest Operator')}
                      </span>
                      <span className="text-[9px] px-1.5 py-0.5 rounded bg-cyan-signal/15 border border-cyan-signal/40 text-cyan-signal font-mono font-bold uppercase">
                        {user?.role || (isAuthenticated ? 'ADMIN' : 'GUEST')}
                      </span>
                    </div>
                    <p className="text-[11px] font-mono text-text-dim truncate">
                      {user?.email || (isAuthenticated ? 'operator@recon7.io' : 'No active session token')}
                    </p>
                  </div>
                </div>

                <div className="pt-2 border-t border-border-dim/60 flex items-center justify-between text-[11px] font-mono text-text-dim">
                  <span>Active Tenant:</span>
                  <span className="text-text-primary font-medium truncate max-w-[140px]">{currentTenant.name}</span>
                </div>
              </div>

              {/* Options List */}
              <div className="p-1.5 space-y-0.5 font-mono text-xs">
                {!isAuthenticated && (
                  <button
                    onClick={() => {
                      setUserMenuOpen(false);
                      setAuthModalOpen(true);
                    }}
                    className="w-full flex items-center gap-2.5 px-3 py-2 rounded-md text-cyan-signal bg-cyan-signal/10 hover:bg-cyan-signal/20 transition-colors text-left font-bold"
                  >
                    <LogIn className="w-4 h-4 text-cyan-signal" />
                    <span>Authenticate / Sign In</span>
                  </button>
                )}

                <button
                  onClick={() => {
                    onSelectTab('integrations');
                    setUserMenuOpen(false);
                  }}
                  className="w-full flex items-center gap-2.5 px-3 py-2 rounded-md text-text-dim hover:text-text-primary hover:bg-void transition-colors text-left"
                >
                  <KeyRound className="w-4 h-4 text-cyan-signal" />
                  <span>API & Integrations</span>
                </button>

                <button
                  onClick={() => {
                    onSelectTab('scopes');
                    setUserMenuOpen(false);
                  }}
                  className="w-full flex items-center gap-2.5 px-3 py-2 rounded-md text-text-dim hover:text-text-primary hover:bg-void transition-colors text-left"
                >
                  <ShieldCheck className="w-4 h-4 text-emerald-400" />
                  <span>Authorized Scopes</span>
                </button>

                <button
                  onClick={() => {
                    onSelectTab('settings');
                    setUserMenuOpen(false);
                  }}
                  className="w-full flex items-center gap-2.5 px-3 py-2 rounded-md text-text-dim hover:text-text-primary hover:bg-void transition-colors text-left"
                >
                  <Settings className="w-4 h-4 text-text-dim" />
                  <span>Platform Settings</span>
                </button>

                <button
                  onClick={() => {
                    onSelectTab('docs');
                    setUserMenuOpen(false);
                  }}
                  className="w-full flex items-center gap-2.5 px-3 py-2 rounded-md text-text-dim hover:text-text-primary hover:bg-void transition-colors text-left"
                >
                  <BookOpen className="w-4 h-4 text-cyan-signal" />
                  <span>Documentation Hub</span>
                </button>
              </div>

              {/* Sign Out / Lock Session Action */}
              <div className="p-1.5 border-t border-border-dim bg-void/40">
                <button
                  onClick={() => {
                    setUserMenuOpen(false);
                    handleSignOut();
                  }}
                  className="w-full flex items-center gap-2.5 px-3 py-2 rounded-md text-magenta-alert hover:bg-magenta-alert/10 transition-colors font-mono text-xs font-bold text-left"
                >
                  <LogOut className="w-4 h-4" />
                  <span>{isAuthenticated ? 'Sign Out / Lock Session' : 'Reset Session'}</span>
                </button>
              </div>
            </div>
          )}
        </div>

        {/* Global Auth Modal */}
        <AuthModal
          isOpen={authModalOpen}
          onClose={() => setAuthModalOpen(false)}
          onSuccess={() => setAuthModalOpen(false)}
        />
      </div>
    </header>
  );
}
