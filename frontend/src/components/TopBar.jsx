import React, { useState, useEffect, useRef, useMemo } from 'react';
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
  Search,
} from 'lucide-react';
import { useTenant } from '../context/TenantContext';
import { useTenants, useScansList } from '../api/hooks';
import { useAuth } from '../context/AuthContext';
import { useTheme } from '../context/ThemeContext';
import AuthModal from './auth/AuthModal';

export default function TopBar({ onOpenNewScan, activeTab, onSelectTab }) {
  const { tenantId, setTenantId, activeTarget, selectTarget } = useTenant();
  const { user, logout, isAuthenticated } = useAuth();
  const { theme, toggleTheme, isDark } = useTheme();
  const { data: tenants = [] } = useTenants();
  const { data: scans = [] } = useScansList(100);

  const [dropdownOpen, setDropdownOpen] = useState(false);
  const [userMenuOpen, setUserMenuOpen] = useState(false);
  const [targetMenuOpen, setTargetMenuOpen] = useState(false);
  const [targetSearch, setTargetSearch] = useState('');
  const [authModalOpen, setAuthModalOpen] = useState(false);

  const userMenuRef = useRef(null);
  const tenantMenuRef = useRef(null);
  const targetMenuRef = useRef(null);

  // Close dropdowns on outside click
  useEffect(() => {
    function handleClickOutside(event) {
      if (userMenuRef.current && !userMenuRef.current.contains(event.target)) {
        setUserMenuOpen(false);
      }
      if (tenantMenuRef.current && !tenantMenuRef.current.contains(event.target)) {
        setDropdownOpen(false);
      }
      if (targetMenuRef.current && !targetMenuRef.current.contains(event.target)) {
        setTargetMenuOpen(false);
      }
    }
    document.addEventListener('mousedown', handleClickOutside);
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, []);

  // Derive unique scanned targets sorted by most recent
  const scannedTargets = useMemo(() => {
    const map = new Map();
    for (const s of scans) {
      const domain = s.target_domain;
      if (!domain) continue;
      if (!map.has(domain)) {
        map.set(domain, {
          domain,
          latestScanId: s.id,
          status: s.status,
          createdAt: s.created_at,
          profile: s.scan_profile || 'standard',
        });
      }
    }
    return Array.from(map.values());
  }, [scans]);

  const filteredTargets = useMemo(() => {
    if (!targetSearch.trim()) return scannedTargets;
    return scannedTargets.filter((t) =>
      t.domain.toLowerCase().includes(targetSearch.toLowerCase().trim())
    );
  }, [scannedTargets, targetSearch]);

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
                CONSOLE
              </span>
            </div>
            <p className="text-[10px] text-text-dim tracking-wider font-mono">ATTACK SURFACE INTELLIGENCE</p>
          </div>
        </div>

        <div className="h-6 w-[1px] bg-border-dim hidden md:block" />

        {/* Scanned Targets Dropdown Switcher */}
        <div className="relative hidden md:flex items-center gap-2 text-xs" ref={targetMenuRef}>
          <span className="text-text-dim font-mono font-semibold text-[11px] tracking-wider">TARGET:</span>
          
          <button
            type="button"
            onClick={() => setTargetMenuOpen(!targetMenuOpen)}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-lg border font-mono text-xs transition-all duration-200 select-none ${
              targetMenuOpen
                ? 'bg-cyan-signal/15 border-cyan-signal text-cyan-signal shadow-glow-cyan-sm ring-1 ring-cyan-signal/40'
                : activeTarget
                ? 'bg-cyan-signal/10 border-cyan-signal/40 text-cyan-signal hover:border-cyan-signal/80 hover:bg-cyan-signal/15'
                : 'bg-void border-border-dim text-text-dim hover:border-cyan-signal/40 hover:text-text-primary'
            }`}
            title="Choose Scanned Target Domain"
          >
            {activeTarget ? (
              <span className="font-bold text-cyan-bright truncate max-w-[220px]">{activeTarget}</span>
            ) : (
              <span className="text-text-dim italic">Select target...</span>
            )}
            <ChevronDown className={`w-3.5 h-3.5 text-text-dim transition-transform duration-200 ${targetMenuOpen ? 'rotate-180 text-cyan-signal' : ''}`} />
          </button>

          {/* Target Dropdown Menu */}
          {targetMenuOpen && (
            <div className="absolute top-full left-0 mt-2 w-80 rounded-xl bg-panel/95 border border-border-bright p-3 shadow-2xl z-50 animate-in fade-in zoom-in-95 duration-150 backdrop-blur-2xl">
              <div className="flex items-center justify-between pb-2 mb-2 border-b border-border-dim text-[11px] font-mono text-text-dim">
                <span className="font-bold uppercase tracking-wider text-cyan-signal">Scanned Targets</span>
                <span className="px-1.5 py-0.5 rounded bg-void border border-border-dim text-[10px]">
                  {scannedTargets.length} {scannedTargets.length === 1 ? 'Target' : 'Targets'}
                </span>
              </div>

              {/* Search Filter when multiple targets exist */}
              {scannedTargets.length > 2 && (
                <div className="relative mb-2">
                  <input
                    type="text"
                    value={targetSearch}
                    onChange={(e) => setTargetSearch(e.target.value)}
                    placeholder="Search targets..."
                    className="w-full px-2.5 py-1.5 pl-7 bg-void border border-border-dim rounded-lg text-xs font-mono text-text-primary placeholder:text-text-dim focus:outline-none focus:border-cyan-signal focus:ring-1 focus:ring-cyan-signal/40"
                    autoFocus
                  />
                  <Search className="w-3.5 h-3.5 absolute left-2 top-2 text-text-dim pointer-events-none" />
                </div>
              )}

              {/* Target List Stream */}
              <div className="max-h-56 overflow-y-auto space-y-1 scrollbar-thin pr-0.5">
                {/* Option 1: Overview / All Targets */}
                <button
                  type="button"
                  onClick={() => {
                    selectTarget(null, null);
                    setTargetMenuOpen(false);
                  }}
                  className={`w-full flex items-center justify-between px-2.5 py-2 rounded-lg text-xs font-mono transition-colors text-left ${
                    !activeTarget
                      ? 'bg-cyan-signal/15 text-cyan-signal font-bold border border-cyan-signal/40'
                      : 'hover:bg-void text-text-dim hover:text-text-primary'
                  }`}
                >
                  <div className="flex items-center gap-2">
                    <Globe className="w-3.5 h-3.5 text-cyan-signal" />
                    <span>All Targets (Workspace Overview)</span>
                  </div>
                  {!activeTarget && <Check className="w-3.5 h-3.5 text-cyan-signal" />}
                </button>

                {/* Scanned Target Items */}
                {filteredTargets.map((t) => {
                  const isSelected = activeTarget === t.domain;
                  const isRunning = t.status === 'running' || t.status === 'pending';
                  const isComplete = t.status === 'completed';
                  return (
                    <button
                      key={t.domain}
                      type="button"
                      onClick={() => {
                        selectTarget(t.domain, t.latestScanId);
                        setTargetMenuOpen(false);
                      }}
                      className={`w-full flex items-center justify-between px-2.5 py-2 rounded-lg text-xs font-mono transition-colors text-left group ${
                        isSelected
                          ? 'bg-cyan-signal/15 text-cyan-signal font-bold border border-cyan-signal/40 shadow-glow-cyan-sm'
                          : 'hover:bg-void text-text-primary hover:text-cyan-bright'
                      }`}
                    >
                      <div className="flex items-center gap-2 min-w-0 pr-2">
                        <span
                          className={`w-2 h-2 rounded-full shrink-0 ${
                            isRunning
                              ? 'bg-cyan-signal animate-pulse shadow-glow-cyan-sm'
                              : isComplete
                              ? 'bg-success-green shadow-glow-green-sm'
                              : 'bg-amber-signal'
                          }`}
                        />
                        <span className="truncate">{t.domain}</span>
                      </div>
                      <div className="flex items-center gap-1.5 shrink-0">
                        <span
                          className={`text-[9px] uppercase px-1.5 py-0.5 rounded font-bold ${
                            isRunning
                              ? 'bg-cyan-signal/15 text-cyan-signal border border-cyan-signal/30'
                              : isComplete
                              ? 'bg-success-green/15 text-success-green border border-success-green/30'
                              : 'bg-amber-signal/15 text-amber-signal border border-amber-signal/30'
                          }`}
                        >
                          {t.status}
                        </span>
                        {isSelected && <Check className="w-3.5 h-3.5 text-cyan-signal" />}
                      </div>
                    </button>
                  );
                })}

                {filteredTargets.length === 0 && (
                  <div className="py-4 text-center text-xs font-mono text-text-dim">
                    {scannedTargets.length === 0 ? 'No scanned targets in workspace' : 'No matching targets found'}
                  </div>
                )}
              </div>

              {/* Quick Action: Launch New Scan */}
              <div className="pt-2 mt-2 border-t border-border-dim">
                <button
                  type="button"
                  onClick={() => {
                    setTargetMenuOpen(false);
                    onOpenNewScan();
                  }}
                  className="w-full flex items-center justify-center gap-1.5 py-2 rounded-lg bg-void border border-dashed border-cyan-signal/40 hover:border-cyan-signal text-cyan-signal hover:bg-cyan-signal/10 text-xs font-mono font-bold transition-all"
                >
                  <Plus className="w-3.5 h-3.5" />
                  <span>Launch New Target Scan</span>
                </button>
              </div>
            </div>
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
        <div className="relative" ref={tenantMenuRef}>
          <button
            onClick={() => {
              setDropdownOpen(!dropdownOpen);
              setUserMenuOpen(false);
            }}
            className="flex items-center gap-2.5 px-3 py-1.5 rounded-md bg-void border border-border-dim hover:border-border-bright text-xs text-text-primary transition-colors"
          >
            <Building2 className="w-3.5 h-3.5 text-cyan-signal" />
            <span className="max-w-[140px] truncate font-medium">{currentTenant.name}</span>
            <ChevronDown className="w-3.5 h-3.5 text-text-dim" />
          </button>

          {dropdownOpen && (
            <div className="absolute right-0 mt-2 w-64 rounded-md bg-panel-elevated border border-border-bright shadow-panel z-50 p-1.5">
              <div className="px-2.5 py-1.5 text-[11px] font-mono text-text-dim uppercase tracking-wider border-b border-border-dim mb-1">
                Select Workspace / Tenant
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
                    onSelectTab('scopes');
                    setDropdownOpen(false);
                  }}
                  className="w-full text-left px-2.5 py-1.5 text-xs text-text-dim hover:text-cyan-signal transition-colors flex items-center gap-1.5"
                >
                  <Plus className="w-3.5 h-3.5" />
                  <span>Manage Scopes & Workspaces</span>
                </button>
              </div>
            </div>
          )}
        </div>

        {/* New Scan Action Button */}
        <button
          onClick={() => {
            setDropdownOpen(false);
            setUserMenuOpen(false);
            onOpenNewScan();
          }}
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
