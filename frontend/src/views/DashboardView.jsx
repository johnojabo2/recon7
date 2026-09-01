import React, { useState, useMemo } from 'react';
import {
  Activity,
  ShieldAlert,
  Globe,
  Users,
  ArrowUpRight,
  Plus,
  Server,
  FileText,
  Clock,
  Search,
  X,
  ChevronRight,
  ExternalLink,
  Layers,
  Terminal,
  Ban,
} from 'lucide-react';
import { useDashboard, useScansList, useAbortScan } from '../api/hooks';
import SeverityBadge from '../components/SeverityBadge';
import TechnicalData from '../components/TechnicalData';
import { LoadingState, EmptyState } from '../components/LoadingState';
import AiDisclaimer from '../components/AiDisclaimer';
import { formatScanDuration } from './ScanDetailView';

export default function DashboardView({ onOpenNewScan, onSelectScan, onSelectTab }) {
  const [showAllScansModal, setShowAllScansModal] = useState(false);
  const { data: dashboard, isLoading, error } = useDashboard();
  const abortScanMutation = useAbortScan();

  if (isLoading) return <LoadingState message="Loading tenant telemetry..." />;
  if (error) {
    return (
      <EmptyState
        title="Backend Disconnected"
        message={error.message || 'Make sure FastAPI backend is running on http://localhost:8000'}
      />
    );
  }

  const scans = dashboard?.scans || { total: 0, completed: 0, running: 0 };
  const sev = dashboard?.severity_distribution || { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const types = dashboard?.type_distribution || {};
  const recentScans = dashboard?.recent_scans || [];

  return (
    <div className="space-y-6">
      {/* Top Banner & Quick Action */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-6 rounded-lg panel-glass border border-border-dim shadow-panel">
        <div>
          <h1 className="font-display font-bold text-xl text-text-primary">
            Attack Surface Overview
          </h1>
          <p className="text-xs text-text-dim mt-1">
            Real-time multi-tenant intelligence and reconnaissance findings telemetry.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={() => setShowAllScansModal(true)}
            className="flex items-center gap-1.5 px-4 py-2.5 rounded-md bg-void border border-border-dim hover:border-cyan-signal/50 text-text-dim hover:text-cyan-signal font-mono text-xs tracking-wide transition-all shadow-sm"
          >
            <Activity className="w-4 h-4" />
            <span>ALL SCANS ({scans.total})</span>
          </button>
          <button
            onClick={onOpenNewScan}
            className="flex items-center gap-2 px-5 py-2.5 rounded-md bg-cyan-signal text-black font-semibold text-xs tracking-wide shadow-glow-cyan-sm hover:brightness-110 active:scale-[0.98] transition-all shrink-0"
          >
            <Plus className="w-4 h-4" />
            <span>START RECON SCAN</span>
          </button>
        </div>
      </div>

      {/* Automated Intelligence Advisory */}
      <AiDisclaimer compact className="px-1" />

      {/* Metrics Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Total Scans Card (Interactive) */}
        <div
          onClick={() => setShowAllScansModal(true)}
          className="p-4 rounded-lg panel-glass border border-border-dim hover:border-cyan-signal/60 cursor-pointer transition-all group relative overflow-hidden"
          title="Click to view all performed scans"
        >
          <div className="flex items-center justify-between text-text-dim mb-2">
            <span className="text-xs font-mono uppercase tracking-wider group-hover:text-cyan-signal transition-colors">
              TOTAL SCANS
            </span>
            <ArrowUpRight className="w-4 h-4 text-text-dim group-hover:text-cyan-signal group-hover:translate-x-0.5 group-hover:-translate-y-0.5 transition-transform" />
          </div>
          <div className="text-2xl font-display font-bold text-text-primary group-hover:text-cyan-signal transition-colors">
            {scans.total}
          </div>
          <div className="flex items-center justify-between text-[11px] text-text-dim mt-2 font-mono">
            <div className="flex items-center gap-1.5">
              <span className="text-success-green">{scans.completed} completed</span>
              <span>•</span>
              <span className="text-cyan-signal">{scans.running} active</span>
            </div>
            <span className="text-cyan-signal font-semibold group-hover:underline">View All ➔</span>
          </div>
        </div>

        {/* Total Findings Card */}
        <div
          onClick={() => onSelectTab('findings')}
          className="p-4 rounded-lg panel-glass border border-border-dim hover:border-magenta-alert/50 cursor-pointer transition-all group"
          title="Click to explore all findings"
        >
          <div className="flex items-center justify-between text-text-dim mb-2">
            <span className="text-xs font-mono uppercase tracking-wider group-hover:text-magenta-alert transition-colors">
              DISCOVERED FINDINGS
            </span>
            <ShieldAlert className="w-4 h-4 text-magenta-alert" />
          </div>
          <div className="text-2xl font-display font-bold text-text-primary group-hover:text-magenta-alert transition-colors">
            {dashboard?.findings_count || 0}
          </div>
          <div className="flex items-center gap-2 text-[11px] text-text-dim mt-2 font-mono">
            <span className="text-magenta-alert font-semibold">{sev.critical} Critical</span>
            <span>•</span>
            <span className="text-orange-400">{sev.high} High</span>
          </div>
        </div>

        {/* Subdomains / Assets Card */}
        <div
          onClick={() => onSelectTab('findings')}
          className="p-4 rounded-lg panel-glass border border-border-dim hover:border-cyan-signal/50 cursor-pointer transition-all group"
        >
          <div className="flex items-center justify-between text-text-dim mb-2">
            <span className="text-xs font-mono uppercase tracking-wider group-hover:text-cyan-signal transition-colors">
              SUBDOMAINS & HOSTS
            </span>
            <Globe className="w-4 h-4 text-cyan-signal" />
          </div>
          <div className="text-2xl font-display font-bold text-text-primary group-hover:text-cyan-signal transition-colors">
            {(types.subdomain || 0) + (types.ip_resolution || 0)}
          </div>
          <div className="text-[11px] text-text-dim mt-2 font-mono">
            {types.ip_resolution || 0} resolved origin hosts
          </div>
        </div>

        {/* People OSINT Card */}
        <div
          onClick={() => onSelectTab('people')}
          className="p-4 rounded-lg panel-glass border border-border-dim hover:border-cyan-signal/50 cursor-pointer transition-all group"
        >
          <div className="flex items-center justify-between text-text-dim mb-2">
            <span className="text-xs font-mono uppercase tracking-wider group-hover:text-cyan-signal transition-colors">
              PEOPLE & EMAILS
            </span>
            <Users className="w-4 h-4 text-cyan-signal" />
          </div>
          <div className="text-2xl font-display font-bold text-text-primary group-hover:text-cyan-signal transition-colors">
            {types.people || 0}
          </div>
          <div className="text-[11px] text-text-dim mt-2 font-mono">Corporate email intelligence</div>
        </div>
      </div>

      {/* Two Column Layout: Severity Matrix & Recent Scans */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Severity Breakdown Bar */}
        <div className="p-5 rounded-lg panel-glass border border-border-dim space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="font-display font-bold text-sm text-text-primary">Severity Breakdown</h2>
            <span className="text-[11px] font-mono text-text-dim">Risk Profile</span>
          </div>

          <div className="space-y-2.5">
            {[
              { label: 'Critical', count: sev.critical, color: 'bg-magenta-alert', text: 'text-magenta-alert' },
              { label: 'High', count: sev.high, color: 'bg-orange-500', text: 'text-orange-400' },
              { label: 'Medium', count: sev.medium, color: 'bg-yellow-500', text: 'text-yellow-400' },
              { label: 'Low', count: sev.low, color: 'bg-cyan-signal', text: 'text-cyan-signal' },
              { label: 'Info', count: sev.info, color: 'bg-text-dim', text: 'text-text-dim' },
            ].map((item) => (
              <div key={item.label} className="flex items-center justify-between text-xs font-mono">
                <span className="text-text-dim flex items-center gap-2">
                  <span className={`w-2 h-2 rounded-full ${item.color}`} />
                  {item.label}
                </span>
                <span className={`font-semibold ${item.text}`}>{item.count}</span>
              </div>
            ))}
          </div>

          <div className="pt-2 border-t border-border-dim">
            <button
              onClick={() => onSelectTab('findings')}
              className="w-full text-center text-xs font-medium text-cyan-signal hover:underline flex items-center justify-center gap-1"
            >
              <span>Explore all findings</span>
              <ArrowUpRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>

        {/* Recent Scans List */}
        <div className="lg:col-span-2 p-5 rounded-lg panel-glass border border-border-dim space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="font-display font-bold text-sm text-text-primary">Recent Operations</h2>
              <span className="text-[11px] font-mono text-text-dim">Target History</span>
            </div>
            <button
              onClick={() => setShowAllScansModal(true)}
              className="flex items-center gap-1 text-xs font-mono text-cyan-signal hover:text-white bg-void px-3 py-1.5 rounded border border-border-dim hover:border-cyan-signal/50 transition-colors"
            >
              <span>View All Scans ({scans.total})</span>
              <ArrowUpRight className="w-3.5 h-3.5" />
            </button>
          </div>

          {recentScans.length === 0 ? (
            <div className="py-8 text-center text-xs text-text-dim">
              No scans launched yet. Click "Start Recon Scan" to begin.
            </div>
          ) : (
            <div className="divide-y divide-border-dim">
              {recentScans.map((scan) => (
                <div
                  key={scan.id}
                  onClick={() => onSelectScan(scan.id, scan.target_domain)}
                  className="py-3 flex items-center justify-between hover:bg-void/50 px-2 rounded cursor-pointer transition-colors group"
                >
                  <div className="flex items-center gap-3">
                    <div className="w-8 h-8 rounded bg-void border border-border-dim flex items-center justify-center group-hover:border-cyan-signal/60 transition-colors">
                      <Server className="w-4 h-4 text-cyan-signal" />
                    </div>
                    <div>
                      <div className="font-mono text-xs font-semibold text-text-primary group-hover:text-cyan-signal transition-colors">
                        {scan.target_domain}
                      </div>
                      <div className="text-[10px] text-text-dim flex items-center gap-2 mt-0.5 font-mono">
                        <Clock className="w-3 h-3 text-cyan-signal/70" />
                        <span>{scan.created_at ? new Date(scan.created_at).toLocaleTimeString() : 'N/A'}</span>
                        <span>•</span>
                        <span>{scan.current_step}</span>
                        {scan.status === 'complete' && scan.completed_at && scan.created_at && (
                          <>
                            <span>•</span>
                            <span className="text-success-green font-semibold">
                              {formatScanDuration(scan.created_at, scan.completed_at)}
                            </span>
                          </>
                        )}
                        {scan.status === 'running' && scan.created_at && (
                          <>
                            <span>•</span>
                            <span className="text-cyan-signal font-semibold animate-pulse">
                              {formatScanDuration(scan.created_at, null)}
                            </span>
                          </>
                        )}
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center gap-3">
                    <span
                      className={`text-[10px] font-mono font-semibold px-2 py-0.5 rounded border uppercase ${
                        scan.status === 'complete'
                          ? 'bg-success-green/10 text-success-green border-success-green/30'
                          : scan.status === 'running'
                          ? 'bg-cyan-signal/10 text-cyan-signal border-cyan-signal/40 animate-pulse'
                          : scan.status === 'cancelled'
                          ? 'bg-amber-500/10 text-amber-500 border-amber-500/30'
                          : 'bg-void text-text-dim border-border-dim'
                      }`}
                    >
                      {scan.status}
                    </span>

                    {(scan.status === 'running' || scan.status === 'pending') && (
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          if (window.confirm(`Abort scan for ${scan.target_domain}?`)) {
                            abortScanMutation.mutate(scan.id);
                          }
                        }}
                        disabled={abortScanMutation.isPending}
                        className="px-2 py-0.5 rounded bg-magenta-alert/15 hover:bg-magenta-alert/25 text-magenta-alert border border-magenta-alert/40 text-[10px] font-mono font-semibold transition-all hover:scale-105"
                        title="Abort active scan"
                      >
                        Abort
                      </button>
                    )}

                    <ArrowUpRight className="w-4 h-4 text-text-dim group-hover:text-cyan-signal transition-colors" />
                  </div>
                </div>
              ))}
            </div>
          )}

          {recentScans.length > 0 && (
            <div className="pt-3 border-t border-border-dim">
              <button
                onClick={() => setShowAllScansModal(true)}
                className="w-full py-2.5 rounded bg-void/60 hover:bg-void border border-border-dim hover:border-cyan-signal/40 text-xs font-mono text-cyan-signal flex items-center justify-center gap-2 transition-all group"
              >
                <span>Browse Full Scans History & Target Archive ({scans.total} Scans)</span>
                <ArrowUpRight className="w-3.5 h-3.5 group-hover:translate-x-0.5 group-hover:-translate-y-0.5 transition-transform" />
              </button>
            </div>
          )}
        </div>
      </div>

      {/* All Scans History & Archive Modal */}
      {showAllScansModal && (
        <AllScansModal
          onClose={() => setShowAllScansModal(false)}
          onSelectScan={(id, domain) => {
            setShowAllScansModal(false);
            onSelectScan(id, domain);
          }}
        />
      )}
    </div>
  );
}

// ---------------------------------------------------------
// Subcomponent: All Scans History & Operations Ledger Modal
// ---------------------------------------------------------
function AllScansModal({ onClose, onSelectScan }) {
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState('ALL');
  const { data: allScans = [], isLoading } = useScansList(150);

  const filteredScans = useMemo(() => {
    return allScans.filter((s) => {
      if (statusFilter !== 'ALL' && s.status !== statusFilter) return false;
      if (search.trim()) {
        const q = search.toLowerCase();
        const domainMatch = (s.target_domain || '').toLowerCase().includes(q);
        const idMatch = (s.id || '').toLowerCase().includes(q);
        const profileMatch = (s.scan_profile || '').toLowerCase().includes(q);
        return domainMatch || idMatch || profileMatch;
      }
      return true;
    });
  }, [allScans, statusFilter, search]);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4 animate-fadeIn">
      <div
        className="w-full max-w-4xl bg-panel border border-border-dim rounded-lg shadow-2xl overflow-hidden flex flex-col max-h-[85vh] font-mono"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Modal Header */}
        <div className="p-5 border-b border-border-dim bg-void/60 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded bg-cyan-signal/10 border border-cyan-signal/30 text-cyan-signal">
              <Activity className="w-5 h-5" />
            </div>
            <div>
              <h2 className="font-display font-bold text-base text-text-primary">
                Reconnaissance Operations & Target History
              </h2>
              <p className="text-xs text-text-dim mt-0.5">
                Audit, search, and jump to any reconnaissance scan performed in this workspace.
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded bg-void border border-border-dim text-text-dim hover:text-text-primary transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Filter Bar */}
        <div className="p-4 border-b border-border-dim bg-void/30 flex flex-wrap items-center justify-between gap-3 text-xs">
          <div className="flex items-center gap-3 flex-1 min-w-[240px] max-w-md">
            <div className="relative w-full">
              <Search className="w-3.5 h-3.5 text-text-dim absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                placeholder="Filter by domain name or scan ID..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="w-full pl-8 pr-3 py-1.5 rounded bg-void border border-border-dim text-xs text-text-primary focus:border-cyan-signal focus:outline-none transition-colors"
              />
            </div>
          </div>

          <div className="flex items-center gap-2">
            {['ALL', 'complete', 'running', 'failed'].map((st) => (
              <button
                key={st}
                onClick={() => setStatusFilter(st)}
                className={`px-3 py-1 rounded text-[11px] font-bold uppercase transition-all ${
                  statusFilter === st
                    ? 'bg-cyan-signal text-black shadow-glow-cyan-sm'
                    : 'bg-void border border-border-dim text-text-dim hover:text-text-primary'
                }`}
              >
                {st}
              </button>
            ))}
          </div>
        </div>

        {/* Scans Table List */}
        <div className="flex-1 overflow-y-auto p-4">
          {isLoading ? (
            <div className="py-16 text-center text-xs text-text-dim">
              Loading scan operations archive...
            </div>
          ) : filteredScans.length === 0 ? (
            <div className="py-16 text-center text-xs text-text-dim">
              No scans matched your search filter.
            </div>
          ) : (
            <div className="divide-y divide-border-dim/60 border border-border-dim rounded bg-void/20 overflow-hidden">
              {filteredScans.map((scan) => (
                <div
                  key={scan.id}
                  onClick={() => onSelectScan(scan.id, scan.target_domain)}
                  className="p-3.5 flex flex-col sm:flex-row sm:items-center justify-between gap-3 hover:bg-void/60 transition-colors cursor-pointer group"
                >
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="font-bold text-sm text-cyan-signal group-hover:underline">
                        {scan.target_domain}
                      </span>
                      <span className="px-2 py-0.5 rounded bg-void border border-border-dim text-[10px] text-text-dim uppercase font-bold">
                        {scan.scan_profile || 'standard'}
                      </span>
                    </div>
                    <div className="flex items-center gap-2 text-[11px] text-text-dim">
                      <span>Phase: <span className="text-text-primary font-medium">{scan.current_step}</span></span>
                      <span>•</span>
                      <span>
                        {scan.created_at ? new Date(scan.created_at).toLocaleString() : 'N/A'}
                      </span>
                      {scan.status === 'complete' && scan.completed_at && (
                        <>
                          <span>•</span>
                          <span className="text-success-green">
                            {formatScanDuration(scan.created_at, scan.completed_at)}
                          </span>
                        </>
                      )}
                    </div>
                  </div>

                  <div className="flex items-center gap-3 self-end sm:self-center">
                    <span
                      className={`text-[10px] font-bold px-2.5 py-1 rounded border uppercase ${
                        scan.status === 'complete'
                          ? 'bg-success-green/10 text-success-green border-success-green/30'
                          : scan.status === 'running'
                          ? 'bg-cyan-signal/10 text-cyan-signal border-cyan-signal/40 animate-pulse'
                          : scan.status === 'cancelled'
                          ? 'bg-amber-500/10 text-amber-500 border-amber-500/30'
                          : 'bg-void text-text-dim border-border-dim'
                      }`}
                    >
                      {scan.status}
                    </span>

                    {(scan.status === 'running' || scan.status === 'pending') && (
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          if (window.confirm(`Abort scan for ${scan.target_domain}?`)) {
                            abortScanMutation.mutate(scan.id);
                          }
                        }}
                        disabled={abortScanMutation.isPending}
                        className="px-2.5 py-1 rounded bg-magenta-alert/15 hover:bg-magenta-alert/25 text-magenta-alert border border-magenta-alert/40 text-xs font-mono font-semibold transition-all hover:scale-105"
                        title="Abort active scan"
                      >
                        Abort
                      </button>
                    )}

                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        onSelectScan(scan.id, scan.target_domain);
                      }}
                      className="px-3 py-1.5 rounded bg-void border border-border-dim group-hover:border-cyan-signal/50 text-xs text-cyan-signal flex items-center gap-1 transition-all"
                    >
                      <span>Open Investigation</span>
                      <ChevronRight className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-border-dim bg-void/60 flex items-center justify-between text-xs text-text-dim">
          <span>
            Total Archive Records: <span className="text-text-primary font-bold">{filteredScans.length}</span>
          </span>
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded bg-void border border-border-dim hover:border-border-bright text-text-primary transition-colors"
          >
            Close Archive
          </button>
        </div>
      </div>
    </div>
  );
}
