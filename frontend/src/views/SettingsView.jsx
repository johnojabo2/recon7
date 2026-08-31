import React from 'react';
import {
  Settings,
  Cpu,
  Search,
  Terminal,
  ShieldCheck,
  CheckCircle2,
  AlertCircle,
  Database,
  Layers,
  Zap,
  Globe,
  Lock,
  ExternalLink,
} from 'lucide-react';
import { useSystemSettings } from '../api/hooks';
import { LoadingState } from '../components/LoadingState';

export default function SettingsView({ onSelectTab }) {
  const { data: settings, isLoading, isError } = useSystemSettings();

  if (isLoading) {
    return <LoadingState message="Fetching system telemetry and engine configuration..." />;
  }

  const ai = settings?.ai || {};
  const search = settings?.search || {};
  const tools = settings?.tools || {};

  return (
    <div className="space-y-8 max-w-6xl">
      {/* Top Banner */}
      <div className="p-6 rounded-lg panel-glass border border-border-dim shadow-panel flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-3">
            <div className="p-2 rounded bg-cyan-signal/10 border border-cyan-signal/30 text-cyan-signal">
              <Settings className="w-5 h-5" />
            </div>
            <div>
              <h1 className="font-display font-bold text-xl text-text-primary">
                System & Engine Settings
              </h1>
              <p className="text-xs text-text-dim mt-0.5">
                Active telemetry, AI intelligence layer, search providers, and scanner tooling parameters.
              </p>
            </div>
          </div>
        </div>
        <div className="flex items-center gap-2 self-start md:self-center shrink-0">
          <span className="px-3 py-1 rounded-full bg-success-green/10 text-success-green border border-success-green/30 text-xs font-mono font-bold flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-success-green shadow-glow-green animate-pulse" />
            <span>ENGINE ONLINE</span>
          </span>
          <span className="px-2.5 py-1 rounded bg-void border border-border-dim text-xs font-mono text-text-dim">
            {settings?.app_version || 'v1.0.0'}
          </span>
        </div>
      </div>

      {/* Section 1: AI Intelligence Layer */}
      <div className="space-y-4">
        <div className="flex items-center gap-2">
          <Cpu className="w-4 h-4 text-cyan-signal" />
          <h2 className="font-display font-bold text-base text-text-primary">
            AI Intelligence & LLM Gateway
          </h2>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {/* Active Model Card */}
          <div className="p-5 rounded-lg bg-void/50 border border-border-dim space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono font-bold text-text-primary flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-cyan-signal" />
                PRIMARY REASONING MODEL
              </span>
              <span className="px-2 py-0.5 rounded bg-cyan-signal/10 text-cyan-signal border border-cyan-signal/30 text-[10px] font-mono font-bold">
                LITELLM ACTIVE
              </span>
            </div>
            <div className="space-y-1">
              <div className="text-sm font-mono font-bold text-text-primary">
                {ai.model || 'claude-sonnet-4-5-20250929'}
              </div>
              <p className="text-xs text-text-dim">
                Automated triage synthesis, finding correlation, executive summary, and attack-vector prioritization.
              </p>
            </div>
            <div className="pt-2 border-t border-border-dim/60 flex items-center justify-between text-xs font-mono">
              <span className="text-text-dim">Engine Status:</span>
              <span className="text-success-green font-semibold">Ready / Enabled</span>
            </div>
          </div>

          {/* Provider Credentials Card */}
          <div className="p-5 rounded-lg bg-void/50 border border-border-dim space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono font-bold text-text-primary flex items-center gap-2">
                <Lock className="w-3.5 h-3.5 text-cyan-signal" />
                ANTHROPIC CLAUDE API KEY
              </span>
              {ai.anthropic_configured ? (
                <span className="px-2 py-0.5 rounded bg-success-green/10 text-success-green border border-success-green/30 text-[10px] font-mono font-bold flex items-center gap-1">
                  <CheckCircle2 className="w-3 h-3" />
                  CONFIGURED
                </span>
              ) : (
                <span className="px-2 py-0.5 rounded bg-yellow-500/10 text-yellow-400 border border-yellow-500/30 text-[10px] font-mono font-bold flex items-center gap-1">
                  <AlertCircle className="w-3 h-3" />
                  DEFAULT ENGINE
                </span>
              )}
            </div>
            <div className="space-y-1">
              <div className="text-xs font-mono text-text-dim">ACTIVE MASKED TOKEN:</div>
              <div className="p-2 rounded bg-void border border-border-dim text-xs font-mono text-cyan-signal">
                {ai.anthropic_key_masked || 'Using deterministic offline fallback engine'}
              </div>
            </div>
            <p className="text-[11px] text-text-dim">
              Loaded securely from environment configuration (<code className="text-text-primary">.env</code>).
            </p>
          </div>
        </div>
      </div>

      {/* Section 2: Search Providers & OSINT Harvesters */}
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Search className="w-4 h-4 text-cyan-signal" />
            <h2 className="font-display font-bold text-base text-text-primary">
              Search Providers & OSINT Pipeline
            </h2>
          </div>
          <span className="text-xs font-mono text-text-dim">
            Budget: <span className="text-cyan-signal font-bold">{search.query_budget_per_scan || 6} Queries</span> / Scan
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {/* SerpAPI Card */}
          <div className="p-4 rounded-lg bg-void/50 border border-border-dim space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono font-bold text-text-primary">SerpAPI (Tier 1)</span>
              {search.serpapi_configured ? (
                <span className="px-2 py-0.5 rounded bg-success-green/10 text-success-green border border-success-green/30 text-[10px] font-mono font-bold">
                  ACTIVE
                </span>
              ) : (
                <span className="px-2 py-0.5 rounded bg-void border border-border-dim text-text-dim text-[10px] font-mono">
                  STANDBY
                </span>
              )}
            </div>
            <p className="text-xs text-text-dim">
              Residential proxy rotation, zero CAPTCHAs, Google Knowledge Graph extraction.
            </p>
            <div className="text-xs font-mono text-cyan-signal">
              {search.serpapi_key_masked ? `Key: ${search.serpapi_key_masked}` : 'Not configured'}
            </div>
            <div className="text-[10px] font-mono text-text-dim">Priority: Primary Engine</div>
          </div>

          {/* Google CSE Card */}
          <div className="p-4 rounded-lg bg-void/50 border border-border-dim space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono font-bold text-text-primary">Google CSE (Tier 2)</span>
              {search.google_cse_configured ? (
                <span className="px-2 py-0.5 rounded bg-cyan-signal/10 text-cyan-signal border border-cyan-signal/30 text-[10px] font-mono font-bold">
                  CONFIGURED
                </span>
              ) : (
                <span className="px-2 py-0.5 rounded bg-void border border-border-dim text-text-dim text-[10px] font-mono">
                  STANDBY
                </span>
              )}
            </div>
            <p className="text-xs text-text-dim">
              Official Google Custom Search JSON API fallback if SerpAPI is inactive.
            </p>
            <div className="text-xs font-mono text-cyan-signal">
              {search.google_cse_key_masked ? `Key: ${search.google_cse_key_masked}` : 'Not configured'}
            </div>
            <div className="text-[10px] font-mono text-text-dim">Priority: Secondary Fallback</div>
          </div>

          {/* Persistent Cache Card */}
          <div className="p-4 rounded-lg bg-void/50 border border-border-dim space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono font-bold text-text-primary">Search Cache</span>
              <span className="px-2 py-0.5 rounded bg-success-green/10 text-success-green border border-success-green/30 text-[10px] font-mono font-bold">
                PERSISTENT
              </span>
            </div>
            <p className="text-xs text-text-dim">
              SQLite deterministic SHA-256 caching. Repeated queries consume 0 API credits.
            </p>
            <div className="text-xs font-mono text-success-green font-semibold">
              TTL: {search.search_cache_ttl_days || 7} Days
            </div>
            <div className="text-[10px] font-mono text-text-dim">Zero-Credit Protection Active</div>
          </div>
        </div>
      </div>

      {/* Section 3: Scanner Binaries & Subsystem Telemetry */}
      <div className="space-y-4">
        <div className="flex items-center gap-2">
          <Terminal className="w-4 h-4 text-cyan-signal" />
          <h2 className="font-display font-bold text-base text-text-primary">
            Scanner Tooling & Binary Telemetry
          </h2>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 font-mono text-xs">
          {Object.entries(tools).map(([tool, isAvailable]) => (
            <div
              key={tool}
              className="p-3 rounded-lg bg-void/40 border border-border-dim flex flex-col justify-between space-y-2"
            >
              <div className="flex items-center justify-between">
                <span className="font-bold uppercase text-text-primary">{tool}</span>
                <span
                  className={`w-2 h-2 rounded-full ${
                    isAvailable ? 'bg-success-green shadow-glow-green' : 'bg-yellow-500'
                  }`}
                />
              </div>
              <span className="text-[10px] text-text-dim">
                {isAvailable ? 'SYSTEM PATH' : 'PYTHON FALLBACK'}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* Section 4: Engine Architecture & Concurrency */}
      <div className="space-y-4">
        <div className="flex items-center gap-2">
          <Layers className="w-4 h-4 text-cyan-signal" />
          <h2 className="font-display font-bold text-base text-text-primary">
            Execution & Concurrency Parameters
          </h2>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 font-mono text-xs">
          <div className="p-4 rounded-lg bg-void/40 border border-border-dim space-y-1">
            <span className="text-[11px] text-text-dim block">DAG PIPELINE CONCURRENCY</span>
            <div className="text-text-primary font-bold">Enabled (Asyncio + Threads)</div>
            <span className="text-[10px] text-text-dim block mt-1">
              Simultaneous OSINT, DNS & Subdomain execution
            </span>
          </div>

          <div className="p-4 rounded-lg bg-void/40 border border-border-dim space-y-1">
            <span className="text-[11px] text-text-dim block">MULTI-HOST PORT SCANNER</span>
            <div className="text-cyan-signal font-bold">6 Concurrent Host Workers</div>
            <span className="text-[10px] text-text-dim block mt-1">
              Capacity: Up to 35 prioritized target hosts
            </span>
          </div>

          <div className="p-4 rounded-lg bg-void/40 border border-border-dim space-y-1">
            <span className="text-[11px] text-text-dim block">STORAGE & LEDGER ENGINE</span>
            <div className="text-text-primary font-bold">SQLite WAL (Zero-Dependency)</div>
            <span className="text-[10px] text-text-dim block mt-1">
              Local filesystem database ({settings?.database_url || 'recon7.db'})
            </span>
          </div>
        </div>
      </div>

      {/* Section 5: Scope Governance Link */}
      <div className="p-5 rounded-lg bg-void/30 border border-border-dim flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="space-y-1">
          <div className="flex items-center gap-2 text-sm font-bold text-text-primary">
            <ShieldCheck className="w-4 h-4 text-cyan-signal" />
            <span>Target Scopes & Multi-Tenant Registry</span>
          </div>
          <p className="text-xs text-text-dim">
            Manage authorized engagement domains, authorization letters, and organization tenants.
          </p>
        </div>
        {onSelectTab && (
          <button
            onClick={() => onSelectTab('scopes')}
            className="px-4 py-2 rounded bg-void border border-border-dim hover:border-cyan-signal/50 text-xs font-mono text-cyan-signal hover:text-white transition-colors self-start sm:self-center flex items-center gap-1.5"
          >
            <span>Manage Target Scopes</span>
            <ExternalLink className="w-3.5 h-3.5" />
          </button>
        )}
      </div>
    </div>
  );
}
