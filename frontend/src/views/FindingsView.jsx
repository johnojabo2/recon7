import React, { useState, useMemo } from 'react';
import { useParams } from 'react-router-dom';
import {
  ShieldAlert,
  Search,
  Download,
  Copy,
  Check,
  ExternalLink,
  Eye,
  X,
  Globe,
  Server,
  Cpu,
  Users,
  AlertTriangle,
  Layers,
  FileCode,
  Terminal,
  ChevronRight,
  Mail,
  Linkedin,
  CheckCircle2,
  HelpCircle,
  ArrowRight,
} from 'lucide-react';
import { useScanFindings, useDashboard, useScansList } from '../api/hooks';
import { useTenant } from '../context/TenantContext';
import SeverityBadge from '../components/SeverityBadge';
import { LoadingState, EmptyState } from '../components/LoadingState';
import AiDisclaimer from '../components/AiDisclaimer';

export default function FindingsView({ scanId, onSelectTab }) {
  const { scanId: routeScanId } = useParams();
  const { activeTarget, activeScanId } = useTenant();
  const { data: scans = [] } = useScansList(100);
  const { data: dashboard } = useDashboard();

  const [selectedTab, setSelectedTab] = useState('all');
  const [selectedSeverity, setSelectedSeverity] = useState('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [inspectFinding, setInspectFinding] = useState(null);
  const [copySuccess, setCopySuccess] = useState('');

  const targetMatchedScan = activeTarget
    ? scans.find((s) => s.target_domain === activeTarget)
    : null;

  const recentJobId =
    routeScanId ||
    scanId ||
    activeScanId ||
    targetMatchedScan?.id ||
    dashboard?.recent_scans?.[0]?.id ||
    scans[0]?.id;

  const { data: rawFindings = [], isLoading } = useScanFindings(recentJobId);
  const baseFindings = Array.isArray(rawFindings) ? rawFindings : [];

  // Expand aggregate people and document findings into individual, queryable entries
  const findings = useMemo(() => {
    const list = [];
    baseFindings.forEach((f) => {
      if (f.type === 'people' && Array.isArray(f.data?.people) && f.data.people.length > 0) {
        // 1. Add an aggregate Email Pattern & Personnel Dossier finding
        list.push({
          id: f.id,
          severity: f.severity || 'info',
          type: 'people_pattern',
          source_tool: f.source_tool,
          created_at: f.created_at,
          data: {
            domain: f.data.domain,
            email_pattern: f.data.email_pattern,
            total_count: f.data.total_count || f.data.people.length,
            deliverable_count: f.data.deliverable_count || 0,
            confirmed_count: f.data.confirmed_count || 0,
            inferred_count: f.data.inferred_count || 0,
            people_list: f.data.people,
          },
        });

        // 2. Unroll each employee profile as an individual finding row
        f.data.people.forEach((p, idx) => {
          list.push({
            id: `${f.id}_person_${idx}`,
            severity: p.deliverability === 'deliverable' ? 'info' : 'info',
            type: 'people',
            source_tool: f.source_tool,
            created_at: f.created_at,
            data: {
              ...p,
              domain: f.data.domain,
              email_pattern: f.data.email_pattern,
            },
            is_person: true,
          });
        });
      } else {
        list.push(f);
      }
    });
    return list;
  }, [baseFindings]);

  // Group counts by category
  const counts = useMemo(() => {
    const map = {
      all: findings.length,
      vuln: 0,
      subdomain: 0,
      port: 0,
      fingerprint: 0,
      ip_resolution: 0,
      people: 0,
    };
    findings.forEach((f) => {
      if (f.type === 'people_pattern' || f.type === 'people') {
        map.people++;
      } else if (f.type in map) {
        map[f.type]++;
      }
    });
    return map;
  }, [findings]);

  // Filter findings
  const filteredFindings = useMemo(() => {
    return findings.filter((f) => {
      if (selectedTab !== 'all') {
        if (selectedTab === 'people') {
          if (f.type !== 'people' && f.type !== 'people_pattern') return false;
        } else if (f.type !== selectedTab) {
          return false;
        }
      }
      if (selectedSeverity !== 'all' && (f.severity || 'info').toLowerCase() !== selectedSeverity) {
        return false;
      }
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const raw = JSON.stringify(f.data).toLowerCase();
        const typeMatch = (f.type || '').toLowerCase().includes(q);
        const toolMatch = (f.source_tool || '').toLowerCase().includes(q);
        return raw.includes(q) || typeMatch || toolMatch;
      }
      return true;
    });
  }, [findings, selectedTab, selectedSeverity, searchQuery]);

  // 1-Click Copy Subdomain List
  const handleCopySubdomains = () => {
    const subdomains = new Set();
    findings.forEach((f) => {
      if (f.type === 'subdomain' && f.data?.subdomain) {
        subdomains.add(f.data.subdomain);
      } else if (f.type === 'ip_resolution' && f.data?.subdomain) {
        subdomains.add(f.data.subdomain);
      }
    });
    const text = Array.from(subdomains).sort().join('\n');
    navigator.clipboard.writeText(text);
    setCopySuccess('subdomains');
    setTimeout(() => setCopySuccess(''), 2500);
  };

  // 1-Click Copy Unique IPs
  const handleCopyIPs = () => {
    const ips = new Set();
    findings.forEach((f) => {
      if (f.type === 'port' && f.data?.ip) {
        ips.add(f.data.ip);
      } else if (f.type === 'ip_resolution' && Array.isArray(f.data?.ips)) {
        f.data.ips.forEach((ip) => {
          if (ip && !ip.includes(':')) ips.add(ip);
        });
      }
    });
    const text = Array.from(ips).sort().join('\n');
    navigator.clipboard.writeText(text);
    setCopySuccess('ips');
    setTimeout(() => setCopySuccess(''), 2500);
  };

  // 1-Click Copy Corporate Emails
  const handleCopyEmails = () => {
    const emails = new Set();
    findings.forEach((f) => {
      if (f.type === 'people' && f.data?.email) {
        emails.add(f.data.email.trim());
      }
    });
    const text = Array.from(emails).sort().join('\n');
    navigator.clipboard.writeText(text);
    setCopySuccess('emails');
    setTimeout(() => setCopySuccess(''), 2500);
  };

  // Export JSON
  const handleExportJSON = () => {
    const blob = new Blob([JSON.stringify(filteredFindings, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `recon7-findings-${recentJobId?.slice(0, 8) || 'export'}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  // Export CSV
  const handleExportCSV = () => {
    const headers = ['ID', 'Severity', 'Type', 'Source Tool', 'Details', 'Timestamp'];
    const rows = filteredFindings.map((f) => [
      f.id,
      f.severity,
      f.type,
      f.source_tool,
      JSON.stringify(f.data).replace(/"/g, '""'),
      f.created_at,
    ]);
    const csvContent = [headers.join(','), ...rows.map((r) => `"${r.join('","')}"`)].join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `recon7-findings-${recentJobId?.slice(0, 8) || 'export'}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  if (!recentJobId) {
    return (
      <EmptyState
        title="No Findings Telemetry"
        message="Launch a scan to populate and query findings across target infrastructure."
      />
    );
  }

  if (isLoading) return <LoadingState message="Loading tactical findings ledger..." />;

  return (
    <div className="space-y-6 max-w-7xl">
      {/* Top Banner & 1-Click Operational Tooling */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 p-5 rounded-lg panel-glass border border-border-dim shadow-panel">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="font-display font-bold text-xl text-text-primary">
              Tactical Findings & Target Ledger
            </h1>
            <span className="px-2.5 py-0.5 rounded text-xs font-mono font-bold bg-void border border-border-dim text-cyan-signal">
              {findings.length} Assets & Vectors
            </span>
          </div>
          <p className="text-xs text-text-dim mt-1">
            Search, inspect, and export clean target lists directly into Burp Suite, Nuclei, Nmap, or engagement reports.
          </p>
        </div>

        {/* 1-Click Tactical Export Bar */}
        <div className="flex flex-wrap items-center gap-2 font-mono text-xs self-start lg:self-center">
          <button
            onClick={handleCopySubdomains}
            className="px-3 py-1.5 rounded bg-void border border-border-dim hover:border-cyan-signal/50 text-text-dim hover:text-cyan-signal transition-all flex items-center gap-1.5 shadow-sm"
            title="Copies clean newline list of subdomains for Burp Suite or Nuclei"
          >
            {copySuccess === 'subdomains' ? (
              <>
                <Check className="w-3.5 h-3.5 text-success-green" />
                <span className="text-success-green font-bold">Subdomains Copied!</span>
              </>
            ) : (
              <>
                <Copy className="w-3.5 h-3.5" />
                <span>Copy Subdomains (.txt)</span>
              </>
            )}
          </button>

          <button
            onClick={handleCopyIPs}
            className="px-3 py-1.5 rounded bg-void border border-border-dim hover:border-cyan-signal/50 text-text-dim hover:text-cyan-signal transition-all flex items-center gap-1.5 shadow-sm"
            title="Copies clean newline list of target server IPs for Nmap"
          >
            {copySuccess === 'ips' ? (
              <>
                <Check className="w-3.5 h-3.5 text-success-green" />
                <span className="text-success-green font-bold">Host IPs Copied!</span>
              </>
            ) : (
              <>
                <Copy className="w-3.5 h-3.5" />
                <span>Copy IPs (.txt)</span>
              </>
            )}
          </button>

          <button
            onClick={handleCopyEmails}
            className="px-3 py-1.5 rounded bg-void border border-border-dim hover:border-cyan-signal/50 text-text-dim hover:text-cyan-signal transition-all flex items-center gap-1.5 shadow-sm"
            title="Copies clean newline list of corporate emails for OSINT & spearphishing audits"
          >
            {copySuccess === 'emails' ? (
              <>
                <Check className="w-3.5 h-3.5 text-success-green" />
                <span className="text-success-green font-bold">Emails Copied!</span>
              </>
            ) : (
              <>
                <Mail className="w-3.5 h-3.5" />
                <span>Copy Emails (.txt)</span>
              </>
            )}
          </button>

          <button
            onClick={handleExportCSV}
            className="px-3 py-1.5 rounded bg-void border border-border-dim hover:border-border-bright text-text-dim hover:text-text-primary transition-all flex items-center gap-1.5 shadow-sm"
          >
            <Download className="w-3.5 h-3.5" />
            <span>CSV</span>
          </button>

          <button
            onClick={handleExportJSON}
            className="px-3 py-1.5 rounded bg-void border border-border-dim hover:border-border-bright text-text-dim hover:text-text-primary transition-all flex items-center gap-1.5 shadow-sm"
          >
            <Download className="w-3.5 h-3.5" />
            <span>JSON</span>
          </button>
        </div>
      </div>

      {/* Automated Intelligence Advisory */}
      <AiDisclaimer className="mb-2" />

      {/* Category Tabs */}
      <div className="flex flex-wrap items-center gap-2 border-b border-border-dim/80 pb-2">
        {[
          { id: 'all', label: 'All Findings', count: counts.all, icon: Layers },
          { id: 'vuln', label: 'Vulnerabilities', count: counts.vuln, icon: AlertTriangle, highlight: counts.vuln > 0 },
          { id: 'subdomain', label: 'Subdomains', count: counts.subdomain, icon: Globe },
          { id: 'people', label: 'People OSINT', count: counts.people, icon: Users },
          { id: 'port', label: 'Open Ports', count: counts.port, icon: Server },
          { id: 'fingerprint', label: 'Technologies', count: counts.fingerprint, icon: Cpu },
          { id: 'ip_resolution', label: 'Resolutions', count: counts.ip_resolution, icon: Terminal },
        ].map((tab) => {
          const Icon = tab.icon;
          const isActive = selectedTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setSelectedTab(tab.id)}
              className={`flex items-center gap-2 px-3 py-2 rounded-md text-xs font-mono transition-all ${
                isActive
                  ? 'bg-void text-cyan-signal border border-cyan-signal/40 shadow-glow-cyan-sm font-bold'
                  : 'text-text-dim hover:text-text-primary hover:bg-void/60 border border-transparent'
              }`}
            >
              <Icon className={`w-3.5 h-3.5 ${isActive ? 'text-cyan-signal' : 'text-text-dim'}`} />
              <span>{tab.label}</span>
              <span
                className={`px-1.5 py-0.2 rounded text-[10px] ${
                  tab.highlight
                    ? 'bg-magenta-alert/20 text-magenta-alert font-bold'
                    : isActive
                    ? 'bg-cyan-signal/20 text-cyan-signal'
                    : 'bg-void border border-border-dim text-text-dim'
                }`}
              >
                {tab.count}
              </span>
            </button>
          );
        })}
      </div>

      {/* Search & Filter Controls */}
      <div className="p-3 rounded-lg panel-glass border border-border-dim flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-3 flex-1">
          <div className="relative flex-1 min-w-[240px] max-w-md">
            <Search className="w-3.5 h-3.5 text-text-dim absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Filter by name, email, hostname, IP, port, software, CVE..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-8 pr-3 py-1.5 rounded bg-void border border-border-dim text-xs text-text-primary font-mono focus:border-cyan-signal focus:outline-none transition-colors"
            />
          </div>

          <select
            value={selectedSeverity}
            onChange={(e) => setSelectedSeverity(e.target.value)}
            className="px-3 py-1.5 rounded bg-void border border-border-dim text-xs text-text-primary focus:border-cyan-signal focus:outline-none transition-colors font-mono"
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="info">Info</option>
          </select>
        </div>

        <div className="flex items-center gap-4 text-xs font-mono text-text-dim">
          {selectedTab === 'people' && onSelectTab && (
            <button
              onClick={() => onSelectTab('people')}
              className="flex items-center gap-1.5 text-cyan-signal hover:text-white transition-colors"
            >
              <span>Open Dedicated People OSINT View</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          )}
          <span>
            Showing <span className="text-text-primary font-bold">{filteredFindings.length}</span> of {findings.length}
          </span>
        </div>
      </div>

      {/* Human-Readable Findings Table */}
      <div className="panel-glass rounded-lg border border-border-dim shadow-panel overflow-hidden">
        {filteredFindings.length === 0 ? (
          <div className="py-16 text-center text-xs text-text-dim font-mono">
            No telemetry findings match the selected filters.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-border-dim bg-void/70 text-text-dim font-mono text-[11px]">
                  <th className="py-3 px-4 w-28">SEVERITY</th>
                  <th className="py-3 px-4 w-32">CATEGORY</th>
                  <th className="py-3 px-4">DISCOVERED ASSET / INTELLIGENCE</th>
                  <th className="py-3 px-4 w-40">SOURCE TOOL</th>
                  <th className="py-3 px-4 w-24 text-right">ACTION</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border-dim/60 font-mono">
                {filteredFindings.map((f) => (
                  <tr
                    key={f.id}
                    onClick={() => setInspectFinding(f)}
                    className="hover:bg-void/60 transition-colors cursor-pointer group"
                  >
                    {/* Severity Badge */}
                    <td className="py-3 px-4 align-top">
                      <SeverityBadge severity={f.severity} />
                    </td>

                    {/* Category Type */}
                    <td className="py-3 px-4 align-top">
                      <span className="px-2 py-0.5 rounded bg-void border border-border-dim text-[10px] font-bold uppercase text-text-dim">
                        {f.type === 'people_pattern' ? 'DOSSIER' : f.type}
                      </span>
                    </td>

                    {/* Human-Readable Data Display */}
                    <td className="py-3 px-4 align-top">
                      <FindingCellContent finding={f} onSelectTab={onSelectTab} />
                    </td>

                    {/* Source Tool & Timestamp */}
                    <td className="py-3 px-4 align-top">
                      <div className="text-text-primary text-xs">{f.source_tool}</div>
                      <div className="text-[10px] text-text-dim mt-0.5">
                        {f.created_at ? new Date(f.created_at).toLocaleTimeString() : 'N/A'}
                      </div>
                    </td>

                    {/* Action: Inspect Detail */}
                    <td className="py-3 px-4 align-top text-right">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          setInspectFinding(f);
                        }}
                        className="p-1.5 rounded bg-void border border-border-dim hover:border-cyan-signal/50 text-text-dim hover:text-cyan-signal transition-colors group-hover:border-cyan-signal/40"
                        title="Inspect finding details"
                      >
                        <ChevronRight className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Slide-Out Detail Inspector Drawer */}
      {inspectFinding && (
        <FindingInspectorDrawer
          finding={inspectFinding}
          onClose={() => setInspectFinding(null)}
          onSelectTab={onSelectTab}
        />
      )}
    </div>
  );
}

// ---------------------------------------------------------
// Subcomponent: Clean Human-Readable Finding Formatter
// ---------------------------------------------------------
function FindingCellContent({ finding, onSelectTab }) {
  const { type, data = {} } = finding;

  // 1. Corporate Identity Dossier & Email Pattern
  if (type === 'people_pattern') {
    const pattern = data.email_pattern || '{first}.{last}@{domain}';
    const total = data.total_count || 0;
    const deliverable = data.deliverable_count || 0;
    const inferred = data.inferred_count || 0;
    return (
      <div className="space-y-1.5">
        <div className="flex items-center gap-2">
          <span className="font-bold text-sm text-cyan-signal">
            Corporate Personnel Dossier ({total} Profiles)
          </span>
          <span className="px-2 py-0.5 rounded bg-cyan-signal/10 border border-cyan-signal/30 text-cyan-signal text-[10px] font-bold">
            Pattern: {pattern}
          </span>
        </div>
        <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
          <span className="px-2 py-0.5 rounded bg-success-green/15 text-success-green border border-success-green/30 text-[10px] font-bold">
            {deliverable} Deliverable Emails
          </span>
          <span className="px-2 py-0.5 rounded bg-yellow-500/15 text-yellow-400 border border-yellow-500/30 text-[10px]">
            {inferred} Inferred
          </span>
          {onSelectTab && (
            <button
              onClick={(e) => {
                e.stopPropagation();
                onSelectTab('people');
              }}
              className="text-[11px] text-cyan-signal hover:underline flex items-center gap-1 font-semibold"
            >
              <span>Explore full people roster</span>
              <ArrowRight className="w-3 h-3" />
            </button>
          )}
        </div>
      </div>
    );
  }

  // 2. Individual Person Row
  if (type === 'people') {
    const name = data.name || data.cleaned_name || 'Individual';
    const role = data.title || 'Staff / Key Personnel';
    const email = data.email || '';
    const platform = data.platform || 'LinkedIn';
    const deliverability = data.deliverability || 'unverified';
    const isDeliverable = deliverability === 'deliverable';
    const profileUrl = data.profile_url;

    return (
      <div className="space-y-1">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="font-bold text-sm text-text-primary">{name}</span>
          <span className="text-xs text-text-dim truncate max-w-sm">— {role}</span>
          {profileUrl && (
            <a
              href={profileUrl}
              target="_blank"
              rel="noopener noreferrer"
              onClick={(e) => e.stopPropagation()}
              className="text-text-dim hover:text-cyan-signal transition-colors inline-flex items-center gap-0.5 text-[10px]"
              title="Open profile"
            >
              {platform === 'LinkedIn' ? <Linkedin className="w-3 h-3 text-[#0A66C2]" /> : <Globe className="w-3 h-3" />}
              <ExternalLink className="w-2.5 h-2.5" />
            </a>
          )}
        </div>
        {email ? (
          <div className="flex items-center gap-2 text-xs">
            <span className="font-mono text-cyan-signal font-semibold">{email}</span>
            {isDeliverable ? (
              <span className="px-1.5 py-0.2 rounded bg-success-green/15 text-success-green border border-success-green/30 text-[9px] font-bold flex items-center gap-0.5">
                <CheckCircle2 className="w-2.5 h-2.5" />
                DELIVERABLE
              </span>
            ) : data.inferred ? (
              <span className="px-1.5 py-0.2 rounded bg-yellow-500/15 text-yellow-400 border border-yellow-500/30 text-[9px] flex items-center gap-0.5">
                <HelpCircle className="w-2.5 h-2.5" />
                INFERRED
              </span>
            ) : (
              <span className="px-1.5 py-0.2 rounded bg-void border border-border-dim text-text-dim text-[9px]">
                UNVERIFIED
              </span>
            )}
          </div>
        ) : (
          <div className="text-[10px] text-text-dim italic">No direct email mapped</div>
        )}
      </div>
    );
  }

  // 3. Subdomain Row
  if (type === 'subdomain') {
    const sub = data.subdomain || 'Unknown Subdomain';
    const sources = Array.isArray(data.sources) ? data.sources : [];
    return (
      <div className="space-y-1">
        <div className="flex items-center gap-2">
          <span className="font-bold text-sm text-cyan-signal">{sub}</span>
          <a
            href={`https://${sub}`}
            target="_blank"
            rel="noopener noreferrer"
            onClick={(e) => e.stopPropagation()}
            className="text-text-dim hover:text-cyan-signal transition-colors"
            title="Open in browser"
          >
            <ExternalLink className="w-3 h-3" />
          </a>
        </div>
        {sources.length > 0 && (
          <div className="flex flex-wrap items-center gap-1 text-[10px] text-text-dim">
            <span>Sources:</span>
            {sources.map((s, idx) => (
              <span key={idx} className="px-1.5 py-0.2 rounded bg-void border border-border-dim text-text-dim/90">
                {s}
              </span>
            ))}
          </div>
        )}
      </div>
    );
  }

  // 4. Open Port / Service Row
  if (type === 'port') {
    const ip = data.ip || 'Host';
    const port = data.port || 0;
    const proto = data.protocol || 'tcp';
    const svc = data.service || 'unknown';
    const prod = data.product || '';
    const ver = data.version ? ` v${data.version}` : '';
    return (
      <div className="space-y-1">
        <div className="flex items-center gap-2">
          <span className="font-bold text-text-primary text-xs">{ip}</span>
          <span className="px-2 py-0.5 rounded bg-cyan-signal/15 border border-cyan-signal/40 text-cyan-signal text-[11px] font-bold">
            {port} / {proto.toUpperCase()}
          </span>
          <span className="text-text-dim text-xs">({svc})</span>
        </div>
        {prod && (
          <div className="text-[11px] text-text-dim">
            Product: <span className="text-text-primary font-semibold">{prod}{ver}</span>
          </div>
        )}
      </div>
    );
  }

  // 5. Vulnerability / Exploit Row
  if (type === 'vuln') {
    const cve = data.cve_id || data.template_id || data.title || 'Security Vulnerability';
    const title = data.title || data.name || '';
    const ip = data.ip || data.host || '';
    const port = data.port ? `:${data.port}` : '';
    const findingStatus = data.finding_status || (data.evidence_tier === 'ACTIVE_EXPLOIT_PROOF' || data.status === 'confirmed' ? 'CONFIRMED' : 'POTENTIALLY_AFFECTED');
    const isNotVuln = findingStatus === 'NOT_VULNERABLE' || data.status === 'patched';
    const isConfirmed = findingStatus === 'CONFIRMED';
    const isLikely = findingStatus === 'LIKELY_VULNERABLE';
    const isCisaKev = data.cisa_kev;

    return (
      <div className="space-y-1">
        <div className="flex items-center gap-2 flex-wrap font-mono">
          <span className={`font-bold text-xs ${isNotVuln ? 'text-emerald-400' : 'text-magenta-alert'}`}>{cve}</span>
          {ip && (
            <span className="text-text-dim text-[11px]">
              on <span className="text-text-primary font-mono">{ip}{port}</span>
            </span>
          )}
          {isNotVuln && (
            <span className="px-1.5 py-0.2 rounded bg-emerald-500/15 text-emerald-400 border border-emerald-500/40 text-[9px] font-bold">
              NOT VULNERABLE (DISTRO BACKPORT)
            </span>
          )}
          {isConfirmed && (
            <span className="px-1.5 py-0.2 rounded bg-magenta-alert/20 text-magenta-alert border border-magenta-alert/40 text-[9px] font-bold">
              CONFIRMED (ACTIVE PROOF)
            </span>
          )}
          {isLikely && (
            <span className="px-1.5 py-0.2 rounded bg-yellow-500/20 text-yellow-400 border border-yellow-500/40 text-[9px] font-bold">
              LIKELY VULNERABLE
            </span>
          )}
          {!isNotVuln && !isConfirmed && !isLikely && (
            <span className="px-1.5 py-0.2 rounded bg-cyan-500/15 text-cyan-signal border border-cyan-500/30 text-[9px]">
              POTENTIALLY AFFECTED / ADVISORY
            </span>
          )}
          {isCisaKev && !isNotVuln && (
            <span className="px-1.5 py-0.2 rounded bg-magenta-alert text-white text-[9px] font-bold">
              CISA KEV
            </span>
          )}
        </div>
        {title && title !== cve && (
          <div className="text-xs text-text-primary font-medium">{title}</div>
        )}
        {data.evidence_proof && (
          <div className="text-[10px] text-text-dim/80 font-mono truncate max-w-xl">
            {data.evidence_proof}
          </div>
        )}
      </div>
    );
  }

  // 6. IP Resolution Row
  if (type === 'ip_resolution') {
    const sub = data.subdomain || 'Asset';
    const ips = Array.isArray(data.ips) ? data.ips.join(', ') : data.ip || 'No IP';
    const isCdn = data.is_cdn;
    const provider = data.cdn_provider || 'Cloudflare';
    return (
      <div className="space-y-1">
        <div className="flex items-center gap-2">
          <span className="text-text-primary font-bold">{sub}</span>
          <span className="text-text-dim">➔</span>
          <span className="text-cyan-signal font-semibold">{ips}</span>
        </div>
        {isCdn ? (
          <span className="px-1.5 py-0.2 rounded bg-yellow-500/15 border border-yellow-500/30 text-yellow-400 text-[10px]">
            CDN Edge ({provider})
          </span>
        ) : (
          <span className="px-1.5 py-0.2 rounded bg-success-green/15 border border-success-green/30 text-success-green text-[10px]">
            Direct Origin Server
          </span>
        )}
      </div>
    );
  }

  // 7. Tech Fingerprint Row
  if (type === 'fingerprint') {
    const url = data.url || data.host || 'Target URL';
    const techs = Array.isArray(data.technologies) ? data.technologies : [];
    return (
      <div className="space-y-1.5">
        <div className="text-xs text-text-primary font-bold truncate max-w-lg">{url}</div>
        {techs.length > 0 && (
          <div className="flex flex-wrap gap-1">
            {techs.map((t, idx) => {
              const name = t.name || t;
              const ver = t.version ? ` v${t.version}` : '';
              return (
                <span
                  key={idx}
                  className="px-2 py-0.5 rounded bg-void border border-border-dim text-[10px] text-cyan-signal font-semibold"
                >
                  {name}{ver}
                </span>
              );
            })}
          </div>
        )}
      </div>
    );
  }

  // Generic / Default View
  return (
    <div className="text-xs text-text-dim truncate max-w-xl">
      {JSON.stringify(data).slice(0, 120)}...
    </div>
  );
}

// ---------------------------------------------------------
// Subcomponent: Finding Inspector Drawer
// ---------------------------------------------------------
function FindingInspectorDrawer({ finding, onClose, onSelectTab }) {
  const [copied, setCopied] = useState(false);
  const { type, data = {} } = finding;

  const handleCopyJson = () => {
    navigator.clipboard.writeText(JSON.stringify(finding, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const isPerson = type === 'people' || finding.is_person;
  const isDossier = type === 'people_pattern';

  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/60 backdrop-blur-sm animate-fadeIn">
      <div
        className="w-full max-w-xl bg-panel border-l border-border-dim h-full overflow-y-auto p-6 space-y-6 shadow-2xl flex flex-col justify-between font-mono"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="space-y-6">
          {/* Header */}
          <div className="flex items-center justify-between border-b border-border-dim pb-4">
            <div className="flex items-center gap-2">
              <SeverityBadge severity={finding.severity} />
              <span className="px-2 py-0.5 rounded bg-void border border-border-dim text-xs font-bold uppercase text-text-primary">
                {isDossier ? 'PERSONNEL DOSSIER' : finding.type}
              </span>
            </div>
            <button
              onClick={onClose}
              className="p-1.5 rounded bg-void border border-border-dim text-text-dim hover:text-text-primary transition-colors"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          {/* Finding Core Meta */}
          <div className="grid grid-cols-2 gap-3 text-xs">
            <div className="p-3 rounded bg-void/50 border border-border-dim space-y-1">
              <span className="text-[10px] text-text-dim block uppercase">Finding ID</span>
              <span className="text-text-primary text-[11px] truncate block font-bold">{finding.id}</span>
            </div>
            <div className="p-3 rounded bg-void/50 border border-border-dim space-y-1">
              <span className="text-[10px] text-text-dim block uppercase">Source Tool</span>
              <span className="text-cyan-signal text-[11px] truncate block font-bold">{finding.source_tool}</span>
            </div>
            <div className="p-3 rounded bg-void/50 border border-border-dim space-y-1">
              <span className="text-[10px] text-text-dim block uppercase">Confidence Score</span>
              <span className="text-success-green text-[11px] block font-bold">
                {data.confidence ? `${Math.round(data.confidence)}%` : '100%'}
              </span>
            </div>
            <div className="p-3 rounded bg-void/50 border border-border-dim space-y-1">
              <span className="text-[10px] text-text-dim block uppercase">Observed At</span>
              <span className="text-text-dim text-[11px] block">
                {finding.created_at ? new Date(finding.created_at).toLocaleString() : 'N/A'}
              </span>
            </div>
          </div>

          {/* Case 1: Individual Person View */}
          {isPerson && (
            <div className="space-y-3">
              <div className="p-4 rounded-lg bg-void/60 border border-cyan-signal/30 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-sm text-text-primary">{data.name || data.cleaned_name}</span>
                  {data.platform && (
                    <span className="px-2 py-0.5 rounded bg-void border border-border-dim text-[10px] text-cyan-signal font-bold">
                      {data.platform}
                    </span>
                  )}
                </div>
                <div className="text-xs text-text-dim">{data.title || 'Staff / Key Personnel'}</div>
                {data.email && (
                  <div className="pt-2 border-t border-border-dim/60 flex items-center justify-between text-xs">
                    <span className="text-cyan-signal font-mono font-bold">{data.email}</span>
                    <span className="px-2 py-0.5 rounded bg-success-green/10 text-success-green border border-success-green/30 text-[10px] uppercase font-bold">
                      {data.deliverability || 'verified'}
                    </span>
                  </div>
                )}
                {data.profile_url && (
                  <a
                    href={data.profile_url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="pt-1 text-xs text-cyan-signal hover:underline flex items-center gap-1"
                  >
                    <span>View Public Profile</span>
                    <ExternalLink className="w-3 h-3" />
                  </a>
                )}
              </div>
            </div>
          )}

          {/* Case 2: Corporate Dossier / Pattern Summary View */}
          {isDossier && (
            <div className="space-y-3">
              <div className="p-4 rounded-lg bg-void/60 border border-border-dim space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-text-primary uppercase">Corporate Email Syntax</span>
                  <span className="px-2 py-0.5 rounded bg-cyan-signal/15 border border-cyan-signal/40 text-cyan-signal text-xs font-bold">
                    {data.email_pattern}
                  </span>
                </div>
                <div className="grid grid-cols-3 gap-2 text-center text-xs">
                  <div className="p-2 rounded bg-void border border-border-dim">
                    <span className="text-[10px] text-text-dim block">Total Staff</span>
                    <span className="text-text-primary font-bold text-sm">{data.total_count}</span>
                  </div>
                  <div className="p-2 rounded bg-void border border-border-dim">
                    <span className="text-[10px] text-text-dim block">Deliverable</span>
                    <span className="text-success-green font-bold text-sm">{data.deliverable_count}</span>
                  </div>
                  <div className="p-2 rounded bg-void border border-border-dim">
                    <span className="text-[10px] text-text-dim block">Inferred</span>
                    <span className="text-yellow-400 font-bold text-sm">{data.inferred_count}</span>
                  </div>
                </div>

                {onSelectTab && (
                  <button
                    onClick={() => {
                      onClose();
                      onSelectTab('people');
                    }}
                    className="w-full py-2 px-3 rounded bg-cyan-signal/10 hover:bg-cyan-signal/20 border border-cyan-signal/40 text-xs font-mono text-cyan-signal font-bold transition-all flex items-center justify-center gap-2"
                  >
                    <span>Open Dedicated People OSINT Workspace</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </button>
                )}
              </div>
            </div>
          )}

          {/* Structured Attributes Breakdown (Filtering out gigantic nested arrays) */}
          <div className="space-y-2">
            <span className="text-[11px] font-bold text-text-dim uppercase tracking-wider block">
              Structured Evidence & Attributes
            </span>
            <div className="rounded border border-border-dim bg-void/40 overflow-hidden divide-y divide-border-dim/60">
              {Object.entries(data).map(([key, val]) => {
                if (key === 'people' || key === 'people_list') return null; // Handled cleanly above!
                return (
                  <div key={key} className="p-2.5 flex flex-col sm:flex-row sm:items-start justify-between gap-2 text-xs">
                    <span className="text-text-dim font-bold uppercase text-[11px] min-w-[120px]">{key}:</span>
                    <span className="text-text-primary font-mono text-[11px] break-all flex-1 text-left sm:text-right">
                      {typeof val === 'object' ? JSON.stringify(val) : String(val)}
                    </span>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Clean JSON Payload */}
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-bold text-text-dim uppercase tracking-wider flex items-center gap-1.5">
                <FileCode className="w-3.5 h-3.5 text-cyan-signal" />
                <span>Raw Finding Payload (JSON)</span>
              </span>
              <button
                onClick={handleCopyJson}
                className="px-2 py-1 rounded bg-void border border-border-dim hover:border-cyan-signal/50 text-[10px] text-text-dim hover:text-cyan-signal transition-colors flex items-center gap-1"
              >
                {copied ? <Check className="w-3 h-3 text-success-green" /> : <Copy className="w-3 h-3" />}
                <span>{copied ? 'Copied' : 'Copy JSON'}</span>
              </button>
            </div>
            <pre className="p-3 rounded bg-panel-subtle border border-border-dim text-[11px] text-cyan-signal overflow-x-auto max-h-48 leading-relaxed shadow-sm font-mono">
              {JSON.stringify(
                isDossier ? { ...data, people_list: `[${data.total_count} personnel profiles]` } : data,
                null,
                2
              )}
            </pre>
          </div>
        </div>

        {/* Footer */}
        <div className="pt-4 border-t border-border-dim flex justify-between items-center">
          {onSelectTab && (
            <button
              onClick={() => {
                onClose();
                onSelectTab('people');
              }}
              className="text-xs text-cyan-signal hover:underline font-mono flex items-center gap-1"
            >
              <span>Switch to People OSINT Hub</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          )}
          <button
            onClick={onClose}
            className="px-4 py-2 rounded bg-void border border-border-dim hover:border-border-bright text-xs font-mono text-text-primary transition-colors ml-auto"
          >
            Close Inspector
          </button>
        </div>
      </div>
    </div>
  );
}
