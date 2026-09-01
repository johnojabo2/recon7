import React, { useState } from 'react';
import { useParams } from 'react-router-dom';
import { Users, Search, Mail, CheckCircle2, HelpCircle, ExternalLink, Globe, Github, Linkedin, Twitter, Filter, ShieldCheck, AlertCircle } from 'lucide-react';
import { useScanFindings, useDashboard, useScansList } from '../api/hooks';
import { useTenant } from '../context/TenantContext';
import TechnicalData from '../components/TechnicalData';
import { LoadingState, EmptyState } from '../components/LoadingState';

export default function PeopleView({ scanId }) {
  const { scanId: routeScanId } = useParams();
  const { activeTarget, activeScanId } = useTenant();
  const { data: scans = [] } = useScansList(100);
  const { data: dashboard } = useDashboard();

  const [search, setSearch] = useState('');
  const [platformFilter, setPlatformFilter] = useState('ALL');
  const [deliverabilityFilter, setDeliverabilityFilter] = useState('ALL');

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

  const { data: findings = [], isLoading } = useScanFindings(recentJobId, 'people');

  if (!recentJobId) {
    return (
      <EmptyState
        title="No People OSINT Data"
        message="Launch a scan to discover exposed employee profiles, verified corporate emails, and public social profile links."
      />
    );
  }

  if (isLoading) return <LoadingState message="Harvesting, correlating, and verifying email deliverability..." />;

  const peopleData = findings[0]?.data || {
    email_pattern: 'Unknown',
    confirmed_count: 0,
    inferred_count: 0,
    deliverable_count: 0,
    total_count: 0,
    people: [],
  };

  const peopleList = peopleData.people || [];

  const platforms = ['ALL', ...Array.from(new Set(peopleList.map(p => p.platform || 'OSINT')))];

  const filteredPeople = peopleList.filter((p) => {
    const matchesSearch = !search.trim() ||
      (p.name || '').toLowerCase().includes(search.toLowerCase()) ||
      (p.email || '').toLowerCase().includes(search.toLowerCase()) ||
      (p.title || '').toLowerCase().includes(search.toLowerCase()) ||
      (p.platform || '').toLowerCase().includes(search.toLowerCase()) ||
      (p.verification_status || '').toLowerCase().includes(search.toLowerCase());

    const matchesPlatform = platformFilter === 'ALL' || (p.platform || 'OSINT') === platformFilter;

    let matchesDeliverability = true;
    if (deliverabilityFilter === 'VERIFIED') {
      matchesDeliverability = p.deliverability === 'deliverable' || (p.confidence >= 90 && p.email);
    } else if (deliverabilityFilter === 'INFERRED') {
      matchesDeliverability = Boolean(p.email) && p.inferred;
    } else if (deliverabilityFilter === 'PROFILE_ONLY') {
      matchesDeliverability = !p.email;
    }

    return matchesSearch && matchesPlatform && matchesDeliverability;
  });

  const getPlatformIcon = (platform, url) => {
    const p = (platform || '').toLowerCase();
    const u = (url || '').toLowerCase();
    if (p.includes('linkedin') || u.includes('linkedin')) return <Linkedin className="w-3.5 h-3.5 text-[#0A66C2]" />;
    if (p.includes('github') || u.includes('github')) return <Github className="w-3.5 h-3.5 text-text-primary" />;
    if (p.includes('twitter') || p.includes('x') || u.includes('twitter') || u.includes('x.com')) return <Twitter className="w-3.5 h-3.5 text-[#1DA1F2]" />;
    return <Globe className="w-3.5 h-3.5 text-cyan-signal" />;
  };

  const getVerificationBadge = (p) => {
    const status = p.verification_status || (p.email ? (p.inferred ? 'Pattern Inferred' : 'Direct Scrape') : 'Profile Only');
    const conf = p.confidence || 75;

    if (p.deliverability === 'deliverable' || conf >= 98) {
      return (
        <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-success-green/10 text-success-green border border-success-green/40 text-[10px] font-bold shadow-glow-green-sm">
          <ShieldCheck className="w-3 h-3" />
          <span>SMTP Deliverable (99%)</span>
        </span>
      );
    }

    if (status.includes('Direct Scrape') || (!p.inferred && p.email)) {
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-cyan-signal/10 text-cyan-signal border border-cyan-signal/30 text-[10px] font-semibold">
          <CheckCircle2 className="w-3 h-3" />
          <span>Direct Scrape ({conf}%)</span>
        </span>
      );
    }

    if (p.deliverability === 'catch_all' || status.includes('Catch-All')) {
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-yellow-500/10 text-yellow-400 border border-yellow-500/30 text-[10px] font-medium">
          <AlertCircle className="w-3 h-3" />
          <span>Catch-All Pattern ({conf}%)</span>
        </span>
      );
    }

    if (p.email) {
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-panel text-text-dim border border-border-dim text-[10px]">
          <HelpCircle className="w-3 h-3" />
          <span>Inferred ({conf}%)</span>
        </span>
      );
    }

    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-void text-text-dim border border-border-dim text-[10px]">
        <span>Public Handle</span>
      </span>
    );
  };

  const socialLinksCount = peopleList.filter(p => p.profile_url).length;

  return (
    <div className="space-y-6">
      {/* Header Metrics */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 p-5 rounded-lg panel-glass border border-border-dim shadow-panel">
        <div>
          <h1 className="font-display font-bold text-xl text-text-primary">
            People & Organizational OSINT (Verified)
          </h1>
          <p className="text-xs text-text-dim mt-1">
            Aggregated employee profiles, LinkedIn rosters, GitHub maintainers, and SMTP deliverability verified emails.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <div className="px-3 py-1.5 rounded bg-void border border-border-dim text-xs font-mono">
            <span className="text-text-dim">TOTAL PROFILES: </span>
            <span className="text-text-primary font-bold">{peopleData.total_count || peopleList.length}</span>
          </div>
          <div className="px-3 py-1.5 rounded bg-void border border-success-green/30 text-xs font-mono shadow-glow-green-sm">
            <span className="text-text-dim">HIGH CONFIDENCE: </span>
            <span className="text-success-green font-bold">{peopleData.deliverable_count || peopleData.confirmed_count}</span>
          </div>
          <div className="px-3 py-1.5 rounded bg-void border border-cyan-signal/30 text-xs font-mono">
            <span className="text-text-dim">PROFILE LINKS: </span>
            <span className="text-cyan-signal font-bold">{socialLinksCount}</span>
          </div>
        </div>
      </div>

      {/* Corporate Syntax Banner */}
      <div className="p-4 rounded-lg bg-void border border-cyan-signal/40 shadow-glow-cyan-sm flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded bg-cyan-signal/10 border border-cyan-signal/40 flex items-center justify-center">
            <Mail className="w-4 h-4 text-cyan-signal" />
          </div>
          <div>
            <span className="text-[10px] font-mono text-text-dim uppercase tracking-wider">
              Detected Organizational Email Format Syntax
            </span>
            <div className="font-mono text-base font-bold text-cyan-signal">
              {peopleData.email_pattern}
            </div>
          </div>
        </div>
        <p className="text-xs text-text-dim max-w-xs font-mono">
          Syntax pattern is verified against MX mail servers and cross-referenced with discovered public staff records.
        </p>
      </div>

      {/* Staff & Social Profiles Roster */}
      <div className="panel-glass rounded-lg border border-border-dim shadow-panel overflow-hidden">
        {/* Filters */}
        <div className="p-4 border-b border-border-dim flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex flex-wrap items-center gap-3">
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-text-dim absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                placeholder="Search staff, role, email, or verification..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="pl-8 pr-3 py-1.5 rounded bg-void border border-border-dim text-xs text-text-primary font-mono w-72 focus:border-cyan-signal focus:outline-none transition-colors"
              />
            </div>

            <div className="flex items-center gap-1.5">
              <Filter className="w-3.5 h-3.5 text-text-dim" />
              <select
                value={platformFilter}
                onChange={(e) => setPlatformFilter(e.target.value)}
                className="px-2.5 py-1.5 rounded bg-void border border-border-dim text-xs text-text-primary font-mono focus:border-cyan-signal focus:outline-none"
              >
                {platforms.map(p => (
                  <option key={p} value={p}>{p === 'ALL' ? 'All Platforms' : p}</option>
                ))}
              </select>
            </div>

            <select
              value={deliverabilityFilter}
              onChange={(e) => setDeliverabilityFilter(e.target.value)}
              className="px-2.5 py-1.5 rounded bg-void border border-border-dim text-xs text-text-primary font-mono focus:border-cyan-signal focus:outline-none"
            >
              <option value="ALL">All Deliverability</option>
              <option value="VERIFIED">Verified / Deliverable Only</option>
              <option value="INFERRED">Inferred Pattern Only</option>
              <option value="PROFILE_ONLY">Public Profiles Only</option>
            </select>
          </div>

          <span className="text-xs text-text-dim font-mono">
            Showing {filteredPeople.length} records
          </span>
        </div>

        {filteredPeople.length === 0 ? (
          <div className="py-12 text-center text-xs text-text-dim font-mono">
            No employee profiles or verified emails matched your filter criteria.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-border-dim bg-void/50 text-text-dim font-mono text-[11px]">
                  <th className="py-3 px-4">EMPLOYEE NAME</th>
                  <th className="py-3 px-4">ROLE / TITLE</th>
                  <th className="py-3 px-4">EMAIL ADDRESS</th>
                  <th className="py-3 px-4">PUBLIC PROFILE / LINK</th>
                  <th className="py-3 px-4">PLATFORM</th>
                  <th className="py-3 px-4">DELIVERABILITY & VERIFICATION</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border-dim/60 font-mono">
                {filteredPeople.map((p, idx) => (
                  <tr key={idx} className="hover:bg-void/40 transition-colors">
                    <td className="py-3 px-4 font-medium text-text-primary">
                      {p.name || 'Organization Staff'}
                    </td>
                    <td className="py-3 px-4 text-text-dim text-xs max-w-xs truncate">
                      {p.title || 'Staff / Member'}
                    </td>
                    <td className="py-3 px-4 text-cyan-signal">
                      {p.email ? (
                        <TechnicalData value={p.email} />
                      ) : (
                        <span className="text-text-dim italic text-[11px]">No direct email</span>
                      )}
                    </td>
                    <td className="py-3 px-4">
                      {p.profile_url ? (
                        <a
                          href={p.profile_url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-void border border-border-dim hover:border-cyan-signal text-text-primary text-[11px] group transition-all"
                        >
                          {getPlatformIcon(p.platform, p.profile_url)}
                          <span className="truncate max-w-[120px]">{p.platform || 'Profile'}</span>
                          <ExternalLink className="w-3 h-3 text-text-dim group-hover:text-cyan-signal transition-colors" />
                        </a>
                      ) : (
                        <span className="text-text-dim text-[11px]">—</span>
                      )}
                    </td>
                    <td className="py-3 px-4">
                      <span className="px-2 py-0.5 rounded bg-panel border border-border-dim text-[10px] text-text-dim">
                        {p.platform || 'OSINT'}
                      </span>
                    </td>
                    <td className="py-3 px-4">
                      {getVerificationBadge(p)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
