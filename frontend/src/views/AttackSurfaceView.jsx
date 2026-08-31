import React, { useState, useMemo } from 'react';
import {
  Globe,
  Server,
  Cpu,
  Fingerprint,
  ShieldAlert,
  ShieldCheck,
  ExternalLink,
  ChevronDown,
  ChevronRight,
  Lock,
  Layers,
  FileCheck,
  Search,
  Copy,
  Check,
  Sliders,
  Filter,
  ArrowUpDown,
  Terminal,
} from 'lucide-react';
import SeverityBadge from '../components/SeverityBadge';
import EvidenceDrawer from '../components/graph/EvidenceDrawer';

export default function AttackSurfaceView({
  scanId,
  subdomains = [],
  ports = [],
  fingerprints = [],
  vulns = [],
}) {
  const [activeView, setActiveView] = useState('hosts'); // 'hosts' | 'subdomains' | 'vulns'
  const [searchQuery, setSearchQuery] = useState('');
  const [expandedHosts, setExpandedHosts] = useState({});
  const [expandedSubList, setExpandedSubList] = useState({});
  const [copiedItem, setCopiedItem] = useState(null);
  const [selectedEvidenceId, setSelectedEvidenceId] = useState(null);

  // Pagination for subdomains ledger
  const [currentPage, setCurrentPage] = useState(1);
  const itemsPerPage = 25;

  // Group ports by IP
  const portsByIp = useMemo(() => {
    const map = {};
    ports.forEach((p) => {
      const ip = p.ip || 'Unknown IP';
      if (!map[ip]) map[ip] = [];
      map[ip].push(p);
    });
    return map;
  }, [ports]);

  // Consolidate Subdomains into Host-Centric IP Clusters
  const hostClusters = useMemo(() => {
    const clusterMap = new Map();

    subdomains.forEach((s) => {
      const subName = s.subdomain || s.domain;
      if (!subName) return;
      const ips = s.ips && s.ips.length > 0 ? s.ips : ['Unresolved / CDN'];

      ips.forEach((ip) => {
        if (!clusterMap.has(ip)) {
          clusterMap.set(ip, {
            ip,
            isCdn: s.is_cdn || false,
            cdnProvider: s.cdn_provider || '',
            subdomains: [],
            ports: portsByIp[ip] || [],
          });
        }
        const host = clusterMap.get(ip);
        if (!host.subdomains.includes(subName)) {
          host.subdomains.push(subName);
        }
      });
    });

    return Array.from(clusterMap.values()).sort(
      (a, b) => b.subdomains.length - a.subdomains.length
    );
  }, [subdomains, portsByIp]);

  // Filtered Host Clusters
  const filteredHostClusters = useMemo(() => {
    if (!searchQuery.trim()) return hostClusters;
    const q = searchQuery.toLowerCase();
    return hostClusters.filter((h) => {
      const matchIp = h.ip.toLowerCase().includes(q);
      const matchSub = h.subdomains.some((s) => s.toLowerCase().includes(q));
      const matchPort = h.ports.some(
        (p) =>
          String(p.port).includes(q) || (p.service || '').toLowerCase().includes(q)
      );
      return matchIp || matchSub || matchPort;
    });
  }, [hostClusters, searchQuery]);

  // Filtered Subdomains
  const filteredSubdomains = useMemo(() => {
    if (!searchQuery.trim()) return subdomains;
    const q = searchQuery.toLowerCase();
    return subdomains.filter((s) => {
      const subName = (s.subdomain || s.domain || '').toLowerCase();
      const matchIp = (s.ips || []).some((ip) => ip.toLowerCase().includes(q));
      return subName.includes(q) || matchIp;
    });
  }, [subdomains, searchQuery]);

  // Paginated Subdomains
  const paginatedSubdomains = useMemo(() => {
    const start = (currentPage - 1) * itemsPerPage;
    return filteredSubdomains.slice(start, start + itemsPerPage);
  }, [filteredSubdomains, currentPage]);

  const totalPages = Math.ceil(filteredSubdomains.length / itemsPerPage) || 1;

  // Filtered Vulnerabilities
  const filteredVulns = useMemo(() => {
    if (!searchQuery.trim()) return vulns;
    const q = searchQuery.toLowerCase();
    return vulns.filter((v) => {
      const cve = (v.cve_id || v.template_id || '').toLowerCase();
      const title = (v.title || v.description || '').toLowerCase();
      return cve.includes(q) || title.includes(q);
    });
  }, [vulns, searchQuery]);

  // Toggle Host Accordion
  const toggleHost = (ip) => {
    setExpandedHosts((prev) => ({
      ...prev,
      [ip]: prev[ip] !== undefined ? !prev[ip] : false, // Default is expanded for first host
    }));
  };

  // Toggle Subdomains View-More
  const toggleSubList = (ip) => {
    setExpandedSubList((prev) => ({ ...prev, [ip]: !prev[ip] }));
  };

  // 1-Click Clipboard Copies
  const copyToClipboard = (text, type) => {
    navigator.clipboard.writeText(text);
    setCopiedItem(type);
    setTimeout(() => setCopiedItem(null), 2000);
  };

  const handleCopyAllSubdomains = () => {
    const list = subdomains.map((s) => s.subdomain || s.domain).filter(Boolean).join('\n');
    copyToClipboard(list, 'all-subs');
  };

  const handleCopyAllIps = () => {
    const ipSet = new Set();
    subdomains.forEach((s) => (s.ips || []).forEach((ip) => ipSet.add(ip)));
    copyToClipboard(Array.from(ipSet).join('\n'), 'all-ips');
  };

  return (
    <div className="space-y-6">
      {/* 1. High-Density Tactical Metric Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <div className="p-4 rounded-lg bg-panel border border-border-dim shadow-panel">
          <span className="text-[11px] font-mono uppercase text-text-dim">Discovered Subdomains</span>
          <p className="text-2xl font-mono font-bold text-cyan-signal mt-1">{subdomains.length}</p>
          <span className="text-[10px] font-mono text-text-dim">Enumerated Assets</span>
        </div>

        <div className="p-4 rounded-lg bg-panel border border-border-dim shadow-panel">
          <span className="text-[11px] font-mono uppercase text-text-dim">Resolving Hosts / IPs</span>
          <p className="text-2xl font-mono font-bold text-teal-400 mt-1">{hostClusters.length}</p>
          <span className="text-[10px] font-mono text-text-dim">
            {hostClusters.filter((h) => !h.isCdn).length} Origin,{' '}
            {hostClusters.filter((h) => h.isCdn).length} CDN/WAF
          </span>
        </div>

        <div className="p-4 rounded-lg bg-panel border border-border-dim shadow-panel">
          <span className="text-[11px] font-mono uppercase text-text-dim">Exposed Services</span>
          <p className="text-2xl font-mono font-bold text-indigo-400 mt-1">{ports.length}</p>
          <span className="text-[10px] font-mono text-text-dim">Discovered Open Ports</span>
        </div>

        <div className="p-4 rounded-lg bg-panel border border-border-dim shadow-panel">
          <span className="text-[11px] font-mono uppercase text-text-dim">Vulnerabilities</span>
          <p className="text-2xl font-mono font-bold text-magenta-alert mt-1">{vulns.length}</p>
          <span className="text-[10px] font-mono text-text-dim">
            {vulns.filter((v) => (v.severity || '').toLowerCase() === 'critical').length} Critical,{' '}
            {vulns.filter((v) => (v.severity || '').toLowerCase() === 'high').length} High
          </span>
        </div>
      </div>

      {/* 2. Interactive Workstation Control Bar */}
      <div className="p-4 rounded-lg bg-panel border border-border-dim shadow-panel flex flex-col md:flex-row md:items-center justify-between gap-4">
        {/* Perspective View Modes */}
        <div className="flex items-center gap-2">
          {[
            { id: 'hosts', label: '🖥️ Host Cluster View', count: hostClusters.length },
            { id: 'subdomains', label: '🌐 Subdomains Ledger', count: subdomains.length },
            { id: 'vulns', label: '🛡️ Vulnerability Matrix', count: vulns.length },
          ].map((mode) => {
            const isActive = activeView === mode.id;
            return (
              <button
                key={mode.id}
                onClick={() => {
                  setActiveView(mode.id);
                  setCurrentPage(1);
                }}
                className={`px-3 py-1.5 rounded text-xs font-mono transition-all flex items-center gap-2 ${
                  isActive
                    ? 'bg-cyan-signal text-black font-bold shadow-glow-cyan-sm'
                    : 'bg-void text-text-dim border border-border-dim hover:text-text-primary hover:bg-void/80'
                }`}
              >
                <span>{mode.label}</span>
                <span
                  className={`px-1.5 py-0.2 rounded text-[10px] ${
                    isActive ? 'bg-black/30 text-black' : 'bg-panel text-text-dim'
                  }`}
                >
                  {mode.count}
                </span>
              </button>
            );
          })}
        </div>

        {/* Search & Export Actions */}
        <div className="flex flex-wrap items-center gap-3">
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-text-dim absolute left-2.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search host, subdomain, port..."
              value={searchQuery}
              onChange={(e) => {
                setSearchQuery(e.target.value);
                setCurrentPage(1);
              }}
              className="pl-8 pr-3 py-1.5 rounded bg-void border border-border-dim text-xs font-mono text-text-primary focus:outline-none focus:border-cyan-signal w-48 sm:w-60"
            />
          </div>

          <button
            onClick={handleCopyAllSubdomains}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-void border border-border-dim hover:border-cyan-signal/50 text-xs font-mono text-text-dim hover:text-cyan-signal transition-colors"
            title="Copy all subdomains to clipboard for Burp / Nuclei"
          >
            {copiedItem === 'all-subs' ? <Check className="w-3.5 h-3.5 text-success-green" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copiedItem === 'all-subs' ? 'Copied Subdomains' : 'Copy Subdomains'}</span>
          </button>

          <button
            onClick={handleCopyAllIps}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-void border border-border-dim hover:border-cyan-signal/50 text-xs font-mono text-text-dim hover:text-cyan-signal transition-colors"
            title="Copy all IPs for Nmap"
          >
            {copiedItem === 'all-ips' ? <Check className="w-3.5 h-3.5 text-success-green" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copiedItem === 'all-ips' ? 'Copied IPs' : 'Copy IPs'}</span>
          </button>
        </div>
      </div>

      {/* ===================================================================== */}
      {/* VIEW 1: HOST CLUSTER VIEW (Consolidates 180 subdomains onto shared IP)  */}
      {/* ===================================================================== */}
      {activeView === 'hosts' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between text-xs font-mono text-text-dim px-1">
            <span>
              Grouped into <strong className="text-text-primary">{filteredHostClusters.length}</strong> resolving physical host(s). Click any host to inspect exposed ports and subdomains.
            </span>
          </div>

          {filteredHostClusters.length === 0 ? (
            <div className="p-8 rounded-lg bg-panel border border-border-dim text-center text-text-dim text-xs font-mono">
              No hosts matched your search filter.
            </div>
          ) : (
            filteredHostClusters.map((cluster) => {
              const isExpanded = expandedHosts[cluster.ip] !== false; // expanded by default
              const isListExpanded = !!expandedSubList[cluster.ip];
              const subCount = cluster.subdomains.length;
              const displayedSubs = isListExpanded ? cluster.subdomains : cluster.subdomains.slice(0, 16);
              const remainingCount = subCount - 16;

              return (
                <div
                  key={cluster.ip}
                  className="rounded-lg bg-panel border border-border-dim overflow-hidden shadow-panel transition-all"
                >
                  {/* Consolidated Host Header */}
                  <div
                    onClick={() => toggleHost(cluster.ip)}
                    className="p-4 bg-void/60 flex flex-col sm:flex-row sm:items-center justify-between gap-3 cursor-pointer select-none hover:bg-void/80 transition-colors border-b border-border-dim/60"
                  >
                    <div className="flex items-center gap-3">
                      <button className="text-text-dim">
                        {isExpanded ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
                      </button>
                      <div className="p-2 rounded bg-void border border-border-dim text-cyan-signal">
                        <Server className="w-4 h-4" />
                      </div>
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="font-mono font-bold text-sm text-text-primary">
                            {cluster.ip}
                          </span>
                          {cluster.isCdn ? (
                            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase bg-amber-500/10 text-amber-400 border border-amber-500/30">
                              PROXIED ({cluster.cdnProvider || 'CDN / WAF'})
                            </span>
                          ) : (
                            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase bg-success-green/10 text-success-green border border-success-green/30">
                              DIRECT ORIGIN SERVER
                            </span>
                          )}
                        </div>
                        <div className="text-[11px] font-mono text-text-dim mt-0.5 flex items-center gap-3">
                          <span>Hosted Subdomains: <strong className="text-cyan-signal">{subCount}</strong></span>
                          <span>•</span>
                          <span>Open Ports: <strong className="text-text-primary">{cluster.ports.length}</strong></span>
                        </div>
                      </div>
                    </div>

                    {/* Quick Host Copy */}
                    <div
                      onClick={(e) => {
                        e.stopPropagation();
                        copyToClipboard(cluster.ip, `host-${cluster.ip}`);
                      }}
                      className="flex items-center gap-1 text-xs font-mono text-text-dim hover:text-cyan-signal transition-colors self-end sm:self-center"
                    >
                      {copiedItem === `host-${cluster.ip}` ? (
                        <span className="text-success-green flex items-center gap-1">
                          <Check className="w-3.5 h-3.5" /> Copied IP
                        </span>
                      ) : (
                        <span className="flex items-center gap-1">
                          <Copy className="w-3.5 h-3.5" /> Copy IP
                        </span>
                      )}
                    </div>
                  </div>

                  {/* Expanded Body */}
                  {isExpanded && (
                    <div className="p-5 space-y-5 bg-void/30">
                      {/* Exposed Ports Badges */}
                      <div>
                        <h4 className="text-xs font-mono font-semibold uppercase tracking-wider text-text-dim flex items-center gap-1.5 mb-2.5">
                          <Lock className="w-3.5 h-3.5 text-cyan-signal" />
                          <span>Exposed Services & Ports ({cluster.ports.length})</span>
                        </h4>

                        {cluster.ports.length === 0 ? (
                          <p className="text-xs font-mono text-text-dim italic">
                            No open ports detected on this host.
                          </p>
                        ) : (
                          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2.5">
                            {cluster.ports.map((p, pIdx) => (
                              <div
                                key={pIdx}
                                className="p-2.5 rounded bg-void/80 border border-border-dim flex items-center justify-between text-xs font-mono shadow-sm"
                              >
                                <div className="flex items-center gap-2">
                                  <span className="w-2 h-2 rounded-full bg-cyan-signal" />
                                  <span className="font-bold text-text-primary">{p.port}</span>
                                  <span className="text-text-dim">/{p.protocol || 'tcp'}</span>
                                </div>
                                <span className="text-cyan-signal/90 font-medium truncate max-w-[120px]">
                                  {p.product || p.service || 'open'}
                                </span>
                              </div>
                            ))}
                          </div>
                        )}
                      </div>

                      {/* Subdomains Hosted On This Server */}
                      <div>
                        <div className="flex items-center justify-between mb-2.5">
                          <h4 className="text-xs font-mono font-semibold uppercase tracking-wider text-text-dim flex items-center gap-1.5">
                            <Globe className="w-3.5 h-3.5 text-cyan-signal" />
                            <span>Subdomains Hosted On This Host ({subCount})</span>
                          </h4>
                          {subCount > 16 && (
                            <button
                              onClick={() => toggleSubList(cluster.ip)}
                              className="text-xs font-mono text-cyan-signal hover:underline flex items-center gap-1"
                            >
                              <span>{isListExpanded ? 'Collapse List' : `View All ${subCount} Subdomains`}</span>
                              {isListExpanded ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />}
                            </button>
                          )}
                        </div>

                        <div className="flex flex-wrap gap-2">
                          {displayedSubs.map((subName) => (
                            <div
                              key={subName}
                              className="px-2.5 py-1 rounded bg-void border border-border-dim hover:border-cyan-signal/40 text-xs font-mono text-text-primary flex items-center gap-2 transition-colors group"
                            >
                              <span className="group-hover:text-cyan-signal">{subName}</span>
                              <a
                                href={`https://${subName}`}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="text-text-dim hover:text-cyan-signal transition-colors"
                                title={`Open https://${subName}`}
                              >
                                <ExternalLink className="w-3 h-3" />
                              </a>
                            </div>
                          ))}

                          {!isListExpanded && remainingCount > 0 && (
                            <button
                              onClick={() => toggleSubList(cluster.ip)}
                              className="px-3 py-1 rounded bg-void/60 border border-border-dim text-xs font-mono text-cyan-signal hover:border-cyan-signal/50 hover:bg-void transition-all font-semibold"
                            >
                              +{remainingCount} more subdomains...
                            </button>
                          )}
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              );
            })
          )}
        </div>
      )}

      {/* ===================================================================== */}
      {/* VIEW 2: COMPACT SUBDOMAINS LEDGER (Paginated High-Density Table)       */}
      {/* ===================================================================== */}
      {activeView === 'subdomains' && (
        <div className="space-y-4">
          <div className="rounded-lg bg-panel border border-border-dim overflow-hidden shadow-panel">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono">
                <thead>
                  <tr className="border-b border-border-dim text-text-dim uppercase text-[11px] bg-void/50">
                    <th className="py-3 px-4">Subdomain / Asset</th>
                    <th className="py-3 px-4">Resolving IP(s)</th>
                    <th className="py-3 px-4">Routing / Proxy</th>
                    <th className="py-3 px-4">Detected Ports</th>
                    <th className="py-3 px-4 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border-dim/60">
                  {paginatedSubdomains.length === 0 ? (
                    <tr>
                      <td colSpan="5" className="py-8 text-center text-text-dim">
                        No subdomains matched your search filter.
                      </td>
                    </tr>
                  ) : (
                    paginatedSubdomains.map((sub, idx) => {
                      const subName = sub.subdomain || sub.domain;
                      const ips = sub.ips || [];
                      const primaryIp = ips[0] || 'Unresolved';
                      const ipPorts = portsByIp[primaryIp] || [];

                      return (
                        <tr key={idx} className="hover:bg-void/40 transition-colors">
                          <td className="py-2.5 px-4 text-text-primary font-medium">
                            <div className="flex items-center gap-2">
                              <Globe className="w-3.5 h-3.5 text-cyan-signal shrink-0" />
                              <span className="truncate">{subName}</span>
                            </div>
                          </td>
                          <td className="py-2.5 px-4 text-cyan-signal font-semibold">
                            {ips.length > 0 ? ips.join(', ') : '—'}
                          </td>
                          <td className="py-2.5 px-4">
                            {sub.is_cdn ? (
                              <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-amber-500/10 text-amber-400 border border-amber-500/30">
                                {sub.cdn_provider || 'CDN / WAF'}
                              </span>
                            ) : (
                              <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-success-green/10 text-success-green border border-success-green/30">
                                Origin Server
                              </span>
                            )}
                          </td>
                          <td className="py-2.5 px-4">
                            {ipPorts.length > 0 ? (
                              <div className="flex items-center gap-1.5 flex-wrap">
                                {ipPorts.map((p, pIdx) => (
                                  <span
                                    key={pIdx}
                                    className="px-1.5 py-0.2 rounded bg-void border border-border-dim text-[10px] text-text-primary"
                                  >
                                    {p.port}/{p.service || 'tcp'}
                                  </span>
                                ))}
                              </div>
                            ) : (
                              <span className="text-text-dim/60">—</span>
                            )}
                          </td>
                          <td className="py-2.5 px-4 text-right">
                            <div className="flex items-center justify-end gap-2">
                              <button
                                onClick={() => copyToClipboard(subName, `sub-${idx}`)}
                                className="text-text-dim hover:text-cyan-signal p-1 transition-colors"
                                title="Copy Subdomain"
                              >
                                {copiedItem === `sub-${idx}` ? (
                                  <Check className="w-3.5 h-3.5 text-success-green" />
                                ) : (
                                  <Copy className="w-3.5 h-3.5" />
                                )}
                              </button>
                              <a
                                href={`https://${subName}`}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="text-text-dim hover:text-cyan-signal p-1 transition-colors"
                                title="Open in Browser"
                              >
                                <ExternalLink className="w-3.5 h-3.5" />
                              </a>
                            </div>
                          </td>
                        </tr>
                      );
                    })
                  )}
                </tbody>
              </table>
            </div>

            {/* Pagination Toolbar */}
            <div className="p-4 border-t border-border-dim bg-void/50 flex flex-col sm:flex-row items-center justify-between gap-3 text-xs font-mono text-text-dim">
              <span>
                Showing {Math.min((currentPage - 1) * itemsPerPage + 1, filteredSubdomains.length)} -{' '}
                {Math.min(currentPage * itemsPerPage, filteredSubdomains.length)} of {filteredSubdomains.length} Subdomains
              </span>

              <div className="flex items-center gap-2">
                <button
                  onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
                  disabled={currentPage === 1}
                  className="px-3 py-1 rounded bg-panel border border-border-dim hover:border-cyan-signal/40 disabled:opacity-40 disabled:pointer-events-none transition-colors"
                >
                  Previous
                </button>
                <span>
                  Page <strong className="text-text-primary">{currentPage}</strong> of {totalPages}
                </span>
                <button
                  onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
                  disabled={currentPage === totalPages}
                  className="px-3 py-1 rounded bg-panel border border-border-dim hover:border-cyan-signal/40 disabled:opacity-40 disabled:pointer-events-none transition-colors"
                >
                  Next
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ===================================================================== */}
      {/* VIEW 3: VULNERABILITY EXPOSURE MATRIX (Surfaced Prominently)          */}
      {/* ===================================================================== */}
      {activeView === 'vulns' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between text-xs font-mono text-text-dim px-1">
            <span>
              Displaying <strong className="text-text-primary">{filteredVulns.length}</strong> identified vulnerability exposure candidates sorted by risk priority.
            </span>
          </div>

          {filteredVulns.length === 0 ? (
            <div className="p-8 rounded-lg bg-panel border border-border-dim text-center text-text-dim text-xs font-mono">
              No vulnerabilities recorded for this target scope.
            </div>
          ) : (
            <div className="grid grid-cols-1 gap-3">
              {filteredVulns.map((v, vIdx) => {
                const cve = v.cve_id || v.template_id || 'CVE-OBSERVED';
                const title = v.title || v.description || 'Observed Vulnerability Finding';
                const severity = v.severity || 'medium';
                const status = v.status || 'potential';
                const conf = v.confidence ? Math.round(v.confidence * 100) : 80;

                return (
                  <div
                    key={vIdx}
                    className="p-4 rounded-lg bg-panel border border-border-dim shadow-panel space-y-3 hover:border-cyan-signal/40 transition-colors"
                  >
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                      <div className="flex items-center gap-3">
                        <SeverityBadge severity={severity} />
                        <span className="font-mono font-bold text-sm text-text-primary">{cve}</span>
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-mono font-semibold uppercase border ${
                            status === 'confirmed'
                              ? 'bg-rose-500/10 text-rose-400 border-rose-500/30'
                              : status === 'likely'
                              ? 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                              : 'bg-blue-500/10 text-blue-400 border-blue-500/30'
                          }`}
                        >
                          {status} ({conf}%)
                        </span>
                      </div>

                      <button
                        onClick={() => copyToClipboard(cve, `cve-${vIdx}`)}
                        className="text-xs font-mono text-text-dim hover:text-cyan-signal flex items-center gap-1 self-end sm:self-center transition-colors"
                      >
                        {copiedItem === `cve-${vIdx}` ? (
                          <span className="text-success-green flex items-center gap-1">
                            <Check className="w-3 h-3" /> Copied CVE
                          </span>
                        ) : (
                          <span className="flex items-center gap-1">
                            <Copy className="w-3 h-3" /> Copy CVE
                          </span>
                        )}
                      </button>
                    </div>

                    <p className="text-xs text-text-primary font-medium">{title}</p>

                    {v.evidence && (
                      <div className="p-2.5 rounded bg-void border border-border-dim text-xs font-mono text-text-dim">
                        <strong className="text-text-primary">Evidence:</strong> {v.evidence}
                      </div>
                    )}

                    {v.remediation && (
                      <div className="text-xs font-mono text-cyan-signal">
                        <strong>Remediation:</strong> {v.remediation}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* Evidence Inspection Drawer */}
      <EvidenceDrawer
        jobId={scanId}
        evidenceId={selectedEvidenceId}
        onClose={() => setSelectedEvidenceId(null)}
      />
    </div>
  );
}
