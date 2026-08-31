import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  Globe,
  Cpu,
  Fingerprint,
  ShieldAlert,
  Users,
  FileText,
  Copy,
  Check,
  ExternalLink,
  RefreshCw,
  AlertOctagon,
  ShieldCheck,
  Server,
  Clock,
  Timer,
  Mail,
  Layers,
  Lock,
  AlertTriangle,
  Key,
  CheckCircle2,
  XCircle,
  LayoutDashboard,
  Share2,
  Cloud,
  Terminal,
  ChevronDown,
  ChevronUp,
  TrendingUp,
  Ban,
} from 'lucide-react';
import { useScanJob, useScanFindings, useScanReport, useAbortScan } from '../api/hooks';
import PipelineVisualizer from '../components/PipelineVisualizer';
import SeverityBadge from '../components/SeverityBadge';
import TechnicalData from '../components/TechnicalData';
import { LoadingState, EmptyState } from '../components/LoadingState';
import AiDisclaimer from '../components/AiDisclaimer';

import AttackSurfaceView from './AttackSurfaceView';
import PeopleIntelligenceView from './PeopleIntelligenceView';
import ExposureView from './ExposureView';
import GraphView from './GraphView';

export function parseUtcDate(dateStr) {
  if (!dateStr) return null;
  if (dateStr instanceof Date) return dateStr;
  let formatted = String(dateStr).trim();
  if (!formatted.endsWith('Z') && !/[+-]\d{2}:?\d{2}$/.test(formatted)) {
    formatted = formatted + 'Z';
  }
  const dt = new Date(formatted);
  return isNaN(dt.getTime()) ? new Date(dateStr) : dt;
}

export function formatScanDuration(createdStr, completedStr) {
  if (!createdStr) return '';
  const startDate = parseUtcDate(createdStr);
  if (!startDate) return '';
  const start = startDate.getTime();
  if (isNaN(start)) return '';
  
  const endDate = completedStr ? parseUtcDate(completedStr) : new Date();
  const end = endDate ? endDate.getTime() : Date.now();
  const totalSecs = Math.max(0, Math.floor((end - start) / 1000));
  
  if (totalSecs < 60) {
    return `${totalSecs}s`;
  }
  const mins = Math.floor(totalSecs / 60);
  const secs = totalSecs % 60;
  return `${mins}m ${secs.toString().padStart(2, '0')}s`;
}

function ScanTimerBadge({ job }) {
  const [now, setNow] = useState(() => Date.now());

  useEffect(() => {
    if (job?.status === 'running' || job?.status === 'pending') {
      const interval = setInterval(() => setNow(Date.now()), 1000);
      return () => clearInterval(interval);
    }
  }, [job?.status]);

  if (!job?.created_at) return null;

  if (job.status === 'running') {
    const elapsed = formatScanDuration(job.created_at, null);
    return (
      <span className="flex items-center gap-1.5 px-2.5 py-0.5 rounded text-[11px] font-mono font-bold bg-cyan-signal/15 text-cyan-signal border border-cyan-signal/40 shadow-glow-cyan-sm animate-pulse">
        <Clock className="w-3.5 h-3.5 text-cyan-signal animate-spin" />
        <span>ACTIVE SCAN: {elapsed}</span>
      </span>
    );
  }

  if (job.status === 'complete') {
    const duration = formatScanDuration(job.created_at, job.completed_at);
    return (
      <span className="flex items-center gap-1.5 px-2.5 py-0.5 rounded text-[11px] font-mono font-bold bg-success-green/10 text-success-green border border-success-green/40">
        <Timer className="w-3.5 h-3.5 text-success-green" />
        <span>DURATION: {duration}</span>
      </span>
    );
  }

  if (job.status === 'failed') {
    const duration = formatScanDuration(job.created_at, job.completed_at);
    return (
      <span className="flex items-center gap-1.5 px-2.5 py-0.5 rounded text-[11px] font-mono font-bold bg-magenta-alert/10 text-magenta-alert border border-magenta-alert/40">
        <Timer className="w-3.5 h-3.5 text-magenta-alert" />
        <span>FAILED AFTER: {duration}</span>
      </span>
    );
  }

  if (job.status === 'cancelled') {
    const duration = formatScanDuration(job.created_at, job.completed_at);
    return (
      <span className="flex items-center gap-1.5 px-2.5 py-0.5 rounded text-[11px] font-mono font-bold bg-amber-500/10 text-amber-500 border border-amber-500/40">
        <Ban className="w-3.5 h-3.5 text-amber-500" />
        <span>ABORTED AFTER: {duration}</span>
      </span>
    );
  }

  return null;
}

export default function ScanDetailView({ scanId, onSelectTab }) {
  const navigate = useNavigate();
  const { scanId: routeScanId } = useParams();
  const effectiveScanId = scanId || routeScanId;
  const [activeTab, setActiveTab] = useState('whois');
  const [copiedText, setCopiedText] = useState(null);
  const [expandedProof, setExpandedProof] = useState({});
  const [expandedHosts, setExpandedHosts] = useState({});
  const [expandedDomains, setExpandedDomains] = useState({});

  const toggleProof = (key) => setExpandedProof((prev) => ({ ...prev, [key]: !prev[key] }));
  const toggleHost = (hostKey) => setExpandedHosts((prev) => ({ ...prev, [hostKey]: !prev[hostKey] }));
  const toggleDomain = (hostKey) => setExpandedDomains((prev) => ({ ...prev, [hostKey]: !prev[hostKey] }));
  const expandAllHosts = (allKeys) => {
    const next = {};
    allKeys.forEach((k) => (next[k] = true));
    setExpandedHosts(next);
  };
  const collapseAllHosts = (allKeys) => {
    const next = {};
    allKeys.forEach((k) => (next[k] = false));
    setExpandedHosts(next);
  };
  const { data: job, isLoading: jobLoading, refetch: refetchJob } = useScanJob(effectiveScanId);
  const { data: findings = [], isLoading: findingsLoading } = useScanFindings(effectiveScanId);
  const { data: report } = useScanReport(effectiveScanId);
  const abortScanMutation = useAbortScan();

  const handleCopy = (text, key) => {
    if (!text) return;
    navigator.clipboard.writeText(text);
    setCopiedText(key);
    setTimeout(() => setCopiedText(null), 2000);
  };

  if (!effectiveScanId) {
    return (
      <EmptyState
        title="No Scan Selected"
        message="Select an active or historical scan from the dashboard to inspect telemetry."
      />
    );
  }

  if (jobLoading) return <LoadingState message="Connecting to pipeline worker telemetry..." />;

  if (!job) {
    return (
      <EmptyState
        title="Scan Job Not Found"
        message={`Job ${scanId} does not exist for the current tenant.`}
      />
    );
  }

  // Filter findings by type
  const companyFinding = findings.find((f) => f.type === 'company_info');
  const companyData = companyFinding?.data || {};
  const emailSec = companyData.email_security || {};
  const tlsIntel = companyData.tls_intel || {};
  const dnsRisks = companyData.dns_risks || {};
  const lifecycleRisk = companyData.domain_lifecycle_risk || {};

  // Deduplicate and merge subdomains with their resolved IP findings by hostname
  const assetMap = new Map();

  findings.filter((f) => f.type === 'subdomain').forEach((f) => {
    const data = f.data || {};
    const host = (data.subdomain || data.host || '').toLowerCase().trim();
    if (host) {
      assetMap.set(host, {
        id: f.id,
        host,
        ips: data.ips && data.ips.length > 0 ? data.ips.join(', ') : '',
        isCdn: data.is_cdn || false,
        cdnProvider: data.cdn_provider || '',
        cloudService: data.cloud_service || '',
        cnames: data.cnames || [],
        source: f.source_tool || 'recon.subdomains',
      });
    }
  });

  findings.filter((f) => f.type === 'ip_resolution').forEach((f) => {
    const data = f.data || {};
    const host = (data.subdomain || data.host || '').toLowerCase().trim();
    if (host) {
      const existing = assetMap.get(host) || {};
      const resolvedIps = data.ips && data.ips.length > 0 ? data.ips.join(', ') : existing.ips;
      assetMap.set(host, {
        id: existing.id || f.id,
        host,
        ips: resolvedIps || 'Direct Query',
        isCdn: data.is_cdn !== undefined ? data.is_cdn : (existing.isCdn || false),
        cdnProvider: data.cdn_provider || existing.cdnProvider || '',
        cloudService: data.cloud_service || existing.cloudService || '',
        cnames: data.cnames || existing.cnames || [],
        source: existing.source ? `${existing.source}, recon.ip_resolve` : (f.source_tool || 'recon.ip_resolve'),
      });
    }
  });

  const mergedAssets = Array.from(assetMap.values());
  const portFindings = findings.filter((f) => f.type === 'port');
  const fpFindings = findings.filter((f) => f.type === 'fingerprint');
  const vulnFindings = findings.filter((f) => f.type === 'vuln');
  const peopleFindings = findings.filter((f) => f.type === 'people');

  // ---------------------------------------------------------
  // Host-Centric Infrastructure Aggregator
  // ---------------------------------------------------------
  const hostMap = new Map();

  const getOrCreateHost = (ip) => {
    const cleanIp = (ip || 'Origin Server').trim();
    if (!hostMap.has(cleanIp)) {
      hostMap.set(cleanIp, {
        ip: cleanIp,
        hostnames: new Set(),
        isCdn: false,
        cdnProvider: '',
        ports: [],
        technologies: [],
        vulnerabilities: [],
      });
    }
    return hostMap.get(cleanIp);
  };

  // 1. Seed hosts from merged perimeter assets
  mergedAssets.forEach((asset) => {
    const rawIps = asset.ips ? asset.ips.split(', ').map(s => s.trim()).filter(s => s && s !== 'Direct Query' && s !== 'Resolving...') : [];
    if (rawIps.length === 0) {
      const h = getOrCreateHost(asset.host);
      h.hostnames.add(asset.host);
      return;
    }
    rawIps.forEach((ip) => {
      const h = getOrCreateHost(ip);
      h.hostnames.add(asset.host);
      if (asset.isCdn) {
        h.isCdn = true;
        h.cdnProvider = asset.cdnProvider;
      }
    });
  });

  // 2. Add port findings
  portFindings.forEach((pf) => {
    const p = pf.data || {};
    const ip = p.ip || (hostMap.size > 0 ? Array.from(hostMap.keys())[0] : 'Origin Server');
    const h = getOrCreateHost(ip);
    if (!h.ports.some(existing => existing.port === p.port && existing.protocol === p.protocol)) {
      h.ports.push(p);
    }
  });

  // 3. Add tech stack & fingerprints (with Cross-Stage Port Harmonization)
  fpFindings.forEach((f) => {
    const data = f.data || {};
    const techs = data.technologies || [];
    const targetHost = data.host || (hostMap.size > 0 ? Array.from(hostMap.keys())[0] : 'Origin Server');
    const h = getOrCreateHost(targetHost);
    techs.forEach((t) => {
      const tName = t.name || t;
      if (!h.technologies.some(existing => (existing.name || existing) === tName)) {
        h.technologies.push(t);
      }
    });

    // Cross-Stage Port Harmonization: If a web endpoint was proven live on a port, ensure it appears in the port table
    if (data.url) {
      try {
        const u = new URL(data.url);
        const parsedPort = u.port ? parseInt(u.port, 10) : (u.protocol === 'https:' ? 443 : 80);
        if (!h.ports.some(p => p.port === parsedPort)) {
          const mainTech = techs[0];
          const techName = mainTech?.name || mainTech || (u.protocol === 'https:' ? 'HTTPS Web Server' : 'HTTP Web Server');
          h.ports.push({
            port: parsedPort,
            protocol: 'tcp',
            service: u.protocol === 'https:' ? 'https' : 'http',
            product: techName,
            version: mainTech?.version || '',
            state: 'open',
            banner: `Live endpoint verified on ${data.url}`,
            service_verified: true,
          });
        }
      } catch (e) {}
    }
  });

  // 4. Add vulnerabilities & misconfigurations
  vulnFindings.forEach((f) => {
    const v = f.data || {};
    const ip = v.ip || (hostMap.size > 0 ? Array.from(hostMap.keys())[0] : 'Origin Server');
    const h = getOrCreateHost(ip);
    const cveId = v.cve_id || v.template_id || v.title || f.id;
    if (!h.vulnerabilities.some(existing => (existing.cve_id || existing.template_id || existing.title) === cveId)) {
      h.vulnerabilities.push({ ...v, severity: f.severity || v.severity || 'low' });
    }
  });

  // ---------------------------------------------------------
  // Risk-Weighted Sorting: Critical & High CVEs Float to Top
  // ---------------------------------------------------------
  const SEVERITY_WEIGHTS = {
    critical: 1000,
    high: 100,
    medium: 10,
    low: 2,
    info: 1,
  };

  const hostInventory = Array.from(hostMap.values()).map(h => {
    let riskScore = 0;
    let criticalCount = 0;
    let highCount = 0;
    let mediumCount = 0;

    h.vulnerabilities.forEach((v) => {
      const sev = (v.severity || 'low').toLowerCase();
      riskScore += SEVERITY_WEIGHTS[sev] || 1;
      if (sev === 'critical') criticalCount++;
      else if (sev === 'high') highCount++;
      else if (sev === 'medium') mediumCount++;
    });

    // Secondary weight: open ports and detected technologies
    riskScore += (h.ports?.length || 0) * 0.1;
    riskScore += (h.technologies?.length || 0) * 0.05;

    return {
      ...h,
      hostnames: Array.from(h.hostnames),
      riskScore,
      criticalCount,
      highCount,
      mediumCount,
    };
  }).sort((a, b) => {
    // 1. Critical CVE count first
    if (b.criticalCount !== a.criticalCount) {
      return b.criticalCount - a.criticalCount;
    }
    // 2. High CVE count second
    if (b.highCount !== a.highCount) {
      return b.highCount - a.highCount;
    }
    // 3. Medium CVE count third
    if (b.mediumCount !== a.mediumCount) {
      return b.mediumCount - a.mediumCount;
    }
    // 4. Overall risk score
    if (b.riskScore !== a.riskScore) {
      return b.riskScore - a.riskScore;
    }
    // 5. Open ports count (active nodes before silent nodes)
    if (b.ports.length !== a.ports.length) {
      return b.ports.length - a.ports.length;
    }
    return a.ip.localeCompare(b.ip);
  });

  return (
    <div className="space-y-6">
      {/* Top Target Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-5 rounded-lg panel-glass border border-border-dim shadow-panel">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="font-display font-bold text-xl text-text-primary">
              {job.target_domain}
            </h1>
            <span
              className={`px-2.5 py-0.5 rounded text-[11px] font-mono font-semibold uppercase border ${
                job.status === 'complete'
                  ? 'bg-success-green/10 text-success-green border-success-green/40'
                  : job.status === 'running'
                  ? 'bg-cyan-signal/10 text-cyan-signal border-cyan-signal/40 animate-pulse'
                  : job.status === 'cancelled'
                  ? 'bg-amber-500/10 text-amber-500 border-amber-500/40'
                  : 'bg-magenta-alert/10 text-magenta-alert border-magenta-alert/40'
              }`}
            >
              {job.status}
            </span>
            {job.scan_profile && (
              <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase border ${
                job.scan_profile === 'deep'
                  ? 'bg-magenta-alert/10 text-magenta-alert border-magenta-alert/40'
                  : job.scan_profile === 'fast'
                  ? 'bg-yellow-500/10 text-yellow-400 border-yellow-500/40'
                  : 'bg-cyan-signal/10 text-cyan-signal border-cyan-signal/40'
              }`}>
                {job.scan_profile === 'deep' ? '🔥 DEEP SCAN' : job.scan_profile === 'fast' ? '⚡ FAST SCAN' : '🎯 STANDARD RECON'}
              </span>
            )}
            <ScanTimerBadge job={job} />
          </div>
          <div className="flex items-center gap-3 mt-1 text-xs text-text-dim font-mono">
            <span>JOB ID: {job.id}</span>
            <span>•</span>
            <span>STEP: {job.current_step}</span>
            <span>•</span>
            <span>PROFILE: {(job.scan_profile || 'standard').toUpperCase()}</span>
            {job.completed_at && job.created_at && (
              <>
                <span>•</span>
                <span className="text-success-green font-semibold">
                  COMPLETED IN {formatScanDuration(job.created_at, job.completed_at)}
                </span>
              </>
            )}
          </div>
        </div>

        <div className="flex items-center gap-3">
          {(job.status === 'running' || job.status === 'pending') && (
            <button
              onClick={() => {
                if (window.confirm(`Are you sure you want to gracefully abort the active reconnaissance scan on ${job.target_domain}?`)) {
                  abortScanMutation.mutate(job.id);
                }
              }}
              disabled={abortScanMutation.isPending}
              className="flex items-center gap-1.5 px-3.5 py-1.5 rounded bg-magenta-alert/15 hover:bg-magenta-alert/25 text-magenta-alert border border-magenta-alert/40 font-semibold text-xs tracking-wide transition-all font-mono shadow-sm hover:brightness-110 active:scale-95 disabled:opacity-50"
              title="Gracefully terminate active reconnaissance and audit operations"
            >
              <Ban className="w-3.5 h-3.5" />
              <span>{abortScanMutation.isPending ? 'ABORTING...' : 'ABORT SCAN'}</span>
            </button>
          )}

          <button
            onClick={() => refetchJob()}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-void border border-border-dim text-xs text-text-dim hover:text-cyan-signal transition-colors font-mono"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            <span>Refresh</span>
          </button>

          {job.status === 'complete' && (
            <button
              onClick={() => {
                if (onSelectTab) onSelectTab('reports');
                navigate(`/reports/${effectiveScanId}`);
              }}
              className="flex items-center gap-2 px-4 py-1.5 rounded bg-cyan-signal text-black font-semibold text-xs tracking-wide shadow-glow-cyan-sm hover:brightness-110 transition-all font-mono"
            >
              <FileText className="w-4 h-4" />
              <span>VIEW REPORT</span>
            </button>
          )}
        </div>
      </div>

      {/* Signature Live 10-Stage Pipeline Visualizer (Displayed when scan is running) */}
      {job.status === 'running' && (
        <PipelineVisualizer currentStep={job.current_step} status={job.status} />
      )}

      {/* Error Banner if Failed */}
      {job.error_message && (
        <div className="p-4 rounded-lg bg-magenta-alert/10 border border-magenta-alert/40 text-magenta-alert text-xs flex items-start gap-3">
          <AlertOctagon className="w-4 h-4 mt-0.5 shrink-0" />
          <div>
            <div className="font-semibold uppercase tracking-wider">Pipeline Failure Telemetry</div>
            <p className="mt-1 font-mono text-[11px]">{job.error_message}</p>
          </div>
        </div>
      )}

      {/* Primary Investigation Interface: Unified Linear Findings View */}
      <div className="panel-glass rounded-lg border border-border-dim shadow-panel overflow-hidden">
        <div className="flex items-center border-b border-border-dim px-3 bg-void/50 overflow-x-auto">
          {[
            { id: 'whois', label: 'WHOIS & Target Intel', count: companyFinding ? '✓' : '0', icon: ShieldCheck },
            { id: 'subdomains', label: 'Subdomains & IPs', count: mergedAssets.length, icon: Globe },
            { id: 'people', label: 'People OSINT', count: peopleFindings[0]?.data?.employees?.length || peopleFindings.length, icon: Users },
            { id: 'infrastructure', label: 'Infrastructure & Hosts', count: hostInventory.length, icon: Server },
            { id: 'documents', label: 'Documents & Exposure', count: null, icon: Cloud },
            { id: 'attack_surface', label: 'Attack Surface', count: null, icon: Layers },
            { id: 'graph', label: 'Intelligence Graph', count: null, icon: Share2 },
          ].map((tab) => {
            const Icon = tab.icon;
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center gap-2 py-3 px-3.5 text-xs font-mono font-bold border-b-2 transition-all shrink-0 ${
                  isActive
                    ? 'border-cyan-signal text-cyan-signal bg-cyan-signal/10 shadow-glow-cyan-sm'
                    : 'border-transparent text-text-dim hover:text-text-primary hover:bg-white/5'
                }`}
              >
                <Icon className="w-3.5 h-3.5" />
                <span>{tab.label}</span>
                {tab.count !== undefined && tab.count !== null && (
                  <span className={`ml-1 px-1.5 py-0.2 rounded text-[10px] font-mono ${
                    isActive ? 'bg-cyan-signal/20 text-cyan-signal' : 'bg-void border border-border-dim text-text-dim'
                  }`}>
                    {tab.count}
                  </span>
                )}
              </button>
            );
          })}
        </div>

        {/* Tab Content Panels */}
        <div className="p-5">
          {/* 0. Enterprise Red Team WHOIS & Target Intelligence Tab */}
          {activeTab === 'whois' && (
            <div className="space-y-6">
              {!companyFinding ? (
                <p className="text-xs text-text-dim font-mono py-4 text-center">
                  Awaiting company resolution and WHOIS stage completion...
                </p>
              ) : (
                <>
                  {/* Security Posture Summary Ribbons */}
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                    {/* Domain Lifecycle Risk Banner */}
                    <div className={`p-3.5 rounded-lg border flex items-start gap-3 ${
                      lifecycleRisk.level === 'HIGH'
                        ? 'bg-magenta-alert/10 border-magenta-alert/40 text-magenta-alert'
                        : lifecycleRisk.level === 'MEDIUM'
                        ? 'bg-yellow-500/10 border-yellow-500/40 text-yellow-400'
                        : 'bg-success-green/10 border-success-green/40 text-success-green'
                    }`}>
                      <Lock className="w-4 h-4 mt-0.5 shrink-0" />
                      <div>
                        <div className="text-[11px] font-mono font-bold uppercase tracking-wider">
                          {lifecycleRisk.score || 'Domain Lifecycle Risk'}
                        </div>
                        <p className="text-xs text-text-dim mt-0.5">{lifecycleRisk.reason}</p>
                      </div>
                    </div>

                    {/* Email Spoofability Posture Banner */}
                    <div className={`p-3.5 rounded-lg border flex items-start gap-3 ${
                      emailSec.spoofable
                        ? 'bg-magenta-alert/10 border-magenta-alert/40 text-magenta-alert'
                        : 'bg-success-green/10 border-success-green/40 text-success-green'
                    }`}>
                      <Mail className="w-4 h-4 mt-0.5 shrink-0" />
                      <div>
                        <div className="text-[11px] font-mono font-bold uppercase tracking-wider">
                          {emailSec.spoofable ? 'Spoofing Feasibility: HIGH' : 'Email Spoofing: BLOCKED'}
                        </div>
                        <p className="text-xs text-text-dim mt-0.5">{emailSec.spoofability_verdict}</p>
                      </div>
                    </div>

                    {/* AXFR & DNS Hygiene Banner */}
                    <div className={`p-3.5 rounded-lg border flex items-start gap-3 ${
                      dnsRisks.axfr_vulnerable || dnsRisks.has_orphaned_ns
                        ? 'bg-magenta-alert/10 border-magenta-alert/40 text-magenta-alert'
                        : 'bg-success-green/10 border-success-green/40 text-success-green'
                    }`}>
                      <Server className="w-4 h-4 mt-0.5 shrink-0" />
                      <div>
                        <div className="text-[11px] font-mono font-bold uppercase tracking-wider">
                          {dnsRisks.axfr_vulnerable ? 'CRITICAL: AXFR Zone Dump' : 'DNS Hygiene & AXFR: Passed'}
                        </div>
                        <p className="text-xs text-text-dim mt-0.5">{dnsRisks.axfr_verdict}</p>
                      </div>
                    </div>
                  </div>

                  {/* Section 1: WHOIS Depth & Lifecycle Metrics */}
                  <div className="p-4 rounded-lg bg-void/40 border border-border-dim space-y-4">
                    <div className="text-xs font-mono font-bold text-text-primary flex items-center gap-2">
                      <ShieldCheck className="w-4 h-4 text-cyan-signal" />
                      <span>WHOIS Registration & Domain Lifecycle Depth</span>
                    </div>

                    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 text-xs font-mono">
                      <div className="space-y-1">
                        <span className="text-text-dim text-[11px]">REGISTRAR</span>
                        <div className="text-text-primary font-semibold">{companyData.registrar || 'Protected / Hidden'}</div>
                        {companyData.registrar_iana_id && (
                          <div className="text-text-dim text-[10px]">IANA ID: #{companyData.registrar_iana_id}</div>
                        )}
                      </div>

                      <div className="space-y-1">
                        <span className="text-text-dim text-[11px]">AGE & REGISTRATION</span>
                        <div className="text-success-green font-semibold">
                          {companyData.domain_age_years ? `${companyData.domain_age_years} Years Old` : 'N/A'}
                        </div>
                        <div className="text-text-dim text-[10px]">
                          Created: {companyData.registration_date ? companyData.registration_date.split('T')[0] : 'N/A'}
                        </div>
                      </div>

                      <div className="space-y-1">
                        <span className="text-text-dim text-[11px]">EXPIRATION & RENEWAL</span>
                        <div className={`font-semibold ${companyData.is_expiring_soon ? 'text-magenta-alert' : 'text-text-primary'}`}>
                          {companyData.days_until_expiry ? `${companyData.days_until_expiry} Days Remaining` : 'N/A'}
                        </div>
                        <div className="text-text-dim text-[10px]">
                          Expires: {companyData.expiration_date ? companyData.expiration_date.split('T')[0] : 'N/A'}
                        </div>
                      </div>

                      <div className="space-y-1">
                        <span className="text-text-dim text-[11px]">PRIVACY PROXY STATUS</span>
                        <div className="text-text-primary font-semibold">
                          {companyData.is_privacy_proxied ? (
                            <span className="text-yellow-400">Proxied ({companyData.privacy_proxy_service})</span>
                          ) : (
                            <span className="text-cyan-signal">Direct Public Record</span>
                          )}
                        </div>
                        <div className="text-text-dim text-[10px]">
                          Jurisdiction: {companyData.country || companyData.registrant_country || 'Global / US'}
                        </div>
                      </div>
                    </div>

                    <div className="flex flex-wrap items-center gap-2 pt-2 border-t border-border-dim/60 text-xs font-mono">
                      <span className="text-text-dim">Domain Lock Statuses:</span>
                      {companyData.status_codes && companyData.status_codes.length > 0 ? (
                        companyData.status_codes.map((st, idx) => (
                          <span key={idx} className="px-2 py-0.5 rounded bg-void border border-border-dim text-cyan-signal text-[11px]">
                            {st}
                          </span>
                        ))
                      ) : (
                        <span className="text-yellow-400">No Locks Active (Unlocked)</span>
                      )}
                    </div>
                  </div>

                  {/* Section 2: Email Security Posture & DKIM Enumeration */}
                  <div className="p-4 rounded-lg bg-void/40 border border-border-dim space-y-4">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="text-xs font-mono font-bold text-text-primary flex items-center gap-2">
                        <Mail className="w-4 h-4 text-magenta-alert" />
                        <span>Email Security & Phishing Feasibility (DMARC / DKIM / SPF)</span>
                      </div>
                      <div className="flex items-center gap-2 text-xs font-mono">
                        <span className="text-text-dim">DMARC Policy:</span>
                        <span className={`px-2 py-0.5 rounded text-[11px] font-bold uppercase border ${
                          emailSec.dmarc_policy === 'reject'
                            ? 'bg-success-green/10 text-success-green border-success-green/40'
                            : emailSec.dmarc_policy === 'quarantine'
                            ? 'bg-yellow-500/10 text-yellow-400 border-yellow-500/40'
                            : 'bg-magenta-alert/10 text-magenta-alert border-magenta-alert/40'
                        }`}>
                          p={emailSec.dmarc_policy || 'none'}
                        </span>
                      </div>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs font-mono">
                      <div className="p-3 rounded bg-void/60 border border-border-dim space-y-1">
                        <span className="text-text-dim text-[11px]">DMARC ENFORCEMENT</span>
                        <div className="text-text-primary">
                          Percentage: <strong className="text-cyan-signal">{emailSec.dmarc_pct || 100}%</strong>
                        </div>
                        {emailSec.dmarc_rua && (
                          <div className="text-[10px] text-text-dim truncate">
                            Report RUA: {emailSec.dmarc_rua}
                          </div>
                        )}
                      </div>

                      <div className="p-3 rounded bg-void/60 border border-border-dim space-y-1">
                        <span className="text-text-dim text-[11px]">DKIM CRYPTOGRAPHIC KEYS</span>
                        <div className="text-text-primary">
                          Discovered: <strong className="text-success-green">{emailSec.discovered_dkim_selectors?.length || 0} Selectors</strong>
                        </div>
                        <div className="text-[10px] text-text-dim">
                          {emailSec.discovered_dkim_selectors?.map(d => d.selector).join(', ') || 'No common selectors match'}
                        </div>
                      </div>

                      <div className="p-3 rounded bg-void/60 border border-border-dim space-y-1">
                        <span className="text-text-dim text-[11px]">SPF ORIGIN MECHANISM</span>
                        <div className="text-text-primary truncate">
                          {companyData.spf_record ? 'SPF Record Active' : 'No SPF Published'}
                        </div>
                        <div className="text-[10px] text-text-dim truncate">
                          {companyData.spf_record || '—'}
                        </div>
                      </div>
                    </div>

                    {/* Discovered DKIM Selectors Table */}
                    {emailSec.discovered_dkim_selectors && emailSec.discovered_dkim_selectors.length > 0 && (
                      <div className="space-y-2">
                        <div className="text-[11px] font-mono text-text-dim">CRYPTOGRAPHICALLY AUTHORIZED PLATFORMS (DKIM):</div>
                        <div className="flex flex-wrap gap-2">
                          {emailSec.discovered_dkim_selectors.map((dkim, idx) => (
                            <div key={idx} className="flex items-center gap-2 px-2.5 py-1 rounded bg-void border border-border-dim text-xs font-mono">
                              <Key className="w-3 h-3 text-cyan-signal" />
                              <span className="text-cyan-signal font-semibold">{dkim.selector}</span>
                              <span className="text-[10px] text-text-dim">({dkim.key_type})</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Mail Exchange Gateways Table */}
                    {companyData.mail_servers && companyData.mail_servers.length > 0 && (
                      <div className="overflow-x-auto pt-2">
                        <table className="w-full text-left text-xs font-mono">
                          <thead>
                            <tr className="border-b border-border-dim text-text-dim text-[11px]">
                              <th className="pb-2">MX HOSTNAME</th>
                              <th className="pb-2">PRIORITY</th>
                              <th className="pb-2">IDENTIFIED PROVIDER</th>
                              <th className="pb-2">RESOLVED IP</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-border-dim/60">
                            {companyData.mail_servers.map((m, idx) => (
                              <tr key={idx} className="hover:bg-void/40">
                                <td className="py-2 text-text-primary">{m.host}</td>
                                <td className="py-2 text-text-dim">{m.preference}</td>
                                <td className="py-2">
                                  <span className="px-1.5 py-0.5 rounded bg-cyan-signal/10 text-cyan-signal border border-cyan-signal/20 text-[10px]">
                                    {m.provider}
                                  </span>
                                </td>
                                <td className="py-2 text-cyan-signal">{m.ips?.join(', ') || 'Resolving'}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    )}
                  </div>

                  {/* Section 3: Live TLS Certificate & Cryptographic Telemetry */}
                  <div className="p-4 rounded-lg bg-void/40 border border-border-dim space-y-4">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="text-xs font-mono font-bold text-text-primary flex items-center gap-2">
                        <Key className="w-4 h-4 text-cyan-signal" />
                        <span>TLS / X.509 Certificate Intelligence & Wildcard Risk</span>
                      </div>
                      {tlsIntel.tls_version && (
                        <span className="px-2 py-0.5 rounded bg-cyan-signal/10 text-cyan-signal border border-cyan-signal/30 text-[11px] font-mono">
                          {tlsIntel.tls_version} ({tlsIntel.cipher})
                        </span>
                      )}
                    </div>

                    {tlsIntel.is_wildcard && (
                      <div className="p-3 rounded bg-yellow-500/10 border border-yellow-500/30 text-yellow-400 text-xs font-mono flex items-center gap-2">
                        <AlertTriangle className="w-4 h-4 shrink-0" />
                        <span>{tlsIntel.wildcard_risk}</span>
                      </div>
                    )}

                    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 text-xs font-mono">
                      <div className="space-y-1">
                        <span className="text-text-dim text-[11px]">ISSUER / CA</span>
                        <div className="text-text-primary font-semibold">{tlsIntel.issuer_cn || tlsIntel.issuer_org || 'Standard CA'}</div>
                        <div className="text-text-dim text-[10px]">{tlsIntel.issuer_org || 'Public Trust'}</div>
                      </div>

                      <div className="space-y-1">
                        <span className="text-text-dim text-[11px]">SUBJECT (CN)</span>
                        <div className="text-cyan-signal font-semibold">{tlsIntel.subject_cn || job.target_domain}</div>
                      </div>

                      <div className="space-y-1">
                        <span className="text-text-dim text-[11px]">CERTIFICATE VALIDITY</span>
                        <div className="text-success-green font-semibold">
                          {tlsIntel.days_remaining ? `${tlsIntel.days_remaining} Days Remaining` : 'Valid'}
                        </div>
                        <div className="text-text-dim text-[10px]">
                          {tlsIntel.valid_from ? tlsIntel.valid_from.split('T')[0] : '—'} to {tlsIntel.valid_to ? tlsIntel.valid_to.split('T')[0] : '—'}
                        </div>
                      </div>

                      <div className="space-y-1">
                        <span className="text-text-dim text-[11px]">KEY ALGORITHM</span>
                        <div className="text-text-primary font-semibold">{tlsIntel.key_algorithm || 'ECDSA / RSA'}</div>
                      </div>
                    </div>

                    {tlsIntel.sans && tlsIntel.sans.length > 0 && (
                      <div className="space-y-2 pt-2 border-t border-border-dim/60">
                        <div className="text-[11px] font-mono text-text-dim">SUBJECT ALTERNATIVE NAMES (SANs):</div>
                        <div className="flex flex-wrap gap-1.5">
                          {tlsIntel.sans.map((san, idx) => (
                            <span
                              key={idx}
                              className={`px-2 py-0.5 rounded text-[11px] font-mono border ${
                                san.startsWith('*.')
                                  ? 'bg-yellow-500/10 text-yellow-400 border-yellow-500/30 font-bold'
                                  : 'bg-void text-text-primary border-border-dim'
                              }`}
                            >
                              {san}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>

                  {/* Section 4: DNS Risks, AXFR Zone Transfer & Nameservers */}
                  <div className="p-4 rounded-lg bg-void/40 border border-border-dim space-y-4">
                    <div className="text-xs font-mono font-bold text-text-primary flex items-center gap-2">
                      <Server className="w-4 h-4 text-cyan-signal" />
                      <span>DNS Risk Assessment, Zone Transfer (AXFR) & Nameserver Hygiene</span>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      {/* Nameservers List */}
                      <div className="space-y-2">
                        <div className="text-[11px] font-mono text-text-dim">AUTHORITATIVE NAMESERVERS:</div>
                        <div className="flex flex-wrap gap-2">
                          {companyData.nameservers?.map((ns, i) => (
                            <div
                              key={i}
                              onClick={() => handleCopy(ns, `ns-${i}`)}
                              className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-void border border-border-dim hover:border-cyan-signal cursor-pointer text-xs font-mono text-cyan-signal transition-colors"
                            >
                              <span>{ns}</span>
                              {copiedText === `ns-${i}` ? <Check className="w-3 h-3 text-success-green" /> : <Copy className="w-3 h-3 text-text-dim" />}
                            </div>
                          ))}
                        </div>
                      </div>

                      {/* DNSSEC & Orphaned NS */}
                      <div className="space-y-2 text-xs font-mono">
                        <div className="flex justify-between">
                          <span className="text-text-dim">DNSSEC Security:</span>
                          <span className="text-text-primary font-semibold">{dnsRisks.dnssec_status || 'Unsigned / Standard'}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-text-dim">Orphaned / Dangling NS:</span>
                          <span className={dnsRisks.has_orphaned_ns ? 'text-magenta-alert font-bold' : 'text-success-green font-semibold'}>
                            {dnsRisks.has_orphaned_ns ? 'Dangling NS Detected (Takeover Risk)' : 'None (All NS Resolved)'}
                          </span>
                        </div>
                      </div>
                    </div>

                    {/* AXFR Tested Nameserver Telemetry */}
                    {dnsRisks.axfr_tested_servers && dnsRisks.axfr_tested_servers.length > 0 && (
                      <div className="overflow-x-auto pt-2 border-t border-border-dim/60">
                        <table className="w-full text-left text-xs font-mono">
                          <thead>
                            <tr className="border-b border-border-dim text-text-dim text-[11px]">
                              <th className="pb-2">NAMESERVER HOST</th>
                              <th className="pb-2">NS IP ADDRESS</th>
                              <th className="pb-2">AXFR ZONE TRANSFER RESULT</th>
                              <th className="pb-2">RECORDS DUMPED</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-border-dim/60">
                            {dnsRisks.axfr_tested_servers.map((s, idx) => (
                              <tr key={idx} className="hover:bg-void/40">
                                <td className="py-2 text-text-primary">{s.nameserver}</td>
                                <td className="py-2 text-cyan-signal">{s.ip}</td>
                                <td className="py-2">
                                  <span className={`px-1.5 py-0.5 rounded text-[10px] border ${
                                    s.axfr_status.includes('VULNERABLE')
                                      ? 'bg-magenta-alert/10 text-magenta-alert border-magenta-alert/40'
                                      : 'bg-success-green/10 text-success-green border-success-green/40'
                                  }`}>
                                    {s.axfr_status}
                                  </span>
                                </td>
                                <td className="py-2 text-text-dim">{s.records_dumped}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    )}
                  </div>

                  {/* Section 5: Network Scope & ASN Attribution */}
                  <div className="p-4 rounded-lg bg-void/40 border border-border-dim space-y-3">
                    <div className="text-xs font-mono font-bold text-text-primary flex items-center gap-2">
                      <Layers className="w-4 h-4 text-yellow-400" />
                      <span>Network Scope, ASN Attribution & BGP Ranges</span>
                    </div>
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs font-mono">
                      <div className="space-y-1">
                        <span className="text-text-dim text-[11px]">AUTONOMOUS SYSTEM (ASN)</span>
                        <div className="text-text-primary font-semibold">{companyData.asn || 'N/A'} ({companyData.asn_description || 'Unknown'})</div>
                      </div>
                      <div className="space-y-1">
                        <span className="text-text-dim text-[11px]">INFRASTRUCTURE ATTRIBUTION</span>
                        <div className="text-cyan-signal font-semibold">{companyData.asn_infrastructure_type || 'Shared Anycast CDN'}</div>
                      </div>
                      <div className="space-y-1">
                        <span className="text-text-dim text-[11px]">PRIMARY IP / ROUTING</span>
                        <div className="text-text-primary">{companyData.primary_ips?.join(', ') || 'N/A'}</div>
                      </div>
                    </div>
                  </div>
                </>
              )}
            </div>
          )}

          {/* 1. Subdomains & IPs */}
          {activeTab === 'subdomains' && (
            <div className="space-y-3">
              {mergedAssets.length === 0 ? (
                <p className="text-xs text-text-dim font-mono py-4 text-center">
                  Awaiting subdomain enumeration stage completion...
                </p>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs">
                    <thead>
                      <tr className="border-b border-border-dim text-text-dim font-mono text-[11px]">
                        <th className="pb-2.5">SUBDOMAIN / ASSET</th>
                        <th className="pb-2.5">RESOLVED IP</th>
                        <th className="pb-2.5">CDN / WAF STATUS</th>
                        <th className="pb-2.5">CLOUD / CNAME POINTER</th>
                        <th className="pb-2.5">SOURCE</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-border-dim/60 font-mono">
                      {mergedAssets.map((asset) => {
                        return (
                          <tr key={asset.host} className="hover:bg-void/40 transition-colors">
                            <td className="py-2.5 text-text-primary font-medium">{asset.host}</td>
                            <td className="py-2.5 text-cyan-signal">
                              <TechnicalData value={asset.ips || 'Direct Query'} />
                            </td>
                            <td className="py-2.5">
                              {asset.isCdn ? (
                                <span className="px-2 py-0.5 rounded bg-yellow-500/10 text-yellow-400 border border-yellow-500/30 text-[10px]">
                                  CDN ({asset.cdnProvider || 'Cloudflare'})
                                </span>
                              ) : (
                                <span className="px-2 py-0.5 rounded bg-success-green/10 text-success-green border border-success-green/30 text-[10px]">
                                  Direct Origin
                                </span>
                              )}
                            </td>
                            <td className="py-2.5">
                              {asset.cloudService ? (
                                <span className="px-1.5 py-0.5 rounded bg-cyan-signal/10 text-cyan-signal border border-cyan-signal/30 text-[10px]">
                                  {asset.cloudService}
                                </span>
                              ) : asset.cnames && asset.cnames.length > 0 ? (
                                <span className="text-text-dim text-[11px] truncate max-w-[160px] inline-block">{asset.cnames[0]}</span>
                              ) : (
                                <span className="text-text-dim/50">—</span>
                              )}
                            </td>
                            <td className="py-2.5 text-text-dim text-[11px]">{asset.source}</td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}

          {/* 3. People & Social OSINT */}
          {activeTab === 'people' && (
            <div className="space-y-3">
              {peopleFindings.length === 0 ? (
                <p className="text-xs text-text-dim font-mono py-4 text-center">
                  Awaiting people intelligence and contact harvesting stage...
                </p>
              ) : (
                <div className="space-y-4">
                  {peopleFindings.map((f) => {
                    const data = f.data || {};
                    const peopleList = data.people || [];
                    const emailPattern = data.email_pattern || 'Not inferred';

                    return (
                      <div key={f.id} className="space-y-4">
                        <div className="flex flex-wrap items-center justify-between gap-3 p-3 rounded bg-void/50 border border-border-dim text-xs font-mono">
                          <div>
                            <span className="text-text-dim">Corporate Email Syntax: </span>
                            <span className="text-cyan-signal font-semibold">{emailPattern}</span>
                          </div>
                          <div className="flex gap-4">
                            <span>Confirmed: <strong className="text-success-green">{data.confirmed_count || 0}</strong></span>
                            <span>Deliverable / Verified: <strong className="text-cyan-signal">{data.deliverable_count || 0}</strong></span>
                            <span>Pattern Inferred: <strong className="text-yellow-400">{data.inferred_count || 0}</strong></span>
                          </div>
                        </div>

                        <div className="overflow-x-auto">
                          <table className="w-full text-left text-xs font-mono">
                            <thead>
                              <tr className="border-b border-border-dim text-text-dim text-[11px]">
                                <th className="pb-2.5">STAFF NAME</th>
                                <th className="pb-2.5">ROLE / TITLE</th>
                                <th className="pb-2.5">EMAIL ADDRESS</th>
                                <th className="pb-2.5">PROFILE LINK</th>
                                <th className="pb-2.5">PLATFORM</th>
                                <th className="pb-2.5">DELIVERABILITY & STATUS</th>
                                <th className="pb-2.5">CONFIDENCE</th>
                              </tr>
                            </thead>
                            <tbody className="divide-y divide-border-dim/60">
                              {peopleList.map((p, idx) => (
                                <tr key={idx} className="hover:bg-void/40 transition-colors">
                                  <td className="py-2.5 font-sans font-semibold text-text-primary">
                                    {p.name || 'Organization Staff'}
                                  </td>
                                  <td className="py-2.5 text-text-dim">{p.title || 'Staff / Member'}</td>
                                  <td className="py-2.5 text-cyan-signal">
                                    {p.email ? <TechnicalData value={p.email} /> : '—'}
                                  </td>
                                  <td className="py-2.5">
                                    {p.profile_url ? (
                                      <a
                                        href={p.profile_url}
                                        target="_blank"
                                        rel="noopener noreferrer"
                                        className="text-cyan-signal hover:underline flex items-center gap-1"
                                      >
                                        <span>{p.platform || 'Profile'}</span>
                                        <ExternalLink className="w-3 h-3" />
                                      </a>
                                    ) : (
                                      '—'
                                    )}
                                  </td>
                                  <td className="py-2.5 text-text-dim">{p.platform || 'OSINT'}</td>
                                  <td className="py-2.5">
                                    {p.deliverability === 'deliverable' ? (
                                      <span className="px-2 py-0.5 rounded bg-success-green/10 text-success-green border border-success-green/30 text-[10px]">
                                        SMTP Deliverable
                                      </span>
                                    ) : p.deliverability === 'catch_all' ? (
                                      <span className="px-2 py-0.5 rounded bg-yellow-500/10 text-yellow-400 border border-yellow-500/30 text-[10px]">
                                        Catch-All Pattern
                                      </span>
                                    ) : p.verification_status === 'Direct Scrape' ? (
                                      <span className="px-2 py-0.5 rounded bg-cyan-signal/10 text-cyan-signal border border-cyan-signal/30 text-[10px]">
                                        Direct Scrape
                                      </span>
                                    ) : p.inferred ? (
                                      <span className="px-2 py-0.5 rounded bg-yellow-500/10 text-yellow-400 border border-yellow-500/30 text-[10px]">
                                        Inferred Pattern
                                      </span>
                                    ) : (
                                      <span className="px-2 py-0.5 rounded bg-border-dim text-text-dim text-[10px]">
                                        Public Handle
                                      </span>
                                    )}
                                  </td>
                                  <td className="py-2.5 font-bold text-text-primary">{p.confidence || 70}%</td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          )}

          {/* 4. Infrastructure & Target Hosts Command Center */}
          {activeTab === 'infrastructure' && (
            <div className="space-y-4">
              {hostInventory.length === 0 ? (
                <p className="text-xs text-text-dim font-mono py-8 text-center">
                  Awaiting infrastructure port sweep and service fingerprinting completion...
                </p>
              ) : (
                <div className="space-y-4">
                  {/* Summary Bar & Global Controls */}
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 flex-1">
                      <div className="p-3 rounded bg-void/40 border border-border-dim">
                        <span className="text-[10px] font-mono text-text-dim uppercase tracking-wider block">Target Host Machines</span>
                        <span className="text-lg font-mono font-bold text-text-primary">{hostInventory.length}</span>
                      </div>
                      <div className="p-3 rounded bg-void/40 border border-border-dim">
                        <span className="text-[10px] font-mono text-text-dim uppercase tracking-wider block">Open Services / Ports</span>
                        <span className="text-lg font-mono font-bold text-cyan-signal">{portFindings.length}</span>
                      </div>
                      <div className="p-3 rounded bg-void/40 border border-border-dim">
                        <span className="text-[10px] font-mono text-text-dim uppercase tracking-wider block">Detected Tech Stacks</span>
                        <span className="text-lg font-mono font-bold text-text-primary">{fpFindings.length}</span>
                      </div>
                      <div className="p-3 rounded bg-void/40 border border-border-dim">
                        <span className="text-[10px] font-mono text-text-dim uppercase tracking-wider block">Identified Exploits & Risks</span>
                        <span className={`text-lg font-mono font-bold ${vulnFindings.length > 0 ? 'text-magenta-alert' : 'text-success-green'}`}>
                          {vulnFindings.length}
                        </span>
                      </div>
                    </div>
                    <div className="flex items-center gap-2 self-end sm:self-center shrink-0 font-mono text-xs">
                      <button
                        onClick={() => expandAllHosts(hostInventory.map((h) => h.ip))}
                        className="px-2.5 py-1.5 rounded bg-void border border-border-dim hover:border-cyan-signal/50 text-text-dim hover:text-cyan-signal transition-colors flex items-center gap-1"
                      >
                        <ChevronDown className="w-3.5 h-3.5" />
                        <span>Expand All</span>
                      </button>
                      <button
                        onClick={() => collapseAllHosts(hostInventory.map((h) => h.ip))}
                        className="px-2.5 py-1.5 rounded bg-void border border-border-dim hover:border-border-bright text-text-dim hover:text-text-primary transition-colors flex items-center gap-1"
                      >
                        <ChevronUp className="w-3.5 h-3.5" />
                        <span>Collapse All</span>
                      </button>
                    </div>
                  </div>

                  {/* Automated Intelligence & Telemetry Disclaimer */}
                  <AiDisclaimer className="mb-1" />

                  {/* Threat Prioritization Status Bar */}
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 px-3 py-2 rounded bg-void/60 border border-border-dim text-xs font-mono">
                    <div className="flex items-center gap-2 text-[11px]">
                      <ShieldAlert className="w-4 h-4 text-magenta-alert shrink-0" />
                      <span className="text-text-primary font-bold">Threat-Prioritized View:</span>
                      <span className="text-text-dim">Hosts with Critical & High CVEs automatically surfaced at the top.</span>
                    </div>
                    {hostInventory.some(h => h.criticalCount > 0 || h.highCount > 0) && (
                      <span className="px-2 py-0.5 rounded bg-magenta-alert/15 text-magenta-alert border border-magenta-alert/40 text-[10px] font-bold self-start sm:self-center">
                        ⚠️ {hostInventory.filter(h => h.criticalCount > 0 || h.highCount > 0).length} High-Risk Hosts Surfaced
                      </span>
                    )}
                  </div>

                  {/* Host Cards List */}
                  {hostInventory.map((host, idx) => {
                    const hostKey = host.ip;
                    const isCritical = host.criticalCount > 0;
                    const isHigh = host.highCount > 0;
                    const isExpanded = expandedHosts[hostKey] !== undefined ? expandedHosts[hostKey] : (idx === 0 || host.vulnerabilities.length > 0);
                    const isDomainsExpanded = !!expandedDomains[hostKey];
                    const allDomains = host.hostnames || [];
                    const displayedDomains = isDomainsExpanded ? allDomains : allDomains.slice(0, 3);
                    const remainingDomainsCount = allDomains.length - 3;

                    return (
                      <div
                        key={hostKey}
                        className={`rounded-lg border overflow-hidden shadow-panel transition-all ${
                          isCritical
                            ? 'border-magenta-alert/60 bg-magenta-alert/5 shadow-glow-magenta-sm'
                            : isHigh
                            ? 'border-orange-500/50 bg-orange-500/5'
                            : 'border-border-dim bg-void/40 hover:border-border-bright/80'
                        }`}
                      >
                        {/* Server Header - Clickable Accordion Bar */}
                        <div
                          onClick={() => toggleHost(hostKey)}
                          className="p-4 bg-void/80 border-b border-border-dim flex flex-col md:flex-row md:items-center justify-between gap-3 cursor-pointer select-none hover:bg-void/60 transition-colors"
                        >
                          <div className="flex items-start md:items-center gap-3 min-w-0 flex-1">
                            <div className={`p-2.5 rounded border shrink-0 mt-0.5 md:mt-0 ${
                              isCritical
                                ? 'bg-magenta-alert/15 border-magenta-alert/40 text-magenta-alert'
                                : isHigh
                                ? 'bg-orange-500/15 border-orange-500/40 text-orange-400'
                                : 'bg-cyan-signal/10 border-cyan-signal/30 text-cyan-signal'
                            }`}>
                              <Server className="w-5 h-5" />
                            </div>
                            <div className="min-w-0 flex-1">
                              <div className="flex flex-wrap items-center gap-2">
                                <span className="font-mono font-bold text-sm text-text-primary">{host.ip}</span>
                                {isCritical && (
                                  <span className="px-2 py-0.5 rounded bg-magenta-alert/20 text-magenta-alert border border-magenta-alert/60 text-[10px] font-mono font-bold animate-pulse flex items-center gap-1">
                                    <AlertOctagon className="w-3 h-3" />
                                    <span>{host.criticalCount} CRITICAL CVE</span>
                                  </span>
                                )}
                                {!isCritical && isHigh && (
                                  <span className="px-2 py-0.5 rounded bg-orange-500/20 text-orange-400 border border-orange-500/60 text-[10px] font-mono font-bold flex items-center gap-1">
                                    <AlertTriangle className="w-3 h-3" />
                                    <span>{host.highCount} HIGH CVE</span>
                                  </span>
                                )}
                                {host.isCdn ? (
                                  <span className="px-2 py-0.5 rounded bg-yellow-500/10 text-yellow-400 border border-yellow-500/30 text-[10px] font-mono font-bold">
                                    CDN Edge ({host.cdnProvider || 'Cloudflare'})
                                  </span>
                                ) : (
                                  <span className="px-2 py-0.5 rounded bg-success-green/10 text-success-green border border-success-green/30 text-[10px] font-mono font-bold">
                                    Direct Origin Server
                                  </span>
                                )}
                              </div>
                              <div className="text-xs text-text-dim font-mono mt-1.5 flex flex-wrap items-center gap-1.5">
                                <span className="text-text-dim/80 font-semibold">Domains ({allDomains.length}):</span>
                                {allDomains.length > 0 ? (
                                  <>
                                    {displayedDomains.map((h, i) => (
                                      <span key={i} className="text-cyan-signal font-mono font-medium">
                                        {h}{i < displayedDomains.length - 1 ? ',' : ''}
                                      </span>
                                    ))}
                                    {remainingDomainsCount > 0 && (
                                      <button
                                        type="button"
                                        onClick={(e) => {
                                          e.stopPropagation();
                                          toggleDomain(hostKey);
                                        }}
                                        className="ml-1 px-1.5 py-0.5 rounded bg-cyan-signal/15 hover:bg-cyan-signal/25 text-cyan-signal text-[10px] font-mono font-bold border border-cyan-signal/30 transition-colors"
                                      >
                                        {isDomainsExpanded ? 'Hide' : `+${remainingDomainsCount} more`}
                                      </button>
                                    )}
                                  </>
                                ) : (
                                  <span className="text-text-dim/60">—</span>
                                )}
                              </div>

                              {/* Expanded Domains Drawer */}
                              {isDomainsExpanded && allDomains.length > 3 && (
                                <div
                                  onClick={(e) => e.stopPropagation()}
                                  className="mt-2 p-2 rounded bg-panel-elevated border border-border-dim text-xs font-mono max-h-32 overflow-y-auto flex flex-wrap gap-1 shadow-sm"
                                >
                                  {allDomains.map((domain, dIdx) => (
                                    <span
                                      key={dIdx}
                                      className="px-1.5 py-0.5 rounded bg-void border border-border-dim text-[11px] text-cyan-signal"
                                    >
                                      {domain}
                                    </span>
                                  ))}
                                </div>
                              )}
                            </div>
                          </div>

                          {/* Quick Host Stats & Accordion Toggle */}
                          <div className="shrink-0 flex items-center gap-2 text-xs font-mono self-start md:self-center">
                            <span className="px-2.5 py-1 rounded bg-void border border-border-dim text-text-dim">
                              <span className="text-text-primary font-bold">{host.ports.length}</span> Ports
                            </span>
                            <span className="px-2.5 py-1 rounded bg-void border border-border-dim text-text-dim">
                              <span className="text-cyan-signal font-bold">{host.technologies.length}</span> Apps
                            </span>
                            {host.vulnerabilities.length > 0 ? (
                              <span className="px-2.5 py-1 rounded bg-magenta-alert/15 border border-magenta-alert/40 text-magenta-alert font-bold flex items-center gap-1">
                                <AlertOctagon className="w-3.5 h-3.5" />
                                <span>{host.vulnerabilities.length} CVEs / Risks</span>
                              </span>
                            ) : (
                              <span className="px-2.5 py-1 rounded bg-success-green/10 border border-success-green/30 text-success-green font-semibold">
                                0 Risks
                              </span>
                            )}
                            <div className="p-1 rounded text-text-dim hover:text-cyan-signal ml-1">
                              {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                            </div>
                          </div>
                        </div>

                        {/* Collapsible Server Body */}
                        {isExpanded && (
                          <div className="p-4 space-y-4 border-t border-border-dim/40 animate-fadeIn">
                            {/* 1. Deployed Apps & Web Frameworks */}
                            {host.technologies.length > 0 && (
                              <div className="space-y-1.5">
                                <span className="text-[11px] font-mono text-text-dim uppercase tracking-wider font-bold block">
                                  Deployed Applications & Frameworks
                                </span>
                                <div className="flex flex-wrap gap-1.5">
                                  {host.technologies.map((t, idx) => {
                                    const name = t.name || t;
                                    const ver = t.version ? ` v${t.version}` : '';
                                    return (
                                      <span
                                        key={idx}
                                        className="px-2.5 py-1 rounded bg-void border border-border-bright text-xs font-mono text-cyan-signal font-semibold"
                                      >
                                        {name}{ver}
                                      </span>
                                    );
                                  })}
                                </div>
                              </div>
                            )}

                            {/* 2. Active Services & Open Ports Table */}
                            <div className="space-y-1.5">
                              <span className="text-[11px] font-mono text-text-dim uppercase tracking-wider font-bold block">
                                Active Services & Verified Port Probes ({host.ports.length})
                              </span>
                              {host.ports.length === 0 ? (
                                <p className="text-xs text-text-dim font-mono py-2 italic">
                                  No open TCP/UDP ports detected on this host.
                                </p>
                              ) : (
                                <div className="overflow-x-auto max-h-96 overflow-y-auto border border-border-dim rounded bg-void/30">
                                  <table className="w-full text-left text-xs font-mono">
                                    <thead className="sticky top-0 bg-void/95 backdrop-blur z-10">
                                      <tr className="border-b border-border-dim text-text-dim text-[11px]">
                                        <th className="py-2 px-3">PORT / PROTO</th>
                                        <th className="py-2 px-3">SERVICE & PRODUCT</th>
                                        <th className="py-2 px-3">VERIFIED VERSION</th>
                                        <th className="py-2 px-3">EVIDENCE & PROOF</th>
                                        <th className="py-2 px-3">STATE</th>
                                      </tr>
                                    </thead>
                                    <tbody className="divide-y divide-border-dim/50">
                                      {host.ports.map((p, pIdx) => {
                                        const portProofKey = `${host.ip}-${p.port}-${p.protocol}`;
                                        const isProofExpanded = expandedProof[portProofKey];
                                        const proofText = p.banner || p.evidence || (p.cpe && p.cpe.length > 0 ? p.cpe.join(', ') : null);

                                        return (
                                          <tr key={pIdx} className="hover:bg-white/[0.02] transition-colors">
                                            <td className="py-2.5 px-3">
                                              <span className="text-text-primary font-bold">{p.port}</span>
                                              <span className="text-text-dim text-[10px] uppercase ml-1">/{p.protocol || 'tcp'}</span>
                                            </td>
                                            <td className="py-2.5 px-3">
                                              <div className="text-text-primary font-semibold">{p.product || p.service}</div>
                                              <div className="text-text-dim text-[10px] uppercase">{p.service}</div>
                                            </td>
                                            <td className="py-2.5 px-3">
                                              {p.version ? (
                                                <span className="px-2 py-0.5 rounded bg-void border border-border-bright text-cyan-signal font-bold text-[11px]">
                                                  {p.version}
                                                </span>
                                              ) : (
                                                <span className="text-text-dim/50">—</span>
                                              )}
                                            </td>
                                            <td className="py-2.5 px-3">
                                              {proofText ? (
                                                <div>
                                                  <button
                                                    onClick={() => toggleProof(portProofKey)}
                                                    className="text-[11px] font-mono text-cyan-signal hover:underline flex items-center gap-1"
                                                  >
                                                    <Terminal className="w-3 h-3" />
                                                    <span>{isProofExpanded ? 'Hide Raw Banner' : 'View Banner Proof'}</span>
                                                  </button>
                                                  {isProofExpanded && (
                                                    <div className="mt-1.5 p-2 rounded bg-panel-elevated border border-border-dim text-[10px] font-mono text-text-primary whitespace-pre-wrap max-w-lg shadow-sm">
                                                      {proofText}
                                                    </div>
                                                  )}
                                                </div>
                                              ) : (
                                                <span className="text-text-dim/40 text-[11px]">Direct socket handshake</span>
                                              )}
                                            </td>
                                            <td className="py-2.5 px-3">
                                              <span className="px-2 py-0.5 rounded bg-success-green/10 text-success-green border border-success-green/30 text-[10px]">
                                                {p.state || 'open'}
                                              </span>
                                            </td>
                                          </tr>
                                        );
                                      })}
                                    </tbody>
                                  </table>
                                </div>
                              )}
                            </div>

                            {/* 3. Actionable Vulnerabilities & Misconfigurations */}
                            {host.vulnerabilities.length > 0 && (
                              <div className="space-y-2 pt-2 border-t border-border-dim/60">
                                <span className="text-[11px] font-mono text-cyan-signal uppercase tracking-wider font-bold flex items-center gap-1.5">
                                  <ShieldAlert className="w-3.5 h-3.5 text-cyan-signal" />
                                  <span>Evaluated Host Vulnerabilities & Exposures ({host.vulnerabilities.length})</span>
                                </span>
                                <div className="grid grid-cols-1 gap-2.5">
                                  {host.vulnerabilities.map((v, vIdx) => {
                                    const findingStatus = v.finding_status || (v.evidence_tier === 'ACTIVE_EXPLOIT_PROOF' || v.status === 'confirmed' ? 'CONFIRMED' : 'POTENTIALLY_AFFECTED');
                                    const isNotVuln = findingStatus === 'NOT_VULNERABLE' || v.status === 'patched';
                                    const isNotApplicable = findingStatus === 'NOT_APPLICABLE' || v.status === 'not_applicable' || v.evidence_tier === 'PLATFORM_MISMATCH';
                                    const isConfirmed = findingStatus === 'CONFIRMED';
                                    const isLikely = findingStatus === 'LIKELY_VULNERABLE';
                                    const isCritical = v.severity === 'critical';
                                    const isHigh = v.severity === 'high';

                                    return (
                                      <div
                                        key={vIdx}
                                        className={`p-3.5 rounded border transition-all ${
                                          isNotVuln
                                            ? 'bg-emerald-950/20 border-emerald-500/40 text-text-primary'
                                            : isNotApplicable
                                            ? 'bg-void/40 border-border-dim opacity-70 text-text-dim'
                                            : isConfirmed
                                            ? 'bg-magenta-alert/15 border-magenta-alert/60 shadow-glow-magenta-sm'
                                            : isLikely
                                            ? 'bg-yellow-500/10 border-yellow-500/40'
                                            : 'bg-void/50 border-border-dim'
                                        }`}
                                      >
                                        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                                          <div className="flex items-center gap-2 flex-wrap">
                                            <SeverityBadge severity={isNotVuln || isNotApplicable ? 'info' : (v.severity || 'low')} />
                                            <span className="text-xs font-mono font-bold text-text-primary">
                                              {v.title || v.name || v.cve_id || 'Vulnerability Finding'}
                                            </span>
                                          </div>
                                          <div className="flex items-center gap-1.5 flex-wrap font-mono text-[9px] font-bold uppercase tracking-wider">
                                            {/* 4-Tier Evidence Taxonomy Badge */}
                                            {isNotVuln && (
                                              <span className="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-400 border border-emerald-500/50 flex items-center gap-1 shadow-glow-green-sm">
                                                <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                                                <span>NOT VULNERABLE (DISTRO BACKPORT)</span>
                                              </span>
                                            )}
                                            {isNotApplicable && (
                                              <span className="px-2 py-0.5 rounded bg-zinc-700/30 text-text-dim border border-border-dim flex items-center gap-1">
                                                <Ban className="w-3 h-3 text-text-dim" />
                                                <span>NOT APPLICABLE (PLATFORM MISMATCH)</span>
                                              </span>
                                            )}
                                            {isConfirmed && !isNotApplicable && (
                                              <span className="px-2 py-0.5 rounded bg-magenta-alert/20 text-magenta-alert border border-magenta-alert/50 flex items-center gap-1 shadow-glow-magenta-sm">
                                                <AlertOctagon className="w-3 h-3 text-magenta-alert" />
                                                <span>CONFIRMED (ACTIVE PROOF)</span>
                                              </span>
                                            )}
                                            {isLikely && !isNotApplicable && (
                                              <span className="px-2 py-0.5 rounded bg-yellow-500/20 text-yellow-400 border border-yellow-500/50">
                                                LIKELY VULNERABLE
                                              </span>
                                            )}
                                            {!isNotVuln && !isNotApplicable && !isConfirmed && !isLikely && (
                                              <span className="px-2 py-0.5 rounded bg-cyan-500/15 text-cyan-signal border border-cyan-500/30">
                                                POTENTIALLY AFFECTED / ADVISORY
                                              </span>
                                            )}

                                            {/* EPSS Exploit Prediction 30-Day Forecast */}
                                            {v.epss_score !== undefined && v.epss_score > 0 && !isNotVuln && !isNotApplicable && (
                                              <span className={`px-1.5 py-0.5 rounded flex items-center gap-1 border ${
                                                v.epss_score >= 0.70
                                                  ? 'bg-magenta-alert/25 text-magenta-alert border-magenta-alert/50 shadow-glow-magenta-sm font-bold'
                                                  : v.epss_score >= 0.20
                                                  ? 'bg-yellow-500/20 text-yellow-400 border-yellow-500/40 font-semibold'
                                                  : 'bg-void/80 text-text-dim border-border-dim'
                                              }`}>
                                                <TrendingUp className="w-2.5 h-2.5" />
                                                <span>EPSS {v.epss_percent || `${(v.epss_score * 100).toFixed(1)}%`}</span>
                                                {v.epss_percentile_rank && (
                                                  <span className="opacity-70 text-[8px]">({v.epss_percentile_rank})</span>
                                                )}
                                              </span>
                                            )}

                                            {/* Strictly Verified CISA KEV */}
                                            {v.cisa_kev && !isNotVuln && !isNotApplicable && (
                                              <span className="px-1.5 py-0.5 rounded bg-magenta-alert text-white shadow-glow-magenta-sm">
                                                CISA KEV
                                              </span>
                                            )}

                                            {/* Public Exploit / PoC Type */}
                                            {v.exploit_available && !isNotVuln && !isNotApplicable && (
                                              <span className="px-1.5 py-0.5 rounded bg-cyan-signal/20 text-cyan-signal border border-cyan-signal/40">
                                                {v.exploit_type || 'Public PoC'}
                                              </span>
                                            )}
                                          </div>
                                        </div>

                                        {/* Normalized NIST CPE 2.3 Chip */}
                                        {(v.cpe_23 || (v.cpe && v.cpe[0])) && (
                                          <div className="mt-2 flex items-center gap-1.5 text-[10px] font-mono text-text-dim/80">
                                            <span className="px-1.5 py-0.5 rounded bg-void border border-border-dim text-[9px] text-text-dim uppercase font-bold tracking-wider">
                                              CPE 2.3
                                            </span>
                                            <code className="text-cyan-signal/90 font-mono select-all truncate max-w-full">
                                              {v.cpe_23 || v.cpe[0]}
                                            </code>
                                          </div>
                                        )}

                                        {/* Multi-Dimensional Threat Intelligence Grid */}
                                        <div className="mt-2.5 grid grid-cols-2 sm:grid-cols-4 gap-1.5 p-2.5 rounded bg-panel-elevated border border-border-dim text-[10px] font-mono shadow-sm">
                                          <div>
                                            <span className="text-text-dim block uppercase text-[8px] font-semibold">CVSS Base</span>
                                            <span className="text-text-primary font-bold">{v.cvss_score || 'N/A'}</span>
                                          </div>
                                          <div>
                                            <span className="text-text-dim block uppercase text-[8px] font-semibold">30-Day EPSS Forecast</span>
                                            <span className={v.epss_score >= 0.70 ? 'text-magenta-alert font-bold' : 'text-text-primary font-bold'}>
                                              {v.epss_percent || '0.1%'}
                                            </span>
                                          </div>
                                          <div>
                                            <span className="text-text-dim block uppercase text-[8px] font-semibold">CISA KEV Verified</span>
                                            <span className={v.cisa_kev ? 'text-magenta-alert font-bold' : 'text-text-dim font-medium'}>
                                              {v.cisa_kev ? 'YES (Active Exploitation)' : 'NO'}
                                            </span>
                                          </div>
                                          <div>
                                            <span className="text-text-dim block uppercase text-[8px] font-semibold">Distro Security Status</span>
                                            <span className={isNotVuln ? 'text-success-green font-bold' : isConfirmed ? 'text-magenta-alert font-bold' : 'text-amber-500 font-bold'}>
                                              {v.finding_status || 'ADVISORY'}
                                            </span>
                                          </div>
                                        </div>

                                        {v.description && (
                                          <p className="text-xs text-text-dim leading-relaxed mt-2.5 font-mono">
                                            {v.description}
                                          </p>
                                        )}

                                        {/* Proof & Evidence Ledger Block */}
                                        {v.evidence_proof && (
                                          <div className={`mt-2.5 p-2.5 rounded border text-[11px] font-mono shadow-sm ${
                                            isNotVuln
                                              ? 'bg-success-green/10 border-success-green/30 text-success-green'
                                              : 'bg-panel-subtle border-border-dim text-cyan-signal'
                                          }`}>
                                            <span className="text-text-dim text-[10px] uppercase block font-bold mb-0.5">
                                              {isNotVuln
                                                ? 'Distribution Backport Security Proof:'
                                                : isConfirmed
                                                ? 'Verified Payload / Active Port Handshake Evidence:'
                                                : 'Banner & Version Correlation Proof:'}
                                            </span>
                                            <div className="leading-relaxed">{v.evidence_proof}</div>
                                            {v.mathematical_proof && (
                                              <div className="mt-1 text-[10px] text-text-dim font-bold">
                                                Mathematical Proof: <span className="text-text-primary">{v.mathematical_proof}</span>
                                              </div>
                                            )}
                                          </div>
                                        )}

                                        {/* Remediation Advice */}
                                        {v.remediation && (
                                          <div className="mt-2 text-xs font-mono text-text-dim flex items-start gap-1.5">
                                            <span className="text-success-green font-bold shrink-0">Remediation:</span>
                                            <span className="text-text-primary/90">{v.remediation}</span>
                                          </div>
                                        )}
                                      </div>
                                    );
                                  })}
                                </div>
                              </div>
                            )}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          )}



          {/* 6. Public Documents & Exposure Signals */}
          {activeTab === 'documents' && (
            <ExposureView scanId={scanId} />
          )}

          {/* 7. Attack Surface Hierarchy */}
          {activeTab === 'attack_surface' && (
            <AttackSurfaceView
              scanId={scanId}
              subdomains={mergedAssets.map((a) => ({ subdomain: a.host, ips: a.ips ? a.ips.split(', ').filter(Boolean) : [], is_cdn: a.isCdn, cdn_provider: a.cdnProvider }))}
              ports={portFindings.map((p) => p.data)}
              fingerprints={fpFindings.map((f) => f.data)}
              vulns={vulnFindings.map((v) => v.data)}
            />
          )}

          {/* 8. Interactive Force-Directed Intelligence Graph */}
          {activeTab === 'graph' && (
            <GraphView scanId={scanId} />
          )}
        </div>
      </div>
    </div>
  );
}
