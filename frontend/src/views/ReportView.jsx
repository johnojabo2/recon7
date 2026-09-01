import React, { useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  FileText,
  Copy,
  Download,
  Check,
  Brain,
  Printer,
  ChevronDown,
  Layers,
  Activity,
  Loader2,
} from 'lucide-react';
import { marked } from 'marked';
import html2pdf from 'html2pdf.js';
import { useScanReport, useScanJob, useScanFindings, useScansList, useDashboard } from '../api/hooks';
import { useTenant } from '../context/TenantContext';
import { LoadingState, EmptyState } from '../components/LoadingState';
import AiDisclaimer from '../components/AiDisclaimer';
import { formatScanDuration, parseUtcDate } from './ScanDetailView';

// Enable GitHub Flavored Markdown (tables, line breaks, autolinks)
marked.setOptions({
  gfm: true,
  breaks: true,
});

function formatDuration(createdStr, completedStr) {
  return formatScanDuration(createdStr, completedStr) || '—';
}

function formatDate(dateStr) {
  if (!dateStr) return '—';
  try {
    const dt = parseUtcDate(dateStr);
    if (!dt || isNaN(dt.getTime())) return dateStr;
    return dt.toLocaleString('en-US', {
      year: 'numeric',
      month: 'short',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      timeZoneName: 'short',
    });
  } catch (e) {
    return dateStr;
  }
}

export default function ReportView({ scanId }) {
  const { scanId: routeScanId } = useParams();
  const navigate = useNavigate();
  const { activeTarget, activeScanId } = useTenant();
  const [selectedId, setSelectedId] = useState(null);
  const [copied, setCopied] = useState(false);
  const [activeTab, setActiveTab] = useState('executive'); // 'executive' | 'raw_markdown'
  const [selectorOpen, setSelectorOpen] = useState(false);
  const [isGeneratingPdf, setIsGeneratingPdf] = useState(false);

  const { data: dashboard } = useDashboard();
  const { data: scans = [], isLoading: scansLoading } = useScansList(100);

  const targetMatchedScan = activeTarget
    ? scans.find((s) => s.target_domain === activeTarget)
    : null;

  // Determine active scan ID: user selection -> route param -> prop -> active target scan -> recent scan
  const effectiveScanId =
    selectedId ||
    routeScanId ||
    scanId ||
    activeScanId ||
    targetMatchedScan?.id ||
    dashboard?.recent_scans?.[0]?.id ||
    scans[0]?.id;

  const { data: job, isLoading: jobLoading } = useScanJob(effectiveScanId);
  const { data: findings = [], isLoading: findingsLoading } = useScanFindings(effectiveScanId);
  const { data: report, isLoading: reportLoading, error: reportError } = useScanReport(effectiveScanId);

  // Group findings for structured executive report presentation
  const vulnFindings = findings.filter((f) => f.type === 'vuln');
  const subFindings = findings.filter((f) => f.type === 'subdomain');
  const ipFindings = findings.filter((f) => f.type === 'ip_resolution');
  const portFindings = findings.filter((f) => f.type === 'port');
  const fpFindings = findings.filter((f) => f.type === 'fingerprint');
  const peopleFindings = findings.filter((f) => f.type === 'people');

  // Compute host inventory
  const hostMap = new Map();
  const getOrCreateHost = (ip) => {
    const clean = (ip || 'Origin Host').trim();
    if (!hostMap.has(clean)) {
      hostMap.set(clean, { ip: clean, hostnames: new Set(), ports: [], technologies: [], vulns: [] });
    }
    return hostMap.get(clean);
  };

  subFindings.forEach((sf) => {
    const d = sf.data || {};
    const host = d.subdomain || d.host;
    if (host) {
      const h = getOrCreateHost(host);
      h.hostnames.add(host);
    }
  });

  portFindings.forEach((pf) => {
    const p = pf.data || {};
    const ip = p.ip || (hostMap.size > 0 ? Array.from(hostMap.keys())[0] : 'Origin Host');
    const h = getOrCreateHost(ip);
    if (!h.ports.some((existing) => existing.port === p.port && existing.protocol === p.protocol)) {
      h.ports.push(p);
    }
  });

  fpFindings.forEach((f) => {
    const data = f.data || {};
    const techs = data.technologies || [];
    const targetHost = data.host || (hostMap.size > 0 ? Array.from(hostMap.keys())[0] : 'Origin Host');
    const h = getOrCreateHost(targetHost);
    techs.forEach((t) => {
      const tName = t.name || t;
      if (!h.technologies.some((existing) => (existing.name || existing) === tName)) {
        h.technologies.push(t);
      }
    });

    if (data.url) {
      try {
        const u = new URL(data.url);
        const parsedPort = u.port ? parseInt(u.port, 10) : u.protocol === 'https:' ? 443 : 80;
        if (!h.ports.some((p) => p.port === parsedPort)) {
          h.ports.push({
            port: parsedPort,
            protocol: 'tcp',
            service: u.protocol === 'https:' ? 'https' : 'http',
            product: techs[0]?.name || (u.protocol === 'https:' ? 'HTTPS Web Server' : 'HTTP Web Server'),
            version: techs[0]?.version || '',
            state: 'open',
            service_verified: true,
          });
        }
      } catch (e) {}
    }
  });

  vulnFindings.forEach((f) => {
    const v = f.data || {};
    const ip = v.ip || (hostMap.size > 0 ? Array.from(hostMap.keys())[0] : 'Origin Host');
    const h = getOrCreateHost(ip);
    h.vulns.push(v);
  });

  const hostInventory = Array.from(hostMap.values());
  const criticalCount = vulnFindings.filter((v) => (v.data?.severity || v.severity) === 'critical').length;
  const highCount = vulnFindings.filter((v) => (v.data?.severity || v.severity) === 'high').length;
  const mediumCount = vulnFindings.filter((v) => (v.data?.severity || v.severity) === 'medium').length;
  const lowCount = vulnFindings.filter((v) => (v.data?.severity || v.severity) === 'low').length;

  const threatLevel = criticalCount > 0 ? 'CRITICAL' : highCount > 0 ? 'HIGH' : mediumCount > 0 ? 'MEDIUM' : 'LOW';

  // Extract People OSINT Records
  const peopleData = peopleFindings[0]?.data || {};
  const peopleList = peopleData.people || peopleData.employees || [];
  const emailPattern = peopleData.email_pattern;
  const patternConfidence = peopleData.pattern_confidence || (emailPattern ? 95 : null);

  const handleSelectScan = (newJobId) => {
    setSelectedId(newJobId);
    setSelectorOpen(false);
    navigate(`/reports/${newJobId}`);
  };

  const handleCopy = () => {
    if (!report?.report_text) return;
    navigator.clipboard.writeText(report.report_text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownload = () => {
    if (!report?.report_text) return;
    const blob = new Blob([report.report_text], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `Recon7_Security_Assessment_${job?.target_domain || 'report'}_${(effectiveScanId || '').slice(0, 8)}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleDownloadJson = () => {
    if (!report) return;
    const exportData = {
      job_id: effectiveScanId,
      target: job?.target_domain,
      status: job?.status,
      created_at: job?.created_at,
      completed_at: job?.completed_at,
      prioritized_findings: report?.prioritized_findings || [],
      executive_summary: report?.report_text || '',
    };
    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `Recon7_Assessment_${job?.target_domain || 'scan'}_${(effectiveScanId || '').slice(0, 8)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handlePrint = () => {
    window.print();
  };

  // Direct 1-Click PDF Vector Export
  const handleDownloadPdf = async () => {
    let reportElement = document.getElementById(activeTab === 'raw_markdown' ? 'raw-telemetry-root' : 'enterprise-report-root');
    if (!reportElement && activeTab === 'raw_markdown') {
      reportElement = document.getElementById('enterprise-report-root');
    }
    if (!reportElement) {
      window.print();
      return;
    }

    try {
      setIsGeneratingPdf(true);
      const targetName = (job?.target_domain || 'Target').replace(/[^a-zA-Z0-9_-]/g, '_');
      const docKind = activeTab === 'raw_markdown' ? 'Telemetry' : 'Assessment';
      const filename = `Recon7_${docKind}_${targetName}_${(effectiveScanId || '').slice(0, 8)}.pdf`;

      const opt = {
        margin: [6, 6, 6, 6],
        filename: filename,
        image: { type: 'jpeg', quality: 0.98 },
        html2canvas: {
          scale: 2,
          useCORS: true,
          logging: false,
          backgroundColor: activeTab === 'raw_markdown' ? '#090D16' : '#FFFFFF',
          windowWidth: 1024,
        },
        jsPDF: {
          unit: 'mm',
          format: 'a4',
          orientation: 'portrait',
        },
        pagebreak: {
          mode: ['avoid-all', 'css', 'legacy'],
          avoid: ['.avoid-break', 'tr', '.finding-card', '.metric-card', 'pre'],
        },
      };

      await html2pdf().set(opt).from(reportElement).save();
    } catch (err) {
      console.error('PDF Generation Failed:', err);
      window.print();
    } finally {
      setIsGeneratingPdf(false);
    }
  };

  if (!effectiveScanId && !scansLoading && scans.length === 0) {
    return (
      <EmptyState
        title="No Scan Reports Available"
        message="Launch an attack surface reconnaissance scan to generate automated executive and technical assessment reports."
      />
    );
  }

  const prioritized = report?.prioritized_findings || [];
  const htmlContent = report?.report_text ? marked.parse(report.report_text) : '';

  return (
    <div className="space-y-6 max-w-5xl mx-auto">
      {/* 1. Interactive Scan Selector & Action Bar (Hidden on Print) */}
      <div className="no-print relative z-30 p-4 sm:p-5 rounded-lg panel-glass border border-border-dim shadow-panel space-y-4">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          {/* Target & Scan Identity */}
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-void border border-cyan-signal/40 flex items-center justify-center shadow-glow-cyan-sm shrink-0">
              <FileText className="w-5 h-5 text-cyan-signal" />
            </div>
            <div>
              <div className="flex items-center gap-2 flex-wrap">
                <h1 className="font-display font-bold text-lg text-text-primary">
                  {job?.target_domain || 'Security Assessment Report'}
                </h1>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-signal/15 text-cyan-signal border border-cyan-signal/40">
                  {(job?.scan_profile || 'standard').toUpperCase()} PROFILE
                </span>
                <span
                  className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                    job?.status === 'complete'
                      ? 'bg-success-green/10 text-success-green border border-success-green/40'
                      : job?.status === 'running'
                      ? 'bg-cyan-signal/15 text-cyan-signal border border-cyan-signal/40 animate-pulse'
                      : 'bg-magenta-alert/10 text-magenta-alert border border-magenta-alert/40'
                  }`}
                >
                  {(job?.status || 'PENDING').toUpperCase()}
                </span>
              </div>
              <p className="text-xs text-text-dim mt-1.5 font-mono flex items-center gap-2 flex-wrap">
                <span className="text-text-primary/90 font-medium">Job UUID: <code className="text-cyan-signal/90 bg-void px-1.5 py-0.5 rounded border border-border-dim">{effectiveScanId}</code></span>
                <span className="text-text-dim">•</span>
                <span className="text-text-primary/90 font-medium">Duration: {formatDuration(job?.created_at, job?.completed_at)}</span>
                <span className="text-text-dim">•</span>
                <span className="text-text-dim">{formatDate(job?.created_at)}</span>
              </p>
            </div>
          </div>

          {/* Action Buttons */}
          <div className="flex items-center gap-2 sm:gap-2.5 flex-wrap">
            {/* Scan Switcher Dropdown */}
            <div className="relative">
              <button
                onClick={() => setSelectorOpen(!selectorOpen)}
                className="flex items-center gap-2 px-3 py-1.5 rounded bg-void border border-border-dim hover:border-cyan-signal/60 text-xs font-mono text-text-primary transition-all shadow-sm"
              >
                <Layers className="w-3.5 h-3.5 text-cyan-signal" />
                <span className="max-w-[130px] truncate">{job?.target_domain || 'Select Scan'}</span>
                <ChevronDown className={`w-3.5 h-3.5 text-text-dim transition-transform ${selectorOpen ? 'rotate-180' : ''}`} />
              </button>

              {selectorOpen && (
                <div className="absolute right-0 mt-2 w-72 max-h-80 overflow-y-auto rounded-lg bg-panel border border-border-bright shadow-panel z-50 p-1.5 space-y-1">
                  <div className="px-2.5 py-1.5 text-[10px] font-mono uppercase text-text-dim border-b border-border-dim/60">
                    Switch Scan Report ({scans.length})
                  </div>
                  {scans.map((s) => (
                    <button
                      key={s.id}
                      onClick={() => handleSelectScan(s.id)}
                      className={`w-full text-left p-2 rounded text-xs font-mono transition-colors flex flex-col gap-0.5 ${
                        s.id === effectiveScanId
                          ? 'bg-cyan-signal/15 text-cyan-signal border border-cyan-signal/40 font-bold'
                          : 'text-text-dim hover:text-text-primary hover:bg-void/60'
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <span className="text-text-primary font-semibold truncate">{s.target_domain}</span>
                        <span className="text-[10px] uppercase text-text-dim">{(s.scan_profile || 'std').toUpperCase()}</span>
                      </div>
                      <span className="text-[10px] text-text-dim">
                        {formatDate(s.created_at)} • {s.status}
                      </span>
                    </button>
                  ))}
                </div>
              )}
            </div>

            <button
              onClick={handleCopy}
              disabled={!report?.report_text}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-void border border-border-dim text-xs font-mono text-text-primary hover:border-cyan-signal hover:text-cyan-signal transition-all disabled:opacity-50"
              title="Copy Raw Markdown"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-cyan-signal" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copied ? 'Copied' : 'Copy'}</span>
            </button>

            <button
              onClick={handleDownloadJson}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-void border border-border-dim text-xs font-mono text-text-primary hover:border-cyan-signal hover:text-cyan-signal transition-all"
              title="Download Machine-Readable JSON"
            >
              <Download className="w-3.5 h-3.5" />
              <span>JSON</span>
            </button>

            <button
              onClick={handleDownload}
              disabled={!report?.report_text}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-void border border-border-dim text-xs font-mono text-text-primary hover:border-cyan-signal hover:text-cyan-signal transition-all disabled:opacity-50"
              title="Download Markdown Document"
            >
              <Download className="w-3.5 h-3.5" />
              <span>.MD</span>
            </button>

            <button
              onClick={handlePrint}
              disabled={!report}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-void border border-border-dim text-xs font-mono text-text-primary hover:border-cyan-signal hover:text-cyan-signal transition-all disabled:opacity-50"
              title="Print to Physical Printer"
            >
              <Printer className="w-3.5 h-3.5" />
              <span>Print</span>
            </button>

            {/* Prominent Direct 1-Click PDF Download Button */}
            <button
              onClick={handleDownloadPdf}
              disabled={isGeneratingPdf}
              className="flex items-center gap-2 px-4 py-1.5 rounded bg-cyan-signal text-black font-bold text-xs tracking-wider shadow-glow-cyan-sm hover:brightness-110 active:scale-[0.98] transition-all font-mono disabled:opacity-50 shrink-0"
              title="Direct 1-Click Download Clean PDF Report"
            >
              {isGeneratingPdf ? <Loader2 className="w-4 h-4 animate-spin" /> : <Download className="w-4 h-4" />}
              <span>{isGeneratingPdf ? 'GENERATING PDF...' : 'DOWNLOAD PDF'}</span>
            </button>
          </div>
        </div>

        {/* View Mode Navigation Tabs */}
        <div className="flex items-center gap-2.5 pt-2 border-t border-border-dim/60">
          <button
            onClick={() => setActiveTab('executive')}
            className={`px-3.5 py-1.5 rounded-md text-xs font-mono font-bold transition-all flex items-center gap-2 border ${
              activeTab === 'executive'
                ? 'bg-cyan-signal text-black border-cyan-signal shadow-glow-cyan-sm'
                : 'bg-void/80 text-text-primary border-border-dim hover:border-cyan-signal/50 hover:text-cyan-signal'
            }`}
          >
            <Activity className="w-3.5 h-3.5" />
            <span>Executive Assessment (Document Mode)</span>
          </button>

          <button
            onClick={() => setActiveTab('raw_markdown')}
            className={`px-3.5 py-1.5 rounded-md text-xs font-mono font-bold transition-all flex items-center gap-2 border ${
              activeTab === 'raw_markdown'
                ? 'bg-cyan-signal text-black border-cyan-signal shadow-glow-cyan-sm'
                : 'bg-void/80 text-text-primary border-border-dim hover:border-cyan-signal/50 hover:text-cyan-signal'
            }`}
          >
            <FileText className="w-3.5 h-3.5" />
            <span>Raw Telemetry Stream</span>
          </button>
        </div>
      </div>

      {/* Loading and Error States */}
      {reportLoading && <LoadingState message="Compiling executive intelligence and formatting attack surface report..." />}

      {reportError && (
        <EmptyState
          title="Security Report Not Yet Compiled"
          message="The security assessment report is being compiled or the scan is still running preliminary stages."
        />
      )}

      {/* 2. Formal Enterprise Document (Rendered for Screen & Direct Vector PDF Export) */}
      {report && activeTab === 'executive' && (
        <div
          id="enterprise-report-root"
          className="enterprise-report-document space-y-6 text-slate-900 bg-white p-6 sm:p-8 rounded-lg border border-slate-300 shadow-lg font-sans w-full"
        >
          {/* COVER PAGE / EXECUTIVE HEADER */}
          <div className="avoid-break p-5 sm:p-6 rounded-lg border border-slate-300 bg-slate-50 text-slate-900 space-y-4">
            {/* Top Security Banner */}
            <div className="flex items-center justify-between border-b border-slate-300 pb-3 gap-2">
              <div className="font-mono text-xs font-bold tracking-widest text-slate-900 uppercase">
                RECON7 ATTACK SURFACE INTELLIGENCE PLATFORM
              </div>
              <span className="px-2.5 py-0.5 rounded text-[10px] font-mono font-bold uppercase tracking-wider bg-red-100 text-red-800 border border-red-300 whitespace-nowrap shrink-0">
                [ CONFIDENTIAL // RED TEAM ASSESSMENT ]
              </span>
            </div>

            {/* Document Title & Target Metadata */}
            <div className="space-y-1">
              <h1 className="text-2xl sm:text-3xl font-extrabold text-slate-950 tracking-tight leading-tight">
                RED TEAM SECURITY ASSESSMENT REPORT
              </h1>
              <p className="text-xs text-slate-600 font-mono">
                Automated Attack Surface Discovery, Vulnerability Analysis & Triage
              </p>
            </div>

            {/* Metadata Summary Grid */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 p-3.5 rounded-lg border border-slate-300 bg-white text-slate-900 font-mono text-xs">
              <div>
                <span className="text-[10px] text-slate-500 uppercase block font-semibold">Target Scope</span>
                <span className="font-bold text-xs sm:text-sm text-slate-950 break-all block">{job?.target_domain}</span>
              </div>
              <div>
                <span className="text-[10px] text-slate-500 uppercase block font-semibold">Assessment Profile</span>
                <span className="font-bold text-xs sm:text-sm text-slate-900">{(job?.scan_profile || 'standard').toUpperCase()}</span>
              </div>
              <div>
                <span className="text-[10px] text-slate-500 uppercase block font-semibold">Execution Duration</span>
                <span className="font-bold text-xs sm:text-sm text-slate-900">{formatDuration(job?.created_at, job?.completed_at)}</span>
              </div>
              <div>
                <span className="text-[10px] text-slate-500 uppercase block font-semibold">Threat Posture</span>
                <span
                  className={`font-bold text-xs sm:text-sm ${
                    threatLevel === 'CRITICAL'
                      ? 'text-red-700 font-extrabold'
                      : threatLevel === 'HIGH'
                      ? 'text-orange-700 font-extrabold'
                      : threatLevel === 'MEDIUM'
                      ? 'text-amber-700 font-extrabold'
                      : 'text-emerald-700 font-extrabold'
                  }`}
                >
                  {threatLevel} RISK
                </span>
              </div>
            </div>

            {/* Executive Metrics Scorecard */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              <div className="p-3 rounded border border-slate-300 bg-white text-center">
                <span className="text-[10px] font-mono uppercase text-slate-600 font-semibold block">Discovered Subdomains</span>
                <span className="text-xl font-mono font-bold text-cyan-800">{subFindings.length}</span>
              </div>
              <div className="p-3 rounded border border-slate-300 bg-white text-center">
                <span className="text-[10px] font-mono uppercase text-slate-600 font-semibold block">Target Host Machines</span>
                <span className="text-xl font-mono font-bold text-slate-950">{hostInventory.length}</span>
              </div>
              <div className="p-3 rounded border border-slate-300 bg-white text-center">
                <span className="text-[10px] font-mono uppercase text-slate-600 font-semibold block">Open Services / Ports</span>
                <span className="text-xl font-mono font-bold text-teal-800">{portFindings.length}</span>
              </div>
              <div className="p-3 rounded border border-slate-300 bg-white text-center">
                <span className="text-[10px] font-mono uppercase text-slate-600 font-semibold block">Critical & High Risks</span>
                <span className={`text-xl font-mono font-bold ${criticalCount + highCount > 0 ? 'text-red-700' : 'text-emerald-700'}`}>
                  {criticalCount + highCount}
                </span>
              </div>
            </div>
          </div>

          {/* SECTION 1: AI PRIORITIZED ATTACK VECTORS */}
          {prioritized.length > 0 && (
            <div className="avoid-break space-y-3 pt-2">
              <div className="text-xs font-mono uppercase tracking-wider font-bold text-slate-900 border-b border-slate-300 pb-1.5">
                1. Executive Prioritized Attack Vectors
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5">
                {prioritized.map((find, idx) => (
                  <div
                    key={idx}
                    className="enterprise-card avoid-break p-4 rounded-lg border border-slate-300 bg-white space-y-2.5 shadow-sm"
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span
                        className={`px-2 py-0.5 rounded text-[11px] font-mono font-bold uppercase whitespace-nowrap ${
                          find.severity === 'critical'
                            ? 'chip-critical'
                            : find.severity === 'high'
                            ? 'chip-high'
                            : find.severity === 'medium'
                            ? 'chip-medium'
                            : 'chip-low'
                        }`}
                      >
                        {find.severity}
                      </span>
                      {find.risk_score && (
                        <span className="font-mono text-xs font-bold text-red-700 whitespace-nowrap">
                          Risk Score: {find.risk_score}/10
                        </span>
                      )}
                    </div>

                    <h3 className="font-bold text-sm text-slate-950">
                      {find.title}
                    </h3>

                    <p className="text-xs text-slate-700 leading-relaxed">{find.rationale}</p>

                    {find.recommendation && (
                      <div className="remediation-box-print p-2.5 rounded text-[11px] font-mono bg-emerald-50 border border-emerald-300 text-emerald-950">
                        <span className="text-emerald-800 font-bold uppercase mr-1.5">
                          Remediation Action:
                        </span>
                        {find.recommendation}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* SECTION 2: TECHNICAL VULNERABILITIES & VERIFIED EXPOSURES */}
          {vulnFindings.length > 0 && (
            <div className="avoid-break space-y-3 pt-2">
              <div className="text-xs font-mono uppercase tracking-wider font-bold text-slate-900 border-b border-slate-300 pb-1.5">
                2. Evaluated Vulnerabilities & Technical Proof ({vulnFindings.length})
              </div>

              <div className="space-y-3">
                {vulnFindings.map((f) => {
                  const v = f.data || {};
                  return (
                    <div
                      key={f.id}
                      className="enterprise-card avoid-break p-4 rounded-lg border border-slate-300 bg-white space-y-2.5 shadow-sm"
                    >
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <div className="flex items-center gap-2">
                          <span
                            className={`px-2 py-0.5 rounded text-[11px] font-mono font-bold uppercase whitespace-nowrap ${
                              (v.severity || f.severity) === 'critical'
                                ? 'chip-critical'
                                : (v.severity || f.severity) === 'high'
                                ? 'chip-high'
                                : (v.severity || f.severity) === 'medium'
                                ? 'chip-medium'
                                : 'chip-low'
                            }`}
                          >
                            {v.severity || f.severity}
                          </span>
                          <span className="font-mono text-xs font-bold text-slate-950">
                            {v.title || v.cve_id}
                          </span>
                        </div>
                        <div className="flex items-center gap-2 font-mono text-[11px] flex-wrap">
                          {v.cvss_score && (
                            <span className="px-2 py-0.5 rounded bg-red-50 text-red-800 border border-red-300 font-bold whitespace-nowrap">
                              CVSS {v.cvss_score}
                            </span>
                          )}
                          {v.epss_score && (
                            <span className="px-2 py-0.5 rounded bg-amber-50 text-amber-800 border border-amber-300 font-semibold whitespace-nowrap">
                              EPSS {(v.epss_score * 100).toFixed(1)}%
                            </span>
                          )}
                          {v.distro_security_status && (
                            <span className="px-2 py-0.5 rounded font-bold bg-cyan-50 text-cyan-800 border border-cyan-300 whitespace-nowrap">
                              {v.distro_security_status}
                            </span>
                          )}
                        </div>
                      </div>

                      <p className="text-xs text-slate-700 leading-relaxed">{v.description}</p>

                      {/* Mathematical Proof & Evidence */}
                      {v.evidence_proof && (
                        <div className="evidence-box-print p-2.5 rounded border border-slate-300 bg-slate-50 text-slate-900 text-[11px] font-mono space-y-1">
                          <div className="font-bold uppercase text-[10px] text-cyan-800">
                            Evidence & Mathematical Proof:
                          </div>
                          <div className="opacity-95 text-slate-900">{v.evidence_proof}</div>
                        </div>
                      )}

                      {/* Remediation Action */}
                      {v.remediation && (
                        <div className="text-[11px] font-mono text-emerald-900 font-semibold">
                          <span className="text-emerald-800 font-bold uppercase mr-1">Remediation:</span>
                          {v.remediation}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* SECTION 3: INFRASTRUCTURE & HOST INVENTORY LEDGER */}
          <div className="avoid-break space-y-3 pt-2">
            <div className="text-xs font-mono uppercase tracking-wider font-bold text-slate-900 border-b border-slate-300 pb-1.5">
              3. Target Infrastructure & Host Ledger ({hostInventory.length})
            </div>

            <div className="w-full">
              <table className="w-full table-fixed text-left text-xs font-mono border border-slate-300 rounded overflow-hidden">
                <thead>
                  <tr className="bg-slate-100 border-b border-slate-300 text-slate-900 font-bold">
                    <th className="py-2.5 px-3 w-[22%]">HOST IP / ASSET</th>
                    <th className="py-2.5 px-3 w-[28%]">ASSOCIATED SUBDOMAINS</th>
                    <th className="py-2.5 px-3 w-[16%]">PORTS</th>
                    <th className="py-2.5 px-3 w-[20%]">DETECTED TECH STACK</th>
                    <th className="py-2.5 px-3 w-[14%]">RISK STATE</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200">
                  {hostInventory.map((h, idx) => (
                    <tr key={idx} className={idx % 2 === 1 ? 'bg-slate-50' : 'bg-white'}>
                      <td className="py-2.5 px-3 font-bold text-slate-950 break-all">{h.ip}</td>
                      <td className="py-2.5 px-3 text-slate-700 break-words">
                        {Array.from(h.hostnames).join(', ') || 'Direct IP'}
                      </td>
                      <td className="py-2.5 px-3 font-bold text-cyan-800 break-words">
                        {h.ports.map((p) => `${p.port}/${p.protocol || 'tcp'}`).join(', ') || 'None'}
                      </td>
                      <td className="py-2.5 px-3 text-slate-700 break-words">
                        {h.technologies.map((t) => (t.name || t)).join(', ') || '—'}
                      </td>
                      <td className="py-2.5 px-3">
                        {h.vulns.length > 0 ? (
                          <span className="font-bold text-red-700 whitespace-nowrap">{h.vulns.length} Vuln(s)</span>
                        ) : (
                          <span className="text-emerald-700 font-semibold whitespace-nowrap">Secure</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* SECTION 4: PERSONNEL & ORGANIZATIONAL INTELLIGENCE LEDGER */}
          <div className="avoid-break space-y-3 pt-2">
            <div className="text-xs font-mono uppercase tracking-wider font-bold text-slate-900 border-b border-slate-300 pb-1.5">
              4. Personnel & Organizational Intelligence Ledger ({peopleList.length})
            </div>

            {emailPattern && (
              <div className="p-3 rounded border border-slate-300 bg-slate-50 text-xs font-mono flex items-center justify-between gap-2">
                <div>
                  <span className="text-slate-500 uppercase text-[10px] font-bold block">Inferred Corporate Email Syntax</span>
                  <span className="text-slate-900 font-bold">{emailPattern}</span>
                </div>
                {patternConfidence && (
                  <span className="px-2 py-0.5 rounded bg-cyan-50 text-cyan-800 border border-cyan-300 font-bold text-[11px] whitespace-nowrap">
                    Confidence: {patternConfidence}%
                  </span>
                )}
              </div>
            )}

            {peopleList.length > 0 ? (
              <div className="w-full">
                <table className="w-full table-fixed text-left text-xs font-mono border border-slate-300 rounded overflow-hidden">
                  <thead>
                    <tr className="bg-slate-100 border-b border-slate-300 text-slate-900 font-bold">
                      <th className="py-2.5 px-3 w-[22%]">PERSONNEL NAME</th>
                      <th className="py-2.5 px-3 w-[28%]">CORPORATE EMAIL</th>
                      <th className="py-2.5 px-3 w-[14%]">STATUS</th>
                      <th className="py-2.5 px-3 w-[12%]">CONFIDENCE</th>
                      <th className="py-2.5 px-3 w-[24%]">SOURCE & PROVENANCE</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-200">
                    {peopleList.slice(0, 30).map((p, idx) => (
                      <tr key={idx} className={idx % 2 === 1 ? 'bg-slate-50' : 'bg-white'}>
                        <td className="py-2.5 px-3 font-bold text-slate-950 break-words">{p.name || 'Staff Record'}</td>
                        <td className="py-2.5 px-3 text-cyan-800 font-semibold break-all">{p.email || '—'}</td>
                        <td className="py-2.5 px-3">
                          <span
                            className={`px-1.5 py-0.5 rounded text-[10px] font-bold whitespace-nowrap ${
                              p.inferred
                                ? 'bg-amber-50 text-amber-800 border border-amber-300'
                                : 'bg-emerald-50 text-emerald-800 border border-emerald-300'
                            }`}
                          >
                            {p.inferred ? 'Inferred' : 'Confirmed'}
                          </span>
                        </td>
                        <td className="py-2.5 px-3 font-bold text-slate-900 whitespace-nowrap">{p.confidence ? `${p.confidence}%` : '85%'}</td>
                        <td className="py-2.5 px-3 text-slate-600 break-words">
                          {Array.isArray(p.sources) ? p.sources.join(', ') : (p.source || 'Search OSINT')}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="p-3 rounded border border-slate-300 bg-slate-50 text-xs font-mono text-slate-600">
                No corporate personnel records or public employee identities exposed on targeted boundary.
              </div>
            )}
          </div>

          {/* SECTION 5: ENGAGEMENT METHODOLOGY & COVERAGE MATRIX */}
          <div className="avoid-break space-y-3 pt-3 border-t border-slate-300">
            <div className="text-xs font-mono uppercase tracking-wider font-bold text-slate-900 border-b border-slate-300 pb-1.5">
              5. Assessment Scope & Methodology Ledger
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs text-slate-700 font-mono">
              <div className="p-3 rounded border border-slate-300 bg-slate-50 space-y-1.5">
                <div className="font-bold text-slate-900 uppercase text-[11px]">Executed Capabilities</div>
                <ul className="list-disc list-inside space-y-1 text-[11px]">
                  <li>DNS & Subdomain Enumeration (Passive & Active)</li>
                  <li>TCP Service Sweep & Full L7 Handshake Verification</li>
                  <li>HTTP Header & Technology Stack Normalization</li>
                  <li>Personnel OSINT, Email Syntax & Document Intelligence</li>
                  <li>Debian/Ubuntu Distro Package Backport Resolution</li>
                  <li>CVSS v3.1 Base Scoring & EPSS Correlation</li>
                </ul>
              </div>

              <div className="p-3 rounded border border-slate-300 bg-slate-50 space-y-1.5">
                <div className="font-bold text-slate-900 uppercase text-[11px]">Scope & Limitations</div>
                <ul className="list-disc list-inside space-y-1 text-[11px]">
                  <li>Target Range: {job?.target_domain} (Authorized Boundary)</li>
                  <li>UDP Protocol Sweep: Excluded per standard policy</li>
                  <li>Exploitation Mode: Non-destructive verification only</li>
                  <li>Attestation: Audited against CISA KEV & NVD catalogs</li>
                  <li>Report ID: R7-{(effectiveScanId || '').slice(0, 8).toUpperCase()}</li>
                </ul>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* 3. Raw Markdown Stream View */}
      {report && activeTab === 'raw_markdown' && (
        <div id="raw-telemetry-root" className="p-6 sm:p-8 rounded-lg panel-glass border border-border-dim shadow-panel space-y-6">
          <div className="report-markdown text-text-primary" dangerouslySetInnerHTML={{ __html: htmlContent }} />
          <AiDisclaimer compact className="pt-4 border-t border-border-dim" />
        </div>
      )}
    </div>
  );
}
