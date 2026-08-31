import React from 'react';
import {
  CheckCircle2,
  Loader2,
  Circle,
  Building,
  Globe,
  Network,
  Cpu,
  Fingerprint,
  ShieldAlert,
  Search,
  Users,
  Brain,
  FileCheck,
} from 'lucide-react';

export const PIPELINE_STEPS = [
  { id: '1.company_resolve', key: 'company_resolve', label: 'Org Resolve', icon: Building, desc: 'WHOIS & ASN' },
  { id: '2.subdomains', key: 'subdomains', label: 'Subdomains', icon: Globe, desc: 'CT Logs & Subfinder' },
  { id: '3.ip_resolve', key: 'ip_resolve', label: 'IP & CDN', icon: Network, desc: 'Origin Discovery' },
  { id: '4.ports', key: 'ports', label: 'Port Sweep', icon: Cpu, desc: 'masscan -> nmap' },
  { id: '5.fingerprint', key: 'fingerprint', label: 'Tech Stack', icon: Fingerprint, desc: 'httpx & Wappalyzer' },
  { id: '6.nuclei_match', key: 'nuclei_match', label: 'Vuln Probes', icon: ShieldAlert, desc: 'Nuclei Templates' },
  { id: '7.cve_lookup', key: 'cve_lookup', label: 'CVE & OWASP', icon: Search, desc: 'NVD Correlation' },
  { id: '8.people_osint', key: 'people_osint', label: 'People OSINT', icon: Users, desc: 'Email Patterns' },
  { id: '9.ai_triage', key: 'ai_triage', label: 'AI Triage', icon: Brain, desc: 'Risk Scoring' },
  { id: '10.report_writer', key: 'report_writer', label: 'Report Writer', icon: FileCheck, desc: 'Markdown Gen' },
];

export default function PipelineVisualizer({ currentStep = 'init', status = 'pending' }) {
  // Determine index of current step
  const activeStepIdx = PIPELINE_STEPS.findIndex((s) => s.id === currentStep);
  const isComplete = status === 'complete' || currentStep === 'completed';
  const isFailed = status === 'failed';

  return (
    <div className="w-full panel-glass rounded-lg p-5 border border-border-dim shadow-panel overflow-hidden">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-3">
          <span className="font-mono text-xs text-text-dim tracking-wider uppercase">
            10-STAGE RECON PIPELINE
          </span>
          <div className="flex items-center gap-2 px-2 py-0.5 rounded bg-void border border-border-dim text-[11px] font-mono">
            <span
              className={`w-1.5 h-1.5 rounded-full ${
                isComplete
                  ? 'bg-success-green shadow-glow-green'
                  : isFailed
                  ? 'bg-magenta-alert shadow-glow-magenta'
                  : 'bg-cyan-signal shadow-glow-cyan animate-pulse'
              }`}
            />
            <span
              className={
                isComplete
                  ? 'text-success-green'
                  : isFailed
                  ? 'text-magenta-alert'
                  : 'text-cyan-signal'
              }
            >
              {isComplete ? 'ALL STAGES COMPLETE' : isFailed ? 'PIPELINE FAILED' : 'EXECUTION IN PROGRESS'}
            </span>
          </div>
        </div>

        <span className="text-xs font-mono text-text-dim">
          {isComplete
            ? '10 / 10 Completed'
            : activeStepIdx >= 0
            ? `Stage ${activeStepIdx + 1} of 10`
            : 'Initializing...'}
        </span>
      </div>

      {/* Horizontal Pipeline Steps Sequence */}
      <div className="grid grid-cols-2 sm:grid-cols-5 lg:grid-cols-10 gap-2.5 relative">
        {PIPELINE_STEPS.map((step, idx) => {
          const Icon = step.icon;
          const isCurrent = !isComplete && !isFailed && step.id === currentStep;
          const isFinished = isComplete || (activeStepIdx > idx && activeStepIdx !== -1);
          const isPending = !isComplete && !isCurrent && !isFinished;

          return (
            <div
              key={step.id}
              className={`flex flex-col items-center p-3 rounded-md border text-center transition-all duration-300 relative group ${
                isCurrent
                  ? 'bg-void border-cyan-signal shadow-glow-cyan animate-pulse-cyan z-10 scale-[1.02]'
                  : isFinished
                  ? 'bg-void border-cyan-signal/40 text-text-primary'
                  : 'bg-void/40 border-border-dim text-text-dim/60'
              }`}
            >
              {/* Step Status Indicator Icon */}
              <div
                className={`w-8 h-8 rounded-md flex items-center justify-center mb-2 transition-colors ${
                  isCurrent
                    ? 'bg-cyan-signal/20 text-cyan-signal'
                    : isFinished
                    ? 'bg-cyan-signal/10 text-cyan-signal'
                    : 'bg-panel text-text-dim'
                }`}
              >
                {isFinished ? (
                  <CheckCircle2 className="w-4 h-4 text-cyan-signal" />
                ) : isCurrent ? (
                  <Loader2 className="w-4 h-4 text-cyan-signal animate-spin" />
                ) : (
                  <Icon className="w-4 h-4 text-text-dim" />
                )}
              </div>

              {/* Step Title & Metadata */}
              <span
                className={`text-[11px] font-semibold tracking-wide truncate w-full ${
                  isCurrent
                    ? 'text-cyan-signal font-mono'
                    : isFinished
                    ? 'text-text-primary'
                    : 'text-text-dim'
                }`}
              >
                {step.label}
              </span>
              <span className="text-[9px] font-mono text-text-dim truncate w-full mt-0.5">
                {step.desc}
              </span>

              {/* Top Accent Bar */}
              <div
                className={`absolute -top-[1px] left-2 right-2 h-[2px] rounded-full transition-colors ${
                  isCurrent
                    ? 'bg-cyan-signal shadow-glow-cyan'
                    : isFinished
                    ? 'bg-cyan-signal/60'
                    : 'bg-transparent'
                }`}
              />
            </div>
          );
        })}
      </div>
    </div>
  );
}
