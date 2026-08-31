import React from 'react';
import { ShieldCheck } from 'lucide-react';

export default function AiDisclaimer({ compact = false, className = '' }) {
  if (compact) {
    return (
      <div className={`flex items-center gap-1.5 text-[11px] font-mono text-text-dim/80 select-none ${className}`}>
        <ShieldCheck className="w-3.5 h-3.5 text-cyan-signal/70 shrink-0" />
        <span>Automated Security Advisory: Validate perimeter exposure findings within an authorized environment before remediation.</span>
      </div>
    );
  }

  return (
    <div
      className={`flex items-start sm:items-center justify-between gap-3 px-3.5 py-2.5 rounded-lg bg-void/70 border border-border-dim/80 text-xs font-mono select-none ${className}`}
    >
      <div className="flex items-start sm:items-center gap-2.5">
        <ShieldCheck className="w-4 h-4 text-cyan-signal/80 shrink-0 mt-0.5 sm:mt-0" />
        <p className="text-text-dim text-[11px] leading-relaxed">
          <strong className="text-text-primary font-semibold">Automated Security Advisory:</strong> Recon7 attack-surface telemetry, service fingerprinting, and correlated CVE exposures are synthesized through deterministic heuristic engines and verified security catalogs. Findings should be validated within an authorized testing environment prior to deploying production remediations.
        </p>
      </div>
    </div>
  );
}
