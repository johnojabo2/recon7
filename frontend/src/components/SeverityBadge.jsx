import React from 'react';

const SEVERITY_CONFIG = {
  critical: {
    label: 'CRITICAL',
    bg: 'bg-magenta-alert/15 text-magenta-alert border-magenta-alert/50 shadow-glow-magenta-sm',
    dot: 'bg-magenta-alert shadow-glow-magenta',
  },
  high: {
    label: 'HIGH',
    bg: 'bg-orange-500/15 text-orange-400 border-orange-500/50',
    dot: 'bg-orange-400',
  },
  medium: {
    label: 'MEDIUM',
    bg: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/50',
    dot: 'bg-yellow-400',
  },
  low: {
    label: 'LOW',
    bg: 'bg-cyan-signal/15 text-cyan-signal border-cyan-signal/50',
    dot: 'bg-cyan-signal',
  },
  info: {
    label: 'INFO',
    bg: 'bg-text-muted/15 text-text-dim border-border-dim',
    dot: 'bg-text-dim',
  },
};

export default function SeverityBadge({ severity = 'info', showDot = true, className = '' }) {
  const sevKey = (severity || 'info').toLowerCase();
  const config = SEVERITY_CONFIG[sevKey] || SEVERITY_CONFIG.info;

  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] font-mono font-semibold uppercase tracking-wider border ${config.bg} ${className}`}
    >
      {showDot && <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${config.dot}`} />}
      <span>{config.label}</span>
    </span>
  );
}
