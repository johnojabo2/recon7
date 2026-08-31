import React from 'react';
import {
  X,
  ShieldCheck,
  Calendar,
  ExternalLink,
  Cpu,
  Hash,
  FileCheck,
  AlertTriangle,
  Layers,
} from 'lucide-react';
import { useEvidence } from '../../api/hooks';

export default function EvidenceDrawer({ jobId, evidenceId, onClose }) {
  const { data: evidence, isLoading } = useEvidence(jobId, evidenceId);

  if (!evidenceId) return null;

  return (
    <div className="fixed inset-y-0 right-0 w-full max-w-md bg-panel border-l border-border-dim shadow-2xl z-50 flex flex-col transform transition-transform duration-300 ease-in-out">
      {/* Drawer Header */}
      <div className="p-5 border-b border-border-dim flex items-center justify-between bg-void/80 backdrop-blur-sm">
        <div className="flex items-center gap-2">
          <FileCheck className="w-5 h-5 text-cyan-signal" />
          <h3 className="font-display font-bold text-sm tracking-wide text-text-primary uppercase">
            Evidence Ledger Record
          </h3>
        </div>
        <button
          onClick={onClose}
          className="p-1.5 rounded hover:bg-white/5 text-text-dim hover:text-text-primary transition-colors"
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      {/* Drawer Body */}
      <div className="flex-1 overflow-y-auto p-5 space-y-5">
        {isLoading ? (
          <div className="space-y-4 animate-pulse">
            <div className="h-4 bg-white/5 rounded w-1/2"></div>
            <div className="h-20 bg-white/5 rounded"></div>
            <div className="h-32 bg-white/5 rounded"></div>
          </div>
        ) : !evidence ? (
          <div className="p-4 rounded bg-magenta-alert/10 border border-magenta-alert/30 text-magenta-alert text-xs">
            Evidence record with ID <code className="font-mono">{evidenceId}</code> not found or unverified.
          </div>
        ) : (
          <>
            {/* Reliability Badge & Source */}
            <div className="p-4 rounded-lg bg-void/90 border border-border-dim space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-mono uppercase text-text-dim">Source Reliability</span>
                <span className="font-mono text-sm font-bold text-cyan-signal">
                  {Math.round((evidence.reliability || 1) * 100)}%
                </span>
              </div>
              <div className="w-full bg-panel rounded-full h-1.5 overflow-hidden">
                <div
                  className="bg-cyan-signal h-1.5 rounded-full"
                  style={{ width: `${Math.round((evidence.reliability || 1) * 100)}%` }}
                />
              </div>
              <div className="flex items-center justify-between text-xs text-text-dim pt-1 border-t border-border-dim/50">
                <span>Collector: <strong className="text-text-primary font-mono">{evidence.collector}</strong></span>
                <span>Type: <strong className="text-text-primary font-mono">{evidence.source_type}</strong></span>
              </div>
            </div>

            {/* Extracted Claim */}
            <div className="space-y-2">
              <h4 className="text-xs font-mono uppercase tracking-wider text-text-dim">
                Extracted Fact Claim
              </h4>
              <div className="p-3.5 rounded bg-void border border-cyan-signal/30 text-xs font-mono text-cyan-signal/90 leading-relaxed shadow-glow-cyan-sm">
                "{evidence.extracted_claim}"
              </div>
            </div>

            {/* Source Reference & URL */}
            <div className="space-y-2">
              <h4 className="text-xs font-mono uppercase tracking-wider text-text-dim">
                Sensor Provenance
              </h4>
              <div className="p-3 rounded bg-void border border-border-dim space-y-2 text-xs">
                <div className="flex items-center justify-between">
                  <span className="text-text-dim">Sensor Engine:</span>
                  <span className="font-mono text-text-primary">{evidence.source}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-text-dim">Collector Version:</span>
                  <span className="font-mono text-text-primary">v{evidence.collector_version}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-text-dim">Observed At:</span>
                  <span className="font-mono text-text-primary">
                    {new Date(evidence.observed_at).toLocaleString()}
                  </span>
                </div>
                {evidence.source_url && (
                  <div className="pt-2 border-t border-border-dim flex items-center justify-between">
                    <span className="text-text-dim">Source URL:</span>
                    <a
                      href={evidence.source_url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-cyan-signal hover:underline flex items-center gap-1 font-mono truncate max-w-[200px]"
                    >
                      <span>{evidence.source_url}</span>
                      <ExternalLink className="w-3 h-3 shrink-0" />
                    </a>
                  </div>
                )}
              </div>
            </div>

            {/* Cryptographic Hash */}
            {evidence.hash && (
              <div className="space-y-1">
                <h4 className="text-xs font-mono uppercase tracking-wider text-text-dim flex items-center gap-1.5">
                  <Hash className="w-3.5 h-3.5 text-cyan-signal" />
                  Verification Digest (SHA-256)
                </h4>
                <div className="p-2.5 rounded bg-void border border-border-dim text-[11px] font-mono text-text-dim break-all select-all">
                  {evidence.hash}
                </div>
              </div>
            )}

            {/* Raw Reference Payload */}
            <div className="space-y-2">
              <h4 className="text-xs font-mono uppercase tracking-wider text-text-dim flex items-center gap-1.5">
                <Layers className="w-3.5 h-3.5 text-cyan-signal" />
                Raw Sensor Telemetry Payload
              </h4>
              <pre className="p-3 rounded bg-void border border-border-dim text-[11px] font-mono text-text-dim overflow-x-auto max-h-60">
                {JSON.stringify(evidence.raw_reference || {}, null, 2)}
              </pre>
            </div>
          </>
        )}
      </div>

      {/* Drawer Footer */}
      <div className="p-4 border-t border-border-dim bg-void/60 text-center">
        <span className="text-[10px] font-mono uppercase tracking-wider text-text-dim">
          R7 Evidence Ledger • Immutable Audit Trail
        </span>
      </div>
    </div>
  );
}
