import React, { useState } from 'react';
import {
  Cloud,
  FileText,
  AlertOctagon,
  ShieldCheck,
  ExternalLink,
  Lock,
  Unlock,
  Layers,
  FileCheck,
  AlertTriangle,
} from 'lucide-react';
import { useScanExposures, useScanDocuments } from '../api/hooks';
import { LoadingState } from '../components/LoadingState';
import SeverityBadge from '../components/SeverityBadge';
import EvidenceDrawer from '../components/graph/EvidenceDrawer';

export default function ExposureView({ scanId }) {
  const { data: exposures = [], isLoading: expLoading } = useScanExposures(scanId);
  const { data: documents = [], isLoading: docLoading } = useScanDocuments(scanId);
  const [selectedEvidenceId, setSelectedEvidenceId] = useState(null);

  if (expLoading && docLoading) {
    return <LoadingState message="Inspecting storage buckets and public document repositories..." />;
  }

  const cloudBuckets = exposures.filter((e) => e.type === 'cloud_resource');
  const breaches = exposures.filter((e) => e.type === 'breach');

  return (
    <div className="space-y-6">
      {/* Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="p-4 rounded-lg bg-panel border border-border-dim shadow-panel">
          <span className="text-[11px] font-mono uppercase text-text-dim">Cloud Storage Resources</span>
          <p className="text-2xl font-mono font-bold text-orange-400 mt-1">{cloudBuckets.length}</p>
        </div>
        <div className="p-4 rounded-lg bg-panel border border-border-dim shadow-panel">
          <span className="text-[11px] font-mono uppercase text-text-dim">Public Documents Cataloged</span>
          <p className="text-2xl font-mono font-bold text-amber-400 mt-1">{documents.length}</p>
        </div>
        <div className="p-4 rounded-lg bg-panel border border-border-dim shadow-panel">
          <span className="text-[11px] font-mono uppercase text-text-dim">Historical Breach Indicators</span>
          <p className="text-2xl font-mono font-bold text-pink-400 mt-1">{breaches.length}</p>
        </div>
      </div>

      {/* 1. Cloud Storage Exposure Section */}
      <div className="space-y-3">
        <h3 className="text-sm font-mono font-semibold uppercase tracking-wider text-text-dim flex items-center gap-2">
          <Cloud className="w-4 h-4 text-orange-400" />
          Cloud Object Storage & Public Bucket Telemetry
        </h3>

        {cloudBuckets.length === 0 ? (
          <div className="p-6 rounded-lg bg-panel border border-border-dim text-xs font-mono text-text-dim">
            No public cloud storage buckets detected under target naming conventions.
          </div>
        ) : (
          <div className="grid grid-cols-1 gap-3">
            {cloudBuckets.map((bucket, idx) => {
              const props = bucket.properties || {};
              const isAccessible = props.status === 'ACCESSIBLE';

              return (
                <div
                  key={idx}
                  className="p-4 rounded-lg bg-panel border border-border-dim shadow-panel flex flex-col sm:flex-row sm:items-center justify-between gap-4"
                >
                  <div className="space-y-1">
                    <div className="flex items-center gap-2 font-mono text-sm font-bold text-text-primary">
                      {isAccessible ? (
                        <Unlock className="w-4 h-4 text-magenta-alert" />
                      ) : (
                        <Lock className="w-4 h-4 text-amber-400" />
                      )}
                      <span>{props.resource_url || bucket.label}</span>
                    </div>
                    <p className="text-xs text-text-dim font-mono">
                      Provider: <strong className="text-text-primary">{props.provider || 'Cloud Storage'}</strong> • Status:{' '}
                      <span className={isAccessible ? 'text-magenta-alert font-bold' : 'text-amber-400'}>
                        {props.status || 'DISCOVERED'}
                      </span>
                    </p>
                    {props.remediation && (
                      <p className="text-[11px] text-cyan-signal font-mono pt-1">
                        Remediation: {props.remediation}
                      </p>
                    )}
                  </div>

                  <div className="shrink-0 flex items-center gap-2">
                    <span
                      className={`px-2.5 py-1 rounded text-[10px] font-mono font-bold uppercase border ${
                        isAccessible
                          ? 'bg-rose-500/10 text-rose-400 border-rose-500/30 shadow-glow-magenta-sm'
                          : 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                      }`}
                    >
                      {props.status || 'DISCOVERED'}
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* 2. Public Documents Section */}
      <div className="space-y-3">
        <h3 className="text-sm font-mono font-semibold uppercase tracking-wider text-text-dim flex items-center gap-2">
          <FileText className="w-4 h-4 text-amber-400" />
          Cataloged Public Documents & Extracted Metadata
        </h3>

        {documents.length === 0 ? (
          <div className="p-6 rounded-lg bg-panel border border-border-dim text-xs font-mono text-text-dim">
            No public document metadata artifacts indexed.
          </div>
        ) : (
          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3">
            {documents.map((doc, idx) => {
              const props = doc.properties || {};
              const author = props.name || props.author || '';
              const source = props.source || doc.label;
              const docUrl = props.profile_url || props.url || props.link || (typeof source === 'string' && source.startsWith('http') ? source : null);
              const email = props.email || '';
              const emailsFound = props.emails_found || (props.document_info && props.document_info.emails_found) || (email ? [email] : []);
              const fileExt = (doc.label && doc.label.includes('.')) ? doc.label.split('.').pop().toUpperCase() : 'DOC';

              return (
                <div
                  key={idx}
                  className="p-4 rounded-lg bg-panel border border-border-dim shadow-panel flex flex-col justify-between space-y-3 hover:border-border-bright transition-all"
                >
                  <div className="space-y-2">
                    <div className="flex items-center justify-between gap-2">
                      <div className="flex items-center gap-2 font-mono text-xs font-bold text-text-primary truncate">
                        <FileCheck className="w-4 h-4 text-amber-400 shrink-0" />
                        <span className="truncate" title={doc.label}>{doc.label}</span>
                      </div>
                      <span className="px-1.5 py-0.5 rounded text-[10px] font-mono font-bold uppercase bg-amber-500/10 text-amber-400 border border-amber-500/30 shrink-0">
                        {fileExt}
                      </span>
                    </div>

                    <div className="text-xs font-mono text-text-dim space-y-1">
                      {author ? (
                        <div>Author / Signatory: <strong className="text-text-primary">{author}</strong></div>
                      ) : (
                        <div>Author: <span className="text-text-dim/60 italic">Unspecified in metadata</span></div>
                      )}
                      
                      {emailsFound.length > 0 && (
                        <div className="pt-1">
                          <span className="text-[10px] uppercase text-text-dim block mb-1">Emails Cited in Doc:</span>
                          <div className="flex flex-wrap gap-1">
                            {emailsFound.map((em, emIdx) => (
                              <span key={emIdx} className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-cyan-signal/10 text-cyan-signal border border-cyan-signal/30 truncate max-w-full">
                                {em}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  </div>

                  <div className="pt-2 border-t border-border-dim/40 flex items-center justify-between">
                    {docUrl ? (
                      <a
                        href={docUrl}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1 text-xs font-mono font-bold text-cyan-signal hover:text-cyan-300 hover:underline"
                      >
                        <span>Open Document</span>
                        <ExternalLink className="w-3 h-3" />
                      </a>
                    ) : (
                      <span className="text-[11px] font-mono text-text-dim truncate">{source}</span>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* 3. Breach Exposure Signals */}
      <div className="space-y-3">
        <h3 className="text-sm font-mono font-semibold uppercase tracking-wider text-text-dim flex items-center gap-2">
          <AlertOctagon className="w-4 h-4 text-pink-400" />
          Legitimate Breach Exposure Intelligence
        </h3>

        {breaches.length === 0 ? (
          <div className="p-6 rounded-lg bg-panel border border-border-dim text-xs font-mono text-text-dim">
            Zero breach exposure signals identified in authoritative defensive indices.
          </div>
        ) : (
          <div className="grid grid-cols-1 gap-3">
            {breaches.map((b, idx) => {
              const props = b.properties || {};
              return (
                <div
                  key={idx}
                  className="p-4 rounded-lg bg-panel border border-border-dim shadow-panel space-y-2"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-mono font-bold text-sm text-text-primary">
                      {props.breach_name || b.label}
                    </span>
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-pink-500/10 text-pink-400 border border-pink-500/30 uppercase">
                      Exposure Detected
                    </span>
                  </div>
                  <div className="text-xs font-mono text-text-dim space-y-1">
                    <div>
                      Masked Identifier: <strong className="text-text-primary select-all">{props.masked_identifier}</strong>
                    </div>
                    <div>Source: {props.source || 'Defensive Threat Intel'}</div>
                    {props.remediation && (
                      <div className="text-cyan-signal pt-1">
                        <strong>Remediation:</strong> {props.remediation}
                      </div>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Evidence Drawer */}
      <EvidenceDrawer
        jobId={scanId}
        evidenceId={selectedEvidenceId}
        onClose={() => setSelectedEvidenceId(null)}
      />
    </div>
  );
}
