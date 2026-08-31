import React, { useState } from 'react';
import {
  Users,
  Mail,
  Briefcase,
  Building,
  ExternalLink,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  UserCheck,
  Globe,
  FileCheck,
  Layers,
  Sparkles,
  Key,
  FolderTree,
  Terminal,
  Clock,
  CheckCircle2,
  HelpCircle,
  Network,
  Share2,
  Building2,
} from 'lucide-react';
import EvidenceDrawer from '../components/graph/EvidenceDrawer';

export default function PeopleIntelligenceView({ scanId, peopleData = {} }) {
  const [selectedEvidenceId, setSelectedEvidenceId] = useState(null);
  const [activeTab, setActiveTab] = useState('STAFF'); // 'STAFF' | 'FOOTPRINT' | 'SUBSIDIARIES'
  const [selectedDepartment, setSelectedDepartment] = useState('ALL');

  const employees = peopleData.people || peopleData.employees || [];
  const footprint = peopleData.unresolved_footprint || [];
  const subsidiaries = peopleData.subsidiaries || [];
  const roleMailboxes = peopleData.role_mailboxes || [];
  const emails = peopleData.confirmed_count !== undefined ? peopleData.confirmed_count : (peopleData.corporate_emails?.length || 0);
  const syntax = peopleData.email_pattern || peopleData.pattern_info?.pattern || 'unknown';
  const patternConf = peopleData.pattern_info?.confidence || 45;
  const patternStatus = peopleData.pattern_info?.status || 'UNVERIFIED_DEFAULT';
  const hvtCount = peopleData.hvt_count || employees.filter(e => e.is_hvt).length;
  const departments = peopleData.departments || {};
  const docForensics = peopleData.document_forensics || [];
  const adUsernames = peopleData.ad_usernames || [];
  const internalPaths = peopleData.internal_paths || [];

  const filteredEmployees = selectedDepartment === 'ALL'
    ? employees
    : employees.filter(e => (e.department || 'General Staff') === selectedDepartment);

  return (
    <div className="space-y-6">
      {/* Metric Summary Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="p-4 rounded-lg bg-panel border border-border-dim shadow-panel">
          <span className="text-[11px] font-mono uppercase text-text-dim">Verified Human Personnel</span>
          <p className="text-2xl font-mono font-bold text-emerald-400 mt-1">{employees.length}</p>
          <span className="text-[10px] font-mono text-text-dim">Biological Identities Only</span>
        </div>

        <div className="p-4 rounded-lg bg-panel border border-magenta-alert/30 bg-magenta-alert/5 shadow-panel">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-mono uppercase text-magenta-alert font-bold">High-Value Targets (HVT)</span>
            <ShieldAlert className="w-4 h-4 text-magenta-alert" />
          </div>
          <p className="text-2xl font-mono font-bold text-magenta-alert mt-1">{hvtCount}</p>
          <span className="text-[10px] font-mono text-text-dim">C-Suite & Privileged Personnel</span>
        </div>

        <div className="p-4 rounded-lg bg-panel border border-border-dim shadow-panel">
          <span className="text-[11px] font-mono uppercase text-text-dim">Corporate Mailboxes</span>
          <p className="text-2xl font-mono font-bold text-cyan-signal mt-1">{emails + roleMailboxes.length}</p>
          <span className="text-[10px] font-mono text-text-dim">{emails} Personal • {roleMailboxes.length} Role Inboxes</span>
        </div>

        <div className="p-4 rounded-lg bg-panel border border-border-dim shadow-panel">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-mono uppercase text-text-dim">Induced Syntax Pattern</span>
            <span className={`px-1.5 py-0.5 rounded text-[9px] font-mono font-bold ${
              patternStatus === 'UNVERIFIED_DEFAULT'
                ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                : 'bg-cyan-signal/15 text-cyan-signal'
            }`}>
              {patternConf}% Match
            </span>
          </div>
          <p className="text-xs font-mono font-bold text-text-primary mt-2 truncate select-all">{syntax}</p>
          <span className="text-[10px] font-mono text-text-dim">
            {patternStatus === 'UNVERIFIED_DEFAULT' ? 'Default Baseline (No Human Seeds)' : 'Trained on Human Seeds'}
          </span>
        </div>
      </div>

      {/* Main Section Navigation Tabs */}
      <div className="flex border-b border-border-dim gap-2">
        <button
          onClick={() => setActiveTab('STAFF')}
          className={`pb-3 px-3 text-xs font-mono font-bold uppercase tracking-wider transition-all border-b-2 flex items-center gap-2 ${
            activeTab === 'STAFF'
              ? 'border-cyan-signal text-cyan-signal'
              : 'border-transparent text-text-dim hover:text-text-primary'
          }`}
        >
          <UserCheck className="w-4 h-4" />
          <span>Verified Personnel ({employees.length})</span>
        </button>

        <button
          onClick={() => setActiveTab('FOOTPRINT')}
          className={`pb-3 px-3 text-xs font-mono font-bold uppercase tracking-wider transition-all border-b-2 flex items-center gap-2 ${
            activeTab === 'FOOTPRINT'
              ? 'border-cyan-signal text-cyan-signal'
              : 'border-transparent text-text-dim hover:text-text-primary'
          }`}
        >
          <HelpCircle className="w-4 h-4" />
          <span>Unresolved Digital Footprint & Handles ({footprint.length + roleMailboxes.length})</span>
        </button>

        <button
          onClick={() => setActiveTab('SUBSIDIARIES')}
          className={`pb-3 px-3 text-xs font-mono font-bold uppercase tracking-wider transition-all border-b-2 flex items-center gap-2 ${
            activeTab === 'SUBSIDIARIES'
              ? 'border-cyan-signal text-cyan-signal'
              : 'border-transparent text-text-dim hover:text-text-primary'
          }`}
        >
          <Building2 className="w-4 h-4" />
          <span>Corporate Subsidiaries & Affiliates ({subsidiaries.length})</span>
        </button>
      </div>

      {/* TAB 1: VERIFIED HUMAN PERSONNEL */}
      {activeTab === 'STAFF' && (
        <div className="space-y-6">
          {/* Department Filter Chips */}
          {Object.keys(departments).length > 0 && (
            <div className="p-3 rounded-lg bg-void/50 border border-border-dim space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-mono font-bold uppercase tracking-wider text-text-dim flex items-center gap-1.5">
                  <Building className="w-3.5 h-3.5 text-cyan-signal" />
                  <span>Department & Organizational Distribution</span>
                </span>
                <span className="text-[10px] font-mono text-text-dim">{employees.length} Personnel Total</span>
              </div>
              <div className="flex flex-wrap gap-1.5">
                <button
                  onClick={() => setSelectedDepartment('ALL')}
                  className={`px-2.5 py-1 rounded text-xs font-mono font-semibold transition-all ${
                    selectedDepartment === 'ALL'
                      ? 'bg-cyan-signal text-black shadow-glow-cyan-sm'
                      : 'bg-void border border-border-dim text-text-dim hover:text-text-primary'
                  }`}
                >
                  All Personnel ({employees.length})
                </button>
                {Object.entries(departments).map(([dept, count]) => (
                  <button
                    key={dept}
                    onClick={() => setSelectedDepartment(dept)}
                    className={`px-2.5 py-1 rounded text-xs font-mono font-semibold transition-all ${
                      selectedDepartment === dept
                        ? 'bg-cyan-signal text-black shadow-glow-cyan-sm'
                        : 'bg-void border border-border-dim text-text-dim hover:text-text-primary'
                    }`}
                  >
                    {dept} ({count})
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* Document Forensics Disclosures */}
          {(adUsernames.length > 0 || internalPaths.length > 0 || docForensics.length > 0) && (
            <div className="p-4 rounded-lg bg-panel border border-orange-500/40 bg-orange-500/5 space-y-3">
              <div className="flex items-center justify-between">
                <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-orange-400 flex items-center gap-2">
                  <FolderTree className="w-4 h-4 text-orange-400" />
                  <span>Public Document Forensics & Active Directory Disclosures ({docForensics.length} Files)</span>
                </h4>
                <span className="px-2 py-0.5 rounded bg-orange-500/20 text-orange-400 text-[10px] font-mono font-bold">
                  Metadata Leaks
                </span>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs font-mono">
                {adUsernames.length > 0 && (
                  <div className="p-3 rounded bg-void/80 border border-border-dim space-y-1.5">
                    <span className="text-[10px] font-mono uppercase font-bold text-text-dim flex items-center gap-1">
                      <Key className="w-3 h-3 text-magenta-alert" />
                      <span>Exposed Active Directory Accounts ({adUsernames.length})</span>
                    </span>
                    <div className="flex flex-wrap gap-1">
                      {adUsernames.map((u, uIdx) => (
                        <span key={uIdx} className="px-2 py-0.5 rounded bg-magenta-alert/15 border border-magenta-alert/40 text-magenta-alert text-[11px] font-bold">
                          {u}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {internalPaths.length > 0 && (
                  <div className="p-3 rounded bg-void/80 border border-border-dim space-y-1.5">
                    <span className="text-[10px] font-mono uppercase font-bold text-text-dim flex items-center gap-1">
                      <Terminal className="w-3 h-3 text-cyan-signal" />
                      <span>Internal Network Share / UNC Paths ({internalPaths.length})</span>
                    </span>
                    <div className="space-y-1 max-h-24 overflow-y-auto">
                      {internalPaths.map((p, pIdx) => (
                        <div key={pIdx} className="text-[10px] text-cyan-signal truncate select-all bg-void px-1.5 py-0.5 rounded border border-border-dim">
                          {p}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Personnel Grid */}
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-mono font-semibold uppercase tracking-wider text-text-dim flex items-center gap-2">
                <UserCheck className="w-4 h-4 text-emerald-400" />
                Evidence-Resolved People Entities ({filteredEmployees.length})
              </h3>
              <span className="text-xs font-mono text-text-dim">
                Bayesian Signal Resolution • HVT Prioritized
              </span>
            </div>

            {filteredEmployees.length === 0 ? (
              <div className="p-8 rounded-lg bg-panel border border-border-dim text-center text-text-dim text-xs font-mono">
                No employee profiles match the selected department filter.
              </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {filteredEmployees.map((emp, idx) => {
                  const name = emp.name || emp.full_name || `Personnel #${idx + 1}`;
                  const title = emp.title || emp.job_title || 'Identified Staff';
                  const email = emp.email;
                  const source = emp.source || (emp.sources ? emp.sources[0] : 'public_profile');
                  const conf = emp.confidence || 85;
                  const isHvt = emp.is_hvt;
                  const dept = emp.department || 'General Staff';
                  const temporal = emp.temporal_status || 'active';
                  const status = conf >= 85 ? 'confirmed' : conf >= 65 ? 'likely' : 'possible_match';
                  const contradictions = emp.contradicting_evidence || [];
                  const supporting = emp.supporting_evidence || (emp.sources ? emp.sources.map(s => `Corroborated via ${s}`) : [`Observed from ${source} telemetry.`]);
                  const verStatus = emp.verification_status || 'Pattern Inferred';

                  return (
                    <div
                      key={idx}
                      className={`p-5 rounded-lg border shadow-panel space-y-3.5 transition-all ${
                        isHvt
                          ? 'bg-magenta-alert/5 border-magenta-alert/40 shadow-glow-magenta-sm'
                          : 'bg-panel border-border-dim hover:border-border-bright'
                      }`}
                    >
                      {/* Header */}
                      <div className="flex items-start justify-between gap-3">
                        <div className="flex items-center gap-3">
                          <div className={`w-10 h-10 rounded-full border flex items-center justify-center font-mono font-bold ${
                            isHvt
                              ? 'bg-magenta-alert/20 border-magenta-alert/50 text-magenta-alert'
                              : 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
                          }`}>
                            {name.charAt(0)}
                          </div>
                          <div>
                            <div className="flex items-center gap-2 flex-wrap">
                              <h4 className="font-mono font-bold text-sm text-text-primary">{name}</h4>
                              {isHvt && (
                                <span className="px-1.5 py-0.5 rounded bg-magenta-alert/20 text-magenta-alert border border-magenta-alert/60 text-[9px] font-mono font-bold flex items-center gap-1">
                                  <ShieldAlert className="w-2.5 h-2.5" />
                                  <span>HVT</span>
                                </span>
                              )}
                              {temporal === 'historical' && (
                                <span className="px-1.5 py-0.5 rounded bg-yellow-500/10 text-yellow-400 border border-yellow-500/30 text-[9px] font-mono flex items-center gap-1">
                                  <Clock className="w-2.5 h-2.5" />
                                  <span>Historical</span>
                                </span>
                              )}
                            </div>
                            <div className="flex items-center gap-1.5 text-xs text-text-dim mt-0.5">
                              <Briefcase className="w-3 h-3 text-text-dim shrink-0" />
                              <span className="truncate">{title}</span>
                              <span className="text-text-dim/60">•</span>
                              <span className="text-cyan-signal text-[11px] font-mono">{dept}</span>
                            </div>
                          </div>
                        </div>

                        {/* Status Badge */}
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-mono font-semibold uppercase border shrink-0 ${
                            status === 'confirmed'
                              ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                              : status === 'likely'
                              ? 'bg-cyan-signal/10 text-cyan-signal border-cyan-signal/30'
                              : 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                          }`}
                        >
                          {conf}%
                        </span>
                      </div>

                      {/* Contact / Email */}
                      {email && (
                        <div className="flex items-center gap-2 text-xs font-mono text-cyan-signal p-2 rounded bg-void border border-border-dim">
                          <Mail className="w-3.5 h-3.5 shrink-0" />
                          <span className="truncate select-all">{email}</span>
                          <span className={`ml-auto text-[9px] uppercase font-bold px-1.5 py-0.5 rounded ${
                            verStatus.includes('250') || verStatus.includes('Direct')
                              ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40'
                              : verStatus.includes('Catch-All')
                              ? 'bg-cyan-signal/20 text-cyan-signal border border-cyan-signal/40'
                              : 'bg-amber-500/15 text-amber-400 border border-amber-500/30'
                          }`}>
                            {verStatus}
                          </span>
                        </div>
                      )}

                      {/* Supporting Evidence List */}
                      <div className="space-y-1 pt-1">
                        <span className="text-[10px] font-mono uppercase tracking-wider text-text-dim">
                          Evidence Provenance ({supporting.length})
                        </span>
                        <div className="space-y-1">
                          {supporting.slice(0, 2).map((s, sIdx) => (
                            <div
                              key={sIdx}
                              className="text-[11px] font-mono text-text-dim flex items-center gap-1.5"
                            >
                              <CheckCircle2 className="w-3 h-3 text-emerald-400 shrink-0" />
                              <span className="truncate">{s}</span>
                            </div>
                          ))}
                        </div>
                      </div>

                      {/* Contradiction Warning if any */}
                      {contradictions.length > 0 && (
                        <div className="p-2.5 rounded bg-magenta-alert/10 border border-magenta-alert/30 text-magenta-alert text-xs font-mono space-y-1">
                          <div className="flex items-center gap-1.5 font-bold">
                            <AlertTriangle className="w-3.5 h-3.5" />
                            <span>Contradiction Preserved:</span>
                          </div>
                          <p className="text-[11px] opacity-90">{contradictions[0]}</p>
                        </div>
                      )}

                      {/* Footer */}
                      <div className="flex items-center justify-between text-[11px] font-mono text-text-dim pt-2 border-t border-border-dim">
                        <span>Source: {source}</span>
                        {emp.profile_url && (
                          <a
                            href={emp.profile_url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-cyan-signal hover:underline flex items-center gap-1"
                          >
                            <span>Profile</span>
                            <ExternalLink className="w-3 h-3" />
                          </a>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>
      )}

      {/* TAB 2: UNRESOLVED DIGITAL FOOTPRINT & HANDLES */}
      {activeTab === 'FOOTPRINT' && (
        <div className="space-y-4">
          <div className="p-4 rounded-lg bg-panel border border-border-dim shadow-panel flex items-start gap-3">
            <HelpCircle className="w-5 h-5 text-cyan-signal shrink-0 mt-0.5" />
            <div className="space-y-1">
              <h4 className="text-sm font-mono font-bold text-text-primary">
                Unresolved Digital Footprint & Organizational Handles
              </h4>
              <p className="text-xs font-mono text-text-dim">
                These entities were discovered during public reconnaissance but classified as non-human corporate assets, regional branch pages, operating brands, or generic inboxes. They are isolated here to keep the executive personnel roster 100% human-verified.
              </p>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {footprint.map((item, idx) => (
              <div key={idx} className="p-4 rounded-lg bg-panel border border-border-dim shadow-panel space-y-2">
                <div className="flex items-start justify-between gap-2">
                  <div>
                    <h5 className="font-mono font-bold text-sm text-text-primary">{item.name}</h5>
                    <p className="text-xs font-mono text-text-dim">{item.title}</p>
                  </div>
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono uppercase bg-void border border-border-dim text-cyan-signal">
                    {item.entity_type || 'Digital Asset'}
                  </span>
                </div>

                <div className="p-2 rounded bg-void text-[11px] font-mono text-text-dim space-y-1">
                  <div><strong className="text-text-primary">Classification Reason:</strong> {item.classification_reason || 'Identified corporate entity string'}</div>
                  <div><strong className="text-text-primary">Platform / Source:</strong> {item.platform} ({item.source})</div>
                </div>

                {item.profile_url && (
                  <a
                    href={item.profile_url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-xs font-mono text-cyan-signal hover:underline inline-flex items-center gap-1 pt-1"
                  >
                    <span>View Public Asset</span>
                    <ExternalLink className="w-3 h-3" />
                  </a>
                )}
              </div>
            ))}

            {roleMailboxes.map((mb, idx) => (
              <div key={`role-${idx}`} className="p-4 rounded-lg bg-panel border border-border-dim shadow-panel space-y-2">
                <div className="flex items-start justify-between gap-2">
                  <div>
                    <h5 className="font-mono font-bold text-sm text-cyan-signal select-all">{mb.email}</h5>
                    <p className="text-xs font-mono text-text-dim">{mb.name} • {mb.title}</p>
                  </div>
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono uppercase bg-void border border-border-dim text-emerald-400">
                    Role Mailbox
                  </span>
                </div>
                <div className="p-2 rounded bg-void text-[11px] font-mono text-text-dim">
                  <span>Generic corporate contact inbox. Excluded from human naming pattern induction.</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* TAB 3: CORPORATE SUBSIDIARIES & BRAND AFFILIATES */}
      {activeTab === 'SUBSIDIARIES' && (
        <div className="space-y-4">
          <div className="p-4 rounded-lg bg-panel border border-border-dim shadow-panel flex items-start gap-3">
            <Building2 className="w-5 h-5 text-cyan-signal shrink-0 mt-0.5" />
            <div className="space-y-1">
              <h4 className="text-sm font-mono font-bold text-text-primary">
                Multi-Anchor Confirmed Corporate Subsidiaries
              </h4>
              <p className="text-xs font-mono text-text-dim">
                Subsidiaries discovered and confirmed across 5 cryptographic & infrastructure anchors: TLS Subject Alternative Names (SANs), Shared Nameservers, WHOIS registrant identity, and statutory document organograms. Third-party vendor noise is automatically rejected.
              </p>
            </div>
          </div>

          {subsidiaries.length === 0 ? (
            <div className="p-8 rounded-lg bg-panel border border-border-dim text-center text-text-dim text-xs font-mono">
              No multi-anchor subsidiary domains detected for this target.
            </div>
          ) : (
            <div className="grid grid-cols-1 gap-4">
              {subsidiaries.map((sub, idx) => {
                const candDom = sub.candidate_domain;
                const score = sub.confidence_score || 70;
                const anchors = sub.anchors || [];

                return (
                  <div key={idx} className="p-5 rounded-lg bg-panel border border-border-dim shadow-panel space-y-3">
                    <div className="flex items-start justify-between gap-3">
                      <div>
                        <div className="flex items-center gap-2">
                          <h4 className="font-mono font-bold text-base text-cyan-signal select-all">{candDom}</h4>
                          <span className="px-2 py-0.5 rounded text-[10px] font-mono uppercase bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 font-bold">
                            Confirmed Subsidiary
                          </span>
                        </div>
                        <p className="text-xs font-mono text-text-dim mt-0.5">
                          Parent Organization: <strong className="text-text-primary">{sub.parent_domain}</strong>
                        </p>
                      </div>
                      <span className="px-2.5 py-1 rounded text-xs font-mono font-bold bg-cyan-signal/15 text-cyan-signal border border-cyan-signal/30">
                        {score}% Confidence
                      </span>
                    </div>

                    <div className="space-y-1.5 pt-1">
                      <span className="text-[11px] font-mono uppercase font-bold text-text-dim">Corroborating Infrastructure Anchors:</span>
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                        {anchors.map((a, aIdx) => (
                          <div key={aIdx} className="p-2 rounded bg-void border border-border-dim text-xs font-mono space-y-0.5">
                            <div className="flex items-center justify-between">
                              <span className="font-bold text-text-primary">{a.anchor}</span>
                              <span className="text-emerald-400">+{a.weight}%</span>
                            </div>
                            <p className="text-[11px] text-text-dim">{a.description}</p>
                          </div>
                        ))}
                      </div>
                    </div>

                    <div className="pt-2 border-t border-border-dim flex items-center justify-between">
                      <span className="text-xs font-mono text-text-dim">Status: {sub.status}</span>
                      <a
                        href={`https://${candDom}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-xs font-mono text-cyan-signal hover:underline inline-flex items-center gap-1"
                      >
                        <span>Inspect Domain</span>
                        <ExternalLink className="w-3 h-3" />
                      </a>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* Evidence Drawer */}
      <EvidenceDrawer
        jobId={scanId}
        evidenceId={selectedEvidenceId}
        onClose={() => setSelectedEvidenceId(null)}
      />
    </div>
  );
}
