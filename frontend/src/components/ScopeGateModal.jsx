import React, { useState, useEffect } from 'react';
import { ShieldCheck, AlertOctagon, X, ArrowRight, Loader2, Zap, Target, Flame, Server, Users, Cpu, Globe } from 'lucide-react';
import { useRegisterScope, useCreateScan } from '../api/hooks';
import { useTenant } from '../context/TenantContext';

export default function ScopeGateModal({ isOpen, onClose, onScanCreated, initialDomain = '' }) {
  const { tenantId, setActiveTarget } = useTenant();
  const [domain, setDomain] = useState(initialDomain);

  useEffect(() => {
    if (initialDomain && isOpen) {
      setDomain(initialDomain);
    }
  }, [initialDomain, isOpen]);
  const [orgName, setOrgName] = useState('');
  const [ceoName, setCeoName] = useState('');
  const [scanProfile, setScanProfile] = useState('standard');
  const [scanMode, setScanMode] = useState('full');
  const [authType, setAuthType] = useState('engagement_letter');
  const [authorizedBy, setAuthorizedBy] = useState('');
  const [attestationChecked, setAttestationChecked] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');

  const isIpTarget = /^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(domain.trim());

  // Auto-switch mode to vm_audit when an IP address is entered
  useEffect(() => {
    if (isIpTarget && scanMode === 'full') {
      setScanMode('vm_audit');
    }
  }, [isIpTarget]);

  const registerScopeMutation = useRegisterScope();
  const createScanMutation = useCreateScan();

  const isSubmitting = registerScopeMutation.isPending || createScanMutation.isPending;

  if (!isOpen) return null;

  const handleSubmit = async (e) => {
    e.preventDefault();
    setErrorMsg('');

    if (!domain.trim()) {
      setErrorMsg('Please specify a valid target domain or IP address.');
      return;
    }

    if (!attestationChecked) {
      setErrorMsg('Mandatory attestation checkbox must be confirmed before launch.');
      return;
    }

    const effectiveScanMode = isIpTarget && scanMode === 'full' ? 'vm_audit' : scanMode;

    try {
      // 1. Register Scope in Backend
      await registerScopeMutation.mutateAsync({
        domain: domain.trim(),
        authorization_type: authType,
        authorized_by: authorizedBy.trim() || 'red-team-operator',
      });

      // 2. Trigger Scan Job with Selected Scan Profile and Modular Pipeline Mode
      const scanJob = await createScanMutation.mutateAsync({
        domain: domain.trim(),
        scan_profile: scanProfile,
        scan_mode: effectiveScanMode,
        org_name: orgName.trim() || undefined,
        ceo_name: ceoName.trim() || undefined,
      });

      setActiveTarget(domain.trim());
      onScanCreated(scanJob.id, domain.trim());
      onClose();
    } catch (err) {
      setErrorMsg(err.message || 'Failed to trigger scan job.');
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-void/80 backdrop-blur-md">
      <div className="w-full max-w-xl panel-glass rounded-lg border border-border-bright shadow-2xl p-6 relative max-h-[90vh] overflow-y-auto">
        {/* Header */}
        <div className="flex items-center justify-between pb-4 border-b border-border-dim">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded bg-cyan-signal/10 border border-cyan-signal/40 flex items-center justify-center shadow-glow-cyan-sm">
              <ShieldCheck className="w-4 h-4 text-cyan-signal" />
            </div>
            <div>
              <h2 className="font-display font-bold text-base text-text-primary">
                Scope Authorization & Scan Launch
              </h2>
              <p className="text-xs text-text-dim">Configure modular pipeline stages and engagement attestation</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-text-dim hover:text-text-primary p-1 rounded transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Error Alert */}
        {errorMsg && (
          <div className="mt-4 p-3 rounded bg-magenta-alert/10 border border-magenta-alert/40 text-magenta-alert text-xs flex items-center gap-2">
            <AlertOctagon className="w-4 h-4 shrink-0" />
            <span>{errorMsg}</span>
          </div>
        )}

        {/* Form */}
        <form onSubmit={handleSubmit} className="mt-5 space-y-4">
          <div>
            <div className="flex items-center justify-between mb-1.5">
              <label className="block text-xs font-mono text-text-dim uppercase">
                Target Domain or Host IP
              </label>
              {isIpTarget && (
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-400 border border-emerald-500/40 flex items-center gap-1 font-bold">
                  <Server className="w-3 h-3" /> Host Machine / Private VM
                </span>
              )}
            </div>
            <input
              type="text"
              required
              placeholder="e.g. example.com or 10.251.132.28"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              className="w-full px-3 py-2 rounded bg-void border border-border-dim text-sm text-text-primary font-mono focus:border-cyan-signal focus:outline-none focus:shadow-glow-cyan-sm transition-all"
            />
          </div>

          {/* Modular Pipeline Mode Selector */}
          <div>
            <label className="block text-xs font-mono text-text-dim mb-1.5 uppercase">
              Pipeline Execution Mode
            </label>
            <div className="grid grid-cols-2 gap-2">
              {/* Full 360 Recon */}
              <div
                onClick={() => setScanMode('full')}
                className={`p-2.5 rounded-lg border cursor-pointer transition-all ${
                  scanMode === 'full'
                    ? 'bg-cyan-signal/10 border-cyan-signal shadow-glow-cyan-sm'
                    : 'bg-void/50 border-border-dim hover:border-border-bright'
                }`}
              >
                <div className="flex items-center gap-2 mb-1">
                  <Globe className={`w-3.5 h-3.5 ${scanMode === 'full' ? 'text-cyan-signal' : 'text-text-dim'}`} />
                  <span className="text-xs font-bold text-text-primary">Full 360° Recon</span>
                </div>
                <p className="text-[10px] text-text-dim leading-snug font-mono">
                  All 10 stages: OSINT, DNS, Ports, Tech, Vulns & People.
                </p>
              </div>

              {/* VM & Host Audit */}
              <div
                onClick={() => setScanMode('vm_audit')}
                className={`p-2.5 rounded-lg border cursor-pointer transition-all ${
                  scanMode === 'vm_audit'
                    ? 'bg-emerald-500/15 border-emerald-500 shadow-glow-green-sm'
                    : 'bg-void/50 border-border-dim hover:border-border-bright'
                }`}
              >
                <div className="flex items-center gap-2 mb-1">
                  <Server className={`w-3.5 h-3.5 ${scanMode === 'vm_audit' ? 'text-emerald-400' : 'text-text-dim'}`} />
                  <span className="text-xs font-bold text-text-primary">VM & Host Audit</span>
                </div>
                <p className="text-[10px] text-text-dim leading-snug font-mono">
                  Direct L7 Port Probes, Web Fingerprint, Nuclei & CVEs.
                </p>
              </div>

              {/* Infra & Vulns Only */}
              <div
                onClick={() => setScanMode('infra_vuln')}
                className={`p-2.5 rounded-lg border cursor-pointer transition-all ${
                  scanMode === 'infra_vuln'
                    ? 'bg-cyan-signal/10 border-cyan-signal shadow-glow-cyan-sm'
                    : 'bg-void/50 border-border-dim hover:border-border-bright'
                }`}
              >
                <div className="flex items-center gap-2 mb-1">
                  <Cpu className={`w-3.5 h-3.5 ${scanMode === 'infra_vuln' ? 'text-cyan-signal' : 'text-text-dim'}`} />
                  <span className="text-xs font-bold text-text-primary">Infra & Vulns Only</span>
                </div>
                <p className="text-[10px] text-text-dim leading-snug font-mono">
                  Subdomains, IP Resolve, Ports & CVEs (No People OSINT).
                </p>
              </div>

              {/* People & Identity OSINT */}
              <div
                onClick={() => setScanMode('people_only')}
                className={`p-2.5 rounded-lg border cursor-pointer transition-all ${
                  scanMode === 'people_only'
                    ? 'bg-magenta-alert/10 border-magenta-alert shadow-glow-magenta-sm'
                    : 'bg-void/50 border-border-dim hover:border-border-bright'
                }`}
              >
                <div className="flex items-center gap-2 mb-1">
                  <Users className={`w-3.5 h-3.5 ${scanMode === 'people_only' ? 'text-magenta-alert' : 'text-text-dim'}`} />
                  <span className="text-xs font-bold text-text-primary">People OSINT Only</span>
                </div>
                <p className="text-[10px] text-text-dim leading-snug font-mono">
                  Identity resolution, emails, documents & executive exposure.
                </p>
              </div>
            </div>
          </div>

          {/* Seed Intelligence Fields (Optional) */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 p-3 rounded-lg bg-void/40 border border-border-dim/60">
            <div>
              <label className="block text-[11px] font-mono text-text-dim mb-1 uppercase">
                Target Org Name <span className="text-text-dim/60 lowercase font-sans">(optional)</span>
              </label>
              <input
                type="text"
                placeholder="e.g. Example Corp"
                value={orgName}
                onChange={(e) => setOrgName(e.target.value)}
                className="w-full px-2.5 py-1.5 rounded bg-void border border-border-dim text-xs text-text-primary font-mono focus:border-cyan-signal focus:outline-none transition-all"
              />
            </div>
            <div>
              <label className="block text-[11px] font-mono text-text-dim mb-1 uppercase">
                Key Person / CEO <span className="text-text-dim/60 lowercase font-sans">(optional)</span>
              </label>
              <input
                type="text"
                placeholder="e.g. Jane Doe (CEO / Founder)"
                value={ceoName}
                onChange={(e) => setCeoName(e.target.value)}
                className="w-full px-2.5 py-1.5 rounded bg-void border border-border-dim text-xs text-text-primary font-mono focus:border-cyan-signal focus:outline-none transition-all"
              />
            </div>
          </div>

          {/* Scan Depth Profile Selector */}
          <div>
            <label className="block text-xs font-mono text-text-dim mb-1.5 uppercase">
              Scan Depth & Tactical Intensity
            </label>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5">
              {/* Fast / Stealth Card */}
              <div
                onClick={() => setScanProfile('fast')}
                className={`p-3 rounded-lg border cursor-pointer transition-all ${
                  scanProfile === 'fast'
                    ? 'bg-cyan-signal/10 border-cyan-signal shadow-glow-cyan-sm'
                    : 'bg-void/50 border-border-dim hover:border-border-bright'
                }`}
              >
                <div className="flex items-center gap-2 mb-1">
                  <Zap className={`w-4 h-4 ${scanProfile === 'fast' ? 'text-cyan-signal' : 'text-text-dim'}`} />
                  <span className="text-xs font-bold text-text-primary">Fast / Stealth</span>
                </div>
                <p className="text-[11px] text-text-dim leading-snug">
                  Top 100 ports, fast probes (~30s).
                </p>
              </div>

              {/* Standard Assessment Card */}
              <div
                onClick={() => setScanProfile('standard')}
                className={`p-3 rounded-lg border cursor-pointer transition-all ${
                  scanProfile === 'standard'
                    ? 'bg-cyan-signal/10 border-cyan-signal shadow-glow-cyan-sm'
                    : 'bg-void/50 border-border-dim hover:border-border-bright'
                }`}
              >
                <div className="flex items-center gap-2 mb-1">
                  <Target className={`w-4 h-4 ${scanProfile === 'standard' ? 'text-cyan-signal' : 'text-text-dim'}`} />
                  <span className="text-xs font-bold text-text-primary">Standard Recon</span>
                </div>
                <p className="text-[11px] text-text-dim leading-snug">
                  Top 1000 ports, L7 probes & CVEs (~2m).
                </p>
              </div>

              {/* Deep Red Team Card */}
              <div
                onClick={() => setScanProfile('deep')}
                className={`p-3 rounded-lg border cursor-pointer transition-all ${
                  scanProfile === 'deep'
                    ? 'bg-magenta-alert/10 border-magenta-alert shadow-glow-magenta-sm'
                    : 'bg-void/50 border-border-dim hover:border-border-bright'
                }`}
              >
                <div className="flex items-center gap-2 mb-1">
                  <Flame className={`w-4 h-4 ${scanProfile === 'deep' ? 'text-magenta-alert' : 'text-text-dim'}`} />
                  <span className="text-xs font-bold text-text-primary">Deep Red Team</span>
                </div>
                <p className="text-[11px] text-text-dim leading-snug">
                  Full ports, aggressive L7, Nuclei & CVEs (~5m+).
                </p>
              </div>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-mono text-text-dim mb-1.5 uppercase">
                Authorization Type
              </label>
              <select
                value={authType}
                onChange={(e) => setAuthType(e.target.value)}
                className="w-full px-3 py-2 rounded bg-void border border-border-dim text-xs text-text-primary focus:border-cyan-signal focus:outline-none transition-all"
              >
                <option value="engagement_letter">Engagement Letter (Formal)</option>
                <option value="self_attested">Self-Attested (Dev / Lab)</option>
              </select>
            </div>

            <div>
              <label className="block text-xs font-mono text-text-dim mb-1.5 uppercase">
                Authorized By (Contact)
              </label>
              <input
                type="text"
                placeholder="lead@target.com"
                value={authorizedBy}
                onChange={(e) => setAuthorizedBy(e.target.value)}
                className="w-full px-3 py-2 rounded bg-void border border-border-dim text-xs text-text-primary font-mono focus:border-cyan-signal focus:outline-none transition-all"
              />
            </div>
          </div>

          {/* Mandatory Checkbox Attestation */}
          <div className="p-3 rounded bg-void border border-border-dim space-y-2">
            <label className="flex items-start gap-3 cursor-pointer select-none">
              <input
                type="checkbox"
                checked={attestationChecked}
                onChange={(e) => setAttestationChecked(e.target.checked)}
                className="mt-0.5 w-4 h-4 rounded bg-panel border-border-dim text-cyan-signal focus:ring-0 focus:ring-offset-0 cursor-pointer"
              />
              <span className="text-xs text-text-primary leading-snug">
                I formally confirm and attest that this target domain is in-scope for authorized red team operations.
              </span>
            </label>
          </div>

          {/* Actions */}
          <div className="pt-3 flex items-center justify-end gap-3 border-t border-border-dim">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 rounded text-xs font-medium text-text-dim hover:text-text-primary transition-colors"
            >
              Cancel
            </button>

            <button
              type="submit"
              disabled={isSubmitting}
              className="flex items-center gap-2 px-5 py-2 rounded bg-cyan-signal text-black font-semibold text-xs tracking-wide shadow-glow-cyan-sm hover:brightness-110 active:scale-[0.98] transition-all disabled:opacity-50"
            >
              {isSubmitting ? (
                <>
                  <Loader2 className="w-3.5 h-3.5 animate-spin" />
                  <span>Launching Pipeline...</span>
                </>
              ) : (
                <>
                  <span>Authorize & Launch</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
