import React, { useState } from 'react';
import { ShieldCheck, Plus, Building2, Globe, Clock, Check, AlertCircle, CheckCircle2, X } from 'lucide-react';
import { useScopes, useRegisterScope, useTenants, useCreateTenant } from '../api/hooks';
import { useTenant } from '../context/TenantContext';
import { LoadingState } from '../components/LoadingState';

export default function ScopesSettingsView() {
  const { tenantId, setTenantId } = useTenant();
  const { data: scopes = [], isLoading: scopesLoading } = useScopes();
  const { data: tenants = [] } = useTenants();

  const [newDomain, setNewDomain] = useState('');
  const [authType, setAuthType] = useState('engagement_letter');
  const [authorizedBy, setAuthorizedBy] = useState('');
  const [scopeError, setScopeError] = useState(null);
  const [scopeSuccess, setScopeSuccess] = useState(null);

  const [newTenantName, setNewTenantName] = useState('');
  const [tenantError, setTenantError] = useState(null);
  const [tenantSuccess, setTenantSuccess] = useState(null);

  const registerScopeMutation = useRegisterScope();
  const createTenantMutation = useCreateTenant();

  const handleAddScope = async (e) => {
    e.preventDefault();
    setScopeError(null);
    setScopeSuccess(null);

    const cleanDomain = newDomain.trim();
    if (!cleanDomain) {
      setScopeError('Please enter a target domain name.');
      return;
    }

    try {
      await registerScopeMutation.mutateAsync({
        domain: cleanDomain,
        authorization_type: authType,
        authorized_by: authorizedBy.trim() || 'operator',
      });
      setScopeSuccess(`Domain '${cleanDomain}' registered in authorized scope.`);
      setNewDomain('');
      setAuthorizedBy('');
    } catch (err) {
      setScopeError(err.message || 'Failed to register scope.');
    }
  };

  const handleAddTenant = async (e) => {
    e.preventDefault();
    setTenantError(null);
    setTenantSuccess(null);

    const cleanName = newTenantName.trim();
    if (!cleanName) {
      setTenantError('Please enter an organization workspace name.');
      return;
    }

    if (cleanName.length < 2) {
      setTenantError('Organization workspace name must be at least 2 characters long.');
      return;
    }

    try {
      const res = await createTenantMutation.mutateAsync({
        name: cleanName,
      });
      setTenantId(res.id);
      setTenantSuccess(`Workspace '${cleanName}' created successfully.`);
      setNewTenantName('');
    } catch (err) {
      setTenantError(err.message || 'Failed to create tenant workspace.');
    }
  };

  return (
    <div className="space-y-8 max-w-5xl">
      {/* Header */}
      <div className="p-5 rounded-lg panel-glass border border-border-dim shadow-panel">
        <h1 className="font-display font-bold text-xl text-text-primary">
          Scope Governance & Workspace Management
        </h1>
        <p className="text-xs text-text-dim mt-1">
          Manage authorized targets, engagement attestation registries, and multi-tenant organization workspaces.
        </p>
      </div>

      {/* Section 1: Authorized Scopes */}
      <div className="space-y-4">
        <div className="flex items-center gap-2">
          <Globe className="w-4 h-4 text-cyan-signal" />
          <h2 className="font-display font-bold text-base text-text-primary">
            Authorized Target Scopes
          </h2>
        </div>

        {/* Scope Error & Success Banners */}
        {scopeError && (
          <div className="p-3 rounded bg-magenta-alert/10 border border-magenta-alert/40 text-xs font-mono text-magenta-alert flex items-center justify-between">
            <div className="flex items-center gap-2">
              <AlertCircle className="w-4 h-4 shrink-0" />
              <span>{scopeError}</span>
            </div>
            <button onClick={() => setScopeError(null)} className="text-magenta-alert hover:brightness-125">
              <X className="w-4 h-4" />
            </button>
          </div>
        )}
        {scopeSuccess && (
          <div className="p-3 rounded bg-success-green/10 border border-success-green/40 text-xs font-mono text-success-green flex items-center justify-between">
            <div className="flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 shrink-0" />
              <span>{scopeSuccess}</span>
            </div>
            <button onClick={() => setScopeSuccess(null)} className="text-success-green hover:brightness-125">
              <X className="w-4 h-4" />
            </button>
          </div>
        )}

        {/* Add Scope Form */}
        <form onSubmit={handleAddScope} className="p-4 rounded-lg bg-void border border-border-dim grid grid-cols-1 sm:grid-cols-4 gap-3">
          <div>
            <label className="block text-[10px] font-mono text-text-dim uppercase mb-1">Target Domain</label>
            <input
              type="text"
              required
              placeholder="e.g. acmecorp.com"
              value={newDomain}
              onChange={(e) => setNewDomain(e.target.value)}
              className="w-full px-3 py-1.5 rounded bg-panel border border-border-dim text-xs text-text-primary font-mono focus:border-cyan-signal focus:outline-none"
            />
          </div>

          <div>
            <label className="block text-[10px] font-mono text-text-dim uppercase mb-1">Authorization</label>
            <select
              value={authType}
              onChange={(e) => setAuthType(e.target.value)}
              className="w-full px-3 py-1.5 rounded bg-panel border border-border-dim text-xs text-text-primary focus:border-cyan-signal focus:outline-none"
            >
              <option value="engagement_letter">Engagement Letter</option>
              <option value="self_attested">Self-Attested Lab</option>
            </select>
          </div>

          <div>
            <label className="block text-[10px] font-mono text-text-dim uppercase mb-1">Authorized By</label>
            <input
              type="text"
              placeholder="lead@target.com"
              value={authorizedBy}
              onChange={(e) => setAuthorizedBy(e.target.value)}
              className="w-full px-3 py-1.5 rounded bg-panel border border-border-dim text-xs text-text-primary font-mono focus:border-cyan-signal focus:outline-none"
            />
          </div>

          <div className="flex items-end">
            <button
              type="submit"
              disabled={registerScopeMutation.isPending}
              className="w-full flex items-center justify-center gap-2 py-1.5 rounded bg-cyan-signal text-black font-semibold text-xs tracking-wide shadow-glow-cyan-sm hover:brightness-110 active:scale-[0.98] transition-all disabled:opacity-50"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>{registerScopeMutation.isPending ? 'Registering...' : 'Register Scope'}</span>
            </button>
          </div>
        </form>

        {/* Scopes Table */}
        <div className="panel-glass rounded-lg border border-border-dim overflow-hidden">
          {scopesLoading ? (
            <LoadingState message="Loading authorized scopes..." />
          ) : scopes.length === 0 ? (
            <div className="py-8 text-center text-xs text-text-dim font-mono">
              No target domains registered in scope for this tenant yet.
            </div>
          ) : (
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-border-dim bg-void/50 text-text-dim font-mono text-[11px]">
                  <th className="py-2.5 px-4">DOMAIN</th>
                  <th className="py-2.5 px-4">TYPE</th>
                  <th className="py-2.5 px-4">AUTHORIZED BY</th>
                  <th className="py-2.5 px-4">REGISTERED AT</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border-dim/60 font-mono">
                {scopes.map((s) => (
                  <tr key={s.id} className="hover:bg-void/40">
                    <td className="py-2.5 px-4 text-cyan-signal font-semibold">{s.domain}</td>
                    <td className="py-2.5 px-4 text-text-primary">{s.authorization_type}</td>
                    <td className="py-2.5 px-4 text-text-dim">{s.authorized_by || 'N/A'}</td>
                    <td className="py-2.5 px-4 text-text-dim text-[11px]">
                      {s.created_at ? new Date(s.created_at).toLocaleDateString() : 'N/A'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {/* Section 2: Tenant Workspace Management */}
      <div className="space-y-4 pt-4 border-t border-border-dim">
        <div className="flex items-center gap-2">
          <Building2 className="w-4 h-4 text-cyan-signal" />
          <h2 className="font-display font-bold text-base text-text-primary">
            Tenant Organization Workspaces
          </h2>
        </div>

        {/* Tenant Error & Success Banners */}
        {tenantError && (
          <div className="p-3 rounded bg-magenta-alert/10 border border-magenta-alert/40 text-xs font-mono text-magenta-alert flex items-center justify-between">
            <div className="flex items-center gap-2">
              <AlertCircle className="w-4 h-4 shrink-0" />
              <span>{tenantError}</span>
            </div>
            <button onClick={() => setTenantError(null)} className="text-magenta-alert hover:brightness-125">
              <X className="w-4 h-4" />
            </button>
          </div>
        )}
        {tenantSuccess && (
          <div className="p-3 rounded bg-success-green/10 border border-success-green/40 text-xs font-mono text-success-green flex items-center justify-between">
            <div className="flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 shrink-0" />
              <span>{tenantSuccess}</span>
            </div>
            <button onClick={() => setTenantSuccess(null)} className="text-success-green hover:brightness-125">
              <X className="w-4 h-4" />
            </button>
          </div>
        )}

        {/* Create Tenant Form */}
        <form onSubmit={handleAddTenant} className="p-4 rounded-lg bg-void border border-border-dim flex gap-3 max-w-lg">
          <input
            type="text"
            required
            minLength={2}
            placeholder="New Organization / Team Name..."
            value={newTenantName}
            onChange={(e) => setNewTenantName(e.target.value)}
            className="flex-1 px-3 py-1.5 rounded bg-panel border border-border-dim text-xs text-text-primary font-mono focus:border-cyan-signal focus:outline-none"
          />
          <button
            type="submit"
            disabled={createTenantMutation.isPending}
            className="flex items-center gap-2 px-4 py-1.5 rounded bg-cyan-signal text-black font-semibold text-xs shadow-glow-cyan-sm hover:brightness-110 active:scale-[0.98] transition-all shrink-0 disabled:opacity-50"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>{createTenantMutation.isPending ? 'Creating...' : 'Create Tenant'}</span>
          </button>
        </form>

        {/* Tenants Grid */}
        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3">
          {tenants.map((t) => (
            <div
              key={t.id}
              onClick={() => setTenantId(t.id)}
              className={`p-3.5 rounded-lg border cursor-pointer transition-all ${
                t.id === tenantId
                  ? 'bg-void border-cyan-signal shadow-glow-cyan-sm'
                  : 'bg-void/40 border-border-dim hover:border-border-bright'
              }`}
            >
              <div className="flex items-center justify-between">
                <span className="font-display font-semibold text-xs text-text-primary truncate">
                  {t.name}
                </span>
                {t.id === tenantId && <Check className="w-3.5 h-3.5 text-cyan-signal shrink-0" />}
              </div>
              <div className="text-[10px] font-mono text-text-dim mt-1.5 truncate">
                ID: {t.id}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
