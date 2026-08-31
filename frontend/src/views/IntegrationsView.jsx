import React, { useState } from 'react';
import {
  KeyRound,
  Search,
  Cpu,
  Shield,
  CheckCircle2,
  AlertCircle,
  Eye,
  EyeOff,
  Save,
  Loader2,
  Sparkles,
  ExternalLink,
  Zap,
  Globe,
  Lock,
  Database,
  RefreshCw,
  Sliders,
} from 'lucide-react';
import { useIntegrations, useSaveIntegration, useTestIntegration } from '../api/hooks';

const IN_DEVELOPMENT_PROVIDERS = ['shodan', 'securitytrails', 'virustotal', 'hunter'];

export default function IntegrationsView() {
  const { data: integrations = [], isLoading, refetch, isFetching } = useIntegrations();
  const saveMutation = useSaveIntegration();
  const testMutation = useTestIntegration();

  const [activeCategory, setActiveCategory] = useState('all');
  const [formValues, setFormValues] = useState({});
  const [showSecrets, setShowSecrets] = useState({});
  const [saveStatus, setSaveStatus] = useState({}); // { [provider]: 'saving' | 'success' | 'error' }
  const [testResults, setTestResults] = useState({}); // { [provider]: { status, message } }
  const [customModelMode, setCustomModelMode] = useState({});

  // Sync loaded configurations to local edit state
  const getFieldValue = (provider, key, fallback = '') => {
    if (formValues[provider]?.[key] !== undefined) {
      return formValues[provider][key];
    }
    const currentInt = integrations.find((i) => i.provider === provider);
    return currentInt?.config?.[key] || fallback;
  };

  const handleFieldChange = (provider, key, value) => {
    setFormValues((prev) => ({
      ...prev,
      [provider]: {
        ...(prev[provider] || {}),
        [key]: value,
      },
    }));
  };

  const toggleShowSecret = (fieldId) => {
    setShowSecrets((prev) => ({ ...prev, [fieldId]: !prev[fieldId] }));
  };

  const handleSave = async (provider) => {
    const currentInt = integrations.find((i) => i.provider === provider);
    const updatedFields = formValues[provider] || {};
    const finalConfig = { ...(currentInt?.config || {}), ...updatedFields };

    setSaveStatus((prev) => ({ ...prev, [provider]: 'saving' }));
    try {
      await saveMutation.mutateAsync({
        provider,
        config: finalConfig,
        is_enabled: true,
      });
      setFormValues((prev) => {
        const next = { ...prev };
        delete next[provider];
        return next;
      });
      setSaveStatus((prev) => ({ ...prev, [provider]: 'success' }));
      setTimeout(() => {
        setSaveStatus((prev) => ({ ...prev, [provider]: null }));
      }, 3000);
    } catch (err) {
      setSaveStatus((prev) => ({ ...prev, [provider]: 'error' }));
      setTimeout(() => {
        setSaveStatus((prev) => ({ ...prev, [provider]: null }));
      }, 4000);
    }
  };

  const handleTest = async (provider) => {
    const currentInt = integrations.find((i) => i.provider === provider);
    const updatedFields = formValues[provider] || {};
    const finalConfig = { ...(currentInt?.config || {}), ...updatedFields };

    setTestResults((prev) => ({
      ...prev,
      [provider]: { status: 'testing', message: 'Testing live provider connection...' },
    }));

    try {
      const res = await testMutation.mutateAsync({
        provider,
        config: finalConfig,
      });
      if (res?.success) {
        setTestResults((prev) => ({
          ...prev,
          [provider]: { status: 'success', message: res.message || 'Connection verified successfully.' },
        }));
      } else {
        setTestResults((prev) => ({
          ...prev,
          [provider]: { status: 'error', message: res?.message || 'Connection test failed.' },
        }));
      }
    } catch (err) {
      setTestResults((prev) => ({
        ...prev,
        [provider]: {
          status: 'error',
          message: err?.message || 'Connection request failed or timed out.',
        },
      }));
    }
  };

  const categories = [
    { id: 'all', label: 'All Providers' },
    { id: 'Search Engines', label: 'Search Engines' },
    { id: 'Threat Intelligence & OSINT', label: 'Threat Intel & OSINT' },
  ];

  const filteredIntegrations = integrations
    .filter((item) => {
      if (activeCategory === 'all') return true;
      return item.category === activeCategory;
    })
    .sort((a, b) => {
      const aInDev = IN_DEVELOPMENT_PROVIDERS.includes(a.provider);
      const bInDev = IN_DEVELOPMENT_PROVIDERS.includes(b.provider);
      if (aInDev && !bInDev) return 1;
      if (!aInDev && bInDev) return -1;
      if (a.is_configured && !b.is_configured) return -1;
      if (!a.is_configured && b.is_configured) return 1;
      return 0;
    });

  const configuredCount = integrations.filter((i) => i.is_configured).length;

  return (
    <div className="flex-1 overflow-y-auto bg-void p-6 lg:p-8 space-y-8 font-sans">
      {/* Top Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-border-dim pb-6">
        <div>
          <div className="flex items-center gap-2.5">
            <div className="w-9 h-9 rounded-lg bg-panel border border-cyan-signal/40 flex items-center justify-center text-cyan-signal shadow-glow-cyan-sm">
              <KeyRound className="w-5 h-5" />
            </div>
            <div>
              <h1 className="text-xl lg:text-2xl font-display font-black tracking-tight text-text-primary uppercase">
                EXTERNAL API INTEGRATIONS
              </h1>
              <p className="text-xs font-mono text-text-dim">
                Configure API keys and connection credentials for search engines and threat feeds.
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => refetch()}
            disabled={isFetching}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-panel border border-border-dim hover:border-cyan-signal/40 text-xs font-mono text-text-dim hover:text-text-primary transition-all disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isFetching ? 'animate-spin text-cyan-signal' : ''}`} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* Summary KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="p-4 rounded-xl bg-panel border border-border-dim flex items-center justify-between">
          <div>
            <div className="text-[11px] font-mono text-text-dim uppercase tracking-wider">
              Available Connectors
            </div>
            <div className="text-2xl font-display font-black text-text-primary mt-0.5">
              {integrations.length}
            </div>
          </div>
          <div className="w-10 h-10 rounded-lg bg-void border border-border-dim flex items-center justify-center text-cyan-signal">
            <Sliders className="w-5 h-5" />
          </div>
        </div>

        <div className="p-4 rounded-xl bg-panel border border-border-dim flex items-center justify-between">
          <div>
            <div className="text-[11px] font-mono text-text-dim uppercase tracking-wider">
              Connected & Active
            </div>
            <div className="text-2xl font-display font-black text-success-green mt-0.5">
              {configuredCount}
            </div>
          </div>
          <div className="w-10 h-10 rounded-lg bg-void border border-border-dim flex items-center justify-center text-success-green">
            <CheckCircle2 className="w-5 h-5" />
          </div>
        </div>

        <div className="p-4 rounded-xl bg-panel border border-border-dim flex items-center justify-between">
          <div>
            <div className="text-[11px] font-mono text-text-dim uppercase tracking-wider">
              Local Threat Triage Engine
            </div>
            <div className="text-xs font-mono text-cyan-signal font-bold mt-1">
              Zero-Trust Offline Analysis
            </div>
          </div>
          <div className="w-10 h-10 rounded-lg bg-void border border-border-dim flex items-center justify-center text-cyan-signal">
            <Shield className="w-5 h-5" />
          </div>
        </div>
      </div>

      {/* Category Pills Filter */}
      <div className="flex items-center gap-2 border-b border-border-dim pb-3 overflow-x-auto">
        {categories.map((cat) => (
          <button
            key={cat.id}
            onClick={() => setActiveCategory(cat.id)}
            className={`px-3.5 py-1.5 rounded-md text-xs font-mono transition-all shrink-0 ${
              activeCategory === cat.id
                ? 'bg-cyan-signal text-void font-bold shadow-glow-cyan-sm'
                : 'bg-panel text-text-dim hover:text-text-primary hover:bg-panel-elevated border border-border-dim'
            }`}
          >
            {cat.label}
          </button>
        ))}
      </div>

      {/* Integrations Grid */}
      {isLoading ? (
        <div className="py-16 text-center text-xs font-mono text-text-dim flex items-center justify-center gap-2">
          <Loader2 className="w-4 h-4 animate-spin text-cyan-signal" />
          <span>Loading external integration registry...</span>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {filteredIntegrations.map((item) => {
            const isSaving = saveStatus[item.provider] === 'saving';
            const isSuccess = saveStatus[item.provider] === 'success';
            const isError = saveStatus[item.provider] === 'error';

            return (
              <div
                key={item.provider}
                className="rounded-xl bg-panel border border-border-dim hover:border-border-bright transition-all p-6 space-y-5 shadow-panel relative flex flex-col justify-between"
              >
                {/* Header Row */}
                <div className="space-y-2">
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <span className="text-[10px] font-mono uppercase tracking-wider text-cyan-signal font-semibold">
                        {item.category}
                      </span>
                      <h3 className="text-base font-mono font-bold text-text-primary mt-0.5">
                        {item.name}
                      </h3>
                    </div>

                    <div className="flex items-center gap-2 shrink-0 flex-wrap justify-end">
                      {IN_DEVELOPMENT_PROVIDERS.includes(item.provider) && (
                        <span className="text-[10px] font-mono px-2 py-0.5 rounded border uppercase font-bold tracking-wider bg-amber-500/15 border-amber-500/40 text-amber-300">
                          IN DEVELOPMENT
                        </span>
                      )}

                      <span
                        className={`text-[10px] font-mono px-2.5 py-1 rounded border uppercase font-bold tracking-wider shrink-0 ${
                          item.is_configured
                            ? 'bg-success-green/10 border-success-green/40 text-success-green'
                            : 'bg-void border-border-dim text-text-dim'
                        }`}
                      >
                        {item.is_configured ? 'CONNECTED' : 'NOT CONFIGURED'}
                      </span>
                    </div>
                  </div>

                  <p className="text-xs font-mono text-text-dim leading-relaxed">
                    {item.description}
                  </p>

                  {item.provider === 'ai_gateway' && (
                    <div className="p-2.5 rounded-lg bg-void/70 border border-border-dim text-[11px] font-mono text-text-dim space-y-1">
                      <div className="text-[10px] font-mono text-cyan-signal font-bold uppercase tracking-wider flex items-center gap-1.5">
                        <span>⚡ Key Matching & Local Execution:</span>
                      </div>
                      <p className="leading-relaxed">
                        Only fill the key for your active model's vendor (e.g., Anthropic key for Claude, OpenAI key for GPT).
                      </p>
                      <p className="text-emerald-400 font-medium leading-relaxed">
                        🖥️ Local Models (<span className="text-text-primary">ollama/llama3.3</span>, etc.): run fully offline on your machine with <span className="underline font-bold">zero API keys required</span>.
                      </p>
                    </div>
                  )}
                </div>

                {/* Form Fields & Actions */}
                {IN_DEVELOPMENT_PROVIDERS.includes(item.provider) ? (
                  <div className="p-4 rounded-lg bg-void/80 border border-amber-500/25 text-xs font-mono space-y-2">
                    <div className="flex items-center gap-2 text-amber-300 font-bold">
                      <AlertCircle className="w-4 h-4 text-amber-400 shrink-0" />
                      <span>Provider Driver Under Active Engine Development</span>
                    </div>
                    <p className="text-text-dim text-[11px] leading-relaxed">
                      API integration for <span className="text-text-primary font-semibold">{item.name}</span> is staged on the R7 engine roadmap. Configuration textboxes and live key validation will be unlocked in an upcoming release.
                    </p>
                  </div>
                ) : (
                  <>
                    <div className="space-y-3.5 pt-2">
                      {item.fields.map((field) => {
                        const fieldId = `${item.provider}_${field.key}`;
                        const isMasked = field.type === 'password' && !showSecrets[fieldId];
                        const val = getFieldValue(item.provider, field.key);

                        if (field.type === 'select') {
                          const presetValues = field.options
                            .map((o) => o.value)
                            .filter((v) => v !== 'custom');
                          const isKnownPreset = presetValues.includes(val);
                          const isCustom = customModelMode[item.provider] !== undefined
                            ? customModelMode[item.provider]
                            : (!isKnownPreset && Boolean(val));

                          return (
                            <div key={field.key} className="space-y-2.5">
                              <div className="space-y-1">
                                <label className="block text-[11px] font-mono text-text-dim uppercase tracking-wider">
                                  {field.label} {field.required && <span className="text-cyan-signal">*</span>}
                                </label>
                                <select
                                  value={isCustom ? 'custom' : val}
                                  onChange={(e) => {
                                    const selected = e.target.value;
                                    if (selected === 'custom') {
                                      setCustomModelMode((prev) => ({ ...prev, [item.provider]: true }));
                                      if (isKnownPreset) {
                                        handleFieldChange(item.provider, field.key, '');
                                      }
                                    } else {
                                      setCustomModelMode((prev) => ({ ...prev, [item.provider]: false }));
                                      handleFieldChange(item.provider, field.key, selected);
                                    }
                                  }}
                                  className="w-full px-3 py-2 rounded-md bg-void border border-border-dim focus:border-cyan-signal text-xs font-mono text-text-primary focus:outline-none transition-all"
                                >
                                  {field.options.map((opt) => (
                                    <option key={opt.value} value={opt.value}>
                                      {opt.label}
                                    </option>
                                  ))}
                                </select>
                              </div>

                              {isCustom && (
                                <div className="space-y-1.5 p-3 rounded-lg bg-void/90 border border-cyan-signal/50 animate-fade-in">
                                  <div className="flex items-center justify-between">
                                    <label className="block text-[10px] font-mono text-cyan-signal uppercase tracking-wider font-bold">
                                      Custom LiteLLM Model String
                                    </label>
                                    <span className="text-[9px] font-mono text-text-dim">
                                      e.g. anthropic/claude-3-7-sonnet-latest
                                    </span>
                                  </div>
                                  <input
                                    type="text"
                                    autoFocus
                                    placeholder="Type or paste model identifier (e.g. claude-sonnet-4-5-20250929)..."
                                    value={val === 'custom' ? '' : val}
                                    onChange={(e) => handleFieldChange(item.provider, field.key, e.target.value)}
                                    className="w-full px-3 py-2 rounded-md bg-panel border border-border-bright focus:border-cyan-signal text-xs font-mono text-text-primary placeholder:text-text-dim/40 focus:outline-none transition-all"
                                  />
                                </div>
                              )}
                            </div>
                          );
                        }

                        return (
                          <div key={field.key} className="space-y-1">
                            <label className="block text-[11px] font-mono text-text-dim uppercase tracking-wider">
                              {field.label} {field.required && <span className="text-cyan-signal">*</span>}
                            </label>
                            <div className="relative">
                              <input
                                type={isMasked ? 'password' : 'text'}
                                placeholder={field.placeholder || ''}
                                value={val}
                                onFocus={(e) => {
                                  if (typeof val === 'string' && val.includes('••••')) {
                                    e.target.select();
                                  }
                                }}
                                onChange={(e) => handleFieldChange(item.provider, field.key, e.target.value)}
                                className="w-full pl-3 pr-10 py-2 rounded-md bg-void border border-border-dim focus:border-cyan-signal text-xs font-mono text-text-primary placeholder:text-text-dim/40 focus:outline-none transition-all font-mono"
                              />
                              {field.type === 'password' && (
                                <button
                                  type="button"
                                  onClick={() => toggleShowSecret(fieldId)}
                                  className="absolute right-2.5 top-1/2 -translate-y-1/2 text-text-dim hover:text-text-primary transition-colors"
                                  title={showSecrets[fieldId] ? 'Hide secret' : 'Show secret'}
                                >
                                  {showSecrets[fieldId] ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                                </button>
                              )}
                            </div>
                          </div>
                        );
                      })}
                    </div>

                    {/* Live Test Result Banner */}
                    {testResults[item.provider] && (
                      <div
                        className={`p-2.5 rounded-lg text-xs font-mono border flex items-start gap-2 animate-fade-in ${
                          testResults[item.provider].status === 'success'
                            ? 'bg-success-green/10 border-success-green/40 text-success-green'
                            : testResults[item.provider].status === 'error'
                            ? 'bg-magenta-alert/10 border-magenta-alert/40 text-magenta-alert'
                            : 'bg-void border-border-dim text-cyan-signal'
                        }`}
                      >
                        {testResults[item.provider].status === 'testing' && (
                          <Loader2 className="w-4 h-4 animate-spin shrink-0 mt-0.5" />
                        )}
                        {testResults[item.provider].status === 'success' && (
                          <CheckCircle2 className="w-4 h-4 shrink-0 mt-0.5" />
                        )}
                        {testResults[item.provider].status === 'error' && (
                          <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" />
                        )}
                        <span className="leading-relaxed">{testResults[item.provider].message}</span>
                      </div>
                    )}

                    {/* Bottom Action Row */}
                    <div className="pt-3 border-t border-border-dim flex flex-wrap items-center justify-between gap-3">
                      <button
                        type="button"
                        onClick={() => handleTest(item.provider)}
                        disabled={testResults[item.provider]?.status === 'testing'}
                        className="flex items-center gap-1.5 px-3 py-2 rounded-md bg-panel-elevated hover:bg-void border border-border-dim hover:border-cyan-signal/40 text-xs font-mono text-text-dim hover:text-text-primary transition-all disabled:opacity-50"
                      >
                        {testResults[item.provider]?.status === 'testing' ? (
                          <Loader2 className="w-3.5 h-3.5 animate-spin text-cyan-signal" />
                        ) : (
                          <Zap className="w-3.5 h-3.5 text-cyan-signal" />
                        )}
                        <span>TEST CONNECTION</span>
                      </button>

                      <div className="flex items-center gap-3">
                        {isSuccess && (
                          <span className="text-[11px] font-mono text-success-green flex items-center gap-1 font-bold">
                            <CheckCircle2 className="w-3.5 h-3.5" />
                            Saved
                          </span>
                        )}
                        {isError && (
                          <span className="text-[11px] font-mono text-magenta-alert flex items-center gap-1 font-bold">
                            <AlertCircle className="w-3.5 h-3.5" />
                            Failed
                          </span>
                        )}

                        <button
                          onClick={() => handleSave(item.provider)}
                          disabled={isSaving}
                          className="flex items-center gap-2 px-4 py-2 rounded-md bg-cyan-signal text-void font-mono font-bold text-xs tracking-wider hover:bg-cyan-bright active:scale-95 transition-all shadow-glow-cyan-sm disabled:opacity-50"
                        >
                          {isSaving ? (
                            <>
                              <Loader2 className="w-3.5 h-3.5 animate-spin" />
                              <span>SAVING...</span>
                            </>
                          ) : (
                            <>
                              <Save className="w-3.5 h-3.5" />
                              <span>SAVE CONNECTION</span>
                            </>
                          )}
                        </button>
                      </div>
                    </div>
                  </>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
