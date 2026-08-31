import React, { useState } from 'react';
import { Copy, Check } from 'lucide-react';

export default function TechnicalData({ value, label = null, copyable = true, className = '' }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = (e) => {
    e.stopPropagation();
    if (!value) return;
    navigator.clipboard.writeText(String(value));
    setCopied(true);
    setTimeout(() => setCopied(false), 1800);
  };

  return (
    <div
      className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded bg-void border border-border-dim font-mono text-xs text-text-primary ${className}`}
    >
      {label && <span className="text-text-dim text-[10px] uppercase mr-0.5">{label}:</span>}
      <span className="truncate">{value || 'N/A'}</span>
      {copyable && value && (
        <button
          onClick={handleCopy}
          title="Copy technical value"
          className="text-text-dim hover:text-cyan-signal ml-1 p-0.5 rounded transition-colors"
        >
          {copied ? <Check className="w-3 h-3 text-cyan-signal" /> : <Copy className="w-3 h-3" />}
        </button>
      )}
    </div>
  );
}
