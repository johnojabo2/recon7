import React from 'react';
import { Loader2, Radio, AlertCircle } from 'lucide-react';

export function LoadingState({ message = 'Accessing target attack surface...' }) {
  return (
    <div className="flex flex-col items-center justify-center p-12 text-center space-y-3">
      <div className="w-10 h-10 rounded-full bg-void border border-cyan-signal/40 flex items-center justify-center shadow-glow-cyan-sm animate-pulse">
        <Loader2 className="w-5 h-5 text-cyan-signal animate-spin" />
      </div>
      <p className="font-mono text-xs text-cyan-signal tracking-wide uppercase">{message}</p>
      <p className="text-[11px] text-text-dim">Streaming telemetry from R7 worker pipeline...</p>
    </div>
  );
}

export function EmptyState({ title = 'No data discovered', message = 'Trigger a scan to populate findings.', action = null }) {
  return (
    <div className="flex flex-col items-center justify-center p-12 text-center panel-glass rounded-lg border border-border-dim space-y-3">
      <div className="w-10 h-10 rounded-full bg-void border border-border-bright flex items-center justify-center">
        <AlertCircle className="w-5 h-5 text-text-dim" />
      </div>
      <h3 className="font-display font-semibold text-sm text-text-primary">{title}</h3>
      <p className="text-xs text-text-dim max-w-sm">{message}</p>
      {action && <div className="pt-2">{action}</div>}
    </div>
  );
}
