import { useAuth } from '../context/AuthContext';
import {
  Globe,
  LayoutDashboard,
  Activity,
  AlertTriangle,
  Users,
  FileText,
  ShieldCheck,
  Terminal,
  Settings,
  KeyRound,
  BookOpen,
  Shield,
} from 'lucide-react';

const BASE_NAV_ITEMS = [
  { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { id: 'scans', label: 'Scans & Pipeline', icon: Activity },
  { id: 'findings', label: 'Findings', icon: AlertTriangle },
  { id: 'people', label: 'People OSINT', icon: Users },
  { id: 'reports', label: 'Reports', icon: FileText },
  { id: 'scopes', label: 'Target Scopes', icon: ShieldCheck },
  { id: 'integrations', label: 'API Integrations', icon: KeyRound },
  { id: 'docs', label: 'Documentation Hub', icon: BookOpen },
];

export default function Navigation({ activeTab, onSelectTab }) {
  const { user } = useAuth();
  const isSystemAdmin = user?.role === 'system_admin';

  const navItems = [
    ...BASE_NAV_ITEMS,
    ...(isSystemAdmin ? [{ id: 'iam', label: 'IAM & Access Control', icon: Shield }] : []),
    { id: 'settings', label: 'Settings', icon: Settings },
  ];
  return (
    <aside className="w-64 border-r border-border-dim bg-panel flex flex-col justify-between p-4 shrink-0 h-full overflow-y-auto">
      <div className="space-y-1">
        <div className="px-3 py-2 text-[11px] font-mono uppercase tracking-wider text-text-dim">
          Operations
        </div>
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => onSelectTab(item.id)}
              className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-md text-xs font-medium transition-all ${
                isActive
                  ? 'bg-void text-cyan-signal border border-cyan-signal/40 shadow-glow-cyan-sm'
                  : 'text-text-dim hover:text-text-primary hover:bg-void/60 border border-transparent'
              }`}
            >
              <Icon
                className={`w-4 h-4 ${
                  isActive ? 'text-cyan-signal' : 'text-text-dim group-hover:text-text-primary'
                }`}
              />
              <span className="tracking-wide">{item.label}</span>
              {isActive && (
                <span className="ml-auto w-1.5 h-1.5 rounded-full bg-cyan-signal shadow-glow-cyan" />
              )}
            </button>
          );
        })}
      </div>

      {/* Red Team Operational Footer */}
      <div className="p-3 rounded-md bg-void border border-border-dim space-y-2">
        <div className="flex items-center gap-2 text-[11px] font-mono text-text-dim">
          <Terminal className="w-3.5 h-3.5 text-cyan-signal" />
          <span>R7 RED TEAM ENGINE</span>
        </div>
        <p className="text-[10px] text-text-dim leading-relaxed">
          Authorized attack surface discovery & triage platform.
        </p>
      </div>
    </aside>
  );
}
