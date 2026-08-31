import React, { useState } from 'react';
import {
  Lock,
  Globe,
  Server,
  Cpu,
  Fingerprint,
  AlertTriangle,
  FileText,
  Users,
} from 'lucide-react';

const STAGES = [
  {
    id: '01',
    step: '01.INIT',
    title: 'Scope & Auth',
    badge: 'VERIFIED',
    icon: Lock,
    color: '#06b6d4',
    desc: 'Target scope & attestation validation',
  },
  {
    id: '02',
    step: '02.DNS',
    title: 'Subdomain DNS',
    badge: '184 HOSTS',
    icon: Globe,
    color: '#38bdf8',
    desc: 'CT logs & passive enumeration',
  },
  {
    id: '03',
    step: '03.CDN_BYPASS',
    title: 'Origin Bypass',
    badge: 'HEURISTIC',
    icon: Server,
    color: '#f59e0b',
    desc: 'TLS SAN leak & DNS correlation',
  },
  {
    id: '04',
    step: '04.PORTS',
    title: 'Port Sweep',
    badge: 'OPEN PORTS',
    icon: Cpu,
    color: '#60a5fa',
    desc: 'Rapid non-blocking port scanning',
  },
  {
    id: '05',
    step: '05.TECH',
    title: 'Tech Fingerprint',
    badge: 'IDENTIFIED',
    icon: Fingerprint,
    color: '#818cf8',
    desc: 'Web server & CMS banner detection',
  },
  {
    id: '06',
    step: '06.VULNS',
    title: 'Vuln Correlation',
    badge: 'TRIAGED',
    icon: AlertTriangle,
    color: '#f43f5e',
    desc: 'CVE matching & severity scoring',
  },
  {
    id: '07',
    step: '07.WHOIS',
    title: 'WHOIS & ASN',
    badge: 'RESOLVED',
    icon: FileText,
    color: '#10b981',
    desc: 'Registrar authority & IP routes',
  },
  {
    id: '08',
    step: '08.PEOPLE',
    title: 'People OSINT',
    badge: 'SYNTHESIZED',
    icon: Users,
    color: '#2dd4bf',
    desc: 'Leadership & corporate emails',
  },
];

export default function PipelineFlow({ activeStageId, onSelectStage }) {
  const [hoveredId, setHoveredId] = useState(null);

  // Split into Row 1 (01-04) and Row 2 (05-08)
  const row1 = STAGES.slice(0, 4);
  const row2 = STAGES.slice(4, 8);

  const renderHorizontalConnector = (key) => (
    <div key={key} className="hidden lg:flex items-center justify-center flex-1 px-1 relative">
      <svg className="w-full h-6 overflow-visible" preserveAspectRatio="none">
        {/* Dim Background Guide Line */}
        <line
          x1="0%"
          y1="50%"
          x2="100%"
          y2="50%"
          stroke="#142033"
          strokeWidth="2"
        />
        {/* Animated Glowing Flow Line */}
        <line
          x1="0%"
          y1="50%"
          x2="100%"
          y2="50%"
          stroke="#06b6d4"
          strokeWidth="2"
          strokeDasharray="6 6"
          className="animate-pipeline-flow"
        />
        {/* Traveling Signal Pulse Packet */}
        <circle r="3.5" fill="#ffffff">
          <animate
            attributeName="cx"
            from="0%"
            to="100%"
            dur="1.6s"
            repeatCount="indefinite"
          />
          <animate
            attributeName="cy"
            values="50%;50%"
            dur="1.6s"
            repeatCount="indefinite"
          />
          <animate
            attributeName="opacity"
            values="0.2;1;1;0.2"
            dur="1.6s"
            repeatCount="indefinite"
          />
        </circle>
      </svg>
    </div>
  );

  const renderMobileConnector = (key) => (
    <div key={key} className="flex lg:hidden justify-center py-1">
      <svg className="w-6 h-6 overflow-visible">
        <line x1="50%" y1="0%" x2="50%" y2="100%" stroke="#142033" strokeWidth="2" />
        <line
          x1="50%"
          y1="0%"
          x2="50%"
          y2="100%"
          stroke="#06b6d4"
          strokeWidth="2"
          strokeDasharray="6 6"
          className="animate-pipeline-flow"
        />
        <circle r="2.5" fill="#ffffff">
          <animate attributeName="cy" from="0%" to="100%" dur="1.2s" repeatCount="indefinite" />
          <animate attributeName="cx" values="50%;50%" dur="1.2s" repeatCount="indefinite" />
        </circle>
      </svg>
    </div>
  );

  const renderStageCard = (stage) => {
    const Icon = stage.icon;
    const isSelected = activeStageId === stage.id || hoveredId === stage.id;

    return (
      <div
        key={stage.id}
        onClick={() => onSelectStage && onSelectStage(stage.id)}
        onMouseEnter={() => setHoveredId(stage.id)}
        onMouseLeave={() => setHoveredId(null)}
        className={`p-3.5 rounded-xl bg-[#050811]/90 border transition-all duration-200 cursor-pointer flex flex-col justify-between w-full lg:w-56 shrink-0 shadow-panel group relative ${
          isSelected
            ? 'border-cyan-signal shadow-glow-cyan-sm scale-[1.02] bg-[#080d1a]'
            : 'border-[#142033] hover:border-cyan-signal/50'
        }`}
      >
        {/* Top bar with stage number & status pill */}
        <div className="flex items-center justify-between gap-2 mb-2">
          <div className="flex items-center gap-2">
            <span
              className="w-6 h-6 rounded-md bg-[#020408] border border-[#142033] flex items-center justify-center text-xs font-mono font-bold"
              style={{ color: stage.color }}
            >
              {stage.id}
            </span>
            <Icon className="w-4 h-4 text-text-dim group-hover:text-cyan-signal transition-colors" />
          </div>

          <span
            className="text-[9.5px] font-mono font-semibold px-2 py-0.5 rounded border"
            style={{
              color: stage.color,
              borderColor: `${stage.color}40`,
              backgroundColor: `${stage.color}15`,
            }}
          >
            {stage.badge}
          </span>
        </div>

        {/* Stage Name & Subtitle */}
        <div>
          <h4 className="text-xs font-mono font-bold text-text-primary group-hover:text-cyan-signal transition-colors truncate">
            {stage.title}
          </h4>
          <p className="text-[10px] font-mono text-text-dim truncate mt-0.5">
            {stage.desc}
          </p>
        </div>
      </div>
    );
  };

  return (
    <div className="w-full space-y-2 lg:space-y-0">
      {/* ROW 1: Stages 01 to 04 */}
      <div className="flex flex-col lg:flex-row items-center justify-between gap-2 lg:gap-0">
        {row1.map((stage, idx) => (
          <React.Fragment key={stage.id}>
            {renderStageCard(stage)}
            {idx < row1.length - 1 && renderHorizontalConnector(`c1_${idx}`)}
            {idx < row1.length - 1 && renderMobileConnector(`m1_${idx}`)}
          </React.Fragment>
        ))}
      </div>

      {/* MOBILE INTER-ROW CONNECTOR */}
      {renderMobileConnector('m_row_inter')}

      {/* DESKTOP INTER-ROW CONNECTING CIRCUIT TRACK: CONTINUOUS FROM 04 TO 05 */}
      <div className="hidden lg:block w-full h-12 relative my-1">
        <svg
          className="w-full h-full overflow-visible"
          viewBox="0 0 1000 48"
          preserveAspectRatio="none"
        >
          {/* Base Guide Track */}
          <path
            d="M 890 0 L 890 16 Q 890 24 874 24 L 126 24 Q 110 24 110 32 L 110 48"
            stroke="#142033"
            strokeWidth="2"
            fill="none"
          />
          {/* Animated Glowing Signal Flow Line */}
          <path
            d="M 890 0 L 890 16 Q 890 24 874 24 L 126 24 Q 110 24 110 32 L 110 48"
            stroke="#06b6d4"
            strokeWidth="2"
            strokeDasharray="6 6"
            className="animate-pipeline-flow"
            fill="none"
          />
          {/* Traveling Signal Pulse Packet: Starts under Card 04, travels across bus, and lands on Card 05 */}
          <circle r="3.5" fill="#ffffff">
            <animateMotion
              path="M 890 0 L 890 16 Q 890 24 874 24 L 126 24 Q 110 24 110 32 L 110 48"
              dur="2.5s"
              repeatCount="indefinite"
            />
            <animate
              attributeName="opacity"
              values="0.3;1;1;0.3"
              dur="2.5s"
              repeatCount="indefinite"
            />
          </circle>
        </svg>
      </div>

      {/* ROW 2: Stages 05 to 08 */}
      <div className="flex flex-col lg:flex-row items-center justify-between gap-2 lg:gap-0">
        {row2.map((stage, idx) => (
          <React.Fragment key={stage.id}>
            {renderStageCard(stage)}
            {idx < row2.length - 1 && renderHorizontalConnector(`c2_${idx}`)}
            {idx < row2.length - 1 && renderMobileConnector(`m2_${idx}`)}
          </React.Fragment>
        ))}
      </div>
    </div>
  );
}
