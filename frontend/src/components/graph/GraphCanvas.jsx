import React, { useState, useEffect, useRef, useMemo, useCallback } from 'react';
import {
  Globe,
  Server,
  Cpu,
  Fingerprint,
  Users,
  ShieldAlert,
  FileText,
  Cloud,
  Mail,
  Lock,
  Maximize2,
  Minimize2,
  ZoomIn,
  ZoomOut,
  RotateCcw,
  Search,
  CheckCircle,
  AlertOctagon,
  ExternalLink,
  ChevronRight,
  Info,
  Linkedin,
} from 'lucide-react';

const ENTITY_CONFIG = {
  organization: { color: '#a855f7', label: 'Org', icon: Users, radius: 28 },
  domain: { color: '#06b6d4', label: 'Domain', icon: Globe, radius: 26 },
  subdomain: { color: '#38bdf8', label: 'Subdomain', icon: Globe, radius: 18 },
  ip: { color: '#2dd4bf', label: 'IP', icon: Server, radius: 18 },
  port: { color: '#94a3b8', label: 'Port', icon: Lock, radius: 14 },
  service: { color: '#60a5fa', label: 'Service', icon: Cpu, radius: 16 },
  technology: { color: '#818cf8', label: 'Tech', icon: Fingerprint, radius: 16 },
  vulnerability: { color: '#f43f5e', label: 'Vuln', icon: ShieldAlert, radius: 20 },
  person: { color: '#10b981', label: 'Person', icon: Users, radius: 24 },
  staff_cluster: { color: '#ec4899', label: 'Roster', icon: Users, radius: 24 },
  email: { color: '#84cc16', label: 'Email', icon: Mail, radius: 16 },
  username: { color: '#14b8a6', label: 'User', icon: Users, radius: 14 },
  document: { color: '#f59e0b', label: 'Doc', icon: FileText, radius: 20 },
  cloud_resource: { color: '#fb923c', label: 'Cloud', icon: Cloud, radius: 22 },
  breach: { color: '#ec4899', label: 'Breach', icon: AlertOctagon, radius: 18 },
  default: { color: '#64748b', label: 'Entity', icon: Info, radius: 16 },
};

export default function GraphCanvas({
  nodes = [],
  edges = [],
  onSelectEvidence,
  onExpandNode,
  selectedNodeId,
  onSelectNode,
  isExpanding = false,
  expandedNodeIds = new Set(),
}) {
  const containerRef = useRef(null);
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [isDragging, setIsDragging] = useState(false);
  const [dragStart, setDragStart] = useState({ x: 0, y: 0 });
  const [nodePositions, setNodePositions] = useState({});
  const [hoveredEdgeId, setHoveredEdgeId] = useState(null);
  const nodePositionsRef = useRef({});

  // Node Dragging State
  const [draggedNodeId, setDraggedNodeId] = useState(null);
  const draggedNodeRef = useRef(null);
  const dragNodeOffsetRef = useRef({ x: 0, y: 0 });
  const didDragNodeRef = useRef(false);

  // Auto-fit Graph to Viewport (stable reference, no re-triggering loop)
  const fitGraphToViewport = useCallback((positions = nodePositionsRef.current) => {
    const container = containerRef.current;
    const width = container ? container.clientWidth : 900;
    const height = container ? container.clientHeight : 650;
    const posList = Object.values(positions || {});

    if (posList.length === 0) {
      setZoom(1);
      setPan({ x: 0, y: 0 });
      return;
    }

    let minX = Infinity,
      maxX = -Infinity,
      minY = Infinity,
      maxY = -Infinity;

    posList.forEach((p) => {
      if (p.x < minX) minX = p.x;
      if (p.x > maxX) maxX = p.x;
      if (p.y < minY) minY = p.y;
      if (p.y > maxY) maxY = p.y;
    });

    // Margin for outer node radius + label pills
    const padX = 130;
    const padY = 90;
    const graphWidth = Math.max(maxX - minX + padX * 2, 200);
    const graphHeight = Math.max(maxY - minY + padY * 2, 200);

    // Fit zoom with comfortable safety padding
    const fitZoom = Math.min(
      1.0,
      Math.min((width - 40) / graphWidth, (height - 40) / graphHeight)
    );
    const effectiveZoom = Math.max(0.2, Number(fitZoom.toFixed(2)));

    const graphCenterX = (minX + maxX) / 2;
    const graphCenterY = (minY + maxY) / 2;

    const panX = width / 2 - graphCenterX * effectiveZoom;
    const panY = height / 2 - graphCenterY * effectiveZoom;

    setZoom(effectiveZoom);
    setPan({ x: panX, y: panY });
  }, []);

  // Smooth Zooming centered around the viewport midpoint
  const handleZoom = useCallback((delta) => {
    const container = containerRef.current;
    const width = container ? container.clientWidth : 900;
    const height = container ? container.clientHeight : 650;
    const cx = width / 2;
    const cy = height / 2;

    setZoom((prevZoom) => {
      const newZoom = Math.min(2.5, Math.max(0.25, Number((prevZoom + delta).toFixed(2))));
      if (newZoom === prevZoom) return prevZoom;

      setPan((prevPan) => ({
        x: cx - (cx - prevPan.x) * (newZoom / prevZoom),
        y: cy - (cy - prevPan.y) * (newZoom / prevZoom),
      }));

      return newZoom;
    });
  }, []);

  // Mouse wheel zoom
  const handleWheel = (e) => {
    e.preventDefault();
    const delta = e.deltaY < 0 ? 0.12 : -0.12;
    handleZoom(delta);
  };

  // Compute Structured Hierarchical DAG Layout
  useEffect(() => {
    if (!nodes || nodes.length === 0) return;

    const width = containerRef.current ? containerRef.current.clientWidth : 900;
    const height = containerRef.current ? containerRef.current.clientHeight : 650;
    const centerX = width / 2;
    const centerY = height / 2;

    const newPositions = {};

    // 1. Identify Node Categories
    const orgNode = nodes.find((n) => n.type === 'organization');
    const domainNode = nodes.find((n) => n.type === 'domain');

    const execNodes = nodes.filter(
      (n) =>
        n.type === 'person' &&
        (n.properties?.hierarchy_tier === 'Executive Leadership' ||
          n.properties?.hierarchy_tier === 'Executive')
    );
    const leadNodes = nodes.filter(
      (n) => n.type === 'person' && n.properties?.hierarchy_tier === 'Department Leadership'
    );
    const otherPersonNodes = nodes.filter(
      (n) => n.type === 'person' && !execNodes.includes(n) && !leadNodes.includes(n)
    );
    const docNodes = nodes.filter((n) => n.type === 'document');
    const clusterNodes = nodes.filter((n) => n.type === 'staff_cluster');

    const subNodes = nodes.filter((n) => n.type === 'subdomain');
    const ipNodes = nodes.filter((n) => n.type === 'ip');
    const vulnNodes = nodes.filter((n) => n.type === 'vulnerability');
    const cloudNodes = nodes.filter((n) => n.type === 'cloud_resource');

    const hasPeople =
      execNodes.length > 0 ||
      leadNodes.length > 0 ||
      otherPersonNodes.length > 0 ||
      clusterNodes.length > 0;

    // 2. Position Anchors (Org & Domain)
    if (hasPeople) {
      // Split Layout: Org on Left, Domain on Right
      if (orgNode && domainNode) {
        newPositions[orgNode.id] = { x: centerX - 140, y: centerY - 200 };
        newPositions[domainNode.id] = { x: centerX + 140, y: centerY - 200 };
      } else if (orgNode) {
        newPositions[orgNode.id] = { x: centerX - 120, y: centerY - 200 };
      } else if (domainNode) {
        newPositions[domainNode.id] = { x: centerX + 120, y: centerY - 200 };
      }
    } else {
      // Pure Tactical / Infra Layout: Domain is DEAD CENTER
      if (orgNode && domainNode) {
        newPositions[orgNode.id] = { x: centerX - 110, y: centerY - 200 };
        newPositions[domainNode.id] = { x: centerX + 110, y: centerY - 200 };
      } else if (domainNode) {
        newPositions[domainNode.id] = { x: centerX, y: centerY - 200 };
      } else if (orgNode) {
        newPositions[orgNode.id] = { x: centerX, y: centerY - 200 };
      }
    }

    // === LEFT WING: EXECUTIVE & PERSONNEL HIERARCHY ===
    if (hasPeople) {
      execNodes.forEach((ex, idx) => {
        const xOffset = (idx - (execNodes.length - 1) / 2) * 150;
        newPositions[ex.id] = { x: centerX - 260 + xOffset, y: centerY - 80 };
      });

      leadNodes.forEach((ld, idx) => {
        const xOffset = (idx - (leadNodes.length - 1) / 2) * 135;
        newPositions[ld.id] = { x: centerX - 320 + xOffset, y: centerY + 50 };
      });

      docNodes.forEach((doc, idx) => {
        newPositions[doc.id] = { x: centerX - 140, y: centerY + idx * 70 };
      });

      clusterNodes.forEach((cl, idx) => {
        newPositions[cl.id] = { x: centerX - 280, y: centerY + 180 + idx * 60 };
      });

      otherPersonNodes.forEach((p, idx) => {
        const angle = Math.PI * 0.6 + (idx / (otherPersonNodes.length || 1)) * Math.PI * 0.6;
        newPositions[p.id] = {
          x: centerX + 340 * Math.cos(angle),
          y: centerY + 240 * Math.sin(angle),
        };
      });
    }

    // === RIGHT WING / CENTER: INFRASTRUCTURE & ATTACK SURFACE ===
    const infraCenterX = hasPeople ? centerX + 240 : centerX;

    // Subdomains: Wrap into max 4-per-row so they never stretch off screen!
    const SUBDOMAINS_PER_ROW = hasPeople ? 3 : 4;
    subNodes.forEach((sub, idx) => {
      const rowIndex = Math.floor(idx / SUBDOMAINS_PER_ROW);
      const colIndex = idx % SUBDOMAINS_PER_ROW;
      const countInRow = Math.min(
        SUBDOMAINS_PER_ROW,
        subNodes.length - rowIndex * SUBDOMAINS_PER_ROW
      );
      const xOffset = (colIndex - (countInRow - 1) / 2) * 140;
      const yOffset = rowIndex * 90;
      newPositions[sub.id] = {
        x: infraCenterX + xOffset,
        y: centerY - 80 + yOffset,
      };
    });

    const lastSubRow =
      subNodes.length > 0 ? Math.floor((subNodes.length - 1) / SUBDOMAINS_PER_ROW) : 0;
    const ipBaseY = centerY - 80 + (lastSubRow + 1) * 95;

    // Origin IPs: Wrap into max 4-per-row directly beneath subdomains
    const IPS_PER_ROW = 4;
    ipNodes.forEach((ip, idx) => {
      const rowIndex = Math.floor(idx / IPS_PER_ROW);
      const colIndex = idx % IPS_PER_ROW;
      const countInRow = Math.min(IPS_PER_ROW, ipNodes.length - rowIndex * IPS_PER_ROW);
      const xOffset = (colIndex - (countInRow - 1) / 2) * 150;
      newPositions[ip.id] = {
        x: infraCenterX + xOffset,
        y: ipBaseY + rowIndex * 90,
      };
    });

    const lastIpRow = ipNodes.length > 0 ? Math.floor((ipNodes.length - 1) / IPS_PER_ROW) : 0;
    const vulnBaseY = ipBaseY + (lastIpRow + 1) * 90;

    // Critical Vulns attached underneath IPs
    vulnNodes.forEach((v, idx) => {
      const xOffset = (idx - (vulnNodes.length - 1) / 2) * 150;
      newPositions[v.id] = { x: infraCenterX + xOffset, y: vulnBaseY };
    });

    // Cloud Edge Gateways
    cloudNodes.forEach((cl, idx) => {
      newPositions[cl.id] = { x: infraCenterX - 180, y: centerY + idx * 70 };
    });

    // Multi-Ring Orbital Satellite Positioning: Group unassigned child nodes by parent and distribute evenly
    const parentChildrenMap = new Map();
    edges.forEach((edge) => {
      const srcHasPos = !!newPositions[edge.source];
      const tgtHasPos = !!newPositions[edge.target];
      if (srcHasPos && !tgtHasPos) {
        if (!parentChildrenMap.has(edge.source)) parentChildrenMap.set(edge.source, []);
        if (!parentChildrenMap.get(edge.source).includes(edge.target)) {
          parentChildrenMap.get(edge.source).push(edge.target);
        }
      } else if (tgtHasPos && !srcHasPos) {
        if (!parentChildrenMap.has(edge.target)) parentChildrenMap.set(edge.target, []);
        if (!parentChildrenMap.get(edge.target).includes(edge.source)) {
          parentChildrenMap.get(edge.target).push(edge.source);
        }
      }
    });

    parentChildrenMap.forEach((childIds, parentId) => {
      const pPos = newPositions[parentId];
      const total = childIds.length;
      childIds.forEach((childId, idx) => {
        const ring = Math.floor(idx / 8);
        const indexInRing = idx % 8;
        const ringTotal = Math.min(8, total - ring * 8);
        const radius = 130 + ring * 80;
        const baseAngle = -Math.PI / 2 + (indexInRing / (ringTotal || 1)) * 2 * Math.PI;
        newPositions[childId] = {
          x: pPos.x + radius * Math.cos(baseAngle),
          y: pPos.y + radius * Math.sin(baseAngle),
        };
      });
    });

    // Fallback for any other unassigned nodes
    const unassignedNodes = nodes.filter((n) => !newPositions[n.id]);
    unassignedNodes.forEach((n, idx) => {
      const angle = (idx / (unassignedNodes.length || 1)) * 2 * Math.PI;
      const radius = 280 + Math.floor(idx / 12) * 80;
      newPositions[n.id] = {
        x: centerX + radius * Math.cos(angle),
        y: centerY + radius * Math.sin(angle),
      };
    });

    // Iterative Collision Relaxation Pass (Enforce minimum distance between node centers to eliminate stacking)
    const nodeIds = Object.keys(newPositions);
    const MIN_DISTANCE = 80; // Clearance in pixels
    for (let iter = 0; iter < 40; iter++) {
      for (let i = 0; i < nodeIds.length; i++) {
        for (let j = i + 1; j < nodeIds.length; j++) {
          const idA = nodeIds[i];
          const idB = nodeIds[j];
          const posA = newPositions[idA];
          const posB = newPositions[idB];
          const dx = posB.x - posA.x;
          const dy = posB.y - posA.y;
          const dist = Math.sqrt(dx * dx + dy * dy) || 0.001;
          if (dist < MIN_DISTANCE) {
            const overlap = (MIN_DISTANCE - dist) / 2;
            const nx = dx / dist;
            const ny = dy / dist;
            posA.x -= nx * overlap;
            posA.y -= ny * overlap;
            posB.x += nx * overlap;
            posB.y += ny * overlap;
          }
        }
      }
    }

    nodePositionsRef.current = newPositions;
    setNodePositions(newPositions);
    fitGraphToViewport(newPositions);
  }, [nodes, edges]);

  // Node Drag Start Handler
  const handleNodeMouseDown = (e, node) => {
    e.stopPropagation();
    if (e.button !== 0) return; // Left click only

    const container = containerRef.current;
    if (!container) return;
    const rect = container.getBoundingClientRect();
    const pos = nodePositions[node.id] || { x: 0, y: 0 };

    // Mouse position in graph coordinates
    const mouseGraphX = (e.clientX - rect.left - pan.x) / zoom;
    const mouseGraphY = (e.clientY - rect.top - pan.y) / zoom;

    draggedNodeRef.current = node.id;
    dragNodeOffsetRef.current = {
      x: mouseGraphX - pos.x,
      y: mouseGraphY - pos.y,
    };
    didDragNodeRef.current = false;
    setDraggedNodeId(node.id);
  };

  // Pan & Node Drag interaction handlers
  const handleMouseDown = (e) => {
    if (e.button !== 0) return;
    if (e.target.tagName === 'svg' || e.target.tagName === 'g' || e.target.classList?.contains('edges-layer')) {
      setIsDragging(true);
      setDragStart({ x: e.clientX - pan.x, y: e.clientY - pan.y });
    }
  };

  const handleMouseMove = (e) => {
    if (draggedNodeRef.current) {
      const container = containerRef.current;
      if (!container) return;
      const rect = container.getBoundingClientRect();
      const mouseGraphX = (e.clientX - rect.left - pan.x) / zoom;
      const mouseGraphY = (e.clientY - rect.top - pan.y) / zoom;

      const newX = Math.round(mouseGraphX - dragNodeOffsetRef.current.x);
      const newY = Math.round(mouseGraphY - dragNodeOffsetRef.current.y);

      didDragNodeRef.current = true;

      setNodePositions((prev) => {
        const updated = {
          ...prev,
          [draggedNodeRef.current]: { x: newX, y: newY },
        };
        nodePositionsRef.current = updated;
        return updated;
      });
    } else if (isDragging) {
      setPan({ x: e.clientX - dragStart.x, y: e.clientY - dragStart.y });
    }
  };

  const handleMouseUp = () => {
    if (draggedNodeRef.current) {
      draggedNodeRef.current = null;
      setDraggedNodeId(null);
    }
    setIsDragging(false);
  };

  const selectedNode = useMemo(() => {
    if (!selectedNodeId) return null;
    return nodes.find((n) => n.id === selectedNodeId);
  }, [selectedNodeId, nodes]);

  // Helper to determine node image / logo URL
  const getNodeImageUrl = (node) => {
    if (node.properties?.image_url) return node.properties.image_url;
    if (node.type === 'domain') {
      return `https://www.google.com/s2/favicons?domain=${node.label}&sz=128`;
    }
    if (node.type === 'organization') {
      const dNode = nodes.find((n) => n.type === 'domain');
      const domainName = dNode
        ? dNode.label
        : node.label.toLowerCase().replace(/\s+/g, '') + '.com';
      return `https://www.google.com/s2/favicons?domain=${domainName}&sz=128`;
    }
    if (node.type === 'person') {
      return `https://ui-avatars.com/api/?name=${encodeURIComponent(
        node.label
      )}&background=042f2e&color=2dd4bf&bold=true&size=128`;
    }
    return null;
  };

  return (
    <div
      ref={containerRef}
      className="relative w-full h-[640px] bg-void/90 rounded-lg border border-border-dim overflow-hidden select-none"
      onMouseDown={handleMouseDown}
      onMouseMove={handleMouseMove}
      onMouseUp={handleMouseUp}
      onWheel={handleWheel}
    >
      {/* Floating Canvas Controls */}
      <div className="absolute top-4 right-4 z-20 flex items-center gap-1.5 p-1.5 rounded-lg bg-panel/90 backdrop-blur-md border border-border-dim shadow-panel">
        <button
          onClick={() => handleZoom(0.15)}
          className="p-1.5 rounded hover:bg-void text-text-dim hover:text-cyan-signal transition-colors active:scale-95"
          title="Zoom In (+15%)"
        >
          <ZoomIn className="w-4 h-4" />
        </button>
        <button
          onClick={() => handleZoom(-0.15)}
          className="p-1.5 rounded hover:bg-void text-text-dim hover:text-cyan-signal transition-colors active:scale-95"
          title="Zoom Out (-15%)"
        >
          <ZoomOut className="w-4 h-4" />
        </button>
        <button
          onClick={() => fitGraphToViewport()}
          className="p-1.5 rounded hover:bg-void text-text-dim hover:text-cyan-signal transition-colors flex items-center gap-1 active:scale-95"
          title="Fit Graph to Screen"
        >
          <Maximize2 className="w-4 h-4" />
        </button>
        <button
          onClick={() => {
            setZoom(1);
            setPan({ x: 0, y: 0 });
          }}
          className="p-1.5 rounded hover:bg-void text-text-dim hover:text-cyan-signal transition-colors active:scale-95"
          title="Reset Viewport (100%)"
        >
          <RotateCcw className="w-4 h-4" />
        </button>
        <span className="text-[10px] font-mono text-text-dim px-2">
          {Math.round(zoom * 100)}%
        </span>
      </div>

      {/* Selected Node Quick HUD Overlay */}
      {selectedNode && (
        <div className="absolute bottom-4 left-4 z-20 w-84 p-4 rounded-lg bg-panel/95 backdrop-blur-md border border-border-dim shadow-2xl space-y-3 animate-fadeIn">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span
                className="w-2.5 h-2.5 rounded-full"
                style={{
                  backgroundColor: (ENTITY_CONFIG[selectedNode.type] || ENTITY_CONFIG.default).color,
                }}
              />
              <span className="text-[10px] font-mono uppercase tracking-wider text-text-dim font-bold">
                {selectedNode.type === 'staff_cluster' ? 'Personnel Cluster' : selectedNode.type}
              </span>
            </div>
            <button
              onClick={() => onSelectNode(null)}
              className="text-text-dim hover:text-text-primary text-xs"
            >
              ✕
            </button>
          </div>

          {/* Node Identity Card */}
          <div className="flex items-start gap-3">
            {getNodeImageUrl(selectedNode) && (
              <img
                src={getNodeImageUrl(selectedNode)}
                alt={selectedNode.label}
                className="w-10 h-10 rounded-full border border-border-dim shrink-0 bg-void object-cover"
                onError={(e) => {
                  e.target.style.display = 'none';
                }}
              />
            )}
            <div className="min-w-0 flex-1">
              <h4 className="font-mono font-bold text-sm text-text-primary truncate">
                {selectedNode.label}
              </h4>
              {selectedNode.properties?.title && (
                <p className="text-xs text-text-dim truncate">
                  {selectedNode.properties.title}
                </p>
              )}
              {selectedNode.properties?.email && (
                <p className="text-[11px] font-mono text-cyan-signal truncate">
                  {selectedNode.properties.email}
                </p>
              )}
              {!selectedNode.properties?.title && !selectedNode.properties?.email && (
                <p className="text-[11px] font-mono text-text-dim truncate">
                  {selectedNode.canonical_id}
                </p>
              )}
            </div>
          </div>

          {/* PGP Cryptographic Key Badge */}
          {(selectedNode.properties?.key_id || selectedNode.properties?.source?.includes('pgp')) && (
            <div className="flex items-center gap-1.5 px-2 py-1 rounded bg-success-green/10 border border-success-green/30 text-success-green text-[11px] font-mono">
              <Lock className="w-3 h-3 text-success-green" />
              <span>PGP Key: {selectedNode.properties?.key_id ? selectedNode.properties.key_id.slice(-8) : 'Verified'}</span>
              {selectedNode.properties?.key_created && (
                <span className="text-text-dim text-[10px]">({selectedNode.properties.key_created})</span>
              )}
            </div>
          )}

          {/* Cloud Storage Exposure Status Banner */}
          {selectedNode.type === 'cloud_resource' && (
            <div className={`p-2 rounded border text-xs font-mono ${
              selectedNode.properties?.status === 'ACCESSIBLE'
                ? 'bg-rose-500/10 border-rose-500/40 text-rose-400'
                : 'bg-amber-500/10 border-amber-500/40 text-amber-400'
            }`}>
              <div className="font-bold flex items-center gap-1.5">
                <Cloud className="w-3.5 h-3.5" />
                <span>{selectedNode.properties?.provider || 'Cloud Storage'}: {selectedNode.properties?.status}</span>
              </div>
              {selectedNode.properties?.sample_keys?.length > 0 && (
                <div className="mt-1 text-[10px] text-text-dim">
                  Sample files: {selectedNode.properties.sample_keys.slice(0, 2).join(', ')}
                </div>
              )}
            </div>
          )}

          {/* Corporate Subsidiary Anchors */}
          {selectedNode.properties?.is_subsidiary && (
            <div className="p-2 rounded bg-purple-500/10 border border-purple-500/30 text-xs font-mono text-purple-300">
              <div className="font-bold flex items-center justify-between">
                <span>Verified Corporate Subsidiary</span>
                <span className="text-[10px] text-purple-400 font-bold">{selectedNode.properties?.confidence_score}%</span>
              </div>
              {selectedNode.properties?.anchors?.length > 0 && (
                <div className="mt-1 text-[10px] text-text-dim truncate">
                  Anchor: {selectedNode.properties.anchors[0].description}
                </div>
              )}
            </div>
          )}

          {/* LinkedIn Profile Launch Button */}
          {selectedNode.properties?.profile_url && (
            <a
              href={selectedNode.properties.profile_url}
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center justify-center gap-1.5 w-full py-1.5 rounded bg-[#0077b5]/15 hover:bg-[#0077b5]/25 border border-[#0077b5]/40 text-[#38bdf8] text-xs font-mono font-bold transition-all shadow-sm"
            >
              <Linkedin className="w-3.5 h-3.5 text-[#0077b5]" />
              <span>Open LinkedIn Profile</span>
              <ExternalLink className="w-3 h-3" />
            </a>
          )}

          {selectedNode.type === 'staff_cluster' && (
            <div className="p-2 rounded bg-void border border-border-dim text-xs font-mono text-pink-400">
              Click to view all {selectedNode.properties?.count || ''} personnel profiles in side drawer.
            </div>
          )}

          {/* Action button: Expand Node */}
          <div className="flex items-center gap-2 pt-1">
            {onExpandNode && (
              <button
                onClick={() => onExpandNode(selectedNode.id)}
                disabled={isExpanding || expandedNodeIds.has(selectedNode.id)}
                className={`flex-1 px-3 py-1.5 rounded border font-mono text-xs font-semibold flex items-center justify-center gap-1.5 transition-all ${
                  expandedNodeIds.has(selectedNode.id)
                    ? 'bg-success-green/15 border-success-green/40 text-success-green cursor-default'
                    : isExpanding
                    ? 'bg-cyan-signal/20 border-cyan-signal/50 text-cyan-signal animate-pulse cursor-wait'
                    : 'bg-cyan-signal/15 hover:bg-cyan-signal/25 border-cyan-signal/40 text-cyan-signal shadow-glow-cyan-sm'
                }`}
              >
                {expandedNodeIds.has(selectedNode.id) ? (
                  <>
                    <CheckCircle className="w-3.5 h-3.5" />
                    <span>Neighborhood Expanded ✓</span>
                  </>
                ) : isExpanding ? (
                  <>
                    <span className="w-3 h-3 rounded-full border-2 border-cyan-signal border-t-transparent animate-spin" />
                    <span>Unfolding Neighbors...</span>
                  </>
                ) : (
                  <>
                    <span>Expand Neighborhood</span>
                    <ChevronRight className="w-3.5 h-3.5" />
                  </>
                )}
              </button>
            )}
          </div>
        </div>
      )}

      {/* SVG Rendering Layer */}
      <svg
        className="w-full h-full cursor-grab active:cursor-grabbing"
        style={{
          transform: `translate(${pan.x}px, ${pan.y}px) scale(${zoom})`,
          transformOrigin: '0 0',
          transition: isDragging ? 'none' : 'transform 0.15s ease-out',
        }}
      >
        <defs>
          <filter id="glow-cyan" x="-20%" y="-20%" width="140%" height="140%">
            <feGaussianBlur stdDeviation="3" result="blur" />
            <feComposite in="SourceGraphic" in2="blur" operator="over" />
          </filter>
          {/* Directional Arrow Marker */}
          <marker
            id="graph-arrow"
            viewBox="0 0 10 10"
            refX="22"
            refY="5"
            markerWidth="5"
            markerHeight="5"
            orient="auto-start-reverse"
          >
            <path d="M 0 1.5 L 8 5 L 0 8.5 z" fill="#06b6d4" fillOpacity="0.8" />
          </marker>

          {/* Generate Clip Paths for all image nodes */}
          {nodes.map((node) => {
            const cfg = ENTITY_CONFIG[node.type] || ENTITY_CONFIG.default;
            const radius = cfg.radius || 18;
            return (
              <clipPath key={`clip-${node.id}`} id={`clip-${node.id}`}>
                <circle cx="0" cy="0" r={radius - 2} />
              </clipPath>
            );
          })}
        </defs>

        {/* 1. Render Edges (Curved Bezier lines with legible relationship pills) */}
        <g className="edges-layer">
          {edges.map((edge) => {
            const srcPos = nodePositions[edge.source];
            const tgtPos = nodePositions[edge.target];
            if (!srcPos || !tgtPos) return null;

            const isHovered = hoveredEdgeId === edge.id;
            const midX = (srcPos.x + tgtPos.x) / 2;
            const midY = (srcPos.y + tgtPos.y) / 2;
            const hasEvidence = (edge.supporting_evidence_ids || []).length > 0;
            const relText = (edge.type || 'LINKS_TO').replace(/_/g, ' ');

            // Smooth Bezier Curve
            const dx = tgtPos.x - srcPos.x;
            const dy = tgtPos.y - srcPos.y;
            const ctrlX = midX - dy * 0.08;
            const ctrlY = midY + dx * 0.08;

            return (
              <g
                key={edge.id}
                className="cursor-pointer group"
                onMouseEnter={() => setHoveredEdgeId(edge.id)}
                onMouseLeave={() => setHoveredEdgeId(null)}
                onClick={() => {
                  if (hasEvidence && onSelectEvidence) {
                    onSelectEvidence(edge.supporting_evidence_ids[0]);
                  }
                }}
              >
                {/* Curved Edge Path */}
                <path
                  d={`M ${srcPos.x} ${srcPos.y} Q ${ctrlX} ${ctrlY} ${tgtPos.x} ${tgtPos.y}`}
                  fill="none"
                  stroke={isHovered ? '#06b6d4' : '#334155'}
                  strokeWidth={isHovered ? 2.5 : 1.5}
                  strokeDasharray={edge.status === 'possible_match' ? '4,4' : 'none'}
                  markerEnd="url(#graph-arrow)"
                  className="transition-colors duration-200"
                />

                {/* Edge Mid-Label Pill (Shows semantic relationship) */}
                <g transform={`translate(${ctrlX}, ${ctrlY})`}>
                  <rect
                    x={-(relText.length * 3.5 + 8)}
                    y="-9"
                    width={relText.length * 7 + 16}
                    height="18"
                    rx="9"
                    fill="#0a0e17"
                    stroke={isHovered ? '#06b6d4' : '#1e293b'}
                    strokeWidth="1"
                    className="transition-colors"
                  />
                  <text
                    textAnchor="middle"
                    dominantBaseline="middle"
                    fill={isHovered ? '#06b6d4' : '#94a3b8'}
                    fontSize="8.5"
                    fontFamily="monospace"
                    fontWeight="600"
                  >
                    {relText}
                  </text>
                </g>
              </g>
            );
          })}
        </g>

        {/* 2. Render Nodes */}
        <g className="nodes-layer">
          {nodes.map((node) => {
            const pos = nodePositions[node.id];
            if (!pos) return null;

            const cfg = ENTITY_CONFIG[node.type] || ENTITY_CONFIG.default;
            const isSelected = selectedNodeId === node.id;
            const radius = cfg.radius || 18;
            const imageUrl = getNodeImageUrl(node);
            const hasLinkedIn = (node.properties?.profile_url || '')
              .toLowerCase()
              .includes('linkedin');

            // Format clean truncated label to prevent card collisions
            const displayLabel =
              node.label.length > 17 ? `${node.label.slice(0, 15)}…` : node.label;
            const pillWidth = Math.min(displayLabel.length * 6.6, 115) + 12;

            return (
              <g
                key={node.id}
                transform={`translate(${pos.x}, ${pos.y})`}
                className={`cursor-grab active:cursor-grabbing group ${
                  draggedNodeId === node.id ? 'cursor-grabbing' : ''
                }`}
                onMouseDown={(e) => handleNodeMouseDown(e, node)}
                onClick={(e) => {
                  e.stopPropagation();
                  if (!didDragNodeRef.current && onSelectNode) {
                    onSelectNode(node.id);
                  }
                }}
              >
                {/* Outer Glow on selection */}
                {isSelected && (
                  <circle
                    r={radius + 8}
                    fill="none"
                    stroke={cfg.color}
                    strokeWidth="2"
                    strokeOpacity="0.8"
                    strokeDasharray="4,4"
                    className="animate-spin"
                    style={{ animationDuration: '8s' }}
                  />
                )}

                {/* Node Outer Ring & Body */}
                <circle
                  r={radius}
                  fill="#0a0e17"
                  stroke={cfg.color}
                  strokeWidth={isSelected ? 3 : 2}
                  className="transition-transform group-hover:scale-110 duration-150"
                  filter={isSelected ? 'url(#glow-cyan)' : 'none'}
                />

                {/* Inner Icon Pill Fallback */}
                <circle r={radius - 2} fill={cfg.color} fillOpacity="0.18" />

                {/* Node Center Label Abbr (Fallback) */}
                <text
                  textAnchor="middle"
                  dominantBaseline="middle"
                  fill={cfg.color}
                  fontSize="9.5"
                  fontFamily="monospace"
                  fontWeight="bold"
                  className="pointer-events-none select-none"
                >
                  {cfg.label}
                </text>

                {/* Dynamic Image Overlay (Favicon or Profile Avatar) */}
                {imageUrl && (
                  <image
                    href={imageUrl}
                    x={-(radius - 2)}
                    y={-(radius - 2)}
                    width={(radius - 2) * 2}
                    height={(radius - 2) * 2}
                    clipPath={`url(#clip-${node.id})`}
                    preserveAspectRatio="xMidYMid slice"
                    className="pointer-events-none select-none transition-opacity group-hover:opacity-90"
                  />
                )}

                {/* LinkedIn Badge Indicator */}
                {hasLinkedIn && (
                  <g
                    transform={`translate(${radius * 0.7}, ${-radius * 0.7})`}
                    className="cursor-pointer hover:scale-125 transition-transform"
                    onClick={(e) => {
                      e.stopPropagation();
                      window.open(node.properties.profile_url, '_blank');
                    }}
                  >
                    <circle r="8" fill="#0077b5" stroke="#0a0e17" strokeWidth="1.5" />
                    <text
                      textAnchor="middle"
                      dominantBaseline="middle"
                      fill="#ffffff"
                      fontSize="8"
                      fontWeight="bold"
                      fontFamily="sans-serif"
                    >
                      in
                    </text>
                  </g>
                )}

                {/* Node Bottom Label with dark background pill */}
                <g transform={`translate(0, ${radius + 15})`}>
                  <rect
                    x={-(pillWidth / 2)}
                    y="-8"
                    width={pillWidth}
                    height="16"
                    rx="4"
                    fill="#030712"
                    fillOpacity="0.90"
                    stroke="#1e293b"
                    strokeWidth="0.8"
                  />
                  <text
                    textAnchor="middle"
                    dominantBaseline="middle"
                    fill="#e2e8f0"
                    fontSize="9.5"
                    fontFamily="monospace"
                    fontWeight="500"
                    className="pointer-events-none select-none"
                  >
                    {displayLabel}
                  </text>
                </g>
              </g>
            );
          })}
        </g>
      </svg>
    </div>
  );
}
