import React, { useState, useMemo } from 'react';
import {
  Share2,
  Sliders,
  Search,
  Filter,
  CheckCircle2,
  AlertOctagon,
  Layers,
  FileCheck,
  Route,
  ArrowRight,
  X,
  Crosshair,
  Compass,
  Users,
  Target,
  ExternalLink,
  Mail,
  Linkedin,
  Globe,
  Lock,
} from 'lucide-react';
import { useScanGraph } from '../api/hooks';
import GraphCanvas from '../components/graph/GraphCanvas';
import EvidenceDrawer from '../components/graph/EvidenceDrawer';
import { LoadingState, EmptyState } from '../components/LoadingState';
import { apiRequest } from '../api/client';
import { useTenant } from '../context/TenantContext';

const ENTITY_CATEGORIES = [
  { id: 'infrastructure', label: 'Infrastructure', types: ['domain', 'subdomain', 'ip', 'port', 'service'] },
  { id: 'technologies', label: 'Tech Stack', types: ['technology'] },
  { id: 'people', label: 'People & Identities', types: ['person', 'email', 'username', 'staff_cluster'] },
  { id: 'vulnerabilities', label: 'Vulnerabilities', types: ['vulnerability'] },
  { id: 'exposures', label: 'Exposures & Cloud', types: ['cloud_resource', 'breach'] },
  { id: 'documents', label: 'Public Documents', types: ['document'] },
];

export default function GraphView({ scanId }) {
  const { tenantId } = useTenant();
  const [activeLens, setActiveLens] = useState('composite'); // 'composite' | 'attack_surface' | 'executive'
  const [selectedEvidenceId, setSelectedEvidenceId] = useState(null);
  const [selectedNodeId, setSelectedNodeId] = useState(null);
  const [minConfidence, setMinConfidence] = useState(0.0);
  const [searchQuery, setSearchQuery] = useState('');
  const [activeCategories, setActiveCategories] = useState([
    'infrastructure',
    'technologies',
    'people',
    'vulnerabilities',
    'exposures',
    'documents',
  ]);

  // Path Finder State
  const [showPathFinder, setShowPathFinder] = useState(false);
  const [pathSourceId, setPathSourceId] = useState('');
  const [pathTargetId, setPathTargetId] = useState('');
  const [pathResult, setPathResult] = useState(null);
  const [isTracingPath, setIsTracingPath] = useState(false);
  const [pathError, setPathError] = useState(null);

  // Compute active types from selected categories
  const activeTypes = useMemo(() => {
    const types = [];
    activeCategories.forEach((catId) => {
      const cat = ENTITY_CATEGORIES.find((c) => c.id === catId);
      if (cat) types.push(...cat.types);
    });
    return types;
  }, [activeCategories]);

  const { data: graphData, isLoading, refetch } = useScanGraph(scanId, activeTypes, minConfidence, activeLens);

  const toggleCategory = (catId) => {
    setActiveCategories((prev) =>
      prev.includes(catId) ? prev.filter((id) => id !== catId) : [...prev, catId]
    );
  };

  // Dynamic 1-Hop Expansion State
  const [expandedDynamicNodes, setExpandedDynamicNodes] = useState([]);
  const [expandedDynamicEdges, setExpandedDynamicEdges] = useState([]);
  const [isExpanding, setIsExpanding] = useState(false);
  const [expandedNodeIds, setExpandedNodeIds] = useState(new Set());

  // Combined nodes & edges (Lens base + dynamically expanded neighbors)
  const combinedNodes = useMemo(() => {
    const base = graphData?.nodes || [];
    const seen = new Set(base.map((n) => n.id));
    const toAdd = expandedDynamicNodes.filter((n) => !seen.has(n.id));
    return [...base, ...toAdd];
  }, [graphData?.nodes, expandedDynamicNodes]);

  const combinedEdges = useMemo(() => {
    const base = graphData?.edges || [];
    const seen = new Set(base.map((e) => e.id));
    const toAdd = expandedDynamicEdges.filter((e) => !seen.has(e.id));
    return [...base, ...toAdd];
  }, [graphData?.edges, expandedDynamicEdges]);

  // Filter nodes by search query
  const filteredNodes = useMemo(() => {
    if (!combinedNodes) return [];
    if (!searchQuery.trim()) return combinedNodes;
    const query = searchQuery.toLowerCase();
    return combinedNodes.filter(
      (n) => n.label.toLowerCase().includes(query) || (n.canonical_id || '').toLowerCase().includes(query)
    );
  }, [combinedNodes, searchQuery]);

  const filteredNodeIds = useMemo(() => {
    return new Set(filteredNodes.map((n) => n.id));
  }, [filteredNodes]);

  const filteredEdges = useMemo(() => {
    if (!combinedEdges) return [];
    return combinedEdges.filter(
      (e) => filteredNodeIds.has(e.source) && filteredNodeIds.has(e.target)
    );
  }, [combinedEdges, filteredNodeIds]);

  // Selected Node Details
  const selectedNode = useMemo(() => {
    if (!selectedNodeId) return null;
    return combinedNodes.find((n) => n.id === selectedNodeId);
  }, [selectedNodeId, combinedNodes]);

  // Dynamic Node Expansion handler
  const handleExpandNode = async (entityId) => {
    if (isExpanding) return;
    try {
      setIsExpanding(true);
      const resp = await apiRequest(`/scan/${scanId}/graph/expand?entity_id=${encodeURIComponent(entityId)}`, { tenantId });
      if (resp?.nodes?.length > 0) {
        setExpandedDynamicNodes((prev) => {
          const existingIds = new Set(prev.map((n) => n.id).concat((graphData?.nodes || []).map((n) => n.id)));
          const newOnes = resp.nodes.filter((n) => !existingIds.has(n.id));
          return [...prev, ...newOnes];
        });
        setExpandedDynamicEdges((prev) => {
          const existingIds = new Set(prev.map((e) => e.id).concat((graphData?.edges || []).map((e) => e.id)));
          const newOnes = (resp.edges || []).filter((e) => !existingIds.has(e.id));
          return [...prev, ...newOnes];
        });
        setExpandedNodeIds((prev) => new Set([...prev, entityId]));
      }
    } catch (e) {
      console.error('Failed to expand node:', e);
    } finally {
      setIsExpanding(false);
    }
  };

  // Trace Evidence Path between two entities
  const handleFindPath = async () => {
    if (!pathSourceId || !pathTargetId) return;
    setIsTracingPath(true);
    setPathError(null);
    try {
      const data = await apiRequest(
        `/scan/${scanId}/graph/path?source_id=${pathSourceId}&target_id=${pathTargetId}`,
        { tenantId }
      );
      setPathResult(data);
      if (!data.found) {
        setPathError('No evidence path exists between these two entities within max depth.');
      }
    } catch (err) {
      setPathError(err.message || 'Failed to calculate evidence path');
    } finally {
      setIsTracingPath(false);
    }
  };

  const pathNodeIds = useMemo(() => {
    if (!pathResult?.found || !pathResult.nodes) return null;
    return new Set(pathResult.nodes.map((n) => n.id));
  }, [pathResult]);

  const pathEdgeIds = useMemo(() => {
    if (!pathResult?.found || !pathResult.edges) return null;
    return new Set(pathResult.edges.map((e) => e.id));
  }, [pathResult]);

  const handleClearPath = () => {
    setPathResult(null);
    setPathError(null);
  };

  if (isLoading && !graphData) {
    return <LoadingState message="Synthesizing hierarchical intelligence graph..." />;
  }

  return (
    <div className="space-y-4">
      {/* Perspective Lens Selector Bar */}
      <div className="p-3 rounded-lg bg-panel border border-border-dim shadow-panel flex flex-col md:flex-row md:items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <span className="text-xs font-mono text-text-dim uppercase tracking-wider font-bold mr-1">
            Graph Lens:
          </span>
          {[
            { id: 'executive', label: 'Executive & Personnel', desc: 'Leadership, Leads, Leaked Docs, Org Hierarchy' },
            { id: 'attack_surface', label: 'Tactical Attack Surface', desc: 'Origin Servers, Subdomains, Critical Vulns' },
            { id: 'composite', label: 'Composite Infrastructure', desc: 'Balanced Full Infrastructure & Personnel View' },
          ].map((lens) => {
            const isActive = activeLens === lens.id;
            return (
              <button
                key={lens.id}
                onClick={() => {
                  setActiveLens(lens.id);
                  setExpandedDynamicNodes([]);
                  setExpandedDynamicEdges([]);
                  setExpandedNodeIds(new Set());
                }}
                className={`px-3 py-1.5 rounded-md text-xs font-mono transition-all flex items-center gap-1.5 ${
                  isActive
                    ? 'bg-void text-cyan-signal border border-cyan-signal/50 shadow-glow-cyan-sm font-bold'
                    : 'bg-void/40 text-text-dim border border-border-dim hover:text-text-primary hover:bg-void'
                }`}
                title={lens.desc}
              >
                <span>{lens.label}</span>
              </button>
            );
          })}
        </div>

        {/* Telemetry Stats */}
        <div className="flex items-center gap-3 font-mono text-xs text-text-dim">
          <span>
            Entities: <span className="text-cyan-signal font-bold">{filteredNodes.length}</span>
          </span>
          <span>•</span>
          <span>
            Semantic Links: <span className="text-text-primary font-bold">{filteredEdges.length}</span>
          </span>
        </div>
      </div>

      {/* Filter & Controls Toolbar */}
      <div className="p-4 rounded-lg bg-panel border border-border-dim shadow-panel flex flex-col md:flex-row md:items-center justify-between gap-4">
        {/* Category Filter Chips */}
        <div className="flex flex-wrap items-center gap-1.5">
          <div className="flex items-center gap-1.5 text-xs font-mono text-text-dim mr-2">
            <Filter className="w-3.5 h-3.5 text-cyan-signal" />
            <span>Layers:</span>
          </div>
          {ENTITY_CATEGORIES.map((cat) => {
            const isActive = activeCategories.includes(cat.id);
            return (
              <button
                key={cat.id}
                onClick={() => toggleCategory(cat.id)}
                className={`px-2.5 py-1 rounded text-[11px] font-mono font-medium transition-all ${
                  isActive
                    ? 'bg-cyan-signal/15 text-cyan-signal border border-cyan-signal/40 shadow-glow-cyan-sm'
                    : 'bg-void text-text-dim border border-border-dim hover:text-text-primary'
                }`}
              >
                {cat.label}
              </button>
            );
          })}
        </div>

        {/* Controls: Path Tracer Toggle, Search */}
        <div className="flex flex-wrap items-center gap-3 shrink-0">
          <button
            onClick={() => setShowPathFinder((prev) => !prev)}
            className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded text-xs font-mono transition-all ${
              showPathFinder
                ? 'bg-cyan-signal text-black font-bold shadow-glow-cyan-sm'
                : 'bg-void border border-border-dim text-text-dim hover:text-cyan-signal'
            }`}
          >
            <Route className="w-3.5 h-3.5" />
            <span>Trace Path</span>
          </button>

          {/* Search Box */}
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-text-dim absolute left-2.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search graph nodes..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-8 pr-3 py-1.5 rounded bg-void border border-border-dim text-xs font-mono text-text-primary focus:outline-none focus:border-cyan-signal w-40 sm:w-48"
            />
          </div>
        </div>
      </div>

      {/* Path Finder Expansion Bar */}
      {showPathFinder && (
        <div className="p-4 rounded-lg bg-void/95 border border-cyan-signal/40 shadow-panel space-y-3.5 animate-fadeIn">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-xs font-mono text-cyan-signal font-bold uppercase tracking-wider">
              <Route className="w-4 h-4 text-cyan-signal" />
              <span>Evidence-Backed Path Finding</span>
            </div>
            <button
              onClick={() => {
                setShowPathFinder(false);
                handleClearPath();
              }}
              className="p-1 rounded hover:bg-panel text-text-dim hover:text-text-primary"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          <div className="flex flex-col sm:flex-row items-center gap-3">
            <select
              value={pathSourceId}
              onChange={(e) => setPathSourceId(e.target.value)}
              className="w-full sm:w-1/2 p-2 rounded bg-panel border border-border-dim text-xs font-mono text-text-primary focus:border-cyan-signal"
            >
              <option value="">Select Origin Entity...</option>
              {filteredNodes.map((n) => (
                <option key={n.id} value={n.id}>
                  [{n.type.toUpperCase()}] {n.label}
                </option>
              ))}
            </select>

            <ArrowRight className="w-4 h-4 text-cyan-signal hidden sm:block shrink-0" />

            <select
              value={pathTargetId}
              onChange={(e) => setPathTargetId(e.target.value)}
              className="w-full sm:w-1/2 p-2 rounded bg-panel border border-border-dim text-xs font-mono text-text-primary focus:border-cyan-signal"
            >
              <option value="">Select Target Pivot...</option>
              {filteredNodes.map((n) => (
                <option key={n.id} value={n.id}>
                  [{n.type.toUpperCase()}] {n.label}
                </option>
              ))}
            </select>

            <button
              onClick={handleFindPath}
              disabled={!pathSourceId || !pathTargetId || isTracingPath}
              className="px-4 py-2 rounded bg-cyan-signal text-black font-mono text-xs font-bold hover:brightness-110 disabled:opacity-50 transition-all shrink-0 shadow-glow-cyan-sm"
            >
              {isTracingPath ? 'Tracing...' : 'Trace'}
            </button>
          </div>

          {pathResult?.found && (
            <div className="p-3.5 rounded-lg bg-panel border border-cyan-signal/40 text-xs font-mono space-y-2.5 shadow-panel animate-fadeIn">
              <div className="flex items-center justify-between">
                <div className="text-cyan-signal font-bold flex items-center gap-1.5">
                  <CheckCircle2 className="w-4 h-4 text-success-green" />
                  <span>Verified Pivot Chain Discovered ({pathResult.path_length} hops):</span>
                </div>
                <button
                  onClick={handleClearPath}
                  className="text-[11px] text-text-dim hover:text-text-primary px-2.5 py-1 rounded bg-void border border-border-dim hover:border-cyan-signal/40 transition-colors"
                >
                  Clear Highlight
                </button>
              </div>

              {/* Step-by-Step Interactive Breadcrumb Route */}
              <div className="flex flex-wrap items-center gap-2 p-2.5 rounded bg-void/90 border border-border-dim">
                {pathResult.nodes?.map((n, i) => {
                  const edge = pathResult.edges?.[i];
                  const isOrigin = i === 0;
                  const isDestination = i === (pathResult.nodes.length - 1);
                  return (
                    <React.Fragment key={n.id}>
                      <button
                        onClick={() => setSelectedNodeId(n.id)}
                        className={`px-3 py-1.5 rounded-lg border text-xs font-semibold flex items-center gap-2 transition-all ${
                          selectedNodeId === n.id
                            ? 'bg-cyan-signal text-black border-cyan-signal shadow-glow-cyan font-bold scale-105'
                            : isOrigin
                            ? 'bg-emerald-500/15 border-emerald-500/50 text-emerald-300 hover:brightness-125'
                            : isDestination
                            ? 'bg-purple-500/15 border-purple-500/50 text-purple-300 hover:brightness-125'
                            : 'bg-panel text-text-primary border-border-dim hover:border-cyan-signal/60'
                        }`}
                        title="Click to inspect this pivot node on canvas"
                      >
                        <span className={`w-2 h-2 rounded-full ${isOrigin ? 'bg-emerald-400' : isDestination ? 'bg-purple-400' : 'bg-cyan-signal'}`} />
                        <span className="font-bold">{n.label}</span>
                      </button>

                      {edge && (
                        <div className="flex items-center gap-1.5 text-[10px] text-cyan-signal font-mono uppercase bg-cyan-signal/10 px-2 py-0.5 rounded border border-cyan-signal/30">
                          <span>{edge.type.replace(/_/g, ' ')}</span>
                          <span className="text-cyan-bright font-bold">➔</span>
                        </div>
                      )}
                    </React.Fragment>
                  );
                })}
              </div>
            </div>
          )}

          {pathError && (
            <div className="p-3 rounded bg-panel border border-magenta-alert/40 text-xs font-mono text-magenta-alert">
              {pathError}
            </div>
          )}
        </div>
      )}

      {/* Main Interactive Canvas */}
      <GraphCanvas
        nodes={filteredNodes}
        edges={filteredEdges}
        selectedNodeId={selectedNodeId}
        onSelectNode={setSelectedNodeId}
        onSelectEvidence={setSelectedEvidenceId}
        onExpandNode={handleExpandNode}
        isExpanding={isExpanding}
        expandedNodeIds={expandedNodeIds}
        pathNodeIds={pathNodeIds}
        pathEdgeIds={pathEdgeIds}
        pathNodes={pathResult?.nodes || []}
      />

      {/* Slide-Out Drawer 1: Evidence Inspection */}
      {selectedEvidenceId && (
        <EvidenceDrawer
          jobId={scanId}
          evidenceId={selectedEvidenceId}
          onClose={() => setSelectedEvidenceId(null)}
        />
      )}

      {/* Slide-Out Drawer 2: Staff Cluster Full Personnel Roster */}
      {selectedNode?.type === 'staff_cluster' && (
        <StaffClusterDrawer
          clusterNode={selectedNode}
          onClose={() => setSelectedNodeId(null)}
        />
      )}
    </div>
  );
}

// ---------------------------------------------------------
// Subcomponent: Staff Cluster Personnel Roster Drawer
// ---------------------------------------------------------
function StaffClusterDrawer({ clusterNode, onClose }) {
  const [search, setSearch] = useState('');
  const staffList = clusterNode.properties?.staff_list || [];

  const filteredStaff = staffList.filter((s) => {
    if (!search.trim()) return true;
    const q = search.toLowerCase();
    return (
      (s.name || '').toLowerCase().includes(q) ||
      (s.title || '').toLowerCase().includes(q) ||
      (s.email || '').toLowerCase().includes(q)
    );
  });

  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/60 backdrop-blur-sm animate-fadeIn">
      <div
        className="w-full max-w-lg bg-panel border-l border-border-dim h-full overflow-y-auto p-6 space-y-6 shadow-2xl flex flex-col justify-between font-mono"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="space-y-4">
          {/* Header */}
          <div className="flex items-center justify-between border-b border-border-dim pb-4">
            <div className="flex items-center gap-2">
              <div className="p-1.5 rounded bg-pink-500/15 border border-pink-500/30 text-pink-400">
                <Users className="w-4 h-4" />
              </div>
              <div>
                <h3 className="text-sm font-bold text-text-primary">
                  {clusterNode.label}
                </h3>
                <span className="text-[11px] text-text-dim">
                  Collapsible Operational Personnel Roster
                </span>
              </div>
            </div>
            <button
              onClick={onClose}
              className="p-1.5 rounded bg-void border border-border-dim text-text-dim hover:text-text-primary transition-colors"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          {/* Search within cluster */}
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-text-dim absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search personnel by name, role, email..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full pl-8 pr-3 py-1.5 rounded bg-void border border-border-dim text-xs text-text-primary font-mono focus:border-cyan-signal focus:outline-none"
            />
          </div>

          {/* Staff Cards List */}
          <div className="space-y-2 max-h-[60vh] overflow-y-auto pr-1">
            {filteredStaff.map((staff, idx) => (
              <div
                key={idx}
                className="p-3 rounded bg-void/50 border border-border-dim space-y-1 hover:border-cyan-signal/40 transition-colors"
              >
                <div className="flex items-center justify-between">
                  <span className="font-bold text-xs text-text-primary">{staff.name}</span>
                  {staff.profile_url && (
                    <a
                      href={staff.profile_url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-text-dim hover:text-cyan-signal transition-colors inline-flex items-center gap-1 text-[10px]"
                    >
                      <span>LinkedIn</span>
                      <ExternalLink className="w-2.5 h-2.5" />
                    </a>
                  )}
                </div>
                <div className="text-[11px] text-text-dim">{staff.title || 'Operational Staff'}</div>
                {staff.email && (
                  <div className="text-[11px] text-cyan-signal font-mono">{staff.email}</div>
                )}
              </div>
            ))}
          </div>
        </div>

        {/* Footer */}
        <div className="pt-4 border-t border-border-dim flex justify-between items-center text-xs text-text-dim">
          <span>Total Staff: {staffList.length}</span>
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded bg-void border border-border-dim hover:border-border-bright text-text-primary transition-colors"
          >
            Close Roster
          </button>
        </div>
      </div>
    </div>
  );
}
