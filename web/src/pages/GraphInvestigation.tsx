import React, { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Network, Shield, Eye, ZoomIn, ZoomOut, RotateCcw,
  Info, Filter, Layers, ChevronRight, ExternalLink, Box, Sparkles
} from 'lucide-react';
import { useAnalysis } from '@/context/AnalysisContext';
import { DEMO_EMAIL_RAW, DEMO_EMAIL_FILENAME } from '@/demo/demoEmail';
import { analyseEmail } from '@/services/analysisService';
import { useSession } from '@/context/SessionContext';
import { ThreatGraph3D, GraphNodeData, GraphLinkData } from '@/components/3d/ThreatGraph3D';
import type { GraphNode, GraphEdge, GraphNodeKind, Severity } from '@/types';

interface SimNode extends GraphNode {
  x?: number;
  y?: number;
  vx?: number;
  vy?: number;
}

export function GraphInvestigation() {
  const { currentAnalysis, setCurrentAnalysis, addToHistory } = useAnalysis();
  const { session } = useSession();
  const navigate = useNavigate();
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [selectedNode, setSelectedNode] = useState<SimNode | null>(null);
  const [viewMode, setViewMode] = useState<'3D' | '2D'>('3D');
  const [analyzingDemo, setAnalyzingDemo] = useState(false);

  const handleLoadDemo = async () => {
    setAnalyzingDemo(true);
    try {
      const outcome = await analyseEmail({
        raw: DEMO_EMAIL_RAW,
        filename: DEMO_EMAIL_FILENAME,
        analystId: session?.analystId ?? 'DEMO',
        acquisitionSource: 'Graph Investigation Demo Load',
        useBackend: true,
      });
      setCurrentAnalysis(outcome.analysis);
      addToHistory(outcome.analysis);
    } catch (e) {
      console.error(e);
    } finally {
      setAnalyzingDemo(false);
    }
  };

  const analysis = currentAnalysis;

  if (!analysis) {
    return (
      <div className="p-8 max-w-2xl mx-auto my-12 text-center animate-fade-in">
        <div className="panel p-10 border-cyan-500/20 bg-[#080e21]">
          <Network size={48} className="text-cyan-400 mx-auto mb-4 animate-pulse" />
          <h2 className="text-lg font-bold text-slate-100 mb-2">No Active Graph Investigation</h2>
          <p className="text-xs text-slate-400 mb-6 leading-relaxed">
            Analyze an email message to generate a multi-dimensional relationship graph connecting senders, domains, IP infrastructure, URLs, and campaigns.
          </p>
          <div className="flex justify-center gap-3">
            <button onClick={() => navigate('/analyzer')} className="btn-primary text-xs">
              Go to Email Analyzer
            </button>
            <button onClick={handleLoadDemo} disabled={analyzingDemo} className="btn-ghost text-xs border-amber-500/40 text-amber-400">
              {analyzingDemo ? 'Analyzing...' : '⚡ Load BEC Demo Graph'}
            </button>
          </div>
        </div>
      </div>
    );
  }

  // Convert analysis into 3D Graph Nodes
  const graph3DNodes: GraphNodeData[] = [
    {
      id: 'root-eml',
      name: analysis.metadata.subject || 'Analyzed Email',
      category: 'EMAIL',
      threatLevel: analysis.score.level,
    },
    {
      id: 'snd-1',
      name: analysis.metadata.from || 'Claimed Sender',
      category: 'SENDER',
      threatLevel: 'HIGH',
    },
    ...analysis.domainIntel.map((d, i) => ({
      id: `dom-${i}`,
      name: d.domain,
      category: 'DOMAIN' as const,
      threatLevel: d.risk,
    })),
    ...analysis.iocs.map((ioc, i) => ({
      id: `ioc-${i}`,
      name: ioc.value,
      category: (ioc.type === 'IP' ? 'IP' : ioc.type === 'URL' ? 'URL' : 'HASH') as any,
      threatLevel: ioc.risk as any,
    })),
  ];

  const graph3DLinks: GraphLinkData[] = [
    { source: 'root-eml', target: 'snd-1', relation: 'SENT_FROM' },
    ...analysis.domainIntel.map((_, i) => ({
      source: 'snd-1',
      target: `dom-${i}`,
      relation: 'RESOLVES_TO' as const,
    })),
    ...analysis.iocs.map((_, i) => ({
      source: 'root-eml',
      target: `ioc-${i}`,
      relation: 'LINKS_TO' as const,
    })),
  ];

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-cyan-500/15 pb-5">
        <div>
          <div className="flex items-center gap-2">
            <Network size={22} className="text-cyan-400" />
            <h1 className="text-xl font-bold tracking-tight text-white">
              Interactive 3D Threat & Entity Relationship Graph
            </h1>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Visual link analysis across senders, domain lookalikes, hosting ASNs, and payload indicators
          </p>
        </div>

        <div className="flex items-center gap-3">
          {/* Mode Switcher */}
          <div className="flex rounded-lg bg-[#0d1733] border border-cyan-500/20 p-0.5">
            <button
              onClick={() => setViewMode('3D')}
              className={`px-3 py-1.5 rounded-md text-xs font-mono font-bold flex items-center gap-1.5 transition-colors ${
                viewMode === '3D' ? 'bg-cyan-600 text-white shadow-sm' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Box size={13} />
              <span>3D HOLOGRAPHIC</span>
            </button>
            <button
              onClick={() => setViewMode('2D')}
              className={`px-3 py-1.5 rounded-md text-xs font-mono font-bold flex items-center gap-1.5 transition-colors ${
                viewMode === '2D' ? 'bg-cyan-600 text-white shadow-sm' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Layers size={13} />
              <span>2D FORCE GRAPH</span>
            </button>
          </div>

          <button
            onClick={() => navigate('/campaigns')}
            className="btn-primary text-xs flex items-center gap-2"
          >
            <Layers size={14} />
            <span>Campaign Correlator</span>
            <ChevronRight size={14} />
          </button>
        </div>
      </div>

      {/* Graph Display Area */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        <div className="lg:col-span-3 panel p-0 overflow-hidden border-cyan-500/25 h-[520px]">
          <ThreatGraph3D
            nodes={graph3DNodes}
            links={graph3DLinks}
            onSelectNode={(n) => {
              setSelectedNode({
                id: n.id,
                label: n.name,
                kind: n.category as any,
                risk: (n.threatLevel as any) || 'INFO',
                attributes: { Type: n.category, Name: n.name },
                expandable: false,
              });
            }}
          />
        </div>

        {/* Selected Entity Details Panel */}
        <div className="panel p-5 border-cyan-500/25 bg-[#080e21] flex flex-col justify-between">
          <div>
            <div className="text-[10px] font-mono font-bold text-cyan-400 uppercase tracking-wider mb-2 flex items-center gap-1.5">
              <Eye size={12} />
              <span>ENTITY INSPECTOR</span>
            </div>

            {selectedNode ? (
              <div className="space-y-4 animate-fade-in">
                <div>
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-950 text-cyan-300 border border-cyan-500/40">
                    {selectedNode.kind}
                  </span>
                  <div className="text-sm font-bold text-white mt-2 break-all">
                    {selectedNode.label}
                  </div>
                </div>

                <div className="space-y-2 border-t border-cyan-500/15 pt-3 text-xs font-mono">
                  {selectedNode.attributes &&
                    Object.entries(selectedNode.attributes).map(([k, v]) => (
                      <div key={k} className="flex justify-between gap-2">
                        <span className="text-slate-500">{k}:</span>
                        <span className="text-slate-200 font-semibold truncate max-w-[140px]" title={String(v)}>
                          {String(v)}
                        </span>
                      </div>
                    ))}
                </div>
              </div>
            ) : (
              <div className="py-12 text-center text-xs text-slate-500 font-mono">
                Click any node in the 3D graph to inspect attributes and connections.
              </div>
            )}
          </div>

          <div className="p-3 rounded-lg bg-[#050a18] border border-cyan-500/15 text-[11px] text-slate-400 font-mono">
            <div className="text-cyan-400 font-bold mb-1">GRAPH METRICS</div>
            <div>Total Nodes: {graph3DNodes.length}</div>
            <div>Active Edges: {graph3DLinks.length}</div>
          </div>
        </div>
      </div>
    </div>
  );
}
