import React, { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Network, Shield, Eye, ZoomIn, ZoomOut, RotateCcw,
  Info, Filter, Layers, ChevronRight, ExternalLink
} from 'lucide-react';
import { useAnalysis } from '@/context/AnalysisContext';
import { DEMO_EMAIL_RAW, DEMO_EMAIL_FILENAME } from '@/demo/demoEmail';
import { analyseEmail } from '@/services/analysisService';
import { useSession } from '@/context/SessionContext';
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
  const [analyzingDemo, setAnalyzingDemo] = useState(false);
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [filterType, setFilterType] = useState<string>('ALL');

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

  // Build Graph Nodes & Edges from Analysis
  const buildGraphData = (): { nodes: SimNode[]; edges: GraphEdge[] } => {
    if (!analysis) return { nodes: [], edges: [] };

    const nodes: SimNode[] = [];
    const edges: GraphEdge[] = [];

    // Root Email Node
    const emailNodeId = 'node-email-0';
    nodes.push({
      id: emailNodeId,
      kind: 'EMAIL',
      label: analysis.metadata.subject || 'Analyzed Email',
      risk: analysis.score.level,
      attributes: {
        From: analysis.metadata.from,
        Subject: analysis.metadata.subject,
        'Threat Score': `${analysis.score.total}/100`,
        Classification: analysis.assessment.classification,
      },
      expandable: false,
    });

    // Sender Node
    const senderId = 'node-sender-1';
    nodes.push({
      id: senderId,
      kind: 'USER',
      label: analysis.metadata.from.split('<')[0]?.trim() || 'Claimed Sender',
      risk: 'HIGH',
      attributes: { Address: analysis.metadata.from },
      expandable: true,
    });
    edges.push({ id: 'e-1', source: emailNodeId, target: senderId, kind: 'SENT_FROM', weight: 0.9 });

    // Domains
    analysis.domainIntel.forEach((d, idx) => {
      const dId = `node-domain-${idx}`;
      nodes.push({
        id: dId,
        kind: 'DOMAIN',
        label: d.domain,
        risk: d.risk,
        attributes: {
          Domain: d.domain,
          Reputation: d.reputation,
          Age: d.ageDays ? `${d.ageDays} days` : 'Unknown',
          Registrar: d.registrar || 'Private',
        },
        expandable: true,
      });
      edges.push({ id: `e-d-${idx}`, source: emailNodeId, target: dId, kind: 'ASSOCIATED_WITH', weight: 0.8 });
    });

    // IPs
    analysis.ipIntel.forEach((ip, idx) => {
      const ipId = `node-ip-${idx}`;
      nodes.push({
        id: ipId,
        kind: 'IP',
        label: ip.ip,
        risk: ip.risk,
        attributes: {
          IP: ip.ip,
          Location: ip.geo ? `${ip.geo.city || ''} ${ip.geo.country}` : 'Unknown',
          ISP: ip.isp || 'Unknown',
          ASN: ip.asn || 'N/A',
        },
        expandable: true,
      });
      // Link domain to IP if available
      if (nodes.some(n => n.kind === 'DOMAIN')) {
        edges.push({ id: `e-ip-${idx}`, source: `node-domain-0`, target: ipId, kind: 'RESOLVES_TO', weight: 0.7 });
      } else {
        edges.push({ id: `e-ip-${idx}`, source: emailNodeId, target: ipId, kind: 'HOSTED_ON', weight: 0.7 });
      }
    });

    // URLs
    analysis.urls.slice(0, 3).forEach((u, idx) => {
      const uId = `node-url-${idx}`;
      nodes.push({
        id: uId,
        kind: 'URL',
        label: u.host || u.url.slice(0, 24) + '...',
        risk: u.risk,
        attributes: { URL: u.url, Destination: u.host },
        expandable: false,
      });
      edges.push({ id: `e-u-${idx}`, source: emailNodeId, target: uId, kind: 'LINKED_TO', weight: 0.6 });
    });

    // Campaign Node
    if (analysis.campaignId || analysis.score.total >= 70) {
      const cId = 'node-campaign-0';
      nodes.push({
        id: cId,
        kind: 'CAMPAIGN',
        label: 'CT-2041 (Fake Invoice)',
        risk: 'CRITICAL',
        attributes: { Campaign: 'Fake Invoice Campaign', Cluster: 'Domain & IP Infrastructure overlap' },
        expandable: true,
      });
      edges.push({ id: 'e-c-0', source: emailNodeId, target: cId, kind: 'SEEN_IN', weight: 1.0 });
    }

    return { nodes, edges };
  };

  const { nodes: allNodes, edges } = buildGraphData();

  const nodes = filterType === 'ALL'
    ? allNodes
    : allNodes.filter(n => n.kind === filterType || n.id === 'node-email-0');

  // Interactive Force Simulation on Canvas
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas || nodes.length === 0) return;
    const ctx = canvas.getContext('2d')!;

    let animId = 0;
    const W = canvas.width = canvas.offsetWidth;
    const H = canvas.height = canvas.offsetHeight;

    // Initialize positions in a circle around center
    nodes.forEach((n, i) => {
      if (n.x === undefined || n.y === undefined) {
        if (i === 0) {
          n.x = W / 2;
          n.y = H / 2;
        } else {
          const angle = (i / (nodes.length - 1)) * 2 * Math.PI;
          const dist = 140 + (i % 2) * 50;
          n.x = W / 2 + Math.cos(angle) * dist;
          n.y = H / 2 + Math.sin(angle) * dist;
        }
        n.vx = 0;
        n.vy = 0;
      }
    });

    const getNodeColor = (risk: Severity) => {
      switch (risk) {
        case 'CRITICAL': return '#ef4444';
        case 'HIGH': return '#f97316';
        case 'MEDIUM': return '#f59e0b';
        case 'LOW': return '#22c55e';
        default: return '#22d3ee';
      }
    };

    const draw = () => {
      ctx.clearRect(0, 0, W, H);
      ctx.save();
      ctx.translate(pan.x + W / 2, pan.y + H / 2);
      ctx.scale(zoom, zoom);
      ctx.translate(-W / 2, -H / 2);

      // Draw Edges
      edges.forEach(e => {
        const src = nodes.find(n => n.id === e.source);
        const tgt = nodes.find(n => n.id === e.target);
        if (src && tgt && src.x !== undefined && src.y !== undefined && tgt.x !== undefined && tgt.y !== undefined) {
          ctx.beginPath();
          ctx.moveTo(src.x, src.y);
          ctx.lineTo(tgt.x, tgt.y);
          ctx.strokeStyle = 'rgba(34, 211, 238, 0.25)';
          ctx.lineWidth = e.weight * 2;
          ctx.stroke();

          // Edge label
          const mx = (src.x + tgt.x) / 2;
          const my = (src.y + tgt.y) / 2;
          ctx.fillStyle = 'rgba(148, 163, 184, 0.7)';
          ctx.font = '8px monospace';
          ctx.textAlign = 'center';
          ctx.fillText(e.kind, mx, my - 3);
        }
      });

      // Draw Nodes
      nodes.forEach(n => {
        if (n.x === undefined || n.y === undefined) return;
        const color = getNodeColor(n.risk);
        const isSel = selectedNode?.id === n.id;
        const radius = n.kind === 'EMAIL' ? 18 : n.kind === 'CAMPAIGN' ? 16 : 12;

        // Glow for high threat
        if (n.risk === 'CRITICAL') {
          ctx.beginPath();
          ctx.arc(n.x, n.y, radius + 6, 0, Math.PI * 2);
          ctx.fillStyle = 'rgba(239, 68, 68, 0.15)';
          ctx.fill();
        }

        // Node Circle
        ctx.beginPath();
        ctx.arc(n.x, n.y, radius, 0, Math.PI * 2);
        ctx.fillStyle = '#0a0f1a';
        ctx.fill();
        ctx.strokeStyle = isSel ? '#ffffff' : color;
        ctx.lineWidth = isSel ? 3 : 2;
        ctx.stroke();

        // Label
        ctx.fillStyle = '#e2e8f0';
        ctx.font = `${isSel ? 'bold ' : ''}10px sans-serif`;
        ctx.textAlign = 'center';
        ctx.fillText(n.label.slice(0, 18), n.x, n.y + radius + 12);
        ctx.fillStyle = 'rgba(148, 163, 184, 0.8)';
        ctx.font = '8px monospace';
        ctx.fillText(`[${n.kind}]`, n.x, n.y + radius + 22);
      });

      ctx.restore();
      animId = requestAnimationFrame(draw);
    };

    draw();
    return () => cancelAnimationFrame(animId);
  }, [nodes, edges, zoom, pan, selectedNode]);

  // Click handler on canvas
  const handleCanvasClick = (e: React.MouseEvent<HTMLCanvasElement>) => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const rect = canvas.getBoundingClientRect();
    const clickX = e.clientX - rect.left;
    const clickY = e.clientY - rect.top;

    const W = canvas.offsetWidth;
    const H = canvas.offsetHeight;

    // Invert pan & zoom
    const mapX = (clickX - (pan.x + W / 2)) / zoom + W / 2;
    const mapY = (clickY - (pan.y + H / 2)) / zoom + H / 2;

    const hit = nodes.find(n => {
      if (n.x === undefined || n.y === undefined) return false;
      const dx = n.x - mapX;
      const dy = n.y - mapY;
      return Math.sqrt(dx * dx + dy * dy) <= 24;
    });

    setSelectedNode(hit || null);
  };

  if (!analysis) {
    return (
      <div style={{ padding: 32, maxWidth: 800, margin: '40px auto', textAlign: 'center' }}>
        <div className="panel" style={{ padding: 48 }}>
          <Network size={48} color="#22d3ee" style={{ margin: '0 auto 16px' }} />
          <h2 style={{ fontSize: 20, fontWeight: 700, marginBottom: 8 }}>No Threat Graph Available</h2>
          <p style={{ color: 'var(--color-text-dim)', fontSize: 13, marginBottom: 24 }}>
            Generate a correlated multi-dimensional network graph linking emails, domains, IPs, URLs, and active campaigns.
          </p>
          <div className="flex justify-center gap-3">
            <button onClick={() => navigate('/analyzer')} className="btn-primary">
              Go to Email Analyzer
            </button>
            <button onClick={handleLoadDemo} disabled={analyzingDemo} className="btn-ghost" style={{ borderColor: '#f59e0b', color: '#f59e0b' }}>
              {analyzingDemo ? 'Analyzing Demo...' : '⚡ Load Multi-Node Threat Graph'}
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div style={{ padding: 24, maxWidth: 1400, margin: '0 auto' }}>
      {/* Top Header */}
      <div className="flex items-center justify-between mb-6 flex-wrap gap-4">
        <div>
          <div className="flex items-center gap-2">
            <Network size={20} color="#22d3ee" />
            <h1 style={{ fontSize: 20, fontWeight: 800, color: 'var(--color-text)' }}>
              Interactive Threat Network Graph
            </h1>
          </div>
          <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginTop: 2 }}>
            Relational topology connecting senders, lookalike domains, ASN resolvers, payload URLs, and threat clusters
          </div>
        </div>

        {/* Filters & Zoom */}
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1 bg-surface-2 p-1 rounded-lg border border-border">
            {['ALL', 'DOMAIN', 'IP', 'URL', 'CAMPAIGN'].map(f => (
              <button
                key={f}
                onClick={() => setFilterType(f)}
                style={{
                  fontSize: 10, fontWeight: 700,
                  padding: '4px 8px', borderRadius: 4,
                  background: filterType === f ? 'rgba(34,211,238,0.2)' : 'transparent',
                  color: filterType === f ? '#22d3ee' : 'var(--color-text-muted)',
                  border: 'none', cursor: 'pointer',
                }}
              >
                {f}
              </button>
            ))}
          </div>

          <div className="flex items-center gap-1">
            <button onClick={() => setZoom(z => Math.min(z + 0.2, 2.5))} className="btn-ghost" style={{ padding: '6px 10px' }}>
              <ZoomIn size={14} />
            </button>
            <button onClick={() => setZoom(z => Math.max(z - 0.2, 0.5))} className="btn-ghost" style={{ padding: '6px 10px' }}>
              <ZoomOut size={14} />
            </button>
            <button onClick={() => { setZoom(1); setPan({ x: 0, y: 0 }); }} className="btn-ghost" style={{ padding: '6px 10px' }}>
              <RotateCcw size={14} />
            </button>
          </div>
        </div>
      </div>

      {/* Main Graph Canvas & Inspector Grid */}
      <div className="grid gap-6" style={{ gridTemplateColumns: 'minmax(400px, 2fr) minmax(300px, 1fr)' }}>
        {/* Canvas */}
        <div className="panel relative" style={{ padding: 0, height: 580, overflow: 'hidden' }}>
          <canvas
            ref={canvasRef}
            onClick={handleCanvasClick}
            style={{ width: '100%', height: '100%', cursor: 'crosshair', display: 'block' }}
          />

          {/* Graph Legend */}
          <div
            className="absolute bottom-4 left-4 p-3 rounded-lg flex flex-wrap gap-3"
            style={{ background: 'rgba(10,15,26,0.85)', backdropFilter: 'blur(8px)', border: '1px solid var(--color-border)' }}
          >
            {[
              { label: 'Email', color: '#22d3ee' },
              { label: 'Domain', color: '#ef4444' },
              { label: 'IP Address', color: '#f97316' },
              { label: 'User / Alias', color: '#f59e0b' },
              { label: 'Campaign', color: '#a78bfa' },
            ].map(l => (
              <div key={l.label} className="flex items-center gap-1.5" style={{ fontSize: 10, color: 'var(--color-text-dim)' }}>
                <div style={{ width: 8, height: 8, borderRadius: '50%', background: l.color }} />
                <span>{l.label}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Right Node Inspector */}
        <div className="panel" style={{ padding: 20, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          {selectedNode ? (
            <div className="flex flex-col gap-4">
              <div className="flex items-center justify-between pb-3" style={{ borderBottom: '1px solid var(--color-border)' }}>
                <div>
                  <span className="label">SELECTED NODE</span>
                  <div style={{ fontSize: 16, fontWeight: 800, color: '#22d3ee', marginTop: 2 }}>
                    {selectedNode.label}
                  </div>
                </div>
                <span
                  style={{
                    fontSize: 10, fontWeight: 800,
                    padding: '2px 8px', borderRadius: 4,
                    background: selectedNode.risk === 'CRITICAL' ? 'rgba(239,68,68,0.2)' : 'rgba(34,211,238,0.2)',
                    color: selectedNode.risk === 'CRITICAL' ? '#ef4444' : '#22d3ee',
                  }}
                >
                  {selectedNode.kind}
                </span>
              </div>

              <div className="flex flex-col gap-2.5">
                {Object.entries(selectedNode.attributes).map(([k, v]) => (
                  <div key={k}>
                    <div className="label">{k}</div>
                    <div style={{ fontSize: 12, color: 'var(--color-text)', marginTop: 1, wordBreak: 'break-all', fontFamily: 'var(--font-mono)' }}>
                      {v}
                    </div>
                  </div>
                ))}
              </div>

              {selectedNode.expandable && (
                <button
                  onClick={() => alert(`Expanding correlated infrastructure for ${selectedNode.label}...`)}
                  className="btn-ghost flex items-center justify-center gap-2 text-xs mt-2"
                  style={{ borderColor: '#22d3ee', color: '#22d3ee' }}
                >
                  <Eye size={12} />
                  <span>EXPAND RELATED EDGES</span>
                </button>
              )}
            </div>
          ) : (
            <div className="flex flex-col items-center justify-center h-full text-center" style={{ padding: 24 }}>
              <Network size={36} color="var(--color-text-muted)" style={{ marginBottom: 12 }} />
              <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--color-text)' }}>No Node Selected</div>
              <p style={{ fontSize: 11, color: 'var(--color-text-muted)', marginTop: 4 }}>
                Click any node in the graph (Email, Domain, IP, or Campaign) to inspect correlated telemetry attributes.
              </p>
            </div>
          )}

          <div
            className="p-3 rounded-lg flex items-start gap-2.5 mt-4"
            style={{ background: 'rgba(34,211,238,0.04)', border: '1px solid var(--color-border)', fontSize: 11, color: 'var(--color-text-muted)' }}
          >
            <Info size={13} color="#22d3ee" style={{ marginTop: 2, flexShrink: 0 }} />
            <div>
              <strong>SIH Feature Note:</strong> Nodes represent correlated entities extracted during the 13-stage forensic pipeline. Edges indicate provenance, DNS resolution, or campaign cluster membership.
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
