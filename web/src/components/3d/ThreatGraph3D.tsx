import React, { useEffect, useRef, useState } from 'react';
import * as THREE from 'three';
import { Shield, ExternalLink, Filter, X, Info, Search, Sparkles } from 'lucide-react';

export interface GraphNodeData {
  id: string;
  name: string;
  category: 'EMAIL' | 'SENDER' | 'REPLY_TO' | 'DOMAIN' | 'IP' | 'ASN' | 'URL' | 'ATTACHMENT' | 'HASH' | 'CAMPAIGN' | 'CASE';
  threatLevel?: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  details?: Record<string, string | number>;
}

export interface GraphLinkData {
  source: string;
  target: string;
  relation: 'SENT_FROM' | 'REPLY_TO' | 'RESOLVES_TO' | 'HOSTED_ON' | 'LINKS_TO' | 'ATTACHED' | 'RELATED_TO' | 'SHARED_INFRASTRUCTURE';
}

const CATEGORY_COLORS: Record<GraphNodeData['category'], string> = {
  EMAIL: '#38bdf8',
  SENDER: '#f59e0b',
  REPLY_TO: '#fb923c',
  DOMAIN: '#06b6d4',
  IP: '#ef4444',
  ASN: '#818cf8',
  URL: '#f97316',
  ATTACHMENT: '#ec4899',
  HASH: '#e879f9',
  CAMPAIGN: '#a855f7',
  CASE: '#10b981',
};

export function ThreatGraph3D({
  nodes = [],
  links = [],
  onSelectNode,
}: {
  nodes?: GraphNodeData[];
  links?: GraphLinkData[];
  onSelectNode?: (node: GraphNodeData) => void;
}) {
  const mountRef = useRef<HTMLDivElement>(null);
  const [selectedNode, setSelectedNode] = useState<GraphNodeData | null>(null);
  const [hoveredNode, setHoveredNode] = useState<string | null>(null);

  // Fallback rich graph dataset
  const activeNodes: GraphNodeData[] = nodes.length > 0 ? nodes : [
    { id: 'eml-1', name: 'invoice_fraud.eml', category: 'EMAIL', threatLevel: 'HIGH', details: { Subject: 'Overdue Invoice', SHA256: '3776da176934...' } },
    { id: 'snd-1', name: 'billing@paypa1-security.com', category: 'SENDER', threatLevel: 'HIGH', details: { DisplayName: 'Accounts Receivable', SPF: 'FAIL' } },
    { id: 'rep-1', name: 'billing-settlement@paypa1-security.com', category: 'REPLY_TO', threatLevel: 'HIGH', details: { Divergence: 'Detected' } },
    { id: 'dom-1', name: 'paypa1-security.com', category: 'DOMAIN', threatLevel: 'CRITICAL', details: { Technique: 'Typosquatting', Similarity: '94%' } },
    { id: 'ip-1', name: '185.220.101.5', category: 'IP', threatLevel: 'CRITICAL', details: { ISP: 'Offshore VPS Cloud', Location: 'Frankfurt, DE' } },
    { id: 'asn-1', name: 'AS60729 (Cloud Infra)', category: 'ASN', threatLevel: 'INFO', details: { HostType: 'Datacenter VPS' } },
    { id: 'url-1', name: 'http://185.220.101.5/billing/pay', category: 'URL', threatLevel: 'CRITICAL', details: { Status: 'Credential Harvest' } },
    { id: 'cmp-1', name: 'CAMPAIGN #ST-2026-FIN', category: 'CAMPAIGN', threatLevel: 'HIGH', details: { Overlap: '92% Jaccard' } },
    { id: 'cas-1', name: 'CASE #ST-2026-00008', category: 'CASE', threatLevel: 'MEDIUM', details: { Status: 'ACTIVE_TRIAGE' } },
  ];

  const activeLinks: GraphLinkData[] = links.length > 0 ? links : [
    { source: 'eml-1', target: 'snd-1', relation: 'SENT_FROM' },
    { source: 'eml-1', target: 'rep-1', relation: 'REPLY_TO' },
    { source: 'snd-1', target: 'dom-1', relation: 'RESOLVES_TO' },
    { source: 'dom-1', target: 'ip-1', relation: 'HOSTED_ON' },
    { source: 'ip-1', target: 'asn-1', relation: 'RELATED_TO' },
    { source: 'eml-1', target: 'url-1', relation: 'LINKS_TO' },
    { source: 'ip-1', target: 'cmp-1', relation: 'SHARED_INFRASTRUCTURE' },
    { source: 'eml-1', target: 'cas-1', relation: 'RELATED_TO' },
  ];

  useEffect(() => {
    const container = mountRef.current;
    if (!container) return;

    const width = container.clientWidth || 700;
    const height = container.clientHeight || 500;

    const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(50, width / height, 0.1, 1000);
    camera.position.set(0, 0, 180);

    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    renderer.setSize(width, height);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    container.appendChild(renderer.domElement);

    const disposables: { geometries: THREE.BufferGeometry[]; materials: THREE.Material[] } = {
      geometries: [],
      materials: [],
    };

    // Lights
    const ambientLight = new THREE.AmbientLight(0xffffff, 0.7);
    scene.add(ambientLight);

    const pointLight = new THREE.PointLight(0x22d3ee, 2, 300);
    pointLight.position.set(40, 40, 80);
    scene.add(pointLight);

    // Graph Layout Positions
    const nodePositions: Record<string, THREE.Vector3> = {};
    const nodeMeshes: THREE.Mesh[] = [];
    const graphGroup = new THREE.Group();
    scene.add(graphGroup);

    activeNodes.forEach((node, i) => {
      const angle = (i / activeNodes.length) * Math.PI * 2;
      const radius = 55 + (i % 2) * 15;
      const pos = new THREE.Vector3(
        Math.cos(angle) * radius,
        Math.sin(angle) * radius * 0.75 + ((i % 3) - 1) * 8,
        ((i % 2) - 0.5) * 25
      );
      nodePositions[node.id] = pos;

      const sphereGeo = new THREE.SphereGeometry(3.5, 16, 16);
      disposables.geometries.push(sphereGeo);
      const colorHex = CATEGORY_COLORS[node.category] || '#38bdf8';
      const sphereMat = new THREE.MeshStandardMaterial({
        color: new THREE.Color(colorHex),
        emissive: new THREE.Color(colorHex),
        emissiveIntensity: 0.4,
        roughness: 0.3,
      });
      disposables.materials.push(sphereMat);

      const mesh = new THREE.Mesh(sphereGeo, sphereMat);
      mesh.position.copy(pos);
      mesh.userData = node;
      nodeMeshes.push(mesh);
      graphGroup.add(mesh);

      // Outer halo
      const haloGeo = new THREE.RingGeometry(4.2, 5.5, 20);
      disposables.geometries.push(haloGeo);
      const haloMat = new THREE.MeshBasicMaterial({
        color: new THREE.Color(colorHex),
        side: THREE.DoubleSide,
        transparent: true,
        opacity: 0.4,
      });
      disposables.materials.push(haloMat);
      const haloMesh = new THREE.Mesh(haloGeo, haloMat);
      haloMesh.position.copy(pos);
      graphGroup.add(haloMesh);
    });

    // Draw connecting edges
    activeLinks.forEach((link) => {
      const srcPos = nodePositions[link.source];
      const tgtPos = nodePositions[link.target];
      if (!srcPos || !tgtPos) return;

      const lineGeo = new THREE.BufferGeometry().setFromPoints([srcPos, tgtPos]);
      disposables.geometries.push(lineGeo);
      const lineMat = new THREE.LineBasicMaterial({
        color: 0x06b6d4,
        transparent: true,
        opacity: 0.35,
      });
      disposables.materials.push(lineMat);
      const line = new THREE.Line(lineGeo, lineMat);
      graphGroup.add(line);
    });

    // Raycaster for click & hover
    const raycaster = new THREE.Raycaster();
    const mouse = new THREE.Vector2();

    const handleClick = (e: MouseEvent) => {
      const rect = renderer.domElement.getBoundingClientRect();
      mouse.x = ((e.clientX - rect.left) / rect.width) * 2 - 1;
      mouse.y = -((e.clientY - rect.top) / rect.height) * 2 + 1;

      raycaster.setFromCamera(mouse, camera);
      const intersects = raycaster.intersectObjects(nodeMeshes);

      if (intersects.length > 0) {
        const clickedNode = intersects[0].object.userData as GraphNodeData;
        setSelectedNode(clickedNode);
        if (onSelectNode) onSelectNode(clickedNode);
      }
    };

    const handleMouseMove = (e: MouseEvent) => {
      const rect = renderer.domElement.getBoundingClientRect();
      mouse.x = ((e.clientX - rect.left) / rect.width) * 2 - 1;
      mouse.y = -((e.clientY - rect.top) / rect.height) * 2 + 1;

      raycaster.setFromCamera(mouse, camera);
      const intersects = raycaster.intersectObjects(nodeMeshes);

      if (intersects.length > 0) {
        const hNode = intersects[0].object.userData as GraphNodeData;
        setHoveredNode(hNode.name);
      } else {
        setHoveredNode(null);
      }
    };

    renderer.domElement.addEventListener('click', handleClick);
    renderer.domElement.addEventListener('mousemove', handleMouseMove);

    // Mouse drag rotation
    let isDragging = false;
    let previousMousePosition = { x: 0, y: 0 };

    const onMouseDown = (e: MouseEvent) => {
      isDragging = true;
      previousMousePosition = { x: e.clientX, y: e.clientY };
    };

    const onWindowMouseMove = (e: MouseEvent) => {
      if (!isDragging) return;
      const deltaX = e.clientX - previousMousePosition.x;
      const deltaY = e.clientY - previousMousePosition.y;

      graphGroup.rotation.y += deltaX * 0.005;
      graphGroup.rotation.x += deltaY * 0.005;

      previousMousePosition = { x: e.clientX, y: e.clientY };
    };

    const onMouseUp = () => {
      isDragging = false;
    };

    renderer.domElement.addEventListener('mousedown', onMouseDown);
    window.addEventListener('mousemove', onWindowMouseMove);
    window.addEventListener('mouseup', onMouseUp);

    // Animation Loop
    let animId: number;
    const animate = () => {
      if (!prefersReducedMotion && !isDragging && !document.hidden) {
        graphGroup.rotation.y += 0.002;
      }
      renderer.render(scene, camera);
      animId = requestAnimationFrame(animate);
    };

    animate();

    const handleResize = () => {
      if (!container) return;
      const w = container.clientWidth;
      const h = container.clientHeight || 500;
      camera.aspect = w / h;
      camera.updateProjectionMatrix;
      renderer.setSize(w, h);
    };
    window.addEventListener('resize', handleResize);

    return () => {
      cancelAnimationFrame(animId);
      window.removeEventListener('resize', handleResize);
      renderer.domElement.removeEventListener('click', handleClick);
      renderer.domElement.removeEventListener('mousemove', handleMouseMove);
      renderer.domElement.removeEventListener('mousedown', onMouseDown);
      window.removeEventListener('mousemove', onWindowMouseMove);
      window.removeEventListener('mouseup', onMouseUp);

      if (container.contains(renderer.domElement)) {
        container.removeChild(renderer.domElement);
      }

      disposables.geometries.forEach(g => g.dispose());
      disposables.materials.forEach(m => m.dispose());
      renderer.dispose();
    };
  }, [activeNodes, activeLinks, onSelectNode]);

  return (
    <div className="relative w-full h-[520px] rounded-2xl bg-[#020617] border border-cyan-500/20 overflow-hidden shadow-[0_0_40px_rgba(0,0,0,0.8)]">
      <div ref={mountRef} className="w-full h-full cursor-grab active:cursor-grabbing" />

      {/* Top Legend Bar */}
      <div className="absolute top-4 left-4 right-4 z-20 flex flex-wrap items-center justify-between gap-2 p-3 rounded-xl bg-[#080e21]/90 border border-cyan-500/20 backdrop-blur-md">
        <div className="flex items-center gap-2">
          <Shield size={16} className="text-cyan-400" />
          <span className="font-mono text-xs font-bold text-slate-100 uppercase tracking-wider">
            3D FORENSIC RELATIONSHIP GRAPH ({activeNodes.length} ENTITIES)
          </span>
        </div>

        {hoveredNode && (
          <div className="text-[11px] font-mono text-cyan-300 truncate max-w-xs">
            Hovered: <strong>{hoveredNode}</strong>
          </div>
        )}
      </div>

      {/* Category Pills Overlay */}
      <div className="absolute bottom-4 left-4 z-20 flex flex-wrap gap-1.5 max-w-xl p-2 rounded-lg bg-[#050a18]/90 border border-slate-800 backdrop-blur-md">
        {Object.entries(CATEGORY_COLORS).map(([cat, col]) => (
          <div key={cat} className="flex items-center gap-1 text-[9px] font-mono px-1.5 py-0.5 rounded bg-slate-900 border border-slate-700">
            <span className="w-2 h-2 rounded-full" style={{ backgroundColor: col }} />
            <span className="text-slate-300">{cat}</span>
          </div>
        ))}
      </div>

      {/* Selected Node Evidence Inspection Drawer */}
      {selectedNode && (
        <div className="absolute top-16 right-4 bottom-16 z-30 w-80 p-4 rounded-xl bg-[#080e21]/95 border border-cyan-500/30 backdrop-blur-xl shadow-2xl overflow-y-auto space-y-3 animate-fade-in">
          <div className="flex items-center justify-between border-b border-cyan-500/20 pb-2">
            <div>
              <div className="text-[9px] font-mono font-bold uppercase" style={{ color: CATEGORY_COLORS[selectedNode.category] }}>
                {selectedNode.category} ENTITY
              </div>
              <div className="text-sm font-bold text-white mt-0.5 truncate max-w-[200px]" title={selectedNode.name}>
                {selectedNode.name}
              </div>
            </div>
            <button
              onClick={() => setSelectedNode(null)}
              className="p-1 rounded text-slate-400 hover:text-white hover:bg-slate-800"
            >
              <X size={15} />
            </button>
          </div>

          <div className="p-2 rounded bg-[#050a18] border border-cyan-500/15 flex justify-between items-center text-xs font-mono">
            <span className="text-slate-400">THREAT LEVEL</span>
            <span className="font-bold text-red-400">{selectedNode.threatLevel || 'INFO'}</span>
          </div>

          {/* Node Attribute Details */}
          {selectedNode.details && (
            <div className="space-y-1.5 pt-1">
              <div className="text-[10px] font-mono font-bold text-slate-400 uppercase">
                ENTITY ATTRIBUTES
              </div>
              {Object.entries(selectedNode.details).map(([k, v]) => (
                <div key={k} className="p-2 rounded bg-[#050a18] border border-slate-800 text-xs font-mono flex justify-between">
                  <span className="text-slate-500">{k}:</span>
                  <span className="text-slate-200 select-all">{v}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
