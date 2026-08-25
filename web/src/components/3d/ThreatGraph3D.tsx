import React, { useEffect, useRef, useState } from 'react';
import * as THREE from 'three';
import { Shield, ExternalLink, Filter } from 'lucide-react';

export interface GraphNodeData {
  id: string;
  name: string;
  category: 'EMAIL' | 'SENDER' | 'DOMAIN' | 'IP' | 'ASN' | 'URL' | 'ATTACHMENT' | 'HASH' | 'CAMPAIGN' | 'CASE';
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

  // Fallback demo graph data if none provided
  const activeNodes: GraphNodeData[] = nodes.length > 0 ? nodes : [
    { id: 'eml-1', name: 'invoice_fraud.eml', category: 'EMAIL', threatLevel: 'HIGH' },
    { id: 'snd-1', name: 'billing@paypa1-security.com', category: 'SENDER', threatLevel: 'HIGH' },
    { id: 'dom-1', name: 'paypa1-security.com', category: 'DOMAIN', threatLevel: 'CRITICAL' },
    { id: 'ip-1', name: '185.220.101.5', category: 'IP', threatLevel: 'CRITICAL' },
    { id: 'asn-1', name: 'AS60729 (Stiftung)', category: 'ASN', threatLevel: 'INFO' },
    { id: 'url-1', name: 'http://185.220.101.5/billing/pay', category: 'URL', threatLevel: 'CRITICAL' },
    { id: 'cmp-1', name: 'CAMPAIGN #ST-2026-FIN', category: 'CAMPAIGN', threatLevel: 'HIGH' },
    { id: 'cas-1', name: 'CASE #ST-2026-00008', category: 'CASE', threatLevel: 'MEDIUM' },
  ];

  const activeLinks: GraphLinkData[] = links.length > 0 ? links : [
    { source: 'eml-1', target: 'snd-1', relation: 'SENT_FROM' },
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

    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(50, width / height, 0.1, 1000);
    camera.position.set(0, 0, 180);

    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    renderer.setSize(width, height);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    container.appendChild(renderer.domElement);

    // Lights
    const ambientLight = new THREE.AmbientLight(0xffffff, 0.7);
    scene.add(ambientLight);

    const pointLight = new THREE.PointLight(0x22d3ee, 2, 300);
    pointLight.position.set(40, 40, 80);
    scene.add(pointLight);

    // Graph Layout Positions (Cylinder / Circle Orbit)
    const nodePositions: Record<string, THREE.Vector3> = {};
    const nodeMeshes: THREE.Mesh[] = [];

    activeNodes.forEach((node, i) => {
      const angle = (i / activeNodes.length) * Math.PI * 2;
      const radius = 50 + (i % 2) * 15;
      const pos = new THREE.Vector3(
        Math.cos(angle) * radius,
        Math.sin(angle) * radius * 0.75 + ((i % 3) - 1) * 8,
        ((i % 2) - 0.5) * 20
      );
      nodePositions[node.id] = pos;

      const colorHex = CATEGORY_COLORS[node.category] || '#22d3ee';
      const geo = new THREE.SphereGeometry(3.5, 20, 20);
      const mat = new THREE.MeshStandardMaterial({
        color: new THREE.Color(colorHex),
        emissive: new THREE.Color(colorHex),
        emissiveIntensity: 0.5,
        roughness: 0.3,
        metalness: 0.6,
      });

      const mesh = new THREE.Mesh(geo, mat);
      mesh.position.copy(pos);
      mesh.userData = node;
      scene.add(mesh);
      nodeMeshes.push(mesh);
    });

    // Links / Edges
    const lineMat = new THREE.LineBasicMaterial({
      color: 0x38bdf8,
      transparent: true,
      opacity: 0.35,
    });

    activeLinks.forEach((link) => {
      const srcPos = nodePositions[link.source];
      const tgtPos = nodePositions[link.target];
      if (srcPos && tgtPos) {
        const geo = new THREE.BufferGeometry().setFromPoints([srcPos, tgtPos]);
        const line = new THREE.Line(geo, lineMat);
        scene.add(line);
      }
    });

    // Raycaster
    const raycaster = new THREE.Raycaster();
    const mouse = new THREE.Vector2();

    const handleClick = (e: MouseEvent) => {
      const rect = container.getBoundingClientRect();
      mouse.x = ((e.clientX - rect.left) / rect.width) * 2 - 1;
      mouse.y = -((e.clientY - rect.top) / rect.height) * 2 + 1;

      raycaster.setFromCamera(mouse, camera);
      const hits = raycaster.intersectObjects(nodeMeshes);
      if (hits.length > 0) {
        const nodeData = hits[0].object.userData as GraphNodeData;
        setSelectedNode(nodeData);
        if (onSelectNode) onSelectNode(nodeData);
      }
    };

    container.addEventListener('click', handleClick);

    // Animation Loop
    let animId: number;
    let clock = new THREE.Clock();

    const animate = () => {
      animId = requestAnimationFrame(animate);
      const t = clock.getElapsedTime();
      scene.rotation.y = Math.sin(t * 0.15) * 0.12;
      scene.rotation.x = Math.cos(t * 0.1) * 0.08;
      renderer.render(scene, camera);
    };
    animate();

    return () => {
      cancelAnimationFrame(animId);
      container.removeEventListener('click', handleClick);
      if (renderer.domElement && container.contains(renderer.domElement)) {
        container.removeChild(renderer.domElement);
      }
      renderer.dispose();
    };
  }, [nodes, links, onSelectNode]);

  return (
    <div className="relative w-full h-full min-h-[460px] rounded-xl overflow-hidden bg-gradient-to-b from-[#080e21]/70 to-[#020617]/95 border border-cyan-500/15">
      <div ref={mountRef} className="w-full h-full cursor-pointer" />

      {/* Selected Node Inspector HUD */}
      {selectedNode && (
        <div className="absolute top-4 right-4 max-w-xs p-4 rounded-xl bg-[#080e21]/95 border border-cyan-500/30 backdrop-blur-xl shadow-2xl animate-fade-in">
          <div className="flex items-center justify-between gap-2 mb-2">
            <span
              className="px-2 py-0.5 rounded text-[10px] font-bold tracking-wider uppercase"
              style={{
                background: `${CATEGORY_COLORS[selectedNode.category]}20`,
                color: CATEGORY_COLORS[selectedNode.category],
                border: `1px solid ${CATEGORY_COLORS[selectedNode.category]}50`,
              }}
            >
              {selectedNode.category}
            </span>
            {selectedNode.threatLevel && (
              <span className="text-[10px] font-bold text-red-400">
                {selectedNode.threatLevel}
              </span>
            )}
          </div>
          <div className="font-mono text-xs font-semibold text-slate-100 break-all mb-2">
            {selectedNode.name}
          </div>
          <div className="text-[11px] text-slate-400">
            Node connected into active investigation graph.
          </div>
        </div>
      )}

      {/* Graph Legend */}
      <div className="absolute bottom-3 left-3 flex flex-wrap gap-2 px-3 py-2 rounded-lg bg-[#080e21]/80 border border-cyan-500/10 backdrop-blur-md">
        {Object.entries(CATEGORY_COLORS).slice(0, 6).map(([cat, col]) => (
          <div key={cat} className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full" style={{ background: col }} />
            <span className="text-[9px] font-mono text-slate-400">{cat}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
